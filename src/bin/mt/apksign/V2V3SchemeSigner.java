package bin.mt.apksign;

import bin.io.RandomAccessFactory;
import bin.io.RandomAccessFile;
import bin.mt.apksign.data.ByteArrayDataSource;
import bin.mt.apksign.data.DataSource;
import bin.mt.apksign.data.DataSources;
import bin.mt.apksign.key.SignatureKey;

import java.io.File;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import static bin.mt.apksign.ByteArrayUtil.*;

/**
 * @author Bin
 */
class V2V3SchemeSigner {
    private static final int ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 0x1000;
    private static final int VERITY_PADDING_BLOCK_ID = 0x42726577;
    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;
    private static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;

    static void sign(File file, SignatureKey signatureKey, boolean enableV2, boolean enableV3) throws Exception {
        if (!enableV2 && !enableV3) {
            throw new RuntimeException();
        }

        PublicKey publicKey = signatureKey.getCertificate().getPublicKey();

        // Algorithms
        List<SignatureAlgorithm> algorithms = getSuggestedSignatureAlgorithms(publicKey);

        try (RandomAccessFile accessFile = RandomAccessFactory.from(file, "rw")) {
            ZipBuffer zipBuffer = new ZipBuffer(accessFile);

            // DataSource
            DataSource beforeCentralDir = DataSources
                    .fromFile(accessFile, 0, zipBuffer.getEntriesDataSizeBytes())
                    .align(ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);

            long start = zipBuffer.getCentralDirectoryOffset();
            long size = zipBuffer.getCentralDirectorySizeBytes();
            DataSource centralDir = DataSources.fromFile(accessFile, start, size).toMemory();

            start = zipBuffer.getEocdOffset();
            size = zipBuffer.length() - start;
            ByteArrayDataSource eocd = DataSources.fromFile(accessFile, start, size).toMemory();
            int dif = (int) (zipBuffer.getCentralDirectoryOffset() - beforeCentralDir.size());
            if (dif != 0) {
                // beforeCentralDir经过align后size发生变化，这里需要修复cd偏移
                byte[] eocdData = eocd.getBuffer();
                int valueOffset = eocd.getStart() + 16;
                long cdOffset = readUInt(eocdData, valueOffset);
                cdOffset -= dif;
                setUInt(cdOffset, eocdData, valueOffset);
            }

            boolean reset = false;
            for (SignatureAlgorithm algorithm : algorithms) {
                if (reset)
                    DataSources.reset(beforeCentralDir, centralDir, eocd);
                algorithm.computeDigest(beforeCentralDir, centralDir, eocd);
                reset = true;
            }
            byte[] apkSignatureSchemeV2Block = null;
            byte[] apkSignatureSchemeV3Block = null;

            if (enableV2) {
                byte[] v2SignedData = concat(
                        encodeDigestPart(algorithms),
                        encodeCertificatePart(signatureKey.getCertificate()),
                        encodeAdditionalPart(),
                        new byte[4] // length(int32) + byte[0] = 4byte
                );
                for (SignatureAlgorithm algorithm : algorithms) {
                    algorithm.computeSignature(signatureKey.getPrivateKey(), publicKey, v2SignedData);
                }
                byte[] signature = encodeSignature(algorithms);
                byte[] encodedPublicKey = encodePublicKey(publicKey);
                int v2Length = v2SignedData.length + signature.length + encodedPublicKey.length + 12;
                apkSignatureSchemeV2Block = concat(
                        intToBytes(v2Length + 4),
                        intToBytes(v2Length),
                        intToBytes(v2SignedData.length),
                        v2SignedData,
                        intToBytes(signature.length),
                        signature,
                        intToBytes(encodedPublicKey.length),
                        encodedPublicKey
                );
            }
            if (enableV3) {
                byte[] v3SignedData = concat(
                        encodeDigestPart(algorithms),
                        encodeCertificatePart(signatureKey.getCertificate()),
                        intToBytes(28), // minSDK
                        intToBytes(Integer.MAX_VALUE), // maxSDK
                        encodeAdditionalPart()
                );
                for (SignatureAlgorithm algorithm : algorithms) {
                    algorithm.computeSignature(signatureKey.getPrivateKey(), publicKey, v3SignedData);
                }
                byte[] signature = encodeSignature(algorithms);
                byte[] encodedPublicKey = encodePublicKey(publicKey);
                int v3Length = v3SignedData.length + signature.length + encodedPublicKey.length + 20;
                apkSignatureSchemeV3Block = concat(
                        intToBytes(v3Length + 4),
                        intToBytes(v3Length),
                        intToBytes(v3SignedData.length),
                        v3SignedData,
                        intToBytes(28), // minSDK
                        intToBytes(Integer.MAX_VALUE), // maxSDK
                        intToBytes(signature.length),
                        signature,
                        intToBytes(encodedPublicKey.length),
                        encodedPublicKey
                );
            }
            // final data in zip
            int v2BlocksSize = !enableV2 ? 0 : 8 + 4 + apkSignatureSchemeV2Block.length; // size + id + value
            int v3BlocksSize = !enableV3 ? 0 : 8 + 4 + apkSignatureSchemeV3Block.length; // size + id + value
            int resultSize = 8 + v2BlocksSize + v3BlocksSize + 8 + 16; // size blocksSize size magic
            byte[] paddingPair = null;
            if (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0) {
                int padding = ANDROID_COMMON_PAGE_ALIGNMENT_BYTES -
                        (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);
                if (padding < 12) {  // minimum size of an ID-value pair
                    padding += ANDROID_COMMON_PAGE_ALIGNMENT_BYTES;
                }
                paddingPair = new byte[padding];
                setLong(padding - 8, paddingPair, 0);
                setInt(VERITY_PADDING_BLOCK_ID, paddingPair, 8);
                resultSize += padding;
            }
            byte[] result = new byte[resultSize];
            long blockSizeFieldValue = resultSize - 8L;
            int pos = 0;

            // size
            setLong(blockSizeFieldValue, result, pos);
            pos += 8;

            if (enableV2) {
                // v2 block size
                setLong(4 + apkSignatureSchemeV2Block.length, result, pos);
                pos += 8;

                // v2 block id
                setInt(APK_SIGNATURE_SCHEME_V2_BLOCK_ID, result, pos);
                pos += 4;

                // v2 block data
                System.arraycopy(apkSignatureSchemeV2Block, 0, result, pos, apkSignatureSchemeV2Block.length);
                pos += apkSignatureSchemeV2Block.length;
            }

            if (enableV3) {
                // v3 block size
                setLong(4 + apkSignatureSchemeV3Block.length, result, pos);
                pos += 8;

                // v3 block id
                setInt(APK_SIGNATURE_SCHEME_V3_BLOCK_ID, result, pos);
                pos += 4;

                // v3 block data
                System.arraycopy(apkSignatureSchemeV3Block, 0, result, pos, apkSignatureSchemeV3Block.length);
                pos += apkSignatureSchemeV3Block.length;
            }

            // padding
            if (paddingPair != null) {
                System.arraycopy(paddingPair, 0, result, pos, paddingPair.length);
                pos += paddingPair.length;
            }

            setLong(blockSizeFieldValue, result, pos);
            pos += 8;

            setLong(ZipBuffer.APK_SIG_BLOCK_MAGIC_LO, result, pos);
            pos += 8;

            setLong(ZipBuffer.APK_SIG_BLOCK_MAGIC_HI, result, pos);
            pos += 8;

            if (pos != resultSize) {
                throw new IllegalStateException();
            }
            int padSizeBeforeApkSigningBlock = getPaddingSize(zipBuffer.getEntriesDataSizeBytes(), ANDROID_COMMON_PAGE_ALIGNMENT_BYTES);
            accessFile.setLength(zipBuffer.getEntriesDataSizeBytes());
            accessFile.seek(zipBuffer.getEntriesDataSizeBytes());
            if (padSizeBeforeApkSigningBlock != 0)
                accessFile.write(new byte[padSizeBeforeApkSigningBlock]);
            accessFile.write(result);
            int centralStart = (int) accessFile.getFilePointer();
            centralDir.reset();
            centralDir.copyTo(accessFile, centralDir.size());
            byte[] eocdData = eocd.getBuffer();
            int valueOffset = eocd.getStart() + 16;
            setInt(centralStart, eocdData, valueOffset);
            eocd.reset();
            eocd.copyTo(accessFile, eocd.size());
        }
    }

    private static byte[] concat(byte[]... sequence) {
        int payloadSize = 0;
        for (byte[] element : sequence) {
            payloadSize += element.length;
        }
        byte[] result = new byte[payloadSize];
        int pos = 0;
        for (byte[] element : sequence) {
            System.arraycopy(element, 0, result, pos, element.length);
            pos += element.length;
        }
        return result;
    }

    private static byte[] encodeDigestPart(Collection<SignatureAlgorithm> algorithms) {
        List<byte[]> digests = new ArrayList<>(algorithms.size());
        int length = 4;
        for (SignatureAlgorithm algorithm : algorithms) {
            byte[] data = encodeIdWithPrefixLengthData(algorithm.getId(), algorithm.getDigest());
            length += data.length;
            digests.add(data);
        }
        byte[] result = new byte[length];
        setInt(length - 4, result, 0);
        int pos = 4;
        for (byte[] digest : digests) {
            System.arraycopy(digest, 0, result, pos, digest.length);
            pos += digest.length;
        }
        return result;
    }

    private static byte[] encodeCertificatePart(X509Certificate... certificates) throws CertificateEncodingException {
        List<byte[]> encodes = new ArrayList<>(certificates.length);
        int length = 4;
        for (X509Certificate certificate : certificates) {
            byte[] data = certificate.getEncoded();
            length += 4 + data.length;
            encodes.add(data);
        }
        byte[] result = new byte[length];
        setInt(length - 4, result, 0);
        int pos = 4;
        for (byte[] encode : encodes) {
            setInt(encode.length, result, pos);
            pos += 4;
            System.arraycopy(encode, 0, result, pos, encode.length);
            pos += encode.length;
        }
        return result;
    }

    private static byte[] encodeSignature(Collection<SignatureAlgorithm> algorithms) {
        List<byte[]> digests = new ArrayList<>(algorithms.size());
        int length = 0;
        for (SignatureAlgorithm algorithm : algorithms) {
            byte[] data = encodeIdWithPrefixLengthData(algorithm.getId(), algorithm.getSignature());
            length += data.length;
            digests.add(data);
        }
        byte[] result = new byte[length];
        int pos = 0;
        for (byte[] digest : digests) {
            System.arraycopy(digest, 0, result, pos, digest.length);
            pos += digest.length;
        }
        return result;
    }

    private static byte[] encodeAdditionalPart() {
        // length 0
        return new byte[4];
    }

    private static byte[] encodeIdWithPrefixLengthData(int id, byte[] digest) {
        byte[] result = new byte[12 + digest.length];
        setInt(digest.length + 8, result, 0);
        setInt(id, result, 4);
        setInt(digest.length, result, 8);
        System.arraycopy(digest, 0, result, 12, digest.length);
        return result;
    }

    private static int getPaddingSize(long length, int align) {
        int overCount = (int) (length % align);
        if (overCount == 0)
            return 0;
        return align - overCount;
    }

    private static List<SignatureAlgorithm> getSuggestedSignatureAlgorithms(PublicKey signingKey) throws InvalidKeyException {
        String keyAlgorithm = signingKey.getAlgorithm();
        if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            int modulusLengthBits = ((RSAKey) signingKey).getModulus().bitLength();
            if (modulusLengthBits <= 3072) {
                return Arrays.asList(
                        SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA256(),
                        SignatureAlgorithm.VERITY_RSA_PKCS1_V1_5_WITH_SHA256()
                );
            } else {
                return Collections.singletonList(
                        SignatureAlgorithm.RSA_PKCS1_V1_5_WITH_SHA512()
                );
            }
        } else if ("DSA".equalsIgnoreCase(keyAlgorithm)) {
            return Arrays.asList(
                    SignatureAlgorithm.DSA_WITH_SHA256(),
                    SignatureAlgorithm.VERITY_DSA_WITH_SHA256()
            );
        } else if ("EC".equalsIgnoreCase(keyAlgorithm)) {
            return Arrays.asList(
                    SignatureAlgorithm.ECDSA_WITH_SHA256(),
                    SignatureAlgorithm.VERITY_ECDSA_WITH_SHA256()
            );
        } else {
            throw new InvalidKeyException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }

    private static byte[] encodePublicKey(PublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] encodedPublicKey;
        try {
            encodedPublicKey =
                    KeyFactory.getInstance(publicKey.getAlgorithm())
                            .getKeySpec(publicKey, X509EncodedKeySpec.class)
                            .getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException(
                    "Failed to obtain X.509 encoded form of public key " + publicKey
                            + " of class " + publicKey.getClass().getName(),
                    e);
        }
        if ((encodedPublicKey == null) || (encodedPublicKey.length == 0)) {
            throw new InvalidKeyException(
                    "Failed to obtain X.509 encoded form of public key " + publicKey
                            + " of class " + publicKey.getClass().getName());
        }
        return encodedPublicKey;
    }

}
