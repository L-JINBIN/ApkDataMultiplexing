package bin.mt.apksign;

import bin.mt.apksign.data.DataSource;

import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

import static bin.mt.apksign.ByteArrayUtil.setInt;

abstract class SignatureAlgorithm {
    protected static final Map<Integer, Supplier<SignatureAlgorithm>> MAP = new HashMap<>();
    private static final int ONE_MB = 1024 * 1024;
    protected byte[] digest;
    protected byte[] signature;

    static {
        MAP.put(0x0101, SignatureAlgorithm::RSA_PSS_WITH_SHA256);
        MAP.put(0x0102, SignatureAlgorithm::RSA_PSS_WITH_SHA512);
        MAP.put(0x0103, SignatureAlgorithm::RSA_PKCS1_V1_5_WITH_SHA256);
        MAP.put(0x0104, SignatureAlgorithm::RSA_PKCS1_V1_5_WITH_SHA512);
        MAP.put(0x0201, SignatureAlgorithm::ECDSA_WITH_SHA256);
        MAP.put(0x0202, SignatureAlgorithm::ECDSA_WITH_SHA512);
        MAP.put(0x0301, SignatureAlgorithm::DSA_WITH_SHA256);
        MAP.put(0x0421, SignatureAlgorithm::VERITY_RSA_PKCS1_V1_5_WITH_SHA256);
        MAP.put(0x0423, SignatureAlgorithm::VERITY_ECDSA_WITH_SHA256);
        MAP.put(0x0425, SignatureAlgorithm::VERITY_DSA_WITH_SHA256);
    }

    static boolean isAlgorithmIdSupported(int id) {
        return MAP.containsKey(id);
    }

    static SignatureAlgorithm getByAlgorithmId(int id) {
        Supplier<SignatureAlgorithm> supplier = MAP.get(id);
        if (supplier == null) {
            throw new RuntimeException("Unsupported signature algorithm id: 0x" + Integer.toHexString(id));
        }
        return supplier.get();
    }

    static SignatureAlgorithm findByAlgorithmId(int id) {
        Supplier<SignatureAlgorithm> supplier = MAP.get(id);
        if (supplier == null) {
            return null;
        }
        return supplier.get();
    }

    static SignatureAlgorithm RSA_PSS_WITH_SHA256() {
        return new BaseSignatureAlgorithm(0x0101, "SHA-256", "RSA", "SHA256withRSA/PSS",
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1));
    }

    static SignatureAlgorithm RSA_PSS_WITH_SHA512() {
        return new BaseSignatureAlgorithm(0x0102, "SHA-512", "RSA", "SHA512withRSA/PSS",
                new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1));
    }

    static SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA256() {
        return new BaseSignatureAlgorithm(0x0103, "SHA-256", "RSA", "SHA256withRSA", null);
    }

    static SignatureAlgorithm RSA_PKCS1_V1_5_WITH_SHA512() {
        return new BaseSignatureAlgorithm(0x0104, "SHA-512", "RSA", "SHA512withRSA", null);
    }

    static SignatureAlgorithm ECDSA_WITH_SHA256() {
        return new BaseSignatureAlgorithm(0x0201, "SHA-256", "EC", "SHA256withECDSA", null);
    }

    static SignatureAlgorithm ECDSA_WITH_SHA512() {
        return new BaseSignatureAlgorithm(0x0202, "SHA-256", "EC", "SHA512withECDSA", null);
    }

    static SignatureAlgorithm DSA_WITH_SHA256() {
        return new BaseSignatureAlgorithm(0x0301, "SHA-256", "DSA", "SHA256withDSA", null);
    }

    static SignatureAlgorithm VERITY_RSA_PKCS1_V1_5_WITH_SHA256() {
        return new BaseVeritySignatureAlgorithm(0x0421, "RSA", "SHA256withRSA", null);
    }

    static SignatureAlgorithm VERITY_ECDSA_WITH_SHA256() {
        return new BaseVeritySignatureAlgorithm(0x0423, "EC", "SHA256withECDSA", null);
    }

    static SignatureAlgorithm VERITY_DSA_WITH_SHA256() {
        return new BaseVeritySignatureAlgorithm(0x0425, "DSA", "SHA256withDSA", null);
    }

    private static void updateChunkContentDigest(MessageDigest contentDigest, DataSource dataSource,
                                                 OutputStream output) throws IOException {
        int chunkCount = getChunkCount(dataSource.size());

        byte[] chunkContentPrefix = new byte[5];
        chunkContentPrefix[0] = (byte) 0xa5;
        for (int i = 0; i < chunkCount; i++) {
            long start = dataSource.pos();
            long end = Math.min(start + ONE_MB, dataSource.size());
            int chunkSize = (int) (end - start);
            setInt(chunkSize, chunkContentPrefix, 1);

            contentDigest.update(chunkContentPrefix);
            dataSource.copyTo(contentDigest, chunkSize);

            byte[] digest = contentDigest.digest();
            // PrintUtil.printDigest(digest);
            output.write(digest);
        }
    }

    private static int getChunkCount(long inputSize) {
        return (int) ((inputSize + ONE_MB - 1) / ONE_MB);
    }

    public abstract int getId();

    public abstract int getMinSdkVersion();

    public abstract String getKeyAlgorithm();

    public abstract String getSignatureAlgorithm();

    public abstract AlgorithmParameterSpec getSignatureAlgorithmParams();

    public abstract void computeDigest(DataSource beforeCentralDir, DataSource centralDir,
                                       DataSource eocd) throws Exception;

    boolean verifySignature(PublicKey publicKey, byte[] signedData, byte[] signatureBytes) throws Exception {
        String jcaSignatureAlgorithm = getSignatureAlgorithm();
        AlgorithmParameterSpec jcaSignatureAlgorithmParams = getSignatureAlgorithmParams();
        try {
            Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
            signature.initVerify(publicKey);
            if (jcaSignatureAlgorithmParams != null) {
                signature.setParameter(jcaSignatureAlgorithmParams);
            }
            signature.update(signedData);
            return signature.verify(signatureBytes);
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException(
                    "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                            + " public key from certificate", e);
        } catch (InvalidAlgorithmParameterException | SignatureException e) {
            throw new SignatureException(
                    "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                            + " public key from certificate", e);
        }
    }

    void computeSignature(PrivateKey privateKey, PublicKey publicKey, byte[] signedData) throws Exception {
        String jcaSignatureAlgorithm = getSignatureAlgorithm();
        AlgorithmParameterSpec jcaSignatureAlgorithmParams = getSignatureAlgorithmParams();
        byte[] signatureBytes;
        try {
            Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
            signature.initSign(privateKey);
            if (jcaSignatureAlgorithmParams != null) {
                signature.setParameter(jcaSignatureAlgorithmParams);
            }
            signature.update(signedData);
            signatureBytes = signature.sign();
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException("Failed to sign using " + jcaSignatureAlgorithm, e);
        } catch (InvalidAlgorithmParameterException | SignatureException e) {
            throw new SignatureException("Failed to sign using " + jcaSignatureAlgorithm, e);
        }
        try {
            Signature signature = Signature.getInstance(jcaSignatureAlgorithm);
            signature.initVerify(publicKey);
            if (jcaSignatureAlgorithmParams != null) {
                signature.setParameter(jcaSignatureAlgorithmParams);
            }
            signature.update(signedData);
            if (!signature.verify(signatureBytes)) {
                throw new SignatureException("Failed to verify generated "
                        + jcaSignatureAlgorithm
                        + " signature using public key from certificate");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeyException(
                    "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                            + " public key from certificate", e);
        } catch (InvalidAlgorithmParameterException | SignatureException e) {
            throw new SignatureException(
                    "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                            + " public key from certificate", e);
        }
        signature = signatureBytes;
    }

    public byte[] getDigest() {
        return digest;
    }

    public byte[] getSignature() {
        return signature;
    }

    static class BaseSignatureAlgorithm extends SignatureAlgorithm {
        private int id;
        private String digestAlgorithm;
        private String keyAlgorithm;
        private String signatureAlgorithm;
        private AlgorithmParameterSpec signatureAlgorithmParams;

        BaseSignatureAlgorithm(int id, String digestAlgorithm, String keyAlgorithm, String signatureAlgorithm, AlgorithmParameterSpec signatureAlgorithmParams) {
            this.id = id;
            this.digestAlgorithm = digestAlgorithm;
            this.keyAlgorithm = keyAlgorithm;
            this.signatureAlgorithm = signatureAlgorithm;
            this.signatureAlgorithmParams = signatureAlgorithmParams;
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        public int getMinSdkVersion() {
            return 24;
        }

        @Override
        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        @Override
        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        @Override
        public AlgorithmParameterSpec getSignatureAlgorithmParams() {
            return signatureAlgorithmParams;
        }

        @Override
        public void computeDigest(DataSource beforeCentralDir, DataSource centralDir, DataSource eocd) throws Exception {
            MessageDigest messageDigest1 = MessageDigest.getInstance(digestAlgorithm);
            MessageDigest messageDigest2 = MessageDigest.getInstance(digestAlgorithm);
            int totalChunkSize = getChunkCount(beforeCentralDir.size()) + getChunkCount(centralDir.size()) + getChunkCount(eocd.size());
            OutputStream baos = new OutputStream() {
                @Override
                public void write(int b) {
                    messageDigest2.update((byte) b);
                }

                @Override
                public void write(byte[] b, int off, int len) {
                    messageDigest2.update(b, off, len);
                }
            };
            byte[] prefix = new byte[5];
            prefix[0] = (byte) 0x5a;
            setInt(totalChunkSize, prefix, 1);
            baos.write(prefix);

            updateChunkContentDigest(messageDigest1, beforeCentralDir, baos);
            updateChunkContentDigest(messageDigest1, centralDir, baos);
            updateChunkContentDigest(messageDigest1, eocd, baos);

            digest = messageDigest2.digest();
        }
    }

    static class BaseVeritySignatureAlgorithm extends SignatureAlgorithm {
        private int id;
        private String signatureAlgorithm;
        private String keyAlgorithm;
        private AlgorithmParameterSpec signatureAlgorithmParams;

        BaseVeritySignatureAlgorithm(int id, String keyAlgorithm, String signatureAlgorithm, AlgorithmParameterSpec signatureAlgorithmParams) {
            this.id = id;
            this.keyAlgorithm = keyAlgorithm;
            this.signatureAlgorithm = signatureAlgorithm;
            this.signatureAlgorithmParams = signatureAlgorithmParams;
        }

        @Override
        public int getId() {
            return id;
        }

        @Override
        public int getMinSdkVersion() {
            return 28;
        }

        @Override
        public String getKeyAlgorithm() {
            return keyAlgorithm;
        }

        @Override
        public String getSignatureAlgorithm() {
            return signatureAlgorithm;
        }

        @Override
        public AlgorithmParameterSpec getSignatureAlgorithmParams() {
            return signatureAlgorithmParams;
        }

        @Override
        public void computeDigest(DataSource beforeCentralDir, DataSource centralDir, DataSource eocd) throws Exception {
            VerityTreeBuilder builder = new VerityTreeBuilder(new byte[8]);
            byte[] rootHash = builder.generateVerityTreeRootHash(beforeCentralDir, centralDir, eocd);
            byte[] result = new byte[rootHash.length + 8];
            System.arraycopy(rootHash, 0, result, 0, rootHash.length);
            long size = beforeCentralDir.size() + centralDir.size() + eocd.size();
            ByteArrayUtil.setLong(size, result, rootHash.length);
            digest = result;
        }
    }

}
