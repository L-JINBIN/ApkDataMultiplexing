package bin.mt.apksign

import bin.mt.apksign.data.DataSource
import java.io.IOException
import java.io.OutputStream
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.function.Supplier
import kotlin.math.min

internal abstract class SignatureAlgorithm {
    lateinit var digest: ByteArray
        protected set
    lateinit var signature: ByteArray
        protected set
    abstract val id: Int
    abstract val minSdkVersion: Int
    abstract val keyAlgorithm: String
    abstract val signatureAlgorithm: String
    abstract val signatureAlgorithmParams: AlgorithmParameterSpec?

    @Throws(Exception::class)
    abstract fun computeDigest(
        beforeCentralDir: DataSource, centralDir: DataSource,
        eocd: DataSource
    )

    @Throws(Exception::class)
    fun verifySignature(
        publicKey: PublicKey,
        signedData: ByteArray,
        signatureBytes: ByteArray
    ): Boolean {
        val jcaSignatureAlgorithm = signatureAlgorithm
        val jcaSignatureAlgorithmParams = signatureAlgorithmParams
        return try {
            val signature = Signature.getInstance(jcaSignatureAlgorithm)
            signature.initVerify(publicKey)
            if (jcaSignatureAlgorithmParams != null) {
                signature.setParameter(jcaSignatureAlgorithmParams)
            }
            signature.update(signedData)
            signature.verify(signatureBytes)
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException(
                "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                        + " public key from certificate", e
            )
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException(
                "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                        + " public key from certificate", e
            )
        } catch (e: SignatureException) {
            throw SignatureException(
                "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                        + " public key from certificate", e
            )
        }
    }

    @Throws(Exception::class)
    fun computeSignature(privateKey: PrivateKey, publicKey: PublicKey, signedData: ByteArray) {
        val jcaSignatureAlgorithm = signatureAlgorithm
        val jcaSignatureAlgorithmParams = signatureAlgorithmParams
        val signatureBytes = try {
            val signature = Signature.getInstance(jcaSignatureAlgorithm)
            signature.initSign(privateKey)
            if (jcaSignatureAlgorithmParams != null) {
                signature.setParameter(jcaSignatureAlgorithmParams)
            }
            signature.update(signedData)
            signature.sign()
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException("Failed to sign using $jcaSignatureAlgorithm", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
        } catch (e: SignatureException) {
            throw SignatureException("Failed to sign using $jcaSignatureAlgorithm", e)
        }
        try {
            val signature = Signature.getInstance(jcaSignatureAlgorithm)
            signature.initVerify(publicKey)
            if (jcaSignatureAlgorithmParams != null) {
                signature.setParameter(jcaSignatureAlgorithmParams)
            }
            signature.update(signedData)
            if (!signature.verify(signatureBytes)) {
                throw SignatureException(
                    "Failed to verify generated "
                            + jcaSignatureAlgorithm
                            + " signature using public key from certificate"
                )
            }
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException(
                "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                        + " public key from certificate", e
            )
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException(
                "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                        + " public key from certificate", e
            )
        } catch (e: SignatureException) {
            throw SignatureException(
                "Failed to verify generated " + jcaSignatureAlgorithm + " signature using"
                        + " public key from certificate", e
            )
        }
        signature = signatureBytes
    }

    internal class BaseSignatureAlgorithm(
        override val id: Int,
        private val digestAlgorithm: String,
        override val keyAlgorithm: String,
        override val signatureAlgorithm: String,
        override val signatureAlgorithmParams: AlgorithmParameterSpec?
    ) : SignatureAlgorithm() {

        override val minSdkVersion = 24

        @Throws(Exception::class)
        override fun computeDigest(
            beforeCentralDir: DataSource,
            centralDir: DataSource,
            eocd: DataSource
        ) {
            val messageDigest1 = MessageDigest.getInstance(digestAlgorithm)
            val messageDigest2 = MessageDigest.getInstance(digestAlgorithm)
            val totalChunkSize = getChunkCount(
                beforeCentralDir.size()
            ) + getChunkCount(centralDir.size()) + getChunkCount(
                eocd.size()
            )
            val baos: OutputStream = object : OutputStream() {
                override fun write(b: Int) {
                    messageDigest2.update(b.toByte())
                }

                override fun write(b: ByteArray, off: Int, len: Int) {
                    messageDigest2.update(b, off, len)
                }
            }
            val prefix = ByteArray(5)
            prefix[0] = 0x5a.toByte()
            ByteArrayUtil.setInt(totalChunkSize, prefix, 1)
            baos.write(prefix)
            updateChunkContentDigest(messageDigest1, beforeCentralDir, baos)
            updateChunkContentDigest(messageDigest1, centralDir, baos)
            updateChunkContentDigest(messageDigest1, eocd, baos)
            digest = messageDigest2.digest()
        }
    }

    internal class BaseVeritySignatureAlgorithm(
        override val id: Int,
        override val keyAlgorithm: String,
        override val signatureAlgorithm: String,
        override val signatureAlgorithmParams: AlgorithmParameterSpec?
    ) : SignatureAlgorithm() {

        override val minSdkVersion = 28

        @Throws(Exception::class)
        override fun computeDigest(
            beforeCentralDir: DataSource,
            centralDir: DataSource,
            eocd: DataSource
        ) {
            val builder = VerityTreeBuilder(ByteArray(8))
            val rootHash = builder.generateVerityTreeRootHash(beforeCentralDir, centralDir, eocd)
            val result = ByteArray(rootHash.size + 8)
            System.arraycopy(rootHash, 0, result, 0, rootHash.size)
            val size = beforeCentralDir.size() + centralDir.size() + eocd.size()
            ByteArrayUtil.setLong(size, result, rootHash.size)
            digest = result
        }
    }

    companion object {
        protected val MAP: MutableMap<Int, Supplier<SignatureAlgorithm>> = HashMap()
        private const val ONE_MB = 1024 * 1024

        init {
            MAP[0x0101] =
                Supplier { RSA_PSS_WITH_SHA256() }
            MAP[0x0102] =
                Supplier { RSA_PSS_WITH_SHA512() }
            MAP[0x0103] =
                Supplier { RSA_PKCS1_V1_5_WITH_SHA256() }
            MAP[0x0104] =
                Supplier { RSA_PKCS1_V1_5_WITH_SHA512() }
            MAP[0x0201] =
                Supplier { ECDSA_WITH_SHA256() }
            MAP[0x0202] =
                Supplier { ECDSA_WITH_SHA512() }
            MAP[0x0301] =
                Supplier { DSA_WITH_SHA256() }
            MAP[0x0421] =
                Supplier { VERITY_RSA_PKCS1_V1_5_WITH_SHA256() }
            MAP[0x0423] =
                Supplier { VERITY_ECDSA_WITH_SHA256() }
            MAP[0x0425] =
                Supplier { VERITY_DSA_WITH_SHA256() }
        }

        fun isAlgorithmIdSupported(id: Int): Boolean {
            return MAP.containsKey(id)
        }

        fun getByAlgorithmId(id: Int): SignatureAlgorithm {
            val supplier = MAP[id]
                ?: throw RuntimeException(
                    "Unsupported signature algorithm id: 0x" + Integer.toHexString(
                        id
                    )
                )
            return supplier.get()
        }

        fun findByAlgorithmId(id: Int): SignatureAlgorithm? {
            val supplier = MAP[id] ?: return null
            return supplier.get()
        }

        fun RSA_PSS_WITH_SHA256(): SignatureAlgorithm {
            return BaseSignatureAlgorithm(
                0x0101, "SHA-256", "RSA", "SHA256withRSA/PSS",
                PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1)
            )
        }

        fun RSA_PSS_WITH_SHA512(): SignatureAlgorithm {
            return BaseSignatureAlgorithm(
                0x0102, "SHA-512", "RSA", "SHA512withRSA/PSS",
                PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1)
            )
        }

        fun RSA_PKCS1_V1_5_WITH_SHA256(): SignatureAlgorithm {
            return BaseSignatureAlgorithm(0x0103, "SHA-256", "RSA", "SHA256withRSA", null)
        }

        fun RSA_PKCS1_V1_5_WITH_SHA512(): SignatureAlgorithm {
            return BaseSignatureAlgorithm(0x0104, "SHA-512", "RSA", "SHA512withRSA", null)
        }

        fun ECDSA_WITH_SHA256(): SignatureAlgorithm {
            return BaseSignatureAlgorithm(0x0201, "SHA-256", "EC", "SHA256withECDSA", null)
        }

        fun ECDSA_WITH_SHA512(): SignatureAlgorithm {
            return BaseSignatureAlgorithm(0x0202, "SHA-256", "EC", "SHA512withECDSA", null)
        }

        fun DSA_WITH_SHA256(): SignatureAlgorithm {
            return BaseSignatureAlgorithm(0x0301, "SHA-256", "DSA", "SHA256withDSA", null)
        }

        fun VERITY_RSA_PKCS1_V1_5_WITH_SHA256(): SignatureAlgorithm {
            return BaseVeritySignatureAlgorithm(0x0421, "RSA", "SHA256withRSA", null)
        }

        fun VERITY_ECDSA_WITH_SHA256(): SignatureAlgorithm {
            return BaseVeritySignatureAlgorithm(0x0423, "EC", "SHA256withECDSA", null)
        }

        fun VERITY_DSA_WITH_SHA256(): SignatureAlgorithm {
            return BaseVeritySignatureAlgorithm(0x0425, "DSA", "SHA256withDSA", null)
        }

        @Throws(IOException::class)
        private fun updateChunkContentDigest(
            contentDigest: MessageDigest, dataSource: DataSource,
            output: OutputStream
        ) {
            val chunkCount = getChunkCount(dataSource.size())
            val chunkContentPrefix = ByteArray(5)
            chunkContentPrefix[0] = 0xa5.toByte()
            for (i in 0 until chunkCount) {
                val start = dataSource.pos()
                val end = min(start + ONE_MB, dataSource.size())
                val chunkSize = (end - start).toInt()
                ByteArrayUtil.setInt(chunkSize, chunkContentPrefix, 1)
                contentDigest.update(chunkContentPrefix)
                dataSource.copyTo(contentDigest, chunkSize.toLong())
                val digest = contentDigest.digest()
                // PrintUtil.printDigest(digest);
                output.write(digest)
            }
        }

        private fun getChunkCount(inputSize: Long): Int {
            return ((inputSize + ONE_MB - 1) / ONE_MB).toInt()
        }
    }
}