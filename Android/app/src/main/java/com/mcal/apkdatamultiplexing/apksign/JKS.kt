package com.mcal.apkdatamultiplexing.apksign

import org.jetbrains.annotations.Contract
import java.io.*
import java.nio.charset.StandardCharsets
import java.security.*
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*
import javax.crypto.EncryptedPrivateKeyInfo
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

class JKS : KeyStoreSpi() {
    private val aliases: Vector<String> = Vector()
    private val trustedCerts: HashMap<String, Certificate?> = HashMap()
    private val privateKeys: HashMap<String, ByteArray> = HashMap()
    private val certChains: HashMap<String, Array<Certificate?>> = HashMap()
    private val dates: HashMap<String, Date> = HashMap()

    @Throws(NoSuchAlgorithmException::class, UnrecoverableKeyException::class)
    override fun engineGetKey(alias: String, password: CharArray): Key? {
        val finalAlias = alias.lowercase(Locale.getDefault())
        if (!privateKeys.containsKey(finalAlias)) {
            return null
        }
        privateKeys[finalAlias]?.let { privateKey ->
            val key = decryptKey(privateKey, charsToBytes(password))
            engineGetCertificateChain(finalAlias)?.let { chain ->
                return if (chain.isNotEmpty()) {
                    try {
                        // Private and public keys MUST have the same algorithm.
                        chain[0]?.publicKey?.algorithm?.let { publicKeyAlgorithm ->
                            val fact = KeyFactory.getInstance(publicKeyAlgorithm)
                            fact.generatePrivate(PKCS8EncodedKeySpec(key))
                        }
                    } catch (x: InvalidKeySpecException) {
                        throw UnrecoverableKeyException(x.message)
                    }
                } else {
                    SecretKeySpec(key, finalAlias)
                }
            }
        }
        return null
    }

    override fun engineGetCertificateChain(alias: String): Array<Certificate?>? {
        return certChains[alias.lowercase(Locale.getDefault())]
    }

    override fun engineGetCertificate(pAlias: String): Certificate? {
        val finalAlias = pAlias.lowercase(Locale.getDefault())
        if (engineIsKeyEntry(finalAlias)) {
            certChains[finalAlias]?.takeIf { it.isNotEmpty() }?.let { certChain ->
                return certChain[0]
            }
        }
        return trustedCerts[finalAlias]
    }

    override fun engineGetCreationDate(alias: String): Date? {
        return dates[alias.lowercase(Locale.getDefault())]
    }

    @Throws(KeyStoreException::class)
    override fun engineSetKeyEntry(
        pAlias: String,
        key: Key,
        passwd: CharArray,
        certChain: Array<Certificate?>?
    ) {
        val alias = pAlias.lowercase(Locale.getDefault())
        if (trustedCerts.containsKey(alias)) {
            throw KeyStoreException("\"$alias is a trusted certificate entry")
        }
        privateKeys[alias] = encryptKey(key, charsToBytes(passwd))
        certChain?.let {
            certChains[alias] = certChain
        } ?: run {
            certChains[alias] = arrayOfNulls(0)
        }
        if (!aliases.contains(alias)) {
            dates[alias] = Date()
            aliases.add(alias)
        }
    }

    @Throws(KeyStoreException::class)
    override fun engineSetKeyEntry(
        pAlias: String,
        encodedKey: ByteArray,
        certChain: Array<Certificate?>?
    ) {
        val alias = pAlias.lowercase(Locale.getDefault())
        if (trustedCerts.containsKey(alias)) throw KeyStoreException("\"$alias\" is a trusted certificate entry")
        try {
            EncryptedPrivateKeyInfo(encodedKey)
        } catch (ioe: IOException) {
            throw KeyStoreException("encoded key is not an EncryptedPrivateKeyInfo")
        }
        privateKeys[alias] = encodedKey
        certChain?.let {
            certChains[alias] = certChain
        } ?: run {
            certChains[alias] = arrayOfNulls(0)
        }
        if (!aliases.contains(alias)) {
            dates[alias] = Date()
            aliases.add(alias)
        }
    }

    @Throws(KeyStoreException::class)
    override fun engineSetCertificateEntry(pAlias: String, cert: Certificate?) {
        val alias = pAlias.lowercase(Locale.getDefault())
        if (privateKeys.containsKey(alias)) {
            throw KeyStoreException("\"$alias\" is a private key entry")
        }
        if (cert == null) {
            throw NullPointerException()
        }
        trustedCerts[alias] = cert
        if (!aliases.contains(alias)) {
            dates[alias] = Date()
            aliases.add(alias)
        }
    }

    override fun engineDeleteEntry(alias: String) {
        aliases.remove(alias.lowercase(Locale.getDefault()))
    }

    override fun engineAliases(): Enumeration<String>? {
        return aliases.elements()
    }

    override fun engineContainsAlias(alias: String): Boolean {
        return aliases.contains(alias.lowercase(Locale.getDefault()))
    }

    override fun engineSize(): Int {
        return aliases.size
    }

    override fun engineIsKeyEntry(alias: String): Boolean {
        return privateKeys.containsKey(alias.lowercase(Locale.getDefault()))
    }

    override fun engineIsCertificateEntry(alias: String): Boolean {
        return trustedCerts.containsKey(alias.lowercase(Locale.getDefault()))
    }

    override fun engineGetCertificateAlias(cert: Certificate): String? {
        for (alias in trustedCerts.keys) {
            if (cert == trustedCerts[alias]) {
                return alias
            }
        }
        return null
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, CertificateException::class)
    override fun engineStore(out: OutputStream, passwd: CharArray) {
        MessageDigest.getInstance("SHA1").apply {
            update(charsToBytes(passwd))
            update("Mighty Aphrodite".toByteArray(StandardCharsets.UTF_8))
        }.also { messageDigest ->
            val dout = DataOutputStream(DigestOutputStream(out, messageDigest))
            dout.writeInt(MAGIC)
            dout.writeInt(2)
            dout.writeInt(aliases.size)
            val e = aliases.elements()
            while (e.hasMoreElements()) {
                val alias = e.nextElement()
                if (trustedCerts.containsKey(alias)) {
                    dout.writeInt(TRUSTED_CERT)
                    dout.writeUTF(alias)
                    dates[alias]?.let { date ->
                        dout.writeLong(date.time)
                    }
                    trustedCerts[alias]?.let { cert ->
                        writeCert(dout, cert)
                    }

                } else {
                    dout.writeInt(PRIVATE_KEY)
                    dout.writeUTF(alias)
                    dates[alias]?.let { date ->
                        dout.writeLong(date.time)
                    }
                    privateKeys[alias]?.let { key ->
                        dout.writeInt(key.size)
                        dout.write(key)
                    }
                    certChains[alias]?.let { chain ->
                        dout.writeInt(chain.size)
                        for (certificate in chain) {
                            certificate?.let {
                                writeCert(dout, certificate)
                            }
                        }
                    }
                }
            }
            val digest = messageDigest.digest()
            dout.write(digest)
        }
    }

    @Throws(IOException::class, NoSuchAlgorithmException::class, CertificateException::class)
    override fun engineLoad(inputStream: InputStream?, passwd: CharArray?) {
        MessageDigest.getInstance("SHA").apply {
            passwd?.let {
                update(charsToBytes(passwd))
            }
            update("Mighty Aphrodite".toByteArray(StandardCharsets.UTF_8)) // HAR HAR
        }.also { messageDigest ->
            aliases.clear()
            trustedCerts.clear()
            privateKeys.clear()
            certChains.clear()
            dates.clear()
            if (inputStream == null) {
                return
            }
            val din = DataInputStream(DigestInputStream(inputStream, messageDigest))
            if (din.readInt() != MAGIC) {
                throw IOException("not a JavaKeyStore")
            }
            din.readInt() // version no.
            val n = din.readInt()
            aliases.ensureCapacity(n)
            if (n < 0) {
                throw LoadKeystoreException("Malformed key store")
            }
            for (i in 0 until n) {
                val type = din.readInt()
                val alias = din.readUTF()
                aliases.add(alias)
                dates[alias] = Date(din.readLong())
                when (type) {
                    PRIVATE_KEY -> {
                        val len = din.readInt()
                        val encoded = ByteArray(len)
                        din.read(encoded)
                        privateKeys[alias] = encoded
                        val count = din.readInt()
                        val chain = arrayOfNulls<Certificate>(count)
                        var j = 0
                        while (j < count) {
                            chain[j] = readCert(din)
                            j++
                        }
                        certChains[alias] = chain
                    }

                    TRUSTED_CERT -> trustedCerts[alias] = readCert(din)
                    else -> throw LoadKeystoreException("Malformed key store")
                }
            }
            passwd?.let {
                val computedHash = messageDigest.digest()
                val storedHash = ByteArray(20)
                din.read(storedHash)
                if (!MessageDigest.isEqual(storedHash, computedHash)) {
                    throw LoadKeystoreException("Incorrect password, or integrity check failed.")
                }
            }
        }

    }

    companion object {
        private const val MAGIC = -0x1120113
        private const val PRIVATE_KEY = 1
        private const val TRUSTED_CERT = 2

        @Throws(IOException::class, CertificateException::class)
        private fun readCert(inputStream: DataInputStream): Certificate {
            val type = inputStream.readUTF()
            val len = inputStream.readInt()
            val encoded = ByteArray(len)
            inputStream.read(encoded)
            val factory = CertificateFactory.getInstance(type)
            return factory.generateCertificate(ByteArrayInputStream(encoded))
        }

        @Throws(IOException::class, CertificateException::class)
        private fun writeCert(dout: DataOutputStream, cert: Certificate) {
            dout.writeUTF(cert.type)
            val b = cert.encoded
            dout.writeInt(b.size)
            dout.write(b)
        }

        @Throws(UnrecoverableKeyException::class)
        private fun decryptKey(encryptedPKI: ByteArray, passwd: ByteArray): ByteArray {
            return try {
                val epki = EncryptedPrivateKeyInfo(encryptedPKI)
                val encr = epki.encryptedData
                val keystream = ByteArray(20)
                System.arraycopy(encr, 0, keystream, 0, 20)
                val check = ByteArray(20)
                System.arraycopy(encr, encr.size - 20, check, 0, 20)
                val key = ByteArray(encr.size - 40)
                val sha = MessageDigest.getInstance("SHA1")
                var count = 0
                while (count < key.size) {
                    sha.reset()
                    sha.update(passwd)
                    sha.update(keystream)
                    sha.digest(keystream, 0, keystream.size)
                    var i = 0
                    while (i < keystream.size && count < key.size) {
                        key[count] = (keystream[i] xor encr[count + 20])
                        count++
                        i++
                    }
                }
                sha.reset()
                sha.update(passwd)
                sha.update(key)
                if (!MessageDigest.isEqual(check, sha.digest())) {
                    throw UnrecoverableKeyException("checksum mismatch")
                }
                key
            } catch (e: Exception) {
                throw UnrecoverableKeyException(e.message)
            }
        }

        @Throws(KeyStoreException::class)
        private fun encryptKey(key: Key, passwd: ByteArray): ByteArray {
            return try {
                val sha = MessageDigest.getInstance("SHA1")
                val k = key.encoded
                val encrypted = ByteArray(k.size + 40)
                val keyStream = SecureRandom.getSeed(20)
                System.arraycopy(keyStream, 0, encrypted, 0, 20)
                var count = 0
                while (count < k.size) {
                    sha.reset()
                    sha.update(passwd)
                    sha.update(keyStream)
                    sha.digest(keyStream, 0, keyStream.size)
                    var i = 0
                    while (i < keyStream.size && count < k.size) {
                        encrypted[count + 20] = (keyStream[i] xor k[count])
                        count++
                        i++
                    }
                }
                sha.reset()
                sha.update(passwd)
                sha.update(k)
                sha.digest(encrypted, encrypted.size - 20, 20)
                EncryptedPrivateKeyInfo("1.3.6.1.4.1.42.2.17.1.1", encrypted).encoded
            } catch (x: Exception) {
                throw KeyStoreException(x.message)
            }
        }

        @Contract(pure = true)
        private fun charsToBytes(passwd: CharArray): ByteArray {
            val buf = ByteArray(passwd.size * 2)
            var i = 0
            var j = 0
            while (i < passwd.size) {
                buf[j++] = (passwd[i].code ushr 8).toByte()
                buf[j++] = passwd[i].code.toByte()
                i++
            }
            return buf
        }
    }
}

class LoadKeystoreException(message: String?) : IOException(message)