package bin.mt.apksign.key

import com.mcal.apkdatamultiplexing.apksign.JksKeyStore
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate

class JksSignatureKey(file: File, storePassword: String, alias: String, aliasPassword: String) :
    SignatureKey {
    override val certificate: X509Certificate
    override val privateKey: PrivateKey

    constructor(path: String, storePassword: String, alias: String, aliasPassword: String) : this(
        File(path),
        storePassword,
        alias,
        aliasPassword
    )

    init {
        val keyStore = loadKeyStore(FileInputStream(file), storePassword.toCharArray())
        certificate = keyStore.getCertificate(alias) as X509Certificate
        privateKey = keyStore.getKey(alias, aliasPassword.toCharArray()) as PrivateKey
    }

    @Throws(Exception::class)
    private fun loadKeyStore(keystorePath: FileInputStream, password: CharArray): KeyStore {
        var keyStore: KeyStore
        try {
            keyStore = KeyStore.getInstance("jks")
            keyStore.load(keystorePath, password)
        } catch (e: Exception) {
            val provider = BouncyCastleProvider()
            Security.addProvider(provider)
            try {
                keyStore = JksKeyStore(provider)
                keyStore.load(keystorePath, password)
            } catch (e: Exception) {
                try {
                    keyStore = KeyStore.getInstance("bks", provider)
                    keyStore.load(keystorePath, password)
                } catch (e: Exception) {
                    throw RuntimeException("Failed to load keystore: " + e.message)
                }
            }
        } finally {
            keystorePath.close()
        }
        return keyStore
    }
}