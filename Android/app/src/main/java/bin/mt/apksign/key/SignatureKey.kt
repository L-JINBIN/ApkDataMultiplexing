package bin.mt.apksign.key

import java.security.PrivateKey
import java.security.cert.X509Certificate

interface SignatureKey {
    @get:Throws(Exception::class)
    val certificate: X509Certificate

    @get:Throws(Exception::class)
    val privateKey: PrivateKey
}