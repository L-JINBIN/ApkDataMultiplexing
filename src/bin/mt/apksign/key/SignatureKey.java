package bin.mt.apksign.key;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface SignatureKey {

    X509Certificate getCertificate() throws Exception;

    PrivateKey getPrivateKey() throws Exception;

}
