package bin.mt.apksign.key;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class JksSignatureKey implements SignatureKey {
    private X509Certificate certificate;
    private PrivateKey privateKey;

    public JksSignatureKey(String path, String storePassword, String alias, String aliasPassword) throws Exception {
        this(new File(path), storePassword, alias, aliasPassword);
    }

    public JksSignatureKey(File file, String storePassword, String alias, String aliasPassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        keyStore.load(new FileInputStream(file), storePassword.toCharArray());
        certificate = (X509Certificate) keyStore.getCertificate(alias);
        privateKey = (PrivateKey) keyStore.getKey(alias, aliasPassword.toCharArray());
    }

    @Override
    public X509Certificate getCertificate() {
        return certificate;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
