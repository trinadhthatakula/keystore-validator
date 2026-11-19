import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

class EmptyStore {
    public static void main(String[] args) throws Exception {
        Certificate cert;
        try (var in = new FileInputStream(args[0])) {
            cert = CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, new char[0]);
        store.setCertificateEntry("empty-pass", cert);
        try (var out = new FileOutputStream(args[1])) {
            store.store(out, new char[0]);
        }
    }
}
