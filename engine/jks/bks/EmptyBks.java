import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// keytool enforces a minimum password length; this creates a valid empty-password fixture.
public class EmptyBks {
  public static void main(String[] args) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    var ks = KeyStore.getInstance(args.length > 2 ? args[2] : "BKS", "BC");
    ks.load(null, new char[0]);
    try (var in = Files.newInputStream(Path.of(args[0]))) {
      ks.setCertificateEntry("empty-pass", CertificateFactory.getInstance("X.509").generateCertificate(in));
    }
    try (var out = Files.newOutputStream(Path.of(args[1]))) { ks.store(out, new char[0]); }
  }
}
