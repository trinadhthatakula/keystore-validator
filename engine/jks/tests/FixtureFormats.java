import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;

// Test-only converter: all keys are freshly generated in a temporary directory.
public class FixtureFormats {
    public static void main(String[] args) throws Exception {
        char[] storePass = "café🔑pass".toCharArray();
        KeyStore source = KeyStore.getInstance("JKS");
        try (var in = new FileInputStream(args[0])) { source.load(in, storePass); }
        KeyStore out = KeyStore.getInstance("PKCS12");
        out.load(null, storePass);
        for (String[] item : new String[][]{{"alpha", "keypass1", "different1"}, {"café-😀", "keypass2", "different2"}}) {
            var key = source.getKey(item[0], item[1].toCharArray());
            out.setKeyEntry(item[0], key, item[2].toCharArray(), source.getCertificateChain(item[0]));
        }
        out.setCertificateEntry("trusted", source.getCertificate("alpha"));
        try (var file = new FileOutputStream(args[1])) { out.store(file, storePass); }
        if (args.length > 2) {
            var key = (PrivateKey)source.getKey("alpha", "keypass1".toCharArray());
            Files.write(Path.of(args[2]), key.getEncoded());
        }
        if (args.length > 3) {
            KeyStore emptyPassword = KeyStore.getInstance("PKCS12");
            emptyPassword.load(null, new char[0]);
            emptyPassword.setCertificateEntry("trusted-empty", source.getCertificate("alpha"));
            try (var file = new FileOutputStream(args[3])) { emptyPassword.store(file, new char[0]); }
        }
    }
}
