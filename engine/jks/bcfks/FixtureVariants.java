import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Security;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.jcajce.BCFKSLoadStoreParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Test-only variants using a freshly generated BCFKS store.
public class FixtureVariants {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        char[] password = "café🔑pass".toCharArray();
        KeyStore store = KeyStore.getInstance("BCFKS", "BC");
        try (var in = new FileInputStream(args[0])) { store.load(in, password); }
        try (var out = new FileOutputStream(args[1])) {
            var settings = new BCFKSLoadStoreParameter.Builder(out, password)
                .withStorePBKDFConfig(new ScryptConfig.Builder(1024, 8, 1).build()).build();
            store.store(settings);
        }
        try (var out = new FileOutputStream(args[2])) {
            var settings = new BCFKSLoadStoreParameter.Builder(out, password)
                .withStorePBKDFConfig(new PBKDF2Config.Builder().withIterationCount(2048).withSaltLength(32).withPRF(PBKDF2Config.PRF_SHA3_512).build())
                .withStoreMacAlgorithm(BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA3_512).build();
            store.store(settings);
        }
        KeyStore empty = KeyStore.getInstance("BCFKS", "BC");
        empty.load(null, new char[0]);
        empty.setCertificateEntry("empty", store.getCertificate("fips"));
        try (var out = new FileOutputStream(args[3])) { empty.store(out, new char[0]); }
    }
}
