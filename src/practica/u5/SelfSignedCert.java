package practica.u5;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

public class SelfSignedCert {
    private static final Path KEYSTORE_PATH = Paths.get("security", "server-keystore.p12");
    private static final String STORE_TYPE = "PKCS12";
    private static final String ALIAS = "psp-server";
    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String DNAME = "CN=PSP-Server, OU=PSP, O=School, L=Palma, ST=Balears, C=ES";

    public static final class ServerIdentity {
        public final PrivateKey privateKey;
        public final X509Certificate certificate;

        public ServerIdentity(PrivateKey privateKey, X509Certificate certificate) {
            this.privateKey = privateKey;
            this.certificate = certificate;
        } 
    }

    public static ServerIdentity loadOrCreateServerIdentity() {
        try {
            createKeystoreIfMissing();

            KeyStore ks = KeyStore.getInstance(STORE_TYPE);
            try (InputStream in = Files.newInputStream(KEYSTORE_PATH)) {
                ks.load(in, PASSWORD);
            }

            PrivateKey privateKey = (PrivateKey) ks.getKey(ALIAS, PASSWORD); //carga del keystore PrivateKey del servidor
            X509Certificate cert = (X509Certificate) ks.getCertificate(ALIAS); // X509Certificate autofirmado
            if (privateKey == null || cert == null) {
                throw new IllegalStateException("Keystore entry not found: " + ALIAS);
            }
            return new ServerIdentity(privateKey, cert);
        } catch (Exception ex) {
            throw new IllegalStateException("Could not load/create server certificate", ex);
        }
    }

    private static void createKeystoreIfMissing() throws Exception { // // Si no existe server-keystore.p12, lo crea con keytool
        if (Files.exists(KEYSTORE_PATH)) {
            return;
        }

        Path parent = KEYSTORE_PATH.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        List<String> cmd = List.of(
            "keytool",
            "-genkeypair",
            "-alias", ALIAS,
            "-keyalg", "RSA",
            "-keysize", "2048",
            "-validity", "365",
            "-storetype", STORE_TYPE,
            "-keystore", KEYSTORE_PATH.toString(),
            "-storepass", new String(PASSWORD),
            "-keypass", new String(PASSWORD),
            "-dname", DNAME,
            "-noprompt"
        );

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        int exit = p.waitFor();
        if (exit != 0) {
            throw new IllegalStateException("keytool failed with exit code " + exit);
        }
    }

    public static X509Certificate decode(byte[] certBytes) { //Parsea X.509
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid certificate bytes", ex);
        }
    }

    public static PublicKey validateAndGetPublicKey(byte[] certBytes) {
        try {
            X509Certificate cert = decode(certBytes);
            cert.checkValidity(); // Comprueba validez temporal (cert.checkValidity(),
            cert.verify(cert.getPublicKey()); // verifica firma autofirmada
            return cert.getPublicKey(); // si tot va be, extreu PublicKey
        } catch (Exception ex) {
            throw new IllegalStateException("Certificate validation failed", ex);
        }
    }
}
