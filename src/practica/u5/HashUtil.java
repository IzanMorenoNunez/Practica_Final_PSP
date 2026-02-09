package practica.u5;

import java.security.MessageDigest;

public class HashUtil {
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }
}
