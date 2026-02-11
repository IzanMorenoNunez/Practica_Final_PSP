package practica.u5;

import java.security.MessageDigest;

// Esta clase ncapsula el cálculo de hash para que el resto del código sea más limpio y no repitamos el mismo bloque cada vez.

// Cuando el cliente envía la clave AES, también envía su hash.
// El servidor vuelve a calcular el hash y compara

public class HashUtil {
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data); // devuelve el resultado como byte[]
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    } 
}
