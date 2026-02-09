package practica.u5;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;
import javax.crypto.SecretKey;

public class Client {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try (Socket socket = new Socket(HOST, PORT);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.flush();

            out.writeObject("PUBLIC_KEY_REQ"); // missatge de control per demanar clau a servidor
            out.flush();

            Object response = in.readObject();
            if (!(response instanceof PublicKey)) {
                System.out.println("Unexpected response.");
                return;
            }

            PublicKey serverPublicKey = (PublicKey) response;
            System.out.println("Public key received: " + serverPublicKey.getAlgorithm());

            SecretKey sharedKey = AES_Simetric.keygenKeyGeneration(128);
            byte[] keyBytes = sharedKey.getEncoded();
            byte[] keyHash = HashUtil.sha256(keyBytes);

            byte[] encryptedKey = RSA_Asimetric.encryptData(keyBytes, serverPublicKey);
            byte[] encryptedHash = RSA_Asimetric.encryptData(keyHash, serverPublicKey);

            Packet keyPacket = new Packet(encryptedKey, encryptedHash);
            out.writeObject(keyPacket);
            out.flush();

            System.out.println("Shared key (encrypted) sent to server.");
        } catch (Exception ex) {
            System.err.println("Client error: " + ex);
        }
    }
}
