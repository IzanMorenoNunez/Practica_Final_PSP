package practica.u5;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server listening on port " + PORT);

            try (Socket clientSocket = serverSocket.accept();
                ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

                out.flush();

                Object request = in.readObject();
                if (!(request instanceof String) || !"PUBLIC_KEY_REQ".equals(request)) {
                    System.out.println("Unexpected request. Closing.");
                    return;
                }

                KeyPair keyPair = RSA_Asimetric.randomGenerate(2048);
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();

                out.writeObject(publicKey);
                out.flush();

                System.out.println("Public key sent to client.");

                Object keyPacketObj = in.readObject(); //verificamos que el paquete contiene 2 arrays de bytes y que es un paquete
                if (!(keyPacketObj instanceof Packet)) {
                    System.out.println("Unexpected key packet. Closing.");
                    return;
                }

                Packet keyPacket = (Packet) keyPacketObj; // Convertimos el Object a Packet
                byte[] keyBytes = RSA_Asimetric.decryptData(keyPacket.message, privateKey); // clave AES cifrada con RSA
                byte[] keyHash = RSA_Asimetric.decryptData(keyPacket.hash, privateKey); // utilizo privateKey para descifrar ambos

                byte[] computedHash = HashUtil.sha256(keyBytes); // Calculamos el hash SHA-256 de la clave AES recibida
                if (!java.util.Arrays.equals(keyHash, computedHash)) { // comprobam amb el hash del client
                    System.out.println("Key hash mismatch. Closing.");
                    return;
                }
                // Convertimos los bytes de la clave a un objeto SecretKey para AES
                SecretKey sharedKey = new SecretKeySpec(keyBytes, "AES"); // Esta sharedKey es la que se usará para cifrar y descifrar palabras
                System.out.println("Shared key established: " + sharedKey.getAlgorithm()); //imprime AES
            }
        } catch (Exception ex) {
            System.err.println("Server error: " + ex);
        }
    }
}
