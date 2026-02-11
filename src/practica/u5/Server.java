package practica.u5;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.EOFException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
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
                if (!(request instanceof String) || !"CERT_REQ".equals(request)) {
                    System.out.println("Unexpected request. Closing.");
                    return;
                }

                SelfSignedCert.ServerIdentity identity = SelfSignedCert.loadOrCreateServerIdentity();
                PrivateKey privateKey = identity.privateKey;
                X509Certificate cert = identity.certificate;

                out.writeObject(cert.getEncoded()); // envía cert.getEncoded() (byte[]). Que es el certificado
                out.flush();

                System.out.println("Self-signed certificate sent to client.");

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

                while (true) {
                    Packet encryptedWordPacket;
                    try {
                        Object wordObj = in.readObject(); //recibe paquete por red
                        if (!(wordObj instanceof Packet)) {
                            System.out.println("Unexpected payload. Closing."); //control de que sea paquete
                            break;
                        }
                        encryptedWordPacket = (Packet) wordObj; //lo guarda en variable packete
                    } catch (EOFException eof) {
                        System.out.println("Client disconnected.");
                        break;
                    }

                    byte[] wordBytes = AES_Simetric.decryptData(sharedKey, encryptedWordPacket.message); //descifra el mensaje del paquete
                    byte[] receivedWordHash = AES_Simetric.decryptData(sharedKey, encryptedWordPacket.hash); // y el hash
                    if (wordBytes == null || receivedWordHash == null) {
                        System.out.println("Could not decrypt incoming packet."); //control
                        break;
                    }

                    byte[] computedWordHash = HashUtil.sha256(wordBytes); //recalcula el hash en servidor mediante la palabra que recibe
                    if (!java.util.Arrays.equals(receivedWordHash, computedWordHash)) { //compara hashes para verificar integrdidad, sino estan corruptos
                        System.out.println("Word hash mismatch. Packet discarded.");
                        continue;
                    }

                    String word = new String(wordBytes, StandardCharsets.UTF_8); //convierte a bytes descifrados a texto
                    System.out.println("Word received: " + word); //imprime la palabra recibida

                    byte[] ackBytes = "DataRecived".getBytes(StandardCharsets.UTF_8); //crea ack en bytes
                    byte[] ackHash = HashUtil.sha256(ackBytes); // calcula hash sha-256 del ack para poder verificar la integridad cuando llega del cliente
                    byte[] encryptedAck = AES_Simetric.encryptData(sharedKey, ackBytes); // cifra el texto del ack con la clave aes compartida
                    byte[] encryptedAckHash = AES_Simetric.encryptData(sharedKey, ackHash); // tambien el hash del ack

                    out.writeObject(new Packet(encryptedAck, encryptedAckHash));
                    out.flush();
                } 
            }
        } catch (Exception ex) {
            System.err.println("Server error: " + ex);
        }
    }
}
