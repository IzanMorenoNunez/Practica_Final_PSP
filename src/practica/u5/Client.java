package practica.u5;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.SecretKey;

public class Client {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        boolean tamperCert = Arrays.asList(args).contains("--tamper-cert");

        try (Socket socket = new Socket(HOST, PORT);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.flush();

            out.writeObject("CERT_REQ"); // missatge de control per demanar certificat al servidor. El cliente pide certificado, no clave pública suelta
            out.flush();

            Object response = in.readObject();
            if (!(response instanceof byte[])) {
                System.out.println("Unexpected response.");
                return;
            }

            byte[] certBytes = (byte[]) response;
            if (tamperCert) { //esto es una simulación de ataque de certificado falso
                certBytes = certBytes.clone(); // aqui s'altera un byte del certificat
                if (certBytes.length == 0) {
                    System.out.println("Empty certificate received.");
                    return;
                }
                certBytes[certBytes.length - 1] ^= 0x01;
                System.out.println("Certificate tampering mode enabled."); // u aqui tambe, i sa validaci falla.
            }

            PublicKey serverPublicKey = SelfSignedCert.validateAndGetPublicKey(certBytes); //E l cliente valida el certificado antes de confiar
            System.out.println("Certificate validated. Public key received: " + serverPublicKey.getAlgorithm());

            SecretKey sharedKey = AES_Simetric.keygenKeyGeneration(128);
            byte[] keyBytes = sharedKey.getEncoded();
            byte[] keyHash = HashUtil.sha256(keyBytes); //per a que si algu modifica la clau a mitj cami no coincideixi

            //Despres de validar amb certificat: cliente cifra clave AES + hash con la pública del certificado
            byte[] encryptedKey = RSA_Asimetric.encryptData(keyBytes, serverPublicKey); // d'aquesta forma, cifrant la clau y el hash amb RSA 
            byte[] encryptedHash = RSA_Asimetric.encryptData(keyHash, serverPublicKey); // nomes el servidor amb la seva privada podra desxifrar-ho

            Packet keyPacket = new Packet(encryptedKey, encryptedHash); // enviam es paquet de bytes a servidor
            out.writeObject(keyPacket);
            out.flush();

            System.out.println("Shared key (encrypted) sent to server.");

            try (Scanner scanner = new Scanner(System.in)) {
                while (true) {
                    System.out.print("Write a word ('exit' to finish): ");
                    String word = scanner.nextLine();
                    if ("exit".equalsIgnoreCase(word)) {
                        break;
                    }

                    byte[] wordBytes = word.getBytes(StandardCharsets.UTF_8);
                    byte[] wordHash = HashUtil.sha256(wordBytes);
                    byte[] encryptedWord = AES_Simetric.encryptData(sharedKey, wordBytes);
                    byte[] encryptedWordHash = AES_Simetric.encryptData(sharedKey, wordHash);

                    out.writeObject(new Packet(encryptedWord, encryptedWordHash));
                    out.flush();

                    Object ackObj = in.readObject(); //ack, selak enviada por receptor para confirmar la recepcion correcta de los datos, espera servidor
                    if (!(ackObj instanceof Packet)) {
                        System.out.println("Unexpected ACK payload.");
                        break;
                    }

                    Packet ackPacket = (Packet) ackObj; //cast para message y hash
                    byte[] ackBytes = AES_Simetric.decryptData(sharedKey, ackPacket.message); // descifra el contenido del acuse
                    byte[] ackHash = AES_Simetric.decryptData(sharedKey, ackPacket.hash); // descifra hash enviado por servidor
                    if (ackBytes == null || ackHash == null) {
                        System.out.println("ACK could not be decrypted.");
                        break;
                    }

                    byte[] computedAckHash = HashUtil.sha256(ackBytes); //recalcula hash local del acuse ya descifrado.
                    if (!java.util.Arrays.equals(ackHash, computedAckHash)) { // si no coinciden, acuse alterado o corrupto.
                        System.out.println("ACK hash mismatch.");
                        break;
                    }

                    String ack = new String(ackBytes, StandardCharsets.UTF_8); // convierte ACK a texto
                    System.out.println("Server ACK: " + ack); // mostra acuse valid
                }
            }
        } catch (Exception ex) {
            System.err.println("Client error: " + ex);
        } 
    }
}
