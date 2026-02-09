package practica.u5;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;

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

                out.writeObject(publicKey);
                out.flush();

                System.out.println("Public key sent to client.");
            }
        } catch (Exception ex) {
            System.err.println("Server error: " + ex);
        }
    }
}
