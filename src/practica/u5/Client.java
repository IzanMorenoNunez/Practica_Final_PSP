package practica.u5;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.PublicKey;

public class Client {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try (Socket socket = new Socket(HOST, PORT);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream())) {

            out.flush();

            out.writeObject("PUBLIC_KEY_REQ");
            out.flush();

            Object response = in.readObject();
            if (!(response instanceof PublicKey)) {
                System.out.println("Unexpected response.");
                return;
            }

            PublicKey serverPublicKey = (PublicKey) response;
            System.out.println("Public key received: " + serverPublicKey.getAlgorithm());
        } catch (Exception ex) {
            System.err.println("Client error: " + ex);
        }
    }
}
