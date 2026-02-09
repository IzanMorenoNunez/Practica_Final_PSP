package practica.u5;

import java.io.Serializable;

public class Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    public final byte[] message;
    public final byte[] hash;

    public Packet(byte[] message, byte[] hash) {
        this.message = message;
        this.hash = hash;
    }
}
