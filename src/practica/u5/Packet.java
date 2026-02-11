package practica.u5;

import java.io.Serializable;

// Contenedor para enviar bloques de bytes (missatge i hash) entre servidor y cliente

public class Packet implements Serializable {
    private static final long serialVersionUID = 1L;

    public final byte[] message;
    public final byte[] hash;

    public Packet(byte[] message, byte[] hash) {
        this.message = message;
        this.hash = hash;
    } 
}
