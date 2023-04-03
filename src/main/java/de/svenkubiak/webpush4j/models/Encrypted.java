package de.svenkubiak.webpush4j.models;

import java.security.PublicKey;
import java.util.Objects;

public class Encrypted {
    private final PublicKey publicKey;
    private final byte[] salt;
    private final byte[] ciphertext;

    public Encrypted(PublicKey publicKey, byte[] salt, byte[] ciphertext) {
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey can not be null");
        this.salt = Objects.requireNonNull(salt, "salt can not be null");
        this.ciphertext = Objects.requireNonNull(ciphertext, "ciphertext can not be null");
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getCiphertext() {
        return ciphertext;
    }
}