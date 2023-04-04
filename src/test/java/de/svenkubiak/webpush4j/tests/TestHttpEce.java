package de.svenkubiak.webpush4j.tests;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import de.svenkubiak.webpush4j.enums.Encoding;
import de.svenkubiak.webpush4j.utils.HttpEce;

class TestHttpEce {
    @BeforeAll
    public static void addSecurityProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private byte[] decode(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    @Test
    void testZeroSaltAndKey() throws GeneralSecurityException {
        HttpEce httpEce = new HttpEce();
        String plaintext = "Hello";
        byte[] salt = new byte[16];
        byte[] key = new byte[16];
        byte[] actual = httpEce.encrypt(plaintext.getBytes(UTF_8), salt, key, null, null, null, Encoding.AES128GCM);
        byte[] expected = decode("AAAAAAAAAAAAAAAAAAAAAAAAEAAAMpsi6NfZUkOdJI96XyX0tavLqyIdiw");

        assertArrayEquals(expected, actual);
    }

    /**
     * See https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-09#section-3.1
     *
     * - Record size is 4096.
     * - Input keying material is identified by an empty string.
     *
     * @throws GeneralSecurityException
     */
    @Test
    void testSampleEncryption() throws GeneralSecurityException {
        HttpEce httpEce = new HttpEce();

        byte[] plaintext = "I am the walrus".getBytes(UTF_8);
        byte[] salt = decode("I1BsxtFttlv3u_Oo94xnmw");
        byte[] key = decode("yqdlZ-tYemfogSmv7Ws5PQ");
        byte[] actual = httpEce.encrypt(plaintext, salt, key, null, null, null, Encoding.AES128GCM);
        byte[] expected = decode("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg");

        assertArrayEquals(expected, actual);
    }
}