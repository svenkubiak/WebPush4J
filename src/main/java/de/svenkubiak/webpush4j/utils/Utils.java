package de.svenkubiak.webpush4j.utils;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.svenkubiak.webpush4j.enums.Encoding;
import de.svenkubiak.webpush4j.exceptions.WebPushException;
import de.svenkubiak.webpush4j.models.Encrypted;

public class Utils {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String SERVER_KEY_ID = "server-key-id";
    private static final String SERVER_KEY_CURVE = "P-256";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String CURVE = "prime256v1";
    private static final String ALGORITHM = "ECDH";

    public static byte[] encode(ECPublicKey publicKey) {
        return publicKey.getQ().getEncoded(false);
    }

    public static PublicKey loadPublicKey(String encodedPublicKey) throws WebPushException {
        byte[] decodedPublicKey = Base64.getUrlDecoder().decode(encodedPublicKey);
        try {
            return loadPublicKey(decodedPublicKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new WebPushException(e);
        }
    }

    public static PublicKey loadPublicKey(byte[] decodedPublicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        var keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);
        ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECCurve curve = parameterSpec.getCurve();
        ECPoint point = curve.decodePoint(decodedPublicKey);
        var pubSpec = new ECPublicKeySpec(point, parameterSpec);

        return keyFactory.generatePublic(pubSpec);
    }
    
    public static Encrypted encrypt(byte[] payload, ECPublicKey userPublicKey, byte[] userAuth, Encoding encoding) throws WebPushException {
        KeyPair localKeyPair;
        try {
            localKeyPair = Utils.generateLocalKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new WebPushException(e);
        }

        Map<String, KeyPair> keys = new HashMap<>();
        keys.put(SERVER_KEY_ID, localKeyPair);

        Map<String, String> labels = new HashMap<>();
        labels.put(SERVER_KEY_ID, SERVER_KEY_CURVE);

        var salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);

        var httpEce = new HttpEce(keys, labels);
        byte[] ciphertext;
        try {
            ciphertext = httpEce.encrypt(payload, salt, null, SERVER_KEY_ID, userPublicKey, userAuth, encoding);
        } catch (GeneralSecurityException e) {
            throw new WebPushException(e);
        }
        
        return new Encrypted(userPublicKey, salt, ciphertext);
    }

    public static PrivateKey loadPrivateKey(String encodedPrivateKey) throws WebPushException {
        byte[] decodedPrivateKey = Base64.getUrlDecoder().decode(encodedPrivateKey);
        try {
            return loadPrivateKey(decodedPrivateKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new WebPushException(e);
        }
    }

    public static PrivateKey loadPrivateKey(byte[] decodedPrivateKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        var bigInt = BigIntegers.fromUnsignedByteArray(decodedPrivateKey);
        ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(CURVE);
        var privateKeySpec = new ECPrivateKeySpec(bigInt, parameterSpec);
        var keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);

        return keyFactory.generatePrivate(privateKeySpec);
    }

    public static boolean verifyKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        ECNamedCurveParameterSpec curveParameters = ECNamedCurveTable.getParameterSpec(CURVE);
        ECPoint g = curveParameters.getG();
        ECPoint sG = g.multiply(((java.security.interfaces.ECPrivateKey) privateKey).getS());

        return sG.equals(((ECPublicKey) publicKey).getQ());
    }

    public static KeyPair generateLocalKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(CURVE);
        var keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(parameterSpec);

        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] concat(byte[]... arrays) {
        var lastPos = 0;
        var combined = new byte[combinedLength(arrays)];

        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }

            System.arraycopy(array, 0, combined, lastPos, array.length);

            lastPos += array.length;
        }

        return combined;
    }

    public static int combinedLength(byte[]... arrays) {
        var combinedLength = 0;

        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }

            combinedLength += array.length;
        }

        return combinedLength;
    }

    public static byte[] toByteArray(int integer, int size) {
        var buffer = ByteBuffer.allocate(size);
        buffer.putInt(integer);

        return buffer.array();
    }
    
    public static byte[] toJson(Object object) {
        try {
            return objectMapper.writeValueAsBytes(object);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        
        return new byte[0];
    }
}
