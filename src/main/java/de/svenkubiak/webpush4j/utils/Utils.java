package de.svenkubiak.webpush4j.utils;

import static org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

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

import de.svenkubiak.webpush4j.exceptions.WebPushException;

public class Utils {
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String CURVE = "prime256v1";
    private static final String ALGORITHM = "ECDH";

    /**
     * Get the uncompressed encoding of the public key point. The resulting array
     * should be 65 bytes length and start with 0x04 followed by the x and y
     * coordinates (32 bytes each).
     *
     * @param publicKey
     * @return
     */
    public static byte[] encode(ECPublicKey publicKey) {
        return publicKey.getQ().getEncoded(false);
    }

    /**
     * Load the public key from a URL-safe base64 encoded string. Takes into
     * account the different encodings, including point compression.
     *
     * @param encodedPublicKey
     */
    public static PublicKey loadPublicKey(String encodedPublicKey) throws WebPushException {
        byte[] decodedPublicKey = Base64.getUrlDecoder().decode(encodedPublicKey);
        try {
            return loadPublicKey(decodedPublicKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new WebPushException(e);
        }
    }

    /**
     * Load the public key from a byte array. 
     *
     * @param decodedPublicKey
     */
    public static PublicKey loadPublicKey(byte[] decodedPublicKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);
        ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECCurve curve = parameterSpec.getCurve();
        ECPoint point = curve.decodePoint(decodedPublicKey);
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, parameterSpec);

        return keyFactory.generatePublic(pubSpec);
    }

    /**
     * Load the private key from a URL-safe base64 encoded string
     *
     * @param encodedPrivateKey
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey loadPrivateKey(String encodedPrivateKey) throws WebPushException {
        byte[] decodedPrivateKey = Base64.getUrlDecoder().decode(encodedPrivateKey);
        try {
            return loadPrivateKey(decodedPrivateKey);
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new WebPushException(e);
        }
    }

    /**
     * Load the private key from a byte array
     *
     * @param decodedPrivateKey
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey loadPrivateKey(byte[] decodedPrivateKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger s = BigIntegers.fromUnsignedByteArray(decodedPrivateKey);
        ECParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(CURVE);
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(s, parameterSpec);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, PROVIDER_NAME);

        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Verify that the private key belongs to the public key.
     *
     * @param privateKey
     * @param publicKey
     * @return
     */
    public static boolean verifyKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        ECNamedCurveParameterSpec curveParameters = ECNamedCurveTable.getParameterSpec(CURVE);
        ECPoint g = curveParameters.getG();
        ECPoint sG = g.multiply(((java.security.interfaces.ECPrivateKey) privateKey).getS());

        return sG.equals(((ECPublicKey) publicKey).getQ());
    }

    /**
     * Utility to concat byte arrays
     */
    public static byte[] concat(byte[]... arrays) {
        int lastPos = 0;

        byte[] combined = new byte[combinedLength(arrays)];

        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }

            System.arraycopy(array, 0, combined, lastPos, array.length);

            lastPos += array.length;
        }

        return combined;
    }

    /**
     * Compute combined array length
     */
    public static int combinedLength(byte[]... arrays) {
        int combinedLength = 0;

        for (byte[] array : arrays) {
            if (array == null) {
                continue;
            }

            combinedLength += array.length;
        }

        return combinedLength;
    }

    /**
     * Create a byte array of the given length from the given integer.
     *
     * @param integer
     * @param size
     * @return
     */
    public static byte[] toByteArray(int integer, int size) {
        ByteBuffer buffer = ByteBuffer.allocate(size);
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
