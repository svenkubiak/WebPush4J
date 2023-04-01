package de.svenkubiak.webpush4j;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import de.svenkubiak.webpush4j.enums.Encoding;
import de.svenkubiak.webpush4j.exceptions.WebPushException;
import de.svenkubiak.webpush4j.http.HttpEce;
import de.svenkubiak.webpush4j.http.HttpRequest;
import de.svenkubiak.webpush4j.utils.Utils;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class WebPush {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String SERVER_KEY_ID = "server-key-id";
    private static final String SERVER_KEY_CURVE = "P-256";
    private final OkHttpClient client = new OkHttpClient();
    private String gcmApiKey;
    private String subject;
    private String publKey;
    private String privKey;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private Subscriber subscriber;
    private Notification notification;
    
    public WebPush() {
    }
    
    public static WebPush crerate() {
        Security.addProvider(new BouncyCastleProvider());
        return new WebPush();
    }
    
    public WebPush withPublicKey(String publicKey) {
        this.publKey = Objects.requireNonNull(publicKey, "publicKey can not be null");
        return this;
    }
    
    public WebPush withPrivateKey(String privateKey) {
        this.privKey = Objects.requireNonNull(privateKey, "privateKey can not be null");
        return this;
    }

    public WebPush withSubject(String subject) {
        this.subject = subject;
        return this;
    }

    public WebPush withSubscriber(Subscriber subscriber) {
        this.subscriber = Objects.requireNonNull(subscriber, "subscriber can not be null");
        return this;
    }

    public WebPush withNotification(Notification notification) {
        this.notification = Objects.requireNonNull(notification, "notification can not be null");
        return this;
    }
    
    public void send() throws WebPushException {
        send(Encoding.AES128GCM);
    }

    private void send(Encoding encoding) throws WebPushException {
        Objects.requireNonNull(encoding, "encoding can not be null");
        
        publicKey = Utils.loadPublicKey(publKey);
        privateKey = Utils.loadPrivateKey(privKey);
        
        HttpRequest httpRequest = prepareRequest(notification, subscriber, encoding);
        
        Request request = new Request.Builder()
                .url(httpRequest.getUrl())
                .headers(Headers.of(httpRequest.getHeaders()))
                .post(RequestBody.create(httpRequest.getBody()))
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new WebPushException("Unexpected response: " + response);
            }
        } catch (IOException e) {
            throw new WebPushException(e);
        }
    }

    public Encrypted encrypt(byte[] payload, ECPublicKey userPublicKey, byte[] userAuth, Encoding encoding) throws WebPushException {
        KeyPair localKeyPair;
        try {
            localKeyPair = generateLocalKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new WebPushException(e);
        }

        Map<String, KeyPair> keys = new HashMap<>();
        keys.put(SERVER_KEY_ID, localKeyPair);

        Map<String, String> labels = new HashMap<>();
        labels.put(SERVER_KEY_ID, SERVER_KEY_CURVE);

        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);

        HttpEce httpEce = new HttpEce(keys, labels);
        byte[] ciphertext;
        try {
            ciphertext = httpEce.encrypt(payload, salt, null, SERVER_KEY_ID, userPublicKey, userAuth, encoding);
        } catch (GeneralSecurityException e) {
            throw new WebPushException(e);
        }
        
        return new Encrypted(userPublicKey, salt, ciphertext);
    }

    /**
     * Generate the local (ephemeral) keys.
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidAlgorithmParameterException
     */
    private static KeyPair generateLocalKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
        keyPairGenerator.initialize(parameterSpec);

        return keyPairGenerator.generateKeyPair();
    }

    protected final HttpRequest prepareRequest(Notification notification, Subscriber subscriber, Encoding encoding) throws WebPushException {
        if (getPrivateKey() != null && getPublicKey() != null) {
            if (!Utils.verifyKeyPair(getPrivateKey(), getPublicKey())) {
                throw new WebPushException("Public key and private key do not match.");
            }
        }

        Encrypted encrypted = encrypt(
                notification.getPayload(),
                (ECPublicKey) Utils.loadPublicKey(subscriber.getP256dh()),
                Base64.getUrlDecoder().decode(subscriber.getAuth()),
                encoding
        );

        byte[] dh = Utils.encode((ECPublicKey) encrypted.getPublicKey());
        byte[] salt = encrypted.getSalt();

        String url = subscriber.getEndpoint();
        Map<String, String> headers = new HashMap<>();
        byte[] body = null;

        headers.put("TTL", String.valueOf(notification.getTtl()));

        if (notification.hasUrgency()) {
            headers.put("Urgency", notification.getUrgency().getHeaderValue());
        }

        if (notification.hasTopic()) {
            headers.put("Topic", notification.getTopic());
        }

        if (notification.hasPayload()) {
            headers.put("Content-Type", "application/octet-stream");

            if (encoding == Encoding.AES128GCM) {
                headers.put("Content-Encoding", "aes128gcm");
            } else if (encoding == Encoding.AESGCM) {
                headers.put("Content-Encoding", "aesgcm");
                headers.put("Encryption", "salt=" + Base64.getUrlEncoder().withoutPadding().encodeToString(salt));
                headers.put("Crypto-Key", "dh=" + Base64.getUrlEncoder().encodeToString(dh));
            }

            body = encrypted.getCiphertext();
        }

        if (subscriber.isGcm()) {
            if (getGcmApiKey() == null) {
                throw new IllegalStateException("An GCM API key is needed to send a push notification to a GCM endpoint.");
            }

            headers.put("Authorization", "key=" + getGcmApiKey());
        } else if (vapidEnabled()) {
            if (encoding == Encoding.AES128GCM) {
                if (subscriber.getEndpoint().startsWith("https://fcm.googleapis.com")) {
                    url = subscriber.getEndpoint().replace("fcm/send", "wp");
                }
            }

            JwtClaims claims = new JwtClaims();
            claims.setAudience(subscriber.getOrigin());
            claims.setExpirationTimeMinutesInTheFuture(12 * 60);
            if (getSubject() != null) {
                claims.setSubject(getSubject());
            }

            JsonWebSignature jws = new JsonWebSignature();
            jws.setHeader("typ", "JWT");
            jws.setHeader("alg", "ES256");
            jws.setPayload(claims.toJson());
            jws.setKey(getPrivateKey());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

            byte[] pk = Utils.encode((ECPublicKey) getPublicKey());

            try {
                if (encoding == Encoding.AES128GCM) {
                    headers.put("Authorization", "vapid t=" + jws.getCompactSerialization() + ", k=" + Base64.getUrlEncoder().withoutPadding().encodeToString(pk));
                } else if (encoding == Encoding.AESGCM) {
                    headers.put("Authorization", "WebPush " + jws.getCompactSerialization());
                }                
            } catch (JoseException e) {
                throw new WebPushException(e);
            }
            
            if (headers.containsKey("Crypto-Key")) {
                headers.put("Crypto-Key", headers.get("Crypto-Key") + ";p256ecdsa=" + Base64.getUrlEncoder().encodeToString(pk));
            } else {
                headers.put("Crypto-Key", "p256ecdsa=" + Base64.getUrlEncoder().encodeToString(pk));
            }
        } else if (subscriber.isFcm() && getGcmApiKey() != null) {
            headers.put("Authorization", "key=" + getGcmApiKey());
        }

        return new HttpRequest(url, headers, body);
    }

    public String getGcmApiKey() {
        return gcmApiKey;
    }

    public String getSubject() {
        return subject;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public boolean vapidEnabled() {
        return publicKey != null && privateKey != null;
    }
}