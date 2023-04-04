package de.svenkubiak.webpush4j;

import java.io.IOException;
import java.security.Security;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import de.svenkubiak.webpush4j.enums.Encoding;
import de.svenkubiak.webpush4j.exceptions.WebPushException;
import de.svenkubiak.webpush4j.models.HttpRequest;
import de.svenkubiak.webpush4j.models.Notification;
import de.svenkubiak.webpush4j.models.Subscriber;
import de.svenkubiak.webpush4j.utils.Utils;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

public class WebPush {
    private static final String CRYPTO_KEY = "Crypto-Key";
    private static final float EXPIRES = 720f;
    private final OkHttpClient httpClient = new OkHttpClient();
    private String subject;
    private String publicKey;
    private String privateKey;
    private Subscriber subscriber;
    private Notification notification;
    
    private WebPush() {
        //no-args constructor
    }
    
    public static WebPush crerate() {
        Security.addProvider(new BouncyCastleProvider());
        return new WebPush();
    }
    
    public WebPush withPublicKey(String publicKey) {
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey can not be null");
        return this;
    }
    
    public WebPush withPrivateKey(String privateKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey can not be null");
        return this;
    }

    public WebPush withSubject(String subject) {
        this.subject = Objects.requireNonNull(subject, "subject can not be null");
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

    public void send(Encoding encoding) throws WebPushException {
        Objects.requireNonNull(encoding, "encoding can not be null");
        
        var httpRequest = prepareRequest(notification, subscriber, encoding);
        var request = new Request.Builder()
                .url(httpRequest.getUrl())
                .headers(Headers.of(httpRequest.getHeaders()))
                .post(RequestBody.create(httpRequest.getBody()))
                .build();

        try (var response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new WebPushException("Unexpected response: " + response);
            }
        } catch (IOException e) {
            throw new WebPushException(e);
        }
    }
    
    private HttpRequest prepareRequest(Notification notification, Subscriber subscriber, Encoding encoding) throws WebPushException {
        var vapidPublic = Utils.loadPublicKey(publicKey);
        var vapidPrivate = Utils.loadPrivateKey(privateKey);
        
        if (vapidEnabled() && !Utils.verifyKeyPair(vapidPrivate, vapidPublic)) {
            throw new WebPushException("Public key and private key do not match.");
        }

        var encrypted = Utils.encrypt(
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
            headers.put("Urgency", notification.getUrgency().getValue());
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
                headers.put(CRYPTO_KEY, "dh=" + Base64.getUrlEncoder().encodeToString(dh));
            }

            body = encrypted.getCiphertext();
        }

        if (vapidEnabled()) {
            if (subscriber.getEndpoint().startsWith("https://fcm.googleapis.com")) {
                url = subscriber.getEndpoint().replace("fcm/send", "wp");
            }

            var claims = new JwtClaims();
            claims.setAudience(subscriber.getOrigin());
            claims.setExpirationTimeMinutesInTheFuture(EXPIRES);
            if (getSubject() != null) {
                claims.setSubject(getSubject());
            }

            var jws = new JsonWebSignature();
            jws.setHeader("typ", "JWT");
            jws.setHeader("alg", "ES256");
            jws.setPayload(claims.toJson());
            jws.setKey(vapidPrivate);
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

            byte[] pk = Utils.encode((ECPublicKey) vapidPublic);

            try {
                if (encoding == Encoding.AES128GCM) {
                    headers.put("Authorization", "vapid t=" + jws.getCompactSerialization() + ", k=" + Base64.getUrlEncoder().withoutPadding().encodeToString(pk));
                } else if (encoding == Encoding.AESGCM) {
                    headers.put("Authorization", "WebPush " + jws.getCompactSerialization());
                }                
            } catch (JoseException e) {
                throw new WebPushException(e);
            }
            
            var cryptoKey = headers.get(CRYPTO_KEY);
            if (cryptoKey != null) {
                headers.put(CRYPTO_KEY, cryptoKey + ";p256ecdsa=" + Base64.getUrlEncoder().encodeToString(pk));
            } else {
                headers.put(CRYPTO_KEY, "p256ecdsa=" + Base64.getUrlEncoder().encodeToString(pk));
            }
        } else {
            throw new WebPushException("No Vapid keys found. Please set public and private key.");
        }

        return new HttpRequest(url, headers, body);
    }

    public String getSubject() {
        return subject;
    }

    public boolean vapidEnabled() {
        return StringUtils.isNotBlank(publicKey) &&  StringUtils.isNotBlank(privateKey);
    }
}