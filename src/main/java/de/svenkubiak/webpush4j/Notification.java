package de.svenkubiak.webpush4j;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import de.svenkubiak.webpush4j.enums.Urgency;
import de.svenkubiak.webpush4j.utils.Utils;

public class Notification {
    /**
     * The endpoint associated with the push subscription
     */
    private String endpoint;

    /**
     * The client's public key
     */
    private ECPublicKey userPublicKey;

    /**
     * The client's auth
     */
    private byte[] userAuth;

    /**
     * An arbitrary payload
     */
    private byte[] payload;

    /**
     * Push Message Urgency
     *
     *  @see <a href="https://tools.ietf.org/html/rfc8030#section-5.3">Push Message Urgency</a>
     *
     */
    private Urgency urgency;

    /**
     * Push Message Topic
     *
     *  @see <a href="https://tools.ietf.org/html/rfc8030#section-5.4">Replacing Push Messages</a>
     *
     */
    private String topic;

    /**
     * Time in seconds that the push message is retained by the push service
     */
    private int ttl;

    private static final int ONE_DAY_DURATION_IN_SECONDS = 86400;
    private static int DEFAULT_TTL = 28 * ONE_DAY_DURATION_IN_SECONDS;

    public Notification(String endpoint, ECPublicKey userPublicKey, byte[] userAuth, byte[] payload, int ttl, Urgency urgency, String topic) {
        this.endpoint = endpoint;
        this.userPublicKey = userPublicKey;
        this.userAuth = userAuth;
        this.payload = payload;
        this.ttl = ttl;
        this.urgency = urgency;
        this.topic = topic;
    }

    private Notification() {
        this.ttl = DEFAULT_TTL;
    }
    
    public static Notification create() {
        return new Notification();
    }
    
    public Notification to(Subscriber subscriber) {
        Objects.requireNonNull(subscriber, "subscriber can not be null");
        
        this.endpoint = subscriber.getEndpoint();
        try {
            this.userPublicKey = (ECPublicKey) Utils.loadPublicKey(subscriber.getP256dh());
            this.userAuth = Base64.getUrlDecoder().decode(subscriber.getAuth());
        } catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        
        return this;
    }
    
    public Notification withPayload(String payload) {
        Objects.requireNonNull(payload, "payload can not be null");
        
        this.payload = payload.getBytes(UTF_8);
        
        return this;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public ECPublicKey getUserPublicKey() {
        return userPublicKey;
    }

    public byte[] getUserAuth() {
        return userAuth;
    }

    public byte[] getPayload() {
        return payload;
    }

    public boolean hasPayload() {
        return getPayload().length > 0;
    }

    public boolean hasUrgency() {
        return urgency != null;
    }

    public boolean hasTopic() {
        return topic != null;
    }

    /**
     * Detect if the notification is for a GCM-based subscription
     *
     * @return
     */
    public boolean isGcm() {
        return getEndpoint().indexOf("https://android.googleapis.com/gcm/send") == 0;
    }

    public boolean isFcm() {
        return getEndpoint().indexOf("https://fcm.googleapis.com/fcm/send") == 0;
    }

    public int getTTL() {
        return ttl;
    }

    public Urgency getUrgency() {
        return urgency;
    }

    public String getTopic() {
        return topic;
    }

    public String getOrigin() throws MalformedURLException {
        URL url = new URL(getEndpoint());

        return url.getProtocol() + "://" + url.getHost();
    }
}
