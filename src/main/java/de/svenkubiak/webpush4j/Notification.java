package de.svenkubiak.webpush4j;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Objects;

import de.svenkubiak.webpush4j.enums.Urgency;

public class Notification {
    private static final int ONE_DAY_DURATION_IN_SECONDS = 86400;
    private static int DEFAULT_TTL = 28 * ONE_DAY_DURATION_IN_SECONDS;
    private byte[] payload = {};
    private Urgency urgency;
    private String topic;
    private int ttl;
    
    private Notification() {
        this.ttl = DEFAULT_TTL;
    }

    public static Notification create() {
        return new Notification();
    }
    
    public Notification withPayload(String payload) {
        Objects.requireNonNull(payload, "payload can not be null");
        this.payload = payload.getBytes(UTF_8);
        
        return this;
    }
    
    public Notification withUrgency(Urgency urgency) {
        this.urgency = Objects.requireNonNull(urgency, "urgency can not be null");
        return this;
    }
    
    public Notification withTopic(String topic) {
        this.topic = Objects.requireNonNull(topic, "topic can not be null");
        return this;
    }
    
    public Notification withTtl(int ttl) {
        this.ttl = ttl;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public boolean hasPayload() {
        return payload.length > 0;
    }

    public boolean hasUrgency() {
        return urgency != null;
    }

    public boolean hasTopic() {
        return topic != null;
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
}
