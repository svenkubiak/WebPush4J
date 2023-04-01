package de.svenkubiak.webpush4j;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import de.svenkubiak.webpush4j.enums.Urgency;
import de.svenkubiak.webpush4j.utils.Utils;

public class Notification {
    private static final int ONE_DAY_DURATION_IN_SECONDS = 86400;
    private static int DEFAULT_TTL = 28 * ONE_DAY_DURATION_IN_SECONDS;
    private Map<String, String> payload = new HashMap<>();
    private Urgency urgency;
    private int ttl;
    private String topic;
    
    private Notification() {
        this.ttl = DEFAULT_TTL;
    }

    public static Notification create() {
        return new Notification();
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
    
    public Notification withBody(String body) {
        Objects.requireNonNull(body, "body can not be null");
        payload.put("body", body);

        return this;
    }
    
    public Notification withTitle(String title) {
        Objects.requireNonNull(title, "title can not be null");
        payload.put("title", title);

        return this;
    }

    public byte[] getPayload() {
        return Utils.toJson(payload);
    }

    public boolean hasPayload() {
        return !payload.isEmpty();
    }

    public boolean hasUrgency() {
        return urgency != null;
    }

    public boolean hasTopic() {
        return topic != null;
    }

    public int getTtl() {
        return ttl;
    }

    public Urgency getUrgency() {
        return urgency;
    }

    public String getTopic() {
        return topic;
    }
}
