package de.svenkubiak.webpush4j.models;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import de.svenkubiak.webpush4j.enums.Dir;
import de.svenkubiak.webpush4j.enums.Urgency;
import de.svenkubiak.webpush4j.exceptions.WebPushException;
import de.svenkubiak.webpush4j.utils.Utils;

public class Notification {
    private Map<String, String> payload = new HashMap<>();
    private Urgency urgency;
    private String topic;
    private long ttl;
    
    private Notification() {
        this.ttl = TimeUnit.DAYS.toSeconds(1);
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
    
    public Notification withTtl(long duration, TimeUnit timeUnit) {
        Objects.requireNonNull(timeUnit, "timeUnit can not be null");
        
        this.ttl = timeUnit.toSeconds(duration);
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
    
    public Notification withDir(Dir dir) {
        Objects.requireNonNull(dir, "dir can not be null");
        payload.put("dir", dir.getValue());

        return this;
    }
    
    public Notification withData(String data) {
        Objects.requireNonNull(data, "data can not be null");
        payload.put("data", data);

        return this;
    }
    
    public Notification withIcon(String icon) {
        Objects.requireNonNull(icon, "icon can not be null");
        payload.put("icon", icon);

        return this;
    }
    
    public Notification withLang(String lang) {
        Objects.requireNonNull(lang, "lang can not be null");
        payload.put("lang", lang);

        return this;
    }
    
    public Notification withTag(String tag) {
        Objects.requireNonNull(tag, "tag can not be null");
        payload.put("tag", tag);

        return this;
    }

    public byte[] getPayload() throws WebPushException {
        return Utils.toJson(payload);
    }

    public boolean hasPayload() {
        return !payload.isEmpty();
    }
    
    public String getPayload(String key) {
        return payload.get(key);
    }

    public boolean hasUrgency() {
        return urgency != null;
    }

    public boolean hasTopic() {
        return topic != null;
    }

    public long getTtl() {
        return ttl;
    }

    public Urgency getUrgency() {
        return urgency;
    }

    public String getTopic() {
        return topic;
    }
}
