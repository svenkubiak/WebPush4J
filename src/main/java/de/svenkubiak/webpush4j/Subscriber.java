package de.svenkubiak.webpush4j;

import java.util.Objects;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

public class Subscriber {
    private String endpoint;
    private String p256dh;
    private String auth;

    public Subscriber(String endpoint, String p256dh, String auth) {
        this.endpoint = Objects.requireNonNull(endpoint, "endpoint can not be null");
        this.p256dh = Objects.requireNonNull(p256dh, "p256dh can not be null");
        this.auth = Objects.requireNonNull(auth, "auth can not be null");
    }
    
    public static Subscriber from(String json) {
        Objects.requireNonNull(json, "json can not be null");
        
        DocumentContext jsonContext = JsonPath.parse(json);
        String endpoint = jsonContext.read("$.endpoint");
        String p256dh = jsonContext.read("$.keys.p256dh");
        String auth = jsonContext.read("$.keys.auth");
        
        return new Subscriber(endpoint, p256dh, auth);
    }

    public String getEndpoint() {
        return endpoint;
    }

    public String getP256dh() {
        return p256dh;
    }

    public String getAuth() {
        return auth;
    }
}