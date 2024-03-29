package de.svenkubiak.webpush4j.models;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Objects;

import com.jayway.jsonpath.JsonPath;

import de.svenkubiak.webpush4j.exceptions.WebPushException;

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
        
        var documentContext = JsonPath.parse(json);
        String endpoint = documentContext.read("$.endpoint");
        String p256dh = documentContext.read("$.keys.p256dh");
        String auth = documentContext.read("$.keys.auth");
        
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

    public String getOrigin() throws WebPushException {
        URL url;
        try {
            url = URI.create(endpoint).toURL();
            return url.getProtocol() + "://" + url.getHost();
        } catch (MalformedURLException e) {
            throw new WebPushException(e);
        }
    }
}