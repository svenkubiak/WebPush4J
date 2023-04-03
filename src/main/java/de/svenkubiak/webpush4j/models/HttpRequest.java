package de.svenkubiak.webpush4j.models;

import java.util.Map;
import java.util.Objects;

public class HttpRequest {
    private final String url;
    private final Map<String, String> headers;
    private final byte[] body;

    public HttpRequest(String url, Map<String, String> headers, byte[] body) {
        this.url = Objects.requireNonNull(url, "url can not benull");
        this.headers = Objects.requireNonNull(headers, "headers can not benull");
        this.body = Objects.requireNonNull(body, "body can not benull");
    }

    public String getUrl() {
        return url;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public byte[] getBody() {
        return body;
    }
}