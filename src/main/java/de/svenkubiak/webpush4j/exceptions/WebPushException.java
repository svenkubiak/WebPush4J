package de.svenkubiak.webpush4j.exceptions;

public class WebPushException extends Exception {
    private static final long serialVersionUID = -433085553601409813L;

    public WebPushException(Exception e) {
        super(e);
    }

    public WebPushException(String exception) {
        super(exception);
    }
}