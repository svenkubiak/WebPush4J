package de.svenkubiak.webpush4j.enums;

public enum Dir {
    AUTO("auto"),
    LTR("ltr"),
    RTL("rtl");

    private final String value;

    Dir(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}