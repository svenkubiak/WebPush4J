package de.svenkubiak.webpush4j.enums;

public enum Urgency {
	HIGH("high"),
	LOW("low"),
	NORMAL("normal"),
	VERY_LOW("very-low");

	private final String value;

	Urgency(String value) {
		this.value = value;
	}

	public String getValue() {
		return value;
	}
}