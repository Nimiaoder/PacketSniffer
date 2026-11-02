package com.sniffer.model;

public enum Direction {
    IN("接收"), OUT("送出"), OTHER("其他");

    public final String label;

    Direction(String label) { this.label = label; }

    @Override public String toString() { return label; }
}
