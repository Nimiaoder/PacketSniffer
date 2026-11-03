package com.sniffer.stream;

/** 單一 TCP 封包中與串流重組有關的資訊 (與 pcap4j 無關，方便測試)。 */
public record TcpSegment(long no, long timeMillis,
                         String srcIp, int srcPort, String dstIp, int dstPort,
                         long seq, boolean syn, boolean ack, boolean fin, boolean rst,
                         byte[] payload) {
}
