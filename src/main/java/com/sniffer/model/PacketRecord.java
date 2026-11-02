package com.sniffer.model;

import org.pcap4j.packet.Packet;

/** 一筆已擷取並解析完成的封包 (不可變)。 */
public final class PacketRecord {
    public final long no;
    public final long timeMillis;
    public final Direction direction;
    public final String src, dst;          // IP (或 MAC)
    public final String protocol;          // TCP / UDP / HTTP / HTTPS / DNS / ICMP / ARP ...
    public final String transport;         // "TCP" / "UDP" / ""
    public final Integer srcPort, dstPort;
    public final Long seq, ack;
    public final int ipVersion;            // 4 / 6 / 0
    public final String info;
    public final byte[] raw;
    public final Packet packet;

    private String blob;
    private String asciiLower;

    public PacketRecord(long no, long timeMillis, Direction direction, String src, String dst,
                        String protocol, String transport, Integer srcPort, Integer dstPort,
                        Long seq, Long ack, int ipVersion, String info, byte[] raw, Packet packet) {
        this.no = no; this.timeMillis = timeMillis; this.direction = direction;
        this.src = src; this.dst = dst; this.protocol = protocol; this.transport = transport;
        this.srcPort = srcPort; this.dstPort = dstPort; this.seq = seq; this.ack = ack;
        this.ipVersion = ipVersion; this.info = info; this.raw = raw; this.packet = packet;
    }

    /** 所有欄位串成一個小寫字串，供「欄位值」搜尋。 */
    public String blob() {
        if (blob == null) {
            blob = (src + " " + dst + " " + protocol + " " + transport + " "
                    + (srcPort == null ? "" : srcPort) + " " + (dstPort == null ? "" : dstPort) + " "
                    + (seq == null ? "" : seq) + " " + (ack == null ? "" : ack) + " "
                    + direction.label + " " + info).toLowerCase();
        }
        return blob;
    }

    /** 封包位元組轉成可見 ASCII (不可見字元以 . 取代)，小寫。 */
    public String asciiLower() {
        if (asciiLower == null) {
            char[] c = new char[raw.length];
            for (int i = 0; i < raw.length; i++) {
                int v = raw[i] & 0xFF;
                c[i] = (v >= 32 && v < 127) ? Character.toLowerCase((char) v) : '.';
            }
            asciiLower = new String(c);
        }
        return asciiLower;
    }
}
