package com.sniffer.stream;

/** 一條 TCP 連線的識別 (不分方向)：兩端 IP:Port 以字串順序正規化。 */
public record StreamKey(String ipA, int portA, String ipB, int portB) {

    public static StreamKey of(String srcIp, int srcPort, String dstIp, int dstPort) {
        int c = srcIp.compareTo(dstIp);
        if (c == 0) c = Integer.compare(srcPort, dstPort);
        return c <= 0
                ? new StreamKey(srcIp, srcPort, dstIp, dstPort)
                : new StreamKey(dstIp, dstPort, srcIp, srcPort);
    }

    @Override public String toString() {
        return ipA + ":" + portA + " <-> " + ipB + ":" + portB;
    }
}
