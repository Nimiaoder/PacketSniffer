package com.sniffer.stream;

import com.sniffer.model.PacketRecord;
import org.pcap4j.packet.TcpPacket;

/** PacketRecord ↔ 串流重組用資料的轉換。 */
public final class Segments {
    private Segments() {}

    public static StreamKey keyOf(PacketRecord r) {
        return StreamKey.of(r.src, r.srcPort, r.dst, r.dstPort);
    }

    /** 非 TCP 封包回傳 null。 */
    public static TcpSegment of(PacketRecord r) {
        TcpPacket tcp = r.packet == null ? null : r.packet.get(TcpPacket.class);
        if (tcp == null || r.srcPort == null || r.dstPort == null) return null;
        TcpPacket.TcpHeader h = tcp.getHeader();
        byte[] payload = tcp.getPayload() != null ? tcp.getPayload().getRawData() : new byte[0];
        return new TcpSegment(r.no, r.timeMillis, r.src, r.srcPort, r.dst, r.dstPort,
                h.getSequenceNumberAsLong(), h.getSyn(), h.getAck(), h.getFin(), h.getRst(), payload);
    }
}
