package com.sniffer.capture;

import com.sniffer.model.Direction;
import com.sniffer.model.PacketRecord;
import com.sniffer.util.DetailTranslator;
import javafx.scene.control.TreeItem;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.LinkLayerAddress;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** 將 pcap4j 的 Packet 轉成 PacketRecord，並產生詳細資料樹。 */
public final class PacketParser {
    private PacketParser() {}

    private static final String[] HTTP_TOKENS =
            {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/"};

    public static PacketRecord parse(long no, Packet p, long timeMillis, LocalInfo local) {
        byte[] raw = p.getRawData();
        String src = "", dst = "", srcMac = null, dstMac = null, proto = "Other", transport = "", info = "";
        int ipVer = 0;
        Integer sp = null, dp = null;
        Long seq = null, ack = null;

        EthernetPacket eth = p.get(EthernetPacket.class);
        if (eth != null) {
            srcMac = mac(eth.getHeader().getSrcAddr());
            dstMac = mac(eth.getHeader().getDstAddr());
            src = srcMac;
            dst = dstMac;
            proto = eth.getHeader().getType().name();
            info = "Ethernet " + proto;
        }

        IpPacket ip = p.get(IpPacket.class);
        if (ip != null) {
            ipVer = (ip instanceof IpV4Packet) ? 4 : 6;
            src = ip.getHeader().getSrcAddr().getHostAddress();
            dst = ip.getHeader().getDstAddr().getHostAddress();
            proto = ip.getHeader().getProtocol().name();
            info = proto;
        }

        ArpPacket arp = p.get(ArpPacket.class);
        if (arp != null) {
            ArpPacket.ArpHeader h = arp.getHeader();
            proto = "ARP";
            src = h.getSrcProtocolAddr().getHostAddress();
            dst = h.getDstProtocolAddr().getHostAddress();
            if (h.getOperation() == ArpOperation.REQUEST) {
                info = "Who has " + dst + "? Tell " + src;
            } else {
                info = src + " is at " + mac(h.getSrcHardwareAddr());
            }
        }

        TcpPacket tcp = p.get(TcpPacket.class);
        UdpPacket udp = p.get(UdpPacket.class);
        IcmpV4CommonPacket icmp4 = p.get(IcmpV4CommonPacket.class);
        IcmpV6CommonPacket icmp6 = p.get(IcmpV6CommonPacket.class);

        if (tcp != null) {
            TcpPacket.TcpHeader h = tcp.getHeader();
            transport = "TCP";
            proto = "TCP";
            sp = h.getSrcPort().valueAsInt();
            dp = h.getDstPort().valueAsInt();
            seq = h.getSequenceNumberAsLong();
            ack = h.getAcknowledgmentNumberAsLong();
            byte[] payload = tcp.getPayload() != null ? tcp.getPayload().getRawData() : new byte[0];

            List<String> f = new ArrayList<>();
            if (h.getSyn()) f.add("SYN");
            if (h.getAck()) f.add("ACK");
            if (h.getFin()) f.add("FIN");
            if (h.getRst()) f.add("RST");
            if (h.getPsh()) f.add("PSH");
            if (h.getUrg()) f.add("URG");
            info = sp + " → " + dp + " [" + String.join(", ", f) + "] Seq=" + seq + " Ack=" + ack
                    + " Win=" + h.getWindowAsInt() + " Len=" + payload.length;

            String httpLine = httpLine(payload);
            if (isTls(payload)) {
                proto = "HTTPS";
                info += "  " + tlsInfo(payload);
            } else if (httpLine != null) {
                proto = "HTTP";
                info += "  " + httpLine;
            } else if (sp == 443 || dp == 443 || sp == 8443 || dp == 8443) {
                proto = "HTTPS";
            } else if (sp == 80 || dp == 80 || sp == 8080 || dp == 8080) {
                proto = "HTTP";
            } else if (sp == 53 || dp == 53) {
                proto = "DNS";
            }
        } else if (udp != null) {
            UdpPacket.UdpHeader h = udp.getHeader();
            transport = "UDP";
            proto = "UDP";
            sp = h.getSrcPort().valueAsInt();
            dp = h.getDstPort().valueAsInt();
            info = sp + " → " + dp + " Len=" + Math.max(0, h.getLengthAsInt() - 8);
            if (sp == 53 || dp == 53 || sp == 5353 || dp == 5353) {
                proto = "DNS";
                info += dnsInfo(p);
            } else if (sp == 443 || dp == 443) proto = "QUIC";
            else if (sp == 67 || dp == 67 || sp == 68 || dp == 68) proto = "DHCP";
            else if (sp == 123 || dp == 123) proto = "NTP";
            else if (sp == 1900 || dp == 1900) proto = "SSDP";
        } else if (icmp4 != null) {
            proto = "ICMP";
            info = icmp4.getHeader().getType().name() + " (code " + icmp4.getHeader().getCode().valueAsString() + ")";
        } else if (icmp6 != null) {
            proto = "ICMPv6";
            info = icmp6.getHeader().getType().name() + " (code " + icmp6.getHeader().getCode().valueAsString() + ")";
        }

        Direction dir = direction(src, dst, srcMac, dstMac, local);
        return new PacketRecord(no, timeMillis, dir, src, dst, proto, transport, sp, dp, seq, ack, ipVer, info, raw, p);
    }

    // ---------------------------------------------------------------- details tree

    public static TreeItem<String> buildDetails(PacketRecord r, boolean zh) {
        TreeItem<String> root = new TreeItem<>(zh
                ? "封包 #" + r.no + "：" + r.raw.length + " 位元組"
                : "Frame " + r.no + ": " + r.raw.length + " bytes");
        root.setExpanded(true);
        Packet cur = r.packet;
        while (cur != null) {
            String text = null;
            try {
                if (cur.getHeader() != null) text = cur.getHeader().toString();
            } catch (Exception ignored) { }
            if (text == null) text = "[Data (" + cur.length() + " bytes)]";
            root.getChildren().add(layerNode(text, zh));
            cur = cur.getPayload();
        }
        return root;
    }

    private static TreeItem<String> layerNode(String text, boolean zh) {
        String[] lines = text.split("\\R");
        String title = lines[0].trim();
        if (title.startsWith("[") && title.endsWith("]")) title = title.substring(1, title.length() - 1);
        TreeItem<String> node = new TreeItem<>(zh ? DetailTranslator.title(title) : title);
        for (int i = 1; i < lines.length; i++) {
            String l = lines[i].trim();
            if (!l.isEmpty()) node.getChildren().add(new TreeItem<>(zh ? DetailTranslator.line(l) : l));
        }
        node.setExpanded(true);
        return node;
    }

    // ---------------------------------------------------------------- helpers

    private static String mac(LinkLayerAddress a) {
        return ByteArrays.toHexString(a.getAddress(), ":");
    }

    private static Direction direction(String src, String dst, String srcMac, String dstMac, LocalInfo l) {
        boolean srcLocal = l.ips().contains(LocalInfo.norm(src)) || (srcMac != null && l.macs().contains(srcMac));
        boolean dstLocal = l.ips().contains(LocalInfo.norm(dst)) || (dstMac != null && l.macs().contains(dstMac));
        if (srcLocal) return Direction.OUT;
        if (dstLocal) return Direction.IN;
        if (dstMac != null && dstMac.length() >= 2 && (Integer.parseInt(dstMac.substring(0, 2), 16) & 1) == 1) {
            return Direction.IN; // broadcast / multicast
        }
        return Direction.OTHER;
    }

    private static boolean isTls(byte[] b) {
        return b.length >= 5 && (b[0] & 0xFF) >= 0x14 && (b[0] & 0xFF) <= 0x17 && b[1] == 0x03 && (b[2] & 0xFF) <= 0x04;
    }

    private static String tlsInfo(byte[] b) {
        switch (b[0] & 0xFF) {
            case 0x14: return "TLS Change Cipher Spec";
            case 0x15: return "TLS Alert";
            case 0x17: return "TLS Application Data";
            case 0x16:
                if (b.length > 5) {
                    return switch (b[5] & 0xFF) {
                        case 1 -> "TLS Client Hello";
                        case 2 -> "TLS Server Hello";
                        case 4 -> "TLS New Session Ticket";
                        case 11 -> "TLS Certificate";
                        case 12 -> "TLS Server Key Exchange";
                        case 14 -> "TLS Server Hello Done";
                        case 16 -> "TLS Client Key Exchange";
                        case 20 -> "TLS Finished";
                        default -> "TLS Handshake";
                    };
                }
                return "TLS Handshake";
            default: return "TLS";
        }
    }

    private static String httpLine(byte[] pl) {
        if (pl.length < 4) return null;
        String s = new String(pl, 0, Math.min(pl.length, 200), StandardCharsets.ISO_8859_1);
        for (String t : HTTP_TOKENS) {
            if (s.startsWith(t)) {
                int e = s.indexOf('\r');
                if (e < 0) e = s.indexOf('\n');
                if (e < 0) e = s.length();
                return s.substring(0, e);
            }
        }
        return null;
    }

    private static String dnsInfo(Packet p) {
        try {
            DnsPacket dns = p.get(DnsPacket.class);
            if (dns == null) return "";
            DnsPacket.DnsHeader h = dns.getHeader();
            StringBuilder sb = new StringBuilder(h.isResponse() ? "  Response" : "  Query");
            for (DnsQuestion q : h.getQuestions()) sb.append(' ').append(q.getQName().getName());
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
