package com.sniffer.util;

import com.sniffer.model.Direction;
import com.sniffer.model.PacketRecord;

import java.util.List;
import java.util.function.Predicate;

/** 組合 協定 / 方向 / 搜尋 三種條件成一個 Predicate。 */
public final class PacketFilter {
    private PacketFilter() {}

    public enum Mode {
        FIELD("一般搜尋（表格內容）",
              "搜尋表格中的任何內容，例如 IP、埠號、Seq、協定（多個關鍵字用空白分隔，需全部符合）",
              "比對表格各欄與資訊欄的文字。\n例：192.168.1.5 443 SYN（三個條件都要符合）"),
        TEXT("封包文字內容",
             "搜尋封包資料中的可讀文字，例如 GET、Host、password",
             "在封包的原始資料中搜尋可讀的英文/數字文字（不分大小寫）。\n例：GET /index"),
        HEX("特徵碼（十六進位）",
            "輸入十六進位位元組，例如 47 45 54；用 ?? 代表任意一個位元組",
            "在封包原始資料中搜尋指定的位元組序列。\n例：47 45 54（即 GET）、16 03 ?? 01（?? 可為任意值）");

        private final String label;
        public final String prompt;
        public final String tip;

        Mode(String label, String prompt, String tip) {
            this.label = label;
            this.prompt = prompt;
            this.tip = tip;
        }

        @Override public String toString() { return label; }
    }

    public static final String ALL = "全部";
    public static final List<String> PROTOCOLS =
            List.of(ALL, "TCP", "UDP", "HTTP", "HTTPS", "DNS", "ICMP", "ARP", "IPv4", "IPv6");

    public static boolean isValid(Mode mode, String q) {
        if (mode != Mode.HEX || q == null || q.isBlank()) return true;
        return HexUtil.parsePattern(q) != null;
    }

    public static Predicate<PacketRecord> build(String protocol, Direction dir, Mode mode, String query) {
        Predicate<PacketRecord> proto = switch (protocol == null ? ALL : protocol) {
            case "TCP" -> r -> "TCP".equals(r.transport);
            case "UDP" -> r -> "UDP".equals(r.transport);
            case "HTTP" -> r -> "HTTP".equals(r.protocol);
            case "HTTPS" -> r -> "HTTPS".equals(r.protocol);
            case "DNS" -> r -> "DNS".equals(r.protocol);
            case "ICMP" -> r -> r.protocol.startsWith("ICMP");
            case "ARP" -> r -> "ARP".equals(r.protocol);
            case "IPv4" -> r -> r.ipVersion == 4;
            case "IPv6" -> r -> r.ipVersion == 6;
            default -> r -> true;
        };

        Predicate<PacketRecord> direction = dir == null ? r -> true : r -> r.direction == dir;

        Predicate<PacketRecord> search = r -> true;
        if (query != null && !query.isBlank()) {
            switch (mode) {
                case FIELD -> {
                    String[] tokens = query.toLowerCase().trim().split("\\s+");
                    search = r -> {
                        String b = r.blob();
                        for (String t : tokens) if (!b.contains(t)) return false;
                        return true;
                    };
                }
                case TEXT -> {
                    String q = query.toLowerCase();
                    search = r -> r.asciiLower().contains(q);
                }
                case HEX -> {
                    int[] pat = HexUtil.parsePattern(query);
                    if (pat != null) search = r -> HexUtil.contains(r.raw, pat);
                }
            }
        }
        return proto.and(direction).and(search);
    }
}
