package com.sniffer.util;

import java.util.HashMap;
import java.util.Map;

/**
 * 把 pcap4j 輸出的英文標頭描述轉成中文。
 * 只翻譯一般詞彙；IPv4、TTL、TOS、IHL、SYN、ACK、MAC 等專有名詞維持原樣。
 * 找不到對應的欄位名稱時保留英文，不會出錯。
 */
public final class DetailTranslator {
    private DetailTranslator() {}

    private static final Map<String, String> LABELS = new HashMap<>();

    static {
        // 共用
        put("source address", "來源位址");
        put("destination address", "目的位址");
        put("type", "類型");
        put("version", "版本");
        put("length", "長度");
        put("total length", "總長度");
        put("identification", "識別碼");
        put("flags", "旗標");
        put("fragment offset", "分片位移");
        put("protocol", "協定");
        put("checksum", "檢查碼");
        put("header checksum", "標頭檢查碼");
        put("padding", "填充");
        put("pad", "填充");
        put("payload", "資料");
        put("code", "代碼");
        put("reserved", "保留");
        put("option", "選項");
        put("options", "選項");
        // TCP / UDP
        put("source port", "來源埠");
        put("destination port", "目的埠");
        put("sequence number", "序號 (Seq)");
        put("acknowledgment number", "確認號 (Ack)");
        put("data offset", "資料位移");
        put("window", "視窗大小");
        put("urgent pointer", "緊急指標");
        // IPv6
        put("traffic class", "流量類別");
        put("flow label", "流量標籤");
        put("payload length", "資料長度");
        put("next header", "下一個標頭");
        put("hop limit", "跳數限制");
        // ARP
        put("hardware type", "硬體類型");
        put("protocol type", "協定類型");
        put("hardware address length", "硬體位址長度");
        put("protocol address length", "協定位址長度");
        put("operation", "操作");
        put("source hardware address", "來源硬體位址");
        put("source protocol address", "來源協定位址");
        put("destination hardware address", "目的硬體位址");
        put("destination protocol address", "目的協定位址");
    }

    private static void put(String en, String zh) { LABELS.put(en, zh); }

    /** 層標題，例如 "IPv4 Header (20 bytes)" → "IPv4 標頭 (20 位元組)"。 */
    public static String title(String t) {
        return t.replaceAll("\\bCommon Header\\b", "通用標頭")
                .replaceAll("\\bHeader\\b", "標頭")
                .replaceAll("\\bbytes\\b", "位元組")
                .replaceAll("\\bData\\b", "資料")
                .replaceAll("\\bUnknown\\b", "未知");
    }

    /** 一行 "Label: value" → "中文標籤: value"，專有名詞不動。 */
    public static String line(String l) {
        int i = l.indexOf(": ");
        if (i > 0) {
            String label = l.substring(0, i);
            String zh = LABELS.getOrDefault(label.trim().toLowerCase(), label);
            return zh + ": " + value(l.substring(i + 2));
        }
        return value(l);
    }

    private static String value(String v) {
        return v.replaceAll("\\btrue\\b", "是")
                .replaceAll("\\bfalse\\b", "否")
                .replace("[bytes]", "[位元組]")
                .replaceAll("\\bbytes\\b", "位元組")
                .replace("Don't Fragment", "不可分片")
                .replace("More Fragment", "更多分片")
                .replaceAll("\\bReserved\\b", "保留");
    }
}
