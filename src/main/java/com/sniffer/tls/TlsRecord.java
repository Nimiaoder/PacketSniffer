package com.sniffer.tls;

/** 一筆 TLS 記錄 (含解密結果)。 */
public final class TlsRecord {
    public final int dir;            // 0 = 客戶端 → 伺服器, 1 = 伺服器 → 客戶端
    public final int offset;         // 在該方向資料流中的位置
    public final int totalLength;    // 含 5 bytes 記錄標頭
    public final int outerType;      // 記錄標頭上的類型
    public int contentType;          // 解密後的實際類型 (TLS 1.3 為內層類型)
    public boolean encrypted;
    public boolean decrypted;
    public byte[] plaintext;         // 未加密記錄為原內容；解密失敗為 null
    public String note;

    TlsRecord(int dir, int offset, int totalLength, int outerType) {
        this.dir = dir; this.offset = offset; this.totalLength = totalLength; this.outerType = outerType;
        this.contentType = outerType;
    }

    public static String typeName(int t) {
        return switch (t) {
            case 0x14 -> "Change Cipher Spec";
            case 0x15 -> "Alert";
            case 0x16 -> "Handshake";
            case 0x17 -> "Application Data";
            case 0x18 -> "Heartbeat";
            default -> "Unknown (0x" + Integer.toHexString(t) + ")";
        };
    }
}
