package com.sniffer.tls;

import java.util.ArrayList;
import java.util.List;

/** 一條 TCP 連線的 TLS 解析 / 解密結果。 */
public final class TlsResult {
    /** 非 null 表示無法解密，內容為原因 (可直接顯示給使用者)。 */
    public String error;
    public String version = "";
    public String suiteName = "";
    public final List<TlsRecord> records = new ArrayList<>();
    public int decryptedCount;
    public int failedCount;

    public boolean usable() { return error == null; }

    public String summary() {
        if (error != null) return error;
        return version + " · " + suiteName + " · 已解密 " + decryptedCount + " 筆"
                + (failedCount > 0 ? "，失敗 " + failedCount + " 筆" : "");
    }
}
