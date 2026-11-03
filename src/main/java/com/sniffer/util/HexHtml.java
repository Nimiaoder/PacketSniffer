package com.sniffer.util;

/**
 * 產生 WebView 用的 HTML：Hex 傾印拆成「位移 / Hex / 文字」三個獨立欄位，
 * 這樣在畫面上拖曳反白時只會選到同一欄，可以分開複製。
 */
public final class HexHtml {
    private HexHtml() {}

    private static final String CSS =
            "html{overflow-y:scroll;}"
            + "html,body{margin:0;padding:0;background:transparent;color:#e8eef7;"
            + "font:12px 'Cascadia Mono',Consolas,monospace;}"
            + "::-webkit-scrollbar{width:12px;height:12px;}"
            + "::-webkit-scrollbar-track{background:rgba(255,255,255,0.07);}"
            + "::-webkit-scrollbar-thumb{background:rgba(255,255,255,0.38);border-radius:6px;}"
            + "::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,0.58);}"
            + "::-webkit-scrollbar-corner{background:transparent;}"
            + "::selection{background:#f59e0b;color:#111827;}"
            // 一段資料 (含標頭)
            + ".p{margin:0 0 6px 0;border-left:3px solid #94a3b8;background:rgba(255,255,255,0.04);}"
            + ".p.c{border-color:#f87171;background:rgba(248,113,113,0.12);}"
            + ".p.s{border-color:#60a5fa;background:rgba(96,165,250,0.12);}"
            + ".hd{padding:5px 12px;font:11px 'Segoe UI','Microsoft JhengHei UI',sans-serif;"
            + "color:#cbd5e1;background:rgba(0,0,0,0.20);}"
            + ".hd span{margin-right:14px;}"
            + ".hd .tag{font-weight:bold;padding:1px 9px;border-radius:9px;background:#94a3b8;color:#0f172a;}"
            + ".c .hd .tag{background:#f87171;color:#3b0a0a;}"
            + ".s .hd .tag{background:#60a5fa;color:#0b1f4a;}"
            + ".hd .t{color:#e2e8f0;}"
            + ".hd .ep{color:#94a3b8;}"
            + ".hd .len{float:right;margin-right:0;color:#e2e8f0;}"
            // 文字內容
            + "pre{margin:0;padding:6px 12px;white-space:pre-wrap;word-wrap:break-word;font:inherit;}"
            + ".c pre{color:#fecaca;}.s pre{color:#bfdbfe;}"
            // Hex 傾印：三欄各自獨立
            + ".hx{display:table;}"
            + ".hx pre{display:table-cell;white-space:pre;padding:6px 14px 6px 12px;vertical-align:top;}"
            + ".hx .off{color:#94a3b8;}"
            + ".hx .hex{color:#e8eef7;}.c .hx .hex{color:#fecaca;}.s .hx .hex{color:#bfdbfe;}"
            + ".hx .asc{color:#fde68a;}"
            + ".g{padding:4px 12px;color:#fbbf24;font-style:italic;}";

    public static final String PAGE_END = "</body></html>";

    public static String pageStart() {
        return "<html><head><meta charset=\"utf-8\"><style>" + CSS + "</style></head><body>";
    }

    public static String page(String bodyHtml) {
        return pageStart() + bodyHtml + PAGE_END;
    }

    public static String note(String msg) {
        return "<div class=\"g\">" + escape(msg) + "</div>";
    }

    public static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Hex 傾印區塊：位移 | Hex | ASCII 三個獨立欄位 (各自是一個 pre)。 */
    public static String hexBlock(byte[] d, int base) {
        StringBuilder off = new StringBuilder(), hex = new StringBuilder(), asc = new StringBuilder();
        for (int i = 0; i < d.length; i += 16) {
            if (i > 0) { off.append('\n'); hex.append('\n'); asc.append('\n'); }
            off.append(String.format("%08X", base + i));
            for (int j = 0; j < 16; j++) {
                if (j == 8) hex.append(' ');
                if (i + j < d.length) hex.append(String.format("%02X", d[i + j] & 0xFF));
                else hex.append("  ");
                if (j < 15) hex.append(' ');
            }
            for (int j = 0; j < 16 && i + j < d.length; j++) {
                int v = d[i + j] & 0xFF;
                asc.append(v >= 32 && v < 127 ? (char) v : '.');
            }
        }
        return "<div class=\"hx\"><pre class=\"off\">" + off + "</pre><pre class=\"hex\">" + hex
                + "</pre><pre class=\"asc\">" + escape(asc.toString()) + "</pre></div>";
    }

    /** 只有十六進位位元組 (每行 16 個)，給「只複製 Hex」使用。 */
    public static String hexOnly(byte[] d) {
        StringBuilder sb = new StringBuilder(d.length * 3);
        for (int i = 0; i < d.length; i++) {
            if (i > 0) sb.append(i % 16 == 0 ? '\n' : ' ');
            sb.append(String.format("%02X", d[i] & 0xFF));
        }
        return sb.toString();
    }

    /** 只有可見 ASCII (其餘以 . 取代)，給「只複製文字」使用。 */
    public static String asciiOnly(byte[] d) {
        StringBuilder sb = new StringBuilder(d.length);
        for (byte b : d) {
            int v = b & 0xFF;
            sb.append(v >= 32 && v < 127 ? (char) v : '.');
        }
        return sb.toString();
    }
}
