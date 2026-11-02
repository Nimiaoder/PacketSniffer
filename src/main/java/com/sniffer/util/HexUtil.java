package com.sniffer.util;

public final class HexUtil {
    private HexUtil() {}

    /** 產生類似 Wireshark 的 Hex + ASCII 傾印。 */
    public static String dump(byte[] d) {
        StringBuilder sb = new StringBuilder(d.length * 4 + 64);
        for (int i = 0; i < d.length; i += 16) {
            sb.append(String.format("%04X  ", i));
            for (int j = 0; j < 16; j++) {
                if (i + j < d.length) sb.append(String.format("%02X ", d[i + j] & 0xFF));
                else sb.append("   ");
                if (j == 7) sb.append(' ');
            }
            sb.append(' ');
            for (int j = 0; j < 16 && i + j < d.length; j++) {
                int v = d[i + j] & 0xFF;
                sb.append(v >= 32 && v < 127 ? (char) v : '.');
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
     * 解析特徵碼，例如 "47 45 54"、"0x474554"、"47 ?? 54"。
     * 回傳每個位元組 (0-255)，萬用字元為 -1；格式錯誤回傳 null。
     */
    public static int[] parsePattern(String s) {
        if (s == null) return null;
        String t = s.replaceAll("(?i)0x", "").replaceAll("[\\s,:\\-]", "");
        if (t.isEmpty() || t.length() % 2 != 0) return null;
        int[] out = new int[t.length() / 2];
        for (int i = 0; i < out.length; i++) {
            String pair = t.substring(i * 2, i * 2 + 2);
            if (pair.equals("??") || pair.equals("**")) { out[i] = -1; continue; }
            try { out[i] = Integer.parseInt(pair, 16); }
            catch (NumberFormatException e) { return null; }
        }
        return out;
    }

    public static boolean contains(byte[] data, int[] pat) {
        outer:
        for (int i = 0; i <= data.length - pat.length; i++) {
            for (int j = 0; j < pat.length; j++) {
                if (pat[j] >= 0 && (data[i + j] & 0xFF) != pat[j]) continue outer;
            }
            return true;
        }
        return false;
    }
}
