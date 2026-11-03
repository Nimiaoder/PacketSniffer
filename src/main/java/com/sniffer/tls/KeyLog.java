package com.sniffer.tls;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * NSS Key Log (SSLKEYLOGFILE) 格式：每行 "LABEL <client_random hex> <secret hex>"。
 * 支援 TLS 1.2 的 CLIENT_RANDOM，以及 TLS 1.3 的 *_HANDSHAKE_TRAFFIC_SECRET / *_TRAFFIC_SECRET_N。
 */
public final class KeyLog {
    private final Map<String, Map<String, byte[]>> sessions = new HashMap<>();

    /** @return 本次成功讀入的金鑰行數 */
    public synchronized int load(Path file) throws IOException {
        int n = 0;
        for (String line : Files.readAllLines(file, StandardCharsets.ISO_8859_1)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            String[] p = t.split("\\s+");
            if (p.length != 3) continue;
            String cr = p[1].toLowerCase();
            byte[] secret = Hex.parse(p[2].toLowerCase());
            if (cr.length() != 64 || Hex.parse(cr) == null || secret == null || secret.length == 0) continue;
            sessions.computeIfAbsent(cr, k -> new HashMap<>()).put(p[0], secret);
            n++;
        }
        return n;
    }

    public synchronized Map<String, byte[]> get(String clientRandomHex) {
        Map<String, byte[]> m = sessions.get(clientRandomHex.toLowerCase());
        return m == null ? null : new HashMap<>(m);
    }

    public synchronized int sessionCount() { return sessions.size(); }

    public synchronized boolean isEmpty() { return sessions.isEmpty(); }

    public synchronized void clear() { sessions.clear(); }
}
