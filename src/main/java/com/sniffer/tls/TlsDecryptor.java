package com.sniffer.tls;

import com.sniffer.stream.TcpStream;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 以 SSLKEYLOGFILE 的金鑰解密 TLS 1.2 / 1.3 (AES-GCM、ChaCha20-Poly1305)。
 * 不支援 CBC 套件、QUIC、TLS 1.2 以前的版本。
 */
public final class TlsDecryptor {
    private TlsDecryptor() {}

    private record Suite(String name, boolean chacha, int keyLen, String hmac) {}

    private static final Map<Integer, Suite> TLS12 = Map.ofEntries(
            Map.entry(0xC02F, new Suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, 16, "HmacSHA256")),
            Map.entry(0xC02B, new Suite("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", false, 16, "HmacSHA256")),
            Map.entry(0x009C, new Suite("TLS_RSA_WITH_AES_128_GCM_SHA256", false, 16, "HmacSHA256")),
            Map.entry(0x009E, new Suite("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", false, 16, "HmacSHA256")),
            Map.entry(0xC030, new Suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false, 32, "HmacSHA384")),
            Map.entry(0xC02C, new Suite("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", false, 32, "HmacSHA384")),
            Map.entry(0x009D, new Suite("TLS_RSA_WITH_AES_256_GCM_SHA384", false, 32, "HmacSHA384")),
            Map.entry(0x009F, new Suite("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", false, 32, "HmacSHA384")),
            Map.entry(0xCCA8, new Suite("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", true, 32, "HmacSHA256")),
            Map.entry(0xCCA9, new Suite("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", true, 32, "HmacSHA256")),
            Map.entry(0xCCAA, new Suite("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", true, 32, "HmacSHA256")));

    private static final Map<Integer, Suite> TLS13 = Map.of(
            0x1301, new Suite("TLS_AES_128_GCM_SHA256", false, 16, "HmacSHA256"),
            0x1302, new Suite("TLS_AES_256_GCM_SHA384", false, 32, "HmacSHA384"),
            0x1303, new Suite("TLS_CHACHA20_POLY1305_SHA256", true, 32, "HmacSHA256"));

    /** HelloRetryRequest 固定的 server_random。 */
    private static final String HRR_RANDOM =
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c";

    private record Rec(int dir, int offset, int type, int version, byte[] frag) {
        int total() { return 5 + frag.length; }
    }

    private record Hello(boolean tls13, int suite, byte[] random) {}

    private static final class Key {
        final byte[] key, iv;
        Key(byte[] key, byte[] iv) { this.key = key; this.iv = iv; }
    }

    // ------------------------------------------------------------------ entry

    public static TlsResult decrypt(TcpStream st, KeyLog kl) {
        TlsResult r = new TlsResult();
        try {
            run(st, kl, r);
        } catch (Exception e) {
            r.records.clear();
            r.error = "解密時發生錯誤：" + e;
        }
        return r;
    }

    private static void run(TcpStream st, KeyLog kl, TlsResult r) throws GeneralSecurityException {
        List<Rec> rc = parseRecords(st.contiguous(0), 0);
        List<Rec> rs = parseRecords(st.contiguous(1), 1);

        if (rc.isEmpty() || rc.get(0).type() != 0x16 || rc.get(0).frag().length < 38
                || (rc.get(0).frag()[0] & 0xFF) != 1) {
            r.error = "此連線不是 TLS，或擷取時連線已建立、沒有抓到握手 (ClientHello)，無法解密。";
            return;
        }
        byte[] clientRandom = Arrays.copyOfRange(rc.get(0).frag(), 6, 38);
        Hello hello = findServerHello(rs);
        if (hello == null) {
            r.error = "沒有抓到 ServerHello，無法判斷加密套件。";
            return;
        }
        Map<String, byte[]> secrets = kl.get(Hex.toHex(clientRandom));
        if (secrets == null) {
            r.error = "金鑰檔中找不到這條連線的金鑰 (client_random 開頭 "
                    + Hex.toHex(clientRandom).substring(0, 16) + "…)。請確認金鑰檔來自同一次連線。";
            return;
        }
        Suite suite = (hello.tls13() ? TLS13 : TLS12).get(hello.suite());
        if (suite == null) {
            r.error = String.format("尚不支援的加密套件 0x%04X（目前支援 AES-GCM 與 ChaCha20-Poly1305）。", hello.suite());
            return;
        }
        r.version = hello.tls13() ? "TLS 1.3" : "TLS 1.2";
        r.suiteName = suite.name();

        if (hello.tls13()) decrypt13(rc, rs, secrets, suite, r);
        else decrypt12(rc, rs, secrets, suite, clientRandom, hello.random(), r);

        r.records.sort((a, b) -> a.dir != b.dir ? Integer.compare(a.dir, b.dir) : Integer.compare(a.offset, b.offset));
        for (TlsRecord x : r.records) {
            if (x.decrypted) r.decryptedCount++;
            else if (x.encrypted) r.failedCount++;
        }
    }

    // ------------------------------------------------------------------ records / hello

    private static List<Rec> parseRecords(byte[] d, int dir) {
        List<Rec> out = new ArrayList<>();
        int o = 0;
        while (o + 5 <= d.length) {
            int type = d[o] & 0xFF;
            int ver = u16(d, o + 1);
            int len = u16(d, o + 3);
            if (type < 0x14 || type > 0x18 || (ver >> 8) != 3 || len > 16384 + 2048) break;
            if (o + 5 + len > d.length) break;                 // 最後一筆不完整
            out.add(new Rec(dir, o, type, ver, Arrays.copyOfRange(d, o + 5, o + 5 + len)));
            o += 5 + len;
        }
        return out;
    }

    private static Hello findServerHello(List<Rec> rs) {
        for (Rec x : rs) {
            if (x.type() == 0x17) break;                       // 之後都是加密資料
            if (x.type() != 0x16) continue;
            byte[] f = x.frag();
            if (f.length < 40 || (f[0] & 0xFF) != 2) continue;
            byte[] random = Arrays.copyOfRange(f, 6, 38);
            if (Hex.toHex(random).equals(HRR_RANDOM)) continue;   // HelloRetryRequest → 找下一個 ServerHello
            int p = 39 + (f[38] & 0xFF);
            if (p + 3 > f.length) return null;
            int suite = u16(f, p);
            p += 3;                                            // cipher(2) + compression(1)
            boolean tls13 = false;
            if (p + 2 <= f.length) {
                int end = Math.min(f.length, p + 2 + u16(f, p));
                p += 2;
                while (p + 4 <= end) {
                    int t = u16(f, p), l = u16(f, p + 2);
                    p += 4;
                    if (t == 0x002B && l >= 2 && p + 2 <= end && u16(f, p) == 0x0304) tls13 = true;
                    p += l;
                }
            }
            return new Hello(tls13, suite, random);
        }
        return null;
    }

    // ------------------------------------------------------------------ TLS 1.2

    private static void decrypt12(List<Rec> rc, List<Rec> rs, Map<String, byte[]> secrets, Suite s,
                                  byte[] clientRandom, byte[] serverRandom, TlsResult r)
            throws GeneralSecurityException {
        byte[] ms = secrets.get("CLIENT_RANDOM");
        if (ms == null) {
            r.error = "金鑰檔中缺少 CLIENT_RANDOM (master secret)，無法解密 TLS 1.2。";
            return;
        }
        int ivLen = s.chacha() ? 12 : 4;
        byte[] block = prf(s.hmac(), ms, "key expansion", concat(serverRandom, clientRandom), 2 * s.keyLen() + 2 * ivLen);
        Key ck = new Key(Arrays.copyOfRange(block, 0, s.keyLen()),
                Arrays.copyOfRange(block, 2 * s.keyLen(), 2 * s.keyLen() + ivLen));
        Key sk = new Key(Arrays.copyOfRange(block, s.keyLen(), 2 * s.keyLen()),
                Arrays.copyOfRange(block, 2 * s.keyLen() + ivLen, 2 * s.keyLen() + 2 * ivLen));

        for (int dir = 0; dir < 2; dir++) {
            Key k = dir == 0 ? ck : sk;
            boolean encrypted = false;
            long seq = 0;
            for (Rec rec : dir == 0 ? rc : rs) {
                TlsRecord out = new TlsRecord(rec.dir(), rec.offset(), rec.total(), rec.type());
                r.records.add(out);
                if (!encrypted) {
                    out.plaintext = rec.frag();
                    if (rec.type() == 0x14) { encrypted = true; seq = 0; }
                    continue;
                }
                out.encrypted = true;
                try {
                    byte[] frag = rec.frag();
                    int ptLen;
                    byte[] nonce, ct;
                    if (s.chacha()) {
                        ct = frag;
                        ptLen = ct.length - 16;
                        nonce = xorSeq(k.iv, seq);
                    } else {
                        if (frag.length < 8 + 16) throw new GeneralSecurityException("record too short");
                        nonce = concat(k.iv, Arrays.copyOfRange(frag, 0, 8));
                        ct = Arrays.copyOfRange(frag, 8, frag.length);
                        ptLen = ct.length - 16;
                    }
                    if (ptLen < 0) throw new GeneralSecurityException("record too short");
                    byte[] aad = new byte[13];
                    putLong(aad, 0, seq);
                    aad[8] = (byte) rec.type();
                    aad[9] = (byte) (rec.version() >> 8);
                    aad[10] = (byte) rec.version();
                    aad[11] = (byte) (ptLen >> 8);
                    aad[12] = (byte) ptLen;
                    out.plaintext = aead(s, k.key, nonce, aad, ct);
                    out.decrypted = true;
                } catch (GeneralSecurityException e) {
                    out.note = "解密失敗（金鑰不符或資料不完整）";
                }
                seq++;
            }
        }
    }

    // ------------------------------------------------------------------ TLS 1.3

    private static void decrypt13(List<Rec> rc, List<Rec> rs, Map<String, byte[]> secrets, Suite s, TlsResult r)
            throws GeneralSecurityException {
        List<Key> ck = keys13(secrets, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_", s);
        List<Key> sk = keys13(secrets, "SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_", s);
        if (ck.isEmpty() && sk.isEmpty()) {
            r.error = "金鑰檔中缺少 TLS 1.3 的 TRAFFIC_SECRET，無法解密。";
            return;
        }
        for (int dir = 0; dir < 2; dir++) {
            List<Key> keys = dir == 0 ? ck : sk;
            int idx = 0;
            long seq = 0;
            for (Rec rec : dir == 0 ? rc : rs) {
                TlsRecord out = new TlsRecord(rec.dir(), rec.offset(), rec.total(), rec.type());
                r.records.add(out);
                if (rec.type() != 0x17) {                      // ClientHello / ServerHello / CCS 等都是明文
                    out.plaintext = rec.frag();
                    continue;
                }
                out.encrypted = true;
                byte[] aad = {0x17, 0x03, 0x03, (byte) (rec.frag().length >> 8), (byte) rec.frag().length};
                byte[] inner = null;
                int found = -1;
                for (int k = idx; k < keys.size() && inner == null; k++) {
                    long sq = (k == idx) ? seq : 0;            // 換到新一代金鑰時序號從 0 開始
                    try {
                        inner = aead(s, keys.get(k).key, xorSeq(keys.get(k).iv, sq), aad, rec.frag());
                        found = k;
                    } catch (GeneralSecurityException ignored) {
                        // 嘗試下一代金鑰 (握手金鑰 → 應用程式金鑰 → KeyUpdate)
                    }
                }
                if (inner == null) {
                    out.note = "解密失敗（金鑰不符或資料不完整）";
                    seq++;
                    continue;
                }
                if (found != idx) { idx = found; seq = 0; }
                seq++;
                int end = inner.length;
                while (end > 0 && inner[end - 1] == 0) end--;  // 移除結尾 padding
                if (end == 0) {
                    out.note = "內容為空";
                    out.plaintext = new byte[0];
                    out.decrypted = true;
                    continue;
                }
                out.contentType = inner[end - 1] & 0xFF;
                out.plaintext = Arrays.copyOf(inner, end - 1);
                out.decrypted = true;
            }
        }
    }

    /** 依序排出 [握手金鑰, 應用程式金鑰 0, 1, 2…]。 */
    private static List<Key> keys13(Map<String, byte[]> secrets, String hsLabel, String trafficPrefix, Suite s)
            throws GeneralSecurityException {
        List<byte[]> ordered = new ArrayList<>();
        if (secrets.get(hsLabel) != null) ordered.add(secrets.get(hsLabel));
        TreeMap<Integer, byte[]> traffic = new TreeMap<>();
        for (Map.Entry<String, byte[]> e : secrets.entrySet()) {
            if (e.getKey().startsWith(trafficPrefix)) {
                try {
                    traffic.put(Integer.parseInt(e.getKey().substring(trafficPrefix.length())), e.getValue());
                } catch (NumberFormatException ignored) { }
            }
        }
        ordered.addAll(traffic.values());
        List<Key> out = new ArrayList<>();
        for (byte[] sec : ordered) {
            out.add(new Key(hkdfExpandLabel(s.hmac(), sec, "key", new byte[0], s.keyLen()),
                    hkdfExpandLabel(s.hmac(), sec, "iv", new byte[0], 12)));
        }
        return out;
    }

    // ------------------------------------------------------------------ crypto helpers

    static byte[] hkdfExpandLabel(String hmac, byte[] secret, String label, byte[] context, int length)
            throws GeneralSecurityException {
        byte[] full = ("tls13 " + label).getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream info = new ByteArrayOutputStream();
        info.write(length >> 8);
        info.write(length);
        info.write(full.length);
        info.write(full, 0, full.length);
        info.write(context.length);
        info.write(context, 0, context.length);
        return hkdfExpand(hmac, secret, info.toByteArray(), length);
    }

    private static byte[] hkdfExpand(String hmac, byte[] prk, byte[] info, int length) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(hmac);
        mac.init(new SecretKeySpec(prk, hmac));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] t = new byte[0];
        for (int i = 1; out.size() < length; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            out.write(t, 0, t.length);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    /** TLS 1.2 PRF (RFC 5246 §5)。 */
    static byte[] prf(String hmac, byte[] secret, String label, byte[] seed, int length) throws GeneralSecurityException {
        byte[] ls = concat(label.getBytes(StandardCharsets.US_ASCII), seed);
        Mac mac = Mac.getInstance(hmac);
        mac.init(new SecretKeySpec(secret, hmac));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] a = ls;
        while (out.size() < length) {
            a = mac.doFinal(a);                                // A(i)
            mac.update(a);
            mac.update(ls);
            byte[] p = mac.doFinal();
            out.write(p, 0, p.length);
        }
        return Arrays.copyOf(out.toByteArray(), length);
    }

    private static byte[] aead(Suite s, byte[] key, byte[] nonce, byte[] aad, byte[] ct) throws GeneralSecurityException {
        Cipher c;
        if (s.chacha()) {
            c = Cipher.getInstance("ChaCha20-Poly1305");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        } else {
            c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        }
        c.updateAAD(aad);
        return c.doFinal(ct);
    }

    private static byte[] xorSeq(byte[] iv, long seq) {
        byte[] n = iv.clone();
        for (int i = 0; i < 8; i++) n[n.length - 1 - i] ^= (byte) (seq >>> (8 * i));
        return n;
    }

    private static void putLong(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte) (v >>> (56 - 8 * i));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] o = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    private static int u16(byte[] b, int o) { return (b[o] & 0xFF) << 8 | (b[o + 1] & 0xFF); }
}
