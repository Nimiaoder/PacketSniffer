package com.sniffer.stream;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 一條 TCP 連線的重組結果。
 * <ul>
 *   <li>方向 0 = 客戶端 → 伺服器，方向 1 = 伺服器 → 客戶端。</li>
 *   <li>以 Seq 排序、去除重傳與重疊，因此亂序、重傳的封包也能還原出正確資料。</li>
 *   <li>{@link #chunks} 依封包擷取順序排列，可直接用來呈現雙方交錯的對話。</li>
 * </ul>
 */
public final class TcpStream {

    /** 某個封包貢獻的「新」資料。 */
    public static final class Chunk {
        public final int dir;
        public final long pktNo;
        public final long timeMillis;
        public final int offset;        // 在該方向重組後資料流中的位置
        public final byte[] data;
        public final long gapBefore;    // 此資料之前缺少的位元組數 (封包遺失)

        Chunk(int dir, long pktNo, long timeMillis, int offset, byte[] data, long gapBefore) {
            this.dir = dir; this.pktNo = pktNo; this.timeMillis = timeMillis;
            this.offset = offset; this.data = data; this.gapBefore = gapBefore;
        }
    }

    public final String clientIp, serverIp;
    public final int clientPort, serverPort;
    public final int packetCount;
    public final int retransmissions;
    public final long[] bytes = new long[2];
    /** 兩個方向的 chunk，依封包編號排序。 */
    public final List<Chunk> chunks;

    private final byte[][] data = new byte[2][];
    private final int[] contiguousLen = new int[2];
    private final List<List<Chunk>> perDir = new ArrayList<>();
    private final Map<Long, Chunk> byPacket = new HashMap<>();

    private TcpStream(String cIp, int cPort, String sIp, int sPort, int packetCount, int retrans,
                      byte[][] data, int[] contiguousLen, List<Chunk> chunks) {
        this.clientIp = cIp; this.clientPort = cPort; this.serverIp = sIp; this.serverPort = sPort;
        this.packetCount = packetCount; this.retransmissions = retrans;
        this.data[0] = data[0]; this.data[1] = data[1];
        this.contiguousLen[0] = contiguousLen[0]; this.contiguousLen[1] = contiguousLen[1];
        this.chunks = chunks;
        perDir.add(new ArrayList<>());
        perDir.add(new ArrayList<>());
        for (Chunk c : chunks) {
            perDir.get(c.dir).add(c);
            byPacket.put(c.pktNo, c);
            bytes[c.dir] += c.data.length;
        }
    }

    /** @param segs 同一條連線的所有封包，需依擷取順序排列。 */
    public static TcpStream build(List<TcpSegment> segs) {
        if (segs.isEmpty()) throw new IllegalArgumentException("no segments");
        TcpSegment first = segs.get(0);
        TcpSegment initiator = null;
        for (TcpSegment s : segs) {
            if (s.syn() && !s.ack()) { initiator = s; break; }
        }
        String cIp = (initiator != null ? initiator : first).srcIp();
        int cPort = (initiator != null ? initiator : first).srcPort();
        boolean firstFromClient = first.srcIp().equals(cIp) && first.srcPort() == cPort;
        String sIp = firstFromClient ? first.dstIp() : first.srcIp();
        int sPort = firstFromClient ? first.dstPort() : first.srcPort();

        List<List<TcpSegment>> per = List.of(new ArrayList<>(), new ArrayList<>());
        for (TcpSegment s : segs) {
            boolean fromClient = s.srcIp().equals(cIp) && s.srcPort() == cPort;
            per.get(fromClient ? 0 : 1).add(s);
        }

        byte[][] data = new byte[2][];
        int[] contiguous = new int[2];
        List<Chunk> all = new ArrayList<>();
        int retrans = 0;

        for (int d = 0; d < 2; d++) {
            List<TcpSegment> list = per.get(d);
            // 決定相對序號的基準點
            long base = 0;
            boolean haveBase = false;
            for (TcpSegment s : list) {
                if (s.syn()) { base = s.seq() + 1; haveBase = true; break; }
            }
            List<TcpSegment> withData = new ArrayList<>();
            for (TcpSegment s : list) if (s.payload() != null && s.payload().length > 0) withData.add(s);
            if (!haveBase && !withData.isEmpty()) base = withData.get(0).seq();

            final long b = base;
            // 以相對序號排序 (用 int 相減處理 32 位元回繞)，同序號保持擷取順序
            List<TcpSegment> sorted = new ArrayList<>(withData);
            sorted.sort(Comparator.comparingLong(s -> (int) (s.seq() - b)));

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            long next = Long.MIN_VALUE;
            int firstGap = -1;
            for (TcpSegment s : sorted) {
                long rel = (int) (s.seq() - b);
                int len = s.payload().length;
                long end = rel + len;
                if (next == Long.MIN_VALUE) next = rel;
                if (end <= next) { retrans++; continue; }          // 重傳 / 完全重複
                int skip = 0;
                long gap = 0;
                if (rel < next) skip = (int) (next - rel);          // 部分重疊
                else if (rel > next) gap = rel - next;              // 中間缺資料
                byte[] piece = skip > 0 ? Arrays.copyOfRange(s.payload(), skip, len) : s.payload();
                int offset = buf.size();
                if (gap > 0 && firstGap < 0) firstGap = offset;
                buf.write(piece, 0, piece.length);
                all.add(new Chunk(d, s.no(), s.timeMillis(), offset, piece, gap));
                next = end;
            }
            data[d] = buf.toByteArray();
            contiguous[d] = firstGap < 0 ? data[d].length : firstGap;
        }

        all.sort(Comparator.<Chunk>comparingLong(c -> c.pktNo).thenComparingInt(c -> c.offset));
        return new TcpStream(cIp, cPort, sIp, sPort, segs.size(), retrans, data, contiguous, all);
    }

    /** 該方向重組後、遇到第一個缺口之前的連續資料。 */
    public byte[] contiguous(int dir) {
        return Arrays.copyOf(data[dir], contiguousLen[dir]);
    }

    public boolean hasGap(int dir) { return contiguousLen[dir] < data[dir].length; }

    public int dirOf(String srcIp, int srcPort) {
        return srcIp.equals(clientIp) && srcPort == clientPort ? 0 : 1;
    }

    public Chunk chunkFor(long pktNo) { return byPacket.get(pktNo); }

    /** 該方向資料流中某個位置，是由哪個封包送來的；找不到回傳 null。 */
    public Chunk chunkAt(int dir, int offset) {
        List<Chunk> l = perDir.get(dir);
        int lo = 0, hi = l.size() - 1;
        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            Chunk c = l.get(mid);
            if (offset < c.offset) hi = mid - 1;
            else if (offset >= c.offset + c.data.length) lo = mid + 1;
            else return c;
        }
        return null;
    }

    /** 同 {@link #chunkAt}，只回傳封包編號；找不到回傳 -1。 */
    public long packetAt(int dir, int offset) {
        Chunk c = chunkAt(dir, offset);
        return c == null ? -1 : c.pktNo;
    }
}
