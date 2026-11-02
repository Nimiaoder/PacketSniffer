package com.sniffer.capture;

import com.sniffer.model.PacketRecord;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * 以 Npcap (透過 pcap4j) 擷取封包。擷取執行緒把解析好的封包放進佇列，
 * UI 端以 {@link #drain(int)} 定時批次取出，避免高流量時卡住 JavaFX 執行緒。
 */
public final class CaptureService {
    private static final int MAX_PENDING = 300_000;

    private final ConcurrentLinkedQueue<PacketRecord> queue = new ConcurrentLinkedQueue<>();
    private final AtomicInteger pending = new AtomicInteger();
    private final AtomicLong counter = new AtomicLong();

    private volatile boolean running;
    private volatile boolean paused;
    private PcapHandle handle;
    private Thread thread;
    private PcapNetworkInterface current;

    /** 開始 (或從暫停恢復)。換網卡時會自動關閉舊的 handle 並重新開啟。 */
    public synchronized void start(PcapNetworkInterface nif, Consumer<String> onError) throws PcapNativeException {
        if (handle != null && nif.equals(current)) {
            paused = false;
            return;
        }
        shutdown();
        PcapHandle h = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 100);
        LocalInfo local = LocalInfo.of(nif);
        handle = h;
        current = nif;
        paused = false;
        running = true;
        thread = new Thread(() -> loop(h, local, onError), "packet-capture");
        thread.setDaemon(true);
        thread.start();
    }

    /** 暫停：handle 保持開啟，但期間的封包會被丟棄。 */
    public void pause() { paused = true; }

    public synchronized boolean isOpen() { return handle != null; }

    public synchronized void shutdown() {
        running = false;
        PcapHandle h = handle;
        Thread t = thread;
        if (h != null) {
            try { h.breakLoop(); } catch (Exception ignored) { }
        }
        if (t != null) {
            try { t.join(600); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
        if (h != null) {
            try { h.close(); } catch (Exception ignored) { }
        }
        handle = null;
        thread = null;
        current = null;
        paused = false;
    }

    /** 清除尚未顯示的封包並重設編號。 */
    public void reset() {
        queue.clear();
        pending.set(0);
        counter.set(0);
    }

    public List<PacketRecord> drain(int max) {
        List<PacketRecord> out = new ArrayList<>();
        PacketRecord r;
        while (out.size() < max && (r = queue.poll()) != null) out.add(r);
        pending.addAndGet(-out.size());
        return out;
    }

    private void loop(PcapHandle h, LocalInfo local, Consumer<String> onError) {
        try {
            while (running) {
                Packet p = h.getNextPacket();      // timeout 時回傳 null
                if (p == null || paused) continue;
                if (pending.get() > MAX_PENDING) continue;   // UI 來不及消化時丟棄
                long t = h.getTimestamp().getTime();
                queue.add(PacketParser.parse(counter.incrementAndGet(), p, t, local));
                pending.incrementAndGet();
            }
        } catch (NotOpenException e) {
            // handle 已關閉
        } catch (Exception e) {
            if (running) onError.accept(String.valueOf(e.getMessage()));
        }
    }
}
