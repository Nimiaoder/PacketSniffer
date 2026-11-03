package com.sniffer;

import com.sniffer.stream.TcpStream;
import com.sniffer.tls.TlsRecord;
import com.sniffer.tls.TlsResult;
import com.sniffer.ui.ResizeHelper;
import com.sniffer.ui.WindowChrome;
import com.sniffer.util.HexHtml;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.scene.web.WebView;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 「追蹤 TCP 串流」視窗：依封包順序顯示雙方的連續資料。
 * 每一段資料都有標頭 (發送/接收、封包編號、時間、來源→目的、大小)，並以顏色區分方向。
 * 內容可直接反白複製；Hex 傾印模式下「位移 / Hex / 文字」是三個獨立欄位，可分開複製。
 * 有匯入 SSL 金鑰且能解密時，可切換成解密後的內容。
 */
public final class FollowStreamController {

    private static final int MAX_VIEW_BYTES = 1_000_000;
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    /** 顯示用的一段資料。data 為 null 代表「缺口」提示。 */
    private record Piece(int dir, byte[] data, long gap, long pktNo, int offset, long timeMillis, boolean decrypted) {}

    @FXML private BorderPane root;
    @FXML private HBox dragArea;
    @FXML private Button minBtn, maxBtn, closeBtn;
    @FXML private Label titleLabel, endpointLabel, legendSend, legendRecv, statsLabel, tlsLabel;
    @FXML private ComboBox<String> sourceBox, formatBox, dirBox;
    @FXML private CheckBox showHeader;
    @FXML private StackPane viewCard;
    @FXML private WebView webView;

    private TcpStream stream;
    private TlsResult tls;
    private Stage stage;
    private boolean tlsUsable;
    /** 由本機送出的方向 (0 = 客戶端 → 伺服器, 1 = 反向)；-1 表示不知道 (例如在路由器上擷取)。 */
    private int localDir = -1;
    private long firstTime;
    private String plainText = "";

    /** 開啟追蹤視窗。tls 為 null 表示尚未匯入金鑰；localDir 見欄位說明。 */
    public static void open(String css, TcpStream stream, TlsResult tls, int localDir) throws IOException {
        FXMLLoader loader = new FXMLLoader(FollowStreamController.class.getResource("/fxml/FollowStream.fxml"));
        Parent root = loader.load();
        FollowStreamController c = loader.getController();

        Stage st = new Stage(StageStyle.TRANSPARENT);
        Scene scene = new Scene(root, 1040, 700);
        scene.setFill(Color.TRANSPARENT);
        scene.getStylesheets().add(css);
        st.setScene(scene);
        st.setMinWidth(820);
        st.setMinHeight(420);
        st.setTitle("追蹤 TCP 串流");

        WindowChrome chrome = WindowChrome.install(st, c.root, c.dragArea, c.minBtn, c.maxBtn, c.closeBtn);
        ResizeHelper.install(st, scene, 820, 420, chrome::isMaximized);
        c.init(st, stream, tls, localDir);
        st.show();
    }

    @FXML
    private void initialize() {
        Rectangle clip = new Rectangle();
        clip.setArcWidth(32);
        clip.setArcHeight(32);
        clip.widthProperty().bind(viewCard.widthProperty());
        clip.heightProperty().bind(viewCard.heightProperty());
        viewCard.setClip(clip);

        webView.setContextMenuEnabled(false);
        webView.setPageFill(Color.TRANSPARENT);
        webView.getEngine().setJavaScriptEnabled(false);   // 內容來自網路，一律當純文字顯示
    }

    private void init(Stage stage, TcpStream stream, TlsResult tls, int localDir) {
        this.stage = stage;
        this.stream = stream;
        this.tls = tls;
        this.tlsUsable = tls != null && tls.usable();
        this.localDir = localDir;
        this.firstTime = stream.chunks.isEmpty() ? 0 : stream.chunks.get(0).timeMillis;

        String client = stream.clientIp + ":" + stream.clientPort;
        String server = stream.serverIp + ":" + stream.serverPort;
        boolean known = localDir >= 0;
        String local = localDir == 1 ? server : client;
        String remote = localDir == 1 ? client : server;
        titleLabel.setText("追蹤 TCP 串流  ·  " + (known ? local + " ⇄ " + remote : client + " ⇄ " + server));
        endpointLabel.setText(known ? "本機 " + local + "   ⇄   遠端 " + remote
                                    : "客戶端 " + client + "   ⇄   伺服器 " + server);
        legendSend.setText(known ? "■ ↑ 發送（本機 → 遠端）" : "■ 客戶端 → 伺服器");
        legendRecv.setText(known ? "■ ↓ 接收（遠端 → 本機）" : "■ 伺服器 → 客戶端");

        sourceBox.getItems().add("原始資料");
        if (tlsUsable) sourceBox.getItems().add("TLS 解密後");
        sourceBox.getSelectionModel().select(tlsUsable ? 1 : 0);
        formatBox.getItems().addAll("ASCII", "UTF-8", "Hex 傾印");
        formatBox.getSelectionModel().select(0);
        dirBox.getItems().addAll("雙向對話", known ? "只看 發送" : "只看 客戶端 → 伺服器",
                known ? "只看 接收" : "只看 伺服器 → 客戶端");
        dirBox.getSelectionModel().select(0);

        sourceBox.valueProperty().addListener((o, a, b) -> render());
        formatBox.valueProperty().addListener((o, a, b) -> render());
        dirBox.valueProperty().addListener((o, a, b) -> render());
        showHeader.selectedProperty().addListener((o, a, b) -> render());

        long sent = stream.bytes[sendDir()], recv = stream.bytes[1 - sendDir()];
        statsLabel.setText("封包 " + stream.packetCount + " 個　·　" + (known ? "發送 " : "客戶端→伺服器 ") + sent
                + " 位元組　·　" + (known ? "接收 " : "伺服器→客戶端 ") + recv
                + " 位元組　·　重傳 " + stream.retransmissions + " 個");
        tlsLabel.setText(tls == null ? "TLS：尚未匯入金鑰" : "TLS：" + tls.summary());
        render();
    }

    // ------------------------------------------------------------------ direction helpers

    /** 「發送」對應的資料流方向。 */
    private int sendDir() { return localDir >= 0 ? localDir : 0; }

    private boolean isSend(int dir) { return dir == sendDir(); }

    private String tagText(int dir) {
        if (localDir >= 0) return isSend(dir) ? "↑ 發送" : "↓ 接收";
        return dir == 0 ? "客戶端 → 伺服器" : "伺服器 → 客戶端";
    }

    private String endpoints(int dir) {
        String c = stream.clientIp + ":" + stream.clientPort;
        String s = stream.serverIp + ":" + stream.serverPort;
        return dir == 0 ? c + " → " + s : s + " → " + c;
    }

    // ------------------------------------------------------------------ pieces

    private boolean showDecrypted() {
        return tlsUsable && sourceBox.getSelectionModel().getSelectedIndex() == 1;
    }

    private List<Piece> pieces() {
        int sel = dirBox.getSelectionModel().getSelectedIndex();      // 0 雙向, 1 只看發送, 2 只看接收
        List<Piece> out = new ArrayList<>();
        if (showDecrypted()) {
            for (TlsRecord t : tls.records) {
                if (t.contentType != 0x17 || !t.decrypted || t.plaintext == null || t.plaintext.length == 0) continue;
                if (sel == 1 && !isSend(t.dir) || sel == 2 && isSend(t.dir)) continue;
                TcpStream.Chunk c = stream.chunkAt(t.dir, t.offset);
                out.add(new Piece(t.dir, t.plaintext, 0, c == null ? -1 : c.pktNo, t.offset,
                        c == null ? 0 : c.timeMillis, true));
            }
            out.sort(Comparator.comparingLong(Piece::pktNo).thenComparingInt(Piece::offset));
        } else {
            for (TcpStream.Chunk c : stream.chunks) {
                if (sel == 1 && !isSend(c.dir) || sel == 2 && isSend(c.dir)) continue;
                if (c.gapBefore > 0) out.add(new Piece(c.dir, null, c.gapBefore, c.pktNo, c.offset, c.timeMillis, false));
                out.add(new Piece(c.dir, c.data, 0, c.pktNo, c.offset, c.timeMillis, false));
            }
        }
        return out;
    }

    // ------------------------------------------------------------------ rendering

    private String timeText(long millis) {
        if (millis <= 0) return "-";
        return TIME_FMT.format(Instant.ofEpochMilli(millis))
                + String.format("（+%.3f 秒）", Math.max(0, millis - firstTime) / 1000.0);
    }

    private void render() {
        int fmt = formatBox.getSelectionModel().getSelectedIndex();     // 0 ASCII, 1 UTF-8, 2 Hex
        boolean header = showHeader.isSelected();
        StringBuilder html = new StringBuilder(HexHtml.pageStart());
        StringBuilder plain = new StringBuilder();
        int[] hexBase = new int[2];
        long shown = 0;
        boolean truncated = false;

        for (Piece p : pieces()) {
            if (p.data() == null) {
                String msg = "… 缺少 " + p.gap() + " 位元組（封包遺失或未擷取到）…";
                html.append(HexHtml.note(msg));
                plain.append(msg).append('\n');
                continue;
            }
            if (shown >= MAX_VIEW_BYTES) { truncated = true; break; }
            shown += p.data().length;

            String body;                     // 放進 <pre> 的文字，Hex 模式則直接是欄位 HTML
            String bodyPlain;
            if (fmt == 2) {
                body = HexHtml.hexBlock(p.data(), hexBase[p.dir()]);
                bodyPlain = hexDumpPlain(p.data(), hexBase[p.dir()]);
            } else {
                String text = asText(p.data(), fmt == 1);
                body = text.isEmpty() ? "" : "<pre>" + HexHtml.escape(text) + "</pre>";
                bodyPlain = text;
            }
            hexBase[p.dir()] += p.data().length;
            if (body.isEmpty()) continue;

            html.append("<div class=\"p ").append(isSend(p.dir()) ? "c" : "s").append("\">");
            if (header) {
                String len = p.data().length + " 位元組" + (p.decrypted() ? "（TLS 解密）" : "");
                String pkt = p.pktNo() >= 0 ? "封包 #" + p.pktNo() : "封包 -";
                html.append("<div class=\"hd\"><span class=\"tag\">").append(HexHtml.escape(tagText(p.dir()))).append("</span>")
                        .append("<span class=\"t\">").append(pkt).append("</span>")
                        .append("<span class=\"t\">").append(HexHtml.escape(timeText(p.timeMillis()))).append("</span>")
                        .append("<span class=\"ep\">").append(HexHtml.escape(endpoints(p.dir()))).append("</span>")
                        .append("<span class=\"len\">").append(HexHtml.escape(len)).append("</span></div>");
                plain.append("[").append(tagText(p.dir())).append("] ").append(pkt).append("  ")
                        .append(timeText(p.timeMillis())).append("  ").append(endpoints(p.dir()))
                        .append("  ").append(len).append('\n');
            }
            html.append(body).append("</div>");
            plain.append(bodyPlain);
            if (!bodyPlain.endsWith("\n")) plain.append('\n');
            if (header) plain.append('\n');
        }
        if (truncated) {
            String msg = "（資料過長，只顯示前 " + MAX_VIEW_BYTES + " 位元組；完整資料請用「另存新檔」）";
            html.append(HexHtml.note(msg));
            plain.append(msg).append('\n');
        }
        if (plain.length() == 0) {
            html.append(HexHtml.note(showDecrypted() ? "（沒有解密後的應用程式資料）" : "（這條連線沒有傳輸任何資料）"));
        }
        html.append(HexHtml.PAGE_END);
        plainText = plain.toString();
        webView.getEngine().loadContent(html.toString());
    }

    /** 純文字版 Hex 傾印 (給「複製全部文字」用)。 */
    private static String hexDumpPlain(byte[] d, int base) {
        StringBuilder sb = new StringBuilder(d.length * 4);
        for (int i = 0; i < d.length; i += 16) {
            sb.append(String.format("%08X  ", base + i));
            for (int j = 0; j < 16; j++) {
                if (j == 8) sb.append(' ');
                sb.append(i + j < d.length ? String.format("%02X ", d[i + j] & 0xFF) : "   ");
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

    /** 轉成可讀文字：保留換行與 Tab，其他控制字元以 . 取代。 */
    private static String asText(byte[] d, boolean utf8) {
        String s = new String(d, utf8 ? StandardCharsets.UTF_8 : StandardCharsets.ISO_8859_1);
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '\n' || ch == '\t') sb.append(ch);
            else if (ch == '\r') continue;
            else if (ch < 32 || ch == 0x7F || ch == '\uFFFD' || (!utf8 && ch > 126)) sb.append('.');
            else sb.append(ch);
        }
        return sb.toString();
    }

    /** 目前畫面上顯示的所有資料 (依方向與資料來源篩選後)。 */
    private byte[] visibleBytes() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (Piece p : pieces()) {
            if (p.data() != null) bos.write(p.data(), 0, p.data().length);
        }
        return bos.toByteArray();
    }

    // ------------------------------------------------------------------ actions

    private static void copy(String s) {
        ClipboardContent cc = new ClipboardContent();
        cc.putString(s);
        Clipboard.getSystemClipboard().setContent(cc);
    }

    @FXML
    private void onCopyAll() { copy(plainText); }

    @FXML
    private void onCopyHex() { copy(HexHtml.hexOnly(visibleBytes())); }

    @FXML
    private void onCopyText() {
        StringBuilder sb = new StringBuilder();
        for (Piece p : pieces()) {
            if (p.data() == null) continue;
            String t = asText(p.data(), formatBox.getSelectionModel().getSelectedIndex() == 1);
            sb.append(t);
            if (!t.endsWith("\n")) sb.append('\n');
        }
        copy(sb.toString());
    }

    @FXML
    private void onSave() {
        FileChooser fc = new FileChooser();
        fc.setTitle("另存串流資料");
        fc.setInitialFileName("tcp-stream.bin");
        File f = fc.showSaveDialog(stage);
        if (f == null) return;
        try {
            Files.write(f.toPath(), visibleBytes());
        } catch (IOException e) {
            statsLabel.setText("儲存失敗：" + e.getMessage());
        }
    }
}
