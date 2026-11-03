package com.sniffer;

import com.sniffer.stream.TcpStream;
import com.sniffer.tls.TlsRecord;
import com.sniffer.tls.TlsResult;
import com.sniffer.ui.ResizeHelper;
import com.sniffer.ui.WindowChrome;
import com.sniffer.util.HexUtil;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 「追蹤 TCP 串流」視窗：依封包順序顯示客戶端 / 伺服器雙方的連續資料，
 * 客戶端與伺服器以不同顏色區分，文字可直接反白複製。
 * 有匯入 SSL 金鑰且能解密時，可切換成解密後的內容。
 */
public final class FollowStreamController {

    private static final int MAX_VIEW_BYTES = 1_000_000;
    private static final String HTML_HEAD = "<html><head><meta charset=\"utf-8\"><style>"
            + "html,body{margin:0;padding:0;background:transparent;color:#e8eef7;"
            + "font:12px 'Cascadia Mono',Consolas,monospace;}"
            + "pre{margin:0 0 2px 0;padding:6px 12px;white-space:pre-wrap;word-wrap:break-word;"
            + "border-left:3px solid;font:inherit;}"
            + ".c{background:rgba(248,113,113,0.14);border-color:#f87171;color:#fecaca;}"
            + ".s{background:rgba(96,165,250,0.14);border-color:#60a5fa;color:#bfdbfe;}"
            + ".g{padding:4px 12px;color:#fbbf24;font-style:italic;}"
            + "::selection{background:#f59e0b;color:#111827;}"
            + "</style></head><body>";

    /** 顯示用的一段資料。data 為 null 代表「缺口」提示。 */
    private record Piece(int dir, byte[] data, long gap, long pktNo, int offset) {}

    @FXML private BorderPane root;
    @FXML private HBox dragArea;
    @FXML private Button minBtn, maxBtn, closeBtn;
    @FXML private Label titleLabel, endpointLabel, statsLabel, tlsLabel;
    @FXML private ComboBox<String> sourceBox, formatBox, dirBox;
    @FXML private StackPane viewCard;
    @FXML private WebView webView;

    private TcpStream stream;
    private TlsResult tls;
    private Stage stage;
    private boolean tlsUsable;
    private String plainText = "";

    /** 開啟追蹤視窗。tls 為 null 表示尚未匯入金鑰。 */
    public static void open(String css, TcpStream stream, TlsResult tls) throws IOException {
        FXMLLoader loader = new FXMLLoader(FollowStreamController.class.getResource("/fxml/FollowStream.fxml"));
        Parent root = loader.load();
        FollowStreamController c = loader.getController();

        Stage st = new Stage(StageStyle.TRANSPARENT);
        Scene scene = new Scene(root, 980, 680);
        scene.setFill(Color.TRANSPARENT);
        scene.getStylesheets().add(css);
        st.setScene(scene);
        st.setMinWidth(720);
        st.setMinHeight(420);
        st.setTitle("追蹤 TCP 串流");

        WindowChrome chrome = WindowChrome.install(st, c.root, c.dragArea, c.minBtn, c.maxBtn, c.closeBtn);
        ResizeHelper.install(st, scene, 720, 420, chrome::isMaximized);
        c.init(st, stream, tls);
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

    private void init(Stage stage, TcpStream stream, TlsResult tls) {
        this.stage = stage;
        this.stream = stream;
        this.tls = tls;
        this.tlsUsable = tls != null && tls.usable();

        String client = stream.clientIp + ":" + stream.clientPort;
        String server = stream.serverIp + ":" + stream.serverPort;
        titleLabel.setText("追蹤 TCP 串流  ·  " + client + " ⇄ " + server);
        endpointLabel.setText("客戶端 " + client + "   ⇄   伺服器 " + server);

        sourceBox.getItems().add("原始資料");
        if (tlsUsable) sourceBox.getItems().add("TLS 解密後");
        sourceBox.getSelectionModel().select(tlsUsable ? 1 : 0);
        formatBox.getItems().addAll("ASCII", "UTF-8", "Hex 傾印");
        formatBox.getSelectionModel().select(0);
        dirBox.getItems().addAll("雙向對話", "客戶端 → 伺服器", "伺服器 → 客戶端");
        dirBox.getSelectionModel().select(0);

        sourceBox.valueProperty().addListener((o, a, b) -> render());
        formatBox.valueProperty().addListener((o, a, b) -> render());
        dirBox.valueProperty().addListener((o, a, b) -> render());

        statsLabel.setText("封包 " + stream.packetCount + " 個　·　客戶端→伺服器 " + stream.bytes[0]
                + " 位元組　·　伺服器→客戶端 " + stream.bytes[1] + " 位元組　·　重傳 " + stream.retransmissions + " 個");
        tlsLabel.setText(tls == null ? "TLS：尚未匯入金鑰" : "TLS：" + tls.summary());
        render();
    }

    // ------------------------------------------------------------------ rendering

    private boolean showDecrypted() {
        return tlsUsable && sourceBox.getSelectionModel().getSelectedIndex() == 1;
    }

    private List<Piece> pieces() {
        int sel = dirBox.getSelectionModel().getSelectedIndex();      // 0 雙向, 1 僅客戶端, 2 僅伺服器
        List<Piece> out = new ArrayList<>();
        if (showDecrypted()) {
            for (TlsRecord t : tls.records) {
                if (t.contentType != 0x17 || !t.decrypted || t.plaintext == null || t.plaintext.length == 0) continue;
                if (sel != 0 && t.dir != sel - 1) continue;
                out.add(new Piece(t.dir, t.plaintext, 0, stream.packetAt(t.dir, t.offset), t.offset));
            }
            out.sort(Comparator.comparingLong(Piece::pktNo).thenComparingInt(Piece::offset));
        } else {
            for (TcpStream.Chunk c : stream.chunks) {
                if (sel != 0 && c.dir != sel - 1) continue;
                if (c.gapBefore > 0) out.add(new Piece(c.dir, null, c.gapBefore, c.pktNo, c.offset));
                out.add(new Piece(c.dir, c.data, 0, c.pktNo, c.offset));
            }
        }
        return out;
    }

    private void render() {
        int fmt = formatBox.getSelectionModel().getSelectedIndex();     // 0 ASCII, 1 UTF-8, 2 Hex
        StringBuilder html = new StringBuilder(HTML_HEAD);
        StringBuilder plain = new StringBuilder();
        int[] hexBase = new int[2];
        long shown = 0;
        boolean truncated = false;

        for (Piece p : pieces()) {
            if (p.data() == null) {
                String msg = "… 缺少 " + p.gap() + " 位元組（封包遺失或未擷取到）…";
                html.append("<div class=\"g\">").append(escape(msg)).append("</div>");
                plain.append(msg).append('\n');
                continue;
            }
            if (shown >= MAX_VIEW_BYTES) { truncated = true; break; }
            String text = switch (fmt) {
                case 1 -> asText(p.data(), true);
                case 2 -> HexUtil.dump(p.data(), hexBase[p.dir()]);
                default -> asText(p.data(), false);
            };
            hexBase[p.dir()] += p.data().length;
            shown += p.data().length;
            if (text.isEmpty()) continue;
            html.append("<pre class=\"").append(p.dir() == 0 ? "c" : "s").append("\">")
                    .append(escape(text)).append("</pre>");
            plain.append(text);
            if (!text.endsWith("\n")) plain.append('\n');
        }
        if (truncated) {
            String msg = "（資料過長，只顯示前 " + MAX_VIEW_BYTES + " 位元組；完整資料請用「另存新檔」）";
            html.append("<div class=\"g\">").append(escape(msg)).append("</div>");
            plain.append(msg).append('\n');
        }
        if (plain.length() == 0) {
            String msg = showDecrypted() ? "（沒有解密後的應用程式資料）" : "（這條連線沒有傳輸任何資料）";
            html.append("<div class=\"g\">").append(escape(msg)).append("</div>");
        }
        html.append("</body></html>");
        plainText = plain.toString();
        webView.getEngine().loadContent(html.toString(), "text/html");
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

    private static String escape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    // ------------------------------------------------------------------ actions

    @FXML
    private void onCopyAll() {
        ClipboardContent cc = new ClipboardContent();
        cc.putString(plainText);
        Clipboard.getSystemClipboard().setContent(cc);
    }

    @FXML
    private void onSave() {
        FileChooser fc = new FileChooser();
        fc.setTitle("另存串流資料");
        fc.setInitialFileName("tcp-stream.bin");
        File f = fc.showSaveDialog(stage);
        if (f == null) return;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (Piece p : pieces()) {
            if (p.data() != null) bos.write(p.data(), 0, p.data().length);
        }
        try {
            Files.write(f.toPath(), bos.toByteArray());
        } catch (IOException e) {
            statsLabel.setText("儲存失敗：" + e.getMessage());
        }
    }
}
