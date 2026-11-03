package com.sniffer;

import com.sniffer.capture.CaptureService;
import com.sniffer.capture.PacketParser;
import com.sniffer.model.Direction;
import com.sniffer.model.PacketRecord;
import com.sniffer.stream.Segments;
import com.sniffer.stream.StreamKey;
import com.sniffer.stream.TcpSegment;
import com.sniffer.stream.TcpStream;
import com.sniffer.tls.KeyLog;
import com.sniffer.tls.TlsDecryptor;
import com.sniffer.tls.TlsRecord;
import com.sniffer.tls.TlsResult;
import com.sniffer.ui.ResizeHelper;
import com.sniffer.ui.WindowChrome;
import com.sniffer.util.HexUtil;
import com.sniffer.util.PacketFilter;
import javafx.animation.Animation;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.css.PseudoClass;
import javafx.fxml.FXML;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.shape.Rectangle;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.Duration;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** 主視窗控制器。版面定義在 fxml/MainView.fxml，樣式在 style.css。 */
public class MainController {

    static final double MIN_WIDTH = 1040;
    static final double MIN_HEIGHT = 560;

    private static final int MAX_PACKETS = 200_000;
    private static final int MAX_DECRYPT_VIEW = 64 * 1024;
    private static final PseudoClass INVALID = PseudoClass.getPseudoClass("invalid");
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    /** 下拉選單的網卡項目。 */
    private record NicItem(PcapNetworkInterface nif) {
        String ipv4() {
            return nif.getAddresses().stream()
                    .filter(a -> a.getAddress() instanceof Inet4Address)
                    .map(a -> a.getAddress().getHostAddress())
                    .findFirst().orElse("");
        }

        @Override public String toString() {
            String name = nif.getDescription() != null ? nif.getDescription() : nif.getName();
            String ip = ipv4();
            return ip.isEmpty() ? name : name + "  (" + ip + ")";
        }
    }

    /** 某條 TCP 連線重組 / 解密後的快取。 */
    private static final class StreamData {
        final int packetCount;
        final long keyVersion;
        final TcpStream stream;
        final TlsResult tls;     // 未匯入金鑰時為 null

        StreamData(int packetCount, long keyVersion, TcpStream stream, TlsResult tls) {
            this.packetCount = packetCount; this.keyVersion = keyVersion; this.stream = stream; this.tls = tls;
        }
    }

    // ---- FXML 注入 ----
    @FXML private BorderPane root;
    @FXML private HBox dragArea;
    @FXML private Button minBtn, maxBtn, closeBtn;

    @FXML private ComboBox<NicItem> nicBox;
    @FXML private Button startBtn;
    @FXML private Button followBtn;
    @FXML private CheckBox autoScroll;
    @FXML private ComboBox<String> protoBox;
    @FXML private ComboBox<String> dirBox;
    @FXML private ComboBox<PacketFilter.Mode> modeBox;
    @FXML private TextField searchField;

    @FXML private StackPane tableCard;
    @FXML private VBox treeCard, hexCard;
    @FXML private TableView<PacketRecord> table;
    @FXML private TableColumn<PacketRecord, Long> cNo, cTime, cSeq, cAck;
    @FXML private TableColumn<PacketRecord, Direction> cDir;
    @FXML private TableColumn<PacketRecord, String> cSrc, cDst, cProto, cInfo;
    @FXML private TableColumn<PacketRecord, Integer> cSp, cDp, cLen;

    @FXML private TreeView<String> detailTree;
    @FXML private TextArea hexArea, decArea;
    @FXML private ToggleGroup langGroup, viewGroup;
    @FXML private RadioButton rbZh, rbEn, rbRaw, rbDec;

    @FXML private Label statusDot, statusText, keyLabel, countLabel, bytesLabel;

    // ---- 狀態 ----
    private final CaptureService capture = new CaptureService();
    private final ObservableList<PacketRecord> master = FXCollections.observableArrayList();
    private FilteredList<PacketRecord> filtered;
    private SortedList<PacketRecord> sorted;
    private final Tooltip searchTip = new Tooltip();

    private final KeyLog keyLog = new KeyLog();
    private long keyVersion;
    private final Map<StreamKey, List<PacketRecord>> streamIndex = new HashMap<>();
    private final Map<StreamKey, StreamData> streamCache = new HashMap<>();

    private Stage stage;
    private String css;
    private boolean running;
    private long capturedBytes;
    private Timeline timeline;

    // ------------------------------------------------------------------ init

    /** FXML 載入完成後由 FXMLLoader 呼叫：設定表格、下拉選單與各種監聽。 */
    @FXML
    private void initialize() {
        roundClip(tableCard, 16);
        roundClip(treeCard, 16);
        roundClip(hexCard, 16);

        // 篩選列
        protoBox.getItems().setAll(PacketFilter.PROTOCOLS);
        protoBox.setValue(PacketFilter.ALL);
        dirBox.getItems().setAll(PacketFilter.ALL, Direction.IN.label, Direction.OUT.label);
        dirBox.setValue(PacketFilter.ALL);
        modeBox.getItems().setAll(PacketFilter.Mode.values());
        modeBox.setValue(PacketFilter.Mode.FIELD);
        searchField.setPromptText(PacketFilter.Mode.FIELD.prompt);
        searchTip.setText(PacketFilter.Mode.FIELD.tip);
        searchField.setTooltip(searchTip);

        protoBox.valueProperty().addListener((o, a, b) -> applyFilter());
        dirBox.valueProperty().addListener((o, a, b) -> applyFilter());
        modeBox.valueProperty().addListener((o, a, b) -> {
            searchField.setPromptText(b.prompt);
            searchTip.setText(b.tip);
            applyFilter();
        });
        searchField.textProperty().addListener((o, a, b) -> applyFilter());

        // 狀態列
        statusDot.getStyleClass().add("dot-idle");
        updateKeyLabel();

        // 詳細資料
        MenuItem copyLine = new MenuItem("複製此行");
        copyLine.setOnAction(e -> {
            TreeItem<String> it = detailTree.getSelectionModel().getSelectedItem();
            if (it != null) copyText(it.getValue());
        });
        detailTree.setContextMenu(new ContextMenu(copyLine));

        langGroup.selectedToggleProperty().addListener((o, a, b) -> {
            if (b == null) a.setSelected(true);            // 至少要選一個
            else showDetails(table.getSelectionModel().getSelectedItem());
        });
        viewGroup.selectedToggleProperty().addListener((o, a, b) -> {
            if (b == null) { a.setSelected(true); return; }
            boolean dec = b == rbDec;
            hexArea.setVisible(!dec);
            hexArea.setManaged(!dec);
            decArea.setVisible(dec);
            decArea.setManaged(dec);
            if (dec) decArea.setText(decryptedText(table.getSelectionModel().getSelectedItem()));
        });

        buildTable();
    }

    /** 視窗建立後由 MainApp 呼叫。 */
    void attach(Stage stage, Scene scene, String css) {
        this.stage = stage;
        this.css = css;

        WindowChrome chrome = WindowChrome.install(stage, root, dragArea, minBtn, maxBtn, closeBtn);
        ResizeHelper.install(stage, scene, MIN_WIDTH, MIN_HEIGHT, chrome::isMaximized);
        scene.getAccelerators().put(
                new KeyCodeCombination(KeyCode.T, KeyCombination.CONTROL_DOWN, KeyCombination.ALT_DOWN,
                        KeyCombination.SHIFT_DOWN),
                this::onFollowStream);

        applyFilter();
        updateButtons();
        loadInterfaces();

        timeline = new Timeline(new KeyFrame(Duration.millis(100), e -> drain()));
        timeline.setCycleCount(Animation.INDEFINITE);
        timeline.play();
    }

    void shutdown() {
        if (timeline != null) timeline.stop();
        capture.shutdown();
    }

    // ------------------------------------------------------------------ table

    private void buildTable() {
        setValue(cNo, r -> r.no);
        fmt(cNo, Object::toString, "num");
        setValue(cTime, r -> r.timeMillis);
        fmt(cTime, v -> TIME_FMT.format(Instant.ofEpochMilli(v)), null);

        setValue(cDir, r -> r.direction);
        cDir.setCellFactory(c -> new TableCell<>() {
            @Override protected void updateItem(Direction d, boolean empty) {
                super.updateItem(d, empty);
                getStyleClass().removeAll("dir-in", "dir-out");
                if (empty || d == null) { setText(null); return; }
                switch (d) {
                    case IN -> { setText("↓ " + d.label); getStyleClass().add("dir-in"); }
                    case OUT -> { setText("↑ " + d.label); getStyleClass().add("dir-out"); }
                    default -> setText("· " + d.label);
                }
            }
        });

        setValue(cSrc, r -> r.src);
        fmt(cSrc, s -> s, null);
        cSrc.setComparator(MainController::compareIp);
        setValue(cDst, r -> r.dst);
        fmt(cDst, s -> s, null);
        cDst.setComparator(MainController::compareIp);
        setValue(cProto, r -> r.protocol);
        fmt(cProto, s -> s, null);

        setValue(cSp, r -> r.srcPort);
        fmt(cSp, Object::toString, "num");
        setValue(cDp, r -> r.dstPort);
        fmt(cDp, Object::toString, "num");
        setValue(cSeq, r -> r.seq);
        fmt(cSeq, Object::toString, "num");
        setValue(cAck, r -> r.ack);
        fmt(cAck, Object::toString, "num");
        setValue(cLen, r -> r.raw.length);
        fmt(cLen, Object::toString, "num");
        setValue(cInfo, r -> r.info);
        fmt(cInfo, s -> s, null);

        filtered = new FilteredList<>(master, r -> true);
        sorted = new SortedList<>(filtered);
        sorted.comparatorProperty().bind(table.comparatorProperty());   // 點欄位標題即可排序
        table.setItems(sorted);

        table.setRowFactory(tv -> new TableRow<>() {
            @Override protected void updateItem(PacketRecord r, boolean empty) {
                super.updateItem(r, empty);
                getStyleClass().removeAll("r-tcp", "r-udp", "r-http", "r-tls", "r-dns", "r-icmp", "r-arp", "r-other");
                if (!empty && r != null) getStyleClass().add(rowClass(r));
            }
        });

        // 表格本身的右鍵選單 (在方向欄或空白處點右鍵時使用)
        MenuItem follow = new MenuItem("追蹤 TCP 串流");
        follow.setOnAction(e -> onFollowStream());
        follow.disableProperty().bind(followBtn.disableProperty());
        table.setContextMenu(new ContextMenu(follow));

        table.getSelectionModel().selectedItemProperty().addListener((o, a, r) -> {
            followBtn.setDisable(!isTcp(r));
            showDetails(r);
        });
    }

    private static boolean isTcp(PacketRecord r) {
        return r != null && "TCP".equals(r.transport);
    }

    private static String rowClass(PacketRecord r) {
        return switch (r.protocol) {
            case "TCP" -> "r-tcp";
            case "UDP", "QUIC", "DHCP", "NTP", "SSDP" -> "r-udp";
            case "HTTP" -> "r-http";
            case "HTTPS" -> "r-tls";
            case "DNS" -> "r-dns";
            case "ARP" -> "r-arp";
            default -> r.protocol.startsWith("ICMP") ? "r-icmp" : "r-other";
        };
    }

    private <T> void setValue(TableColumn<PacketRecord, T> c, Function<PacketRecord, T> getter) {
        c.setCellValueFactory(cd -> new ReadOnlyObjectWrapper<>(getter.apply(cd.getValue())));
    }

    private <T> void fmt(TableColumn<PacketRecord, T> c, Function<T, String> f, String styleClass) {
        c.setCellFactory(col -> new SelectableCell<>(f, styleClass));
    }

    /**
     * 可反白複製的儲存格：內部放一個唯讀、透明的 TextField。
     * 滑鼠拖曳可反白，雙擊選一個詞，連點三下選整格，Ctrl+C 或右鍵複製；
     * 點擊時仍會同時選取該列。右鍵選單另有「追蹤 TCP 串流」。
     */
    private final class SelectableCell<T> extends TableCell<PacketRecord, T> {
        private final TextField tf = new TextField();
        private final Function<T, String> formatter;

        SelectableCell(Function<T, String> formatter, String styleClass) {
            this.formatter = formatter;
            tf.setEditable(false);
            tf.getStyleClass().add("cell-text");
            if (styleClass != null) tf.getStyleClass().add(styleClass);
            tf.prefWidthProperty().bind(widthProperty().subtract(10));
            tf.addEventFilter(MouseEvent.MOUSE_PRESSED, e -> {
                int i = getIndex();
                if (i >= 0 && i < table.getItems().size()) table.getSelectionModel().select(i);
            });

            MenuItem copy = new MenuItem("複製");
            copy.setOnAction(e -> {
                String t = tf.getSelectedText();
                copyText(t == null || t.isEmpty() ? tf.getText() : t);
            });
            MenuItem follow = new MenuItem("追蹤 TCP 串流");
            follow.setOnAction(e -> {
                PacketRecord r = getTableRow() == null ? null : getTableRow().getItem();
                if (isTcp(r)) followStream(r);
            });
            ContextMenu cm = new ContextMenu(copy, follow);
            cm.setOnShowing(e -> follow.setDisable(!isTcp(getTableRow() == null ? null : getTableRow().getItem())));
            tf.setContextMenu(cm);

            setContentDisplay(ContentDisplay.GRAPHIC_ONLY);
        }

        @Override protected void updateItem(T item, boolean empty) {
            super.updateItem(item, empty);
            if (empty || item == null) {
                setGraphic(null);
            } else {
                tf.setText(formatter.apply(item));
                setGraphic(tf);
            }
        }
    }

    private static int compareIp(String a, String b) {
        long x = ipv4(a), y = ipv4(b);
        if (x >= 0 && y >= 0) return Long.compare(x, y);
        if (x >= 0) return -1;
        if (y >= 0) return 1;
        return a.compareToIgnoreCase(b);
    }

    private static long ipv4(String s) {
        String[] p = s.split("\\.");
        if (p.length != 4) return -1;
        long v = 0;
        try {
            for (String q : p) {
                int n = Integer.parseInt(q);
                if (n < 0 || n > 255) return -1;
                v = v * 256 + n;
            }
        } catch (NumberFormatException e) {
            return -1;
        }
        return v;
    }

    private static void roundClip(Region r, double radius) {
        Rectangle c = new Rectangle();
        c.setArcWidth(radius * 2);
        c.setArcHeight(radius * 2);
        c.widthProperty().bind(r.widthProperty());
        c.heightProperty().bind(r.heightProperty());
        r.setClip(c);
    }

    private static void copyText(String s) {
        ClipboardContent cc = new ClipboardContent();
        cc.putString(s == null ? "" : s);
        Clipboard.getSystemClipboard().setContent(cc);
    }

    // ------------------------------------------------------------------ capture

    private void loadInterfaces() {
        try {
            List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
            if (devs == null || devs.isEmpty()) {
                showAlert(Alert.AlertType.ERROR, "找不到任何網路卡。請確認 Npcap 已安裝，並以系統管理員身分執行。");
                return;
            }
            List<NicItem> items = devs.stream().map(NicItem::new).toList();
            nicBox.getItems().setAll(items);
            NicItem pick = items.stream()
                    .filter(i -> !i.ipv4().isEmpty() && !i.ipv4().startsWith("169.254") && !i.ipv4().startsWith("127."))
                    .findFirst().orElse(items.get(0));
            nicBox.setValue(pick);
        } catch (Throwable t) {
            showAlert(Alert.AlertType.ERROR, "無法載入 Npcap。請確認：\n"
                    + "1. 已安裝 Npcap (https://npcap.com)，安裝時勾選「Install Npcap in WinPcap API-compatible Mode」\n"
                    + "2. 以系統管理員身分執行（或安裝 Npcap 時允許非管理員使用）\n"
                    + "3. 使用 64 位元 JDK\n\n詳細訊息：" + t);
        }
    }

    @FXML
    private void onToggleCapture() {
        if (!running) {
            NicItem nic = nicBox.getValue();
            if (nic == null) {
                showAlert(Alert.AlertType.ERROR, "請先選擇網卡。");
                return;
            }
            try {
                capture.start(nic.nif(), msg -> Platform.runLater(() -> {
                    running = false;
                    updateButtons();
                    showAlert(Alert.AlertType.ERROR, "擷取發生錯誤：" + msg);
                }));
                running = true;
            } catch (Throwable t) {
                showAlert(Alert.AlertType.ERROR, "無法開始擷取：" + t.getMessage()
                        + "\n\n請嘗試以系統管理員身分執行，或確認 Npcap 安裝正常。");
                return;
            }
        } else {
            capture.pause();
            running = false;
        }
        updateButtons();
    }

    private void updateButtons() {
        startBtn.setText(running ? "⏸  暫停" : "▶  開始");
        startBtn.getStyleClass().remove("running");
        if (running) startBtn.getStyleClass().add("running");
        nicBox.setDisable(running);

        statusText.setText(running ? "擷取中" : (capture.isOpen() ? "已暫停" : "就緒"));
        statusDot.getStyleClass().removeAll("dot-idle", "dot-run", "dot-pause");
        statusDot.getStyleClass().add(running ? "dot-run" : (capture.isOpen() ? "dot-pause" : "dot-idle"));
    }

    private void drain() {
        List<PacketRecord> batch = capture.drain(20_000);
        if (!batch.isEmpty()) {
            master.addAll(batch);
            for (PacketRecord r : batch) {
                capturedBytes += r.raw.length;
                indexPacket(r);
            }
            if (master.size() > MAX_PACKETS) {                       // 超過上限就丟掉最舊的 10%
                master.remove(0, master.size() - (MAX_PACKETS - MAX_PACKETS / 10));
                rebuildIndex();
            }
            if (autoScroll.isSelected() && table.getSortOrder().isEmpty() && !sorted.isEmpty()) {
                table.scrollTo(sorted.size() - 1);
            }
        }
        countLabel.setText("顯示 " + filtered.size() + " 筆 / 共 " + master.size() + " 筆");
        bytesLabel.setText("累計 " + formatBytes(capturedBytes));
    }

    @FXML
    private void onClear() {
        capture.reset();
        master.clear();
        streamIndex.clear();
        streamCache.clear();
        capturedBytes = 0;
        table.getSelectionModel().clearSelection();
        showDetails(null);
        drain();
    }

    @FXML
    private void onReset() {
        protoBox.setValue(PacketFilter.ALL);
        dirBox.setValue(PacketFilter.ALL);
        modeBox.setValue(PacketFilter.Mode.FIELD);
        searchField.clear();
        applyFilter();
    }

    private void applyFilter() {
        PacketFilter.Mode mode = modeBox.getValue();
        String q = searchField.getText();
        searchField.pseudoClassStateChanged(INVALID, !PacketFilter.isValid(mode, q));
        filtered.setPredicate(PacketFilter.build(protoBox.getValue(), selectedDirection(), mode, q));
    }

    private Direction selectedDirection() {
        String v = dirBox.getValue();
        if (Direction.IN.label.equals(v)) return Direction.IN;
        if (Direction.OUT.label.equals(v)) return Direction.OUT;
        return null;
    }

    // ------------------------------------------------------------------ details

    private void showDetails(PacketRecord r) {
        if (r == null) {
            detailTree.setRoot(null);
            hexArea.clear();
            decArea.clear();
            return;
        }
        detailTree.setRoot(PacketParser.buildDetails(r, rbZh.isSelected()));
        hexArea.setText(HexUtil.dump(r.raw));
        if (rbDec.isSelected()) decArea.setText(decryptedText(r));
    }

    // ------------------------------------------------------------------ streams / TLS

    private void indexPacket(PacketRecord r) {
        if (isTcp(r) && r.srcPort != null && r.dstPort != null) {
            streamIndex.computeIfAbsent(Segments.keyOf(r), k -> new ArrayList<>()).add(r);
        }
    }

    private void rebuildIndex() {
        streamIndex.clear();
        streamCache.clear();
        for (PacketRecord r : master) indexPacket(r);
    }

    /** 取得 (必要時重新計算) 某條連線的重組 / 解密結果。 */
    private StreamData streamData(StreamKey key) {
        List<PacketRecord> list = streamIndex.get(key);
        if (list == null || list.isEmpty()) return null;
        StreamData c = streamCache.get(key);
        if (c != null && c.packetCount == list.size() && c.keyVersion == keyVersion) return c;

        List<TcpSegment> segs = new ArrayList<>(list.size());
        for (PacketRecord r : list) {
            TcpSegment s = Segments.of(r);
            if (s != null) segs.add(s);
        }
        if (segs.isEmpty()) return null;
        TcpStream st = TcpStream.build(segs);
        TlsResult tls = keyLog.isEmpty() ? null : TlsDecryptor.decrypt(st, keyLog);
        if (streamCache.size() > 64) streamCache.clear();
        StreamData d = new StreamData(list.size(), keyVersion, st, tls);
        streamCache.put(key, d);
        return d;
    }

    @FXML
    private void onFollowStream() {
        PacketRecord r = table.getSelectionModel().getSelectedItem();
        if (!isTcp(r)) {
            showAlert(Alert.AlertType.INFORMATION, "請先在列表中選取一個 TCP 封包。");
            return;
        }
        followStream(r);
    }

    private void followStream(PacketRecord r) {
        StreamData d = streamData(Segments.keyOf(r));
        if (d == null) {
            showAlert(Alert.AlertType.ERROR, "找不到這條連線的封包資料。");
            return;
        }
        try {
            FollowStreamController.open(css, d.stream, d.tls);
        } catch (IOException e) {
            showAlert(Alert.AlertType.ERROR, "無法開啟追蹤視窗：" + e.getMessage());
        }
    }

    @FXML
    private void onImportKeys() {
        FileChooser fc = new FileChooser();
        fc.setTitle("匯入 SSL 金鑰檔 (sslkey.txt)");
        fc.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("金鑰檔 (*.txt, *.log)", "*.txt", "*.log"),
                new FileChooser.ExtensionFilter("所有檔案", "*.*"));
        File f = fc.showOpenDialog(stage);
        if (f == null) return;
        try {
            int n = keyLog.load(f.toPath());
            if (n == 0) {
                showAlert(Alert.AlertType.WARNING, "這個檔案中沒有可用的金鑰行。\n\n"
                        + "格式應為（NSS Key Log）：\nCLIENT_RANDOM <32 bytes hex> <secret hex>\n"
                        + "TLS 1.3 則是 CLIENT_TRAFFIC_SECRET_0 等行。");
                return;
            }
            onKeysChanged();
        } catch (IOException e) {
            showAlert(Alert.AlertType.ERROR, "讀取金鑰檔失敗：" + e.getMessage());
        }
    }

    @FXML
    private void onClearKeys() {
        keyLog.clear();
        onKeysChanged();
    }

    private void onKeysChanged() {
        keyVersion++;
        streamCache.clear();
        updateKeyLabel();
        showDetails(table.getSelectionModel().getSelectedItem());
    }

    private void updateKeyLabel() {
        keyLabel.setText(keyLog.isEmpty() ? "SSL 金鑰：未匯入" : "SSL 金鑰：已匯入 " + keyLog.sessionCount() + " 條連線");
    }

    /** 「TLS 解密後」分頁的內容：顯示與所選封包資料重疊的 TLS 記錄。 */
    private String decryptedText(PacketRecord r) {
        if (r == null) return "";
        if (!isTcp(r)) return "此封包不是 TCP，沒有可解密的 TLS 資料。";
        if (keyLog.isEmpty()) {
            return "尚未匯入 SSL 金鑰。\n\n請按上方工具列「SSL 金鑰」→「匯入 sslkey.txt…」。\n"
                    + "（瀏覽器可設定環境變數 SSLKEYLOGFILE 來匯出金鑰檔。）";
        }
        StreamData d = streamData(Segments.keyOf(r));
        if (d == null || d.tls == null) return "無法取得這條連線的資料。";
        if (!d.tls.usable()) return d.tls.error;

        int dir = d.stream.dirOf(r.src, r.srcPort);
        TcpStream.Chunk ch = d.stream.chunkFor(r.no);
        if (ch == null) return "此封包沒有新的 TCP 資料（純 ACK、握手或重傳）。";

        StringBuilder sb = new StringBuilder(d.tls.summary());
        sb.append("\n方向：").append(dir == 0 ? "客戶端 → 伺服器" : "伺服器 → 客戶端").append("\n\n");
        int chEnd = ch.offset + ch.data.length;
        int shown = 0;
        for (TlsRecord t : d.tls.records) {
            if (t.dir != dir || t.offset >= chEnd || t.offset + t.totalLength <= ch.offset) continue;
            shown++;
            sb.append("── TLS 記錄　類型：").append(TlsRecord.typeName(t.contentType))
                    .append("　長度：").append(t.totalLength - 5).append(" 位元組　");
            sb.append(t.encrypted ? (t.decrypted ? "(已解密)" : "(解密失敗)") : "(未加密)");
            if (t.offset < ch.offset || t.offset + t.totalLength > chEnd) sb.append("　※ 此記錄橫跨多個封包");
            sb.append(" ──\n");
            if (t.plaintext != null) {
                byte[] p = t.plaintext;
                sb.append(HexUtil.dump(p.length > MAX_DECRYPT_VIEW ? Arrays.copyOf(p, MAX_DECRYPT_VIEW) : p));
                if (p.length > MAX_DECRYPT_VIEW) sb.append("…（內容過長，只顯示前 64 KB，完整內容請用「追蹤串流」）\n");
            } else if (t.note != null) {
                sb.append(t.note).append('\n');
            }
            sb.append('\n');
        }
        if (shown == 0) sb.append("此封包的資料沒有對應到可解析的 TLS 記錄。");
        return sb.toString();
    }

    // ------------------------------------------------------------------ misc

    private static String formatBytes(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024L * 1024) return String.format("%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format("%.1f MB", b / 1048576.0);
        return String.format("%.2f GB", b / 1073741824.0);
    }

    private void showAlert(Alert.AlertType type, String msg) {
        Alert a = new Alert(type, msg, ButtonType.OK);
        a.initOwner(stage);
        a.initStyle(StageStyle.UNDECORATED);
        a.setHeaderText(null);
        a.getDialogPane().getStylesheets().add(css);
        a.showAndWait();
    }
}
