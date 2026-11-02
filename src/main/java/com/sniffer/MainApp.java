package com.sniffer;

import com.sniffer.capture.CaptureService;
import com.sniffer.capture.PacketParser;
import com.sniffer.model.Direction;
import com.sniffer.model.PacketRecord;
import com.sniffer.ui.ResizeHelper;
import com.sniffer.ui.TitleBar;
import com.sniffer.util.HexUtil;
import com.sniffer.util.PacketFilter;
import javafx.animation.Animation;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.collections.transformation.SortedList;
import javafx.css.PseudoClass;
import javafx.geometry.Insets;
import javafx.geometry.Orientation;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.util.Duration;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.net.Inet4Address;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.function.Function;

public class MainApp extends Application {

    private static final int MAX_PACKETS = 200_000;
    private static final PseudoClass INVALID = PseudoClass.getPseudoClass("invalid");
    private static final PseudoClass MAXIMIZED = PseudoClass.getPseudoClass("maximized");
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

    private final CaptureService capture = new CaptureService();
    private final ObservableList<PacketRecord> master = FXCollections.observableArrayList();
    private FilteredList<PacketRecord> filtered;
    private SortedList<PacketRecord> sorted;
    private final TableView<PacketRecord> table = new TableView<>();

    private final ComboBox<NicItem> nicBox = new ComboBox<>();
    private final Button startBtn = new Button();
    private final CheckBox autoScroll = new CheckBox("自動捲動");
    private final ComboBox<String> protoBox = new ComboBox<>();
    private final ComboBox<String> dirBox = new ComboBox<>();
    private final ComboBox<PacketFilter.Mode> modeBox = new ComboBox<>();
    private final TextField searchField = new TextField();
    private final Tooltip searchTip = new Tooltip();
    private final TreeView<String> detailTree = new TreeView<>();
    private final TextArea hexArea = new TextArea();
    private final RadioButton rbZh = new RadioButton("中文");
    private final RadioButton rbEn = new RadioButton("English");
    private final Label statusDot = new Label("●");
    private final Label statusText = new Label("就緒");
    private final Label countLabel = new Label();
    private final Label bytesLabel = new Label();

    private Stage stage;
    private String css;
    private boolean running;
    private long capturedBytes;
    private Timeline timeline;

    // ------------------------------------------------------------------ lifecycle

    @Override
    public void start(Stage stage) {
        this.stage = stage;
        stage.initStyle(StageStyle.TRANSPARENT);          // 透明視窗 → 圓角 + 半透明玻璃質感
        stage.setTitle("Packet Sniffer");
        css = getClass().getResource("/style.css").toExternalForm();

        TitleBar titleBar = new TitleBar(stage, "Packet Sniffer  ·  Npcap");

        VBox glassBar = new VBox(buildToolbar(), buildFilterBar());
        glassBar.getStyleClass().add("glass-bar");
        VBox top = new VBox(titleBar, glassBar);
        VBox.setMargin(glassBar, new Insets(4, 12, 10, 12));

        BorderPane root = new BorderPane();
        root.getStyleClass().add("app-root");
        root.setTop(top);
        Node center = buildCenter();
        BorderPane.setMargin(center, new Insets(0, 12, 0, 12));
        root.setCenter(center);
        root.setBottom(buildStatusBar());

        titleBar.setOnMaximizeChanged(m -> root.pseudoClassStateChanged(MAXIMIZED, m));

        Scene scene = new Scene(root, 1280, 780);
        scene.setFill(Color.TRANSPARENT);
        scene.getStylesheets().add(css);
        stage.setScene(scene);
        stage.setMinWidth(900);
        stage.setMinHeight(560);
        ResizeHelper.install(stage, scene, 900, 560, titleBar::isMaximized);

        applyFilter();
        updateButtons();
        loadInterfaces();

        timeline = new Timeline(new KeyFrame(Duration.millis(100), e -> drain()));
        timeline.setCycleCount(Animation.INDEFINITE);
        timeline.play();

        stage.show();
    }

    @Override
    public void stop() {
        if (timeline != null) timeline.stop();
        capture.shutdown();
    }

    // ------------------------------------------------------------------ UI building

    private Node buildToolbar() {
        Label l = new Label("網卡");
        l.getStyleClass().add("field-label");
        nicBox.setPrefWidth(430);
        nicBox.setPromptText("選擇網路卡…");
        nicBox.setTooltip(new Tooltip("選擇要監聽的網路卡（上網用的通常是有 IP 的那張）"));

        startBtn.getStyleClass().add("primary-btn");
        startBtn.setOnAction(e -> toggleCapture());

        Button clearBtn = new Button("清除封包");
        clearBtn.setTooltip(new Tooltip("清空列表中已抓到的封包"));
        clearBtn.setOnAction(e -> clearPackets());
        Button resetBtn = new Button("重設篩選");
        resetBtn.setTooltip(new Tooltip("把協定、方向、搜尋條件都恢復成預設"));
        resetBtn.setOnAction(e -> resetFilters());

        autoScroll.setSelected(true);
        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);

        HBox bar = new HBox(10, l, nicBox, startBtn, clearBtn, resetBtn, sp, autoScroll);
        bar.getStyleClass().add("toolbar");
        return bar;
    }

    private Node buildFilterBar() {
        Label pl = new Label("協定");
        pl.getStyleClass().add("field-label");
        protoBox.getItems().setAll(PacketFilter.PROTOCOLS);
        protoBox.setValue(PacketFilter.ALL);
        protoBox.setTooltip(new Tooltip("只顯示指定協定的封包"));

        Label dl = new Label("方向");
        dl.getStyleClass().add("field-label");
        dirBox.getItems().setAll(PacketFilter.ALL, Direction.IN.label, Direction.OUT.label);
        dirBox.setValue(PacketFilter.ALL);
        dirBox.setTooltip(new Tooltip("接收：送到本機的封包\n送出：本機發出的封包"));

        Label sl = new Label("搜尋");
        sl.getStyleClass().add("field-label");
        modeBox.getItems().setAll(PacketFilter.Mode.values());
        modeBox.setValue(PacketFilter.Mode.FIELD);
        searchField.setPromptText(PacketFilter.Mode.FIELD.prompt);
        searchTip.setText(PacketFilter.Mode.FIELD.tip);
        searchField.setTooltip(searchTip);
        modeBox.setTooltip(new Tooltip("選擇要搜尋的範圍：表格內容、封包文字，或十六進位特徵碼"));
        HBox.setHgrow(searchField, Priority.ALWAYS);

        protoBox.valueProperty().addListener((o, a, b) -> applyFilter());
        dirBox.valueProperty().addListener((o, a, b) -> applyFilter());
        modeBox.valueProperty().addListener((o, a, b) -> {
            searchField.setPromptText(b.prompt);
            searchTip.setText(b.tip);
            applyFilter();
        });
        searchField.textProperty().addListener((o, a, b) -> applyFilter());

        HBox bar = new HBox(10, pl, protoBox, dl, dirBox, sl, modeBox, searchField);
        bar.getStyleClass().add("filter-bar");
        return bar;
    }

    private Node buildCenter() {
        buildTable();
        StackPane tableCard = new StackPane(table);
        tableCard.getStyleClass().add("glass-card");
        roundClip(tableCard, 16);

        detailTree.getStyleClass().add("detail-tree");
        MenuItem copyLine = new MenuItem("複製此行");
        copyLine.setOnAction(e -> {
            TreeItem<String> it = detailTree.getSelectionModel().getSelectedItem();
            if (it != null) {
                ClipboardContent cc = new ClipboardContent();
                cc.putString(it.getValue());
                Clipboard.getSystemClipboard().setContent(cc);
            }
        });
        detailTree.setContextMenu(new ContextMenu(copyLine));

        hexArea.setEditable(false);
        hexArea.setWrapText(false);
        hexArea.getStyleClass().add("hex-area");

        ToggleGroup langGroup = new ToggleGroup();
        rbZh.setToggleGroup(langGroup);
        rbEn.setToggleGroup(langGroup);
        rbZh.setSelected(true);
        langGroup.selectedToggleProperty().addListener((o, a, b) -> {
            if (b == null) a.setSelected(true);            // 至少要選一個
            else showDetails(table.getSelectionModel().getSelectedItem());
        });
        Label langLabel = new Label("顯示語言");
        langLabel.getStyleClass().add("field-label");

        SplitPane lower = new SplitPane(
                titled("封包詳細資料", detailTree, langLabel, rbZh, rbEn),
                titled("封包內容  (Hex / ASCII)", hexArea));
        lower.setDividerPositions(0.45);

        SplitPane main = new SplitPane(tableCard, lower);
        main.setOrientation(Orientation.VERTICAL);
        main.setDividerPositions(0.6);
        return main;
    }

    /** 玻璃卡片：標題列 + 內容，圓角裁切。 */
    private VBox titled(String title, Node content, Node... extras) {
        Label t = new Label(title);
        t.getStyleClass().add("pane-title");
        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        HBox head = new HBox(8, t, sp);
        head.getChildren().addAll(extras);
        head.setAlignment(Pos.CENTER_LEFT);
        head.getStyleClass().add("pane-head");
        VBox.setVgrow(content, Priority.ALWAYS);
        VBox box = new VBox(head, content);
        box.getStyleClass().add("glass-card");
        roundClip(box, 16);
        return box;
    }

    private static void roundClip(Region r, double radius) {
        Rectangle c = new Rectangle();
        c.setArcWidth(radius * 2);
        c.setArcHeight(radius * 2);
        c.widthProperty().bind(r.widthProperty());
        c.heightProperty().bind(r.heightProperty());
        r.setClip(c);
    }

    private Node buildStatusBar() {
        statusDot.getStyleClass().addAll("dot", "dot-idle");
        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        Label sep = new Label("·");
        for (Label l : List.of(statusText, countLabel, bytesLabel, sep)) l.getStyleClass().add("status-text");
        HBox bar = new HBox(8, statusDot, statusText, sp, countLabel, sep, bytesLabel);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.getStyleClass().add("status-bar");
        return bar;
    }

    private void buildTable() {
        Label ph = new Label("選擇網卡後按「開始」擷取封包");
        ph.getStyleClass().add("placeholder");
        table.setPlaceholder(ph);

        TableColumn<PacketRecord, Long> cNo = col("#", 70, r -> r.no);
        fmt(cNo, Object::toString, "num");
        TableColumn<PacketRecord, Long> cTime = col("時間", 110, r -> r.timeMillis);
        fmt(cTime, v -> TIME_FMT.format(Instant.ofEpochMilli(v)), null);

        TableColumn<PacketRecord, Direction> cDir = col("方向", 80, r -> r.direction);
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

        TableColumn<PacketRecord, String> cSrc = col("來源", 170, r -> r.src);
        fmt(cSrc, s -> s, null);
        cSrc.setComparator(MainApp::compareIp);
        TableColumn<PacketRecord, String> cDst = col("目的", 170, r -> r.dst);
        fmt(cDst, s -> s, null);
        cDst.setComparator(MainApp::compareIp);
        TableColumn<PacketRecord, String> cProto = col("協定", 80, r -> r.protocol);
        fmt(cProto, s -> s, null);

        TableColumn<PacketRecord, Integer> cSp = col("來源埠", 80, r -> r.srcPort);
        fmt(cSp, Object::toString, "num");
        TableColumn<PacketRecord, Integer> cDp = col("目的埠", 80, r -> r.dstPort);
        fmt(cDp, Object::toString, "num");
        TableColumn<PacketRecord, Long> cSeq = col("Seq", 120, r -> r.seq);
        fmt(cSeq, Object::toString, "num");
        TableColumn<PacketRecord, Long> cAck = col("Ack", 120, r -> r.ack);
        fmt(cAck, Object::toString, "num");
        TableColumn<PacketRecord, Integer> cLen = col("長度", 70, r -> r.raw.length);
        fmt(cLen, Object::toString, "num");
        TableColumn<PacketRecord, String> cInfo = col("資訊", 560, r -> r.info);
        fmt(cInfo, s -> s, null);

        table.getColumns().addAll(List.of(cNo, cTime, cDir, cSrc, cDst, cProto, cSp, cDp, cSeq, cAck, cLen, cInfo));

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

        table.getSelectionModel().selectedItemProperty().addListener((o, a, r) -> showDetails(r));
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

    private <T> TableColumn<PacketRecord, T> col(String title, double width, Function<PacketRecord, T> getter) {
        TableColumn<PacketRecord, T> c = new TableColumn<>(title);
        c.setPrefWidth(width);
        c.setCellValueFactory(cd -> new ReadOnlyObjectWrapper<>(getter.apply(cd.getValue())));
        return c;
    }

    private <T> void fmt(TableColumn<PacketRecord, T> c, Function<T, String> f, String styleClass) {
        c.setCellFactory(col -> new SelectableCell<>(f, styleClass));
    }

    /**
     * 可反白複製的儲存格：內部放一個唯讀、透明的 TextField。
     * 滑鼠拖曳可反白，雙擊選一個詞，連點三下選整格，Ctrl+C 或右鍵複製；
     * 點擊時仍會同時選取該列。
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

    // ------------------------------------------------------------------ behaviour

    private void loadInterfaces() {
        try {
            List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
            if (devs == null || devs.isEmpty()) {
                showError("找不到任何網路卡。請確認 Npcap 已安裝，並以系統管理員身分執行。");
                return;
            }
            List<NicItem> items = devs.stream().map(NicItem::new).toList();
            nicBox.getItems().setAll(items);
            NicItem pick = items.stream()
                    .filter(i -> !i.ipv4().isEmpty() && !i.ipv4().startsWith("169.254") && !i.ipv4().startsWith("127."))
                    .findFirst().orElse(items.get(0));
            nicBox.setValue(pick);
        } catch (Throwable t) {
            showError("無法載入 Npcap。請確認：\n"
                    + "1. 已安裝 Npcap (https://npcap.com)，安裝時勾選「Install Npcap in WinPcap API-compatible Mode」\n"
                    + "2. 以系統管理員身分執行（或安裝 Npcap 時允許非管理員使用）\n"
                    + "3. 使用 64 位元 JDK\n\n詳細訊息：" + t);
        }
    }

    private void toggleCapture() {
        if (!running) {
            NicItem nic = nicBox.getValue();
            if (nic == null) {
                showError("請先選擇網卡。");
                return;
            }
            try {
                capture.start(nic.nif(), msg -> Platform.runLater(() -> {
                    running = false;
                    updateButtons();
                    showError("擷取發生錯誤：" + msg);
                }));
                running = true;
            } catch (Throwable t) {
                showError("無法開始擷取：" + t.getMessage()
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
            for (PacketRecord r : batch) capturedBytes += r.raw.length;
            if (master.size() > MAX_PACKETS) {                       // 超過上限就丟掉最舊的 10%
                master.remove(0, master.size() - (MAX_PACKETS - MAX_PACKETS / 10));
            }
            if (autoScroll.isSelected() && table.getSortOrder().isEmpty() && !sorted.isEmpty()) {
                table.scrollTo(sorted.size() - 1);
            }
        }
        countLabel.setText("顯示 " + filtered.size() + " 筆 / 共 " + master.size() + " 筆");
        bytesLabel.setText("累計 " + formatBytes(capturedBytes));
    }

    private void clearPackets() {
        capture.reset();
        master.clear();
        capturedBytes = 0;
        table.getSelectionModel().clearSelection();
        showDetails(null);
        drain();
    }

    private void resetFilters() {
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

    private void showDetails(PacketRecord r) {
        if (r == null) {
            detailTree.setRoot(null);
            hexArea.clear();
            return;
        }
        detailTree.setRoot(PacketParser.buildDetails(r, rbZh.isSelected()));
        hexArea.setText(HexUtil.dump(r.raw));
    }

    private static String formatBytes(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024L * 1024) return String.format("%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format("%.1f MB", b / 1048576.0);
        return String.format("%.2f GB", b / 1073741824.0);
    }

    private void showError(String msg) {
        Alert a = new Alert(Alert.AlertType.ERROR, msg, ButtonType.OK);
        a.initOwner(stage);
        a.initStyle(StageStyle.UNDECORATED);
        a.setHeaderText(null);
        a.getDialogPane().getStylesheets().add(css);
        a.showAndWait();
    }
}
