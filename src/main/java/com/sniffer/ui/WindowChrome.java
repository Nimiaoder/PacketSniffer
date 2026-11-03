package com.sniffer.ui;

import javafx.css.PseudoClass;
import javafx.geometry.Rectangle2D;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.stage.Screen;
import javafx.stage.Stage;

/**
 * 自訂標題列的行為：拖曳移動、雙擊最大化、最小化 / 最大化 / 關閉。
 * 標題列的外觀在 FXML 中定義，這裡只負責把行為接上去。
 */
public final class WindowChrome {
    private static final PseudoClass MAXIMIZED = PseudoClass.getPseudoClass("maximized");

    private final Stage stage;
    private final Parent root;
    private final Button maxBtn;
    private boolean maximized;
    private Rectangle2D restoreBounds;
    private double offX, offY;

    private WindowChrome(Stage stage, Parent root, Button maxBtn) {
        this.stage = stage;
        this.root = root;
        this.maxBtn = maxBtn;
    }

    public static WindowChrome install(Stage stage, Parent root, Node dragArea,
                                       Button minBtn, Button maxBtn, Button closeBtn) {
        WindowChrome c = new WindowChrome(stage, root, maxBtn);
        if (!closeBtn.getStyleClass().contains("win-btn-close")) closeBtn.getStyleClass().add("win-btn-close");
        dragArea.setOnMousePressed(c::onPress);
        dragArea.setOnMouseDragged(c::onDrag);
        dragArea.setOnMouseClicked(e -> {
            if (e.getButton() == MouseButton.PRIMARY && e.getClickCount() == 2) c.toggleMaximize();
        });
        minBtn.setOnAction(e -> stage.setIconified(true));
        maxBtn.setOnAction(e -> c.toggleMaximize());
        closeBtn.setOnAction(e -> stage.close());
        return c;
    }

    public boolean isMaximized() { return maximized; }

    private void onPress(MouseEvent e) {
        if (e.getButton() != MouseButton.PRIMARY) return;
        offX = e.getScreenX() - stage.getX();
        offY = e.getScreenY() - stage.getY();
    }

    private void onDrag(MouseEvent e) {
        if (e.getButton() != MouseButton.PRIMARY) return;
        if (maximized) {                       // 從最大化狀態拖曳 → 還原並跟著滑鼠
            double w = restoreBounds.getWidth();
            applyRestore();
            offX = w / 2;
            offY = 16;
        }
        stage.setX(e.getScreenX() - offX);
        stage.setY(e.getScreenY() - offY);
    }

    private void toggleMaximize() {
        if (maximized) {
            applyRestore();
            return;
        }
        restoreBounds = new Rectangle2D(stage.getX(), stage.getY(), stage.getWidth(), stage.getHeight());
        Screen screen = Screen.getScreensForRectangle(
                stage.getX(), stage.getY(), stage.getWidth(), stage.getHeight())
                .stream().findFirst().orElse(Screen.getPrimary());
        Rectangle2D vb = screen.getVisualBounds();     // 不含工作列
        stage.setX(vb.getMinX());
        stage.setY(vb.getMinY());
        stage.setWidth(vb.getWidth());
        stage.setHeight(vb.getHeight());
        maximized = true;
        maxBtn.setText("\uE923");
        root.pseudoClassStateChanged(MAXIMIZED, true);
    }

    private void applyRestore() {
        stage.setX(restoreBounds.getMinX());
        stage.setY(restoreBounds.getMinY());
        stage.setWidth(restoreBounds.getWidth());
        stage.setHeight(restoreBounds.getHeight());
        maximized = false;
        maxBtn.setText("\uE922");
        root.pseudoClassStateChanged(MAXIMIZED, false);
    }
}
