package com.sniffer.ui;

import javafx.geometry.Pos;
import javafx.geometry.Rectangle2D;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.stage.Screen;
import javafx.stage.Stage;

import java.util.function.Consumer;

/** 自訂標題列：拖曳移動、雙擊最大化、最小化 / 最大化 / 關閉按鈕。 */
public final class TitleBar extends HBox {
    private final Stage stage;
    private final Button maxBtn = winButton("\uE922", false);
    private boolean maximized;
    private Rectangle2D restoreBounds;
    private double offX, offY;
    private Consumer<Boolean> onMaximizeChanged = m -> { };

    public TitleBar(Stage stage, String title) {
        this.stage = stage;
        getStyleClass().add("title-bar");
        setAlignment(Pos.CENTER_LEFT);

        Label logo = new Label("◉");
        logo.getStyleClass().add("title-logo");
        Label text = new Label(title);
        text.getStyleClass().add("title-text");

        HBox dragArea = new HBox(10, logo, text);
        dragArea.setAlignment(Pos.CENTER_LEFT);
        dragArea.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(dragArea, Priority.ALWAYS);
        dragArea.setOnMousePressed(this::onPress);
        dragArea.setOnMouseDragged(this::onDrag);
        dragArea.setOnMouseClicked(e -> {
            if (e.getButton() == MouseButton.PRIMARY && e.getClickCount() == 2) toggleMaximize();
        });

        Button min = winButton("\uE921", false);
        Button close = winButton("\uE8BB", true);
        min.setOnAction(e -> stage.setIconified(true));
        maxBtn.setOnAction(e -> toggleMaximize());
        close.setOnAction(e -> stage.close());

        getChildren().addAll(dragArea, min, maxBtn, close);
    }

    public boolean isMaximized() { return maximized; }

    /** 最大化狀態改變時通知 (最大化時主視窗要取消圓角)。 */
    public void setOnMaximizeChanged(Consumer<Boolean> c) { this.onMaximizeChanged = c; }

    private static Button winButton(String glyph, boolean isClose) {
        Button b = new Button(glyph);
        b.getStyleClass().add("win-btn");
        if (isClose) b.getStyleClass().add("win-btn-close");
        b.setFocusTraversable(false);
        return b;
    }

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
        onMaximizeChanged.accept(true);
    }

    private void applyRestore() {
        stage.setX(restoreBounds.getMinX());
        stage.setY(restoreBounds.getMinY());
        stage.setWidth(restoreBounds.getWidth());
        stage.setHeight(restoreBounds.getHeight());
        maximized = false;
        maxBtn.setText("\uE922");
        onMaximizeChanged.accept(false);
    }
}
