package com.sniffer;

import com.sniffer.ui.ResizeHelper;
import com.sniffer.ui.WindowChrome;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.Window;

import java.io.IOException;

/**
 * 玻璃風格的訊息視窗，取代系統的 Alert：
 * 有自己的標題列 (可拖曳、可按 X 關閉)、可捲動且可反白複製的訊息區，Esc / Enter 也能關閉。
 */
public final class GlassDialogController {

    public enum Kind {
        INFO("ⓘ", "提示"), WARNING("⚠", "注意"), ERROR("✕", "發生錯誤");

        final String icon, title;

        Kind(String icon, String title) { this.icon = icon; this.title = title; }
    }

    @FXML private BorderPane root;
    @FXML private HBox dragArea;
    @FXML private StackPane card;
    @FXML private Label iconLabel, titleLabel;
    @FXML private TextArea messageArea;
    @FXML private Button closeBtn, okBtn;

    private Stage stage;

    /** 顯示並等待使用者關閉。owner 可為 null。 */
    public static void show(Window owner, String css, Kind kind, String message) {
        try {
            FXMLLoader loader = new FXMLLoader(GlassDialogController.class.getResource("/fxml/GlassDialog.fxml"));
            Parent root = loader.load();
            GlassDialogController c = loader.getController();

            Stage st = new Stage(StageStyle.TRANSPARENT);
            st.initModality(Modality.APPLICATION_MODAL);
            if (owner != null && owner.isShowing()) st.initOwner(owner);
            Scene scene = new Scene(root, 580, 320);
            scene.setFill(Color.TRANSPARENT);
            scene.getStylesheets().add(css);
            scene.addEventFilter(KeyEvent.KEY_PRESSED, e -> {
                if (e.getCode() == KeyCode.ESCAPE) st.close();
            });
            st.setScene(scene);
            st.setMinWidth(420);
            st.setMinHeight(220);
            st.setTitle(kind.title);

            WindowChrome.install(st, c.root, c.dragArea, null, null, c.closeBtn);
            ResizeHelper.install(st, scene, 420, 220, () -> false);
            c.stage = st;
            c.iconLabel.setText(kind.icon);
            c.titleLabel.setText(kind.title);
            c.messageArea.setText(message);
            c.messageArea.positionCaret(0);
            st.showAndWait();
        } catch (IOException e) {
            e.printStackTrace();   // 連對話框都載入失敗時，至少留下紀錄
        }
    }

    @FXML
    private void initialize() {
        Rectangle clip = new Rectangle();
        clip.setArcWidth(32);
        clip.setArcHeight(32);
        clip.widthProperty().bind(card.widthProperty());
        clip.heightProperty().bind(card.heightProperty());
        card.setClip(clip);
    }

    @FXML
    private void onOk() {
        stage.close();
    }
}
