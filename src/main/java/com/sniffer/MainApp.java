package com.sniffer;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.stage.StageStyle;

import java.io.IOException;

/** 啟動入口：載入 FXML 並建立透明、無邊框的主視窗。介面與邏輯分別在 MainView.fxml 與 MainController。 */
public class MainApp extends Application {

    private MainController controller;

    @Override
    public void start(Stage stage) throws IOException {
        stage.initStyle(StageStyle.TRANSPARENT);          // 透明視窗 → 圓角 + 半透明玻璃質感
        stage.setTitle("Packet Sniffer");

        FXMLLoader loader = new FXMLLoader(getClass().getResource("/fxml/MainView.fxml"));
        Parent root = loader.load();
        controller = loader.getController();

        String css = getClass().getResource("/style.css").toExternalForm();
        Scene scene = new Scene(root, 1280, 780);
        scene.setFill(Color.TRANSPARENT);
        scene.getStylesheets().add(css);
        stage.setScene(scene);
        stage.setMinWidth(MainController.MIN_WIDTH);
        stage.setMinHeight(MainController.MIN_HEIGHT);

        controller.attach(stage, scene, css);
        stage.show();
    }

    @Override
    public void stop() {
        if (controller != null) controller.shutdown();
    }
}
