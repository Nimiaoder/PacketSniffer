package com.sniffer;

import javafx.application.Application;

import java.io.File;

/** 非 JavaFX Application 子類別的啟動入口，並在載入 pcap4j 前設定 Npcap 路徑。 */
public class Launcher {
    public static void main(String[] args) {
        String root = System.getenv("SystemRoot");
        if (root == null) root = "C:\\Windows";
        File npcap = new File(root, "System32\\Npcap");
        if (npcap.isDirectory()) {
            String old = System.getProperty("jna.library.path");
            String p = npcap.getAbsolutePath();
            System.setProperty("jna.library.path", old == null || old.isEmpty() ? p : old + File.pathSeparator + p);
        }
        Application.launch(MainApp.class, args);
    }
}
