package com.sniffer.ui;

import javafx.scene.Cursor;
import javafx.scene.Scene;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;

import java.util.function.BooleanSupplier;

/** 無邊框視窗的邊緣拖曳縮放。 */
public final class ResizeHelper {
    private static final double B = 6;

    private ResizeHelper() {}

    public static void install(Stage stage, Scene scene, double minW, double minH, BooleanSupplier locked) {
        double[] s = new double[6];          // 起始 screenX, screenY, x, y, w, h
        boolean[] d = new boolean[4];        // left, right, top, bottom
        boolean[] active = {false};

        scene.addEventFilter(MouseEvent.MOUSE_MOVED, e -> {
            if (locked.getAsBoolean()) { scene.setCursor(Cursor.DEFAULT); return; }
            scene.setCursor(cursor(
                    e.getSceneX() < B, e.getSceneX() > scene.getWidth() - B,
                    e.getSceneY() < B, e.getSceneY() > scene.getHeight() - B));
        });

        scene.addEventFilter(MouseEvent.MOUSE_PRESSED, e -> {
            if (locked.getAsBoolean()) return;
            d[0] = e.getSceneX() < B;
            d[1] = e.getSceneX() > scene.getWidth() - B;
            d[2] = e.getSceneY() < B;
            d[3] = e.getSceneY() > scene.getHeight() - B;
            active[0] = d[0] || d[1] || d[2] || d[3];
            if (active[0]) {
                s[0] = e.getScreenX(); s[1] = e.getScreenY();
                s[2] = stage.getX();   s[3] = stage.getY();
                s[4] = stage.getWidth(); s[5] = stage.getHeight();
                e.consume();
            }
        });

        scene.addEventFilter(MouseEvent.MOUSE_DRAGGED, e -> {
            if (!active[0]) return;
            double dx = e.getScreenX() - s[0], dy = e.getScreenY() - s[1];
            double x = s[2], y = s[3], w = s[4], h = s[5];
            if (d[1]) w = Math.max(minW, s[4] + dx);
            if (d[0]) { double nw = Math.max(minW, s[4] - dx); x = s[2] + (s[4] - nw); w = nw; }
            if (d[3]) h = Math.max(minH, s[5] + dy);
            if (d[2]) { double nh = Math.max(minH, s[5] - dy); y = s[3] + (s[5] - nh); h = nh; }
            stage.setX(x); stage.setY(y); stage.setWidth(w); stage.setHeight(h);
            e.consume();
        });

        scene.addEventFilter(MouseEvent.MOUSE_RELEASED, e -> active[0] = false);
    }

    private static Cursor cursor(boolean l, boolean r, boolean t, boolean b) {
        if (t && l) return Cursor.NW_RESIZE;
        if (t && r) return Cursor.NE_RESIZE;
        if (b && l) return Cursor.SW_RESIZE;
        if (b && r) return Cursor.SE_RESIZE;
        if (l) return Cursor.W_RESIZE;
        if (r) return Cursor.E_RESIZE;
        if (t) return Cursor.N_RESIZE;
        if (b) return Cursor.S_RESIZE;
        return Cursor.DEFAULT;
    }
}
