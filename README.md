# PacketSniffer

JavaFX + Npcap 封包擷取工具（類 Wireshark）。介面以 FXML 定義，樣式在 `style.css`。

## 執行

1. 安裝 [Npcap](https://npcap.com)（建議勾選 *WinPcap API-compatible Mode*），以系統管理員身分執行。
2. JDK 17 以上，`mvn javafx:run`。

## 追蹤 TCP 串流 (Follow TCP Stream)

在列表選取任一 TCP 封包後：工具列「追蹤串流」、列表右鍵「追蹤 TCP 串流」，或 `Ctrl+Alt+Shift+T`。
依 Seq 重組、去除重傳，客戶端 / 伺服器以不同顏色顯示，可切換 ASCII / UTF-8 / Hex、只看單一方向、複製或另存。

## 解密 HTTPS (匯入 sslkey.txt)

1. 讓瀏覽器匯出金鑰：設定系統環境變數 `SSLKEYLOGFILE=C:\path\sslkey.txt`，重新啟動瀏覽器。
2. **先開始擷取，再開啟網頁**（需要抓到連線的握手封包）。
3. 工具列「SSL 金鑰」→「匯入 sslkey.txt…」。
4. 選取封包後，右下「TLS 解密後」可看該封包的內容；「追蹤串流」可看整段解密後的對話。

支援 TLS 1.2 / 1.3 的 AES-GCM 與 ChaCha20-Poly1305。不支援 CBC 套件、QUIC (HTTP/3)，也無法解壓縮 gzip / HTTP/2 標頭壓縮。
