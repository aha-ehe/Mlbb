# Laporan Analisis Reverse Engineering: Arsitektur Jaringan Game Mobile

**Tanggal:** 24 Februari 2025
**Analyst:** Senior Reverse Engineer & Network Security Analyst
**Subjek:** Analisis Protokol Jaringan & Keamanan In-Game Server (Unity/IL2CPP)

---

## 1. Ringkasan Eksekutif

Berdasarkan analisis statis terhadap artefak yang diberikan (`libmoba.so`, `libmultinetwork.so`, `libEncryptor.so`, `iplist.xml`, `classes.dex`, dll.), disimpulkan bahwa aplikasi ini menggunakan arsitektur **Hybrid Client-Server** dengan komunikasi real-time berbasis **Reliable UDP (KCP)** yang dikustomisasi.

Sistem serialisasi data menggunakan format biner khusus yang disebut **Sdp (Simple Data Packer)**, dan lapisan keamanan melibatkan enkripsi hibrida: **ttEncrypt** (kemungkinan berbasis pustaka ByteDance) untuk autentikasi awal, serta **Checksum/CRC + Session Key** ringan untuk paket in-game guna meminimalkan latensi.

---

## 2. Identifikasi Endpoint & Server

Dari analisis file konfigurasi XML dan `classes.dex`, berikut adalah pemetaan infrastruktur server:

### A. Server Autentikasi (Login/Auth)
Digunakan untuk pertukaran kredensial awal dan mendapatkan token sesi.
*   **Global**: `login.ml.youngjoygame.com` (Port: 30021), `global-login.ml.youngjoygame.com`
*   **Amerika Serikat**: `login-mlus.mproject.skystone.games` (Port: 30021)
*   **Backup/New Login**: `newlogin.ml.youngjoygame.com`, `newlogin.ml.mlbangbang.com`

### B. Server Patching & Update
Digunakan untuk memeriksa versi klien dan mengunduh aset baru.
*   **URL**: `https://loginclientversion.ml.youngjoygame.com:30022`
*   **IP Laporan**: `169.57.143.242` (Port: 9992)

### C. Server In-Game & Battle
Server ini menangani logika permainan real-time. Alamat IP dinamis didapat setelah handshake dengan Login Server, namun port berikut terindikasi penting:
*   **Port UDP/KCP**: Rentang dinamis, namun port `30021` (TCP/Login) dan `30071` (Report) sering muncul.

### D. Server Laporan & Analitik
*   **Endpoints**: `report.ml.youngjoygame.com`, `global-report.ml.youngjoygame.com`
*   **Analytics (3rd Party)**: `app.adjust.com`, `mon.isnssdk.com` (ByteDance/TikTok SDK), `gpm-mon-sg.bytegsdk.com`.

---

## 3. Analisis Protokol & Socket

### A. Transport Layer: Custom KCP
Game ini **tidak menggunakan TCP standar** untuk gameplay, melainkan **Reliable UDP** yang dibangun di atas pustaka **KCP**.

*   **Bukti**: Ditemukan simbol `ikcp_create`, `ikcp_send`, `ikcp_recv`, `ikcp_update`, `ikcp_flush` di dalam `libmoba.so`.
*   **Konfigurasi KCP**:
    *   `IKCP_MTU_DEF`: 1400 bytes (standar).
    *   `IKCP_CMD_PUSH`, `IKCP_CMD_ACK`: Command ID standar KCP.
    *   **Fast Retransmit**: Diaktifkan (`IKCP_ACK_FAST`).

### B. Socket Management
*   **Library Utama**: `libmoba.so`
*   **Class Kunci**:
    *   `UdpPipeManager`: Mengelola siklus hidup koneksi UDP.
    *   `PipeConnection`: Abstraksi koneksi (likely wrapper untuk socket UDP).
    *   `mfw::ReliableUdp`: Wrapper C++ di atas C-style KCP.
*   **Thread**: `UdpPipeManager::threadUdpMain` menangani loop utama penerimaan paket secara terpisah dari thread rendering Unity.

### C. Struktur Packet & Serialisasi (Sdp)
Tidak menggunakan Protobuf atau FlatBuffers standar. Game ini menggunakan sistem serialisasi custom bernama **Sdp (Simple Data Packer)**.

*   **Header Packet (Inferensi)**:
    1.  **Frame Header**: Menandakan awal paket.
    2.  **Version**: 1 byte (Indikasi dari error `ERROR_headerVersion_wrong`).
    3.  **Checksum/CRC**: 2-4 bytes (Indikasi dari `ERROR_headerChecksum_invalid`).
    4.  **Session ID**: 4 bytes (Indikasi dari error `udp recv packet with mismatch session`).
    5.  **OpCode (Command ID)**: 2 bytes.
    6.  **Payload**: Data game yang diserialisasi dengan Sdp.

*   **OpCode / Command ID**:
    Ditemukan referensi ke class `ProtoUdp` dengan perintah seperti:
    *   `Cmd_Udp_Init`: Handshake awal.
    *   `Cmd_Udp_Data`: Data gameplay (posisi, skill).
    *   `CmdProto`: Kemungkinan base class untuk semua command.

*   **Serialisasi**:
    *   `mfw::SdpPacker`: Class untuk mem-packing struct C++ ke binary stream.
    *   `mfw::SdpUnpacker`: Class untuk meng-unpack binary stream kembali ke struct.

---

## 4. Mekanisme Enkripsi & Keamanan

### A. Enkripsi Login (ttEncrypt)
Proses login dan pertukaran token awal dilindungi oleh pustaka `libEncryptor.so`.
*   **Algoritma**: Kemungkinan besar algoritma proprietari ByteDance (`ttEncrypt`), yang seringkali merupakan varian dari AES atau modifikasi RC4 dengan key derivation yang kompleks.
*   **Fungsi Ekspor**: `ttEncrypt` adalah satu-satunya simbol yang diekspor, menandakan ini adalah "black box" encryption module.

### B. Enkripsi In-Game (Lightweight)
Untuk mempertahankan performa tinggi (low latency), enkripsi paket UDP gameplay lebih ringan.
*   **Integritas**: Menggunakan **Checksum/CRC** pada header untuk mendeteksi korupsi data (`header crc mismatch`).
*   **Session Key**: `UdpPipeManager` menggunakan `mfw::UtilRandom` (`randombytes`, `randomseed`) untuk menghasilkan Session ID atau kunci XOR dinamis saat handshake (`Cmd_Udp_Init`).
*   **Signature**: Ditemukan string `digestEncryptionAlgorithmId` dan `subjectPublicKeyInfo` di `libmoba.so`, menunjukkan adanya verifikasi tanda tangan digital (RSA/ECC) pada data sensitif atau file konfigurasi, namun bukan pada setiap paket UDP.

---

## 5. Kesimpulan & Rekomendasi

Arsitektur jaringan game ini cukup matang dan teroptimasi untuk game MOBA (Multiplayer Online Battle Arena). Penggunaan **KCP** meminimalkan lag akibat packet loss, sementara serialisasi **Sdp** mengurangi overhead bandwidth dibandingkan JSON/XML.

**Untuk Studi Lebih Lanjut (Dynamic Analysis):**
1.  **Hooking**: Fokuskan hooking pada fungsi `UdpPipeManager::sendMsg` dan `mfw::ReliableUdp::decodePacket` di `libmoba.so` untuk melihat *plaintext* paket sebelum dienkripsi/setelah didekripsi.
2.  **Packet Capture**: Gunakan Wireshark dengan filter UDP. Payload akan terenkripsi/ter-encode KCP, sehingga perlu menulis plugin Wireshark khusus yang menggunakan logika `ikcp_decode` untuk membacanya.

---
*Laporan ini disusun berdasarkan analisis statis artefak versi `2.1.48.1149.2`.*
