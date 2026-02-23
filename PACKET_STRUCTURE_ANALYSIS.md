# Laporan Analisis Struktur Paket Sdp & Handshake KCP

**Tanggal:** 24 Februari 2025
**Analyst:** Senior Reverse Engineer & Network Security Analyst
**Subjek:** Spesifikasi Byte-Level Header Sdp & Protokol Handshake UDP

---

## 1. Struktur Header Paket Sdp (Rekonstruksi Byte-Level)

Berdasarkan urutan pengecekan error di `libmoba.so` (`ERROR_headerVersion_wrong` -> `ERROR_headerChecksum_invalid` -> `mismatch session`), berikut adalah layout header yang divalidasi oleh server.

### Format Header (Total: 7-9 Bytes + Payload)
Struktur ini berada **sebelum** data KCP atau membungkus data KCP, tergantung pada layer implementasi. Berdasarkan analisis `ReliableUdp::decodePacket`:

| Offset | Ukuran | Nama Field | Tipe Data | Keterangan |
| :--- | :--- | :--- | :--- | :--- |
| **0x00** | 1 Byte | **Version** | `uint8` | Versi protokol. Server memvalidasi ini pertama kali. Jika salah, drop packet. |
| **0x01** | 2 Bytes | **Checksum** | `uint16` | CRC16 atau checksum sederhana dari payload. Validasi kedua. |
| **0x03** | 4 Bytes | **Session ID** | `uint32` | ID Sesi unik yang didapat saat Login. Validasi ketiga. Jika mismatch, koneksi ditolak. |
| **0x07** | Variable | **Payload** | `Bytes` | Data KCP atau Sdp (tergantung enkapsulasi). |

*Catatan: OpCode biasanya berada di dalam payload Sdp yang telah didekripsi/unpack, bukan di header transport "luar" ini.*

---

## 2. Analisis Handshake (`Cmd_Udp_Init`)

Saat klien pertama kali terhubung via UDP, ia mengirimkan paket inisialisasi (`Cmd_Udp_Init`).

### Logika Koneksi
1.  **TCP Login**: Klien login ke server TCP (Login Server), mendapatkan `Session Token` dan `Endpoint` UDP.
2.  **UDP Handshake**: Klien mengirim `Cmd_Udp_Init` ke Battle Server UDP.
3.  **Identifier Check**: Server memvalidasi "Identifier" dalam paket init. String `udp recv establish cmd with mismatch identifier` mengonfirmasi hal ini.

### Struktur `Cmd_Udp_Init` (Estimasi Isi)
Paket ini diserialisasi menggunakan `SdpPacker` dan berisi:
*   **Unique Identifier** (4-8 Bytes): Token/ID yang didapat dari Login Server. Ini digunakan server untuk memetakan koneksi UDP anonim ke akun pemain.
*   **Retry Count** (`num=`): Counter untuk retransmisi handshake jika packet loss.
*   **Client Timestamp**: Untuk sinkronisasi clock awal.

### OpCode Handshake
Berdasarkan pola umum dan string log `establish cmd`, OpCode untuk `Cmd_Udp_Init` kemungkinan besar adalah **1** atau **1001** (nilai awal umum). Nilai pastinya tertanam dalam instruksi assembly `switch-case`.

---

## 3. KCP Conversation ID (`conv`)

KCP membutuhkan `conv` ID agar kedua belah pihak tahu paket mana milik koneksi mana.

*   **Dinamis**: `conv` tidak statis.
*   **Sumber**: `GetUniqIdentifier` di `libmoba.so`.
*   **Mekanisme**:
    1.  Klien menggunakan ID yang didapat dari Login Server sebagai basis.
    2.  `ikcp_create` dipanggil menggunakan ID ini.
    3.  Paket UDP pertama (`Cmd_Udp_Init`) membawa ID ini di header KCP (4 byte pertama dari frame KCP standard) ATAU di dalam payload Sdp.
    4.  Server membaca `conv` via `ikcp_getconv`, membandingkannya dengan daftar sesi yang valid (`establish cmd with mismatch identifier`), dan jika cocok, koneksi KCP established.

### Rekomendasi Pembuatan Paket Palsu
Untuk membuat paket "malformed" yang lolos validasi awal server (sehingga bisa memicu parsing Sdp "Smart Lag"):
1.  **Sniff/Replay Session ID**: Anda harus memiliki **Session ID** yang valid dari match yang sedang berjalan. Anda tidak bisa menebak ini.
2.  **Valid Header**: Paket harus memiliki [Version Benar] + [Checksum Valid] + [Session ID Benar].
3.  **KCP Layer**: Bungkus payload Sdp "jahat" (misal: Vector Length Overflow) di dalam frame KCP yang valid dengan sequence number yang benar.

---
*Analisis ini mengonfirmasi bahwa serangan "Smart Lag" membutuhkan akses autentik ke dalam match (man-in-the-middle atau client modifikasi) dan tidak bisa dilakukan secara anonim dari luar (spoofing).*
