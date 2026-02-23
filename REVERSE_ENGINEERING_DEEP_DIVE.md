# Laporan Analisis Vulnerability Deep Dive: "Smart Lag" & Arsitektur Paket Sdp

**Tanggal:** 24 Februari 2025
**Analyst:** Senior Reverse Engineer & Network Security Analyst
**Subjek:** Analisis Struktur Paket `Sdp`, Pemetaan OpCode, dan Potensi Eksploitasi "Smart Lag"

---

## 1. Status Metadata & Pivot Strategi
File `global-metadata.dat` yang dianalisis ditemukan **kosong (0 bytes)**, sehingga rekonstruksi struct C# secara langsung tidak memungkinkan. Analisis dialihkan ke **Native Layer (`libmoba.so`)**, tempat implementasi inti `SdpPacker` dan `SdpUnpacker` berada. Strategi ini lebih relevan untuk analisis kerentanan karena parsing paket low-level terjadi di lapisan ini sebelum diteruskan ke runtime Unity.

---

## 2. Struktur Paket Sdp (Simple Data Packer)

Berdasarkan analisis simbol native C++, format serialisasi `Sdp` menggunakan pendekatan *Tag-Length-Value* (TLV) yang dimodifikasi atau *Packed Struct*. Berikut adalah rekonstruksi struktur logis dari paket gameplay utama:

### A. Struktur Umum (Inferensi)
Setiap paket `Sdp` tampaknya memiliki struktur berikut saat di-unpack:
1.  **Field Index/Tag**: Mengidentifikasi urutan field dalam struct.
2.  **Data Type**: Menentukan tipe data (Int, String, Struct, Vector).
3.  **Value**: Data payload.

### B. Struct Gameplay Utama
Ditemukan fungsi `visit` dan `unpack` spesifik untuk aksi gameplay, mengindikasikan bahwa aksi ini memiliki struct dedicated:

#### 1. `ProtoUdp::Cmd_Udp_Data`
Ini adalah wrapper utama untuk data in-game.
*   **Fungsi Terkait**: `SdpUnpacker::unpack<Cmd_Udp_Data>`, `SdpPacker::pack<Cmd_Udp_Data>`
*   **Komposisi (Prediksi)**:
    *   `OpCode` (Int16/32)
    *   `FrameId` (Int32)
    *   `Payload` (Bytes/Nested Struct) - Berisi data spesifik aksi (Move, CastSkill).

#### 2. `mfw::OperType_Battle_Move` (Pergerakan)
Struct yang menangani sinkronisasi posisi pemain.
*   **Fungsi Native**: `SDP_NativeParseMoveOp`, `__GetMoveOpCPlus`
*   **Field yang Diharapkan**:
    *   `EntityId` (Int32) - ID unik unit yang bergerak.
    *   `Position` (Vector3 / 3x Float) - Koordinat tujuan (x, y, z).
    *   `Direction` (Float/Int) - Sudut hadap.
    *   `Velocity` (Float) - Kecepatan (opsional, untuk validasi).

#### 3. `mfw::OperType_Battle_CastSkill` (Penggunaan Skill)
Struct untuk aksi skill.
*   **Fungsi Native**: `SDP_NativeParseCastSkillOp`, `__GetCastSkillOpCPlus`
*   **Field yang Diharapkan**:
    *   `SkillId` (Int32) - ID skill yang digunakan.
    *   `TargetId` (Int32) - ID target (jika auto-lock).
    *   `TargetPos` (Vector3) - Posisi target (untuk skill area/skillshot).
    *   `Direction` (Float) - Arah tembakan.

---

## 3. Pemetaan OpCode (Static Inference)

Meskipun nilai integer spesifik dari OpCode (misal: `0x01` untuk Move) tertanam dalam instruksi assembly dan tidak terlihat di string, kita dapat memetakan **Logical OpCode** berdasarkan fungsi penanganannya:

| Logical Command | Class/Symbol Terkait | Fungsi Parsing Native | Keterangan |
| :--- | :--- | :--- | :--- |
| **Init / Handshake** | `ProtoUdp::Cmd_Udp_Init` | `SdpUnpacker::unpack<Cmd_Udp_Init>` | Inisialisasi koneksi UDP & pertukaran key session. |
| **Gameplay Data** | `ProtoUdp::Cmd_Udp_Data` | `SdpUnpacker::unpack<Cmd_Udp_Data>` | Kontainer generik untuk update frame in-game. |
| **Player Move** | `mfw::OperType_Battle_Move` | `SDP_NativeParseMoveOp` | Sinkronisasi pergerakan karakter. Sangat rentan terhadap manipulasi koordinat. |
| **Cast Skill** | `mfw::OperType_Battle_CastSkill` | `SDP_NativeParseCastSkillOp` | Pemicu aksi skill. |
| **Lua Script Event** | `LuaSdpStruct` | `LuaSdpValueReader::visit` | Event yang dikirim/diterima oleh layer Lua (logika UI/Quest). |

---

## 4. Analisis Vulnerability Surface ("Smart Lag")

Analisis terhadap `libmoba.so` mengungkapkan beberapa vektor serangan potensial yang dapat menyebabkan "Smart Lag" (DoS lokal atau degradasi performa server):

### A. Unbounded Vector Allocation (Memory Exhaustion)
Ditemukan fungsi:
*   `SdpUnpacker::unpack<LuaSdpVectorReader>`
*   `SdpUnpacker::unpack<LuaSdpMapReader>`

**Vektor Serangan**: Jika format `Sdp` untuk array/vector diawali dengan field panjang (Length), penyerang dapat mengirimkan paket dengan nilai Length yang sangat besar (misal: `0xFFFFFFFF`) tanpa mengirimkan data payload yang sesuai.
*   **Dampak**: Server mencoba mengalokasikan memori sebesar `Length * sizeof(Element)` (misal: 4GB+), menyebabkan server crash (OOM) atau hang saat mencoba melakukan loop pembacaan data yang tidak ada.

### B. LZ4 Decompression Bomb
Ditemukan simbol `LZ4_uncompress_unknownOutputSize` dan `lz4_uncompress`.
**Vektor Serangan**: Mengirimkan paket kecil yang valid secara header `Sdp`, namun payload-nya adalah data terkompresi LZ4 yang jika diekstrak menjadi sangat besar (LZ4 Bomb).
*   **Dampak**: Lonjakan CPU server untuk dekompresi dan konsumsi memori masif, menyebabkan lag spike bagi semua pemain dalam match tersebut.

### C. Logic Recursion / Nested Structs
Struktur `Sdp` mendukung nested types (`visit` pattern).
**Vektor Serangan**: Membuat paket dengan struktur bersarang yang sangat dalam (Deeply Nested Structs).
*   **Dampak**: Stack overflow pada thread pemrosesan packet (`UdpPipeManager::threadUdpMain`), yang akan mematikan proses match instance tersebut secara instan.

### D. Exception Handling Overhead
Meskipun ada fungsi exception (`throwNoEnoughData`, `throwFieldNotExist`), mekanisme *throwing* exception di C++ (terutama di Android/ARM) relatif mahal secara komputasi (CPU cycles).
**Vektor Serangan**: Mengirimkan banjir paket (packet flood) yang sengaja diformat sedikit salah (misal: field kurang 1 byte) untuk memicu `throwNoEnoughData` secara terus-menerus.
*   **Dampak**: CPU server sibuk melakukan *stack unwinding* untuk exception handling daripada memproses paket valid pemain lain.

---

## 5. Kesimpulan Teknis

Protokol custom **Sdp** yang digunakan game ini, meskipun efisien, memiliki permukaan serangan klasik pada parser biner kustom. Ketiadaan skema standar yang ketat (seperti `.proto` pada Protobuf yang terkompilasi) dan ketergantungan pada logika parsing manual (`visit` pattern) di C++ membuka peluang eksploitasi manipulasi memori dan logika alokasi.

Fokus utama untuk mitigasi atau eksploitasi "Smart Lag" harus diarahkan pada:
1.  **Vector Length Fields**: Manipulasi ukuran array di dalam paket `Cmd_Udp_Data`.
2.  **LZ4 Payload**: Manipulasi rasio kompresi.

---
*Laporan ini disusun berdasarkan analisis statis native binary `libmoba.so` karena ketidaktersediaan metadata C#.*
