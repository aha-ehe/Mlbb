# Laporan Mitigasi & Remediasi: Thread Starvation pada UdpPipeManager

**Tanggal:** 24 Februari 2025
**Analyst:** Senior Network Security Analyst
**Subjek:** Strategi Perbaikan Arsitektur untuk Mencegah Serangan TCP-PPS Interrupt Storm

---

## 1. Analisis Mekanisme Vulnerability

Berdasarkan analisis binary `libmoba.so`, kerentanan "Perfect Lag" disebabkan oleh desain **Single-Threaded Network Reactor** pada kelas `UdpPipeManager`.

### Pseudo-Code Kondisi Vulnerable (Saat Ini)
```cpp
// Thread tunggal menangani SEMUA event network
void UdpPipeManager::threadUdpMain() {
    while (running) {
        // 1. Multiplexing TCP dan UDP dalam satu select()
        // Jika flood TCP terjadi, select() return seketika (non-blocking efektif)
        int events = select(max_fd, &read_fds, NULL, NULL, &timeout);

        // 2. Prioritas Eksekusi tidak terisolasi
        if (FD_ISSET(tcp_socket, &read_fds)) {
            // High-cost operation: Parsing handshake, error checking, LOGGING
            processRemoteTcp();
        }

        if (FD_ISSET(udp_socket, &read_fds)) {
            // Gameplay packet processing
            // TERHAMBAT jika processRemoteTcp memakan waktu lama (CPU starvation)
            processRemoteUdp();
        }

        // 3. Lock Contention
        // processRemoteTcp memegang lock global saat error logging
        mutex.lock();
        LogError("Invalid TCP Header!"); // Blocking I/O ke logcat
        mutex.unlock();
    }
}
```

**Dampak**: Serangan TCP-PPS tinggi memaksa thread ini menghabiskan 99% waktu CPU di blok `processRemoteTcp` dan logging, menyebabkan starvation pada `processRemoteUdp`.

---

## 2. Strategi Mitigasi 1: Thread Separation (Isolasi)

Solusi paling efektif adalah memisahkan pemrosesan UDP (kritis untuk gameplay) dari TCP (hanya untuk signaling/chat/log).

### Desain Arsitektur Baru
*   **Thread A (Gameplay)**: Hanya menangani socket UDP dan logika KCP. Prioritas thread `REALTIME` atau `HIGH`.
*   **Thread B (Signaling)**: Menangani socket TCP. Prioritas thread `NORMAL` atau `LOW`.

### Pseudo-Code Remediasi (C++)
```cpp
// Thread Khusus Gameplay (UDP Only)
void UdpPipeManager::threadUdpLoop() {
    while (running) {
        // Hanya monitor socket UDP
        int events = select(udp_fd, &udp_fds, NULL, NULL, &timeout);

        if (FD_ISSET(udp_fd, &udp_fds)) {
            // Fast-path packet processing
            processRemoteUdp();
        }
        // Tidak ada gangguan dari traffic TCP
    }
}

// Thread Terpisah untuk TCP
void UdpPipeManager::threadTcpLoop() {
    while (running) {
        // Monitor socket TCP
        int events = select(tcp_fd, &tcp_fds, NULL, NULL, &timeout);

        if (FD_ISSET(tcp_fd, &tcp_fds)) {
            // Slow-path logic (Handshake, Chat)
            processRemoteTcp();
        }
    }
}
```

Dengan desain ini, serangan flood ke port TCP hanya akan memacetkan `ThreadTcpLoop` (chat lag), tetapi **TIDAK** akan mempengaruhi `ThreadUdpLoop` (gameplay lancar).

---

## 3. Strategi Mitigasi 2: Asynchronous Logging

Fungsi logging sinkron (`__android_log_print` atau `fprintf`) adalah operasi "mahal" yang memblokir thread.

### Masalah
```cpp
// Blocking I/O - Sangat berbahaya di network loop
LogError("Packet Error: %s", buffer);
```

### Solusi: Lock-Free Ring Buffer
Implementasikan sistem logging asinkron dimana thread network hanya "menitipkan" pesan ke buffer memori, dan thread terpisah yang menulisnya ke disk/logcat.

```cpp
void AsyncLog(const char* msg) {
    // Operasi atomik/cepat ke memori
    ringBuffer.push(msg);
}

// Thread Logger Terpisah
void LoggerThread() {
    while (true) {
        if (!ringBuffer.empty()) {
            msg = ringBuffer.pop();
            WriteToDisk(msg); // Blocking I/O terjadi di sini, aman.
        }
    }
}
```

---

## 4. Strategi Mitigasi 3: Kernel-Level Filtering (iptables)

Mencegah paket sampah mencapai aplikasi (userspace) sama sekali adalah pertahanan terbaik.

### Rekomendasi Konfigurasi Server (Linux)
Gunakan `iptables` untuk membatasi rate koneksi TCP baru (SYN flood protection) dan paket TCP tidak valid.

```bash
# 1. Drop paket TCP invalid (misal: flag kombinasi aneh)
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# 2. Limit koneksi baru (Anti-SYN Flood)
# Maksimal 10 koneksi baru per detik per IP
iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# 3. Limit RST packets (sering digunakan untuk interrupt storm)
iptables -A INPUT -p tcp --tcp-flags RST RST -m limit --limit 2/s -j ACCEPT
iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
```

Konfigurasi ini memastikan kernel Linux membuang sampah TCP *sebelum* `select()` di aplikasi `libmoba.so` terbangun, menjaga CPU tetap dingin.

---
*Dokumen ini disusun sebagai panduan remediasi bagi tim pengembang untuk menutup celah keamanan "Thread Starvation".*
