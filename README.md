# Tool Analysis Foren

CTF Forensics Automated Diagnostic, Extraction & De-LiME Suite.

---

## 🚀 Quick Start

### 1. Instalasi Dependensi
```bash
# Windows / Linux / WSL
pip install -r requirements.txt
```

### 2. Shortcut Command
**Linux / WSL:**
```bash
chmod +x foren.py
sudo ln -sf $(pwd)/foren.py /usr/local/bin/foren
```

**Windows:**
Gunakan script pembungkus `foren.cmd` yang sudah disediakan:
```cmd
foren challenge.png
```

---

## 📖 Cara Penggunaan Umum

| Perintah | Deskripsi |
|---|---|
| `foren <file>` | Analisis otomatis berkas target (auto-detect format biner). |
| `foren <file> -o ./output` | Tentukan folder spesifik untuk menyimpan file hasil ekstraksi/carving. |
| `foren ./folder_soal/` | Mode Batch: otomatis menganalisis semua file di dalam folder. |
| `foren <file> --no-stop` | Deep scan tuntas tanpa berhenti pada temuan flag pertama. |
| `foren <file.lime> --delime` | Ekstrak & konversi format LiME menjadi raw physical memory (`.raw`). |

---

## 🧠 Panduan Lengkap RAM Memory & Ekstraksi De-LiME

### 1. Apa itu Format LiME (`.lime`)?
LiME (Linux Memory Extractor) menambahkan header 32-byte pada setiap blok physical memory (Magic bytes `0x4c694d45` / `EMiL`). Format ini tidak bisa dibaca langsung oleh Volatility tanpa dikonversi ke flat memory (`.raw`).

### 2. Ekstrak & De-LiME ke Raw RAM
Gunakan flag `--delime`:
```bash
# Otomatis mengupas header LiME dan menghasilkan memory.raw
foren memory.lime --delime -o ./ram_hasil
```
Hasil file `memory.raw` di folder output adalah flat physical memory murni yang kompatibel 100% dengan Volatility 2 & 3.

### 3. Analisis RAM Cepat (Zero-OOM Streamer)
Jalankan `foren` atau `memodump.py` pada dump memory (`.lime`, `.raw`, `.dmp`, `.vmem`):
```bash
# Analisis memory instan dengan streaming memory (hemat RAM, tidak crash pada dump besar)
foren memory.lime

# Atau menggunakan memodump standalone
python memodump.py memory.lime
```
**Fitur otomatis yang dijalankan:**
- **Linux Kernel Banner:** Menemukan versi kernel dan distro dari dump RAM.
- **Bash History Carving:** Mengambil riwayat perintah terminal Linux yang pernah dieksekusi.
- **Credential & Key Scan:** Mencari SSH Private Key, file token, dan environment variables.
- **Malfind & Injection:** Deteksi PE/MZ header dan preamble shellcode x86/x64 Metasploit di RAM.
- **Crypto Volume Scan:** Deteksi header partisi terenkripsi VeraCrypt / TrueCrypt di memori.

### 4. Analisis Lanjutan Menggunakan Volatility 3
Setelah dikonversi menjadi `memory.raw`, jalankan Volatility 3 di terminal:
```bash
# Analisis Profil Linux
vol -f memory.raw linux.bash.Bash
vol -f memory.raw linux.pslist.PsList
vol -f memory.raw linux.check_syscall.Check_syscall

# Analisis Profil Windows
vol -f memory.raw windows.pslist
vol -f memory.raw windows.cmdline
vol -f memory.raw windows.filescan
vol -f memory.raw windows.dumpfiles --virtaddr <address>
```

---

## 🛠️ Perintah Lengkap Berdasarkan Kategori Soal

### 1. Citra & Steganografi (PNG, JPG, BMP, GIF)
```bash
# Analisis lengkap stego, perbaikan header, LSB, dan OCR
foren challenge.png -o ./stego_out
```
- **PNG Corrupt:** Otomatis mendeteksi dan memperbaiki CRC IHDR yang rusak atau dimensi yang salah (misal tinggi gambar dipotong).
- **Steghide:** Otomatis brute-force password kosong dan wordlist bawaan.
- **JPG DQT:** Ekstraksi data tersembunyi pada Quantization Tables.
- **LSB Bitplanes:** Ekstraksi plane Red, Green, Blue, Alpha bit 0.

### 2. Network Packet Capture (PCAP / PCAPNG)
```bash
# Analisis traffic jaringan, USB capture, dan credentials
foren traffic.pcapng -o ./pcap_out
```
- **USB HID Keystroke:** Otomatis mengubah packet USB HID keyboard menjadi teks yang diketik.
- **USB Mouse Trajectory:** Merender pergerakan mouse menjadi gambar PNG lintasan kursor.
- **Credentials & Files:** Otomatis mengekstrak file HTTP, password FTP, Telnet, dan query DNS covert channel.

### 3. Dokumen & PDF
```bash
# Analisis dokumen tersembunyi dan redaction
foren confidential.pdf -o ./pdf_out
```
- **PDF FlateDecode:** Mendekompresi stream biner PDF dan mengekstrak teks/gambar tersembunyi.
- **Unmask Redaction:** Membuka teks yang ditutup kotak hitam sensor (redaction annotation).
- **Password Crack:** Ekstraksi hash PDF dan dictionary attack.

### 4. Disk Forensics & Container (AD1, MFT, RAID5, E01)
```bash
# Ekstrak AccessData AD1 container
foren evidence.ad1 -o ./ad1_out

# Analisis NTFS Master File Table
foren '$MFT' -o ./mft_out

# Rekonstruksi RAID5 XOR parity
foren disk_chunk*
```

### 5. Arsip & Kompresi (ZIP, 7z, TAR, GZ)
```bash
# Ekstrak arsip berlapis (Matreshka) & auto-crack password
foren nested_challenge.zip -o ./archive_out
```
- Otomatis melakukan unpacking rekursif hingga lapisan terdalam.
- Deteksi ZIP password protected dan cracking otomatis via dictionary rockyou/common.

### 6. IoT & Firmware (ESP32 Flash)
```bash
# Analisis dump flash ESP32
foren esp32_flash.bin -o ./esp32_out
```
- Membaca ESP32 Partition Table (NVS, factory, app, SPIFFS).
- Mendekripsi NVS keys yang di-obfuscate menggunakan XOR 0x80.

---

## 📊 Format Output

### Jika Flag Ditemukan:
```text
============================================================
[+] Flag found:
    - HackToday26{sample_ctf_flag_success}
      Method: [String Scan] Plaintext

[+] Output: /path/to/output_folder
============================================================
```

### Jika Perlu Triage / Analisis Manual:
```text
------------------------------------------------------------
[-] Flag tidak ditemukan secara otomatis pada analisis statis.
[*] Rekomendasi langkah manual / dinamis:
    1. Periksa berkas hasil ekstraksi di:
       /path/to/output_folder
------------------------------------------------------------
```
Periksa folder output untuk memeriksa file-file hasil carving (gambar tersembunyi, pcap stream, dokumen ter-ekstrak, atau dump RAM).
