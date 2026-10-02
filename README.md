# CTF Forensics Toolkit
### Forensic Solver Suite for CTF Competitions (HackToday & National CTFs)

Toolkit analisis forensik digital offline berbasis script Python untuk memecahkan berbagai tantangan CTF (Disk, Memory, Network, Steganografi, Log, Database, dan Hardware Signals).

---

## 🚀 Cara Penggunaan

### 1. Satu Perintah Auto-Detector & Solver (Rekomendasi Utama)
Cukup jalankan satu perintah ini, script akan **langsung mendeteksi tipe soalnya** (PCAP, Memory, Image, Audio, DB, EVTX, Disk, dll.) dan mengeksekusi pemeriksaan yang sesuai:
```bash
python foren.py <nama_file_soal>
```
Opsi tambahan:
- `--no-stop` : Lakukan deep scan tuntas tanpa berhenti di temuan pertama
- `--outdir <folder>` : Tentukan folder hasil analisis (default: `results`)

---

### 2. Master Solver Alternatif
```bash
python solve.py <nama_file_soal>
```

### 2. Tool Spesifik (Singkat & Terarah)

Jika jenis soal sudah diketahui, gunakan script langsung yang singkat:

| Script | Deskripsi & Penggunaan |
|---|---|
| **`memodump.py`** | Analisis memory dump RAM (`.lime`, `.raw`, `.dmp`, `.vmem`). Ekstraksi bash history, kernel banner, env flags, dan carving raw framebuffer bitmap.<br>`python memodump.py memory.lime` |
| **`stegano.py`** | Analisis steganografi citra & audio. Cek LSB bitplanes, JPEG DQT quantization table, PNG IHDR/PLTE slack, dan decoding nada DTMF audio.<br>`python stegano.py challenge.png` |
| **`pcap.py`** | Analisis capture jaringan (`.pcap`, `.pcapng`). Rekonstruksi keystroke USB HID keyboard, gambar USB mouse (SVG), ekstraksi kredensial HTTP, ICMP/DNS exfil, dan timing interval stego.<br>`python pcap.py capture.pcapng` |
| **`carver.py`** | Ekstraksi file tertanam dan perbaikan struktur (signature scanning 70+ format, trailing data / EOF overlay, dan pemulihan ZIP lokal yang rusak).<br>`python carver.py evidence.bin` |
| **`strings.py`** | Pencarian string & regex flag multi-encoding (Plaintext, Base64, Hex, ROT13, Single-byte XOR, Repeating XOR, dan WordPerfect macro XOR).<br>`python strings.py suspect.raw` |
| **`disk.py`** | Analisis disk image, decoding GPT partition GUID data, rekonstruksi RAID 5 via XOR, deteksi APFS snapshot / VMDK, dan parser Windows Recycle Bin `$I`/`$R`.<br>`python disk.py disk.img` |

---

## 🛠️ Modul Core (`core/`)

| Modul | File | Kemampuan Analisis |
|---|---|---|
| **String Hunter** | `core/string_hunter.py` | Multi-encoding regex: Plaintext, Base64 (ASCII & UTF-16LE PowerShell), Hex, ROT13, Single-byte XOR (0x01-0xFF), Repeating XOR (2-4 bytes), WordPerfect Macro XOR. Format flag: `HackToday26{}`, `HackToday25{}`, `HackToday{}`, `flag{}`, `FLAG{}`, `CTF{}`, `ITToday{}`. |
| **Magic Carver** | `core/magic_carver.py` | Database 70+ signature. Deteksi format mismatch, ekstraksi EOF overlay (JPEG, PNG, GIF, ZIP, PDF), carving archive aman, dan perbaikan corrupted ZIP local headers (`PK\x03\x04`). |
| **PCAP Analyzer** | `core/pcap_analyzer.py` | Parser native Libpcap & PCAPNG. Reassembly stream TCP/UDP, pencarian kredensial plaintext, ekstraksi keystroke USB HID keyboard, timing interval stego, TCP 6-bit covert flags, dan eksfiltrasi DNS/ICMP. |
| **Peripheral Hunter** | `core/peripheral_hunter.py` | Rekonstruksi USB Mouse / Drawing tablet ke file vektor SVG. Decoding Caps Lock LED blink ke kode Morse dan teks. |
| **Memory Streamer** | `core/memory_streamer.py` | Streaming engine sliding-window 32MB untuk LiME dan Windows dump. Ekstraksi banner kernel Linux, riwayat bash, environment variables, dan visual inspection raw framebuffer bitmap. |
| **Database Inspector** | `core/db_inspector.py` | SQLite v3 parser: enumerasi tabel, pencarian kolom rahasia, ekstraksi riwayat browser & cookies, carving unallocated page slack, serta rekonstruksi diff edit history. |
| **ESP32 & IoT Inspector** | `core/esp32_inspector.py` | ESP32 Flash Memory & NVS Forensics (HackToday 'Durrr Intern'): parser tabel partisi ESP-IDF (magic `\xaa\x50`), NVS extraction, filter decoy flag, 0x80 XOR key recovery, continuous keystream SHA-256 counter mode decryptor, serta carving slack space Base64. |
| **System Inspector** | `core/system_inspector.py` | Triage Windows Event Log (`.evtx`) Event ID 4104/4688/1102, decode Base64 PowerShell `-EncodedCommand`. Parser USN Journal `$J` multi-part file synthesis (HackToday 'Alice in DFIRland'), Registry `RunMRU`, Scheduled Tasks XML, Linux `input_event` keylogger struct, KAPE triage, dan NTFS `$MFT` resident data carving. |
| **Disk Inspector** | `core/disk_inspector.py` | Decoding data GPT partition GUID (bzip2/gzip/zlib/ASCII85), rekonstruksi missing disk RAID 5 via streaming XOR, deteksi VMDK sparse & snapshot APFS, parser Recycle Bin `$I` / `$R`, LNK, dan Prefetch. |
| **Signals & Stego** | `core/signal_engine.py` | Decoder audio DTMF tone (Goertzel murni Python), parser radio Flipper Zero `.sub`, carving komentar & toolpath 3D printing G-code. |
| **Stego Engine** | `core/stego_engine.py` | Audit chunk PNG, auto-repair tinggi gambar via CRC brute-force, bitplane extraction LSB 0-2, RGB parity, JPEG DQT LSB table markers, dan PNG PLTE slack. |
| **Exif Inspector** | `core/exif_inspector.py` | Ekstraksi metadata gambar (JPEG/PNG/TIFF/WEBP), PDF metadata, OpenXML tags, dan koordinat GPS. |
| **Triage Heuristics** | `core/triage.py` | Perhitungan Shannon entropy data, deteksi anomali struktur, dan penyusunan rekomendasi tahapan analisis berbasis pattern soal CTF. |
| **Reporter** | `core/reporter.py` | Visualisasi terminal, banner alert instan saat flag ditemukan, serta ekspor laporan `report.json` dan `report.md`. |

---

## 📊 Hasil Output

Semua hasil scan tersimpan di folder `results/out_<filename>_<timestamp>/`:
- `report.md`: Ringkasan temuan dan flag untuk writeup.
- `report.json`: Data terstruktur lengkap hasil parsing.
- `extracted_artifacts/`: File-file yang berhasil di-carve atau diekstrak.
- `usb_drawing.svg`: File vektor gambar jika ditemukan traffic mouse drawing.

---

## 🧪 Verifikasi Pengujian & Trainer Benchmark

### 1. Battery Test (Unit Tests)
Jalankan battery test untuk memastikan seluruh engine berfungsi normal:
```bash
python -m unittest discover tests
```
Semua 37 unit test mencakup seluruh skenario penanganan format file, steganografi, network, triage KAPE/USN Journal, WordPress IR kill-chain memory analysis, ESP32 IoT flash dump, dan ekstraksi memori RAM.

### 2. PCAP Benchmark & Trainer (10 Skenario CTF Nyata)
Simulasi dan benchmark otomatis 10 soal network forensics dari HackToday, IPB, PicoCTF, dan kompetisi nasional:
```bash
python trainer_pcap.py
```
Mencakup pengujian otomatis:
- USB HID Keyboard Keystroke injection
- PicoCTF UDP Port Delta steganography (*shark on wire 2*)
- ICMP Echo data tunneling
- DNS Subdomain Base64 exfiltration
- HTTP POST multipart file upload (*shark on wire 1*)
- HTTP Response Gzip compressed body carving
- FTP plaintext credentials & FTP-DATA transfer
- Packet Inter-Arrival Timing stego (EHAX 2026)
- TCP 6-bit flags covert channel
- VoIP RTP audio stream payload

