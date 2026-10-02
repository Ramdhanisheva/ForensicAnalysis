#!/usr/bin/env python3
"""
foren.py - CTF Forensics Automated Diagnostic & Solver
Mendeteksi tipe soal forensik secara otomatis dan langsung menjalankan
pemeriksaan spesifik serta pencarian flag tanpa konfigurasi rumit.

Penggunaan:
    python foren.py <nama_file_soal>
    python foren.py <nama_file_soal> --no-stop
"""

import argparse
import datetime
import os
import sys
import time
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

# Tambahkan direktori root ke sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Pastikan console Windows aman dengan UTF-8
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import config
from core.ad1_parser import AD1Parser
from core.archive_unpacker import ArchiveUnpacker
from core.db_inspector import DBInspector
from core.disk_inspector import DiskInspector
from core.exif_inspector import ExifInspector
from core.magic_carver import MagicCarver
from core.memory_streamer import MemoryStreamer
from core.pcap_analyzer import PcapAnalyzer
from core.pdf_inspector import PDFInspector
from core.peripheral_hunter import PeripheralHunter
from core.reporter import Reporter
from core.signal_engine import SignalEngine
from core.stego_engine import StegoEngine
from core.string_hunter import StringHunter
from core.system_inspector import SystemInspector
from core.triage import Triage


def run_forensic_solver(filepath: str, stop_on_flag: bool = True, output_base: Optional[str] = None, delime: bool = False) -> Dict[str, Any]:
    """Jalankan deteksi tipe soal dan eksekusi analisa forensik terarah."""
    file_path = os.path.abspath(filepath)
    if not os.path.exists(file_path):
        print(f"\033[1;31m[-] File tidak ditemukan: {filepath}\033[0m")
        return {}

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    start_time = time.time()

    # Tentukan direktori output artefak:
    # Jika user secara spesifik memberikan argumen -o / --output, gunakan folder tersebut secara langsung.
    if output_base and output_base != "results":
        target_out_dir = os.path.abspath(output_base)
    else:
        target_out_dir = os.path.join(output_base or "results", f"out_{file_name}_{int(datetime.datetime.now().timestamp())}")

    # Generate folder otomatis jika belum ada
    os.makedirs(target_out_dir, exist_ok=True)

    reporter = Reporter(target_out_dir)

    print(f"\n\033[1;36m[*] Analysis Foren: \033[1;33m{file_name}\033[0m ({file_size:,} bytes)\033[0m\n")

    # Inisialisasi engine
    string_hunter = StringHunter()
    magic_carver = MagicCarver(target_out_dir)
    exif_inspector = ExifInspector(target_out_dir)
    stego_engine = StegoEngine(target_out_dir)
    pcap_analyzer = PcapAnalyzer(target_out_dir)
    ad1_parser = AD1Parser(target_out_dir)
    memory_streamer = MemoryStreamer()
    db_inspector = DBInspector(target_out_dir)
    system_inspector = SystemInspector(target_out_dir)
    archive_unpacker = ArchiveUnpacker(target_out_dir)
    disk_inspector = DiskInspector(target_out_dir)
    signal_engine = SignalEngine(target_out_dir)
    peripheral_hunter = PeripheralHunter(target_out_dir)
    pdf_inspector = PDFInspector(target_out_dir)

    all_discovered_flags: List[Dict[str, str]] = []
    seen_flag_strings = set()
    stop_signal = [False]

    def on_instant_flag(flag_info: Dict[str, str], source_label: str = ""):
        flag_str = flag_info.get("flag", "")
        if flag_str and flag_str not in seen_flag_strings:
            seen_flag_strings.add(flag_str)
            method = f"[{source_label}] {flag_info.get('encoding', '')}" if source_label else flag_info.get("encoding", "")
            flag_info["encoding"] = method
            all_discovered_flags.append(flag_info)
            reporter.print_instant_bingo(flag_str, method)
            if stop_on_flag:
                stop_signal[0] = True

    # Baca sampel header awal
    # Untuk file sangat besar (memory dump), cukup baca header untuk deteksi format
    is_memory_dump = (
        file_path.lower().endswith((".lime", ".dmp", ".vmem", ".raw", ".mem"))
        or file_size > 200 * 1024 * 1024
    )
    header_read_size = 4 * 1024 * 1024 if is_memory_dump else min(file_size, 16 * 1024 * 1024)
    try:
        with open(file_path, "rb") as f:
            header_sample = f.read(header_read_size)
    except Exception as e:
        print(f"\033[1;31m[-] Gagal membaca file: {e}\033[0m")
    is_lime_file = (
        file_path.lower().endswith(".lime")
        or header_sample.startswith((b"EMiL", b"LiME"))
        or delime
    )

    # =========================================================================
    # TAHAP 1: DETEKSI TIPE SOAL & ANOMALI STRUKTUR
    # =========================================================================
    print("\033[1;35m--- [ Tahap 1: Deteksi Tipe Soal & Struktur File ] ---\033[0m")
    fmt_info = magic_carver.identify_format(header_sample, file_path)
    primary = fmt_info["primary"]
    primary_ext = primary.get("ext", "bin")
    entropy = Triage.calculate_entropy(header_sample[:65536])

    # Kategori soal
    actual_ext = Path(file_path).suffix.lower().lstrip(".")
    detected_cat = "General Binary / Unknown"
    name = primary.get("name", "Unknown")

    if primary_ext in ("pcap", "pcapng") or actual_ext in ("pcap", "pcapng", "cap") or "PCAP" in name:
        detected_cat = "Network / Packet Capture (PCAP/PCAPNG)"
    elif primary_ext in ("lime", "dmp", "vmem") or actual_ext in ("lime", "dmp", "vmem", "mem") or "Memory" in name or header_sample.startswith((b"EMiL", b"LiME")):
        detected_cat = "RAM Memory Dump (LiME / Minidump)"
    elif primary_ext in ("png", "jpg", "jpeg", "bmp", "gif") or actual_ext in ("png", "jpg", "jpeg", "bmp", "gif", "webp") or "Image" in name or b"IHDR" in header_sample[:64]:
        detected_cat = "Citra Digital / Steganografi Gambar"
    elif primary_ext == "svg" or actual_ext == "svg" or header_sample.lstrip().startswith(b"<svg") or b"<svg" in header_sample[:512]:
        detected_cat = "Citra Vektor SVG / XML Steganografi"
    elif primary_ext == "pdf" or actual_ext == "pdf" or header_sample.startswith(b"%PDF-"):
        detected_cat = "Dokumen PDF / Redaction & Stream Forensics"
    elif primary_ext in ("pptx", "docx", "xlsx") or actual_ext in ("pptx", "docx", "xlsx"):
        detected_cat = "Dokumen Office OpenXML (PPTX/DOCX/XLSX)"
    elif primary_ext in ("wav", "mp3", "flac") or actual_ext in ("wav", "mp3", "flac") or "Audio" in name:
        detected_cat = "Audio / Steganografi Sinyal Suara"
    elif primary_ext in ("sqlite", "db", "sqlite3") or actual_ext in ("sqlite", "db", "sqlite3") or "SQLite" in name:
        detected_cat = "Database Forensics (SQLite v3)"
    elif primary_ext in ("evtx", "log") or actual_ext in ("evtx", "log") or "Event Log" in name:
        detected_cat = "Log Sistem (Windows Event Log / Syslog)"
    elif actual_ext in ("eml", "msg") or b"From:" in header_sample[:1024] or b"Subject:" in header_sample[:1024]:
        detected_cat = "Email Forensics & Phishing Investigation"
    elif actual_ext == "lnk" or header_sample.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        detected_cat = "Windows Shortcut LNK Forensics"
    elif actual_ext == "mft" or "$mft" in file_name.lower() or b"FILE0" in header_sample[:2048]:
        detected_cat = "NTFS Master File Table ($MFT) Forensics"
    elif primary_ext in ("ad1", "e01", "vmdk", "vdi", "raw", "img", "vhdx", "vhd") or actual_ext in ("ad1", "e01", "vmdk", "vdi", "raw", "img", "vhdx", "vhd"):
        detected_cat = "Disk Image / Evidence Container"
    elif primary_ext in ("7z", "zip", "tar", "gz", "bz2", "xz", "rar") or actual_ext in ("7z", "zip", "tar", "gz", "bz2", "xz", "rar"):
        detected_cat = "Arsip Terkompresi (Archive Container)"
    elif primary_ext in ("g", "bgcode", "gcode") or actual_ext in ("g", "bgcode", "gcode") or header_sample.startswith(b"GCDE"):
        detected_cat = "3D Printing & G-Code Forensics"

    # Check ESP32 flash dump signature (magic 0xAA 0xE5 at offset 0x8000)
    is_esp32 = False
    try:
        if os.path.exists(file_path) and os.path.getsize(file_path) >= 0x8020:
            with open(file_path, "rb") as f_chk:
                f_chk.seek(0x8000)
                if f_chk.read(2) == b"\xaa\xe5":
                    is_esp32 = True
    except Exception:
        pass

    if is_esp32 or "esp32" in file_path.lower() or "flash_dump" in file_path.lower():
        detected_cat = "IoT / ESP32 Flash Memory & Firmware Forensics"

    if detected_cat == "General Binary / Unknown":
        print(f" [-] Kategori Soal Terdeteksi: \033[1;33m{detected_cat}\033[0m (Header tidak spesifik, fallback adaptif aktif)")
    else:
        print(f" [+] Kategori Soal Terdeteksi: \033[1;32m{detected_cat}\033[0m")
    print(f" [*] Format Biner:             {name} (Ekstensi Standar: .{primary_ext})")
    print(f" [*] Shannon Entropy:          {entropy:.3f} / 8.0")

    if fmt_info.get("mismatch_warning"):
        print(f" \033[1;33m[!] ANOMALI EKSTENSI: {fmt_info['mismatch_warning']}\033[0m")

    # =========================================================================
    # TAHAP 2: DEEP STRING HUNTING CEPAT (Plaintext, B64, Hex, XOR, ROT13)
    # =========================================================================
    print("\n\033[1;35m--- [ Tahap 2: Pemindaian String & Multi-Encoding Grep ] ---\033[0m")
    direct_flags = string_hunter.hunt_flags(
        header_sample,
        early_stop=stop_on_flag,
        on_flag_found=lambda fl: on_instant_flag(fl, "String Scan")
    )
    for fl in direct_flags:
        if fl.get("flag") not in seen_flag_strings:
            on_instant_flag(fl, "String Scan")
    if not direct_flags:
        print(" [-] Tidak ada flag langsung pada sampel header (buffer awal).")

    # Cek indikator teks mencurigakan
    sus_patterns = string_hunter.hunt_suspicious_patterns(header_sample, limit_per_type=2)
    if sus_patterns:
        print(" [+] Pola mencurigakan terdeteksi dalam data:")
        for k, vals in sus_patterns.items():
            print(f"     \033[1;33m{k}:\033[0m {vals[0]}")

    if stop_signal[0]:
        print("\n\033[1;32m[*] Flag ditemukan pada fase awal! Menyelesaikan sisa pemeriksaan cepat...\033[0m")

    task_results: Dict[str, Any] = {
        "pcap": None, "mem": None, "ad1": None, "stego": None,
        "db": None, "sys": None, "archive": None, "disk": None,
        "signal": None, "overlay": None, "carved": [], "exif": None
    }

    # Inisialisasi pool candidate passwords / keys
    candidate_passwords = set(["", "admin", "password", "infected", "hacktoday", "HackToday", "HackToday26", "123456", "root", "flag"])
    base_no_ext = os.path.splitext(file_name)[0]
    if 3 <= len(base_no_ext) <= 40:
        candidate_passwords.add(base_no_ext)

    # =========================================================================
    # TAHAP 3: METADATA EXIF & PANEN KUNCI PASSPHRASE
    # =========================================================================
    if not stop_signal[0]:
        print("\n\033[1;35m--- [ Tahap 3: Metadata EXIF & Panen Kunci Passphrase ] ---\033[0m")
        exif_res = exif_inspector.inspect(file_path, header_sample)
        if exif_res.get("extracted_thumbnails"):
            for th in exif_res["extracted_thumbnails"]:
                print(f" [+] EXIF Thumbnail/Preview Diekstrak: \033[1;36m{os.path.basename(th['path'])}\033[0m ({th['size']:,} bytes)")
        if exif_res.get("decrypted_comments"):
            for dc in exif_res["decrypted_comments"]:
                print(f" [+] EXIF Tag Deobfuscated (\033[1;33m{dc['method']}\033[0m): \033[1;32m{dc['value'][:80]}\033[0m")
        if exif_res.get("candidate_keys"):
            for ck in exif_res["candidate_keys"]:
                candidate_passwords.add(ck)
                print(f" [+] Candidate Key dari EXIF/Metadata: \033[1;33m{ck}\033[0m")
        if exif_res.get("flags_found"):
            for fl in exif_res["flags_found"]:
                on_instant_flag(fl, "EXIF Metadata")
        if exif_res.get("comments"):
            for cm in exif_res["comments"]:
                for fl in string_hunter.hunt_flags(cm):
                    on_instant_flag(fl, "Exif Comment")
        if not exif_res.get("candidate_keys") and not exif_res.get("flags_found") and not exif_res.get("comments") and not exif_res.get("extracted_thumbnails"):
            print(" [-] Metadata EXIF standar kosong / tidak ditemukan info sensitif.")
        task_results["exif"] = exif_res

    # =========================================================================
    # TAHAP 4: UJI COBA STEGHIDE & STEGO QUICK UNLOCK
    # =========================================================================
    if not stop_signal[0] and ("Citra" in detected_cat or primary_ext in ("jpg", "jpeg", "bmp", "png", "wav")):
        print("\n\033[1;35m--- [ Tahap 4: Uji Coba Steghide & Stego Quick Unlock ] ---\033[0m")
        if primary_ext in ("jpg", "jpeg", "bmp", "wav") and stego_engine.has_steghide:
            print(f" [*] Mencoba ekstraksi Steghide dengan {len(candidate_passwords)} candidate keys...")
            steg_res = stego_engine.try_steghide(file_path, candidate_passwords=list(candidate_passwords))
            if steg_res and steg_res.get("success"):
                print(f" \033[1;42;37m[!] STEGHIDE BERHASIL DI-UNLOCK!\033[0m Key: \033[1;32m'{steg_res['passphrase']}'\033[0m")
                print(f"     -> Ekstraksi: {steg_res['output_file']} ({steg_res['size']} bytes)")
                for fl in steg_res.get("flags", []):
                    on_instant_flag(fl, f"Steghide ({steg_res['passphrase']})")

        # Cek cepat IHDR CRC dan bitplane LSB
        s_res = stego_engine.audit_image_steganography(file_path)
        task_results["stego"] = s_res
        for fl in s_res.get("flags_found", []):
            on_instant_flag(fl, "Stego Engine")
        if s_res.get("anomalies"):
            for an in s_res["anomalies"]:
                print(f" [+] Anomali Gambar: {an}")
        if not all_discovered_flags:
            print(" [-] Stego quick unlock / LSB awal belum menemukan flag.")

    # =========================================================================
    # TAHAP 5: FILE CARVING & REKURSIF EKSTRAKSI ARTEFAK (Carver / Binwalk)
    # =========================================================================
    if not stop_signal[0]:
        print("\n\033[1;35m--- [ Tahap 5: File Carving & Rekursif Ekstraksi Artefak ] ---\033[0m")
        overlay_info = magic_carver.check_eof_overlay(header_sample, primary)
        if overlay_info:
            overlay_path = os.path.join(target_out_dir, f"{file_name}_overlay.bin")
            try:
                with open(overlay_path, "wb") as of:
                    of.write(overlay_info["full_overlay"])
            except Exception:
                pass
            for fl in string_hunter.hunt_flags(overlay_info["full_overlay"]):
                on_instant_flag(fl, "EOF Overlay")
            task_results["overlay"] = overlay_info
            print(f" [+] Ditemukan Trailing Data (EOF Overlay): {len(overlay_info['full_overlay']):,} bytes")

        # Binwalk extraction jika tersedia di sistem
        if shutil.which("binwalk"):
            binwalk_dir = os.path.join(target_out_dir, "binwalk_extracted")
            try:
                subprocess.run(["binwalk", "-e", "-C", binwalk_dir, file_path], capture_output=True, timeout=5)
                if os.path.exists(binwalk_dir):
                    for root, _, bfiles in os.walk(binwalk_dir):
                        for bf in bfiles:
                            bf_p = os.path.join(root, bf)
                            try:
                                with open(bf_p, "rb") as bff:
                                    bdata = bff.read(10 * 1024 * 1024)
                                    for fl in string_hunter.hunt_flags(bdata):
                                        on_instant_flag(fl, f"Binwalk ({bf})")
                            except Exception:
                                pass
            except Exception:
                pass

        # Native MagicCarver (70+ signatures) - Skip on valid archive containers to avoid carving deflated noise
        carved = []
        if primary_ext not in ("zip", "7z", "tar", "gz", "bz2", "xz", "rar"):
            carved = magic_carver.carve_embedded_files(header_sample, file_name, candidate_passwords=list(candidate_passwords))
        if carved:
            task_results["carved"] = carved
            print(f" [+] File tertanam berhasil diekstrak (Carved): {len(carved)} file")
            for c in carved:
                c_path = c["path"]
                c_type = c.get("type", "").upper()
                for fl in c.get("flags_found", []):
                    on_instant_flag(fl, f"Carved {c_type} Embedded")
                try:
                    with open(c_path, "rb") as cf:
                        c_data = cf.read()

                    # A. Deep String Scan pada setiap file carved (first 256KB)
                    for fl in string_hunter.hunt_flags(c_data[:256 * 1024]):
                        on_instant_flag(fl, f"Carved {c_type}")

                    # B. Rekursif EXIF & Steghide jika file carved adalah gambar
                    if c_type in ("PNG", "JPG", "JPEG", "BMP"):
                        c_exif = exif_inspector.inspect(c_path, c_data)
                        if c_exif.get("candidate_keys"):
                            for ck in c_exif["candidate_keys"]:
                                candidate_passwords.add(ck)
                        if c_exif.get("flags_found"):
                            for fl in c_exif["flags_found"]:
                                on_instant_flag(fl, f"Carved {c_type} EXIF")

                        if stego_engine.has_steghide:
                            steg_c = stego_engine.try_steghide(c_path, candidate_passwords=list(candidate_passwords))
                            if steg_c and steg_c.get("success"):
                                for fl in steg_c.get("flags", []):
                                    on_instant_flag(fl, f"Carved {c_type} Steghide ({steg_c['passphrase']})")

                        if c_type == "PNG":
                            png_res = stego_engine.analyze_png(c_data)
                            for fl in png_res.get("extracted_flags", []):
                                on_instant_flag(fl, "Carved PNG Chunks")
                        elif c_type in ("JPG", "JPEG"):
                            dqt_res = stego_engine.analyze_jpeg_dqt(c_data)
                            for fl in dqt_res.get("extracted_flags", []):
                                on_instant_flag(fl, "Carved JPEG DQT")

                    # C. Rekursif Auto-Unpack jika file carved adalah arsip
                    elif c_type in ("ZIP", "7Z", "TAR", "GZ"):
                        unp_sub = os.path.join(target_out_dir, f"unpacked_carved_{os.path.basename(c_path)}")
                        u_res = archive_unpacker.unpack(c_path, unp_sub, candidate_passwords=list(candidate_passwords))
                        if u_res.get("success"):
                            for ef in u_res.get("extracted_files", []):
                                try:
                                    with open(ef["path"], "rb") as eff:
                                        edata = eff.read(10 * 1024 * 1024)
                                        for fl in string_hunter.hunt_flags(edata):
                                            on_instant_flag(fl, f"Carved Archive ({ef['filename']})")
                                except Exception:
                                    pass
                except Exception:
                    pass

        if not overlay_info and not carved and b"PK\x03\x04" not in header_sample:
            print(" [-] Tidak ditemukan file tertanam (carved) atau trailing EOF overlay.")

        # Cek corrupted local ZIP header PK\x03\x04
        if b"PK\x03\x04" in header_sample:
            corrupted_zips = magic_carver.carve_corrupted_zip_entries(header_sample, file_name)
            for cz in corrupted_zips:
                cz_payload = cz.get("payload", b"")
                if cz.get("name", "").lower().endswith("mft") or b"FILE0" in cz_payload[:2048]:
                    m_res = disk_inspector.parse_mft_records(cz_payload)
                    for fl in m_res.get("flags_found", []):
                        on_instant_flag(fl, f"Carved MFT ({cz['name']})")
                else:
                    for fl in string_hunter.hunt_flags(cz_payload[:2 * 1024 * 1024]):
                        on_instant_flag(fl, f"Corrupted ZIP ({cz['name']})")

    # =========================================================================
    # TAHAP 6: ANALISA SPESIFIK SESUAI KATEGORI SOAL & ADAPTIVE FALLBACK
    # =========================================================================
    if not stop_signal[0] or is_lime_file:
        print("\n\033[1;35m--- [ Tahap 6: Analisa Spesifik Sesuai Kategori Soal & Adaptive Fallback ] ---\033[0m")

        executed_modules = set()

        def _deep_triage_artifact(art_path: str, art_name: str, depth: int = 0):
            if depth > 4 or not os.path.exists(art_path) or stop_signal[0]:
                return
            art_ext = Path(art_path).suffix.lower().lstrip(".")
            try:
                file_sz = os.path.getsize(art_path)
                with open(art_path, "rb") as af:
                    header_data = af.read(min(file_sz, 2 * 1024 * 1024))
            except Exception:
                return

            # 1. EML Phishing
            if art_ext in ("eml", "msg") or b"From:" in header_data[:1024] or b"Subject:" in header_data[:1024]:
                em_r = disk_inspector.parse_eml_file(art_path)
                for fl in em_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted EML ({art_name})")
                for att in em_r.get("attachments", []):
                    _deep_triage_artifact(att["path"], att["filename"], depth + 1)
                return

            # 2. LNK Shortcut
            if art_ext == "lnk" or header_data.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
                lnk_r = disk_inspector.parse_lnk_file(art_path)
                for field in ("local_path", "relative_path", "command_args", "arguments"):
                    val = lnk_r.get(field, "")
                    if val:
                        for fl in string_hunter.hunt_flags(val):
                            on_instant_flag(fl, f"Extracted LNK ({art_name})")
                for fl in lnk_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted LNK ({art_name})")
                return

            # 3. NTFS MFT
            if art_ext == "mft" or "$mft" in art_name.lower() or b"FILE0" in header_data[:2048] or b"FILE*" in header_data[:2048]:
                mft_r = disk_inspector.parse_mft_records(art_path)
                for fl in mft_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted MFT ({art_name})")
                return

            # 4. Nested Archive
            if art_ext in ("zip", "7z", "tar", "gz", "bz2", "xz", "rar") or header_data.startswith((b"PK\x03\x04", b"7z\xbc\xaf")):
                sub_unp = os.path.join(target_out_dir, f"nested_{depth}_{art_name}")
                sub_a = archive_unpacker.unpack(art_path, sub_unp, candidate_passwords=list(candidate_passwords))
                if sub_a.get("success"):
                    for sf in sub_a.get("extracted_files", []):
                        _deep_triage_artifact(sf["path"], sf.get("filename", ""), depth + 1)
                return

            # 5. Citra / Gambar
            if art_ext in ("png", "jpg", "jpeg", "bmp", "gif", "webp") or b"IHDR" in header_data[:64]:
                s_r = stego_engine.audit_image_steganography(art_path)
                for fl in s_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted Image ({art_name})")
                return

            # 6. Memory Dump
            if art_ext in ("lime", "dmp", "vmem") or header_data.startswith((b"EMiL", b"LiME")):
                m_r = memory_streamer.scan_memory_dump(art_path, on_flag_found=lambda fl: on_instant_flag(fl, f"Extracted Memory ({art_name})"), early_stop=stop_on_flag)
                for fl in m_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted Memory ({art_name})")
                return

            # 7. PCAP
            if art_ext in ("pcap", "pcapng") or header_data.startswith((b"\xd4\xc3\xb2\xa1", b"\n\r\r\n")):
                p_r = pcap_analyzer.analyze_pcap(art_path)
                for fl in p_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted PCAP ({art_name})")
                if p_r.get("trevorc2_traffic"):
                    candidate_passwords.add("lobsterwashere")
                return

            # 8. EVTX
            if art_ext == "evtx" or header_data.startswith(b"ElfFile\x00"):
                ev_r = system_inspector.analyze_evtx_or_logs(art_path)
                for fl in ev_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted EVTX ({art_name})")
                return

            # 9. PDF & SVG
            if art_ext == "pdf" or header_data.startswith(b"%PDF"):
                pd_r = pdf_inspector.inspect(art_path, candidate_passwords=list(candidate_passwords))
                for fl in pd_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted PDF ({art_name})")
                return
            if art_ext == "svg":
                sv_r = stego_engine.analyze_svg(art_path)
                for fl in sv_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted SVG ({art_name})")
                return

            # 10. AccessData AD1 Logical Image
            if art_ext == "ad1" or header_data.startswith(b"ADSEGMENTED"):
                cand_b = [p.encode() if isinstance(p, str) else p for p in candidate_passwords] + [b"lobsterwashere"]
                ad_r = ad1_parser.parse(art_path, candidate_keys=cand_b)
                for fl in ad_r.get("flags_found", []):
                    on_instant_flag(fl, f"Extracted AD1 ({art_name})")
                return

            # Generic Fallback: String hunter on first 2MB
            for fl in string_hunter.hunt_flags(header_data):
                on_instant_flag(fl, f"Extracted ({art_name})")

        # Modul Forensik Individual
        def run_module_network():
            print(" [*] [Modul PCAP] Menjalankan modul analisis jaringan (PCAP)...")
            try:
                p_res = pcap_analyzer.analyze_pcap(file_path)
                task_results["pcap"] = p_res
                for fl in p_res.get("flags_found", []):
                    on_instant_flag(fl, "PCAP")
                if p_res.get("usb_hid_keystrokes"):
                    print(f" [+] Keystroke USB HID Keyboard Reconstructed: \033[1;32m{p_res['usb_hid_keystrokes']}\033[0m")
                    for fl in string_hunter.hunt_flags(p_res["usb_hid_keystrokes"]):
                        on_instant_flag(fl, "USB Keystroke")
                if p_res.get("usb_mouse_drawing"):
                    print(f" [+] USB Mouse Drawing tersimpan: \033[1;36m{p_res['usb_mouse_drawing']}\033[0m")
                if p_res.get("credentials"):
                    print(f" [+] Kredensial Plaintext ditemukan: {len(p_res['credentials'])} entri")
                if p_res.get("timing_stego"):
                    print(f" [+] Timing Interval Stego: {p_res['timing_stego']}")
                if p_res.get("tcp_flags_covert"):
                    print(f" [+] TCP 6-bit Covert Channel: {p_res['tcp_flags_covert']}")
                if p_res.get("trevorc2_traffic"):
                    candidate_passwords.add("lobsterwashere")
                if not task_results.get("pcap", {}).get("flags_found") and not all_discovered_flags:
                    print(" [-] [Modul PCAP] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul PCAP] Terjadi kendala: {e}")

        def run_module_memory():
            print(" [*] [Modul Memory] Menjalankan modul streaming memori RAM (Zero-OOM, sliding-window 32MB)...")
            try:
                # B0: LiME Header & Physical Memory Range Triage
                if header_sample.startswith((b"EMiL", b"LiME")) or file_path.lower().endswith(".lime"):
                    lime_ranges = memory_streamer.parse_lime_headers(file_path)
                    if lime_ranges:
                        total_ram_mb = sum(r["size_mb"] for r in lime_ranges)
                        print(f" [+] Format LiME Terverifikasi: {len(lime_ranges)} Rentang Memori Fisik ({total_ram_mb:,.1f} MB Total)")
                        for lr in lime_ranges[:5]:
                            print(f"     - Range #{lr['index']}: {lr['start_addr']} s/d {lr['end_addr']} ({lr['size_mb']} MB)")
                        if len(lime_ranges) > 5:
                            print(f"     ... ({len(lime_ranges) - 5} rentang memori fisik lainnya)")

                        if delime or file_path.lower().endswith(".lime") or header_sample.startswith((b"EMiL", b"LiME")):
                            raw_out_path = os.path.join(target_out_dir, f"{os.path.splitext(file_name)[0]}.raw")
                            if not os.path.exists(raw_out_path) or os.path.getsize(raw_out_path) == 0:
                                print(f" [*] Auto De-LiME: Mengonversi format LiME ke Flat Physical RAM .raw...")
                                conv_res = memory_streamer.convert_lime_to_raw(file_path, raw_out_path)
                                if conv_res.get("success"):
                                    print(f" [+] Sukses De-LiME: {conv_res['total_bytes_written']:,} bytes tersimpan di {raw_out_path}")
                                    task_results["delime_raw"] = raw_out_path

                # B1: WSL strings + grep (fast, bounded to 20s)
                wsl_distros = ["kali-linux", "Ubuntu", "Debian"]
                _wsl_done = False
                for distro in wsl_distros:
                    try:
                        wsl_path = file_path.replace("\\", "/")
                        drive = wsl_path[0].lower()
                        wsl_path = f"/mnt/{drive}" + wsl_path[2:]
                        grep_pats = "|".join([
                            "HackToday26{", "HackToday25{", "HackToday{", "hacktoday{",
                            "picoCTF{", "PicoCTF{", "flag{", "FLAG{", "CTF{", "COMPFEST{",
                            "ITToday{", "CJ{"
                        ])
                        cmd = ["wsl", "-d", distro, "bash", "-c",
                               f"strings -n 6 '{wsl_path}' | grep -aEi '({grep_pats})' | head -200"]
                        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                        if proc.returncode == 0 and proc.stdout.strip():
                            print(f" \033[1;42;37m[!] WSL strings+grep menemukan hasil!\033[0m")
                            for line in proc.stdout.strip().splitlines():
                                line = line.strip()
                                if line:
                                    print(f"     \033[1;32m>> {line}\033[0m")
                                    for fl in string_hunter.hunt_flags(line):
                                        on_instant_flag(fl, "WSL strings grep")
                            _wsl_done = True
                            break
                    except Exception:
                        pass

                # B2: Python Streaming Engine
                m_res = memory_streamer.scan_memory_dump(
                    file_path,
                    max_bytes=None,
                    on_flag_found=lambda fl: on_instant_flag(fl, "Memory Stream"),
                    early_stop=stop_on_flag
                )
                task_results["mem"] = m_res

                for fl in m_res.get("flags_found", []):
                    on_instant_flag(fl, "Memory Stream")

                if m_res.get("kernel_banner"):
                    kb = m_res["kernel_banner"]
                    print(f" [+] Kernel Banner: \033[1;36m{kb[:100]}\033[0m")
                    m_kver = __import__("re").search(r"(\d+\.\d+\.\d+)", kb)
                    if m_kver:
                        print(f" [*] Kernel Version: \033[1;33m{m_kver.group(1)}\033[0m")

                if m_res.get("bash_commands"):
                    cmds = m_res["bash_commands"]
                    print(f" [+] Riwayat Shell Bash ({len(cmds)} perintah ditemukan):")
                    for cmd in cmds[:5]:
                        print(f"     $ {cmd}")
                        for fl in string_hunter.hunt_flags(cmd):
                            on_instant_flag(fl, "Bash History")

                if m_res.get("extracted_passwords"):
                    print(f" [+] Kunci/Password dalam RAM ({len(m_res['extracted_passwords'])}):")
                    for pw in m_res["extracted_passwords"][:5]:
                        print(f"     -> \033[1;32m'{pw}'\033[0m")
                        candidate_passwords.add(pw)

                # Fallback framebuffer
                if not all_discovered_flags:
                    fb_res = memory_streamer.scan_raw_framebuffer(file_path, output_dir=target_out_dir)
                    if fb_res.get("saved_images"):
                        print(f" [+] Raw Framebuffers Carved ({len(fb_res['saved_images'])} BMP desktop screenshots)")

                # Volatility auto-run (bounded to 25s)
                if memory_streamer.has_vol and m_res.get("kernel_banner") and not stop_signal[0]:
                    for vol_cmd_args in [
                        ["vol", "-f", file_path, "linux.bash"],
                        ["vol", "-f", file_path, "linux.pslist"],
                    ]:
                        try:
                            vp = subprocess.run(vol_cmd_args, capture_output=True, text=True, timeout=25)
                            if vp.stdout:
                                for line in vp.stdout.splitlines():
                                    for fl in string_hunter.hunt_flags(line):
                                        on_instant_flag(fl, f"Volatility ({vol_cmd_args[2]})")
                        except Exception:
                            pass
                if not all_discovered_flags:
                    print(" [-] [Modul Memory] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Memory] Terjadi kendala: {e}")

        def run_module_esp32():
            print(" [*] [Modul ESP32] Menjalankan modul forensik ESP32 Flash Memory & NVS...")
            try:
                from core.esp32_inspector import ESP32Inspector
                esp_inspector = ESP32Inspector(output_dir=target_out_dir)
                esp_res = esp_inspector.inspect_flash_dump(file_path)
                task_results["esp32"] = esp_res
                for fl in esp_res.get("flags_found", []):
                    on_instant_flag(fl, "ESP32 Firmware Forensics")
                if not all_discovered_flags:
                    print(" [-] [Modul ESP32] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul ESP32] Terjadi kendala: {e}")

        def run_module_stego():
            print(" [*] [Modul Citra/Stego] Menjalankan audit steganografi gambar...")
            try:
                s_res = stego_engine.audit_image_steganography(file_path)
                task_results["stego"] = s_res
                for fl in s_res.get("flags_found", []):
                    on_instant_flag(fl, "Stego")
                if s_res.get("anomalies"):
                    for an in s_res["anomalies"]:
                        print(f" [+] Anomali Gambar: {an}")
                if not all_discovered_flags:
                    print(" [-] [Modul Citra/Stego] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Citra/Stego] Terjadi kendala: {e}")

        def run_module_svg():
            print(" [*] [Modul SVG] Menjalankan modul forensik SVG (<tspan>/<text> inspection)...")
            try:
                svg_res = stego_engine.analyze_svg(file_path)
                task_results["svg"] = svg_res
                for fl in svg_res.get("flags_found", []):
                    on_instant_flag(fl, "SVG Inspector")
                if svg_res.get("extracted_text"):
                    print(f" [+] Teks <tspan> terkumpul: \033[1;32m{svg_res['extracted_text'][:80]}\033[0m")
                if not all_discovered_flags:
                    print(" [-] [Modul SVG] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul SVG] Terjadi kendala: {e}")

        def run_module_pdf():
            print(" [*] [Modul PDF] Menjalankan inspeksi PDF (Streams, Redaction & Passwords)...")
            try:
                pdf_res = pdf_inspector.inspect(file_path, candidate_passwords=list(candidate_passwords))
                task_results["pdf"] = pdf_res
                for fl in pdf_res.get("flags_found", []):
                    on_instant_flag(fl, "PDF Inspector")
                if pdf_res.get("streams_decompressed"):
                    print(f" [+] Stream FlateDecode berhasil didekompresi: {pdf_res['streams_decompressed']}")
                if not all_discovered_flags:
                    print(" [-] [Modul PDF] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul PDF] Terjadi kendala: {e}")

        def run_module_office():
            print(" [*] [Modul Office] Menjalankan modul inspeksi Office OpenXML...")
            try:
                doc_res = stego_engine.analyze_office_document(file_path)
                task_results["office"] = doc_res
                for fl in doc_res.get("flags_found", []):
                    on_instant_flag(fl, "Office XML")
                if not all_discovered_flags:
                    print(" [-] [Modul Office] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Office] Terjadi kendala: {e}")

        def run_module_audio():
            print(" [*] [Modul Audio/Sinyal] Menjalankan modul sinyal audio & telemetri...")
            try:
                sig_res = signal_engine.inspect_audio_signals(file_path)
                task_results["signal"] = sig_res
                for fl in sig_res.get("flags_found", []):
                    on_instant_flag(fl, "Signal/Audio")
                if sig_res.get("dtmf_digits"):
                    print(f" [+] Nada Telepon DTMF Terdeteksi: \033[1;32m{sig_res['dtmf_digits']}\033[0m")
                if not all_discovered_flags:
                    print(" [-] [Modul Audio/Sinyal] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Audio/Sinyal] Terjadi kendala: {e}")

        def run_module_db():
            print(" [*] [Modul Database] Menjalankan modul deep SQLite forensics...")
            try:
                d_res = db_inspector.inspect_database(file_path)
                task_results["db"] = d_res
                for fl in d_res.get("flags_found", []):
                    on_instant_flag(fl, "Database")
                if not all_discovered_flags:
                    print(" [-] [Modul Database] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Database] Terjadi kendala: {e}")

        def run_module_sys():
            print(" [*] [Modul Log/EVTX] Menjalankan modul audit log sistem (EVTX)...")
            try:
                sys_res = system_inspector.inspect_evtx(file_path)
                task_results["sys"] = sys_res
                for fl in sys_res.get("flags_found", []):
                    on_instant_flag(fl, "EVTX Log")
                if not all_discovered_flags:
                    print(" [-] [Modul Log/EVTX] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Log/EVTX] Terjadi kendala: {e}")

        def run_module_eml():
            print(" [*] [Modul Email] Menjalankan modul forensik email (.eml / phishing triage)...")
            try:
                eml_res = disk_inspector.parse_eml_file(file_path)
                task_results["eml"] = eml_res
                for fl in eml_res.get("flags_found", []):
                    on_instant_flag(fl, "Email EML")
                for att in eml_res.get("attachments", []):
                    print(f" [+] Lampiran Email Tersimpan: {att['filename']} ({att['size']} bytes)")
                    _deep_triage_artifact(att["path"], att["filename"], depth=0)
                if not all_discovered_flags:
                    print(" [-] [Modul Email] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Email] Terjadi kendala: {e}")

        def run_module_lnk():
            print(" [*] [Modul LNK] Menjalankan modul analisis Windows LNK Shortcut...")
            try:
                lnk_res = disk_inspector.parse_lnk_file(file_path)
                task_results["lnk"] = lnk_res
                for fl in lnk_res.get("flags_found", []):
                    on_instant_flag(fl, "LNK Shortcut")
                for field in ("local_path", "relative_path", "command_args", "arguments"):
                    val = lnk_res.get(field, "")
                    if val:
                        for fl in string_hunter.hunt_flags(val):
                            on_instant_flag(fl, "LNK Shortcut")
                if not all_discovered_flags:
                    print(" [-] [Modul LNK] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul LNK] Terjadi kendala: {e}")

        def run_module_mft():
            print(" [*] [Modul MFT] Menjalankan modul analisis NTFS Master File Table ($MFT)...")
            try:
                mft_res = disk_inspector.parse_mft_records(file_path)
                task_results["mft"] = mft_res
                for fl in mft_res.get("flags_found", []):
                    on_instant_flag(fl, "MFT Record")
                if not all_discovered_flags:
                    print(" [-] [Modul MFT] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul MFT] Terjadi kendala: {e}")

        def run_module_disk():
            print(" [*] [Modul Disk/AD1] Menjalankan modul disk artifacts & partitions...")
            try:
                if primary_ext == "ad1" or header_sample.startswith(b"ADSEGMENTED"):
                    cand_b = [p.encode() if isinstance(p, str) else p for p in candidate_passwords] + [b"lobsterwashere"]
                    ad_res = ad1_parser.parse(file_path, candidate_keys=cand_b)
                    task_results["ad1"] = ad_res
                    for fl in ad_res.get("flags_found", []):
                        on_instant_flag(fl, "AD1")
                else:
                    disk_res = disk_inspector.inspect_disk_artifacts(file_path)
                    task_results["disk"] = disk_res
                    for fl in disk_res.get("flags_found", []):
                        on_instant_flag(fl, "Disk")
                if not all_discovered_flags:
                    print(" [-] [Modul Disk/AD1] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Disk/AD1] Terjadi kendala: {e}")

        def run_module_archive():
            print(" [*] [Modul Arsip] Mengekstrak arsip terkompresi & recursive triage...")
            try:
                unpacked_dir = os.path.join(target_out_dir, "unpacked")
                arch_res = archive_unpacker.unpack(file_path, unpacked_dir, candidate_passwords=list(candidate_passwords))
                task_results["archive"] = arch_res
                if arch_res.get("success"):
                    ext_files = arch_res.get("extracted_files", [])
                    print(f" [OK] Berhasil mengekstrak {len(ext_files)} file.")
                    ext_files_sorted = sorted(ext_files, key=lambda ef: 0 if ef.get("filename", "").lower().endswith((".pcap", ".pcapng")) else 1)
                    for ef in ext_files_sorted:
                        _deep_triage_artifact(ef["path"], ef.get("filename", ""), depth=0)
                else:
                    print(f" [-] [Modul Arsip] Tidak dapat mengekstrak arsip: {arch_res.get('error', 'format tidak cocok')}")
            except Exception as e:
                print(f" [-] [Modul Arsip] Terjadi kendala: {e}")

        def run_module_deep_strings():
            print(" [*] [Modul Deep Strings] Menjalankan pemindaian multi-encoding mendalam...")
            try:
                read_sz = min(file_size, 32 * 1024 * 1024)
                with open(file_path, "rb") as f_deep:
                    deep_data = f_deep.read(read_sz)
                deep_flags = string_hunter.hunt_flags(
                    deep_data,
                    early_stop=stop_on_flag,
                    on_flag_found=lambda fl: on_instant_flag(fl, "Deep String Scan")
                )
                for fl in deep_flags:
                    on_instant_flag(fl, "Deep String Scan")
                if not all_discovered_flags:
                    print(" [-] [Modul Deep Strings] Selesai (Belum menemukan flag).")
            except Exception as e:
                print(f" [-] [Modul Deep Strings] Terjadi kendala: {e}")

        module_map = {
            "NETWORK": run_module_network,
            "MEMORY": run_module_memory,
            "ESP32": run_module_esp32,
            "IMAGE": run_module_stego,
            "SVG": run_module_svg,
            "PDF": run_module_pdf,
            "OFFICE": run_module_office,
            "AUDIO": run_module_audio,
            "DATABASE": run_module_db,
            "LOG": run_module_sys,
            "EMAIL": run_module_eml,
            "LNK": run_module_lnk,
            "MFT": run_module_mft,
            "DISK": run_module_disk,
            "ARCHIVE": run_module_archive,
            "DEEP_STRINGS": run_module_deep_strings
        }

        # 1. Tentukan Modul Target Utama Berdasarkan Deteksi Tahap 1
        primary_module = None
        if "Network" in detected_cat:
            primary_module = "NETWORK"
        elif "Memory" in detected_cat or (file_size > 100 * 1024 * 1024 and not primary_ext in ("ad1", "e01", "vmdk")):
            primary_module = "MEMORY"
        elif "ESP32" in detected_cat:
            primary_module = "ESP32"
        elif "Citra Digital" in detected_cat:
            primary_module = "IMAGE"
        elif "SVG" in detected_cat or primary_ext == "svg":
            primary_module = "SVG"
        elif "PDF" in detected_cat or primary_ext == "pdf":
            primary_module = "PDF"
        elif "Office" in detected_cat or primary_ext in ("pptx", "docx", "xlsx"):
            primary_module = "OFFICE"
        elif "Audio" in detected_cat or "3D" in detected_cat:
            primary_module = "AUDIO"
        elif "Database" in detected_cat:
            primary_module = "DATABASE"
        elif "Log" in detected_cat:
            primary_module = "LOG"
        elif "Email" in detected_cat:
            primary_module = "EMAIL"
        elif "LNK" in detected_cat:
            primary_module = "LNK"
        elif "MFT" in detected_cat:
            primary_module = "MFT"
        elif "Disk" in detected_cat or primary_ext == "ad1":
            primary_module = "DISK"
        elif "Arsip" in detected_cat:
            primary_module = "ARCHIVE"

        # Eksekusi modul utama jika ada
        if primary_module and primary_module in module_map:
            print(f" [+] Menjalankan modul target utama: \033[1;36m{primary_module}\033[0m")
            executed_modules.add(primary_module)
            module_map[primary_module]()

        # 2. ADAPTIVE FALLBACK ENGINE
        # Jika belum ada flag, atau jika modul utama tidak menghasilkan flag
        if not stop_signal[0] and not all_discovered_flags:
            print("\n\033[1;33m[*] [Adaptive Fallback Engine] Flag belum terdeteksi. Menganalisis karakteristik biner & mencoba tahap alternatif non-konflik...\033[0m")

            fallback_order = []

            # Prioritas A: Cek apakah file bisa diekstrak sebagai arsip (ZIP / 7z / TAR)
            if "ARCHIVE" not in executed_modules:
                if (
                    b"PK\x03\x04" in header_sample
                    or b"7z\xbc\xaf" in header_sample
                    or header_sample.startswith((b"PK", b"7z", b"\x1f\x8b", b"BZh"))
                    or primary_ext in ("zip", "7z", "tar", "gz", "bz2", "xz", "rar")
                ):
                    fallback_order.append("ARCHIVE")

            # Prioritas B: Cek PDF
            if "PDF" not in executed_modules:
                if b"%PDF" in header_sample[:65536]:
                    fallback_order.append("PDF")

            # Prioritas C: Cek Steganografi Citra (PNG / JPG / BMP)
            if "IMAGE" not in executed_modules:
                if (
                    b"IHDR" in header_sample[:64]
                    or header_sample.startswith((b"\x89PNG", b"\xff\xd8\xff", b"BM"))
                    or primary_ext in ("png", "jpg", "jpeg", "bmp", "gif", "webp")
                ):
                    fallback_order.append("IMAGE")

            # Prioritas D: Cek Network PCAP
            if "NETWORK" not in executed_modules:
                if (
                    header_sample.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"))
                    or primary_ext in ("pcap", "pcapng", "cap")
                ):
                    fallback_order.append("NETWORK")

            # Prioritas E: Cek Disk Image / AD1 / MFT
            if "DISK" not in executed_modules:
                if (
                    header_sample.startswith(b"ADSEGMENTED")
                    or primary_ext in ("ad1", "img", "raw", "vmdk", "e01")
                ):
                    fallback_order.append("DISK")

            if "MFT" not in executed_modules:
                if b"FILE0" in header_sample[:2048] or b"FILE*" in header_sample[:2048]:
                    fallback_order.append("MFT")

            # Prioritas F: Cek Memory Dump jika ukuran file cukup besar (> 5MB)
            if "MEMORY" not in executed_modules:
                if (
                    header_sample.startswith((b"EMiL", b"LiME"))
                    or (file_size > 8 * 1024 * 1024 and not primary_ext in ("ad1", "e01", "vmdk", "pcap", "pcapng"))
                ):
                    fallback_order.append("MEMORY")

            # Prioritas G: Cek LNK Shortcut
            if "LNK" not in executed_modules:
                if header_sample.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
                    fallback_order.append("LNK")

            # Prioritas H: Cek Email
            if "EMAIL" not in executed_modules:
                if b"From:" in header_sample[:1024] or b"Subject:" in header_sample[:1024]:
                    fallback_order.append("EMAIL")

            # Prioritas I: Cek SQLite Database
            if "DATABASE" not in executed_modules:
                if header_sample.startswith(b"SQLite format 3"):
                    fallback_order.append("DATABASE")

            # Prioritas J: Cek Log EVTX
            if "LOG" not in executed_modules:
                if header_sample.startswith(b"ElfFile\x00"):
                    fallback_order.append("LOG")

            # Jalankan fallback yang cocok dengan karakteristik biner
            for fb_mod in fallback_order:
                if stop_signal[0] or (all_discovered_flags and stop_on_flag):
                    break
                if fb_mod not in executed_modules:
                    print(f" [*] [Adaptive Fallback] Mencoba kandidat: \033[1;36m{fb_mod}\033[0m")
                    executed_modules.add(fb_mod)
                    module_map[fb_mod]()

            # Terakhir: Jika masih belum ada flag, coba ekstrak arsip universal & deep string scan
            if not stop_signal[0] and not all_discovered_flags:
                if "ARCHIVE" not in executed_modules:
                    print(" [*] [Adaptive Fallback] Mencoba universal archive extraction (7z/carver)...")
                    executed_modules.add("ARCHIVE")
                    run_module_archive()

            if not stop_signal[0] and not all_discovered_flags:
                if "DEEP_STRINGS" not in executed_modules:
                    executed_modules.add("DEEP_STRINGS")
                    run_module_deep_strings()

    # =========================================================================
    # TAHAP 7: KESIMPULAN TEMUAN & SOLVER PLAYBOOK
    # =========================================================================
    elapsed = time.time() - start_time
    print(f"\n\033[1;35m--- [ Tahap 7: Ringkasan Hasil Analisis (Selesai dalam {elapsed:.2f}s) ] ---\033[0m")

    if all_discovered_flags:
        print(f"\033[1;42;37m [!] TOTAL FLAG VALID BERHASIL DIDAPATKAN: {len(all_discovered_flags)} \033[0m")
        for idx, fl in enumerate(all_discovered_flags, 1):
            print(f"    \033[1;32m{idx}. {fl.get('flag')}\033[0m ({fl.get('encoding')})")
    else:
        print("\033[1;33m[-] Belum ada flag standar yang langsung cocok.\033[0m")
        reporter.print_diagnostic_next_steps(
            primary_ext=primary_ext,
            carved_count=len(task_results["carved"]),
            overlay_found=task_results["overlay"] is not None
        )

    # Heuristic Triage & Recommendations
    triage_assessment = Triage.generate_triage_assessment(
        filename=file_name,
        file_size=file_size,
        primary_format=primary,
        header_sample=header_sample,
        flags_found=all_discovered_flags,
        task_results=task_results
    )
    reporter.print_triage_advisory(triage_assessment)

    # Tampilkan daftar file hasil ekstraksi/artefak jika ada
    saved_artifacts = []
    if os.path.exists(target_out_dir):
        for r, _, fnames in os.walk(target_out_dir):
            for fn in fnames:
                if fn not in ("report.json", "report.md"):
                    fp = os.path.join(r, fn)
                    rel_p = os.path.relpath(fp, target_out_dir)
                    saved_artifacts.append((rel_p, os.path.getsize(fp)))

    if saved_artifacts:
        print(f" [*] Folder Output:   \033[1;34m{target_out_dir}\033[0m")
        print(f"\n \033[1;36m[+] File Ter-ekstrak ({len(saved_artifacts)} file tersimpan):\033[0m")
        for rel_name, sz in saved_artifacts[:15]:
            print(f"     -> \033[1;32m{rel_name}\033[0m ({sz:,} bytes)")
        if len(saved_artifacts) > 15:
            print(f"     ... ({len(saved_artifacts) - 15} file lainnya di folder output)")
    else:
        # Bersihkan folder jika tidak ada file yang diekstrak dan merupakan folder default
        if output_base is None or output_base == "results":
            try:
                os.rmdir(target_out_dir)
            except Exception:
                pass

    out_dir_abs = os.path.abspath(target_out_dir)
    if all_discovered_flags:
        print("\n" + "=" * 60)
        print("[+] Flag found:")
        for idx, fl in enumerate(all_discovered_flags, 1):
            print(f"    - {fl.get('flag')}")
            if fl.get('encoding'):
                print(f"      Method: {fl.get('encoding')}")
        print(f"\n[+] Output: {out_dir_abs}")
        print("=" * 60 + "\n")
    else:
        print("\n" + "-" * 60)
        print("[*] Analysis done.")
        print(f"[*] Output directory: {out_dir_abs}")
        if saved_artifacts:
            print(f"[*] Extracted artifacts: {len(saved_artifacts)} file(s)")
        print("-" * 60 + "\n")

    return {
        "target_file": file_path,
        "target_name": file_name,
        "all_flags": all_discovered_flags,
        "saved_artifacts": saved_artifacts,
        "target_out_dir": target_out_dir
    }


def synthesize_multi_target_summary(results: List[Dict[str, Any]], tool_name: str = "Tool Analysis Foren"):
    """
    Rangkuman cerdas untuk analisis jamak (multiple files / directory / glob).
    Menyusun tabel hasil, menganalisis kemungkinan flag multi-part / terpisah,
    dan memberikan kesimpulan akhir yang jelas.
    """
    if not results:
        return

    print("\n" + "=" * 70)
    print(f"[*] RANGKUMAN HASIL ANALISIS JAMAK (TOTAL: {len(results)} TARGET) - {tool_name}")
    print("=" * 70)

    all_flags_list = []
    seen_flags = set()
    partial_flags = []

    for idx, r in enumerate(results, 1):
        target_name = r.get("target_name") or os.path.basename(r.get("target_file", "unknown"))
        flags = r.get("all_flags", [])
        out_dir = r.get("target_out_dir", "N/A")
        artifacts = r.get("saved_artifacts", [])

        print(f"\n[{idx}] Target: {target_name}")
        if flags:
            print(f"    Status : FLAG FOUND ({len(flags)} flag)")
            for f_info in flags:
                f_val = f_info.get("flag", "")
                enc = f_info.get("encoding", "N/A")
                print(f"    -> Flag   : {f_val}")
                print(f"       Method : {enc}")
                if f_val not in seen_flags:
                    seen_flags.add(f_val)
                    all_flags_list.append((target_name, f_val, enc))
                    if "{" in f_val and not f_val.endswith("}"):
                        partial_flags.append((target_name, f_val, "prefix"))
                    elif "}" in f_val and "{" not in f_val:
                        partial_flags.append((target_name, f_val, "suffix"))
        else:
            print(f"    Status : MANUAL TRIAGE / SELESAI")
            if artifacts:
                print(f"    Hasil  : {len(artifacts)} file ter-ekstrak di folder output")
            else:
                print(f"    Hasil  : Tidak ada file biner tersembunyi terdeteksi langsung")
            print(f"    Output : {out_dir}")

    # Rekonstruksi Flag Multi-Part jika ada indikasi bagian terpisah
    reconstructed_flags = []
    prefixes = [p for p in partial_flags if p[2] == "prefix"]
    suffixes = [s for s in partial_flags if s[2] == "suffix"]
    if prefixes and suffixes:
        for p_target, p_val, _ in prefixes:
            for s_target, s_val, _ in suffixes:
                combined = p_val + s_val
                if combined not in seen_flags:
                    reconstructed_flags.append(combined)

    print("\n" + "-" * 70)
    print("[*] KESIMPULAN AKHIR:")
    if reconstructed_flags:
        print("\n [!] TERDETEKSI FLAG MULTI-PART (GABUNGAN DARI BERBAGAI FILE):")
        for rf in reconstructed_flags:
            print(f"     >>> {rf} <<<")

    if all_flags_list:
        print(f"\n [+] Total Flag Valid Ditemukan : {len(all_flags_list)}")
        for i, (src, fv, enc) in enumerate(all_flags_list, 1):
            print(f"     {i}. {fv} (Sumber: {src})")
    else:
        print("\n [-] Tidak ada flag yang ditemukan secara otomatis dari seluruh target.")
        print(" [*] Silakan periksa masing-masing folder output untuk analisis mendalam.")

    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        prog="foren",
        description="\033[1;36m[*] Analysis Foren - CTF Forensics Automated Diagnostic & Solver\033[0m",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\033[1;33mKEMAMPUAN ANALISIS TERCAKUP:\033[0m
  [1] PCAP / PCAPNG     : USB HID Keystroke & Mouse drawing, Creds, Timing/Covert, TLS
  [2] Steganografi Citra: PNG IHDR repair, JPG DQT LSB, Steghide, LSB Bitplanes, OCR
  [3] Dokumen & PDF     : PDF FlateDecode, Unmask Redactions, pdf2john + dictionary attack
  [4] RAM Memory Dumps  : Zero-OOM LiME parser, de-LiME, Bash history, Volatility 3
  [5] Disk & Partition  : AD1 Evidence Container, MFT Records, GPT, RAID5 XOR Recovery
  [6] Arsip Kompresi    : ZIP/7z/TAR/GZ recursive unpacking, password cracking
  [7] IoT & Firmware    : ESP32 Flash Memory & NVS XOR 0x80 recovery
  [8] System Logs & EML : EVTX PowerShell -EncodedCommand, EML phishing triage

\033[1;32mCONTOH PENGGUNAAN:\033[0m
  foren challenge.png
  foren chall_1.png chall_2.pcap chall_3.lime
  foren ./soal_ctf/* -o ./output_kolektif
  foren ./folder_soal/
  foren memory.lime
  foren dump.raw --no-stop
"""
    )
    parser.add_argument("targets", nargs="*", help="Path ke satu atau lebih file/folder/wildcard target soal forensik CTF")
    parser.add_argument("-o", "--output", "--outdir", dest="output", default=None,
                        help="Folder tujuan hasil analisa, gambar ter-ekstrak, PDF, dan artefak (dibuat otomatis jika belum ada)")
    parser.add_argument("--no-stop", dest="stop_on_flag", action="store_false", default=True,
                        help="Lakukan deep scan tuntas tanpa berhenti pada flag pertama")
    parser.add_argument("--delime", action="store_true",
                        help="Ekstrak / de-LiME format .lime menjadi raw physical RAM (.raw)")

    args = parser.parse_args()

    if not args.targets:
        parser.print_help()
        print("\n\033[1;33mContoh Cepat:\033[0m")
        print("  foren challenge.png")
        print("  foren chall_1.png chall_2.png")
        print("  foren ./folder_soal/")
        print("  foren memory.lime\n")
        sys.exit(0)

    import glob

    # 1. Expand globs / wildcards
    expanded_targets = []
    for arg_t in args.targets:
        if any(c in arg_t for c in ("*", "?", "[", "]")):
            matches = glob.glob(arg_t)
            if matches:
                expanded_targets.extend(matches)
            else:
                expanded_targets.append(arg_t)
        else:
            expanded_targets.append(arg_t)

    # 2. Collect files from targets and directories
    files_to_analyze = []
    for t in expanded_targets:
        t_abs = os.path.abspath(t)
        if not os.path.exists(t_abs):
            print(f"\033[1;31m[-] Target '{t}' tidak ditemukan.\033[0m", file=sys.stderr)
            continue
        if os.path.isdir(t_abs):
            print(f"[*] Direktori terdeteksi: Memindai semua berkas dalam '{t_abs}'...")
            for root, _, files in os.walk(t_abs):
                for f in sorted(files):
                    fp = os.path.join(root, f)
                    if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                        files_to_analyze.append(fp)
        else:
            files_to_analyze.append(t_abs)

    # Deduplicate while preserving order
    unique_files = []
    seen = set()
    for f in files_to_analyze:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    if not unique_files:
        print("[-] Tidak ada berkas valid untuk dianalisis.")
        sys.exit(1)

    all_results = []
    for idx, f_target in enumerate(unique_files, 1):
        if len(unique_files) > 1:
            print(f"\n\033[1;34m{'=' * 65}\033[0m")
            print(f"\033[1;34m[*] MEMPROSES TARGET [{idx}/{len(unique_files)}]: {os.path.basename(f_target)}\033[0m")
            print(f"\033[1;34m{'=' * 65}\033[0m")

        sub_out = os.path.join(args.output, f"out_{os.path.basename(f_target)}") if (args.output and len(unique_files) > 1) else args.output
        res = run_forensic_solver(f_target, stop_on_flag=args.stop_on_flag, output_base=sub_out, delime=args.delime)
        if res:
            res["target_name"] = os.path.basename(f_target)
            res["target_out_dir"] = sub_out or res.get("target_out_dir", "N/A")
            all_results.append(res)

    if len(all_results) > 1:
        synthesize_multi_target_summary(all_results, tool_name="Tool Analysis Foren")


if __name__ == "__main__":
    main()
