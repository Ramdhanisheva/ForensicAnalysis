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
from core.peripheral_hunter import PeripheralHunter
from core.reporter import Reporter
from core.signal_engine import SignalEngine
from core.stego_engine import StegoEngine
from core.string_hunter import StringHunter
from core.system_inspector import SystemInspector
from core.triage import Triage


def run_forensic_solver(filepath: str, stop_on_flag: bool = True, output_base: str = "results") -> Dict[str, Any]:
    """Jalankan deteksi tipe soal dan eksekusi analisa forensik terarah."""
    file_path = os.path.abspath(filepath)
    if not os.path.exists(file_path):
        print(f"\033[1;31m[-] File tidak ditemukan: {filepath}\033[0m")
        return {}

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    start_time = time.time()

    target_out_dir = os.path.join(output_base, f"out_{file_name}_{int(datetime.datetime.now().timestamp())}")
    os.makedirs(target_out_dir, exist_ok=True)

    reporter = Reporter(target_out_dir)

    print("\n" + "\033[1;36m" + "=" * 70 + "\033[0m")
    print("\033[1;32m [*] DIGITAL FORENSIC ANALYSIS & TRIAGE\033[0m")
    print(f"\033[1;33m Target: {file_name}\033[0m ({file_size:,} bytes)")
    print("\033[1;36m" + "=" * 70 + "\033[0m\n")

    # Inisialisasi engine
    string_hunter = StringHunter()
    magic_carver = MagicCarver(target_out_dir)
    exif_inspector = ExifInspector()
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
        return {}

    # =========================================================================
    # TAHAP 1: DETEKSI TIPE SOAL & ANOMALI STRUKTUR
    # =========================================================================
    print("\033[1;35m--- [ Tahap 1: Deteksi Tipe Soal & Struktur File ] ---\033[0m")
    fmt_info = magic_carver.identify_format(header_sample, file_path)
    primary = fmt_info["primary"]
    primary_ext = primary.get("ext", "bin")
    entropy = Triage.calculate_entropy(header_sample[:65536])

    # Kategori soal
    detected_cat = "General Binary / Unknown"
    name = primary.get("name", "Unknown")

    if primary_ext in ("pcap", "pcapng") or "PCAP" in name:
        detected_cat = "Network / Packet Capture (PCAP/PCAPNG)"
    elif primary_ext in ("lime", "dmp", "vmem") or "Memory" in name:
        detected_cat = "RAM Memory Dump (LiME / Minidump)"
    elif primary_ext in ("png", "jpg", "jpeg", "bmp", "gif") or "Image" in name:
        detected_cat = "Citra Digital / Steganografi Gambar"
    elif primary_ext == "svg" or header_sample.lstrip().startswith(b"<svg") or b"<svg" in header_sample[:512]:
        detected_cat = "Citra Vektor SVG / XML Steganografi"
    elif primary_ext == "pdf" or header_sample.startswith(b"%PDF-"):
        detected_cat = "Dokumen PDF / Redaction & Stream Forensics"
    elif primary_ext in ("pptx", "docx", "xlsx"):
        detected_cat = "Dokumen Office OpenXML (PPTX/DOCX/XLSX)"
    elif primary_ext in ("wav", "mp3", "flac") or "Audio" in name:
        detected_cat = "Audio / Steganografi Sinyal Suara"
    elif primary_ext in ("sqlite", "db", "sqlite3") or "SQLite" in name:
        detected_cat = "Database Forensics (SQLite v3)"
    elif primary_ext in ("evtx", "log") or "Event Log" in name:
        detected_cat = "Log Sistem (Windows Event Log / Syslog)"
    elif primary_ext in ("ad1", "e01", "vmdk", "vdi", "raw", "img"):
        detected_cat = "Disk Image / Evidence Container"
    elif primary_ext in ("7z", "zip", "tar", "gz", "bz2", "xz", "rar"):
        detected_cat = "Arsip Terkompresi (Archive Container)"
    elif primary_ext in ("g", "bgcode", "gcode") or header_sample.startswith(b"GCDE"):
        detected_cat = "3D Printing & G-Code Forensics"

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

        # Native MagicCarver (70+ signatures)
        carved = magic_carver.carve_embedded_files(header_sample, file_name)
        if carved:
            task_results["carved"] = carved
            print(f" [+] File tertanam berhasil diekstrak (Carved): {len(carved)} file")
            for c in carved:
                c_path = c["path"]
                c_type = c.get("type", "").upper()
                try:
                    with open(c_path, "rb") as cf:
                        c_data = cf.read()

                    # A. Deep String Scan pada setiap file carved
                    for fl in string_hunter.hunt_flags(c_data):
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

        # Cek corrupted local ZIP header PK\x03\x04
        if b"PK\x03\x04" in header_sample:
            corrupted_zips = magic_carver.carve_corrupted_zip_entries(header_sample, file_name)
            for cz in corrupted_zips:
                for fl in string_hunter.hunt_flags(cz.get("payload", b"")):
                    on_instant_flag(fl, f"Corrupted ZIP ({cz['name']})")

    # =========================================================================
    # TAHAP 6: ANALISA SPESIFIK SESUAI KATEGORI SOAL
    # =========================================================================
    if not stop_signal[0]:
        print("\n\033[1;35m--- [ Tahap 6: Analisa Spesifik Sesuai Kategori Soal ] ---\033[0m")
        # A. NETWORK / PCAP
        if "Network" in detected_cat:
            print(" [*] Menjalankan modul analisis jaringan (PCAP)...")
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

        # B. MEMORY DUMP
        elif "Memory" in detected_cat or file_size > 100 * 1024 * 1024:
            print(" [*] Menjalankan modul streaming memori RAM (Zero-OOM, sliding-window 32MB)...")

            # --- Step B1: WSL strings + grep (paling cepat temukan flag) ---
            wsl_distros = ["kali-linux", "Ubuntu", "Debian"]
            _wsl_done = False
            for distro in wsl_distros:
                try:
                    wsl_path = file_path.replace("\\", "/")
                    drive = wsl_path[0].lower()
                    wsl_path = f"/mnt/{drive}" + wsl_path[2:]
                    # Build grep pattern from all flag prefixes
                    grep_pats = "|".join([
                        "HackToday26{", "HackToday25{", "HackToday{", "hacktoday{",
                        "picoCTF{", "PicoCTF{", "flag{", "FLAG{", "CTF{", "COMPFEST{",
                        "ITToday{", "CJ{"
                    ])
                    cmd = ["wsl", "-d", distro, "bash", "-c",
                           f"strings -n 6 '{wsl_path}' | grep -aEi '({grep_pats})' | head -200"]
                    print(f" [*] WSL strings|grep via {distro}...")
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
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
                    elif proc.stderr:
                        pass  # distro tidak ada / wsl error, coba distro berikutnya
                except Exception:
                    pass

            if not _wsl_done:
                print(" [*] WSL strings tidak tersedia, langsung ke Python streaming engine...")

            # --- Step B2: Python Streaming Engine (full file scan) ---
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
                # Kernel version for Volatility symbol table
                m_kver = __import__("re").search(r"(\d+\.\d+\.\d+)", kb)
                if m_kver:
                    print(f" [*] Kernel Version: \033[1;33m{m_kver.group(1)}\033[0m")

            if m_res.get("bash_commands"):
                cmds = m_res["bash_commands"]
                print(f" [+] \033[1;33mRiwayat Shell Bash ({len(cmds)} perintah ditemukan):\033[0m")
                for cmd in cmds[:10]:
                    print(f"     $ {cmd}")
                    for fl in string_hunter.hunt_flags(cmd):
                        on_instant_flag(fl, "Bash History")

            if m_res.get("env_vars"):
                print(f" [+] \033[1;33mEnvironment Variables ({len(m_res['env_vars'])} ditemukan):\033[0m")
                for ev in m_res["env_vars"][:10]:
                    print(f"     {ev}")
                    for fl in string_hunter.hunt_flags(ev):
                        on_instant_flag(fl, "Env Variable")

            if m_res.get("ssh_keys"):
                print(f" \033[1;31m[!] SSH Private Key ditemukan di memori: {len(m_res['ssh_keys'])} kunci!\033[0m")
                for ki, k in enumerate(m_res["ssh_keys"][:3], 1):
                    print(f"     Key #{ki}: {k[:60]}...")

            if m_res.get("scripts_found"):
                print(f" [+] Script in-memory ditemukan: {len(m_res['scripts_found'])}")
                for sc in m_res["scripts_found"][:3]:
                    print(f"     {sc[:80]}")
                    for fl in string_hunter.hunt_flags(sc):
                        on_instant_flag(fl, "In-Memory Script")

            if m_res.get("extracted_passwords"):
                print(f" [+] \033[1;32mKunci/Password ditemukan dalam command RAM ({len(m_res['extracted_passwords'])}):\033[0m")
                for pw in m_res["extracted_passwords"]:
                    print(f"     -> \033[1;32m'{pw}'\033[0m")
                    candidate_passwords.add(pw)

            if m_res.get("reverse_shells"):
                print(f" \033[1;31m[!] Reverse Shell / C2 Sockets terdeteksi ({len(m_res['reverse_shells'])}):\033[0m")
                for rs in m_res["reverse_shells"][:5]:
                    print(f"     -> {rs}")

            if m_res.get("http_requests"):
                print(f" [+] HTTP / JWT Buffers di RAM ({len(m_res['http_requests'])}):")
                for hr in m_res["http_requests"][:5]:
                    print(f"     -> {hr[:100]}")

            if m_res.get("carved_elfs"):
                print(f" [+] In-Memory ELF Binaries Carved ({len(m_res['carved_elfs'])}):")
                for ce in m_res["carved_elfs"][:5]:
                    print(f"     -> Offset {ce['offset']}: {ce['type']} ({ce['class']})")

            if m_res.get("ntlm_hashes"):
                print(f" [+] NTLM Hashes di RAM ({len(m_res['ntlm_hashes'])}):")
                for nh in m_res["ntlm_hashes"][:5]:
                    print(f"     -> {nh}")

            # Fallback jika belum ada flag: visual framebuffer inspection
            if not all_discovered_flags:
                fb_res = memory_streamer.scan_raw_framebuffer(file_path, output_dir=target_out_dir)
                if fb_res.get("saved_images"):
                    print(f" [+] Raw Framebuffers Carved ({len(fb_res['saved_images'])} BMP desktop screenshots tersimpan)")
                    for img in fb_res["saved_images"][:3]:
                        print(f"     -> {img}")

            # --- Step B3: Tampilkan Volatility recommendations ---
            if m_res.get("volatility_recommendations"):
                print(f"\n \033[1;36m[*] Volatility 3 — Command yang disarankan:\033[0m")
                for vc in m_res["volatility_recommendations"]:
                    print(f"     {vc}")

            # --- Step B4: Auto-run Volatility jika tersedia ---
            if memory_streamer.has_vol and m_res.get("kernel_banner") and not stop_signal[0]:
                print("\n [*] Mencoba Volatility 3 pslist & bash history otomatis...")
                for vol_cmd_args in [
                    ["vol", "-f", file_path, "linux.bash"],
                    ["vol", "-f", file_path, "linux.pslist"],
                    ["vol", "-f", file_path, "linux.filescan"],
                ]:
                    try:
                        vp = subprocess.run(vol_cmd_args, capture_output=True, text=True, timeout=120)
                        if vp.stdout:
                            for line in vp.stdout.splitlines():
                                for fl in string_hunter.hunt_flags(line):
                                    on_instant_flag(fl, f"Volatility ({vol_cmd_args[2]})")
                            # Print first few lines
                            lines_out = [l for l in vp.stdout.splitlines() if l.strip()]
                            if lines_out:
                                print(f" [+] {vol_cmd_args[2]} output ({len(lines_out)} baris):")
                                for ln in lines_out[:8]:
                                    print(f"     {ln}")
                    except Exception:
                        pass


        # C. CITRA / STEGANOGRAFI
        elif "Citra Digital" in detected_cat:
            print(" [*] Menjalankan modul audit steganografi gambar...")
            s_res = stego_engine.audit_image_steganography(file_path)
            task_results["stego"] = s_res
            for fl in s_res.get("flags_found", []):
                on_instant_flag(fl, "Stego")
            if s_res.get("anomalies"):
                for an in s_res["anomalies"]:
                    print(f" [+] Anomali Gambar: {an}")

        # D. CITRA VEKTOR SVG / XML
        elif "SVG" in detected_cat or primary_ext == "svg":
            print(" [*] Menjalankan modul forensik SVG (<tspan>/<text> inspection)...")
            svg_res = stego_engine.analyze_svg(file_path)
            task_results["svg"] = svg_res
            for fl in svg_res.get("flags_found", []):
                on_instant_flag(fl, "SVG Inspector")
            if svg_res.get("extracted_text"):
                print(f" [+] Teks <tspan> terkumpul: \033[1;32m{svg_res['extracted_text'][:80]}\033[0m")

        # E. DOKUMEN PDF
        elif "PDF" in detected_cat or primary_ext == "pdf":
            print(" [*] Menjalankan modul ekstraksi PDF (FlateDecode & Redaction unmasking)...")
            pdf_res = stego_engine.analyze_pdf(file_path)
            task_results["pdf"] = pdf_res
            for fl in pdf_res.get("flags_found", []):
                on_instant_flag(fl, "PDF Inspector")
            if pdf_res.get("streams_decompressed"):
                print(f" [+] Stream FlateDecode berhasil didekompresi: {pdf_res['streams_decompressed']}")

        # F. DOKUMEN OFFICE OPENXML
        elif "Office" in detected_cat or primary_ext in ("pptx", "docx", "xlsx"):
            print(" [*] Menjalankan modul inspeksi Office OpenXML...")
            doc_res = stego_engine.analyze_office_document(file_path)
            task_results["office"] = doc_res
            for fl in doc_res.get("flags_found", []):
                on_instant_flag(fl, "Office XML")
            if doc_res.get("hidden_entries"):
                print(f" [+] Entri dokumen tersembunyi: {doc_res['hidden_entries']}")

        # G. AUDIO / SINYAL
        elif "Audio" in detected_cat or "3D" in detected_cat:
            print(" [*] Menjalankan modul sinyal audio & telemetri...")
            sig_res = signal_engine.inspect_audio_signals(file_path)
            task_results["signal"] = sig_res
            for fl in sig_res.get("flags_found", []):
                on_instant_flag(fl, "Signal/Audio")
            if sig_res.get("dtmf_digits"):
                print(f" [+] Nada Telepon DTMF Terdeteksi: \033[1;32m{sig_res['dtmf_digits']}\033[0m")

        # H. DATABASE SQLITE
        elif "Database" in detected_cat:
            print(" [*] Menjalankan modul deep SQLite forensics...")
            d_res = db_inspector.inspect_database(file_path)
            task_results["db"] = d_res
            for fl in d_res.get("flags_found", []):
                on_instant_flag(fl, "Database")
            if d_res.get("tables"):
                print(f" [+] Tabel SQLite: {', '.join(d_res['tables'][:8])}")

        # I. LOG SISTEM / EVTX
        elif "Log" in detected_cat:
            print(" [*] Menjalankan modul audit log sistem (EVTX)...")
            sys_res = system_inspector.inspect_evtx(file_path)
            task_results["sys"] = sys_res
            for fl in sys_res.get("flags_found", []):
                on_instant_flag(fl, "EVTX Log")
            if sys_res.get("decoded_commands"):
                print(f" [+] PowerShell -EncodedCommand Decoded: {len(sys_res['decoded_commands'])} perintah")

        # J. DISK & PARTISI
        elif "Disk" in detected_cat or primary_ext == "ad1":
            print(" [*] Menjalankan modul disk artifacts & partitions...")
            if primary_ext == "ad1":
                ad_res = ad1_parser.parse_ad1(file_path)
                task_results["ad1"] = ad_res
                for fl in ad_res.get("flags_found", []):
                    on_instant_flag(fl, "AD1")
            else:
                disk_res = disk_inspector.inspect_disk_artifacts(file_path)
                task_results["disk"] = disk_res
                for fl in disk_res.get("flags_found", []):
                    on_instant_flag(fl, "Disk")

        # K. ARSIP TERKOMPRESI (DENGAN DEEP REKURSIF PADA ARTEFAK TERKESTRAK)
        elif "Arsip" in detected_cat:
            print(" [*] Mengekstrak arsip terkompresi...")
            unpacked_dir = os.path.join(target_out_dir, "unpacked")
            arch_res = archive_unpacker.unpack(file_path, unpacked_dir, candidate_passwords=list(candidate_passwords))
            task_results["archive"] = arch_res
            if arch_res.get("success"):
                ext_files = arch_res.get("extracted_files", [])
                print(f" [OK] Berhasil mengekstrak {len(ext_files)} file.")
                for ef in ext_files:
                    ef_path = ef["path"]
                    ef_name = ef.get("filename", "")
                    ef_ext = Path(ef_path).suffix.lower().lstrip(".")
                    try:
                        with open(ef_path, "rb") as ef_f:
                            ef_data = ef_f.read(16 * 1024 * 1024)
                        for fl in string_hunter.hunt_flags(ef_data):
                            on_instant_flag(fl, f"Extracted ({ef_name})")

                        # Deep inspection for specialized extracted formats
                        if ef_ext in ("lime", "dmp", "vmem") or ef_data.startswith(b"EMiL"):
                            m_sub = memory_streamer.scan_memory_dump(ef_path, on_flag_found=lambda fl: on_instant_flag(fl, f"Extracted Memory ({ef_name})"), early_stop=stop_on_flag)
                            for fl in m_sub.get("flags_found", []):
                                on_instant_flag(fl, f"Extracted Memory ({ef_name})")
                        elif ef_ext == "evtx" or ef_data.startswith(b"ElfFile\x00"):
                            ev_sub = system_inspector.analyze_evtx_or_logs(ef_path)
                            for fl in ev_sub.get("flags_found", []):
                                on_instant_flag(fl, f"Extracted EVTX ({ef_name})")
                        elif ef_ext in ("pcap", "pcapng") or ef_data.startswith((b"\xd4\xc3\xb2\xa1", b"\n\r\r\n")):
                            p_sub = pcap_analyzer.analyze_pcap(ef_path)
                            for fl in p_sub.get("flags_found", []):
                                on_instant_flag(fl, f"Extracted PCAP ({ef_name})")
                        elif ef_ext in ("png", "jpg", "jpeg", "bmp"):
                            s_sub = stego_engine.audit_image_steganography(ef_path)
                            for fl in s_sub.get("flags_found", []):
                                on_instant_flag(fl, f"Extracted Image ({ef_name})")
                        elif ef_ext == "pdf":
                            pdf_sub = stego_engine.analyze_pdf(ef_path)
                            for fl in pdf_sub.get("flags_found", []):
                                on_instant_flag(fl, f"Extracted PDF ({ef_name})")
                        elif ef_ext == "svg":
                            svg_sub = stego_engine.analyze_svg(ef_path)
                            for fl in svg_sub.get("flags_found", []):
                                on_instant_flag(fl, f"Extracted SVG ({ef_name})")
                    except Exception:
                        pass

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

    # Simpan laporan
    report_payload = {
        "target_file": file_path,
        "file_size_bytes": file_size,
        "format_identification": fmt_info,
        "detected_category": detected_cat,
        "elapsed_seconds": round(elapsed, 2),
        "all_flags": all_discovered_flags,
        "triage_assessment": triage_assessment,
        "eof_overlay": task_results["overlay"] is not None,
        "carved_artifacts": task_results["carved"]
    }
    json_path, md_path = reporter.save_reports(report_payload)
    print(f" [*] Markdown Report: \033[1;34m{md_path}\033[0m")
    print(f" [*] Folder Artefak:  \033[1;34m{target_out_dir}\033[0m\n")

    return report_payload


def main():
    parser = argparse.ArgumentParser(
        description="foren.py - CTF Forensics Automated Diagnostic & Solver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh Pemakaian:
  python foren.py challenge.png
  python foren.py traffic.pcapng
  python foren.py memory.lime
  python foren.py dump.raw --no-stop
        """
    )
    parser.add_argument("target", nargs="?", help="Path ke file soal forensik CTF yang ingin dianalisis")
    parser.add_argument("--no-stop", dest="stop_on_flag", action="store_false", default=True, help="Lakukan deep scan tuntas tanpa berhenti pada flag pertama")
    parser.add_argument("--outdir", default="results", help="Folder output hasil analisis (default: results)")

    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        print("\n\033[1;33mContoh: python foren.py <nama_file_soal>\033[0m")
        sys.exit(1)

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"\033[1;31m[-] Target '{args.target}' tidak ditemukan.\033[0m", file=sys.stderr)
        sys.exit(1)

    if os.path.isdir(target_path):
        print(f"[*] Memindai seluruh folder: {target_path}")
        for root, _, files in os.walk(target_path):
            for file in files:
                p = os.path.join(root, file)
                run_forensic_solver(p, stop_on_flag=args.stop_on_flag, output_base=args.outdir)
    else:
        run_forensic_solver(target_path, stop_on_flag=args.stop_on_flag, output_base=args.outdir)


if __name__ == "__main__":
    main()
