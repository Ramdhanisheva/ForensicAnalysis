#!/usr/bin/env python3
"""
Forensics Solver - High-Speed Parallel Forensic Solver & Triage Suite
Tailored for HackToday Final IPB IT Today (2025/2026) & National CTF Competitions.

Architecture:
- Smart Routing: Only triggers relevant category engines based on probed magic bytes.
- Parallel Workers: Concurrently runs Metadata, Overlays/Carving, and Specialized Engines.
- Strict Timeouts: Prevents hanging or infinite loops on heavy files.
- Instant BINGO Alert: Immediately prints flag the millisecond it is found.
- Actionable Diagnostic: Provides concrete next-step recommendations if no flag is immediately visible.
"""

import argparse
import concurrent.futures
import datetime
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Safe UTF-8 reconfiguration for Windows console
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import config
from core.ad1_parser import AD1Parser
from core.triage import Triage
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


def scan_single_file(filepath: str, args, output_base: str) -> Dict[str, Any]:
    """Execute high-speed, parallel forensic triage on a target file."""
    start_time = time.time()
    file_path = os.path.abspath(filepath)
    if not os.path.exists(file_path):
        print(f"\033[1;31m[-] File not found: {filepath}\033[0m")
        return {}

    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    target_out_dir = os.path.join(output_base, f"out_{file_name}_{int(datetime.datetime.now().timestamp())}")
    os.makedirs(target_out_dir, exist_ok=True)

    reporter = Reporter(target_out_dir)
    reporter.print_terminal_banner(file_name)

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
    stop_flag_signal = [False]

    def on_instant_flag(flag_info: Dict[str, str], source_label: str = ""):
        flag_str = flag_info.get("flag", "")
        if flag_str and flag_str not in seen_flag_strings:
            seen_flag_strings.add(flag_str)
            method = f"[{source_label}] {flag_info.get('encoding', '')}" if source_label else flag_info.get('encoding', '')
            flag_info["encoding"] = method
            all_discovered_flags.append(flag_info)
            reporter.print_instant_bingo(flag_str, method)
            if args.stop_on_flag:
                stop_flag_signal[0] = True

    # Read header sample
    try:
        with open(file_path, "rb") as f:
            header_sample = f.read(min(file_size, 16 * 1024 * 1024))
    except Exception as e:
        print(f"\033[1;31m[-] Could not read file: {e}\033[0m")
        return {}

    # Stage 1: Fast Probe & Mismatch Detection
    reporter.print_section("Stage 1: Fast Probe & Signature Audit (< 0.05s)")
    fmt_info = magic_carver.identify_format(header_sample, file_path)
    primary = fmt_info["primary"]
    primary_ext = primary.get("ext", "bin")
    print(f" [*] Detected Type: \033[1;32m{primary['name']}\033[0m (Standard Ext: .{primary_ext})")
    print(f" [*] File Size:     {file_size:,} bytes")

    if fmt_info.get("mismatch_warning"):
        print(f"\033[1;33m [!] {fmt_info['mismatch_warning']}\033[0m")

    # Stage 2: Instant String & Multi-Encoding Grep
    reporter.print_section("Stage 2: Instant String Grep (Plaintext, B64, Hex)")
    direct_flags = string_hunter.hunt_flags(
        header_sample,
        early_stop=args.stop_on_flag,
        on_flag_found=lambda fl: on_instant_flag(fl, "Primary Sample")
    )
    for fl in direct_flags:
        if fl.get("flag") not in seen_flag_strings:
            on_instant_flag(fl, "Primary Sample")

    sus_patterns = string_hunter.hunt_suspicious_patterns(header_sample, limit_per_type=3)
    if sus_patterns:
        print(" [+] Indikator mencurigakan terdeteksi:")
        for k, vals in sus_patterns.items():
            print(f"     \033[1;33m{k}:\033[0m {vals[0]}")

    if stop_flag_signal[0]:
        print("\n\033[1;32m[*] Flag ditemukan pada fase awal! Menyelesaikan analisis cepat...\033[0m")

    # Stage 3: Parallel Smart Analysis with Strict Timeout
    reporter.print_section(f"Stage 3: Parallel Engine Analysis (Timeout: {args.timeout}s per stage)")

    task_results = {
        "pcap": None,
        "mem": None,
        "ad1": None,
        "stego": None,
        "db": None,
        "sys": None,
        "archive": None,
        "disk": None,
        "signal": None,
        "overlay": None,
        "carved": [],
        "exif": None
    }

    # Worker definitions
    def task_exif():
        if stop_flag_signal[0]:
            return None
        res = exif_inspector.inspect(file_path, header_sample)
        if res.get("comments"):
            for cm in res["comments"]:
                for fl in string_hunter.hunt_flags(cm):
                    on_instant_flag(fl, "Exif Comment")
        return res

    def task_overlay_and_carve():
        if stop_flag_signal[0]:
            return None, []
        overlay_info = magic_carver.check_eof_overlay(header_sample, primary)
        if overlay_info:
            overlay_path = os.path.join(target_out_dir, f"{file_name}_eof_overlay.bin")
            try:
                with open(overlay_path, "wb") as of:
                    of.write(overlay_info["full_overlay"])
            except Exception:
                pass
            for fl in string_hunter.hunt_flags(overlay_info["full_overlay"]):
                on_instant_flag(fl, "EOF Overlay")

        carved_files = magic_carver.carve_embedded_files(header_sample, file_name)
        for c in carved_files:
            try:
                with open(c["path"], "rb") as cf:
                    c_data = cf.read()
                    for fl in string_hunter.hunt_flags(c_data):
                        on_instant_flag(fl, f"Carved {c['type']}")
            except Exception:
                pass

        # Check for corrupted ZIP local headers if PK\x03\x04 present
        if b"PK\x03\x04" in header_sample:
            corrupted_zips = magic_carver.carve_corrupted_zip_entries(header_sample, file_name)
            for cz in corrupted_zips:
                for fl in string_hunter.hunt_flags(cz.get("payload", b"")):
                    on_instant_flag(fl, f"Corrupted ZIP ({cz['name']})")

        return overlay_info, carved_files

    def task_specialized():
        if stop_flag_signal[0]:
            return None

        # 1. Archive Unpacking (.7z, .zip, .tar, .tar.gz, etc.)
        detected_arch = archive_unpacker.is_archive(file_path, header_sample)
        if detected_arch or getattr(args, "archive", False):
            print(f" [*] [Archive Worker] Unpacking {detected_arch or 'archive'}...")
            unpacked_dir = os.path.join(target_out_dir, "unpacked")
            arch_res = archive_unpacker.unpack(file_path, unpacked_dir)
            if arch_res.get("success"):
                ext_files = arch_res.get("extracted_files", [])
                print(f" [OK] Successfully unpacked {len(ext_files)} file(s).")
                for ef in ext_files:
                    ef_path = ef["path"]
                    ef_size = ef.get("size_bytes", 0)
                    ef_name = ef.get("filename", "")
                    print(f"    [+] File: \033[1;36m{ef_name}\033[0m ({ef_size:,} bytes)")

                    # If it extracted a memory dump (.lime, .dmp, etc.)
                    if ef_name.endswith((".lime", ".dmp", ".raw", ".vmem")) or ef_size > 100 * 1024 * 1024:
                        print(f"    [*] Auto-routing unpacked memory dump to Memory Streamer: {ef_name}...")
                        m_limit = None if getattr(args, "full_mem", False) else 500 * 1024 * 1024
                        m_res = memory_streamer.scan_memory_dump(
                            ef_path,
                            max_bytes=m_limit,
                            on_flag_found=lambda fl: on_instant_flag(fl, f"Memory ({ef_name})"),
                            early_stop=args.stop_on_flag
                        )
                        for fl in m_res.get("flags_found", []):
                            on_instant_flag(fl, f"Memory ({ef_name})")
                        task_results["mem"] = m_res

                    elif ef_name.endswith((".sqlite", ".db", ".sqlite3")):
                        print(f"    [*] Auto-routing unpacked database to DB Inspector: {ef_name}...")
                        d_res = db_inspector.inspect_database(ef_path)
                        for fl in d_res.get("flags_found", []):
                            on_instant_flag(fl, f"DB ({ef_name})")
                        task_results["db"] = d_res

                    else:
                        # Quick hunt flags in unpacked file
                        try:
                            with open(ef_path, "rb") as ef_f:
                                ef_data = ef_f.read(min(ef_size, 16 * 1024 * 1024))
                            for fl in string_hunter.hunt_flags(ef_data):
                                on_instant_flag(fl, f"Extracted ({ef_name})")
                        except Exception:
                            pass
            return ("archive", arch_res)

        # 2. SQLite Database (.db, .sqlite)
        elif primary_ext in ("sqlite", "db", "sqlite3") or getattr(args, "db", False) or header_sample.startswith(b"SQLite format 3\x00") or file_name.endswith((".db", ".sqlite", ".sqlite3")):
            print(" [*] [SQLite Worker] Enumerating tables, browser history, cookies, and slack space...")
            d_res = db_inspector.inspect_database(file_path)
            for fl in d_res.get("flags_found", []):
                on_instant_flag(fl, "SQLite Engine")
            return ("db", d_res)

        # 3. System / Windows Event Logs (.evtx) & Linux Logs
        elif primary_ext in ("evtx", "log") or getattr(args, "sys", False) or header_sample.startswith(b"ElfFile\x00") or file_name.endswith((".evtx", ".log")):
            print(" [*] [System/EVTX Worker] Triaging Event IDs, PowerShell commands, and keyloggers...")
            s_res = system_inspector.analyze_evtx_or_logs(file_path)
            for fl in s_res.get("flags_found", []):
                on_instant_flag(fl, "System Engine")
            inp_res = system_inspector.parse_linux_input_events(header_sample)
            if inp_res.get("is_input_event"):
                s_res["linux_input_event"] = inp_res
                for fl in inp_res.get("flags_found", []):
                    on_instant_flag(fl, "Linux Keylogger")
            return ("sys", s_res)

        # 4. PCAP / PCAPNG Network
        elif primary_ext in ("pcap", "pcapng") or getattr(args, "pcap", False) or header_sample.startswith((b"\xd4\xc3", b"\xa1\xb2", b"\n\r\r\n")):
            print(" [*] [PCAP Worker] Parsing protocol hierarchy, USB HID, and streams...")
            p_res = pcap_analyzer.analyze(file_path)
            for fl in p_res.get("flags_found", []):
                on_instant_flag(fl, "PCAP Engine")
            return ("pcap", p_res)

        # 5. Memory Dumps (.lime, .dmp, .raw, .vmem)
        elif primary_ext == "lime" or getattr(args, "mem", False) or primary.get("name") in ("LiME Memory Dump", "Raw Memory Image / Dump") or file_name.endswith((".lime", ".dmp", ".vmem")):
            print(" [*] [Memory Worker] Streaming memory dump chunks...")
            m_limit = None if getattr(args, "full_mem", False) else (500 * 1024 * 1024 if file_size > 500 * 1024 * 1024 else None)
            m_res = memory_streamer.scan_memory_dump(
                file_path,
                max_bytes=m_limit,
                on_flag_found=lambda fl: on_instant_flag(fl, "Memory Streamer"),
                early_stop=args.stop_on_flag
            )
            for fl in m_res.get("flags_found", []):
                on_instant_flag(fl, "Memory Engine")
            return ("mem", m_res)

        # 6. AD1 (AccessData FTK Imager)
        elif primary_ext == "ad1" or getattr(args, "ad1", False) or header_sample.startswith(b"ADSEGMENTED"):
            print(" [*] [AD1 Worker] Parsing AD1 directory index & zlib blocks...")
            a_res = ad1_parser.parse(file_path, max_scan_bytes=20 * 1024 * 1024)
            for fl in a_res.get("flags_found", []):
                on_instant_flag(fl, "AD1 Engine")
            return ("ad1", a_res)

        # 7. Stego Images (PNG, JPG, BMP)
        elif primary_ext in ("png", "jpg", "jpeg", "bmp", "gif") or getattr(args, "stego", False) or header_sample.startswith((b"\x89PNG", b"\xff\xd8\xff", b"BM")):
            print(" [*] [Stego Worker] Auditing PNG chunks, CRC, DQT tables, and bitplanes...")
            s_res = stego_engine.analyze_png(header_sample)
            if header_sample.startswith(b"\xff\xd8\xff"):
                dqt_res = stego_engine.analyze_jpeg_dqt(header_sample)
                for fl in dqt_res.get("extracted_flags", []):
                    on_instant_flag(fl, "JPEG DQT Engine")
                s_res["dqt_analysis"] = dqt_res
            for fl in s_res.get("extracted_flags", []):
                on_instant_flag(fl, "Stego Engine")
            return ("stego", s_res)

        # 8. Signals & Audio (WAV, MP3, DTMF) & 3D G-code
        elif primary_ext in ("wav", "mp3", "g", "bgcode", "gcode", "sub") or getattr(args, "signals", False) or header_sample.startswith((b"GCDE", b"RIFF")):
            print(" [*] [Signals Worker] Triaging audio DTMF tones, Flipper radio, and 3D printing toolpaths...")
            sig_res = {}
            if primary_ext in ("wav", "mp3") or header_sample.startswith(b"RIFF"):
                dtmf = signal_engine.decode_dtmf_wav(file_path)
                sig_res["dtmf"] = dtmf
                for fl in dtmf.get("flags_found", []):
                    on_instant_flag(fl, "DTMF Audio")
            if primary_ext in ("g", "bgcode", "gcode") or header_sample.startswith(b"GCDE"):
                gcode_res = signal_engine.parse_gcode(file_path)
                sig_res["gcode"] = gcode_res
                for fl in gcode_res.get("flags_found", []):
                    on_instant_flag(fl, "G-Code Toolpath")
            if primary_ext == "sub" or b"Flipper SubGhz" in header_sample:
                flip = signal_engine.parse_flipper_sub(file_path)
                sig_res["flipper"] = flip
                for fl in flip.get("flags_found", []):
                    on_instant_flag(fl, "Flipper Radio")
            return ("signal", sig_res)

        # 9. Disk, Partitions & Windows Shell Artifacts (GPT, VMDK, APFS, Recycle Bin, LNK)
        elif getattr(args, "disk", False) or file_name.startswith("$I") or file_name.endswith((".lnk", ".vmdk", ".dmg", ".img", ".dd", ".iso")) or (len(header_sample) > 520 and header_sample[512:520] == b"EFI PART") or header_sample.startswith((b"KDMV", b"\x55\xaa")):
            print(" [*] [Disk Worker] Auditing GPT partition GUIDs, disk structures, and Windows shell artifacts...")
            disk_res = {}
            if file_name.startswith("$I"):
                rec_res = disk_inspector.inspect_recycle_bin(file_path)
                disk_res["recycle_bin"] = rec_res
                for fl in rec_res.get("flags_found", []):
                    on_instant_flag(fl, "Recycle Bin")
            elif file_name.endswith(".lnk"):
                lnk_res = disk_inspector.inspect_lnk(file_path)
                disk_res["lnk"] = lnk_res
                for fl in lnk_res.get("flags_found", []):
                    on_instant_flag(fl, "LNK Shortcut")
            else:
                gpt_res = disk_inspector.inspect_gpt_partitions(file_path)
                disk_res["gpt"] = gpt_res
                for fl in gpt_res.get("flags_found", []):
                    on_instant_flag(fl, "GPT Partition GUID")

                struct_res = disk_inspector.detect_disk_structures(file_path)
                disk_res["structures"] = struct_res
                if struct_res.get("format") != "Unknown Raw / Disk":
                    print(f"    [+] Disk Structure: \033[1;36m{struct_res['format']}\033[0m")
                if struct_res.get("apfs_snapshots"):
                    print(f"    [!] Detected {len(struct_res['apfs_snapshots'])} APFS snapshot(s)!")
            return ("disk", disk_res)

        return None

    # Execute workers in parallel with timeout guard
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_exif = executor.submit(task_exif)
        future_carve = executor.submit(task_overlay_and_carve)
        future_spec = executor.submit(task_specialized)

        # Collect Exif
        try:
            task_results["exif"] = future_exif.result(timeout=args.timeout)
            print(" [OK] Exif / Metadata inspection completed.")
        except concurrent.futures.TimeoutError:
            print(f" [TIMEOUT] Exif inspection skipped after {args.timeout}s timeout.")

        # Collect Overlay & Carving
        try:
            overlay_info, carved_files = future_carve.result(timeout=args.timeout)
            task_results["overlay"] = overlay_info
            task_results["carved"] = carved_files
            if overlay_info:
                print(f" [!] DETECTED {overlay_info['overlay_size']:,} BYTES OF TRAILING DATA!")
            if carved_files:
                print(f" [OK] Successfully carved {len(carved_files)} embedded file(s).")
            else:
                print(" [OK] Carving scan completed (no embedded archives).")
        except concurrent.futures.TimeoutError:
            print(f" [TIMEOUT] Carving analysis skipped after {args.timeout}s timeout.")

        # Collect Specialized Engine
        try:
            # Memory and archive extraction might need a bit more time if user didn't set a large timeout
            spec_timeout = max(args.timeout, 30.0) if (primary_ext in ("7z", "lime") or getattr(args, "full_mem", False)) else args.timeout
            spec_out = future_spec.result(timeout=spec_timeout)
            if spec_out:
                kind, data = spec_out
                task_results[kind] = data
                print(f" [OK] {kind.upper()} specialized engine completed.")
        except concurrent.futures.TimeoutError:
            print(f" [TIMEOUT] Specialized engine skipped after timeout.")

    elapsed = time.time() - start_time

    # Stage 4: Final Summary & Diagnostic Recommendations
    reporter.print_section(f"Stage 4: Temuan Akhir & Laporan (Selesai dalam {elapsed:.2f} detik)")

    if all_discovered_flags:
        print(f"\033[1;42;37m [!] TOTAL FLAG VALID DITEMUKAN: {len(all_discovered_flags)} \033[0m")
        for idx, fl in enumerate(all_discovered_flags, 1):
            print(f"    {idx}. \033[1;32m{fl['flag']}\033[0m ({fl['encoding']})")
    else:
        print("\033[1;33m[-] Belum ada pola flag standar yang langsung cocok.\033[0m")
        reporter.print_diagnostic_next_steps(
            primary_ext=primary_ext,
            carved_count=len(task_results["carved"]),
            overlay_found=task_results["overlay"] is not None
        )

    # Stage 5: Rule-Based Forensic Triage & Heuristic Playbook
    triage_assessment = Triage.generate_triage_assessment(
        filename=file_name,
        file_size=file_size,
        primary_format=primary,
        header_sample=header_sample,
        flags_found=all_discovered_flags,
        task_results=task_results
    )
    reporter.print_triage_advisory(triage_assessment)

    # Save reports
    report_payload = {
        "target_file": file_path,
        "file_size_bytes": file_size,
        "format_identification": fmt_info,
        "elapsed_seconds": round(elapsed, 2),
        "all_flags": all_discovered_flags,
        "triage_assessment": triage_assessment,
        "eof_overlay": task_results["overlay"] is not None,
        "carved_artifacts": task_results["carved"],
        "pcap_analysis": task_results["pcap"],
        "memory_analysis": task_results["mem"],
        "ad1_analysis": task_results["ad1"],
        "stego_analysis": task_results["stego"],
        "db_analysis": task_results["db"],
        "system_analysis": task_results["sys"],
        "archive_analysis": task_results["archive"],
        "disk_analysis": task_results["disk"],
        "signal_analysis": task_results["signal"],
        "exif_metadata": task_results["exif"],
        "suspicious_patterns": sus_patterns
    }

    json_p, md_p = reporter.save_reports(report_payload)
    print(f"\n [*] JSON Report:     \033[1;34m{json_p}\033[0m")
    print(f" [*] Markdown Report: \033[1;34m{md_p}\033[0m")
    print(f" [*] Extracted Files: \033[1;34m{target_out_dir}\033[0m\n")

    return report_payload


def main():
    parser = argparse.ArgumentParser(
        description="Forensics Solver - High-Speed Parallel CTF Forensic Solver (HackToday Final)"
    )
    parser.add_argument("target", nargs="?", default=None, help="Target forensic challenge file or directory")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout in seconds per worker stage (default: 5.0s)")
    parser.add_argument("--stop-on-flag", action="store_true", default=True, help="Stop subsequent stages immediately when a flag is discovered (default: True)")
    parser.add_argument("--no-stop", dest="stop_on_flag", action="store_false", help="Don't stop on first flag, perform exhaustive deep scan")
    parser.add_argument("--pcap", action="store_true", help="Force PCAP network inspection")
    parser.add_argument("--mem", action="store_true", help="Force memory dump scan")
    parser.add_argument("--ad1", action="store_true", help="Force AD1 image parsing")
    parser.add_argument("--stego", action="store_true", help="Force steganography analysis")
    parser.add_argument("--db", action="store_true", help="Force SQLite database inspection")
    parser.add_argument("--sys", action="store_true", help="Force Windows EVTX / Linux log inspection")
    parser.add_argument("--archive", action="store_true", help="Force archive extraction (.7z, .zip, .tar, etc.)")
    parser.add_argument("--signals", action="store_true", help="Force audio DTMF / radio / G-code inspection")
    parser.add_argument("--disk", action="store_true", help="Force GPT partition table & Windows shell artifacts inspection")
    parser.add_argument("--full-mem", action="store_true", help="Stream entire memory dump without size limit")
    parser.add_argument("--raid-xor", nargs="+", help="Recover missing RAID 5 disk: provide paths to remaining N-1 disk images (e.g. --raid-xor disk1.raw disk3.raw -o disk2.raw)")
    parser.add_argument("-o", "--output-disk", help="Output path for recovered RAID 5 disk image")
    parser.add_argument("--outdir", default="results", help="Directory for reports and extracted files")

    args = parser.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    # Check RAID 5 XOR Recovery mode
    if args.raid_xor:
        print("\033[1;34m[*] Running RAID 5 Missing Disk Recovery via XOR...\033[0m")
        disk_inspector = DiskInspector(args.outdir)
        res = disk_inspector.recover_raid5_missing_disk(args.raid_xor, args.output_disk)
        if res.get("success"):
            print(f"\033[1;32m[+] Successfully recovered missing disk: {res['output_path']}\033[0m ({res['recovered_size']:,} bytes)")
            if res.get("detected_fs"):
                print(f" [+] Detected Filesystem: \033[1;36m{res['detected_fs']}\033[0m")
            if res.get("flags_found"):
                for fl in res["flags_found"]:
                    print(f" \033[1;42;37m[!] FLAG FOUND: {fl['flag']}\033[0m ({fl['encoding']})")
        else:
            print(f"\033[1;31m[-] RAID 5 recovery failed: {res.get('error')}\033[0m")
        sys.exit(0)

    if not args.target:
        parser.print_help()
        sys.exit(1)

    target_path = os.path.abspath(args.target)
    if not os.path.exists(target_path):
        print(f"Error: Target '{args.target}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if os.path.isdir(target_path):
        print(f"[*] Scanning directory: {target_path}")
        for root, _, files in os.walk(target_path):
            for file in files:
                p = os.path.join(root, file)
                scan_single_file(p, args, args.outdir)
    else:
        scan_single_file(target_path, args, args.outdir)


if __name__ == "__main__":
    main()
