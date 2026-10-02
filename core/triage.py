"""
CTF Forensics - Triage & Heuristic Engine
Distills all 15 reference modules from ctf-forensics:
(3d-printing, disk-advanced, disk-and-memory, disk-recovery, linux-forensics,
network-advanced, network, peripheral-capture, signals-and-hardware, SKILL,
steganography, stego-advanced-2, stego-advanced, stego-image, windows).
Provides heuristic anomaly scoring, CTF challenge pattern matching,
and automated solver command recipes.
"""

import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple


class Triage:
    """Deterministic CTF Forensics Decision Matrix & Rule-Based Heuristic Engine."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy (0.0 to 8.0) to measure randomness/compression/encryption."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @staticmethod
    def generate_triage_assessment(
        filename: str,
        file_size: int,
        primary_format: Dict[str, Any],
        header_sample: bytes,
        flags_found: List[Dict[str, str]],
        task_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Synthesize cross-category CTF forensic heuristics into an deterministic rule-based solver advisory.
        """
        entropy = Triage.calculate_entropy(header_sample[:65536])
        ext = primary_format.get("ext", "bin")
        name = primary_format.get("name", "Unknown")

        assessment: Dict[str, Any] = {
            "entropy": entropy,
            "entropy_rating": "Normal",
            "detected_category": "General Binary",
            "confidence_score": 95 if flags_found else 75,
            "ctf_patterns_identified": [],
            "automated_actions_taken": [],
            "recommended_next_steps": []
        }

        # Entropy assessment
        if entropy > 7.8:
            assessment["entropy_rating"] = "High (Encrypted or Compressed payload present)"
        elif entropy < 2.0:
            assessment["entropy_rating"] = "Low (Sparse or padded data structure)"

        # 1. Network / PCAP heuristics
        if ext in ("pcap", "pcapng") or "PCAP" in name:
            assessment["detected_category"] = "Network Capture / Peripheral USB Forensic"
            assessment["ctf_patterns_identified"].append("Network Packet Capture (Libpcap / PCAPNG)")
            p_res = task_results.get("pcap") or {}
            if p_res.get("usb_hid_keystrokes"):
                assessment["ctf_patterns_identified"].append("USB HID Keyboard Keystroke sequence reconstructed")
            if p_res.get("usb_mouse_drawing"):
                assessment["ctf_patterns_identified"].append("USB Mouse/Pen Drawing recovered (SVG generated)")
            if p_res.get("dns_exfil_data"):
                assessment["ctf_patterns_identified"].append("DNS Subdomain Exfiltration tunnel detected")
            if p_res.get("icmp_exfil_data"):
                assessment["ctf_patterns_identified"].append("ICMP Echo payload exfiltration detected")

            assessment["recommended_next_steps"].extend([
                "Wireshark Filter: `http || dns || icmp || tcp.stream eq 0 || usb.capdata`",
                "Export HTTP Objects: File -> Export Objects -> HTTP...",
                "Check for Packet Interval Timing stego (EHAX 2026): analyze delta time between packet timestamps",
                "Check for TCP Flag covert channel (BearCatCTF 2026): 6-bit flag base64 mapping"
            ])

        # 2. Memory / LiME / DMP heuristics
        elif ext in ("lime", "dmp", "vmem") or "Memory" in name:
            assessment["detected_category"] = "Operating System RAM Memory Forensics"
            assessment["ctf_patterns_identified"].append("RAM Memory Image (LiME / Minidump / Windows Crash Dump)")
            m_res = task_results.get("mem") or {}
            if m_res.get("kernel_banner"):
                assessment["ctf_patterns_identified"].append(f"Linux Kernel Banner: {m_res['kernel_banner'][:60]}")
            if m_res.get("bash_commands"):
                assessment["ctf_patterns_identified"].append(f"{len(m_res['bash_commands'])} shell commands scraped from memory")

            assessment["recommended_next_steps"].extend([
                "Volatility 3 Linux: `vol -f <dump> linux.bash`, `linux.pslist`, `linux.sockstat`",
                "Volatility 3 Windows: `vol -f <dump> windows.cmdline`, `windows.filescan`, `windows.netscan`",
                "Strings grep for process tokens: `strings -a -n 8 <dump> | grep -E 'FLAG|PASSWORD|SSH_CLIENT'`",
                "GIMP Raw Memory Visual Inspection (INShAck 2018): If Volatility fails, inspect candidate framebuffer BMP images in extracted_artifacts/",
                "MFT Resident Recovery: parse $MFT records for resident $DATA attributes (<700 bytes)"
            ])

        # 3. SQLite / Database heuristics
        elif ext in ("sqlite", "db", "sqlite3") or "SQLite" in name:
            assessment["detected_category"] = "Database & Browser Storage Forensics"
            assessment["ctf_patterns_identified"].append("SQLite v3 Database Storage")
            d_res = task_results.get("db") or {}
            if d_res.get("tables"):
                assessment["ctf_patterns_identified"].append(f"Tables identified: {', '.join(d_res['tables'][:5])}")
            assessment["recommended_next_steps"].extend([
                "Open in DB Browser for SQLite: Inspect table data, sqlite_sequence, and schema triggers",
                "Check browser history: `SELECT url, title, visit_count FROM moz_places;` (Firefox) or `urls` (Chrome)",
                "Reconstruct Edit Diff History: automated replay checks intermediate states for typed-and-deleted flags",
                "Carve unallocated B-Tree page slack space: deleted records persist in free pages"
            ])

        # 4. Windows EVTX / Event Log heuristics
        elif ext in ("evtx", "log") or "Event Log" in name:
            assessment["detected_category"] = "Windows Event & Security Log Forensics"
            assessment["ctf_patterns_identified"].append("Windows Event Log (EVTX XML Blocks)")
            assessment["recommended_next_steps"].extend([
                "Event ID 4104: Inspect PowerShell ScriptBlock execution & decode -EncodedCommand (Base64 UTF-16LE)",
                "Event ID 4688: Audit new process creations and command lines",
                "Event ID 1102: Audit log cleared (Anti-forensics indicator)",
                "Event ID 4720: User account created / privilege escalation",
                "KAPE Triage: check ConsoleHost_history.txt for attacker commands"
            ])

        # 5. Image Steganography heuristics
        elif ext in ("png", "jpg", "jpeg", "bmp", "gif") or "Image" in name:
            assessment["detected_category"] = "Digital Image Steganography"
            assessment["ctf_patterns_identified"].append(f"{name} Steganographic container")
            assessment["recommended_next_steps"].extend([
                "Check LSB Bitplanes: inspect bit 0, 1, 2 across R, G, B channels using Stegsolve",
                "PNG Height Check: if IHDR CRC was tampered, height was auto-calculated and patched",
                "JPEG DQT Check: inspect Quantization Tables 2-15 LSB (EHAX 2026 pattern)",
                "Trailing data check: inspect any bytes after JPEG FF D9 or PNG IEND"
            ])

        # 6. Audio / Signals heuristics
        elif ext in ("wav", "mp3", "flac") or "Audio" in name:
            assessment["detected_category"] = "Audio Signal & Telephony Steganography"
            assessment["ctf_patterns_identified"].append("Audio Sound Stream")
            assessment["recommended_next_steps"].extend([
                "DTMF Keypad Tones: check dual-tone frequencies (697-941 Hz + 1209-1633 Hz)",
                "Spectrogram: open in Audacity or Sonic Visualiser (Switch to Spectrogram view)",
                "Audio Reverse / Phase Inversion: check reversed audio or stereo differential subtraction"
            ])

        # 7. 3D Printing / CAD heuristics
        elif ext in ("g", "bgcode", "gcode") or header_sample.startswith(b"GCDE"):
            assessment["detected_category"] = "3D Printing & CAD Forensics"
            assessment["ctf_patterns_identified"].append("PrusaSlicer G-Code / Binary G-Code (GCDE)")
            assessment["recommended_next_steps"].extend([
                "Extract G-code comments: grep for `;=== FLAG ... ===` at layer changes",
                "Plot toolpath: XZ (side view) or XY projection reveals embossed 3D text",
                "Check thumbnail: extract embedded QOIF / PNG images from block type 5"
            ])

        # 8. Archive heuristics
        elif ext in ("7z", "zip", "tar", "gz", "bz2", "xz", "rar"):
            assessment["detected_category"] = "Compressed Archive & File Container"
            assessment["ctf_patterns_identified"].append(f"{name} Archive")
            assessment["recommended_next_steps"].extend([
                "Check for nested archives (Matryoshka pattern): recursively unpack inner archives",
                "Check duplicate entries (Tar duplicate name overwrite attack)",
                "If password protected: use CTF password dictionary ('hacktoday', 'infected', 'admin')"
            ])

        # 9. Disk image heuristics
        elif ext in ("ad1", "e01", "vmdk", "vdi", "raw", "img"):
            assessment["detected_category"] = "Disk Image & Filesystem Forensics"
            assessment["ctf_patterns_identified"].append("Raw Disk / Logical Evidence Container")
            assessment["recommended_next_steps"].extend([
                "GPT Partition GUIDs: check if partition GUIDs encode bzip2 or ASCII flags (VuwCTF 2025)",
                "RAID 5 Missing Disk Recovery: if N-1 disks given, reconstruct missing disk via `--raid-xor disk1 disk3 -o disk2`",
                "APFS Snapshots: search for APSB superblocks across transaction IDs (XID) to recover original historical files",
                "Deleted Partitions: run testdisk or scan for MBR/VBR signatures",
                "Recycle Bin: parse $I metadata (original path, deletion time) and $R payload"
            ])

        # 10. TrueCrypt / VeraCrypt Volume Candidate
        if entropy > 7.85 and file_size % 512 == 0 and name == "Raw Binary / Unknown":
            assessment["detected_category"] = "Plausible TrueCrypt / VeraCrypt Encrypted Volume"
            assessment["ctf_patterns_identified"].append("TrueCrypt / VeraCrypt Candidate (High Entropy, 512-byte aligned, No Magic Bytes)")
            assessment["recommended_next_steps"].extend([
                "Mount with VeraCrypt: `veracrypt -t -p \"<password>\" volume.tc /mnt/tc`",
                "Try legacy TrueCrypt flag: `veracrypt -t --truecrypt -p \"<password>\" volume.tc /mnt/tc`",
                "Mount with keyfile: `veracrypt -t -k keyfile.png volume.tc /mnt/tc`"
            ])

        return assessment
