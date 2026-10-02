"""
Automotion Forensics - Reporter Engine
Formats findings into terminal visual output, JSON reports, and Markdown writeups.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple


class Reporter:
    """Generates formatted reports across terminal, JSON, and Markdown."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def print_terminal_banner(self, filename: str):
        """Display clean terminal header."""
        print(f"\n[*] Tool Analysis Foren: {filename}\n")

    def print_section(self, title: str):
        """Display section divider."""
        print(f"--- [ {title} ] ---")

    def print_flag(self, flag_info: Dict[str, str]):
        """Highlight discovered flag in terminal."""
        flag = flag_info.get("flag", "")
        enc = flag_info.get("encoding", "Plaintext")
        print(f"\n[+] Flag found: {flag}")
        if enc:
            print(f"    Method: {enc}")

    def print_instant_bingo(self, flag: str, method: str):
        """Immediately print clean flag output when caught."""
        print(f"\n[+] Flag found: {flag}")
        if method:
            print(f"    Source: {method}\n")


    def print_triage_advisory(self, assessment: Dict[str, Any]):
        """Display rule-based forensic triage evaluation."""
        border = "-" * 70
        print(f"\n\033[1;36m{border}\033[0m")
        print("\033[1;35m [*] Forensic Triage & Investigation Profile\033[0m")
        print(f" [*] Heuristic Category: \033[1;32m{assessment.get('detected_category')}\033[0m (Confidence: {assessment.get('confidence_score')}%)")
        print(f" [*] Entropy Score:      \033[1;33m{assessment.get('entropy')}\033[0m / 8.0 ({assessment.get('entropy_rating')})")

        patterns = assessment.get("ctf_patterns_identified", [])
        if patterns:
            print(" [+] Detected CTF Patterns:")
            for p in patterns:
                print(f"     \033[1;32m[+]\033[0m {p}")

        next_steps = assessment.get("recommended_next_steps", [])
        if next_steps:
            print(" [>] Recommended Forensic Next Steps:")
            for idx, ns in enumerate(next_steps, 1):
                print(f"     {idx}. {ns}")
        print(f"\033[1;36m{border}\033[0m\n")

    def print_diagnostic_next_steps(self, primary_ext: str, carved_count: int, overlay_found: bool):
        """Print concrete, actionable forensic next-step recommendations if no flag is immediately found."""
        print("\n\033[1;33m[!] TEMUAN AKHIR & REKOMENDASI ANALISIS:\033[0m")
        if carved_count > 0:
            print(f"  \033[1;32m1.\033[0m Ditemukan {carved_count} file tertanam! Periksa folder output:")
            print(f"     -> Buka folder \033[1;34m{self.output_dir}\033[0m dan analisa file carved di dalamnya.")
        if overlay_found:
            print("  \033[1;32m2.\033[0m Ditemukan Trailing Data (EOF Overlay). File overlay tersimpan di folder output.")
            print("     -> Coba decode dengan CyberChef (Magic, Base64, Gzip, atau XOR).")
        
        if primary_ext in ("png", "jpg", "jpeg", "bmp"):
            print("  \033[1;36m3. Analisis Lanjutan Citra (Stego):\033[0m")
            print("     -> Buka di Stegsolve (cek Red plane 0, Green plane 0, Blue plane 0, Alpha 0).")
            print("     -> Jalankan Zsteg jika PNG: zsteg -a <file>")
            print("     -> Coba Stegseek jika JPG: stegseek <file> /usr/share/wordlists/rockyou.txt")
        elif primary_ext in ("pcap", "pcapng"):
            print("  \033[1;36m3. Analisis Lanjutan Jaringan (PCAP):\033[0m")
            print("     -> Buka di Wireshark, filter: http, tcp.stream eq 0, dns, icmp, usb.")
            print("     -> Cek 'File -> Export Objects -> HTTP...' atau SMB/TFTP.")
            print("     -> Jika ada SSL/TLS, cari secret keylog file (SSLKEYLOGFILE).")
        elif primary_ext in ("lime", "raw", "dmp", "vmem"):
            print("  \033[1;36m3. Analisis Lanjutan Memory Dump:\033[0m")
            print("     -> Jalankan Volatility 3: vol -f <file> windows.pslist / linux.bash")
            print("     -> Dump proses mencurigakan atau periksa command line arguments.")
        elif primary_ext in ("sqlite", "db", "sqlite3"):
            print("  \033[1;36m3. Analisis Lanjutan SQLite Database:\033[0m")
            print("     -> Buka di DB Browser for SQLite: periksa tabel tersembunyi, sqlite_sequence.")
            print("     -> Carve unallocated B-Tree page slack space dengan strings -a -n 8 <file>.")
            print("     -> Periksa riwayat browser (moz_places, urls) atau cookies (moz_cookies, cookies).")
        elif primary_ext in ("evtx", "log"):
            print("  \033[1;36m3. Analisis Lanjutan Log / EVTX:\033[0m")
            print("     -> Buka di Event Viewer atau gunakan Chainsaw / Hayabusa.")
            print("     -> Cek Event ID 4104 (PowerShell Script Block), 4688 (Process Creation), 1102 (Log Cleared).")
            print("     -> Decode string Base64 UTF-16LE dari parameter -EncodedCommand.")
        elif primary_ext in ("7z", "zip", "tar", "gz", "bz2", "xz", "rar"):
            print("  \033[1;36m3. Analisis Lanjutan Arsip Terkompresi:\033[0m")
            print("     -> Periksa file tersembunyi atau file yang di-unpack di folder output.")
            print("     -> Jika ber-password, gunakan John the Ripper atau Hashcat (rockyou.txt).")
        else:
            print("  \033[1;36m3. Analisis Biner/Reverse:\033[0m")
            print("     -> Buka di Ghidra / IDA / Radare2 / Binwalk.")
            print("     -> Cek entropy biner dengan binwalk -E atau hexdump.")

    def save_reports(self, report_data: Dict[str, Any]) -> Tuple[str, str]:
        """Disabled to keep competition workspace clean without bot/AI trace."""
        return "", ""

    def _generate_markdown(self, data: Dict[str, Any]) -> str:
        """Build structured Markdown report."""
        lines = []
        lines.append("# Forensic Analysis Report\n")
        lines.append(f"- **Target File:** `{data.get('target_file')}`")
        lines.append(f"- **File Size:** {data.get('file_size_bytes', 0):,} bytes")
        lines.append(f"- **Primary Format:** {data.get('format_identification', {}).get('primary', {}).get('name', 'Unknown')}\n")

        # Flags section
        all_flags = data.get("all_flags", [])
        if all_flags:
            lines.append("## Flags Discovered\n")
            lines.append("> [!IMPORTANT]")
            for fl in all_flags:
                lines.append(f"> - **Flag:** `{fl.get('flag')}` ({fl.get('encoding')})")
            lines.append("")

        # Forensic Triage Assessment & Playbook
        triage = data.get("triage_assessment") or data.get("ai_assessment")
        if triage:
            lines.append("## Forensic Triage Assessment & Playbook\n")
            lines.append(f"- **Heuristic Category:** `{triage.get('detected_category')}` (Confidence: {triage.get('confidence_score')}%)")
            lines.append(f"- **Entropy:** `{triage.get('entropy')}` / 8.0 ({triage.get('entropy_rating')})\n")
            patterns = triage.get("ctf_patterns_identified", [])
            if patterns:
                lines.append("### Detected CTF Patterns\n")
                for p in patterns:
                    lines.append(f"- {p}")
                lines.append("")
            next_steps = triage.get("recommended_next_steps", [])
            if next_steps:
                lines.append("### Recommended Solver Playbook\n")
                for idx, ns in enumerate(next_steps, 1):
                    lines.append(f"{idx}. {ns}")
                lines.append("")

        # Extension Mismatch Warning
        mismatch = data.get("format_identification", {}).get("mismatch_warning")
        if mismatch:
            lines.append("## Format Anomaly")
            lines.append(f"> [!WARNING]\n> {mismatch}\n")

        # Carved Files
        carved = data.get("carved_artifacts", [])
        if carved:
            lines.append("## Carved Artifacts\n")
            lines.append("| Type | Offset | Size (bytes) | File Path |")
            lines.append("|------|--------|--------------|-----------|")
            for c in carved:
                lines.append(f"| {c.get('type')} | 0x{c.get('offset', 0):x} | {c.get('size', 0):,} | `{c.get('filename')}` |")
            lines.append("")

        # Network / PCAP
        pcap_data = data.get("pcap_analysis")
        if pcap_data and not pcap_data.get("error"):
            lines.append("## Network Analysis Summary\n")
            lines.append(f"- **Packets:** {pcap_data.get('packet_count', 0):,}")
            lines.append(f"- **Protocols:** {', '.join(pcap_data.get('protocols', []))}")
            if pcap_data.get("usb_hid_keystrokes"):
                lines.append(f"\n### Decoded USB HID Keystrokes\n```text\n{pcap_data['usb_hid_keystrokes']}\n```")
            if pcap_data.get("credentials"):
                lines.append("\n### Network Credentials\n")
                for cred in pcap_data["credentials"]:
                    lines.append(f"- {cred}")
            lines.append("")

        # Memory / LiME
        mem_data = data.get("memory_analysis")
        if mem_data and not mem_data.get("error"):
            lines.append("## Memory Analysis Summary\n")
            lines.append(f"- **Memory Type:** {mem_data.get('memory_type')}")
            cmds = mem_data.get("bash_commands", [])
            if cmds:
                lines.append("\n### Recovered Shell History\n```bash")
                for cmd in cmds[:30]:
                    lines.append(cmd)
                lines.append("```\n")

            envs = mem_data.get("env_vars", [])
            if envs:
                lines.append("\n### Recovered Environment Variables\n```text")
                for env in envs[:20]:
                    lines.append(env)
                lines.append("```\n")

            recs = mem_data.get("volatility_recommendations", [])
            if recs:
                lines.append("\n### Suggested Volatility Commands\n```bash")
                for r in recs:
                    lines.append(r)
                lines.append("```\n")

        # Database / SQLite
        db_data = data.get("db_analysis")
        if db_data and not db_data.get("error"):
            lines.append("## SQLite Database Analysis\n")
            lines.append(f"- **Tables:** {', '.join(db_data.get('tables', []))}")
            if db_data.get("browser_history"):
                lines.append("\n### Browser History Extracted\n")
                for bh in db_data["browser_history"][:15]:
                    lines.append(f"- {bh}")
            if db_data.get("credentials"):
                lines.append("\n### Credentials in Database Rows\n")
                for cred in db_data["credentials"][:10]:
                    lines.append(f"- `{cred}`")
            lines.append("")

        # System / EVTX / Logs
        sys_data = data.get("system_analysis")
        if sys_data and not sys_data.get("error"):
            lines.append("## System & Log Analysis\n")
            if sys_data.get("key_events"):
                lines.append("### Key Event IDs\n")
                for ke in sys_data["key_events"]:
                    lines.append(f"- **Event {ke.get('event_id')}:** {ke.get('description')}")
            if sys_data.get("powershell_scripts"):
                lines.append("\n### PowerShell Scripts & Commands\n```powershell")
                for ps in sys_data["powershell_scripts"][:15]:
                    lines.append(ps)
                lines.append("```\n")
            if sys_data.get("reconstructed_text"):
                lines.append(f"\n### Reconstructed Linux Keystrokes\n```text\n{sys_data['reconstructed_text']}\n```\n")
            lines.append("")

        # Exif / Metadata
        exif_data = data.get("exif_metadata")
        if exif_data and exif_data.get("metadata"):
            lines.append("## Metadata & Exif Findings\n")
            lines.append("| Key | Value |")
            lines.append("|-----|-------|")
            for k, v in list(exif_data["metadata"].items())[:20]:
                lines.append(f"| {k} | `{v}` |")
            lines.append("")

        return "\n".join(lines)


# Type alias helper
Tuple_Path = tuple[str, str]
