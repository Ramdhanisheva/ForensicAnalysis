"""
Automotion Forensics - Memory Dump Streaming Engine
High-performance zero-OOM sliding-window analyzer for Linux LiME (.lime)
and Windows (.dmp, .raw, .vmem) memory dumps.
Never freezes, never exhausts RAM, extracts bash history, env vars, and flags.
"""

import os
import re
import shutil
import struct
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple

import config
from core.string_hunter import StringHunter


class MemoryStreamer:
    """Streams and analyzes multi-gigabyte memory dumps with constant memory footprint."""

    def __init__(self, chunk_size: int = config.CHUNK_SIZE, overlap: int = config.CHUNK_OVERLAP):
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.string_hunter = StringHunter()
        self.has_vol = shutil.which("vol") is not None or shutil.which("volatility") is not None

    def identify_memory_type(self, header_bytes: bytes) -> Dict[str, Any]:
        """Detect LiME or Windows crash dump magic."""
        if header_bytes.startswith(b"EMiL") or header_bytes.startswith(b"LiME"):
            return {"type": "Linux LiME Memory Dump", "os": "linux", "magic": "LiME"}
        elif header_bytes.startswith(b"PAGE") or header_bytes.startswith(b"MDMP"):
            return {"type": "Windows Minidump / Crash Dump", "os": "windows", "magic": "Windows Dump"}
        return {"type": "Raw Memory Image / Dump", "os": "unknown", "magic": "Raw"}

    def scan_memory_dump(
        self,
        filepath: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_bytes: Optional[int] = None,
        on_flag_found: Optional[Callable[[Dict[str, str]], None]] = None,
        early_stop: bool = False
    ) -> Dict[str, Any]:
        """
        Stream through memory dump in 32MB sliding windows with 64KB overlap.
        Extracts:
        - Flags across plaintext, base64, hex with instant early-stop callback
        - Linux Kernel Banner (exact kernel version for Volatility 3 symbol table)
        - Bash history & terminal commands
        - Environment variables
        - SSH private keys and executed scripts
        - Volatility 3 recipe commands
        """
        results: Dict[str, Any] = {
            "source": filepath,
            "file_size_bytes": 0,
            "memory_type": "Unknown",
            "flags_found": [],
            "bash_commands": [],
            "env_vars": [],
            "suspicious_patterns": {},
            "volatility_recommendations": []
        }

        if not os.path.exists(filepath):
            results["error"] = "File not found"
            return results

        file_size = os.path.getsize(filepath)
        results["file_size_bytes"] = file_size
        limit_size = min(file_size, max_bytes) if max_bytes else file_size
        results["kernel_banner"] = None
        results["ssh_keys"] = []
        results["scripts_found"] = []

        seen_commands = set()
        seen_env = set()

        try:
            with open(filepath, "rb") as f:
                header = f.read(1024)
                type_info = self.identify_memory_type(header)
                results["memory_type"] = type_info["type"]
                os_target = type_info["os"]

                # Generate comprehensive Volatility 3 recommendation commands
                if os_target == "linux":
                    results["volatility_recommendations"] = [
                        f"vol -f \"{filepath}\" linux.bash",
                        f"vol -f \"{filepath}\" linux.pslist",
                        f"vol -f \"{filepath}\" linux.pstree",
                        f"vol -f \"{filepath}\" linux.cmdline",
                        f"vol -f \"{filepath}\" linux.envars",
                        f"vol -f \"{filepath}\" linux.elfs",
                        f"vol -f \"{filepath}\" linux.filescan 2>/dev/null | grep -i flag",
                        f"vol -f \"{filepath}\" linux.enumerate_files",
                        f"vol -f \"{filepath}\" linux.malfind",
                        f"vol -f \"{filepath}\" linux.check_modules",
                        f"vol -f \"{filepath}\" linux.sockstat",
                        f"vol -f \"{filepath}\" linux.netstat",
                        f"strings \"{filepath}\" | grep -aEi 'HackToday26{{|HackToday{{|flag{{|picoCTF{{' | head -50",
                    ]
                else:
                    results["volatility_recommendations"] = [
                        f"vol -f \"{filepath}\" windows.pslist",
                        f"vol -f \"{filepath}\" windows.cmdline",
                        f"vol -f \"{filepath}\" windows.envars",
                        f"vol -f \"{filepath}\" windows.netscan",
                        f"vol -f \"{filepath}\" windows.filescan | findstr /i flag",
                        f"vol -f \"{filepath}\" windows.mftscan | findstr /i flag",
                        f"vol -f \"{filepath}\" windows.dumpfiles --physaddr <offset>",
                        f"vol -f \"{filepath}\" windows.hashdump",
                        f"vol -f \"{filepath}\" windows.malfind",
                        f"strings \"{filepath}\" | findstr /i \"HackToday26{{ flag{{ picoCTF{{\"",
                    ]

                f.seek(0)
                bytes_read = 0
                prev_overlap = b""

                # 32MB chunks for maximum streaming performance on NVMe/SSD
                effective_chunk_size = max(self.chunk_size, 32 * 1024 * 1024)
                last_progress_print = 0

                while bytes_read < limit_size:
                    chunk = f.read(effective_chunk_size)
                    if not chunk:
                        break

                    current_buffer = prev_overlap + chunk
                    chunk_offset = bytes_read
                    bytes_read += len(chunk)

                    # Update progress
                    if progress_callback:
                        progress_callback(bytes_read, limit_size)
                    elif bytes_read - last_progress_print >= 256 * 1024 * 1024 or bytes_read >= limit_size:
                        last_progress_print = bytes_read
                        mb_read = bytes_read // (1024 * 1024)
                        mb_total = limit_size // (1024 * 1024)
                        pct = (bytes_read * 100) // max(1, limit_size)
                        print(f"    [*] [Memory Streamer] Processed {mb_read:,} MB / {mb_total:,} MB ({pct}%)...")

                    # 1. Hunt flags in this memory chunk
                    def _chunk_flag_cb(fl):
                        fl["context"] = f"[RAM Offset 0x{chunk_offset:x}] {fl.get('context', '')}"
                        if on_flag_found:
                            on_flag_found(fl)

                    flags = self.string_hunter.hunt_flags(
                        current_buffer,
                        early_stop=early_stop,
                        on_flag_found=_chunk_flag_cb if on_flag_found else None
                    )
                    for fl in flags:
                        fl["context"] = f"[RAM Offset 0x{chunk_offset:x}] {fl.get('context', '')}"
                        results["flags_found"].append(fl)

                    if early_stop and results["flags_found"]:
                        break

                    # 2. Extract Linux Kernel Banner if not yet found
                    if not results["kernel_banner"]:
                        m_kb = re.search(rb"Linux version ([0-9]+\.[0-9]+\.[0-9]+[^\x00\r\n]{5,150})", current_buffer)
                        if m_kb:
                            banner_str = m_kb.group(0).decode("latin-1", errors="ignore").strip()
                            results["kernel_banner"] = banner_str
                            print(f"    [+] Detected Kernel: \033[1;36m{banner_str}\033[0m")

                    # 3. Scrape Bash History / Terminal Commands
                    cmd_matches = re.findall(
                        rb"(?:^|[\x00\n])((?:sudo\s+|bash\s+|sh\s+|python[23]?\s+|curl\s+|wget\s+|ssh\s+|export\s+|cat\s+|nc\s+|ncat\s+|chmod\s+|chown\s+|nano\s+|vim\s+|grep\s+|tar\s+|7z\s+|unzip\s+|systemctl\s+|service\s+)[^\x00\r\n]{3,150})",
                        current_buffer
                    )
                    for cm in cmd_matches:
                        clean_cm = cm.decode("latin-1", errors="ignore").strip()
                        if clean_cm and clean_cm not in seen_commands:
                            seen_commands.add(clean_cm)
                            results["bash_commands"].append(clean_cm)

                    # 4. Scrape Environment Variables
                    env_matches = re.findall(
                        rb"(?:^|[\x00\n])([A-Z0-9_]{3,40}=[^\x00\r\n]{3,120})",
                        current_buffer
                    )
                    for em in env_matches:
                        clean_em = em.decode("latin-1", errors="ignore").strip()
                        if any(k in clean_em.upper() for k in ("FLAG", "PASS", "SECRET", "TOKEN", "KEY", "USER", "HOST", "ROOT", "AUTH")):
                            if clean_em not in seen_env:
                                seen_env.add(clean_em)
                                results["env_vars"].append(clean_em)

                    # 5. Scrape SSH & Private Keys in memory
                    key_matches = re.findall(
                        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[^-]+-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                        current_buffer
                    )
                    for km in key_matches:
                        key_str = km.decode("latin-1", errors="ignore").strip()
                        if key_str not in results["ssh_keys"]:
                            results["ssh_keys"].append(key_str)

                    # 6. Scrape in-memory scripts
                    script_matches = re.findall(
                        rb"(?:^|[\x00\n])(#!(?:/usr/bin/env python[23]?|/bin/bash|/bin/sh)[^\x00]{20,500})",
                        current_buffer
                    )
                    for sm in script_matches:
                        s_clean = sm.decode("latin-1", errors="ignore").strip()
                        if s_clean not in results["scripts_found"]:
                            results["scripts_found"].append(s_clean[:300])

                    # 7. Scrape Python/shell variable assignments that might hold the flag
                    flag_assign_matches = re.findall(
                        rb"(?:flag|secret|answer|key|token|password)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-\.\{\}]{6,120})['\"]?",
                        current_buffer,
                        re.IGNORECASE
                    )
                    for fa in flag_assign_matches:
                        fa_str = fa.decode("latin-1", errors="ignore").strip()
                        if fa_str and fa_str not in seen_commands:
                            seen_commands.add(fa_str)
                            results["bash_commands"].append(f"[VAR] {fa_str}")

                    # 8. Flag file references in memory (/tmp/flag, /root/flag.txt, etc.)
                    flag_file_matches = re.findall(
                        rb"(?:/tmp/flag|/root/flag|/home/\w+/flag|flag\.txt|secret\.txt|key\.txt)[^\x00\r\n]{0,60}",
                        current_buffer,
                        re.IGNORECASE
                    )
                    for ffm in flag_file_matches:
                        ff_str = ffm.decode("latin-1", errors="ignore").strip()
                        if ff_str and ff_str not in results["scripts_found"]:
                            results["scripts_found"].append(ff_str)


                    prev_overlap = chunk[-self.overlap:] if len(chunk) >= self.overlap else chunk


        except Exception as e:
            results["error"] = f"Streaming memory error: {str(e)}"

        return results

    def scan_raw_framebuffer(
        self,
        filepath_or_data,
        output_dir: Optional[str] = None,
        widths: Tuple[int, ...] = (1920, 1366, 1280, 1024),
        height: int = 120,
        max_frames: int = 5
    ) -> Dict[str, Any]:
        """
        GIMP Raw Memory Dump Visual Inspection (INShAck 2018):
        - Scans memory dump for framebuffer desktop/browser pixel data.
        - Analyzes pixel variance to find non-zero, non-noise candidate frames.
        - Exports recovered candidate frames as uncompressed 24-bit BMP images (pure Python).
        """
        results: Dict[str, Any] = {
            "candidate_frames": [],
            "saved_images": []
        }

        data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            try:
                with open(filepath_or_data, "rb") as f:
                    data = f.read(100 * 1024 * 1024)
            except Exception:
                return results
        elif isinstance(filepath_or_data, bytes):
            data = filepath_or_data[:100 * 1024 * 1024]
        else:
            return results

        out_dir = output_dir or "extracted_artifacts"
        os.makedirs(out_dir, exist_ok=True)

        for width in widths:
            row_size = width * 3
            frame_size = row_size * height
            step = frame_size * 2

            for off in range(0, len(data) - frame_size + 1, step):
                chunk = data[off:off + frame_size]
                if len(chunk) < frame_size:
                    break

                sample = chunk[::max(1, len(chunk) // 500)]
                mean = sum(sample) / len(sample)
                variance = sum((x - mean) ** 2 for x in sample) / len(sample)
                std = variance ** 0.5

                if 20 < mean < 235 and std > 25:
                    bmp_name = f"framebuffer_w{width}_off0x{off:x}.bmp"
                    bmp_path = os.path.join(out_dir, bmp_name)

                    pad_bytes = (4 - (row_size % 4)) % 4
                    img_bytes_total = (row_size + pad_bytes) * height
                    file_size = 54 + img_bytes_total

                    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
                    dib_header = struct.pack("<IIIHHIIIIII", 40, width, height, 1, 24, 0, img_bytes_total, 2835, 2835, 0, 0)

                    pixel_data = bytearray()
                    for r in range(height - 1, -1, -1):
                        r_start = r * row_size
                        r_slice = chunk[r_start:r_start + row_size]
                        for c in range(0, len(r_slice), 3):
                            p = r_slice[c:c + 3]
                            if len(p) == 3:
                                pixel_data.extend([p[2], p[1], p[0]])
                        if pad_bytes:
                            pixel_data.extend(b"\x00" * pad_bytes)

                    try:
                        with open(bmp_path, "wb") as bf:
                            bf.write(file_header + dib_header + bytes(pixel_data))
                        results["saved_images"].append(bmp_path)
                        results["candidate_frames"].append({
                            "width": width,
                            "height": height,
                            "offset": off,
                            "path": bmp_path,
                            "mean": round(mean, 1),
                            "std": round(std, 1)
                        })
                    except Exception:
                        pass

                    if len(results["candidate_frames"]) >= max_frames:
                        return results

        return results

