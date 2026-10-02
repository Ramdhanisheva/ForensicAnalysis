"""
Automotion Forensics - AccessData FTK AD1 Image Parser
Parses AD1 container headers, extracts file table entries,
and streams decompressed zlib data chunks to hunt for flags and credentials.
"""

import os
import re
import struct
import zlib
from typing import Any, Dict, List, Optional

from core.string_hunter import StringHunter


class AD1Parser:
    """Parses AccessData AD1 logical forensic images without requiring FTK Imager GUI."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def is_ad1(self, header_bytes: bytes) -> bool:
        """Check if file starts with AD1 signature."""
        return header_bytes.startswith(b"ADSEGMENTEDFILE") or header_bytes.startswith(b"AD1\x00") or b"ADSEGMENTED" in header_bytes[:32]

    # Keywords that are always suspicious regardless of location in the image
    SENSITIVE_KEYWORDS = (
        "flag", "secret", "pass", "key", "token", "cred",
        "shadow", "sam", "ntuser.dat",
        ".kdbx", ".gpg", ".enc", ".pfx", ".p12",
        "id_rsa", "id_ed25519", "authorized_keys",
        ".bash_history", "consolehost_history",
        "memory.lime", "dump", "loot", "exfil",
        "mimikatz", "procdump", "wce.exe", "pwdump",
    )

    def parse(self, filepath: str, max_scan_bytes: int = 50 * 1024 * 1024) -> Dict[str, Any]:
        """
        Parse AD1 image:
        - Extract metadata & segment info
        - Decompress zlib blocks and grep strings
        - Scan ALL file paths: Users/, /root, /etc, /tmp, /var, C:\\Windows, admin dirs
        """
        results: Dict[str, Any] = {
            "source": filepath,
            "format": "AccessData FTK AD1 Logical Image",
            "is_valid_ad1": False,
            "users_detected": [],
            "user_artifacts": {},
            "suspicious_artifacts": [],
            "discovered_paths": [],
            "flags_found": [],
            "suspicious_patterns": {},
            "decompressed_chunks": 0
        }

        if not os.path.exists(filepath):
            results["error"] = "File not found"
            return results

        file_size = os.path.getsize(filepath)
        results["file_size_bytes"] = file_size

        try:
            with open(filepath, "rb") as f:
                header = f.read(1024)
                if not self.is_ad1(header):
                    results["error"] = "Not a recognized AD1 image signature"
                    return results

                results["is_valid_ad1"] = True

                # Fast scan: hunt for ALL paths in the image directory index (UTF-16LE and ASCII)
                f.seek(0)
                scan_buf = f.read(min(file_size, 10 * 1024 * 1024))
                text_sources = [
                    scan_buf.decode("latin-1", errors="ignore"),
                    scan_buf.decode("utf-16le", errors="ignore")
                ]
                users_set = set()
                user_files: Dict[str, List[str]] = {}
                suspicious_files = []

                # User paths pattern (Windows Users\ and Unix /home/)
                user_pattern = re.compile(
                    r"(?:[A-Za-z]:[\\/]|/)(?:Users|home)[\\/]([A-Za-z0-9_\-\.]+)[\\/]([A-Za-z0-9_\-\.\\/\s]{2,120})",
                    re.IGNORECASE
                )
                # Broad ALL-filesystem path pattern:
                # - Windows: C:\anything
                # - Unix root dirs: /root, /etc, /tmp, /var, /opt, /srv, /home, /usr, /bin, /sbin, /lib
                path_pattern = re.compile(
                    r"(?:"
                    r"[A-Za-z]:\\[A-Za-z0-9_\-\.\\ ]{3,120}"
                    r"|/(?:root|etc|tmp|var|opt|home|srv|mnt|proc|dev|usr|bin|sbin|lib)[/A-Za-z0-9_\-\.]{1,100}"
                    r")"
                )

                for src in text_sources:
                    # User-specific paths
                    for u_match in user_pattern.finditer(src):
                        uname, subpath = u_match.group(1), u_match.group(2)
                        if len(uname) >= 2 and uname.lower() not in ("public", "default", "all users"):
                            users_set.add(uname)
                            if uname not in user_files:
                                user_files[uname] = []
                            clean_sub = subpath.split("\x00")[0].split("\r")[0].split("\n")[0].strip()
                            full_user_path = f"Users/{uname}/{clean_sub}"
                            if clean_sub and full_user_path not in user_files[uname]:
                                user_files[uname].append(full_user_path)
                            if any(k in clean_sub.lower() for k in self.SENSITIVE_KEYWORDS):
                                if full_user_path not in suspicious_files:
                                    suspicious_files.append(full_user_path)

                    # ALL filesystem paths (root, system, admin dirs included)
                    for p_match in path_pattern.finditer(src):
                        raw_p = p_match.group(0)
                        clean_p = raw_p.split("\x00")[0].split("\r")[0].split("\n")[0].strip()
                        if len(clean_p) < 4:
                            continue
                        if clean_p not in results["discovered_paths"]:
                            results["discovered_paths"].append(clean_p)
                        if any(k in clean_p.lower() for k in self.SENSITIVE_KEYWORDS):
                            if clean_p not in suspicious_files:
                                suspicious_files.append(clean_p)

                results["users_detected"] = sorted(list(users_set))
                results["user_artifacts"] = user_files
                results["suspicious_artifacts"] = suspicious_files

                # Streaming decompression: AD1 stores logical data in zlib streams (RFC 1950 headers: 0x7801, 0x789c, 0x78da)
                f.seek(0)
                bytes_processed = 0
                while bytes_processed < file_size and bytes_processed < max_scan_bytes:
                    chunk = f.read(1024 * 1024)  # 1MB buffer
                    if not chunk:
                        break

                    # Scan for zlib header (0x78 0x9c or 0x78 0x01 or 0x78 0xda)
                    zlib_pos = 0
                    while True:
                        idx = chunk.find(b"\x78\x9c", zlib_pos)
                        if idx == -1:
                            idx = chunk.find(b"\x78\x01", zlib_pos)
                        if idx == -1:
                            break

                        try:
                            # Attempt standard zlib decompress, fallback to raw deflate
                            try:
                                decompressed = zlib.decompress(chunk[idx:idx + 65536])
                            except Exception:
                                decompressed = zlib.decompress(chunk[idx:idx + 65536], -15)

                            results["decompressed_chunks"] += 1
                            
                            # Hunt flags in decompressed buffer
                            flags = self.string_hunter.hunt_flags(decompressed)
                            for fl in flags:
                                fl["context"] = f"[AD1 Offset 0x{bytes_processed + idx:x}] {fl['context']}"
                                results["flags_found"].append(fl)

                            sus = self.string_hunter.hunt_suspicious_patterns(decompressed, limit_per_type=2)
                            for k, v in sus.items():
                                if k not in results["suspicious_patterns"]:
                                    results["suspicious_patterns"][k] = []
                                results["suspicious_patterns"][k].extend(v)

                        except Exception:
                            pass

                        zlib_pos = idx + 2

                    # Also grep raw uncompressed strings in this chunk
                    raw_flags = self.string_hunter.hunt_flags(chunk)
                    for fl in raw_flags:
                        fl["context"] = f"[AD1 Raw 0x{bytes_processed:x}] {fl['context']}"
                        results["flags_found"].append(fl)

                    bytes_processed += len(chunk)

        except Exception as e:
            results["error"] = f"AD1 parsing error: {str(e)}"

        return results
