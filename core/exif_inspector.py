"""
Automotion Forensics - Exif & Metadata Inspector
Inspects Exif, image comments, GPS coordinates, PDF metadata, and Office XML tags.
Pure-Python parser with automated ExifTool fallback if installed.
"""

import json
import os
import re
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Dict, List, Optional


def to_wsl_path(win_path: str) -> str:
    """Convert Windows path to WSL /mnt/<drive>/... path."""
    abs_p = os.path.abspath(win_path)
    drive, rest = os.path.splitdrive(abs_p)
    if drive:
        return f"/mnt/{drive[0].lower()}" + rest.replace("\\", "/")
    return rest.replace("\\", "/")


class ExifInspector:
    """Extracts metadata, comments, and GPS coordinates from multiple file formats."""

    def __init__(self):
        self.has_exiftool = shutil.which("exiftool") is not None
        self.exiftool_cmd = ["exiftool"] if self.has_exiftool else None

        if not self.has_exiftool:
            try:
                proc = subprocess.run(["wsl", "-d", "kali-linux", "which", "exiftool"], capture_output=True, text=True, timeout=8)
                if proc.returncode == 0 and "exiftool" in proc.stdout:
                    self.has_exiftool = True
                    self.exiftool_cmd = ["wsl", "-d", "kali-linux", "exiftool"]
            except Exception:
                pass

    def inspect(self, filepath: str, data: Optional[bytes] = None) -> Dict[str, Any]:
        """Inspect file metadata using native parsers or exiftool."""
        results: Dict[str, Any] = {
            "source": filepath,
            "tool_used": "native_python",
            "metadata": {},
            "gps": None,
            "comments": [],
            "flags_found": [],
            "candidate_keys": []
        }

        # 1. Try ExifTool if installed
        if self.has_exiftool and os.path.exists(filepath):
            try:
                target_p = to_wsl_path(filepath) if (self.exiftool_cmd and self.exiftool_cmd[0] == "wsl") else filepath
                proc = subprocess.run(
                    self.exiftool_cmd + ["-j", target_p],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    tool_json = json.loads(proc.stdout)
                    if tool_json and isinstance(tool_json, list):
                        results["metadata"] = tool_json[0]
                        results["tool_used"] = "exiftool"
                        self._extract_gps_from_dict(results)
                        self._process_metadata_findings(results)
                        return results
            except Exception:
                pass

        # 2. Pure Python fallback
        if data is None and os.path.exists(filepath):
            try:
                with open(filepath, "rb") as f:
                    data = f.read(5 * 1024 * 1024)  # Read up to 5MB for metadata
            except Exception:
                return results

        if not data:
            return results

        if data.startswith(b"\xff\xd8\xff"):
            self._parse_jpeg_metadata(data, results)
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            self._parse_png_metadata(data, results)
        elif data.startswith(b"%PDF-"):
            self._parse_pdf_metadata(data, results)
        elif data.startswith(b"PK\x03\x04"):
            self._parse_office_metadata(filepath, results)

        self._extract_gps_from_dict(results)
        self._process_metadata_findings(results)
        return results

    def _process_metadata_findings(self, results: Dict[str, Any]):
        """
        Deep analysis of all metadata values and comments:
        - Detects flags
        - Decodes Base64 payloads (and searches for inner flags/keys)
        - Decodes Hex strings
        - Extracts candidate passphrases/keys for steghide, zip, and binwalk
        """
        import base64
        import re
        import config

        flag_patterns = config.FLAG_PATTERNS
        results.setdefault("flags_found", [])
        results.setdefault("candidate_keys", [])
        keys_set = set(results["candidate_keys"])
        flags_set = set()

        strings_to_check = list(results.get("comments", []))
        for k, v in results.get("metadata", {}).items():
            if isinstance(v, str):
                strings_to_check.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        strings_to_check.append(item)

        for s in strings_to_check:
            s_clean = s.strip()
            if not s_clean:
                continue

            # 1. Check for flags
            for pat in flag_patterns:
                for m in pat.finditer(s_clean):
                    fl = m.group(0).strip()
                    if fl not in flags_set:
                        flags_set.add(fl)
                        results["flags_found"].append({"flag": fl, "encoding": "EXIF/Metadata"})

            # 2. Extract potential passphrases / keys
            if 3 <= len(s_clean) <= 64 and not s_clean.startswith("{") and "\n" not in s_clean:
                keys_set.add(s_clean)

            # Check for patterns like key=XYZ, pass: XYZ, password: XYZ, passphrase: XYZ
            m_key = re.findall(r"(?:key|passphrase|password|pass|secret|token)\s*[:=]\s*([^\s,;]+)", s_clean, re.IGNORECASE)
            for k in m_key:
                keys_set.add(k.strip())

            # Also harvest word tokens from comments/descriptions
            for word in s_clean.split():
                w_clean = word.strip(":,;'\"(){}[]")
                if 4 <= len(w_clean) <= 40 and any(c.isalnum() for c in w_clean):
                    keys_set.add(w_clean)

            # 3. Check for Base64 strings in metadata
            b64_cands = re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", s_clean)
            for b64_str in b64_cands:
                try:
                    pad = (4 - len(b64_str) % 4) % 4
                    dec = base64.b64decode(b64_str + "=" * pad)
                    dec_text = dec.decode("latin-1", errors="ignore").strip()

                    for pat in flag_patterns:
                        for m in pat.finditer(dec_text):
                            fl = m.group(0).strip()
                            if fl not in flags_set:
                                flags_set.add(fl)
                                results["flags_found"].append({"flag": fl, "encoding": f"EXIF Base64 ({b64_str})"})

                    # Extract key patterns from decoded text
                    m_dec_keys = re.findall(r"(?:key|pass|password|secret|token)\s*[:=]\s*([^\s,;]+)", dec_text, re.IGNORECASE)
                    for k in m_dec_keys:
                        keys_set.add(k.strip())

                    if 3 <= len(dec_text) <= 80 and all(32 <= ord(c) <= 126 for c in dec_text):
                        keys_set.add(dec_text)
                except Exception:
                    pass

            # 4. Check for Hex strings in metadata
            hex_cands = re.findall(r"\b[0-9a-fA-F]{8,}\b", s_clean)
            for h_str in hex_cands:
                if len(h_str) % 2 == 0:
                    try:
                        dec_hex = bytes.fromhex(h_str).decode("latin-1", errors="ignore").strip()
                        for pat in flag_patterns:
                            for m in pat.finditer(dec_hex):
                                fl = m.group(0).strip()
                                if fl not in flags_set:
                                    flags_set.add(fl)
                                    results["flags_found"].append({"flag": fl, "encoding": f"EXIF Hex ({h_str[:20]})"})
                        m_hex_keys = re.findall(r"(?:key|pass|password|secret|token)\s*[:=]\s*([^\s,;]+)", dec_hex, re.IGNORECASE)
                        for k in m_hex_keys:
                            keys_set.add(k.strip())
                        if 3 <= len(dec_hex) <= 80 and all(32 <= ord(c) <= 126 for c in dec_hex):
                            keys_set.add(dec_hex)
                    except Exception:
                        pass

        results["candidate_keys"] = sorted(list(keys_set))

    def _parse_jpeg_metadata(self, data: bytes, results: Dict[str, Any]):
        """Parse JPEG markers: APP1 (Exif), COM (Comment), etc."""
        pos = 2
        while pos < len(data) - 4:
            if data[pos] != 0xff:
                break
            marker = data[pos + 1]
            pos += 2
            if marker in (0xd8, 0xd9, 0x00):  # SOI, EOI, Escaped
                continue
            if marker in (0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7):  # RST
                continue

            length = struct.unpack(">H", data[pos:pos + 2])[0]
            marker_data = data[pos + 2:pos + length]
            pos += length

            # COM marker (Comment)
            if marker == 0xfe:
                comment = marker_data.decode("latin-1", errors="ignore").strip()
                results["comments"].append(comment)
                results["metadata"]["JPEG_Comment"] = comment

            # APP1 marker (Exif)
            elif marker == 0xe1:
                if marker_data.startswith(b"Exif\x00\x00"):
                    tiff_data = marker_data[6:]
                    self._parse_tiff_ifd(tiff_data, results)

    def _parse_tiff_ifd(self, tiff_data: bytes, results: Dict[str, Any]):
        """Parse TIFF Header and IFD0 tags."""
        if len(tiff_data) < 8:
            return
        endian = tiff_data[:2]
        fmt_char = "<" if endian == b"II" else ">" if endian == b"MM" else None
        if not fmt_char:
            return

        magic = struct.unpack(f"{fmt_char}H", tiff_data[2:4])[0]
        if magic != 42:
            return

        ifd_offset = struct.unpack(f"{fmt_char}I", tiff_data[4:8])[0]
        if ifd_offset >= len(tiff_data):
            return

        num_entries = struct.unpack(f"{fmt_char}H", tiff_data[ifd_offset:ifd_offset + 2])[0]
        curr = ifd_offset + 2

        tag_names = {
            0x010e: "ImageDescription",
            0x010f: "Make",
            0x0110: "Model",
            0x0131: "Software",
            0x0132: "DateTime",
            0x013b: "Artist",
            0x8298: "Copyright",
            0x9286: "UserComment",
            0x9c9b: "XPTitle",
            0x9c9c: "XPComment",
            0x9c9d: "XPAuthor",
            0x8825: "GPSInfoIFDPointer"
        }

        for _ in range(num_entries):
            if curr + 12 > len(tiff_data):
                break
            tag, tag_type, count, val_or_offset = struct.unpack(f"{fmt_char}HHI I", tiff_data[curr:curr + 12])
            curr += 12

            name = tag_names.get(tag, f"Tag_0x{tag:04x}")
            # Ascii string
            if tag_type == 2:
                if count <= 4:
                    val = struct.pack(f"{fmt_char}I", val_or_offset)[:count].decode("latin-1", errors="ignore").rstrip("\x00")
                else:
                    if val_or_offset + count <= len(tiff_data):
                        val = tiff_data[val_or_offset:val_or_offset + count].decode("latin-1", errors="ignore").rstrip("\x00")
                    else:
                        val = str(val_or_offset)
                results["metadata"][name] = val
                if "comment" in name.lower() or "description" in name.lower():
                    results["comments"].append(val)

    def _parse_png_metadata(self, data: bytes, results: Dict[str, Any]):
        """Parse PNG tEXt, zTXt, iTXt chunks."""
        pos = 8
        try:
            while pos < len(data) - 8:
                length = struct.unpack(">I", data[pos:pos + 4])[0]
                chunk_type = data[pos + 4:pos + 8].decode("latin-1", errors="ignore")
                if chunk_type == "IEND":
                    break
                if pos + 8 + length > len(data):
                    break
                chunk_data = data[pos + 8:pos + 8 + length]
                pos += 12 + length  # len + type + data + crc

                if chunk_type in ("tEXt", "zTXt", "iTXt"):
                    if b"\x00" in chunk_data:
                        k, v = chunk_data.split(b"\x00", 1)
                        key = k.decode("latin-1", errors="ignore")
                        val = v.decode("latin-1", errors="ignore")
                        results["metadata"][f"PNG_{key}"] = val
                        results["comments"].append(f"{key}: {val}")
        except Exception:
            pass

    def _parse_pdf_metadata(self, data: bytes, results: Dict[str, Any]):
        """Extract metadata from PDF header/trailer info dictionaries."""
        text = data[:50000].decode("latin-1", errors="ignore") + data[-50000:].decode("latin-1", errors="ignore")
        fields = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"]
        for f in fields:
            match = re.search(rf"/{f}\s*\((.*?)\)", text)
            if match:
                results["metadata"][f"PDF_{f}"] = match.group(1)

    def _parse_office_metadata(self, filepath: str, results: Dict[str, Any]):
        """Extract OpenXML docProps/core.xml metadata."""
        if not os.path.exists(filepath):
            return
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                if "docProps/core.xml" in zf.namelist():
                    xml_content = zf.read("docProps/core.xml")
                    root = ET.fromstring(xml_content)
                    for elem in root.iter():
                        tag_clean = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                        if elem.text and elem.text.strip():
                            results["metadata"][f"Doc_{tag_clean}"] = elem.text.strip()
        except Exception:
            pass

    def _extract_gps_from_dict(self, results: Dict[str, Any]):
        """Format GPS coordinates if present."""
        md = results.get("metadata", {})
        lat = md.get("GPSLatitude")
        lon = md.get("GPSLongitude")
        if lat and lon:
            results["gps"] = {
                "latitude": str(lat),
                "longitude": str(lon),
                "google_maps": f"https://www.google.com/maps?q={lat},{lon}"
            }
