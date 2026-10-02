"""
Automotion Forensics - Exif & Metadata Inspector
Inspects Exif, image comments, GPS coordinates, PDF metadata, and Office XML tags.
Pure-Python parser with automated ExifTool fallback if installed.
Supports deep UserComment/tag deobfuscation (XOR, ROT13, Base64, Hex, Zlib, embedded ZIP)
and embedded thumbnail/preview binary extraction.
"""

import base64
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Set, Tuple

import config
from core.string_hunter import StringHunter


def to_wsl_path(win_path: str) -> str:
    """Convert Windows path to WSL /mnt/<drive>/... path."""
    abs_p = os.path.abspath(win_path)
    drive, rest = os.path.splitdrive(abs_p)
    if drive:
        return f"/mnt/{drive[0].lower()}" + rest.replace("\\", "/")
    return rest.replace("\\", "/")


class ExifInspector:
    """Extracts metadata, comments, GPS coordinates, and embedded thumbnail binaries."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "results"
        self.string_hunter = StringHunter()
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
            "candidate_keys": [],
            "extracted_thumbnails": [],
            "decrypted_comments": []
        }

        # 1. Try ExifTool with deep flags (-j -u -a -G)
        if self.has_exiftool and os.path.exists(filepath):
            try:
                target_p = to_wsl_path(filepath) if (self.exiftool_cmd and self.exiftool_cmd[0] == "wsl") else filepath
                proc = subprocess.run(
                    self.exiftool_cmd + ["-j", "-u", "-a", "-G", target_p],
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
                        self._extract_thumbnails(filepath, data, results)
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
        self._extract_thumbnails(filepath, data, results)
        self._process_metadata_findings(results)
        return results

    def _extract_thumbnails(self, filepath: str, data: Optional[bytes], results: Dict[str, Any]):
        """
        Extract embedded thumbnails or preview images:
        - ExifTool binary export (-ThumbnailImage, -PreviewImage, -JpgFromRaw)
        - Pure-Python IFD1 JPEGInterchangeFormat (0x0201/0x0202)
        - Embedded SOI markers inside APP1/APP2
        """
        out_folder = self.output_dir or os.path.dirname(filepath) or "."
        os.makedirs(out_folder, exist_ok=True)
        base_name = os.path.splitext(os.path.basename(filepath))[0]
        results.setdefault("extracted_thumbnails", [])

        # Method 1: ExifTool binary export if available
        if self.has_exiftool and os.path.exists(filepath):
            target_p = to_wsl_path(filepath) if (self.exiftool_cmd and self.exiftool_cmd[0] == "wsl") else filepath
            for tag_name in ["ThumbnailImage", "PreviewImage", "JpgFromRaw", "OtherImage"]:
                try:
                    cmd = self.exiftool_cmd + ["-b", f"-{tag_name}", target_p]
                    proc = subprocess.run(cmd, capture_output=True, timeout=8)
                    thumb_bytes = proc.stdout
                    if thumb_bytes and len(thumb_bytes) > 64:
                        ext = "jpg"
                        if thumb_bytes.startswith(b"\x89PNG"):
                            ext = "png"
                        elif thumb_bytes.startswith(b"PK\x03\x04"):
                            ext = "zip"
                        elif thumb_bytes.startswith(b"7z\xbc\xaf"):
                            ext = "7z"
                        elif thumb_bytes.startswith(b"BM"):
                            ext = "bmp"
                        elif not thumb_bytes.startswith(b"\xff\xd8\xff"):
                            ext = "bin"

                        out_path = os.path.join(out_folder, f"exif_{tag_name.lower()}_{base_name}.{ext}")
                        with open(out_path, "wb") as f_out:
                            f_out.write(thumb_bytes)

                        results["extracted_thumbnails"].append({
                            "type": tag_name,
                            "path": out_path,
                            "size": len(thumb_bytes),
                            "format": ext
                        })

                        # Run StringHunter on extracted thumbnail
                        for fl in self.string_hunter.hunt_flags(thumb_bytes):
                            fl["encoding"] = f"EXIF {tag_name} ({fl['encoding']})"
                            results["flags_found"].append(fl)

                        # If thumbnail is a ZIP/7z, unpack it!
                        if ext in ("zip", "7z"):
                            try:
                                from core.archive_unpacker import ArchiveUnpacker
                                unpacker = ArchiveUnpacker(out_folder)
                                sub_unp = os.path.join(out_folder, f"unpacked_thumb_{tag_name}")
                                arch_res = unpacker.unpack(out_path, sub_unp, candidate_passwords=results.get("candidate_keys", []))
                                if arch_res.get("success"):
                                    for ef in arch_res.get("extracted_files", []):
                                        try:
                                            with open(ef["path"], "rb") as eff:
                                                edata = eff.read(10 * 1024 * 1024)
                                                for fl in self.string_hunter.hunt_flags(edata):
                                                    fl["encoding"] = f"EXIF {tag_name} Archive ({ef['filename']})"
                                                    results["flags_found"].append(fl)
                                        except Exception:
                                            pass
                            except Exception:
                                pass
                except Exception:
                    pass

        # Method 2: Pure-Python IFD1 Thumbnail extraction
        if not results["extracted_thumbnails"] and data:
            try:
                self._extract_python_thumbnail(data, out_folder, base_name, results)
            except Exception:
                pass

    def _extract_python_thumbnail(self, data: bytes, out_folder: str, base_name: str, results: Dict[str, Any]):
        """Pure-Python extraction of IFD1 thumbnail from JPEG APP1."""
        if not data.startswith(b"\xff\xd8\xff"):
            return

        pos = 2
        while pos < len(data) - 4:
            if data[pos] != 0xff:
                break
            marker = data[pos + 1]
            pos += 2
            if marker in (0xd8, 0xd9, 0x00) or marker in range(0xd0, 0xd8):
                continue

            length = struct.unpack(">H", data[pos:pos + 2])[0]
            marker_data = data[pos + 2:pos + length]
            pos += length

            if marker == 0xe1 and marker_data.startswith(b"Exif\x00\x00"):
                tiff_data = marker_data[6:]
                if len(tiff_data) < 8:
                    continue
                endian = tiff_data[:2]
                fmt_char = "<" if endian == b"II" else ">" if endian == b"MM" else None
                if not fmt_char:
                    continue

                ifd_offset = struct.unpack(f"{fmt_char}I", tiff_data[4:8])[0]
                if ifd_offset >= len(tiff_data):
                    continue

                num_entries = struct.unpack(f"{fmt_char}H", tiff_data[ifd_offset:ifd_offset + 2])[0]
                curr = ifd_offset + 2 + num_entries * 12
                if curr + 4 <= len(tiff_data):
                    ifd1_offset = struct.unpack(f"{fmt_char}I", tiff_data[curr:curr + 4])[0]
                    if ifd1_offset > 0 and ifd1_offset + 2 <= len(tiff_data):
                        num_ifd1 = struct.unpack(f"{fmt_char}H", tiff_data[ifd1_offset:ifd1_offset + 2])[0]
                        curr_ifd1 = ifd1_offset + 2
                        thumb_offset = None
                        thumb_length = None
                        for _ in range(num_ifd1):
                            if curr_ifd1 + 12 > len(tiff_data):
                                break
                            tag, _, _, val = struct.unpack(f"{fmt_char}HHI I", tiff_data[curr_ifd1:curr_ifd1 + 12])
                            curr_ifd1 += 12
                            if tag == 0x0201:
                                thumb_offset = val
                            elif tag == 0x0202:
                                thumb_length = val

                        if thumb_offset and thumb_length and thumb_offset + thumb_length <= len(tiff_data):
                            thumb_bytes = tiff_data[thumb_offset:thumb_offset + thumb_length]
                            ext = "jpg" if thumb_bytes.startswith(b"\xff\xd8\xff") else "bin"
                            out_path = os.path.join(out_folder, f"exif_thumbnail_{base_name}.{ext}")
                            with open(out_path, "wb") as f_out:
                                f_out.write(thumb_bytes)
                            results["extracted_thumbnails"].append({
                                "type": "IFD1_Thumbnail",
                                "path": out_path,
                                "size": len(thumb_bytes),
                                "format": ext
                            })
                            for fl in self.string_hunter.hunt_flags(thumb_bytes):
                                fl["encoding"] = f"EXIF IFD1 Thumbnail ({fl['encoding']})"
                                results["flags_found"].append(fl)

    def _process_metadata_findings(self, results: Dict[str, Any]):
        """
        Deep multi-channel analysis across all metadata values and comments:
        - Plaintext flags
        - Deobfuscate UserComment, XPComment, MakerNotes
        - Single-byte XOR (1..255)
        - Multi-byte repeating XOR with CTF wordlist
        - Base64 / Hex / Base32 / Base85 / ROT13 / Caesar
        - Zlib / Gzip decompression
        - Embedded ZIP carving
        - Password harvesting
        """
        results.setdefault("flags_found", [])
        results.setdefault("candidate_keys", [])
        results.setdefault("decrypted_comments", [])

        keys_set = set(results["candidate_keys"])
        items_to_check = []

        for c in results.get("comments", []):
            items_to_check.append(("Comment", c))

        for k, v in results.get("metadata", {}).items():
            if isinstance(v, (str, bytes)):
                items_to_check.append((str(k), v))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, (str, bytes)):
                        items_to_check.append((str(k), item))

        for tag_name, val in items_to_check:
            self._deep_deobfuscate_tag(tag_name, val, results, keys_set)

        results["candidate_keys"] = sorted(list(keys_set))

    def _deep_deobfuscate_tag(self, tag_name: str, val: Any, results: Dict[str, Any], keys_set: Set[str]):
        """Perform deep multi-encoding inspection on a single tag value."""
        if val is None:
            return

        raw_bytes = b""
        raw_str = ""

        if isinstance(val, bytes):
            raw_bytes = val
            raw_str = val.decode("latin-1", errors="ignore")
        elif isinstance(val, str):
            raw_str = val.strip()
            raw_bytes = val.encode("latin-1", errors="ignore")
        else:
            raw_str = str(val).strip()
            raw_bytes = raw_str.encode("latin-1", errors="ignore")

        if not raw_bytes:
            return

        # 1. Clean UserComment headers
        payload_bytes = raw_bytes
        if "usercomment" in tag_name.lower():
            if raw_bytes.startswith(b"ASCII\x00\x00\x00"):
                payload_bytes = raw_bytes[8:]
            elif raw_bytes.startswith(b"UNICODE\x00"):
                payload_bytes = raw_bytes[8:]
                try:
                    raw_str = payload_bytes.decode("utf-16le", errors="ignore")
                except Exception:
                    pass
            elif raw_bytes.startswith(b"\x00\x00\x00\x00\x00\x00\x00\x00"):
                payload_bytes = raw_bytes[8:]

        # 2. Run StringHunter (Plaintext, B64, Hex, Single-byte XOR 1..255, ROT13, Reverse, Morse)
        for fl in self.string_hunter.hunt_flags(payload_bytes):
            fl["encoding"] = f"EXIF {tag_name} ({fl['encoding']})"
            results["flags_found"].append(fl)

        # 3. Multi-byte repeating XOR brute-force
        ctf_keys = [b"ctf", b"CTF", b"flag", b"FLAG", b"key", b"pass", b"admin", b"hacktoday", b"HackToday", b"secret", b"lobster"]
        for k in ctf_keys:
            if len(payload_bytes) >= len(k):
                try:
                    dec = bytes([payload_bytes[i] ^ k[i % len(k)] for i in range(len(payload_bytes))])
                    for fl in self.string_hunter.hunt_flags(dec):
                        fl["encoding"] = f"EXIF {tag_name} Repeating XOR [{k.decode(errors='ignore')}] ({fl['encoding']})"
                        results["flags_found"].append(fl)
                        results["decrypted_comments"].append({
                            "tag": tag_name,
                            "method": f"Repeating XOR [{k.decode(errors='ignore')}]",
                            "value": fl["flag"]
                        })
                except Exception:
                    pass

        # 4. Check for Hex-encoded strings (4861636b... or 0x48, 0x61...)
        hex_cands = re.findall(r"\b(?:0x)?[0-9a-fA-F]{8,}\b", raw_str)
        for hc in hex_cands:
            clean_h = hc.replace("0x", "").replace(" ", "").replace(",", "")
            if len(clean_h) % 2 == 0:
                try:
                    h_bytes = bytes.fromhex(clean_h)
                    for fl in self.string_hunter.hunt_flags(h_bytes):
                        fl["encoding"] = f"EXIF Hex ({fl['encoding']})"
                        results["flags_found"].append(fl)
                    # XOR on decoded hex bytes
                    for key in range(1, 256):
                        xored = bytes([b ^ key for b in h_bytes])
                        for fl in self.string_hunter.hunt_flags(xored):
                            fl["encoding"] = f"EXIF Hex+XOR 0x{key:02x} ({fl['encoding']})"
                            results["flags_found"].append(fl)
                except Exception:
                    pass

        # 5. Check for Base64 strings
        b64_cands = re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", raw_str)
        for b64_s in b64_cands:
            try:
                pad = (4 - len(b64_s) % 4) % 4
                dec_b64 = base64.b64decode(b64_s + "=" * pad)
                for fl in self.string_hunter.hunt_flags(dec_b64):
                    fl["encoding"] = f"EXIF Base64 ({fl['encoding']})"
                    results["flags_found"].append(fl)
                # XOR on decoded base64 bytes
                for key in range(1, 256):
                    xored = bytes([b ^ key for b in dec_b64])
                    for fl in self.string_hunter.hunt_flags(xored):
                        fl["encoding"] = f"EXIF Base64+XOR 0x{key:02x} ({fl['encoding']})"
                        results["flags_found"].append(fl)
            except Exception:
                pass

        # 6. Check for Compressed Streams (zlib / gzip)
        if payload_bytes.startswith((b"\x78\x9c", b"\x78\x01", b"\x78\xda")):
            try:
                decomp = zlib.decompress(payload_bytes)
                for fl in self.string_hunter.hunt_flags(decomp):
                    fl["encoding"] = f"EXIF {tag_name} Zlib ({fl['encoding']})"
                    results["flags_found"].append(fl)
            except Exception:
                pass
        elif payload_bytes.startswith(b"\x1f\x8b\x08"):
            try:
                decomp = gzip.decompress(payload_bytes)
                for fl in self.string_hunter.hunt_flags(decomp):
                    fl["encoding"] = f"EXIF {tag_name} Gzip ({fl['encoding']})"
                    results["flags_found"].append(fl)
            except Exception:
                pass

        # 7. Check for Embedded ZIP inside tag
        if b"PK\x03\x04" in payload_bytes:
            pk_idx = payload_bytes.find(b"PK\x03\x04")
            zip_cand = payload_bytes[pk_idx:]
            out_folder = self.output_dir or "."
            safe_tag = re.sub(r"[^a-zA-Z0-9_]", "_", tag_name)
            zip_out = os.path.join(out_folder, f"exif_{safe_tag.lower()}_carved.zip")
            try:
                with open(zip_out, "wb") as zf:
                    zf.write(zip_cand)
                from core.archive_unpacker import ArchiveUnpacker
                unp = ArchiveUnpacker(out_folder)
                unp_res = unp.unpack(zip_out, os.path.join(out_folder, f"unpacked_exif_{safe_tag.lower()}"))
                if unp_res.get("success"):
                    for ef in unp_res.get("extracted_files", []):
                        try:
                            with open(ef["path"], "rb") as eff:
                                for fl in self.string_hunter.hunt_flags(eff.read(10 * 1024 * 1024)):
                                    fl["encoding"] = f"EXIF {tag_name} ZIP ({ef['filename']})"
                                    results["flags_found"].append(fl)
                        except Exception:
                            pass
            except Exception:
                pass

        # 8. Harvest potential candidate keys & passphrases
        clean_text = raw_str.strip()
        if 3 <= len(clean_text) <= 64 and "\n" not in clean_text and not clean_text.startswith("{"):
            keys_set.add(clean_text)

        m_keys = re.findall(r"(?:key|passphrase|password|pass|secret|token)\s*[:=]\s*([^\s,;]+)", clean_text, re.IGNORECASE)
        for k in m_keys:
            keys_set.add(k.strip())

        for word in clean_text.split():
            w_c = word.strip(":,;'\"(){}[]")
            if 4 <= len(w_c) <= 40 and any(c.isalnum() for c in w_c):
                keys_set.add(w_c)

    def _parse_jpeg_metadata(self, data: bytes, results: Dict[str, Any]):
        """Parse JPEG markers: APP1 (Exif), COM (Comment), etc."""
        pos = 2
        while pos < len(data) - 4:
            if data[pos] != 0xff:
                break
            marker = data[pos + 1]
            pos += 2
            if marker in (0xd8, 0xd9, 0x00) or marker in range(0xd0, 0xd8):
                continue

            length = struct.unpack(">H", data[pos:pos + 2])[0]
            marker_data = data[pos + 2:pos + length]
            pos += length

            if marker == 0xfe:
                comment = marker_data.decode("latin-1", errors="ignore").strip()
                results["comments"].append(comment)
                results["metadata"]["JPEG_Comment"] = comment
            elif marker == 0xe1:
                if marker_data.startswith(b"Exif\x00\x00"):
                    tiff_data = marker_data[6:]
                    self._parse_tiff_ifd(tiff_data, results)

    def _parse_tiff_ifd(self, tiff_data: bytes, results: Dict[str, Any]):
        """Parse TIFF Header and IFD0/ExifSubIFD tags."""
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
            0x9c9e: "XPKeywords",
            0x9c9f: "XPSubject",
            0x8825: "GPSInfoIFDPointer",
            0x8769: "ExifIFDPointer",
            0x927c: "MakerNote",
            0x0201: "JPEGInterchangeFormat",
            0x0202: "JPEGInterchangeFormatLength"
        }

        # Helper to parse an IFD chain
        def parse_entries_at(offset: int, depth: int = 0):
            if depth > 3 or offset + 2 > len(tiff_data):
                return
            num_entries = struct.unpack(f"{fmt_char}H", tiff_data[offset:offset + 2])[0]
            curr = offset + 2

            sub_ifd_offsets = []

            for _ in range(num_entries):
                if curr + 12 > len(tiff_data):
                    break
                tag, tag_type, count, val_or_offset = struct.unpack(f"{fmt_char}HHI I", tiff_data[curr:curr + 12])
                curr += 12

                name = tag_names.get(tag, f"Tag_0x{tag:04x}")

                # Follow ExifIFDPointer or GPSInfoIFDPointer
                if tag in (0x8769, 0x8825) and val_or_offset < len(tiff_data):
                    sub_ifd_offsets.append(val_or_offset)
                    continue

                # Type 2: ASCII string
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

                # Type 1: Byte or Type 7: Undefined (UserComment, MakerNote, XP tags)
                elif tag_type in (1, 7):
                    if count <= 4:
                        raw_b = struct.pack(f"{fmt_char}I", val_or_offset)[:count]
                    else:
                        if val_or_offset + count <= len(tiff_data):
                            raw_b = tiff_data[val_or_offset:val_or_offset + count]
                        else:
                            raw_b = b""

                    if raw_b:
                        # Windows XP tags (XPTitle, XPComment, XPAuthor) are UTF-16LE
                        if 0x9c9b <= tag <= 0x9c9f:
                            val = raw_b.decode("utf-16le", errors="ignore").rstrip("\x00")
                        else:
                            val = raw_b.decode("latin-1", errors="ignore").rstrip("\x00")
                        results["metadata"][name] = val
                        if "comment" in name.lower() or "description" in name.lower() or tag == 0x9286:
                            results["comments"].append(val)

            for sub_off in sub_ifd_offsets:
                parse_entries_at(sub_off, depth + 1)

        parse_entries_at(ifd_offset, depth=0)

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
