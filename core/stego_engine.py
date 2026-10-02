"""
Automotion Forensics - Steganography Engine
PNG chunk audit, IHDR height/CRC tamper solver, LSB bitplane extractor,
and automated Steghide trial runner.
"""

import os
import shutil
import struct
import subprocess
import zlib
from typing import Any, Dict, List, Optional

from core.string_hunter import StringHunter


def to_wsl_path(win_path: str) -> str:
    """Convert Windows path to WSL /mnt/<drive>/... path."""
    abs_p = os.path.abspath(win_path)
    drive, rest = os.path.splitdrive(abs_p)
    if drive:
        return f"/mnt/{drive[0].lower()}" + rest.replace("\\", "/")
    return rest.replace("\\", "/")


class StegoEngine:
    """Analyzes steganography artifacts across images and audio."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()
        self.has_steghide = shutil.which("steghide") is not None
        self.steghide_cmd_prefix = ["steghide"] if self.has_steghide else None

        if not self.has_steghide:
            # Check WSL Kali for steghide
            try:
                proc = subprocess.run(["wsl", "-d", "kali-linux", "which", "steghide"], capture_output=True, text=True, timeout=8)
                if proc.returncode == 0 and "steghide" in proc.stdout:
                    self.has_steghide = True
                    self.steghide_cmd_prefix = ["wsl", "-d", "kali-linux", "steghide"]
            except Exception:
                pass

    def audit_image_steganography(self, target) -> Dict[str, Any]:
        """Unified audit for image steganography artifacts across PNG, JPG, and BMP."""
        results: Dict[str, Any] = {
            "flags_found": [],
            "anomalies": []
        }
        data = None
        if isinstance(target, bytes):
            data = target
        elif isinstance(target, str) and os.path.exists(target):
            try:
                with open(target, "rb") as f:
                    data = f.read(20 * 1024 * 1024)
            except Exception:
                pass
        if not data:
            return results

        if data.startswith(b"\x89PNG"):
            p_res = self.analyze_png(data)
            results["flags_found"].extend(p_res.get("extracted_flags", []))
            results["anomalies"].extend(p_res.get("anomalies", []))
            if p_res.get("crc_errors"):
                results["anomalies"].extend([f"PNG CRC Error: {e}" for e in p_res["crc_errors"]])
            pal_res = self.analyze_png_palette_slack(data)
            results["flags_found"].extend(pal_res.get("extracted_flags", []))
        elif data.startswith(b"\xff\xd8\xff"):
            dqt_res = self.analyze_jpeg_dqt(data)
            results["flags_found"].extend(dqt_res.get("extracted_flags", []))
        elif data.startswith(b"BM"):
            bmp_res = self.analyze_bmp_or_raw_pixels(data)
            results["flags_found"].extend(bmp_res.get("extracted_flags", []))

        return results

    def analyze_png(self, data: bytes) -> Dict[str, Any]:
        """
        Inspect PNG structure:
        - Validate chunk CRCs
        - Solve IHDR height/width tampering if CRC mismatch is detected
        - Extract non-standard or hidden chunks
        """
        results: Dict[str, Any] = {
            "chunks": [],
            "anomalies": [],
            "crc_errors": [],
            "ihdr_fix": None,
            "extracted_flags": []
        }

        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return results

        pos = 8
        idat_parts = []

        while pos < len(data) - 4:
            if pos + 8 > len(data):
                break
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8]
            type_str = chunk_type.decode("latin-1", errors="ignore")
            
            chunk_data = data[pos + 8:pos + 8 + length]
            crc_offset = pos + 8 + length
            if crc_offset + 4 > len(data):
                break
            expected_crc = struct.unpack(">I", data[crc_offset:crc_offset + 4])[0]
            calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff

            chunk_info = {
                "type": type_str,
                "length": length,
                "offset": pos,
                "crc_valid": (calc_crc == expected_crc)
            }
            results["chunks"].append(chunk_info)

            # Check CRC
            if calc_crc != expected_crc:
                results["crc_errors"].append({
                    "chunk": type_str,
                    "expected_crc": hex(expected_crc),
                    "calc_crc": hex(calc_crc)
                })

                # Check if IHDR height/width is tampered
                if type_str == "IHDR" and len(chunk_data) == 13:
                    width, height = struct.unpack(">II", chunk_data[:8])
                    fixed_height = self._solve_ihdr_tampering(width, height, chunk_data[8:], expected_crc)
                    if fixed_height:
                        results["ihdr_fix"] = {
                            "original_dimensions": f"{width}x{height}",
                            "repaired_dimensions": f"{width}x{fixed_height}",
                            "message": f"Fixed IHDR height to {fixed_height} matching CRC {hex(expected_crc)}"
                        }

            # Check non-standard chunks
            standard_chunks = {
                "IHDR", "PLTE", "IDAT", "IEND", "cHRM", "gAMA", "iCCP", "sBIT",
                "sRGB", "bKGD", "hIST", "tRNS", "pHYs", "sPLT", "tIME", "iTXt",
                "tEXt", "zTXt"
            }
            if type_str not in standard_chunks:
                results["anomalies"].append(f"Non-standard chunk: {type_str} ({length} bytes)")
                flags = self.string_hunter.hunt_flags(chunk_data)
                results["extracted_flags"].extend(flags)

            if type_str == "IDAT":
                idat_parts.append(chunk_data)

            pos = crc_offset + 4
            if type_str == "IEND":
                break

        # Check decompressed IDAT LSB
        if idat_parts:
            try:
                raw_idat = b"".join(idat_parts)
                decompressed = zlib.decompress(raw_idat)
                lsb_flags = self._extract_lsb_strings(decompressed)
                results["extracted_flags"].extend(lsb_flags)
            except Exception:
                pass

        return results

    def _solve_ihdr_tampering(self, width: int, current_height: int, remaining_ihdr: bytes, target_crc: int) -> Optional[int]:
        """Brute-force IHDR height (up to 4096 px) to match CRC32."""
        for h in range(1, 4096):
            if h == current_height:
                continue
            test_data = b"IHDR" + struct.pack(">II", width, h) + remaining_ihdr
            if (zlib.crc32(test_data) & 0xffffffff) == target_crc:
                return h
        return None

    def _extract_lsb_strings(self, raw_bytes: bytes, max_bytes: int = 500000) -> List[Dict[str, str]]:
        """Extract Least Significant Bit (bit 0) sequential stream and hunt for flags."""
        sample = raw_bytes[:max_bytes]
        extracted_flags = []
        if len(sample) < 64:
            return extracted_flags

        # Extract bits
        bits = [b & 1 for b in sample]
        byte_stream = bytearray()
        for i in range(0, len(bits) - 7, 8):
            b_val = 0
            for bit in bits[i:i + 8]:
                b_val = (b_val << 1) | bit
            byte_stream.append(b_val)

        flags = self.string_hunter.hunt_flags(bytes(byte_stream))
        for f in flags:
            f["encoding"] = f"LSB Bit-0 ({f['encoding']})"
            extracted_flags.append(f)

        return extracted_flags

    def analyze_bmp_or_raw_pixels(self, data: bytes) -> Dict[str, Any]:
        """
        Analyze BMP image or raw RGB pixels:
        - Multi-bitplane extraction (bits 0, 1, 2)
        - RGB Parity steganography ((R+G+B) % 2)
        - Binary border steganography
        """
        results = {"extracted_flags": []}
        if not data.startswith(b"BM") or len(data) < 54:
            return results

        try:
            pixel_offset = struct.unpack("<I", data[10:14])[0]
            width, height = struct.unpack("<ii", data[18:26])
            bpp = struct.unpack("<H", data[28:30])[0]
            width = abs(width)
            height = abs(height)

            pixel_data = data[pixel_offset:]
            if bpp not in (24, 32) or len(pixel_data) < width * height * (bpp // 8):
                return results

            bytes_per_pixel = bpp // 8

            # 1. Multi-bitplane extraction (bit 0, bit 1, bit 2)
            for plane_bit in (0, 1, 2):
                bits = [(b >> plane_bit) & 1 for b in pixel_data[:300000]]
                byte_stream = bytearray()
                for i in range(0, len(bits) - 7, 8):
                    val = 0
                    for bit in bits[i:i + 8]:
                        val = (val << 1) | bit
                    byte_stream.append(val)
                for fl in self.string_hunter.hunt_flags(bytes(byte_stream)):
                    fl["encoding"] = f"BMP Bitplane {plane_bit} ({fl['encoding']})"
                    results["extracted_flags"].append(fl)

            # 2. RGB Parity steganography: Sum R+G+B % 2
            parity_bits = []
            stride = bytes_per_pixel
            sample_count = min(len(pixel_data) // stride, 100000)
            for i in range(sample_count):
                p = pixel_data[i * stride:i * stride + 3]
                parity_bits.append(sum(p) % 2)

            parity_bytes = bytearray()
            for i in range(0, len(parity_bits) - 7, 8):
                val = 0
                for bit in parity_bits[i:i + 8]:
                    val = (val << 1) | bit
                parity_bytes.append(val)

            for fl in self.string_hunter.hunt_flags(bytes(parity_bytes)):
                fl["encoding"] = f"RGB Parity Stego ({fl['encoding']})"
                results["extracted_flags"].append(fl)

            # 3. Binary Border Steganography (1px perimeter clockwise)
            if width > 4 and height > 4:
                border_bits = []
                # Top row
                for x in range(width):
                    idx = (0 * width + x) * bytes_per_pixel
                    border_bits.append(0 if sum(pixel_data[idx:idx + 3]) < 384 else 1)
                # Right column
                for y in range(1, height):
                    idx = (y * width + (width - 1)) * bytes_per_pixel
                    border_bits.append(0 if sum(pixel_data[idx:idx + 3]) < 384 else 1)
                # Bottom row (reversed)
                for x in range(width - 2, -1, -1):
                    idx = ((height - 1) * width + x) * bytes_per_pixel
                    border_bits.append(0 if sum(pixel_data[idx:idx + 3]) < 384 else 1)
                # Left column (reversed)
                for y in range(height - 2, 0, -1):
                    idx = (y * width + 0) * bytes_per_pixel
                    border_bits.append(0 if sum(pixel_data[idx:idx + 3]) < 384 else 1)

                border_bytes = bytearray()
                for i in range(0, len(border_bits) - 7, 8):
                    val = 0
                    for bit in border_bits[i:i + 8]:
                        val = (val << 1) | bit
                    border_bytes.append(val)

                for fl in self.string_hunter.hunt_flags(bytes(border_bytes)):
                    fl["encoding"] = f"Binary Border Stego ({fl['encoding']})"
                    results["extracted_flags"].append(fl)

        except Exception:
            pass

        return results

    def analyze_ansi_art(self, text_or_bytes) -> Dict[str, Any]:
        """Strip ANSI escape sequences and non-ASCII to reveal hidden text."""
        import re
        results = {"extracted_flags": []}
        if isinstance(text_or_bytes, bytes):
            raw = text_or_bytes.decode("latin-1", errors="ignore")
        else:
            raw = str(text_or_bytes)

        if "\x1b[" in raw or "\\e[" in raw or "\\033[" in raw:
            # Strip ANSI escape codes
            clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw)
            clean_ascii = "".join(c for c in clean if 32 <= ord(c) <= 126 or c in "\n\r\t")
            for fl in self.string_hunter.hunt_flags(clean_ascii):
                fl["encoding"] = f"ANSI Stego Stripped ({fl['encoding']})"
                results["extracted_flags"].append(fl)

        return results

    def analyze_jpeg_dqt(self, data: bytes) -> Dict[str, Any]:
        """
        JPEG Unused Quantization Table LSB Steganography (EHAX 2026):
        DQT markers (0xFFDB) contain 8x8 tables.
        Tables 2-15 are unreferenced by SOF and carry hidden data in their LSBs.
        """
        results: Dict[str, Any] = {
            "is_jpeg": False,
            "dqt_tables": {},
            "extracted_flags": []
        }

        if not (data.startswith(b"\xff\xd8\xff")):
            return results

        results["is_jpeg"] = True
        pos = 0
        unused_table_bits = []

        while pos < len(data) - 4:
            if data[pos] == 0xFF and data[pos+1] == 0xDB:
                length = int.from_bytes(data[pos+2:pos+4], "big")
                dqt_data = data[pos+4:pos+2+length]
                if len(dqt_data) >= 65:
                    table_id = dqt_data[0] & 0x0F
                    precision = (dqt_data[0] >> 4) & 0x0F
                    results["dqt_tables"][table_id] = len(dqt_data)
                    # Table IDs 2-15 are typically unused/hidden in standard JPEGs
                    if table_id >= 2 and precision == 0:
                        vals = dqt_data[1:65]
                        for val in vals:
                            unused_table_bits.append(val & 1)
                pos += 2 + length
            else:
                pos += 1

        if len(unused_table_bits) >= 8:
            extracted_bytes = bytearray()
            for i in range(0, len(unused_table_bits) - 7, 8):
                byte_val = int("".join(str(b) for b in unused_table_bits[i:i+8]), 2)
                extracted_bytes.append(byte_val)

            for fl in self.string_hunter.hunt_flags(bytes(extracted_bytes)):
                fl["encoding"] = f"JPEG DQT LSB ({fl['encoding']})"
                results["extracted_flags"].append(fl)

        return results

    def analyze_png_palette_slack(self, data: bytes) -> Dict[str, Any]:
        """Inspect PNG PLTE chunk slack space and unreferenced palette bytes."""
        results: Dict[str, Any] = {"extracted_flags": []}
        if not data.startswith(b"\x89PNG"):
            return results

        pos = 8
        while pos < len(data) - 8:
            length = struct.unpack(">I", data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8]
            if chunk_type == b"PLTE":
                plte_bytes = data[pos+8:pos+8+length]
                for fl in self.string_hunter.hunt_flags(plte_bytes):
                    fl["encoding"] = f"PNG PLTE Palette ({fl['encoding']})"
                    results["extracted_flags"].append(fl)
                break
            pos += 12 + length

        return results

    def try_steghide(self, filepath: str, candidate_passwords: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """Attempt extraction using Steghide with harvested passphrases and CTF wordlist."""
        if not self.has_steghide or not os.path.exists(filepath):
            return None

        # Build prioritized password list
        default_pwds = ["", "admin", "password", "infected", "hacktoday", "HackToday", "HackToday26", "123456", "root", "flag"]
        seen_pwds = set()
        test_pwds = []

        # Candidate passwords from EXIF / strings go first
        if candidate_passwords:
            for p in candidate_passwords:
                p_str = str(p).strip()
                if p_str and p_str not in seen_pwds:
                    seen_pwds.add(p_str)
                    test_pwds.append(p_str)

        for p in default_pwds:
            if p not in seen_pwds:
                seen_pwds.add(p)
                test_pwds.append(p)

        safe_base = os.path.splitext(os.path.basename(filepath))[0]
        is_wsl = bool(self.steghide_cmd_prefix and self.steghide_cmd_prefix[0] == "wsl")
        base_cmd = self.steghide_cmd_prefix or ["steghide"]

        for pwd in test_pwds:
            pwd_clean = "".join(c for c in pwd if c.isalnum()) or "pwd"
            out_dest = os.path.join(self.output_dir, f"steghide_{safe_base}_{pwd_clean}.bin")
            try:
                if is_wsl:
                    cmd = base_cmd + [
                        "extract", "-sf", to_wsl_path(filepath),
                        "-p", pwd, "-xf", to_wsl_path(out_dest), "-f"
                    ]
                else:
                    cmd = base_cmd + ["extract", "-sf", filepath, "-p", pwd, "-xf", out_dest, "-f"]

                res = subprocess.run(cmd, capture_output=True, timeout=8)
                if res.returncode == 0 and os.path.exists(out_dest) and os.path.getsize(out_dest) > 0:
                    with open(out_dest, "rb") as ef:
                        extracted_bytes = ef.read()
                    flags = self.string_hunter.hunt_flags(extracted_bytes)
                    return {
                        "success": True,
                        "passphrase": pwd,
                        "output_file": out_dest,
                        "size": len(extracted_bytes),
                        "flags": flags
                    }
            except Exception:
                continue

        return None

    def analyze_svg(self, target) -> Dict[str, Any]:
        """
        PicoCTF 'Enhance!' & UTCTF 'Insanity Check' SVG Forensics:
        - Extracts and concatenates fragmented text from <tspan> and <text> elements
        - Scans XML attributes (id, style, d, title)
        - Detects animation keyframes (<animate>) Morse/binary alternations
        """
        import re
        results: Dict[str, Any] = {
            "flags_found": [],
            "extracted_text": "",
            "tspan_fragments": []
        }
        text = ""
        if isinstance(target, str) and os.path.exists(target):
            try:
                with open(target, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                return results
        elif isinstance(target, (bytes, bytearray)):
            text = target.decode("utf-8", errors="ignore")
        elif isinstance(target, str):
            text = target

        if not text:
            return results

        # 1. Extract and join all <tspan> inner texts (PicoCTF Enhance! pattern)
        tspans = re.findall(r"<tspan[^>]*>(.*?)</tspan>", text, re.DOTALL)
        if tspans:
            joined_tspan = "".join(t.strip() for t in tspans if t.strip())
            results["extracted_text"] = joined_tspan
            results["tspan_fragments"] = tspans[:20]
            for fl in self.string_hunter.hunt_flags(joined_tspan):
                fl["encoding"] = f"SVG Joined <tspan> ({fl['encoding']})"
                results["flags_found"].append(fl)

        # 2. Extract and join all <text> elements
        texts = re.findall(r"<text[^>]*>(.*?)</text>", text, re.DOTALL)
        if texts:
            joined_text = " ".join(t.strip() for t in texts if t.strip())
            for fl in self.string_hunter.hunt_flags(joined_text):
                fl["encoding"] = f"SVG <text> ({fl['encoding']})"
                results["flags_found"].append(fl)

        # 3. Scan full raw SVG XML
        for fl in self.string_hunter.hunt_flags(text):
            fl["encoding"] = f"SVG Raw ({fl['encoding']})"
            results["flags_found"].append(fl)

        return results

    def analyze_pdf(self, target) -> Dict[str, Any]:
        """
        PicoCTF 'Redaction gone wrong', Nullcon 'rdctd 1-6', Pragyan 'epstein files':
        - Decompresses all FlateDecode streams (stream ... endstream) to reveal un-redacted text
        - Extracts PDF text operators (Tj / TJ)
        - Extracts link annotations (/Link /URI with escaped braces)
        - Inspects document metadata (/Producer, /Author, /Keywords)
        - Scans trailing overlay after %%EOF
        """
        import re
        import zlib
        results: Dict[str, Any] = {
            "flags_found": [],
            "streams_decompressed": 0,
            "metadata_entries": {},
            "uri_links": []
        }
        data = b""
        if isinstance(target, str) and os.path.exists(target):
            try:
                with open(target, "rb") as f:
                    data = f.read()
            except Exception:
                return results
        elif isinstance(target, (bytes, bytearray)):
            data = bytes(target)

        if not data:
            return results

        # 1. Scan metadata (/Author, /Producer, /Keywords, /Title)
        for meta_key in (b"Author", b"Producer", b"Keywords", b"Title", b"Creator", b"Subject"):
            m = re.search(rb"/" + meta_key + rb"\s*\((.*?)\)", data)
            if m:
                val = m.group(1).decode("latin-1", errors="ignore")
                results["metadata_entries"][meta_key.decode()] = val
                for fl in self.string_hunter.hunt_flags(val):
                    fl["encoding"] = f"PDF Metadata /{meta_key.decode()} ({fl['encoding']})"
                    results["flags_found"].append(fl)

        # 2. Extract link URI annotations (/Subtype /Link ... /URI (...))
        uris = re.findall(rb"/URI\s*\((.*?)\)", data)
        for u in uris:
            clean_u = u.decode("latin-1", errors="ignore").replace(r"\{", "{").replace(r"\}", "}")
            results["uri_links"].append(clean_u)
            for fl in self.string_hunter.hunt_flags(clean_u):
                fl["encoding"] = f"PDF URI Annotation ({fl['encoding']})"
                results["flags_found"].append(fl)

        # 3. Decompress all FlateDecode streams (Nullcon rdctd 5 / PicoCTF Redaction gone wrong)
        stream_matches = re.findall(rb"stream[\r\n]+(.*?)[\r\n]+endstream", data, re.DOTALL)
        for s_bytes in stream_matches:
            decomp = None
            for wbits in (15, -15, 31):
                try:
                    decomp = zlib.decompress(s_bytes, wbits)
                    break
                except Exception:
                    pass
            if decomp:
                results["streams_decompressed"] += 1
                for fl in self.string_hunter.hunt_flags(decomp):
                    fl["encoding"] = f"PDF Decompressed Stream ({fl['encoding']})"
                    results["flags_found"].append(fl)

                # Extract text operators from content stream: (string) Tj or [(str1)(str2)] TJ
                tj_texts = re.findall(rb"\(([^\)]+)\)\s*Tj", decomp)
                if tj_texts:
                    joined_tj = b"".join(tj_texts).decode("latin-1", errors="ignore")
                    for fl in self.string_hunter.hunt_flags(joined_tj):
                        fl["encoding"] = f"PDF Tj Stream Text ({fl['encoding']})"
                        results["flags_found"].append(fl)

        # 4. Check trailing overlay after %%EOF (Pragyan CTF pattern)
        eof_pos = data.rfind(b"%%EOF")
        if eof_pos != -1 and eof_pos + 5 < len(data):
            overlay = data[eof_pos + 5:].strip()
            if len(overlay) > 4:
                for fl in self.string_hunter.hunt_flags(overlay):
                    fl["encoding"] = f"PDF %%EOF Overlay ({fl['encoding']})"
                    results["flags_found"].append(fl)

        # 5. Raw string hunt
        for fl in self.string_hunter.hunt_flags(data):
            fl["encoding"] = f"PDF Raw ({fl['encoding']})"
            results["flags_found"].append(fl)

        return results

    def analyze_office_document(self, filepath: str) -> Dict[str, Any]:
        """
        PicoCTF 'MacroHard WeakEdge' / Office OpenXML Forensics:
        - Inspects PPTX/DOCX/XLSX zip packages for hidden slides, slide masters, customXml
        - Searches for hidden base64 payloads (e.g. cGljb0NURnt... without spaces/padding)
        - Inspects vbaProject.bin macros
        """
        import zipfile
        results: Dict[str, Any] = {
            "flags_found": [],
            "hidden_entries": [],
            "has_macros": False
        }
        if not os.path.exists(filepath):
            return results

        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                for name in zf.namelist():
                    if "hidden" in name.lower() or "customxml" in name.lower():
                        results["hidden_entries"].append(name)
                    if "vbaproject.bin" in name.lower():
                        results["has_macros"] = True

                    try:
                        content = zf.read(name)
                        for fl in self.string_hunter.hunt_flags(content):
                            fl["encoding"] = f"Office XML ({name}: {fl['encoding']})"
                            results["flags_found"].append(fl)
                    except Exception:
                        pass
        except Exception:
            pass

        return results
