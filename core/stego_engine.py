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
        target_path = target if isinstance(target, str) and os.path.exists(target) else None

        if isinstance(target, bytes):
            data = target
        elif target_path:
            try:
                with open(target_path, "rb") as f:
                    data = f.read(20 * 1024 * 1024)
            except Exception:
                pass
        if not data:
            return results

        # 0. Check for corrupted PNG (magic header, chunk names like C"DR, lengths, CRCs)
        is_png_tampered = (
            (b"IHDR" in data[:64] or b'C"DR' in data[:64] or (len(data) > 16 and data[8:12] == b"\x00\x00\x00\x0d"))
            and not data.startswith(b"\x89PNG\r\n\x1a\n")
        )
        if is_png_tampered or (data.startswith(b"\x89PNG") and b'C"DR' in data[:64]):
            fixed_png = self.repair_corrupted_png(data)
            if fixed_png:
                results["anomalies"].append("Repaired corrupted PNG header/chunks/CRCs (c0rrupt pattern)")
                data = fixed_png
                # Scan repaired image with QR and OCR
                results["flags_found"].extend(self.scan_qr_code_from_bytes(data))
                repaired_png_path = os.path.join(self.output_dir, "repaired_png.png")
                results["flags_found"].extend(self.run_ocr_on_file(repaired_png_path))

        # 1. Standard QR code scan on image
        qr_flags = self.scan_qr_code_from_bytes(data)
        results["flags_found"].extend(qr_flags)

        # 2. PNG Stego & Zsteg
        if data.startswith(b"\x89PNG"):
            p_res = self.analyze_png(data)
            results["flags_found"].extend(p_res.get("extracted_flags", []))
            results["anomalies"].extend(p_res.get("anomalies", []))
            if p_res.get("crc_errors"):
                results["anomalies"].extend([f"PNG CRC Error: {e}" for e in p_res["crc_errors"]])
            pal_res = self.analyze_png_palette_slack(data)
            results["flags_found"].extend(pal_res.get("extracted_flags", []))

            # Run zsteg on target PNG
            if target_path:
                zsteg_flags = self.run_zsteg_on_file(target_path)
                results["flags_found"].extend(zsteg_flags)
                # Run OCR on target image
                ocr_flags = self.run_ocr_on_file(target_path)
                results["flags_found"].extend(ocr_flags)

        # 3. JPEG DQT & Height Tampering
        elif data.startswith(b"\xff\xd8\xff"):
            dqt_res = self.analyze_jpeg_dqt(data)
            results["flags_found"].extend(dqt_res.get("extracted_flags", []))

            # Explore JPEG Height Tampering (SOF0/SOF2 cropping)
            if target_path:
                height_fixes = self.explore_jpeg_height(data, target_path)
                results["anomalies"].extend(height_fixes)
                ocr_flags = self.run_ocr_on_file(target_path)
                results["flags_found"].extend(ocr_flags)

        # 4. BMP & Raw Pixels + tunn3l v1s10n repair
        elif data.startswith(b"BM"):
            # Check for corrupted BMP header or truncated height (tunn3l v1s10n pattern)
            repaired_bmp_bytes, bmp_anomalies = self.repair_corrupted_bmp(data, target_path)
            if bmp_anomalies:
                results["anomalies"].extend(bmp_anomalies)
            if repaired_bmp_bytes:
                data = repaired_bmp_bytes
                base_name = os.path.basename(target_path) if target_path else "sample"
                repaired_bmp_path = os.path.join(self.output_dir, f"repaired_bmp_{base_name}.bmp")
                ocr_flags = self.run_ocr_on_file(repaired_bmp_path)
                results["flags_found"].extend(ocr_flags)

            bmp_res = self.analyze_bmp_or_raw_pixels(data)
            results["flags_found"].extend(bmp_res.get("extracted_flags", []))
            if target_path:
                ocr_flags = self.run_ocr_on_file(target_path)
                results["flags_found"].extend(ocr_flags)

        # 5. SVG Image Triage (<tspan> coordinates & base64 embeds)
        elif b"<svg" in data[:500] or (data.startswith(b"<?xml") and b"<svg" in data[:1000]):
            svg_res = self.analyze_svg(data)
            results["flags_found"].extend(svg_res.get("flags_found", []))
            results["flags_found"].extend(svg_res.get("extracted_flags", []))
            results["anomalies"].extend(svg_res.get("anomalies", []))

        return results

    def repair_corrupted_png(self, data: bytes) -> Optional[bytes]:
        """
        Detect and repair tampered PNGs (PicoCTF 'c0rrupt' / Magic Show patterns):
        - Fix corrupted magic header (\x89PNG\r\n\x1a\n)
        - Fix corrupted chunk headers (e.g. C"DR -> IHDR)
        - Fix corrupted chunk lengths (e.g. pHYs length must be 9)
        - Recalculate corrupted CRCs
        - Append missing or corrupted IEND trailer
        """
        try:
            fixed = bytearray(data)
            # 1. Force valid PNG 8-byte magic
            fixed[0:8] = b"\x89PNG\r\n\x1a\n"

            # 2. Fix 1st chunk (must be IHDR with length 13)
            if len(fixed) >= 29:
                fixed[8:12] = b"\x00\x00\x00\x0d"
                fixed[12:16] = b"IHDR"
                ihdr_data = fixed[16:29]
                ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data) & 0xffffffff
                fixed[29:33] = struct.pack(">I", ihdr_crc)

            # 3. Walk remaining chunks
            pos = 33
            standard_chunks = [b"PLTE", b"IDAT", b"IEND", b"pHYs", b"sBIT", b"sRGB", b"gAMA", b"cHRM", b"tEXt", b"zTXt", b"iTXt", b"tIME", b"bKGD", b"hIST"]
            
            while pos < len(fixed) - 8:
                length = struct.unpack(">I", fixed[pos:pos+4])[0]
                chunk_type = bytes(fixed[pos+4:pos+8])

                # Corrupted pHYs (often precedes IDAT)
                if chunk_type not in standard_chunks:
                    if b"IDAT" in fixed[pos:pos+64]:
                        idat_next = fixed.find(b"IDAT", pos)
                        if idat_next - 4 == pos + 21 or (idat_next > pos and idat_next - pos <= 32):
                            fixed[pos:pos+4] = b"\x00\x00\x00\x09"
                            fixed[pos+4:pos+8] = b"pHYs"
                            phys_crc = zlib.crc32(b"pHYs" + fixed[pos+8:pos+17]) & 0xffffffff
                            fixed[pos+17:pos+21] = struct.pack(">I", phys_crc)
                            pos = pos + 21
                            continue
                    # Test if any known chunk matches CRC
                    if pos + 8 + length + 4 <= len(fixed):
                        c_data = fixed[pos+8:pos+8+length]
                        c_crc = struct.unpack(">I", fixed[pos+8+length:pos+12+length])[0]
                        matched_chunk = None
                        for sc in standard_chunks:
                            if (zlib.crc32(sc + c_data) & 0xffffffff) == c_crc:
                                matched_chunk = sc
                                break
                        if matched_chunk:
                            fixed[pos+4:pos+8] = matched_chunk
                            pos += 12 + length
                            continue

                # Recalculate CRC for known chunks
                if chunk_type in standard_chunks and pos + 8 + length + 4 <= len(fixed):
                    c_data = fixed[pos+8:pos+8+length]
                    actual_crc = zlib.crc32(chunk_type + c_data) & 0xffffffff
                    fixed[pos+8+length:pos+12+length] = struct.pack(">I", actual_crc)
                    pos += 12 + length
                    if chunk_type == b"IEND":
                        break
                else:
                    pos += 1

            # 4. Ensure valid IEND trailer
            if not fixed.endswith(b"IEND\xaeB`\x82"):
                iend_idx = fixed.rfind(b"IEND")
                if iend_idx != -1 and iend_idx >= len(fixed) - 32:
                    fixed[iend_idx-4:iend_idx] = b"\x00\x00\x00\x00"
                    fixed[iend_idx:iend_idx+4] = b"IEND"
                    fixed[iend_idx+4:iend_idx+8] = b"\xaeB`\x82"
                    fixed = fixed[:iend_idx+8]
                else:
                    fixed += b"\x00\x00\x00\x00IEND\xaeB`\x82"

            repaired_out = os.path.join(self.output_dir, "repaired_png.png")
            with open(repaired_out, "wb") as f:
                f.write(fixed)
            return bytes(fixed)
        except Exception:
            return None

    def repair_corrupted_png_magic(self, data: bytes) -> Optional[bytes]:
        """Detect and repair tampered PNG magic header and trailer."""
        return self.repair_corrupted_png(data)

    def repair_corrupted_bmp(self, data: bytes, target_path: Optional[str] = None) -> Tuple[Optional[bytes], List[str]]:
        """
        Detect and repair tampered BMP headers and vertical cropping (PicoCTF 'tunn3l v1s10n'):
        - Fix corrupted pixel data offset (bytes 10-13)
        - Fix corrupted DIB header size (bytes 14-17)
        - Recalculate maximum true height from total byte capacity and expand cropped height
        """
        anomalies = []
        if not data.startswith(b"BM") or len(data) < 54:
            return None, anomalies

        try:
            fixed = bytearray(data)
            file_size = struct.unpack("<I", fixed[2:6])[0]
            if file_size == 0 or file_size > len(fixed):
                file_size = len(fixed)
                fixed[2:6] = struct.pack("<I", file_size)

            pixel_offset = struct.unpack("<I", fixed[10:14])[0]
            dib_size = struct.unpack("<I", fixed[14:18])[0]

            repaired_header = False
            # Fix corrupted DIB size (tunn3l v1s10n has 0xBAD0 instead of 40)
            if dib_size not in (12, 40, 52, 56, 64, 108, 124):
                fixed[14:18] = struct.pack("<I", 40)
                dib_size = 40
                repaired_header = True
                anomalies.append("Repaired corrupted BMP DIB header size (reset to 40)")

            # Fix corrupted pixel offset (tunn3l v1s10n has 0xBAD0 instead of 54)
            if pixel_offset != 54 and dib_size == 40:
                fixed[10:14] = struct.pack("<I", 54)
                pixel_offset = 54
                repaired_header = True
                anomalies.append("Repaired corrupted BMP pixel data offset (reset to 54)")

            width = abs(struct.unpack("<i", fixed[18:22])[0])
            height = abs(struct.unpack("<i", fixed[22:26])[0])
            bpp = struct.unpack("<H", fixed[28:30])[0]

            if bpp not in (1, 4, 8, 16, 24, 32):
                bpp = 24
                fixed[28:30] = struct.pack("<H", 24)

            row_size = ((width * bpp + 31) // 32) * 4
            if row_size > 0:
                data_capacity = len(fixed) - pixel_offset
                max_height = data_capacity // row_size

                if max_height > height:
                    anomalies.append(f"BMP height tampering detected: header has {height}px, payload contains data for {max_height}px")
                    fixed[22:26] = struct.pack("<i", max_height)
                    repaired_header = True

            if repaired_header:
                base_name = os.path.basename(target_path) if target_path else "sample"
                out_path = os.path.join(self.output_dir, f"repaired_bmp_{base_name}.bmp")
                with open(out_path, "wb") as f:
                    f.write(fixed)
                anomalies.append(f"Saved repaired full-height BMP: {out_path}")
                return bytes(fixed), anomalies
        except Exception:
            pass

        return None, anomalies

    def run_ocr_on_file(self, img_path: str) -> List[Dict[str, str]]:
        """Run OCR on image file using tesseract via WSL Kali Linux across multiple PSM modes."""
        flags: List[Dict[str, str]] = []
        if not os.path.exists(img_path):
            return flags
        try:
            wsl_p = to_wsl_path(img_path)
            for psm in ("6", "3", "11"):
                cmd = ["wsl", "-u", "root", "-d", "kali-linux", "tesseract", wsl_p, "stdout", "--psm", psm]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
                if proc.stdout:
                    for fl in self.string_hunter.hunt_flags(proc.stdout):
                        fl["encoding"] = f"OCR Tesseract PSM {psm} ({fl['encoding']})"
                        if not any(f["flag"] == fl["flag"] for f in flags):
                            flags.append(fl)
                if flags:
                    break
        except Exception:
            pass
        return flags

    def analyze_svg(self, data: bytes) -> Dict[str, Any]:
        """
        Analyze SVG image files:
        - Extract text from <tspan> and <text> sorted by coordinate or order
        - Extract embedded Base64 raster images (PNG/JPG data URIs)
        - Hunt flags in SVG comments, metadata, and CSS styles
        """
        results: Dict[str, Any] = {"extracted_flags": [], "anomalies": []}
        try:
            svg_text = data.decode("utf-8", errors="ignore")
            for fl in self.string_hunter.hunt_flags(svg_text):
                fl["encoding"] = f"SVG Source ({fl['encoding']})"
                results["extracted_flags"].append(fl)

            # Extract and concatenate <tspan> elements
            tspans = re.findall(r'<tspan[^>]*>(.*?)</tspan>', svg_text, re.DOTALL)
            if tspans:
                joined_tspans = "".join(t.strip() for t in tspans if t.strip())
                for fl in self.string_hunter.hunt_flags(joined_tspans):
                    fl["encoding"] = f"SVG <tspan> Assembled ({fl['encoding']})"
                    results["extracted_flags"].append(fl)

            # Extract embedded Base64 images
            for m_b64 in re.finditer(r'data:image/(?:png|jpeg|jpg);base64,([A-Za-z0-9+/=]+)', svg_text):
                try:
                    img_bytes = base64.b64decode(m_b64.group(1))
                    img_res = self.audit_image_steganography(img_bytes)
                    results["extracted_flags"].extend(img_res.get("flags_found", []))
                except Exception:
                    pass
        except Exception:
            pass
        return results

    def scan_qr_code_from_bytes(self, image_data: bytes) -> List[Dict[str, str]]:
        """Decode QR codes / barcodes using zbarimg via WSL or pyzbar."""
        flags: List[Dict[str, str]] = []
        if len(image_data) < 64:
            return flags

        tmp_path = os.path.join(self.output_dir, "_temp_qr_scan.png")
        try:
            with open(tmp_path, "wb") as f:
                f.write(image_data)

            # Try zbarimg via WSL
            wsl_p = to_wsl_path(tmp_path)
            cmd = ["wsl", "-u", "root", "-d", "kali-linux", "zbarimg", "-q", "--raw", wsl_p]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if proc.returncode == 0 and proc.stdout.strip():
                for line in proc.stdout.splitlines():
                    clean_line = line.strip()
                    if clean_line:
                        for fl in self.string_hunter.hunt_flags(clean_line):
                            fl["encoding"] = f"QR Code (zbarimg) -> {fl['encoding']}"
                            flags.append(fl)
        except Exception:
            pass
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

        return flags

    def run_zsteg_on_file(self, win_path: str) -> List[Dict[str, str]]:
        """Execute zsteg via WSL and harvest all embedded flags."""
        flags: List[Dict[str, str]] = []
        try:
            wsl_p = to_wsl_path(win_path)
            cmd = ["wsl", "-u", "root", "-d", "kali-linux", "zsteg", "-a", wsl_p]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if proc.stdout:
                for fl in self.string_hunter.hunt_flags(proc.stdout):
                    fl["encoding"] = f"Zsteg LSB Multi-Plane ({fl['encoding']})"
                    flags.append(fl)
        except Exception:
            pass
        return flags

    def explore_jpeg_height(self, data: bytes, orig_path: str) -> List[str]:
        """Automatically repair/expand cropped JPEG height (SOF0/SOF2 marker tampering)."""
        anomalies = []
        try:
            # Search for SOF0 (0xFFC0) or SOF2 (0xFFC2)
            pos = 0
            while pos < len(data) - 9:
                if data[pos] == 0xFF and data[pos+1] in (0xC0, 0xC2):
                    sof_len = struct.unpack(">H", data[pos+2:pos+4])[0]
                    precision = data[pos+4]
                    height, width = struct.unpack(">HH", data[pos+5:pos+9])
                    anomalies.append(f"JPEG SOF marker detected: {width}x{height} (precision={precision})")

                    # Generate expanded height images (1.5x, 2.0x, 2.5x, 3.0x)
                    for multiplier in (1.5, 2.0, 3.0):
                        new_h = int(height * multiplier)
                        if new_h <= 65535:
                            fixed = bytearray(data)
                            fixed[pos+5:pos+7] = struct.pack(">H", new_h)
                            base_name = os.path.basename(orig_path)
                            out_name = os.path.join(self.output_dir, f"height_{int(multiplier*100)}pct_{base_name}")
                            with open(out_name, "wb") as f:
                                f.write(fixed)
                            anomalies.append(f"Generated height-expanded JPEG ({int(multiplier*100)}% height: {width}x{new_h}): {out_name}")
                    break
                pos += 1
        except Exception:
            pass
        return anomalies

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
