"""
Automotion Forensics - Magic Carver Engine
File signature identification, extension mismatch detection,
EOF overlay / trailing data extractor, and embedded file carver.
"""

import base64
import bz2
import lzma
import os
import re
import shutil
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import config
from core.pdf_inspector import PDFInspector, to_wsl_path
from core.string_hunter import StringHunter


class MagicCarver:
    """Identifies file types, detects corrupted extensions, overlays, and carves embedded files."""

    def __init__(self, output_dir: Optional[str] = None):
        self.signatures = config.MAGIC_SIGNATURES
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)

    def identify_format(self, data: bytes, filepath: Optional[str] = None) -> Dict[str, Any]:
        """Identify primary file format based on header magic bytes."""
        matched = []
        for sig in self.signatures:
            offset = sig.get("offset", 0)
            magic = sig["magic"]
            if b"...." in magic:
                # Regex-like pattern (e.g., RIFF....WEBP or RIFF....WAVE)
                pattern = re.escape(magic).replace(b"\\.\\.\\.\\.", b".{4}")
                if re.match(pattern, data[offset:offset + len(magic)]):
                    matched.append(sig)
            else:
                if len(data) >= offset + len(magic) and data[offset:offset + len(magic)] == magic:
                    matched.append(sig)

        primary = matched[0] if matched else {"name": "Raw Binary / Unknown", "ext": "bin", "trailer": None}
        
        # Check extension mismatch
        mismatch_warning = None
        if filepath:
            actual_ext = Path(filepath).suffix.lower().lstrip(".")
            expected_ext = primary.get("ext")
            if expected_ext and actual_ext and actual_ext != expected_ext:
                # Allow common aliases (jpg/jpeg, tiff/tif)
                aliases = {("jpg", "jpeg"), ("jpeg", "jpg"), ("tif", "tiff"), ("tiff", "tif"), ("pcap", "pcapng"), ("pcapng", "pcap")}
                if (actual_ext, expected_ext) not in aliases:
                    mismatch_warning = (
                        f"EXTENSION MISMATCH: File is named '.{actual_ext}' but magic bytes indicate '{primary['name']}' (.{expected_ext})!"
                    )

        return {
            "primary": primary,
            "all_matches": matched,
            "mismatch_warning": mismatch_warning
        }

    def check_eof_overlay(self, data: bytes, primary_sig: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect trailing data after standard file trailer."""
        trailer = primary_sig.get("trailer")
        if not trailer:
            return None

        # Find the last occurrence of the trailer
        trailer_pos = data.rfind(trailer)
        if trailer_pos == -1:
            return None

        trailer_end = trailer_pos + len(trailer)
        trailing_bytes = len(data) - trailer_end

        if trailing_bytes > 0:
            overlay_data = data[trailer_end:]
            return {
                "trailer_offset": trailer_pos,
                "trailer_end": trailer_end,
                "overlay_size": trailing_bytes,
                "overlay_bytes": overlay_data[:1024],  # Sample
                "full_overlay": overlay_data
            }
        return None

    def carve_embedded_files(self, data: bytes, base_name: str = "carved", candidate_passwords: Optional[List[str]] = None, _depth: int = 0) -> List[Dict[str, Any]]:
        """Carve embedded files found at non-zero offsets with recursive unpack and PDF triage (PicoCTF Matryoshka doll solver)."""
        carved_files = []
        if _depth > 6:
            return carved_files

        carve_targets = [
            ("zip", b"PK\x03\x04", b"PK\x05\x06", 22),
            ("png", b"\x89PNG\r\n\x1a\n", b"IEND\xaeB`\x82", 8),
            ("jpg", b"\xff\xd8\xff", b"\xff\xd9", 2),
            ("gif", b"GIF89a", b"\x00\x3b", 2),
            ("pdf", b"%PDF", b"%%EOF", 5),
            ("elf", b"\x7fELF", None, 0),
            ("pcap", b"\xd4\xc3\xb2\xa1", None, 0),
            ("pcapng", b"\n\r\r\n", None, 0),
            ("gz", b"\x1f\x8b\x08", None, 0),
        ]

        hunter = StringHunter()
        passwords_list = list(candidate_passwords or [])
        for dp in ["", "bluelobsterislove", "password", "spongebob", "admin", "123456", "CTF", "flag"]:
            if dp not in passwords_list:
                passwords_list.append(dp)

        for ext, magic, trailer, trailer_extra in carve_targets:
            start_pos = 0
            while True:
                pos = data.find(magic, start_pos)
                if pos == -1:
                    break

                end_pos = None
                if trailer:
                    t_pos = data.find(trailer, pos + len(magic))
                    if ext == "zip" and len(data) >= t_pos + 22:
                        comment_len = struct.unpack("<H", data[t_pos + 20:t_pos + 22])[0]
                        end_pos = t_pos + 22 + comment_len
                    elif ext == "pdf" and t_pos != -1:
                        end_pos = t_pos + len(trailer) + trailer_extra
                    elif t_pos != -1:
                        end_pos = t_pos + len(trailer) + trailer_extra

                    if end_pos and end_pos - pos > config.MAX_CARVE_FILE_SIZE:
                        end_pos = pos + config.MAX_CARVE_FILE_SIZE
                else:
                    end_pos = min(len(data), pos + 5 * 1024 * 1024)

                if end_pos and end_pos > pos:
                    carved_chunk = data[pos:end_pos]
                    carve_filename = f"{base_name}_offset_{pos}_{len(carved_chunk)}b.{ext}"
                    carve_path = os.path.join(self.output_dir, carve_filename)

                    try:
                        with open(carve_path, "wb") as f:
                            f.write(carved_chunk)

                        carved_info: Dict[str, Any] = {
                            "type": ext.upper(),
                            "offset": pos,
                            "size": len(carved_chunk),
                            "path": carve_path,
                            "filename": carve_filename,
                            "flags_found": []
                        }

                        # Hunt flags in the raw carved chunk
                        for fl in hunter.hunt_flags(carved_chunk):
                            fl["context"] = f"Carved {ext.upper()} Offset {pos}: {fl.get('context', '')}"
                            carved_info["flags_found"].append(fl)

                        # If it's a PDF directly, run PDF inspector
                        if ext == "pdf":
                            try:
                                pdf_insp = PDFInspector(self.output_dir)
                                pdf_res = pdf_insp.inspect(carve_path, passwords_list)
                                carved_info["flags_found"].extend(pdf_res.get("flags_found", []))
                            except Exception:
                                pass

                        # If it's a ZIP, inspect file list inside safely and try extraction
                        if ext == "zip":
                            extract_sub = os.path.join(self.output_dir, f"{carve_filename}_extracted")
                            os.makedirs(extract_sub, exist_ok=True)
                            carved_info["extracted_to"] = extract_sub

                            # 1. Try python zipfile
                            try:
                                with zipfile.ZipFile(carve_path, "r") as zf:
                                    namelist = zf.namelist()
                                    carved_info["zip_entries"] = namelist
                                    for entry in namelist:
                                        if not os.path.isabs(entry) and ".." not in entry:
                                            try:
                                                zf.extract(entry, extract_sub)
                                            except Exception:
                                                pass
                            except Exception as ze:
                                carved_info["zip_error"] = str(ze)

                            # 2. If extraction is empty or incomplete (0-byte files from zipfile password failure), try 7z via WSL or native
                            incomplete = (
                                not os.listdir(extract_sub)
                                or any(os.path.getsize(os.path.join(extract_sub, f)) == 0 for f in os.listdir(extract_sub))
                            )
                            if incomplete:
                                wsl_carve = to_wsl_path(carve_path)
                                wsl_extract = to_wsl_path(extract_sub)
                                for pwd in passwords_list:
                                    try:
                                        cmd = ["wsl", "-u", "root", "-d", "kali-linux", "7z", "x", f"-p{pwd}", "-y", "-aoa", f"-o{wsl_extract}", wsl_carve]
                                        res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                                        if "Everything is Ok" in res.stdout:
                                            carved_info["password_used"] = pwd
                                            break
                                    except Exception:
                                        pass

                            # 3. Scan all extracted files inside the ZIP
                            for root, _, files in os.walk(extract_sub):
                                for fn in files:
                                    fp = os.path.join(root, fn)
                                    if fn.lower().endswith(".pdf"):
                                        try:
                                            pdf_insp = PDFInspector(self.output_dir)
                                            pdf_res = pdf_insp.inspect(fp, passwords_list)
                                            carved_info["flags_found"].extend(pdf_res.get("flags_found", []))
                                        except Exception:
                                            pass
                                    else:
                                        try:
                                            with open(fp, "rb") as ef:
                                                e_bytes = ef.read()
                                            for fl in hunter.hunt_flags(e_bytes):
                                                fl["source_file"] = fn
                                                carved_info["flags_found"].append(fl)

                                            # Recursive unpacking for Matryoshka nested images / archives
                                            if _depth < 5 and (b"PK\x03\x04" in e_bytes[4:] or fn.lower().endswith((".jpg", ".jpeg", ".png", ".bmp"))):
                                                nested_carves = self.carve_embedded_files(
                                                    e_bytes,
                                                    base_name=f"{base_name}_sub_{fn}",
                                                    candidate_passwords=passwords_list,
                                                    _depth=_depth + 1
                                                )
                                                for nc in nested_carves:
                                                    carved_info["flags_found"].extend(nc.get("flags_found", []))
                                                    carved_files.append(nc)
                                        except Exception:
                                            pass

                        carved_files.append(carved_info)
                    except Exception:
                        pass

                start_pos = pos + len(magic)

        return carved_files

    def carve_corrupted_zip_entries(self, data: bytes, base_name: str = "recovered_zip") -> List[Dict[str, Any]]:
        """
        ZIP Local Header Parser without Central Directory (srdnlenCTF 2026 / PlaidCTF pattern):
        - When ZIP central directory (PK\\x01\\x02) or EOCD (PK\\x05\\x06) is missing or corrupted,
          iterates local headers (PK\\x03\\x04) directly.
        - Decompresses Deflate (method 8) and Stored (method 0) streams independently.
        - Saves extracted files and returns metadata and extracted payload.
        """
        import zlib
        extracted_entries = []
        pos = 0

        while True:
            off = data.find(b"PK\x03\x04", pos)
            if off == -1 or off + 30 > len(data):
                break

            try:
                (ver, flag, method, mtime, mdate, crc, csize, usize, nlen, xlen) = struct.unpack_from(
                    "<HHHHHIIIHH", data, off + 4
                )
                name_start = off + 30
                name_end = name_start + nlen
                if name_end > len(data):
                    pos = off + 4
                    continue

                name = data[name_start:name_end].decode("utf-8", errors="replace")
                data_off = name_end + xlen

                # Check if data_off + csize fits within data
                raw_payload = None
                if csize > 0 and data_off + csize <= len(data):
                    comp = data[data_off:data_off + csize]
                    if method == 8:  # Deflate
                        try:
                            raw_payload = zlib.decompress(comp, -15)
                        except Exception:
                            try:
                                raw_payload = zlib.decompress(comp)
                            except Exception:
                                pass
                    elif method == 0:  # Stored
                        raw_payload = comp
                elif csize == 0 and method == 8:
                    try:
                        raw_payload = zlib.decompress(data[data_off:data_off + 1024 * 1024], -15)
                    except Exception:
                        pass

                if raw_payload is not None:
                    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
                    save_path = os.path.join(self.output_dir, f"{base_name}_{off}_{safe_name}")
                    try:
                        with open(save_path, "wb") as out_f:
                            out_f.write(raw_payload)
                    except Exception:
                        pass

                    extracted_entries.append({
                        "name": name,
                        "offset": off,
                        "compression_method": method,
                        "compressed_size": csize,
                        "uncompressed_size": len(raw_payload),
                        "saved_to": save_path,
                        "payload": raw_payload
                    })

                pos = max(off + 4, data_off + max(csize, 1))
            except Exception:
                pos = off + 4

        return extracted_entries

    def reconstruct_bson_chunks(self, data: bytes, base_name: str = "reconstructed_bson") -> Dict[str, Any]:
        """
        BSON / Chunked Stream Reconstruction (IceCTF 2016 pattern):
        - Scans binary/text data for base64 encoded file fragments associated with chunk indices:
          e.g. {"index": 0, "data": "..."} or {"i": 0, "d": "..."} or raw BSON documents.
        - Sorts chunks by index, concatenates, and base64 decodes.
        - Identifies reconstructed file format (e.g. PNG, PDF, ZIP) and searches for flags.
        """
        results: Dict[str, Any] = {
            "chunks_found": 0,
            "reconstructed": False,
            "format": None,
            "saved_to": None,
            "flags_found": []
        }

        text = data.decode("latin-1", errors="ignore")
        pattern1 = re.findall(r'["\'](?:index|i|idx)["\']\s*:\s*([0-9]+)\s*,\s*["\'](?:data|d|chunk|payload)["\']\s*:\s*["\']([A-Za-z0-9+/=]{10,})["\']', text)
        pattern2 = re.findall(r'["\'](?:data|d|chunk|payload)["\']\s*:\s*["\']([A-Za-z0-9+/=]{10,})["\']\s*,\s*["\'](?:index|i|idx)["\']\s*:\s*([0-9]+)', text)

        indexed_chunks = {}
        for idx_str, b64 in pattern1:
            indexed_chunks[int(idx_str)] = b64
        for b64, idx_str in pattern2:
            indexed_chunks[int(idx_str)] = b64

        if not indexed_chunks:
            raw_b64s = re.findall(rb'[A-Za-z0-9+/]{40,}={0,2}', data)
            if len(raw_b64s) > 1:
                for i, b in enumerate(raw_b64s):
                    indexed_chunks[i] = b.decode("ascii", errors="ignore")

        if indexed_chunks:
            results["chunks_found"] = len(indexed_chunks)
            sorted_indices = sorted(indexed_chunks.keys())
            full_b64 = "".join(indexed_chunks[idx] for idx in sorted_indices)
            
            try:
                raw_bytes = base64.b64decode(full_b64)
                results["reconstructed"] = True
                
                fmt_info = self.identify_format(raw_bytes)
                ext = fmt_info["primary"].get("ext", "bin")
                results["format"] = fmt_info["primary"]["name"]
                
                out_path = os.path.join(self.output_dir, f"{base_name}_reassembled.{ext}")
                with open(out_path, "wb") as f:
                    f.write(raw_bytes)
                results["saved_to"] = out_path

                from core.string_hunter import StringHunter
                hunter = StringHunter()
                for fl in hunter.hunt_flags(raw_bytes):
                    fl["encoding"] = f"BSON Reconstructed ({fl['encoding']})"
                    results["flags_found"].append(fl)

            except Exception:
                pass

        return results

    def trial_decompress_blob(self, data: bytes) -> Dict[str, Any]:
        """
        Multi-Compressor Trial Decompression (ASIS Finals 2018 pattern):
        - When an unknown binary blob has no magic byte, test trial decompression:
          zlib, bzip2, lzma, and brotli.
        - Checks for compressor signatures (e.g. Brotli ASCII-art 'Brrroootttllliii').
        - Scans decompressed output for flags.
        """
        results: Dict[str, Any] = {
            "decompressed": False,
            "method": None,
            "uncompressed_size": 0,
            "flags_found": []
        }

        # 1. Brotli (if library installed)
        try:
            import brotli
            decomp = brotli.decompress(data)
            results["decompressed"] = True
            results["method"] = "Brotli"
            results["uncompressed_size"] = len(decomp)
            from core.string_hunter import StringHunter
            for fl in StringHunter().hunt_flags(decomp):
                fl["encoding"] = f"Brotli Trial Decompression ({fl['encoding']})"
                results["flags_found"].append(fl)
            return results
        except Exception:
            pass

        # 2. zlib Deflate (raw -15 window & standard)
        for wbits in (-15, 15, 31):
            try:
                decomp = zlib.decompress(data, wbits)
                if len(decomp) > 10:
                    results["decompressed"] = True
                    results["method"] = f"zlib (wbits={wbits})"
                    results["uncompressed_size"] = len(decomp)
                    from core.string_hunter import StringHunter
                    for fl in StringHunter().hunt_flags(decomp):
                        fl["encoding"] = f"zlib Trial Decompression ({fl['encoding']})"
                        results["flags_found"].append(fl)
                    return results
            except Exception:
                pass

        # 3. bz2
        try:
            decomp = bz2.decompress(data)
            results["decompressed"] = True
            results["method"] = "bzip2"
            results["uncompressed_size"] = len(decomp)
            from core.string_hunter import StringHunter
            for fl in StringHunter().hunt_flags(decomp):
                fl["encoding"] = f"bzip2 Trial Decompression ({fl['encoding']})"
                results["flags_found"].append(fl)
            return results
        except Exception:
            pass

        # 4. lzma
        try:
            decomp = lzma.decompress(data)
            results["decompressed"] = True
            results["method"] = "lzma"
            results["uncompressed_size"] = len(decomp)
            from core.string_hunter import StringHunter
            for fl in StringHunter().hunt_flags(decomp):
                fl["encoding"] = f"lzma Trial Decompression ({fl['encoding']})"
                results["flags_found"].append(fl)
            return results
        except Exception:
            pass

        return results

    def carve_recursive(
        self,
        filepath_or_data,
        max_depth: int = 5,
        on_flag_found=None
    ) -> Dict[str, Any]:
        """
        PicoCTF 'Matryoshka doll' / Layered Stego Recursive Carver:
        - Traverses nested embedded archives and images up to max_depth
        - Unpacks embedded ZIP/PNG/GZ/7Z slices iteratively
        - Scans all intermediate carved files for flags
        """
        results: Dict[str, Any] = {
            "depth_reached": 0,
            "carved_files": [],
            "flags_found": []
        }
        from core.string_hunter import StringHunter
        hunter = StringHunter()

        initial_path = None
        initial_data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            initial_path = filepath_or_data
            try:
                with open(initial_path, "rb") as f:
                    initial_data = f.read(50 * 1024 * 1024)
            except Exception:
                return results
        elif isinstance(filepath_or_data, (bytes, bytearray)):
            initial_data = bytes(filepath_or_data)

        if not initial_data:
            return results

        queue = [(initial_path, initial_data, 0)]
        visited_hashes = set()

        while queue:
            cur_path, cur_data, depth = queue.pop(0)
            if depth > max_depth:
                continue

            results["depth_reached"] = max(results["depth_reached"], depth)

            flags = hunter.hunt_flags(cur_data)
            for fl in flags:
                fl["encoding"] = f"Matryoshka Depth {depth} ({fl['encoding']})"
                results["flags_found"].append(fl)
                if on_flag_found:
                    on_flag_found(fl)

            if results["flags_found"]:
                break

            base_name = os.path.basename(cur_path) if cur_path else f"depth_{depth}"
            carved = self.carve_embedded_files(cur_data, base_name=f"d{depth}_{base_name}")
            for c in carved:
                c_p = c["path"]
                results["carved_files"].append(c_p)
                try:
                    with open(c_p, "rb") as cf:
                        cd = cf.read()
                    ch = hash(cd[:1024])
                    if ch not in visited_hashes:
                        visited_hashes.add(ch)
                        queue.append((c_p, cd, depth + 1))
                except Exception:
                    pass

                extracted_dir = c.get("extracted_to")
                if extracted_dir and os.path.exists(extracted_dir):
                    for root, _, files in os.walk(extracted_dir):
                        for ef in files:
                            ef_path = os.path.join(root, ef)
                            try:
                                with open(ef_path, "rb") as eff:
                                    ef_data = eff.read()
                                ef_hash = hash(ef_data[:1024])
                                if ef_hash not in visited_hashes:
                                    visited_hashes.add(ef_hash)
                                    queue.append((ef_path, ef_data, depth + 1))
                            except Exception:
                                pass

        return results
