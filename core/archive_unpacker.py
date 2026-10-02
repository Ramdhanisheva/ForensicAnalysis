"""
Automotion Forensics - Archive Unpacker Engine
Supports .7z (via py7zr), .zip, .tar, .tar.gz, .bz2, .xz.
Safely extracts compressed challenge artifacts (including multi-GB memory dumps)
and handles password-protected CTF archives.
"""

import bz2
import gzip
import lzma
import os
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False


class ArchiveUnpacker:
    """Safe, multi-format archive unpacker with CTF wordlist auto-unlock."""

    CTF_DEFAULT_PASSWORDS = [
        "",
        "password",
        "infected",
        "hacktoday",
        "HackToday",
        "admin",
        "123456",
        "12345678",
        "toor",
        "root",
        "flag",
        "CTF",
        "forensic",
        "forensics"
    ]

    def __init__(self, output_base: Optional[str] = None):
        self.output_base = output_base or "extracted_artifacts"
        os.makedirs(self.output_base, exist_ok=True)

    def is_archive(self, filepath: str, header_sample: bytes = b"") -> Optional[str]:
        """Detect archive type by header or extension."""
        ext = Path(filepath).suffix.lower().lstrip(".")
        name_lower = os.path.basename(filepath).lower()

        if header_sample.startswith(b"7z\xbc\xaf\x27\x1c") or ext == "7z":
            return "7z"
        if header_sample.startswith(b"PK\x03\x04") or ext == "zip":
            return "zip"
        if (len(header_sample) > 262 and header_sample[257:262] == b"ustar") or ext == "tar":
            return "tar"
        if header_sample.startswith(b"\x1f\x8b\x08") or name_lower.endswith((".tar.gz", ".tgz", ".gz")):
            return "tar.gz" if ".tar" in name_lower or ext == "tgz" else "gz"
        if header_sample.startswith(b"BZh") or name_lower.endswith((".tar.bz2", ".tbz2", ".bz2")):
            return "tar.bz2" if ".tar" in name_lower or ext == "tbz2" else "bz2"
        if header_sample.startswith(b"\xfd7zXZ\x00") or name_lower.endswith((".tar.xz", ".txz", ".xz")):
            return "tar.xz" if ".tar" in name_lower or ext == "txz" else "xz"
        if header_sample.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")) or ext == "rar":
            return "rar"

        return None

    def unpack(
        self,
        filepath: str,
        target_dir: Optional[str] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        candidate_passwords: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Unpack archive to target_dir.
        Returns:
            Dict containing list of extracted files, total bytes, archive type, and password used (if any).
        """
        results: Dict[str, Any] = {
            "source": filepath,
            "archive_type": "unknown",
            "success": False,
            "extracted_files": [],
            "password_used": None,
            "error": None
        }

        # Build prioritized password list
        passwords_to_try = []
        seen_p = set()
        if candidate_passwords:
            for cp in candidate_passwords:
                if cp and cp not in seen_p:
                    seen_p.add(cp)
                    passwords_to_try.append(cp)
        for dp in self.CTF_DEFAULT_PASSWORDS:
            if dp not in seen_p:
                seen_p.add(dp)
                passwords_to_try.append(dp)

        if not os.path.exists(filepath):
            results["error"] = "File not found"
            return results

        file_name = os.path.basename(filepath)
        out_dest = target_dir or os.path.join(self.output_base, f"unpacked_{file_name}")
        os.makedirs(out_dest, exist_ok=True)

        with open(filepath, "rb") as f:
            header = f.read(1024)

        arch_type = self.is_archive(filepath, header)
        results["archive_type"] = arch_type or "unknown"

        if not arch_type:
            results["error"] = "Not a recognized archive format"
            return results

        # 1. 7-Zip (.7z)
        if arch_type == "7z":
            if not HAS_PY7ZR:
                results["error"] = "py7zr library not installed, cannot unpack .7z"
                return results

            # Attempt unpack (with passwords if required)
            for pwd in passwords_to_try[:50]:  # cap at 50 attempts
                password = pwd if pwd else None
                try:
                    with py7zr.SevenZipFile(filepath, mode="r", password=password) as archive:
                        all_names = archive.getnames()
                        file_info = archive.list()
                        total_uncompressed = sum(f.uncompressed for f in file_info)
                        
                        if progress_callback:
                            progress_callback("Extracting 7z archive...", 0, total_uncompressed)

                        archive.extractall(path=out_dest)

                        for f_info in file_info:
                            full_p = os.path.join(out_dest, f_info.filename)
                            if os.path.exists(full_p):
                                results["extracted_files"].append({
                                    "filename": f_info.filename,
                                    "path": full_p,
                                    "size_bytes": f_info.uncompressed
                                })

                        results["success"] = True
                        if password:
                            results["password_used"] = password
                        return results
                except py7zr.Bad7zFile:
                    results["error"] = "Corrupted or encrypted 7z archive"
                except py7zr.PasswordRequired:
                    continue
                except Exception as e:
                    results["error"] = f"7z extraction error: {e}"
                    return results

            results["error"] = "7z password required (not in default CTF wordlist)"
            return results

        # 2. ZIP Archive (.zip)
        elif arch_type == "zip":
            try:
                with zipfile.ZipFile(filepath, "r") as zf:
                    # Test password if encrypted
                    test_pwd = None
                    is_encrypted = False
                    for info in zf.infolist():
                        if info.flag_bits & 0x1:
                            is_encrypted = True
                            break

                    if is_encrypted:
                        for pwd in passwords_to_try[:50]:  # cap at 50 attempts
                            try:
                                zf.extractall(path=out_dest, pwd=pwd.encode() if pwd else None)
                                test_pwd = pwd
                                results["password_used"] = pwd
                                break
                            except Exception:
                                continue
                        if test_pwd is None:
                            results["error"] = "Encrypted ZIP password not found in dictionary"
                            return results
                    else:
                        zf.extractall(path=out_dest)

                    for info in zf.infolist():
                        full_p = os.path.join(out_dest, info.filename)
                        if os.path.exists(full_p) and not info.is_dir():
                            results["extracted_files"].append({
                                "filename": info.filename,
                                "path": full_p,
                                "size_bytes": info.file_size
                            })
                    results["success"] = True
                    return results
            except Exception as e:
                results["error"] = f"ZIP extraction error: {e}"
                return results

        # 3. Tar Archives (.tar, .tar.gz, .tar.bz2, .tar.xz)
        elif arch_type in ("tar", "tar.gz", "tar.bz2", "tar.xz"):
            mode = "r:*"
            try:
                with tarfile.open(filepath, mode) as tf:
                    def is_within_directory(directory, target):
                        abs_directory = os.path.abspath(directory)
                        abs_target = os.path.abspath(target)
                        prefix = os.path.commonprefix([abs_directory, abs_target])
                        return prefix == abs_directory

                    seen_names: Dict[str, int] = {}
                    for member in tf.getmembers():
                        member_path = os.path.join(out_dest, member.name)
                        if not is_within_directory(out_dest, member_path):
                            continue

                        # Handle duplicate filenames (BSidesSF 2025 duplicate tar entry attack)
                        extract_path = member_path
                        if member.name in seen_names:
                            seen_names[member.name] += 1
                            base_n, ext_n = os.path.splitext(member.name)
                            unique_name = f"{base_n}_dup{seen_names[member.name]}{ext_n}"
                            extract_path = os.path.join(out_dest, unique_name)
                            # Extract directly to custom path
                            f_obj = tf.extractfile(member)
                            if f_obj:
                                with open(extract_path, "wb") as out_f:
                                    shutil.copyfileobj(f_obj, out_f)
                        else:
                            seen_names[member.name] = 1
                            tf.extract(member, path=out_dest)

                        if member.isfile():
                            results["extracted_files"].append({
                                "filename": os.path.basename(extract_path),
                                "path": extract_path,
                                "size_bytes": member.size
                            })
                    results["success"] = True
                    return results
            except Exception as e:
                results["error"] = f"Tar extraction error: {e}"
                return results

        # 4. Single Compressed Streams (.gz, .bz2, .xz)
        elif arch_type in ("gz", "bz2", "xz"):
            out_name = Path(filepath).stem
            dest_file = os.path.join(out_dest, out_name)
            try:
                if arch_type == "gz":
                    with gzip.open(filepath, "rb") as gf, open(dest_file, "wb") as df:
                        shutil.copyfileobj(gf, df)
                elif arch_type == "bz2":
                    with bz2.open(filepath, "rb") as bf, open(dest_file, "wb") as df:
                        shutil.copyfileobj(bf, df)
                elif arch_type == "xz":
                    with lzma.open(filepath, "rb") as xf, open(dest_file, "wb") as df:
                        shutil.copyfileobj(xf, df)

                if os.path.exists(dest_file):
                    results["extracted_files"].append({
                        "filename": out_name,
                        "path": dest_file,
                        "size_bytes": os.path.getsize(dest_file)
                    })
                    results["success"] = True
                    return results
            except Exception as e:
                results["error"] = f"Decompression error ({arch_type}): {e}"
                return results

        return results
