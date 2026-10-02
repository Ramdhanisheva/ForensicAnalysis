"""
Automotion Forensics - PDF Inspector Engine
Extracts plaintext, FlateDecode streams, metadata, and handles password-protected
PDFs via wordlists (rockyou) and pdf2john + john / qpdf integration.
"""

import os
import re
import shutil
import subprocess
import zlib
from typing import Any, Dict, List, Optional

try:
    import pypdf
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False

from core.string_hunter import StringHunter


def to_wsl_path(win_path: str) -> str:
    """Convert Windows path to WSL /mnt/<drive>/... path."""
    abs_p = os.path.abspath(win_path)
    drive, rest = os.path.splitdrive(abs_p)
    clean_rest = rest.replace("\\", "/")
    if drive:
        return f"/mnt/{drive[0].lower()}" + clean_rest
    return clean_rest


class PDFInspector:
    """Inspects PDF files, decrypts password-protected PDFs, and extracts embedded streams."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def inspect(self, filepath: str, candidate_passwords: Optional[List[str]] = None) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "source": filepath,
            "is_pdf": False,
            "is_encrypted": False,
            "decrypted": False,
            "password_used": None,
            "pages_extracted": 0,
            "flags_found": [],
            "streams_carved": 0
        }

        if not os.path.exists(filepath):
            results["error"] = "File not found"
            return results

        with open(filepath, "rb") as f:
            raw_bytes = f.read()

        if not raw_bytes.startswith(b"%PDF"):
            results["error"] = "Not a valid PDF header"
            return results

        results["is_pdf"] = True

        # Check raw bytes for flags directly
        for fl in self.string_hunter.hunt_flags(raw_bytes):
            fl["encoding"] = f"Raw PDF Stream ({fl['encoding']})"
            results["flags_found"].append(fl)

        # Decompress unencrypted FlateDecode streams
        stream_matches = re.finditer(rb"stream[\r\n]+(.*?)(?:[\r\n]+endstream)", raw_bytes, re.DOTALL)
        for sm in stream_matches:
            s_data = sm.group(1)
            try:
                dec = zlib.decompress(s_data)
                results["streams_carved"] += 1
                for fl in self.string_hunter.hunt_flags(dec):
                    fl["encoding"] = f"FlateDecode Stream ({fl['encoding']})"
                    results["flags_found"].append(fl)
            except Exception:
                pass

        # Check encryption
        is_encrypted = b"/Encrypt" in raw_bytes
        results["is_encrypted"] = is_encrypted

        passwords_to_try = []
        if candidate_passwords:
            passwords_to_try.extend([p for p in candidate_passwords if p])
        passwords_to_try.extend(["", "password", "spongebob", "admin", "123456", "CTF", "sunctf", "flag"])

        # Try pypdf decrypt if available
        if HAS_PYPDF and is_encrypted:
            try:
                reader = pypdf.PdfReader(filepath)
                if reader.is_encrypted:
                    for pwd in passwords_to_try:
                        try:
                            if reader.decrypt(pwd) > 0:
                                results["decrypted"] = True
                                results["password_used"] = pwd
                                text = ""
                                for page in reader.pages:
                                    text += page.extract_text() or ""
                                results["pages_extracted"] = len(reader.pages)
                                for fl in self.string_hunter.hunt_flags(text.encode()):
                                    fl["encoding"] = f"Decrypted PDF Text ({fl['encoding']})"
                                    results["flags_found"].append(fl)
                                break
                        except Exception:
                            continue
            except Exception:
                pass

        # If still encrypted and flags not found, try WSL pdf2john + john
        if is_encrypted and not results["flags_found"]:
            wsl_pdf = to_wsl_path(filepath)
            wsl_hash = f"/tmp/pdf_{os.path.basename(filepath)}.hash"
            wsl_dec = to_wsl_path(os.path.join(self.output_dir, f"decrypted_{os.path.basename(filepath)}"))

            try:
                # 1. Try crack with john
                cmd = f"pdf2john '{wsl_pdf}' > '{wsl_hash}' 2>/dev/null; john '{wsl_hash}' -w=/usr/share/wordlists/rockyou.txt 2>/dev/null; john --show '{wsl_hash}'"
                p = subprocess.run(["wsl", "-u", "root", "-d", "kali-linux", "bash", "-c", cmd], capture_output=True, text=True, timeout=15)
                cracked_pwd = None
                for line in p.stdout.splitlines():
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2 and parts[1].strip():
                            cracked_pwd = parts[1].strip()
                            break

                if not cracked_pwd:
                    for cp in passwords_to_try:
                        q_chk = subprocess.run(
                            ["wsl", "-u", "root", "-d", "kali-linux", "qpdf", f"--password={cp}", "--decrypt", wsl_pdf, wsl_dec],
                            capture_output=True, timeout=5
                        )
                        if q_chk.returncode == 0:
                            cracked_pwd = cp
                            break

                if cracked_pwd is not None:
                    results["decrypted"] = True
                    results["password_used"] = cracked_pwd
                    # Decrypt with qpdf
                    subprocess.run(
                        ["wsl", "-u", "root", "-d", "kali-linux", "qpdf", f"--password={cracked_pwd}", "--decrypt", wsl_pdf, wsl_dec],
                        capture_output=True, timeout=10
                    )
                    # Extract text via pdftotext
                    txt_p = subprocess.run(
                        ["wsl", "-u", "root", "-d", "kali-linux", "pdftotext", wsl_dec, "-"],
                        capture_output=True, text=True, timeout=10
                    )
                    if txt_p.stdout:
                        for fl in self.string_hunter.hunt_flags(txt_p.stdout.encode()):
                            fl["encoding"] = f"Cracked PDF Text ({fl['encoding']})"
                            results["flags_found"].append(fl)

                    # Also check strings of decrypted pdf
                    dec_local = os.path.join(self.output_dir, f"decrypted_{os.path.basename(filepath)}")
                    if os.path.exists(dec_local):
                        with open(dec_local, "rb") as dec_f:
                            for fl in self.string_hunter.hunt_flags(dec_f.read()):
                                fl["encoding"] = f"Cracked PDF Raw ({fl['encoding']})"
                                results["flags_found"].append(fl)
            except Exception:
                pass

        return results
