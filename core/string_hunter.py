"""
Automotion Forensics - String Hunter Engine
Deep string extraction, multi-encoding decoders (Base64, Hex, ROT13, Reverse, XOR),
and suspicious pattern detection.
"""

import base64
import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple

import config

# Base58 Bitcoin alphabet
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(v: str) -> Optional[bytes]:
    """Decode Base58 string (Bitcoin / IPFS format)."""
    try:
        num = 0
        for char in v:
            idx = B58_ALPHABET.find(char)
            if idx == -1:
                return None
            num = num * 58 + idx
        combined = num.to_bytes((num.bit_length() + 7) // 8, "big")
        npad = len(v) - len(v.lstrip("1"))
        return b"\x00" * npad + combined
    except Exception:
        return None

def rot47(s: str) -> str:
    """Standard ASCII printable ROT47 cipher shift."""
    res = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            res.append(chr(33 + ((o - 33 + 47) % 94)))
        else:
            res.append(c)
    return "".join(res)

def atbash(s: str) -> str:
    """Alphabet inversion Atbash cipher."""
    res = []
    for c in s:
        if 'a' <= c <= 'z':
            res.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif 'A' <= c <= 'Z':
            res.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif '0' <= c <= '9':
            res.append(chr(ord('9') - (ord(c) - ord('0'))))
        else:
            res.append(c)
    return "".join(res)

MORSE_CODE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
    '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
    '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
    '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
    '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
    '---..': '8', '----.': '9', '-.--.': '{', '-.--.-': '}', '..--.-': '_',
    '-...-': '=', '.-.-.-': '.', '--..--': ','
}

def decode_morse(s: str) -> Optional[str]:
    """Decode space-delimited Morse code."""
    try:
        cleaned = s.strip()
        words = cleaned.split("   ") if "   " in cleaned else cleaned.split(" / ") if " / " in cleaned else [cleaned]
        res_words = []
        for w in words:
            letters = []
            for ch in w.split():
                c_clean = ch.strip()
                if c_clean in MORSE_CODE_DICT:
                    letters.append(MORSE_CODE_DICT[c_clean])
                else:
                    return None
            res_words.append("".join(letters))
        return " ".join(res_words)
    except Exception:
        return None

BACON_DICT_26 = {
    "AAAAA": "A", "AAAAB": "B", "AAABA": "C", "AAABB": "D", "AABAA": "E",
    "AABAB": "F", "AABBA": "G", "AABBB": "H", "ABAAA": "I", "ABAAB": "J",
    "ABABA": "K", "ABABB": "L", "ABBAA": "M", "ABBAB": "N", "ABBBA": "O",
    "ABBBB": "P", "BAAAA": "Q", "BAAAB": "R", "BAABA": "S", "BAABB": "T",
    "BABAA": "U", "BABAB": "V", "BABBA": "W", "BABBB": "X", "BBAAA": "Y", "BBAAB": "Z"
}

def decode_bacon(s: str) -> Optional[str]:
    """Decode 5-symbol Baconian cipher."""
    try:
        clean = "".join(c for c in s.upper() if c in ("A", "B"))
        if len(clean) < 15 or len(clean) % 5 != 0:
            return None
        res = []
        for i in range(0, len(clean), 5):
            chunk = clean[i:i + 5]
            if chunk in BACON_DICT_26:
                res.append(BACON_DICT_26[chunk])
            else:
                return None
        return "".join(res)
    except Exception:
        return None


class StringHunter:
    """Extracts and decodes flags and suspicious indicators from text or raw bytes."""

    def __init__(self):
        self.flag_patterns = config.FLAG_PATTERNS
        self.suspicious_regex = config.SUSPICIOUS_REGEX

    def extract_ascii_strings(self, data: bytes, min_len: int = 4) -> List[str]:
        """Fast extraction of printable ASCII strings from raw bytes."""
        pattern = f"[ -~]{{{min_len},}}".encode("ascii")
        matches = re.findall(pattern, data)
        return [m.decode("ascii", errors="ignore") for m in matches]

    def is_valid_flag(self, fl: str) -> bool:
        """Validate that candidate flag adheres to real CTF flag formatting."""
        if not ("{" in fl and fl.endswith("}")):
            return False
        inner = fl[fl.find("{") + 1 : -1]
        if len(inner) < 3 or len(inner) > 120:
            return False
        # Inner MUST NOT contain another opening or closing brace
        if "{" in inner or "}" in inner:
            return False
        # Short 3-char flags must be strictly alphanumeric (e.g. flag{hid})
        if len(inner) == 3:
            return inner.isalnum()
        # Flag inner content MUST be printable ASCII (32 to 126)
        if not all(32 <= ord(c) <= 126 for c in inner):
            return False
        # Filter noise collisions: require at least 40% alphanumeric chars
        alnum_count = sum(1 for c in inner if c.isalnum())
        if alnum_count < 2 or (alnum_count / len(inner)) < 0.4:
            return False
        # Filter random punctuation in short candidates
        if len(inner) < 8 and any(c in inner for c in "[]()\\;`^~?"):
            return False
        # Filter excessive repeated punctuation noise
        if any(inner.count(c) > 3 for c in "[]()\\;`^~?"):
            return False
        return True

    def hunt_flags(
        self,
        text_or_bytes,
        early_stop: bool = False,
        on_flag_found=None,
        depth: int = 0
    ) -> List[Dict[str, str]]:
        """
        Scan for flags in plaintext and across multiple encoding/cipher layers:
        - Plaintext & URL-decoded
        - Base64, Base32, Base85, Ascii85, Base58
        - Hex, Hex escapes, Decimal streams, Binary streams, Octal streams
        - Caesar (ROT 1-25), ROT18, ROT47, Atbash, Baconian, Morse Code
        - Single-byte XOR & Multi-byte Repeating XOR
        - Recursive Multi-layer Decoding (depth up to 2)
        """
        found_flags: List[Dict[str, str]] = []
        seen_flags: Set[str] = set()
        intermediate_texts: List[str] = []

        def _record_flag(flag: str, enc: str, ctx: str):
            if not self.is_valid_flag(flag):
                return
            if flag not in seen_flags:
                seen_flags.add(flag)
                entry = {"flag": flag, "encoding": enc, "context": ctx}
                found_flags.append(entry)
                if on_flag_found:
                    try:
                        on_flag_found(entry)
                    except Exception:
                        pass

        if isinstance(text_or_bytes, bytes):
            raw_text = text_or_bytes.decode("latin-1", errors="ignore")
            raw_bytes = text_or_bytes
        else:
            raw_text = str(text_or_bytes)
            raw_bytes = raw_text.encode("latin-1", errors="ignore")

        # 1. Plaintext scan
        for pattern in self.flag_patterns:
            for match in pattern.finditer(raw_text):
                flag = match.group(0).strip()
                _record_flag(flag, "Plaintext", raw_text[max(0, match.start() - 30):min(len(raw_text), match.end() + 30)].strip())

        if early_stop and found_flags:
            return found_flags

        # 2. URL-encoded scan
        if "%" in raw_text:
            unquoted = urllib.parse.unquote(raw_text)
            intermediate_texts.append(unquoted)
            for pattern in self.flag_patterns:
                for match in pattern.finditer(unquoted):
                    flag = match.group(0).strip()
                    _record_flag(flag, "URL-decoded", unquoted[max(0, match.start() - 20):min(len(unquoted), match.end() + 20)].strip())

        if early_stop and found_flags:
            return found_flags

        # 3. Base64 scan
        b64_matches = re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", raw_text)
        for cand in set(b64_matches):
            try:
                pad_len = (4 - len(cand) % 4) % 4
                padded = cand + ("=" * pad_len)
                decoded = base64.b64decode(padded.encode("ascii"), validate=False)
                dec_text = decoded.decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_text)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_text):
                        flag = match.group(0).strip()
                        _record_flag(flag, f"Base64 (raw: {cand[:40]}...)", dec_text[:100].strip())
                # Also try decoding as UTF-16LE (PowerShell -EncodedCommand)
                try:
                    dec_utf16 = decoded.decode("utf-16le", errors="ignore")
                    intermediate_texts.append(dec_utf16)
                    for pattern in self.flag_patterns:
                        for match in pattern.finditer(dec_utf16):
                            flag = match.group(0).strip()
                            _record_flag(flag, f"Base64 UTF-16LE (PowerShell EncodedCommand)", dec_utf16[:100].strip())
                except Exception:
                    pass
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 4. Base32 scan (RFC 4648)
        b32_matches = re.findall(r"\b[A-Z2-7=]{16,}\b", raw_text.upper())
        for cand in set(b32_matches):
            try:
                pad_len = (8 - len(cand) % 8) % 8
                padded = cand + ("=" * pad_len)
                decoded = base64.b32decode(padded.encode("ascii"))
                dec_text = decoded.decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_text)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_text):
                        _record_flag(match.group(0).strip(), f"Base32 (raw: {cand[:30]}...)", dec_text[:100].strip())
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 5. Base85 & Ascii85 scan
        b85_matches = re.findall(r"[0-9a-zA-Z!#$%&()*+;<=>?@^_`{|}~-]{16,}", raw_text)
        for cand in set(b85_matches):
            try:
                dec = base64.b85decode(cand.encode("ascii"))
                dec_text = dec.decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_text)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_text):
                        _record_flag(match.group(0).strip(), f"Base85 (raw: {cand[:30]}...)", dec_text[:100].strip())
            except Exception:
                pass

        a85_matches = re.findall(r"[!-u]{16,}", raw_text)
        for cand in set(a85_matches):
            try:
                dec = base64.a85decode(cand.encode("ascii"))
                dec_text = dec.decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_text)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_text):
                        _record_flag(match.group(0).strip(), f"Ascii85 (raw: {cand[:30]}...)", dec_text[:100].strip())
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 6. Base58 scan (Bitcoin format)
        b58_matches = re.findall(r"\b[1-9A-HJ-NP-Za-km-z]{16,}\b", raw_text)
        for cand in set(b58_matches):
            try:
                dec = b58decode(cand)
                if dec:
                    dec_text = dec.decode("latin-1", errors="ignore")
                    intermediate_texts.append(dec_text)
                    for pattern in self.flag_patterns:
                        for match in pattern.finditer(dec_text):
                            _record_flag(match.group(0).strip(), f"Base58 (raw: {cand[:30]}...)", dec_text[:100].strip())
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 7. Hex string & Hex escapes scan
        hex_matches = re.findall(r"\b(?:[0-9a-fA-F]{2}){8,}\b", raw_text)
        for h in set(hex_matches):
            try:
                decoded_hex = bytes.fromhex(h).decode("latin-1", errors="ignore")
                intermediate_texts.append(decoded_hex)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(decoded_hex):
                        flag = match.group(0).strip()
                        _record_flag(flag, f"Hex (raw: {h[:30]}...)", decoded_hex[:100].strip())
            except Exception:
                pass

        hex_esc_matches = re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", raw_text)
        for he in set(hex_esc_matches):
            try:
                hx = he.replace("\\x", "")
                dec_hx = bytes.fromhex(hx).decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_hx)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_hx):
                        _record_flag(match.group(0).strip(), "Hex Escape Stream", dec_hx[:100].strip())
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 8. Decimal Byte Stream scan (e.g. 72 97 99 107...)
        dec_matches = re.findall(r"\b(?:(?:[3-9][0-9]|1[0-1][0-9]|12[0-6])[ ,;\-]+){4,}(?:[3-9][0-9]|1[0-1][0-9]|12[0-6])\b", raw_text)
        for d in set(dec_matches):
            try:
                nums = [int(x) for x in re.split(r"[ ,;\-]+", d.strip()) if x]
                dec_str = bytes(nums).decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_str)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_str):
                        _record_flag(match.group(0).strip(), "Decimal Byte Stream", dec_str[:100].strip())
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 9. Binary 8-bit Stream scan (e.g. 01001000 01100001...)
        bin_matches = re.findall(r"\b(?:[01]{8}[ \t]*){4,}\b", raw_text)
        for b in set(bin_matches):
            try:
                octets = re.findall(r"[01]{8}", b)
                dec_str = bytes(int(x, 2) for x in octets).decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_str)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_str):
                        _record_flag(match.group(0).strip(), "Binary 8-bit Stream", dec_str[:100].strip())
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 10. Octal Stream scan (e.g. \110\141\143...)
        oct_matches = re.findall(r"(?:\\(?:[0-1]?[0-7]{2}|[0-7]{3})){4,}", raw_text)
        for o in set(oct_matches):
            try:
                vals = [int(x, 8) for x in re.findall(r"\\([0-7]{2,3})", o)]
                dec_str = bytes(vals).decode("latin-1", errors="ignore")
                intermediate_texts.append(dec_str)
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(dec_str):
                        _record_flag(match.group(0).strip(), "Octal Stream", dec_str[:100].strip())
            except Exception:
                pass

        if early_stop and found_flags:
            return found_flags

        # 11. Reverse scan
        rev_text = raw_text[::-1]
        for pattern in self.flag_patterns:
            for match in pattern.finditer(rev_text):
                flag = match.group(0).strip()
                _record_flag(flag, "Reversed string", rev_text[max(0, match.start() - 20):min(len(rev_text), match.end() + 20)].strip())

        if early_stop and found_flags:
            return found_flags

        # 12. ROT47 & Atbash
        r47_cand = rot47(raw_text)
        for pattern in self.flag_patterns:
            for match in pattern.finditer(r47_cand):
                _record_flag(match.group(0).strip(), "ROT47", r47_cand[max(0, match.start() - 20):min(len(r47_cand), match.end() + 20)].strip())

        atb_cand = atbash(raw_text)
        for pattern in self.flag_patterns:
            for match in pattern.finditer(atb_cand):
                _record_flag(match.group(0).strip(), "Atbash", atb_cand[max(0, match.start() - 20):min(len(atb_cand), match.end() + 20)].strip())

        # 13. Morse Code & Baconian Cipher
        morse_candidates = re.findall(r"[.\-]{1,8}(?:[ \t]+[.\-]{1,8}){5,}", raw_text)
        for mc in set(morse_candidates):
            decoded_m = decode_morse(mc)
            if decoded_m:
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(decoded_m):
                        _record_flag(match.group(0).strip(), "Morse Code", decoded_m[:100].strip())

        bacon_cands = re.findall(r"\b[ABab]{20,}\b", raw_text)
        for bc in set(bacon_cands):
            for mode, m_label in ((bc.upper(), "Standard"), (bc.upper().replace("A", "X").replace("B", "A").replace("X", "B"), "Inverted")):
                dec_b = decode_bacon(mode)
                if dec_b:
                    for pattern in self.flag_patterns:
                        for match in pattern.finditer(dec_b):
                            _record_flag(match.group(0).strip(), f"Baconian Cipher ({m_label})", dec_b[:100].strip())

        if early_stop and found_flags:
            return found_flags

        # 14. ROT13 & ROT18 (ROT13 letters + ROT5 digits)
        candidate_blocks = re.findall(r"[A-Za-z0-9_]{3,30}\{[^}\n\r\t]{4,100}\}", raw_text)
        for block in set(candidate_blocks):
            # Standard Caesar shifts 1-25
            for shift in range(1, 26):
                shifted = []
                for c in block:
                    if 'a' <= c <= 'z':
                        shifted.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
                    elif 'A' <= c <= 'Z':
                        shifted.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
                    else:
                        shifted.append(c)
                shifted_str = "".join(shifted)
                for pattern in self.flag_patterns:
                    m = pattern.search(shifted_str)
                    if m:
                        flag = m.group(0).strip()
                        _record_flag(flag, f"Caesar/ROT (shift={shift}, raw: {block})", shifted_str)

            # ROT18: ROT13 on letters + ROT5 on digits
            rot18 = []
            for c in block:
                if 'a' <= c <= 'z':
                    rot18.append(chr((ord(c) - ord('a') - 13) % 26 + ord('a')))
                elif 'A' <= c <= 'Z':
                    rot18.append(chr((ord(c) - ord('A') - 13) % 26 + ord('A')))
                elif '0' <= c <= '9':
                    rot18.append(chr((ord(c) - ord('0') - 5) % 10 + ord('0')))
                else:
                    rot18.append(c)
            rot18_str = "".join(rot18)
            for pattern in self.flag_patterns:
                m = pattern.search(rot18_str)
                if m:
                    flag = m.group(0).strip()
                    _record_flag(flag, f"ROT18 (ROT13+ROT5, raw: {block})", rot18_str)

        if early_stop and found_flags:
            return found_flags

        # 7. Two-layer Byte Deinterleaving (even and odd bytes)
        if len(raw_bytes) >= 16:
            even_bytes = raw_bytes[0::2]
            odd_bytes = raw_bytes[1::2]
            for deint_label, db in (("Even-bytes", even_bytes), ("Odd-bytes", odd_bytes)):
                d_str = db.decode("latin-1", errors="ignore")
                for pattern in self.flag_patterns:
                    for match in pattern.finditer(d_str):
                        flag = match.group(0).strip()
                        _record_flag(flag, f"Deinterleaved ({deint_label})", d_str[max(0, match.start() - 20):min(len(d_str), match.end() + 20)].strip())

        if early_stop and found_flags:
            return found_flags

        # 8. Single-byte XOR scan on chunks up to 1MB
        scan_xor_data = raw_bytes[:1024 * 1024]
        for key in range(1, 256):
            xored_prefixes = [bytes(b ^ key for b in p) for p in config.FLAG_PREFIXES]
            for p_idx, xp in enumerate(xored_prefixes):
                pos = scan_xor_data.find(xp)
                if pos != -1:
                    slice_start = max(0, pos - 20)
                    slice_end = min(len(scan_xor_data), pos + 200)
                    decrypted_slice = bytes(b ^ key for b in scan_xor_data[slice_start:slice_end])
                    dec_str = decrypted_slice.decode("latin-1", errors="ignore")
                    for pattern in self.flag_patterns:
                        m = pattern.search(dec_str)
                        if m:
                            flag = m.group(0).strip()
                            _record_flag(flag, f"Single-Byte XOR (key=0x{key:02x})", dec_str[:100].strip())

        # 15. Multi-byte repeating XOR scan (2, 3, 4 bytes)
        if not found_flags or not early_stop:
            rep_flags = self.hunt_repeating_xor_flags(raw_bytes)
            for rf in rep_flags:
                _record_flag(rf["flag"], rf["encoding"], rf["context"])

        # 16. Multi-layer Recursive Decoding (Level 2)
        if depth < 1 and not (early_stop and found_flags):
            candidates = [it for it in intermediate_texts if len(it) >= 12 and not any(it == f["flag"] for f in found_flags)]
            for cand_inter in set(candidates[:15]):
                nested = self.hunt_flags(cand_inter, early_stop=early_stop, on_flag_found=on_flag_found, depth=depth + 1)
                for nf in nested:
                    _record_flag(nf["flag"], f"Layered [{nf['encoding']}]", nf["context"])

        return found_flags

    def hunt_repeating_xor_flags(
        self,
        raw_bytes: bytes,
        max_scan_len: int = 128 * 1024,
        key_lens: Tuple[int, ...] = (2, 3, 4)
    ) -> List[Dict[str, str]]:
        """
        Multi-byte repeating XOR flag hunter (VuwCTF, srdnlenCTF pattern):
        Deduces repeating XOR key from known flag prefixes and validates key periodicity.
        """
        results = []
        scan_data = raw_bytes[:max_scan_len]
        data_len = len(scan_data)

        for prefix in config.FLAG_PREFIXES:
            p_len = len(prefix)
            for k_len in key_lens:
                # Require at least 2 bytes of periodicity verification to prevent false positive blowup
                if p_len < k_len + 2:
                    continue

                target_d0 = prefix[0] ^ prefix[k_len]
                target_d1 = prefix[1] ^ prefix[k_len + 1]

                for i in range(data_len - p_len):
                    # Fast delta check filters 99.998% of candidate offsets in single comparison
                    if (scan_data[i] ^ scan_data[i + k_len]) != target_d0 or (scan_data[i + 1] ^ scan_data[i + k_len + 1]) != target_d1:
                        continue

                    # Deducing candidate key bytes
                    cand_key = [scan_data[i + j] ^ prefix[j] for j in range(k_len)]
                    # Check if candidate key matches remainder of prefix
                    match = True
                    for j in range(k_len, p_len):
                        if (scan_data[i + j] ^ prefix[j]) != cand_key[j % k_len]:
                            match = False
                            break
                    if match:
                        # Candidate found! Decrypt next up to 100 bytes
                        slice_len = min(100, data_len - i)
                        dec = bytes(scan_data[i + idx] ^ cand_key[idx % k_len] for idx in range(slice_len))
                        dec_str = dec.decode("latin-1", errors="ignore")
                        for pattern in self.flag_patterns:
                            m = pattern.search(dec_str)
                            if m:
                                flag = m.group(0).strip()
                                if not self.is_valid_flag(flag):
                                    continue
                                key_hex = " ".join(f"0x{b:02x}" for b in cand_key)
                                results.append({
                                    "flag": flag,
                                    "encoding": f"Repeating XOR ({k_len}-byte, key=[{key_hex}])",
                                    "context": dec_str[:80].strip()
                                })
        return results

    def brute_force_charset_xor(
        self,
        ciphertext: bytes,
        key_len: int = 4,
        allowed_chars: Optional[Set[int]] = None
    ) -> List[Dict[str, Any]]:
        """
        WordPerfect Macro / Byte Array XOR Brute-forcer under charset constraints (srdnlenCTF 2026):
        - Finds valid key bytes independently for each position mod key_len
        - Validates Cartesian product for flag format
        """
        if len(ciphertext) < key_len * 2:
            return []

        if allowed_chars is None:
            # Standard CTF flag characters: a-z, A-Z, 0-9, _, {, }, -, !
            allowed_chars = set(ord(c) for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-! @:")

        cands = []
        for j in range(key_len):
            good = []
            slice_indices = range(j, len(ciphertext), key_len)
            for k in range(256):
                if all((ciphertext[i] ^ k) in allowed_chars for i in slice_indices):
                    good.append(k)
            cands.append(good)
            if not good:
                return []

        import itertools
        recovered = []
        for key in itertools.product(*cands):
            pt = bytes(b ^ key[i % key_len] for i, b in enumerate(ciphertext))
            pt_str = pt.decode("latin-1", errors="ignore")
            for pattern in self.flag_patterns:
                m = pattern.search(pt_str)
                if m:
                    flag = m.group(0).strip()
                    key_hex = " ".join(f"0x{b:02x}" for b in key)
                    recovered.append({
                        "flag": flag,
                        "encoding": f"Charset-Constrained XOR ({key_len}-byte, key=[{key_hex}])",
                        "context": pt_str[:80].strip()
                    })
        return recovered

    def hunt_suspicious_patterns(self, text_or_bytes, limit_per_type: int = 10) -> Dict[str, List[str]]:
        """Scan for suspicious patterns like passwords, URLs, commands, keys."""
        results: Dict[str, List[str]] = {}

        if isinstance(text_or_bytes, bytes):
            text = text_or_bytes.decode("latin-1", errors="ignore")
        else:
            text = str(text_or_bytes)

        for regex, label in self.suspicious_regex:
            matches = []
            for m in regex.finditer(text):
                val = m.group(0).strip()
                if val and val not in matches:
                    matches.append(val)
                    if len(matches) >= limit_per_type:
                        break
            if matches:
                results[label] = matches

        return results
