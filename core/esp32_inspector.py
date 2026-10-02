"""
Automotion Forensics - ESP32 Flash Memory & NVS Inspector
Engine for IoT / ESP-IDF firmware forensics (HackToday 'Durrr Intern'):
- ESP32 Partition Table Parser (magic 0xAA 0xE5 at offset 0x8000)
- NVS (Non-Volatile Storage) Key-Value & Namespace Extractor
- Decoy Flag Detection (filtering intentional prank/bait flags)
- Flash Unallocated Slack Space Carving (e.g. 2MB boundary 0x200000)
- 0x80 XOR Config Deobfuscation (recovering device_cfg keys)
- Continuous Counter Keystream SHA-256 Decryptor for multi-blob fragments
"""

import base64
import hashlib
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

import config
from core.string_hunter import StringHunter


class ESP32Inspector:
    """Inspects ESP32 / ESP-IDF raw flash memory dumps and NVS partitions."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def inspect_flash_dump(self, filepath_or_data) -> Dict[str, Any]:
        """Comprehensive analysis of ESP32 flash memory dump."""
        results: Dict[str, Any] = {
            "is_esp32_flash": False,
            "partition_table": [],
            "nvs_entries": {},
            "slack_space_artifacts": [],
            "recovered_keys": [],
            "decoy_flags": [],
            "flags_found": []
        }

        data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            try:
                with open(filepath_or_data, "rb") as f:
                    data = f.read()
            except Exception:
                return results
        elif isinstance(filepath_or_data, (bytes, bytearray)):
            data = bytes(filepath_or_data)
        else:
            return results

        if len(data) < 0x9000:
            return results

        # 1. Parse ESP-IDF Partition Table at offset 0x8000
        partitions = self._parse_partition_table(data)
        if partitions:
            results["is_esp32_flash"] = True
            results["partition_table"] = partitions

        # 2. Parse NVS Partitions
        nvs_part = next((p for p in partitions if p.get("label") == "nvs" or p.get("subtype") == 0x02), None)
        nvs_offset = nvs_part["offset"] if nvs_part else 0x9000
        nvs_size = nvs_part["size"] if nvs_part else 0x6000

        if nvs_offset + nvs_size <= len(data):
            nvs_data = data[nvs_offset : nvs_offset + nvs_size]
            results["nvs_entries"] = self._parse_nvs_entries(nvs_data, nvs_offset)

        # 3. Detect and Filter Decoy Flags
        all_raw_flags = self.string_hunter.hunt_flags(data)
        for fl in all_raw_flags:
            fl_text = fl.get("flag", "")
            if any(term in fl_text.lower() for term in ("just_l3t_1t_b3", "l3t_1t_b3", "just_let_it_be", "let_it_be", "fake", "decoy", "prank", "bait", "wrong")):
                results["decoy_flags"].append({
                    "flag": fl_text,
                    "reason": "Decoy marker detected in flag content ('just_l3t_1t_b3' / fake pattern)"
                })
            else:
                results["flags_found"].append(fl)

        # 4. Recover Obfuscated Config Keys (0x80 XOR or Single-byte XOR in Factory / App Partitions)
        cfg_matches = re.finditer(
            rb"(?:device_cfg|config|cfg|secret|key|pass|password|token|auth|wifi|salt|seed|aes|enc|cipher)\s*[:=]\s*([^\s\r\n\x00]{4,64})",
            data,
            re.IGNORECASE
        )
        for cm in cfg_matches:
            raw_val = cm.group(1)
            var_name = cm.group(0).decode("latin-1", errors="ignore")[:35]
            offset_hex = hex(cm.start())

            # A. If already printable ASCII (e.g. key=my_secret_token)
            if all(32 <= b <= 126 for b in raw_val) and len(raw_val) >= 6:
                key_candidate = raw_val.decode("latin-1", errors="ignore").strip()
                if not any(k["deobfuscated_key"] == key_candidate for k in results["recovered_keys"]):
                    results["recovered_keys"].append({
                        "var": var_name,
                        "deobfuscated_key": key_candidate,
                        "offset": offset_hex,
                        "method": "Plaintext Config"
                    })

            # B. If high-bit set (0x80 XOR)
            if all(b >= 0x80 for b in raw_val):
                deobf = bytes([b ^ 0x80 for b in raw_val]).decode("latin-1", errors="ignore").strip()
                if not any(k["deobfuscated_key"] == deobf for k in results["recovered_keys"]):
                    results["recovered_keys"].append({
                        "var": var_name,
                        "deobfuscated_key": deobf,
                        "offset": offset_hex,
                        "method": "0x80 High-Bit XOR"
                    })

            # C. General Single-Byte XOR Brute Force on raw config
            for xor_k in range(1, 256):
                cand_bytes = bytes([b ^ xor_k for b in raw_val])
                if all(32 <= b <= 126 for b in cand_bytes):
                    cand_str = cand_bytes.decode("latin-1", errors="ignore").strip()
                    if any(term in cand_str.lower() for term in ("key", "gh0st", "secret", "pass", "token", "flag", "2026", "admin")):
                        if not any(k["deobfuscated_key"] == cand_str for k in results["recovered_keys"]):
                            results["recovered_keys"].append({
                                "var": var_name,
                                "deobfuscated_key": cand_str,
                                "offset": offset_hex,
                                "method": f"Single-Byte XOR 0x{xor_k:02x}"
                            })

        hex_high_bit = re.finditer(rb"[\x80-\xff]{6,48}", data)
        for hm in hex_high_bit:
            candidate = hm.group(0)
            deobf = bytes([b ^ 0x80 for b in candidate]).decode("latin-1", errors="ignore").strip()
            if any(term in deobf.lower() for term in ("key", "gh0st", "secret", "pass", "2026")):
                if not any(k["deobfuscated_key"] == deobf for k in results["recovered_keys"]):
                    results["recovered_keys"].append({
                        "var": "high_bit_string",
                        "deobfuscated_key": deobf,
                        "offset": hex(hm.start()),
                        "method": "0x80 High-Bit String"
                    })

        # 5. Scan Slack Space for Base64 / Hex Cryptographic Fragments (dynamic length)
        max_part_end = max((p["offset"] + p["size"] for p in partitions), default=0x110000)
        if len(data) > max_part_end:
            slack_data = data[max_part_end:]
            # Capture Base64 fragments from 16 to 512 chars
            b64_slack = re.findall(rb"[A-Za-z0-9+/=]{16,512}", slack_data)
            for bs in b64_slack:
                bs_str = bs.decode("ascii", errors="ignore")
                if bs_str not in results["slack_space_artifacts"] and len(bs_str) >= 16:
                    results["slack_space_artifacts"].append(bs_str)

            # Capture Hex fragments from 32 to 512 chars
            hex_slack = re.findall(rb"[0-9a-fA-F]{32,512}", slack_data)
            for hs in hex_slack:
                hs_str = hs.decode("ascii", errors="ignore")
                if hs_str not in results["slack_space_artifacts"]:
                    results["slack_space_artifacts"].append(hs_str)

        # 6. Automated Cryptographic Decryption Solver for Multi-Part Keystreams
        # Gather all candidate fragments from NVS and Slack Space
        all_fragments: List[str] = []
        # Priority: ordered parts (e.g. p1, p2, p3 or blob_p1, blob_p2)
        nvs_sorted_keys = sorted(
            results["nvs_entries"].keys(),
            key=lambda k: (0 if "p1" in k.lower() or "part1" in k.lower() else (1 if "p2" in k.lower() or "part2" in k.lower() else 2))
        )
        for k in nvs_sorted_keys:
            val = results["nvs_entries"][k]
            if val not in all_fragments and len(val) >= 16:
                all_fragments.append(val)

        for s_art in results["slack_space_artifacts"]:
            if s_art not in all_fragments:
                all_fragments.append(s_art)

        keys = [k["deobfuscated_key"].encode() for k in results["recovered_keys"]]
        # Also try default CTF keys if none recovered
        if not keys:
            keys = [b"gh0st_k3y_2026", b"secret", b"esp32", b"flag"]

        # Build fragment permutations to test (single, pair, and ordered p1+p2)
        test_combinations: List[Tuple[str, ...]] = []
        # Pair combinations
        for i, f1 in enumerate(all_fragments[:8]):
            test_combinations.append((f1,))
            for j, f2 in enumerate(all_fragments[:8]):
                if i != j:
                    test_combinations.append((f1, f2))

        for key in keys:
            for comb in test_combinations:
                decrypted_candidates = self._try_generalized_decrypt(comb, key)
                for dec_text, enc_name in decrypted_candidates:
                    candidate_flags = [
                        dec_text,
                        f"HackToday26{{{dec_text}}}",
                        f"flag{{{dec_text}}}",
                        f"HackToday{{{dec_text}}}",
                        f"picoCTF{{{dec_text}}}"
                    ]
                    for cand in candidate_flags:
                        if self.string_hunter.is_valid_flag(cand):
                            fl_obj = {
                                "flag": cand,
                                "encoding": f"ESP32 Crypto ({enc_name}, key='{key.decode(errors='ignore')}')",
                                "context": f"Fragments: {' + '.join(f[:12] + '...' for f in comb)}"
                            }
                            if not any(f["flag"] == cand for f in results["flags_found"]):
                                results["flags_found"].append(fl_obj)

        return results

    def _parse_partition_table(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse ESP-IDF partition table at offset 0x8000 (32 bytes per entry)."""
        partitions = []
        pos = 0x8000
        while pos + 32 <= len(data):
            entry = data[pos : pos + 32]
            magic = entry[:2]
            if magic not in (b"\xaa\x50", b"\xaa\xe5"):
                break
            part_type = entry[2]
            part_subtype = entry[3]
            offset = struct.unpack("<I", entry[4:8])[0]
            size = struct.unpack("<I", entry[8:12])[0]
            label = entry[12:28].split(b"\x00")[0].decode("latin-1", errors="ignore").strip()
            flags = struct.unpack("<I", entry[28:32])[0]

            partitions.append({
                "type": hex(part_type),
                "subtype": hex(part_subtype),
                "offset": offset,
                "size": size,
                "label": label,
                "flags": hex(flags)
            })
            pos += 32

        return partitions

    def _parse_nvs_entries(self, nvs_data: bytes, base_offset: int) -> Dict[str, str]:
        """Extract strings and Base64/Hex blobs of any length from ESP32 NVS pages."""
        entries = {}
        # Dynamic regex for arbitrary key-value pairs
        kv_matches = re.finditer(rb"([a-zA-Z0-9_\-]{1,32})\x00+([A-Za-z0-9+/=]{12,256})", nvs_data)
        for km in kv_matches:
            key_name = km.group(1).decode("latin-1", errors="ignore")
            val_str = km.group(2).decode("latin-1", errors="ignore")
            if val_str not in ("bCLEARED", "CLEARED") and len(val_str) >= 12:
                entries[key_name] = val_str

        # Dynamic regex for loose Base64 blobs of variable length (16 to 256)
        b64_nvs = re.findall(rb"[A-Za-z0-9+/=]{16,256}", nvs_data)
        for idx, bs in enumerate(b64_nvs):
            bs_str = bs.decode("ascii", errors="ignore")
            if bs_str not in entries.values() and bs_str != "bCLEARED":
                entries[f"blob_{idx}"] = bs_str

        return entries

    def _try_generalized_decrypt(self, fragments: Tuple[str, ...], key: bytes) -> List[Tuple[str, str]]:
        """
        Generalized multi-mode decryption:
        - Supports arbitrary number of fragments concatenated or individually
        - Supports Base64 and Hex decoded ciphertexts
        - Tests SHA-256 / SHA-1 / MD5 counter mode keystreams (both big/little endian, counter 0/1)
        - Tests repeating XOR and RC4 stream cipher
        """
        results: List[Tuple[str, str]] = []
        combined_str = "".join(fragments)

        # 1. Try decoding as Base64
        candidate_ciphertexts: List[Tuple[bytes, str]] = []
        try:
            pad = (4 - len(combined_str) % 4) % 4
            candidate_ciphertexts.append((base64.b64decode(combined_str + "=" * pad), "Base64"))
        except Exception:
            pass

        # 2. Try decoding as Hex
        try:
            candidate_ciphertexts.append((bytes.fromhex(combined_str), "Hex"))
        except Exception:
            pass

        # 3. Direct bytes
        candidate_ciphertexts.append((combined_str.encode("latin-1", errors="ignore"), "Raw"))

        for ciphertext, enc_label in candidate_ciphertexts:
            if len(ciphertext) < 8:
                continue

            # Mode A: Continuous Counter Keystream (SHA-256, SHA-1, MD5)
            for hash_name in ("sha256", "sha1", "md5"):
                h_factory = getattr(hashlib, hash_name, None)
                if not h_factory:
                    continue

                for endian in ("big", "little"):
                    for start_cnt in (0, 1):
                        for key_first in (True, False):
                            try:
                                keystream = bytearray()
                                counter = start_cnt
                                while len(keystream) < len(ciphertext):
                                    cnt_bytes = counter.to_bytes(4, endian)
                                    feed = (key + cnt_bytes) if key_first else (cnt_bytes + key)
                                    keystream.extend(h_factory(feed).digest())
                                    counter += 1

                                plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream[:len(ciphertext)])])
                                text = plaintext.decode("utf-8", errors="ignore").strip()
                                if len(text) >= 10 and all(32 <= ord(c) <= 126 for c in text):
                                    results.append((text, f"Continuous {hash_name.upper()} counter-{endian}-{start_cnt} ({enc_label})"))
                            except Exception:
                                pass

            # Mode B: Repeating Key XOR
            try:
                if len(key) > 0:
                    xor_pt = bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)])
                    text = xor_pt.decode("utf-8", errors="ignore").strip()
                    if len(text) >= 10 and all(32 <= ord(c) <= 126 for c in text):
                        results.append((text, f"Repeating XOR ({enc_label})"))
            except Exception:
                pass

            # Mode C: RC4 / ArcFour Stream Cipher
            try:
                rc4_pt = self._rc4_decrypt(key, ciphertext)
                text = rc4_pt.decode("utf-8", errors="ignore").strip()
                if len(text) >= 10 and all(32 <= ord(c) <= 126 for c in text):
                    results.append((text, f"RC4 Stream ({enc_label})"))
            except Exception:
                pass

        return results

    def _rc4_decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        """Pure-Python standard RC4 / ArcFour stream cipher."""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        i = j = 0
        keystream = bytearray()
        for _ in range(len(ciphertext)):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream.append(S[(S[i] + S[j]) % 256])

        return bytes([c ^ k for c, k in zip(ciphertext, keystream)])

    def _try_continuous_sha256_counter_decrypt(self, p1: str, p2: str, key: bytes) -> Optional[str]:
        """Backward-compatible helper for continuous SHA-256 counter mode."""
        res = self._try_generalized_decrypt((p1, p2), key)
        for text, _ in res:
            if len(text) >= 10:
                return text
        return None
