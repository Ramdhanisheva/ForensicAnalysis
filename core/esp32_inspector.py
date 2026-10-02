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

        # 4. Recover Obfuscated Config Keys (0x80 XOR in Factory / App Partitions)
        cfg_matches = re.finditer(rb"(?:device_cfg|config|secret|key)\s*=\s*([^\s\r\n\x00]{8,64})", data, re.IGNORECASE)
        for cm in cfg_matches:
            raw_val = cm.group(1)
            if all(b >= 0x80 for b in raw_val):
                deobf = bytes([b ^ 0x80 for b in raw_val]).decode("latin-1", errors="ignore").strip()
                results["recovered_keys"].append({
                    "var": cm.group(0).decode("latin-1", errors="ignore")[:30],
                    "deobfuscated_key": deobf,
                    "offset": hex(cm.start())
                })

        hex_high_bit = re.finditer(rb"[\x80-\xff]{8,32}", data)
        for hm in hex_high_bit:
            candidate = hm.group(0)
            deobf = bytes([b ^ 0x80 for b in candidate]).decode("latin-1", errors="ignore").strip()
            if any(term in deobf.lower() for term in ("key", "gh0st", "secret", "pass", "2026")):
                if not any(k["deobfuscated_key"] == deobf for k in results["recovered_keys"]):
                    results["recovered_keys"].append({
                        "var": "high_bit_string",
                        "deobfuscated_key": deobf,
                        "offset": hex(hm.start())
                    })

        # 5. Scan Slack Space for Base64 Cryptographic Fragments
        max_part_end = max((p["offset"] + p["size"] for p in partitions), default=0x110000)
        if len(data) > max_part_end:
            slack_data = data[max_part_end:]
            b64_slack = re.findall(rb"[A-Za-z0-9+/]{40}", slack_data)
            for bs in b64_slack:
                bs_str = bs.decode("ascii")
                if bs_str not in results["slack_space_artifacts"]:
                    results["slack_space_artifacts"].append(bs_str)

        # 6. Automated Cryptographic Decryption Solver for Multi-Part Keystreams
        p1_candidates = []
        for k, v in results["nvs_entries"].items():
            if "blob" in k.lower() or "p1" in k.lower() or len(v) == 40:
                p1_candidates.append(v)

        p2_candidates = results["slack_space_artifacts"]
        keys = [k["deobfuscated_key"].encode() for k in results["recovered_keys"]]

        for key in keys:
            for p1 in p1_candidates:
                for p2 in p2_candidates:
                    decrypted_text = self._try_continuous_sha256_counter_decrypt(p1, p2, key)
                    if decrypted_text:
                        candidate_flags = [
                            decrypted_text,
                            f"HackToday26{{{decrypted_text}}}",
                            f"flag{{{decrypted_text}}}"
                        ]
                        for cand in candidate_flags:
                            if self.string_hunter.is_valid_flag(cand):
                                fl_obj = {
                                    "flag": cand,
                                    "encoding": f"ESP32 Continuous Keystream (SHA-256 counter, key='{key.decode()}')",
                                    "context": f"p1='{p1[:15]}...' + p2='{p2[:15]}...'"
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
        """Extract strings and Base64 blobs from ESP32 NVS pages."""
        entries = {}
        kv_matches = re.finditer(rb"([a-zA-Z0-9_\-]{2,15})\x00+([A-Za-z0-9+/=]{16,64})", nvs_data)
        for km in kv_matches:
            key_name = km.group(1).decode("latin-1", errors="ignore")
            val_str = km.group(2).decode("latin-1", errors="ignore")
            if val_str not in ("bCLEARED", "CLEARED"):
                entries[key_name] = val_str

        b64_nvs = re.findall(rb"[A-Za-z0-9+/]{40}", nvs_data)
        for idx, bs in enumerate(b64_nvs):
            bs_str = bs.decode("ascii")
            if bs_str not in entries.values() and bs_str != "bCLEARED":
                entries[f"blob_{idx}"] = bs_str

        return entries

    def _try_continuous_sha256_counter_decrypt(self, p1: str, p2: str, key: bytes) -> Optional[str]:
        """Continuous keystream SHA-256 counter mode decryption (HackToday 'Durrr Intern')."""
        try:
            combined_b64 = p1 + p2
            pad_len = (4 - len(combined_b64) % 4) % 4
            ciphertext = base64.b64decode(combined_b64 + "=" * pad_len)

            keystream = bytearray()
            counter = 0
            while len(keystream) < len(ciphertext):
                block = hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
                keystream.extend(block)
                counter += 1

            plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream[:len(ciphertext)])])
            text = plaintext.decode("utf-8", errors="ignore").strip()
            if len(text) >= 10 and all(32 <= ord(c) <= 126 for c in text):
                return text
        except Exception:
            pass
        return None
