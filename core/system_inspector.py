"""
Automotion Forensics - System, Logs & Artifact Inspector
Covers techniques from ctf-forensics:
- Windows Event Logs (.evtx) parsing & Event ID triage
- PowerShell history & EncodedCommand decoder
- Linux input_event keylogger dump parser (24-byte / 16-byte structs)
- Git repository & loose object carver/decompressor
- Docker container layer inspection
- Corrupted ZIP header repair
"""

import base64
import json
import os
import re
import struct
import tarfile
import zlib
from typing import Any, Dict, List, Optional

import config
from core.string_hunter import StringHunter


class SystemInspector:
    """Analyzes system artifacts: event logs, keyloggers, git repositories, and containers."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def analyze_evtx_or_logs(self, filepath_or_data) -> Dict[str, Any]:
        """
        Inspect Windows Event Logs (.evtx) or text log files:
        - Key Event IDs: 1102 (Cleared), 4720 (User Created), 1149 (RDP Success), 4104 (PowerShell Script), 4688 (Process Created)
        - Uses python-evtx when available, with UTF-16LE fallback
        - Automatically decodes PowerShell -EncodedCommand (Base64 UTF-16LE)
        - Hunts for flags, credentials, and script blocks
        """
        results: Dict[str, Any] = {
            "key_events": [],
            "powershell_scripts": [],
            "decoded_commands": [],
            "rdp_sessions": [],
            "flags_found": []
        }

        raw_bytes = b""
        filepath = None
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            filepath = filepath_or_data
            try:
                with open(filepath, "rb") as f:
                    raw_bytes = f.read(50 * 1024 * 1024)
            except Exception:
                return results
        elif isinstance(filepath_or_data, bytes):
            raw_bytes = filepath_or_data
        else:
            return results

        # 1. Native python-evtx parser if available and file starts with ElfFile\x00
        is_evtx = raw_bytes.startswith(b"ElfFile\x00") or (filepath and filepath.lower().endswith(".evtx"))
        if is_evtx and filepath:
            try:
                import Evtx.Evtx as evtx_module
                with evtx_module.Evtx(filepath) as log:
                    _evtx_record_count = 0
                    for record in log.records():
                        _evtx_record_count += 1
                        if _evtx_record_count > 20000:
                            break
                        xml_str = record.xml()
                        # Event ID
                        m_eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml_str)
                        if m_eid:
                            eid = m_eid.group(1)
                            for target_eid, desc in [
                                ("1102", "Audit log cleared"),
                                ("4720", "User account created"),
                                ("4781", "Account renamed"),
                                ("1149", "RDP logon successful"),
                                ("4104", "PowerShell Script Block execution"),
                                ("4688", "New process created")
                            ]:
                                if eid == target_eid and not any(k["event_id"] == eid for k in results["key_events"]):
                                    results["key_events"].append({"event_id": eid, "description": desc})

                        # Extract HostApplication and CommandLine
                        for tag in ["HostApplication", "CommandLine", "ScriptBlockText", "Payload"]:
                            matches = re.findall(rf"<{tag}[^>]*>(.*?)</{tag}>", xml_str, re.DOTALL)
                            for content in matches:
                                clean_c = content.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").strip()
                                if clean_c and clean_c not in results["powershell_scripts"]:
                                    results["powershell_scripts"].append(clean_c)

                        # Extract HostApplication= attribute patterns
                        for ha in re.findall(r"HostApplication=([^\r\n\t]+)", xml_str):
                            clean_ha = ha.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").strip()
                            if clean_ha and clean_ha not in results["powershell_scripts"]:
                                results["powershell_scripts"].append(clean_ha)

                        # Check for -EncodedCommand in XML
                        for m_enc in re.finditer(r"(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{12,})", xml_str, re.IGNORECASE):
                            b64_val = m_enc.group(1)
                            try:
                                dec = base64.b64decode(b64_val).decode("utf-16le", errors="ignore").strip()
                                if dec and dec not in results["decoded_commands"]:
                                    results["decoded_commands"].append(dec)
                                    for fl in self.string_hunter.hunt_flags(dec):
                                        fl["encoding"] = f"EVTX EncodedCommand ({fl['encoding']})"
                                        results["flags_found"].append(fl)
                                    # Also capture flag fragments like (part X/Y)
                                    if "part" in dec.lower() or "{" in dec or "}" in dec:
                                        results["flags_found"].append({
                                            "flag": dec,
                                            "encoding": "EVTX PowerShell Script Fragment",
                                            "context": dec
                                        })
                            except Exception:
                                pass

                        # Hunt flags directly in record XML
                        for fl in self.string_hunter.hunt_flags(xml_str):
                            fl["encoding"] = f"EVTX Record ({fl['encoding']})"
                            results["flags_found"].append(fl)
            except Exception:
                pass

        # 2. Raw Stream Scanner (Latin-1 and UTF-16LE)
        texts_to_scan = [
            raw_bytes.decode("latin-1", errors="ignore"),
            raw_bytes.decode("utf-16le", errors="ignore")
        ]

        for text in texts_to_scan:
            event_indicators = [
                ("1102", "Audit log cleared (Anti-forensics indicator)"),
                ("4720", "User account created"),
                ("4781", "Account renamed"),
                ("1149", "RDP logon successful"),
                ("4104", "PowerShell Script Block execution"),
                ("4688", "New process created")
            ]
            for eid, desc in event_indicators:
                pattern = rf"(?:EventID>|EventID:?\s*){eid}\b"
                if re.search(pattern, text) and not any(k["event_id"] == eid for k in results["key_events"]):
                    results["key_events"].append({"event_id": eid, "description": desc})

            # Extract PowerShell commands
            ps_commands = re.findall(r"(?:powershell(?:\.exe)?|pwsh)\s+([^\r\n]{5,300})", text, re.IGNORECASE)
            for cmd in set(ps_commands):
                if cmd not in results["powershell_scripts"]:
                    results["powershell_scripts"].append(cmd)
                m_enc = re.search(r"(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{12,})", cmd, re.IGNORECASE)
                if m_enc:
                    b64_val = m_enc.group(1)
                    try:
                        dec = base64.b64decode(b64_val).decode("utf-16le", errors="ignore").strip()
                        if dec not in results["decoded_commands"]:
                            results["decoded_commands"].append(dec)
                            for fl in self.string_hunter.hunt_flags(dec):
                                fl["encoding"] = f"EVTX PowerShell EncodedCommand ({fl['encoding']})"
                                results["flags_found"].append(fl)
                            if "part" in dec.lower() or "{" in dec or "}" in dec:
                                results["flags_found"].append({
                                    "flag": dec,
                                    "encoding": "EVTX PowerShell Script Fragment",
                                    "context": dec
                                })
                    except Exception:
                        pass

            for fl in self.string_hunter.hunt_flags(text):
                fl["encoding"] = f"Log/EVTX ({fl['encoding']})"
                results["flags_found"].append(fl)

        return results

    inspect_evtx = analyze_evtx_or_logs

    def parse_linux_input_events(self, data: bytes) -> Dict[str, Any]:
        """
        Parse Linux struct input_event keylogger dump:
        struct input_event {
            struct timeval time; // 16 bytes on 64-bit (8 bytes on 32-bit)
            __u16 type;          // 2 bytes (EV_KEY = 1)
            __u16 code;          // 2 bytes (Linux keycode)
            __s32 value;         // 4 bytes (1 = press, 0 = release)
        };
        Total struct size: 24 bytes (64-bit) or 16 bytes (32-bit).
        """
        results: Dict[str, Any] = {
            "is_input_event": False,
            "reconstructed_text": "",
            "flags_found": []
        }

        # Linux input-event-codes.h keymap (partial for typing)
        LINUX_KEY_MAP = {
            1: '',  # KEY_ESC
            2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
            12: '-', 13: '=', 14: '\b', 15: '\t',
            16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p',
            26: '[', 27: ']', 28: '\n', 29: '',  # KEY_LEFTCTRL
            30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l',
            39: ';', 40: "'", 41: '`', 42: '',  # KEY_LEFTSHIFT
            43: '\\', 44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
            51: ',', 52: '.', 53: '/', 54: '',  # KEY_RIGHTSHIFT
            57: ' ',  # KEY_SPACE
        }

        LINUX_SHIFT_MAP = {
            '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
            '-': '_', '=': '+', '[': '{', ']': '}', ';': ':', "'": '"', '`': '~', '\\': '|',
            ',': '<', '.': '>', '/': '?',
        }

        # Try 24-byte (64-bit) then 16-byte (32-bit)
        for struct_size, fmt in ((24, "<QQHHI"), (16, "<IIHHI")):
            if len(data) >= struct_size and len(data) % struct_size == 0:
                typed = []
                shift_held = False
                valid_events = 0

                for i in range(0, len(data), struct_size):
                    chunk = data[i:i + struct_size]
                    if struct_size == 24:
                        sec, usec, ev_type, code, val = struct.unpack(fmt, chunk)
                    else:
                        sec, usec, ev_type, code, val = struct.unpack(fmt, chunk)

                    if ev_type == 1:  # EV_KEY
                        valid_events += 1
                        if code in (42, 54):  # Left / Right Shift
                            shift_held = (val == 1)
                        elif val == 1:  # Key press
                            char = LINUX_KEY_MAP.get(code, "")
                            if shift_held:
                                char = LINUX_SHIFT_MAP.get(char, char.upper())
                            if char == '\b':
                                if typed:
                                    typed.pop()
                            elif char:
                                typed.append(char)

                if valid_events > 5:
                    results["is_input_event"] = True
                    results["reconstructed_text"] = "".join(typed)
                    for fl in self.string_hunter.hunt_flags(results["reconstructed_text"]):
                        fl["encoding"] = f"Linux input_event ({fl['encoding']})"
                        results["flags_found"].append(fl)
                    break

        return results

    def inspect_git_directory(self, git_dir: str) -> Dict[str, Any]:
        """
        Inspect .git folder or loose objects:
        - Decompresses all zlib object files in .git/objects/??/*
        - Greps for flags across deleted/unreachable commits
        """
        results: Dict[str, Any] = {
            "objects_scanned": 0,
            "flags_found": []
        }

        if not os.path.exists(git_dir):
            return results

        objects_root = os.path.join(git_dir, "objects") if not git_dir.endswith("objects") else git_dir
        if not os.path.exists(objects_root):
            return results

        for root, _, files in os.walk(objects_root):
            for file in files:
                obj_path = os.path.join(root, file)
                if len(file) == 38 or len(file) >= 20:  # SHA1/SHA256 loose object
                    try:
                        with open(obj_path, "rb") as of:
                            compressed = of.read()
                        decompressed = zlib.decompress(compressed)
                        results["objects_scanned"] += 1
                        for fl in self.string_hunter.hunt_flags(decompressed):
                            fl["encoding"] = f"Git Object {file[:8]} ({fl['encoding']})"
                            results["flags_found"].append(fl)
                    except Exception:
                        pass

        return results

    def inspect_docker_tar(self, tar_path: str) -> Dict[str, Any]:
        """Inspect Docker image tar for config commands, build secrets, and layer flags."""
        results: Dict[str, Any] = {
            "is_docker": False,
            "run_commands": [],
            "flags_found": []
        }

        if not os.path.exists(tar_path) or not tarfile.is_tarfile(tar_path):
            return results

        try:
            with tarfile.open(tar_path, "r") as tf:
                names = tf.getnames()
                if "manifest.json" in names:
                    results["is_docker"] = True
                    manifest_f = tf.extractfile("manifest.json")
                    if manifest_f:
                        manifest_data = json.load(manifest_f)
                        # Extract Config JSON
                        for item in manifest_data:
                            cfg_name = item.get("Config")
                            if cfg_name and cfg_name in names:
                                cfg_f = tf.extractfile(cfg_name)
                                if cfg_f:
                                    cfg_json = json.load(cfg_f)
                                    history = cfg_json.get("history", [])
                                    for h in history:
                                        created_by = h.get("created_by", "")
                                        if created_by:
                                            results["run_commands"].append(created_by)
                                            for fl in self.string_hunter.hunt_flags(created_by):
                                                fl["encoding"] = f"Docker RUN ({fl['encoding']})"
                                                results["flags_found"].append(fl)
        except Exception:
            pass

        return results

    def parse_mft_records(self, mft_data: bytes, max_records: int = 10000) -> Dict[str, Any]:
        """
        NTFS Master File Table ($MFT) Record Parser & Resident Data Carver:
        - Evaluates 1024-byte MFT records starting with 'FILE'
        - Identifies deleted records (flags == 0x00) and allocated records (flags == 0x01)
        - Carves resident $DATA attributes (files < ~700 bytes stored inline in MFT)
        - Extracts filenames ($FILE_NAME 0x30) and searches resident content for flags
        """
        results: Dict[str, Any] = {
            "total_records": 0,
            "allocated_records": 0,
            "deleted_records": 0,
            "resident_files": [],
            "flags_found": []
        }

        rec_size = 1024
        total_len = len(mft_data)
        record_count = 0

        for off in range(0, total_len - rec_size + 1, rec_size):
            if record_count >= max_records:
                break
            record = mft_data[off:off + rec_size]
            if not record.startswith(b"FILE"):
                continue

            record_count += 1
            results["total_records"] += 1

            flags = struct.unpack_from("<H", record, 0x16)[0]
            is_allocated = bool(flags & 0x01)
            if is_allocated:
                results["allocated_records"] += 1
            else:
                results["deleted_records"] += 1

            first_attr_off = struct.unpack_from("<H", record, 0x14)[0]
            if first_attr_off < 0x20 or first_attr_off >= rec_size:
                continue

            attr_pos = first_attr_off
            filename = ""
            resident_data = None

            while attr_pos + 8 <= rec_size:
                attr_type = struct.unpack_from("<I", record, attr_pos)[0]
                if attr_type == 0xFFFFFFFF or attr_type == 0:
                    break

                attr_len = struct.unpack_from("<I", record, attr_pos + 4)[0]
                if attr_len <= 0 or attr_pos + attr_len > rec_size:
                    break

                non_resident = record[attr_pos + 8]

                # $FILE_NAME (0x30)
                if attr_type == 0x30 and non_resident == 0:
                    try:
                        content_off = struct.unpack_from("<H", record, attr_pos + 0x14)[0]
                        fn_payload = record[attr_pos + content_off:]
                        if len(fn_payload) >= 0x42:
                            fn_len = fn_payload[0x40]
                            fn_bytes = fn_payload[0x42:0x42 + fn_len * 2]
                            filename = fn_bytes.decode("utf-16le", errors="ignore")
                    except Exception:
                        pass

                # $DATA (0x80)
                elif attr_type == 0x80 and non_resident == 0:
                    try:
                        data_len = struct.unpack_from("<I", record, attr_pos + 0x10)[0]
                        data_off = struct.unpack_from("<H", record, attr_pos + 0x14)[0]
                        if data_len > 0 and attr_pos + data_off + data_len <= rec_size:
                            resident_data = record[attr_pos + data_off:attr_pos + data_off + data_len]
                    except Exception:
                        pass

                attr_pos += attr_len

            if resident_data:
                file_info = {
                    "filename": filename or f"unnamed_record_{record_count}",
                    "is_deleted": not is_allocated,
                    "size": len(resident_data),
                    "offset": off
                }
                results["resident_files"].append(file_info)

                flags_found = self.string_hunter.hunt_flags(resident_data)
                for fl in flags_found:
                    status = "DELETED" if not is_allocated else "ALLOCATED"
                    fl["context"] = f"[$MFT {status} Record '{file_info['filename']}'] {fl['context']}"
                    fl["encoding"] = f"MFT Resident Data ({fl['encoding']})"
                    results["flags_found"].append(fl)

        return results

    def inspect_kape_triage(self, triage_dir: str) -> Dict[str, Any]:
        """Windows KAPE Triage Analysis."""
        return self._inspect_kape_triage_impl(triage_dir)

    inspect_kape_triage_folder = inspect_kape_triage

    def _inspect_kape_triage_impl(self, triage_dir: str) -> Dict[str, Any]:
        """
        Windows KAPE Triage Analysis:
        - PowerShell history (ConsoleHost_history.txt)
        - $MFT resident files and deleted data
        - Execution timeline (Amcache.hve)
        - User hives (NTUSER.DAT) and system hives (SAM, SYSTEM)
        """
        results: Dict[str, Any] = {
            "is_kape_triage": False,
            "powershell_history": [],
            "mft_summary": None,
            "registry_hives_found": [],
            "flags_found": []
        }

        if not os.path.exists(triage_dir):
            return results

        for root, _, files in os.walk(triage_dir):
            for file in files:
                f_path = os.path.join(root, file)
                f_lower = file.lower()

                # 1. PowerShell ConsoleHost_history.txt
                if f_lower == "consolehost_history.txt":
                    results["is_kape_triage"] = True
                    try:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = [ln.strip() for ln in f if ln.strip()]
                        results["powershell_history"].extend(lines[:100])
                        for ln in lines:
                            for fl in self.string_hunter.hunt_flags(ln):
                                fl["context"] = f"[PSReadLine History] {fl['context']}"
                                fl["encoding"] = f"PowerShell History ({fl['encoding']})"
                                results["flags_found"].append(fl)
                    except Exception:
                        pass

                # 2. $MFT (Master File Table)
                elif f_lower == "$mft" or file == "$MFT":
                    results["is_kape_triage"] = True
                    try:
                        with open(f_path, "rb") as f:
                            mft_chunk = f.read(50 * 1024 * 1024)
                        mft_res = self.parse_mft_records(mft_chunk)
                        results["mft_summary"] = {
                            "total_records": mft_res["total_records"],
                            "deleted_records": mft_res["deleted_records"],
                            "resident_files_count": len(mft_res["resident_files"])
                        }
                        for fl in mft_res["flags_found"]:
                            results["flags_found"].append(fl)
                    except Exception:
                        pass

                # 3. Registry Hives (SAM, SYSTEM, NTUSER.DAT, Amcache.hve)
                elif f_lower in ("sam", "system", "software", "ntuser.dat", "amcache.hve"):
                    results["is_kape_triage"] = True
                    results["registry_hives_found"].append(file)
                    try:
                        with open(f_path, "rb") as f:
                            hive_bytes = f.read(20 * 1024 * 1024)
                        for fl in self.string_hunter.hunt_flags(hive_bytes):
                            fl["context"] = f"[Registry {file}] {fl['context']}"
                            fl["encoding"] = f"Registry Hive ({fl['encoding']})"
                            results["flags_found"].append(fl)

                        # Check RunMRU commands: cmd /c echo ... & rem (part X/Y) or similar execution history
                        runmru_matches = re.finditer(
                            rb"(?:(?:cmd(?:\.exe)?\s+/c\s+echo|echo|set\s+[a-zA-Z0-9_]+\s*=)\s*([^\s\r\n\x00>&]+)[^\r\n\x00]*(?:rem|::|#|//|\b)(?:\(?part|frag|chunk|p)[_\s]*(\d+)(?:\s*(?:/|of)\s*(\d+))?\)?)",
                            hive_bytes,
                            re.IGNORECASE
                        )
                        for rm in runmru_matches:
                            val = rm.group(1).decode("latin-1", errors="ignore").strip()
                            p_idx = int(rm.group(2)) if rm.group(2) else 1
                            p_tot = int(rm.group(3)) if rm.group(3) else 0
                            tot_str = f"/{p_tot}" if p_tot else ""
                            results["flags_found"].append({
                                "flag": val,
                                "encoding": f"Registry RunMRU (part {p_idx}{tot_str})",
                                "context": f"Part {p_idx} from Registry {file}: {val}"
                            })
                    except Exception:
                        pass

                # 4. NTFS USN Journal ($J / $Extend\$J)
                elif f_lower in ("$j", "$usnjrnl", "$usnjrnl:$j") or "usn" in f_lower or file == "$J":
                    results["is_kape_triage"] = True
                    try:
                        with open(f_path, "rb") as f:
                            usn_bytes = f.read(50 * 1024 * 1024)
                        # Dynamic pattern for transient files with Base64 / Hex names and optional part markers
                        usn_matches = re.finditer(
                            rb"(?:(?:PART|part|frag|chunk|p)[_\s]*(\d+)(?:(?:OF|of|_|/)(\d+))?_+)?([A-Za-z0-9+/]{12,}={0,2})\.(?:[a-zA-Z0-9]{1,5})",
                            usn_bytes,
                            re.IGNORECASE
                        )
                        for um in usn_matches:
                            p_idx = int(um.group(1)) if um.group(1) else 1
                            p_tot = int(um.group(2)) if um.group(2) else 0
                            b64_name = um.group(3).decode("latin-1", errors="ignore")
                            tot_str = f"/{p_tot}" if p_tot else ""
                            # Try Base64 decode
                            try:
                                pad = (4 - len(b64_name) % 4) % 4
                                dec_name = base64.b64decode((b64_name + "=" * pad).encode("ascii")).decode("latin-1", errors="ignore")
                                if any(c.isalnum() for c in dec_name):
                                    results["flags_found"].append({
                                        "flag": dec_name,
                                        "encoding": f"USN Journal $J Base64 (part {p_idx}{tot_str})",
                                        "context": f"Decoded filename: {b64_name} -> {dec_name}"
                                    })
                            except Exception:
                                pass
                            # Try Hex decode
                            try:
                                dec_hex = bytes.fromhex(b64_name).decode("latin-1", errors="ignore")
                                if any(c.isalnum() for c in dec_hex):
                                    results["flags_found"].append({
                                        "flag": dec_hex,
                                        "encoding": f"USN Journal $J Hex (part {p_idx}{tot_str})",
                                        "context": f"Hex filename: {b64_name} -> {dec_hex}"
                                    })
                            except Exception:
                                pass
                    except Exception:
                        pass

                # 5. Scheduled Tasks XML (Windows\System32\Tasks)
                elif "tasks" in root.lower() or f_lower.endswith(".xml") or "task" in f_lower:
                    try:
                        with open(f_path, "rb") as f:
                            task_bytes = f.read(2 * 1024 * 1024)
                        # Extract -EncodedCommand (-enc, -ec, -encodedcommand)
                        enc_matches = re.finditer(rb"(?:-enc|-ec|-encodedcommand)\s+([A-Za-z0-9+/=]{16,})", task_bytes, re.IGNORECASE)
                        for em in enc_matches:
                            b64_val = em.group(1).decode("ascii", errors="ignore")
                            try:
                                pad = (4 - len(b64_val) % 4) % 4
                                dec_cmd = base64.b64decode((b64_val + "=" * pad).encode("ascii")).decode("utf-16le", errors="ignore")
                                for fl in self.string_hunter.hunt_flags(dec_cmd):
                                    fl["encoding"] = f"Scheduled Task XML ({fl['encoding']})"
                                    fl["context"] = f"Task {file}: {fl['context']}"
                                    results["flags_found"].append(fl)

                                # Extract (part X/Y) or part X from comments or commands
                                m_part = re.search(r"(?:part|frag|chunk|p)[_\s]*(\d+)(?:\s*(?:/|of)\s*(\d+))?[_\s\)\:]*([A-Za-z0-9_\-\{\}\!@#\$%\^&\*\+=~`]+)", dec_cmd, re.IGNORECASE)
                                if m_part:
                                    p_idx = int(m_part.group(1))
                                    p_tot = int(m_part.group(2)) if m_part.group(2) else 0
                                    p_val = m_part.group(3).strip()
                                    tot_str = f"/{p_tot}" if p_tot else ""
                                    results["flags_found"].append({
                                        "flag": p_val,
                                        "encoding": f"Scheduled Task Script (part {p_idx}{tot_str})",
                                        "context": f"Part {p_idx} from Task {file}: {p_val}"
                                    })
                            except Exception:
                                pass
                    except Exception:
                        pass

        # 6. Generalized Multi-Part Flag Synthesis (N-Part Assembly)
        parts_collected: Dict[int, str] = {}
        for fl in results["flags_found"]:
            text_context = fl.get("encoding", "") + " " + fl.get("context", "")
            m_p = re.search(r"(?:part|p|frag|chunk)[_\s]*(\d+)(?:\s*(?:/|of)\s*(\d+))?", text_context, re.IGNORECASE)
            if m_p:
                idx = int(m_p.group(1))
                val = fl.get("flag", "").strip()
                if val and idx not in parts_collected:
                    parts_collected[idx] = val

        if len(parts_collected) >= 2:
            max_idx = max(parts_collected.keys())
            if all(i in parts_collected for i in range(1, max_idx + 1)):
                raw_combined = "".join(parts_collected[i] for i in range(1, max_idx + 1))
                candidates = [
                    raw_combined,
                    f"HackToday26{{{raw_combined}}}",
                    f"flag{{{raw_combined}}}",
                    f"HackToday{{{raw_combined}}}",
                    f"CTF{{{raw_combined}}}"
                ]
                for cand in candidates:
                    if self.string_hunter.is_valid_flag(cand):
                        results["flags_found"].insert(0, {
                            "flag": cand,
                            "encoding": f"Synthesized {max_idx}-Part Flag (KAPE Artifacts)",
                            "context": f"Combined {max_idx} parts: " + " + ".join(f"p{i}='{parts_collected[i]}'" for i in range(1, max_idx + 1))
                        })
                        break

        return results

