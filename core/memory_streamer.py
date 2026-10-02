"""
Automotion Forensics - Memory Dump Streaming Engine
High-performance zero-OOM sliding-window analyzer for Linux LiME (.lime)
and Windows (.dmp, .raw, .vmem) memory dumps.
Never freezes, never exhausts RAM, extracts bash history, env vars, and flags.
"""

import os
import re
import shutil
import struct
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple

import config
from core.string_hunter import StringHunter


class MemoryStreamer:
    """Streams and analyzes multi-gigabyte memory dumps with constant memory footprint."""

    def __init__(self, chunk_size: int = config.CHUNK_SIZE, overlap: int = config.CHUNK_OVERLAP):
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.string_hunter = StringHunter()
        self.has_vol = shutil.which("vol") is not None or shutil.which("volatility") is not None

    def identify_memory_type(self, header_bytes: bytes) -> Dict[str, Any]:
        """Detect LiME or Windows crash dump magic."""
        if header_bytes.startswith(b"EMiL") or header_bytes.startswith(b"LiME"):
            return {"type": "Linux LiME Memory Dump", "os": "linux", "magic": "LiME"}
        elif header_bytes.startswith(b"PAGE") or header_bytes.startswith(b"MDMP"):
            return {"type": "Windows Minidump / Crash Dump", "os": "windows", "magic": "Windows Dump"}
        return {"type": "Raw Memory Image / Dump", "os": "unknown", "magic": "Raw"}

    def scan_memory_dump(
        self,
        filepath: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        max_bytes: Optional[int] = None,
        on_flag_found: Optional[Callable[[Dict[str, str]], None]] = None,
        early_stop: bool = False
    ) -> Dict[str, Any]:
        """
        Stream through memory dump in 32MB sliding windows with 64KB overlap.
        Extracts:
        - Flags across plaintext, base64, hex with instant early-stop callback
        - Linux Kernel Banner (exact kernel version for Volatility 3 symbol table)
        - Bash history & terminal commands
        - Environment variables
        - SSH private keys and executed scripts
        - Volatility 3 recipe commands
        """
        results: Dict[str, Any] = {
            "source": filepath,
            "file_size_bytes": 0,
            "memory_type": "Unknown",
            "flags_found": [],
            "bash_commands": [],
            "env_vars": [],
            "extracted_passwords": [],
            "reverse_shells": [],
            "http_requests": [],
            "carved_elfs": [],
            "ntlm_hashes": [],
            "suspicious_patterns": {},
            "volatility_recommendations": []
        }

        if not os.path.exists(filepath):
            results["error"] = "File not found"
            return results

        file_size = os.path.getsize(filepath)
        results["file_size_bytes"] = file_size
        limit_size = min(file_size, max_bytes) if max_bytes else file_size
        results["kernel_banner"] = None
        results["ssh_keys"] = []
        results["scripts_found"] = []

        seen_commands = set()
        seen_env = set()
        seen_passwords = set()
        seen_rev_shells = set()
        seen_elf_offsets = set()
        split_fragments: Dict[str, Dict[int, str]] = {}

        try:
            with open(filepath, "rb") as f:
                header = f.read(1024)
                type_info = self.identify_memory_type(header)
                results["memory_type"] = type_info["type"]
                os_target = type_info["os"]

                # Generate comprehensive Volatility 3 recommendation commands
                if os_target == "linux":
                    results["volatility_recommendations"] = [
                        f"vol -f \"{filepath}\" linux.bash",
                        f"vol -f \"{filepath}\" linux.pslist",
                        f"vol -f \"{filepath}\" linux.pstree",
                        f"vol -f \"{filepath}\" linux.cmdline",
                        f"vol -f \"{filepath}\" linux.envars",
                        f"vol -f \"{filepath}\" linux.elfs",
                        f"vol -f \"{filepath}\" linux.filescan 2>/dev/null | grep -i flag",
                        f"vol -f \"{filepath}\" linux.enumerate_files",
                        f"vol -f \"{filepath}\" linux.malfind",
                        f"vol -f \"{filepath}\" linux.check_modules",
                        f"vol -f \"{filepath}\" linux.sockstat",
                        f"vol -f \"{filepath}\" linux.netstat",
                        f"strings \"{filepath}\" | grep -aEi 'HackToday26{{|HackToday{{|flag{{|picoCTF{{' | head -50",
                    ]
                else:
                    results["volatility_recommendations"] = [
                        f"vol -f \"{filepath}\" windows.pslist",
                        f"vol -f \"{filepath}\" windows.cmdline",
                        f"vol -f \"{filepath}\" windows.envars",
                        f"vol -f \"{filepath}\" windows.netscan",
                        f"vol -f \"{filepath}\" windows.filescan | findstr /i flag",
                        f"vol -f \"{filepath}\" windows.mftscan | findstr /i flag",
                        f"vol -f \"{filepath}\" windows.dumpfiles --physaddr <offset>",
                        f"vol -f \"{filepath}\" windows.hashdump",
                        f"vol -f \"{filepath}\" windows.malfind",
                        f"strings \"{filepath}\" | findstr /i \"HackToday26{{ flag{{ picoCTF{{\"",
                    ]

                f.seek(0)
                bytes_read = 0
                prev_overlap = b""

                # 32MB chunks for maximum streaming performance on NVMe/SSD
                effective_chunk_size = max(self.chunk_size, 32 * 1024 * 1024)
                last_progress_print = 0

                while bytes_read < limit_size:
                    chunk = f.read(effective_chunk_size)
                    if not chunk:
                        break

                    current_buffer = prev_overlap + chunk
                    chunk_offset = bytes_read
                    bytes_read += len(chunk)

                    # Update progress
                    if progress_callback:
                        progress_callback(bytes_read, limit_size)
                    elif bytes_read - last_progress_print >= 256 * 1024 * 1024 or bytes_read >= limit_size:
                        last_progress_print = bytes_read
                        mb_read = bytes_read // (1024 * 1024)
                        mb_total = limit_size // (1024 * 1024)
                        pct = (bytes_read * 100) // max(1, limit_size)
                        print(f"    [*] [Memory Streamer] Processed {mb_read:,} MB / {mb_total:,} MB ({pct}%)...")

                    # 1. Hunt flags in this memory chunk
                    def _chunk_flag_cb(fl):
                        fl["context"] = f"[RAM Offset 0x{chunk_offset:x}] {fl.get('context', '')}"
                        if on_flag_found:
                            on_flag_found(fl)

                    flags = self.string_hunter.hunt_flags(
                        current_buffer,
                        early_stop=early_stop,
                        on_flag_found=_chunk_flag_cb if on_flag_found else None
                    )
                    for fl in flags:
                        fl["context"] = f"[RAM Offset 0x{chunk_offset:x}] {fl.get('context', '')}"
                        results["flags_found"].append(fl)

                    if early_stop and results["flags_found"]:
                        break

                    # 2. Extract Linux Kernel Banner if not yet found
                    if not results["kernel_banner"]:
                        m_kb = re.search(rb"Linux version ([0-9]+\.[0-9]+\.[0-9]+[^\x00\r\n]{5,150})", current_buffer)
                        if m_kb:
                            banner_str = m_kb.group(0).decode("latin-1", errors="ignore").strip()
                            results["kernel_banner"] = banner_str
                            print(f"    [+] Detected Kernel: \033[1;36m{banner_str}\033[0m")

                    # 3. Scrape Bash History / Terminal Commands
                    cmd_matches = re.findall(
                        rb"(?:^|[\x00\n])((?:sudo\s+|bash\s+|sh\s+|python[23]?\s+|curl\s+|wget\s+|ssh\s+|export\s+|cat\s+|nc\s+|ncat\s+|chmod\s+|chown\s+|nano\s+|vim\s+|grep\s+|tar\s+|7z\s+|unzip\s+|systemctl\s+|service\s+)[^\x00\r\n]{3,150})",
                        current_buffer
                    )
                    for cm in cmd_matches:
                        clean_cm = cm.decode("latin-1", errors="ignore").strip()
                        if clean_cm and clean_cm not in seen_commands:
                            seen_commands.add(clean_cm)
                            results["bash_commands"].append(clean_cm)

                    # 4. Scrape Environment Variables
                    env_matches = re.findall(
                        rb"(?:^|[\x00\n])([A-Z0-9_]{3,40}=[^\x00\r\n]{3,120})",
                        current_buffer
                    )
                    for em in env_matches:
                        clean_em = em.decode("latin-1", errors="ignore").strip()
                        if any(k in clean_em.upper() for k in ("FLAG", "PASS", "SECRET", "TOKEN", "KEY", "USER", "HOST", "ROOT", "AUTH")):
                            if clean_em not in seen_env:
                                seen_env.add(clean_em)
                                results["env_vars"].append(clean_em)

                    # 5. Scrape SSH & Private Keys in memory
                    key_matches = re.findall(
                        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[^-]+-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                        current_buffer
                    )
                    for km in key_matches:
                        key_str = km.decode("latin-1", errors="ignore").strip()
                        if key_str not in results["ssh_keys"]:
                            results["ssh_keys"].append(key_str)

                    # 6. Scrape in-memory scripts
                    script_matches = re.findall(
                        rb"(?:^|[\x00\n])(#!(?:/usr/bin/env python[23]?|/bin/bash|/bin/sh)[^\x00]{20,500})",
                        current_buffer
                    )
                    for sm in script_matches:
                        s_clean = sm.decode("latin-1", errors="ignore").strip()
                        if s_clean not in results["scripts_found"]:
                            results["scripts_found"].append(s_clean[:300])

                    # 7. Scrape Python/shell variable assignments that might hold the flag
                    flag_assign_matches = re.findall(
                        rb"(?:flag|secret|answer|key|token|password)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-\.\{\}]{6,120})['\"]?",
                        current_buffer,
                        re.IGNORECASE
                    )
                    for fa in flag_assign_matches:
                        fa_str = fa.decode("latin-1", errors="ignore").strip()
                        if fa_str and fa_str not in seen_commands:
                            seen_commands.add(fa_str)
                            results["bash_commands"].append(f"[VAR] {fa_str}")

                    # 8. Flag file references in memory (/tmp/flag, /root/flag.txt, etc.)
                    flag_file_matches = re.findall(
                        rb"(?:/tmp/flag|/root/flag|/home/\w+/flag|flag\.txt|secret\.txt|key\.txt)[^\x00\r\n]{0,60}",
                        current_buffer,
                        re.IGNORECASE
                    )
                    for ffm in flag_file_matches:
                        ff_str = ffm.decode("latin-1", errors="ignore").strip()
                        if ff_str and ff_str not in results["scripts_found"]:
                            results["scripts_found"].append(ff_str)

                    # 9. Scrape Command-Line Passwords (OpenSSL, 7z, GPG, unzip, sshpass, curl -u, etc.)
                    pwd_patterns = [
                        rb"(?:openssl\s+enc\s+[^\r\n]*?(?:-k|-pass\s+pass:)\s*['\"]?([^\s\"'\r\n]{3,60})['\"]?)",
                        rb"(?:(?:7z|7za|zip|unzip)\s+[^\r\n]*?-(?:p|P)\s*['\"]?([^\s\"'\r\n]{3,60})['\"]?)",
                        rb"(?:gpg\s+[^\r\n]*?--passphrase\s+['\"]?([^\s\"'\r\n]{3,60})['\"]?)",
                        rb"(?:sshpass\s+-p\s*['\"]?([^\s\"'\r\n]{3,60})['\"]?)",
                        rb"(?:curl\s+[^\r\n]*?-u\s+[^:\s\r\n]+:([^\s\"'\r\n]{3,60}))",
                        rb"(?:echo\s+['\"]?([^\s\"'\r\n]{4,60})['\"]?\s*\|\s*sudo\s+-S)"
                    ]
                    for pp in pwd_patterns:
                        for m_pwd in re.finditer(pp, current_buffer, re.IGNORECASE):
                            pwd_str = m_pwd.group(1).decode("latin-1", errors="ignore").strip()
                            if pwd_str and pwd_str not in seen_passwords and len(pwd_str) >= 3:
                                seen_passwords.add(pwd_str)
                                results["extracted_passwords"].append(pwd_str)

                    # 10. Scrape Reverse Shells & Socket C2 strings
                    rev_matches = re.findall(
                        rb"(?:(?:bash\s+-i\s+>&|/bin/sh\s+-i\s+>&|/bin/bash\s+-i\s+>&)?\s*(?:/dev/tcp/[0-9\.]+|/dev/udp/[0-9\.]+)/[0-9]{2,5}|(?:nc|ncat|socat)\s+(?:-[le]|exec:)[^\r\n]{5,100})",
                        current_buffer,
                        re.IGNORECASE
                    )
                    for rm in rev_matches:
                        rm_str = rm.decode("latin-1", errors="ignore").strip()
                        if rm_str and rm_str not in seen_rev_shells:
                            seen_rev_shells.add(rm_str)
                            results["reverse_shells"].append(rm_str)

                    # 11. Scrape HTTP Requests, JWT Tokens & Cookies in RAM
                    jwt_matches = re.findall(rb"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}", current_buffer)
                    for jm in jwt_matches:
                        jwt_str = jm.decode("latin-1", errors="ignore").strip()
                        if jwt_str not in results["http_requests"]:
                            results["http_requests"].append(f"[JWT] {jwt_str}")
                            # Hunt flags in decoded JWT payload (second segment)
                            try:
                                payload_b64 = jwt_str.split(".")[1]
                                pad_len = (4 - len(payload_b64) % 4) % 4
                                dec_jwt = base64.b64decode((payload_b64 + "=" * pad_len).encode("ascii")).decode("latin-1", errors="ignore")
                                for fl in self.string_hunter.hunt_flags(dec_jwt):
                                    fl["encoding"] = f"In-Memory JWT Payload ({fl['encoding']})"
                                    results["flags_found"].append(fl)
                                    if on_flag_found:
                                        on_flag_found(fl)
                            except Exception:
                                pass

                    http_matches = re.findall(rb"(?:GET|POST|PUT|DELETE)\s+/[^\s\r\n]{1,120}\s+HTTP/1\.[01]", current_buffer)
                    for hm in http_matches:
                        hm_str = hm.decode("latin-1", errors="ignore").strip()
                        if hm_str not in results["http_requests"]:
                            results["http_requests"].append(hm_str)

                    # 12. Multi-Part Split Flag Assembler (e.g. part 1/3, part 2/3, part 3/3, or part_1 = '...')
                    # Pattern A: Fraction format (part 1/3, part 1 of 3)
                    pat_frac = rb"(?:#|\(|\[)?part\s*(\d+)\s*(?:/|of)\s*(\d+)(?:#|\)|\])?\s*[:=]?\s*['\"]?([A-Za-z0-9_\-\{\}\!@#\$%\^&\*\+=~`]+)"
                    for pm in re.finditer(pat_frac, current_buffer, re.IGNORECASE):
                        try:
                            p_idx = int(pm.group(1))
                            total_parts = int(pm.group(2))
                            p_text = pm.group(3).decode("latin-1", errors="ignore").strip().rstrip("'\"")
                            grp_key = f"fraction_{total_parts}"
                            if grp_key not in split_fragments:
                                split_fragments[grp_key] = {}
                            split_fragments[grp_key][p_idx] = p_text

                            if len(split_fragments[grp_key]) == total_parts:
                                assembled = "".join(split_fragments[grp_key][i] for i in range(1, total_parts + 1))
                                if self.string_hunter.is_valid_flag(assembled):
                                    assembled_fl = {
                                        "flag": assembled,
                                        "encoding": f"Assembled Multi-Part ({total_parts} fragments)",
                                        "context": f"Stitched {total_parts} memory parts: {split_fragments[grp_key]}"
                                    }
                                    if not any(f["flag"] == assembled for f in results["flags_found"]):
                                        results["flags_found"].append(assembled_fl)
                                        if on_flag_found:
                                            on_flag_found(assembled_fl)
                        except Exception:
                            pass

                    # Pattern B: Variable assignment (part_1 = '...', $part1 = '...')
                    pat_var = rb"(?:\$|var\s+|let\s+)?part_?(\d+)\s*=\s*['\"]([A-Za-z0-9_\-\{\}\!@#\$%\^&\*\+=~`]+)['\"]"
                    for pm in re.finditer(pat_var, current_buffer, re.IGNORECASE):
                        try:
                            p_idx = int(pm.group(1))
                            p_text = pm.group(2).decode("latin-1", errors="ignore").strip()
                            grp_key = "var_parts"
                            if grp_key not in split_fragments:
                                split_fragments[grp_key] = {}
                            split_fragments[grp_key][p_idx] = p_text

                            # Try assembling up to maximum known part index
                            max_idx = max(split_fragments[grp_key].keys())
                            if all(i in split_fragments[grp_key] for i in range(1, max_idx + 1)):
                                assembled = "".join(split_fragments[grp_key][i] for i in range(1, max_idx + 1))
                                if self.string_hunter.is_valid_flag(assembled):
                                    assembled_fl = {
                                        "flag": assembled,
                                        "encoding": f"Assembled Multi-Part ({max_idx} variables)",
                                        "context": f"Stitched variables: {split_fragments[grp_key]}"
                                    }
                                    if not any(f["flag"] == assembled for f in results["flags_found"]):
                                        results["flags_found"].append(assembled_fl)
                                        if on_flag_found:
                                            on_flag_found(assembled_fl)
                        except Exception:
                            pass

                    # 13. Vim Swap File buffer recovery (b0VIM magic)
                    vim_pos = 0
                    while True:
                        v_idx = current_buffer.find(b"b0VIM", vim_pos)
                        if v_idx == -1:
                            break
                        vim_pos = v_idx + 5
                        # Vim swap block is typically 4096 bytes
                        swp_block = current_buffer[v_idx : min(len(current_buffer), v_idx + 4096)]
                        for fl in self.string_hunter.hunt_flags(swp_block):
                            fl["context"] = f"[Vim Swap Buffer @ 0x{chunk_offset + v_idx:x}] {fl.get('context', '')}"
                            results["flags_found"].append(fl)
                            if on_flag_found:
                                on_flag_found(fl)

                    # 14. In-Memory ELF Carving (LKM .ko, injected binaries, core dumps)
                    if len(results["carved_elfs"]) < 10:
                        elf_pos = 0
                        while True:
                            e_idx = current_buffer.find(b"\x7fELF", elf_pos)
                            if e_idx == -1:
                                break
                            elf_pos = e_idx + 4
                            if e_idx + 64 > len(current_buffer):
                                break
                            ei_class = current_buffer[e_idx + 4]
                            ei_data = current_buffer[e_idx + 5]
                            if ei_class not in (1, 2) or ei_data != 1:  # 32/64-bit little endian
                                continue
                            e_type = struct.unpack("<H", current_buffer[e_idx + 16 : e_idx + 18])[0]
                            if e_type not in (1, 2, 3, 4):  # REL(1)=LKM, EXEC(2), DYN(3), CORE(4)
                                continue

                            abs_elf_off = chunk_offset + e_idx
                            if abs_elf_off not in seen_elf_offsets:
                                seen_elf_offsets.add(abs_elf_off)
                                type_names = {1: "LKM/Relocatable", 2: "Executable", 3: "SharedLib", 4: "CoreDump"}
                                t_name = type_names.get(e_type, "ELF")
                                elf_sample = current_buffer[e_idx : min(len(current_buffer), e_idx + 1024 * 1024)]
                                results["carved_elfs"].append({
                                    "offset": hex(abs_elf_off),
                                    "type": t_name,
                                    "class": "64-bit" if ei_class == 2 else "32-bit"
                                })
                                for fl in self.string_hunter.hunt_flags(elf_sample):
                                    fl["context"] = f"[Carved {t_name} @ 0x{abs_elf_off:x}] {fl.get('context', '')}"
                                    results["flags_found"].append(fl)
                                    if on_flag_found:
                                        on_flag_found(fl)
                            if len(results["carved_elfs"]) >= 10:
                                break

                    # 15. Windows NTLM Hash Scanner in RAM
                    ntlm_matches = re.finditer(
                        rb"(?:Administrator|Admin|Guest|User|ctfplayer|[A-Za-z0-9_\-\.]{3,20}):\d{3,5}:[0-9a-fA-F]{32}:([0-9a-fA-F]{32})",
                        current_buffer
                    )
                    for nm in ntlm_matches:
                        ntlm_line = nm.group(0).decode("latin-1", errors="ignore").strip()
                        if ntlm_line not in results["ntlm_hashes"]:
                            results["ntlm_hashes"].append(ntlm_line)

                    # 16. Web Server & CMS Incident Response Profiler (WordPress / Apache / Nginx)
                    log_matches = re.finditer(
                        rb"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+-\s+-\s+\[([^\]]+)\]\s+\"([A-Z]+)\s+([^\s\"]+)\s+HTTP/[0-9\.]+\"\s+(\d{3})\s+(\d+)",
                        current_buffer
                    )
                    for lm in log_matches:
                        ip_str = lm.group(1).decode("ascii")
                        method = lm.group(3).decode("ascii")
                        url_path = lm.group(4).decode("latin-1")

                        if "web_ir_killchain" not in results:
                            results["web_ir_killchain"] = {
                                "target_hosts": set(),
                                "attacker_ips": {},
                                "failed_logins": 0,
                                "exploited_endpoints": set(),
                                "cve_mentions": set(),
                                "webshells": set(),
                                "rce_parameters": set(),
                                "executed_commands": []
                            }

                        if "wp-login.php" in url_path or "login" in url_path.lower():
                            if method == "POST":
                                results["web_ir_killchain"]["failed_logins"] += 1
                                results["web_ir_killchain"]["attacker_ips"][ip_str] = results["web_ir_killchain"]["attacker_ips"].get(ip_str, 0) + 1

                        if "admin-ajax.php" in url_path or "xmlrpc.php" in url_path:
                            results["web_ir_killchain"]["exploited_endpoints"].add(url_path)

                        if "plugins" in url_path or "uploads" in url_path:
                            if ".php" in url_path:
                                results["web_ir_killchain"]["webshells"].add(url_path)

                    host_matches = re.finditer(rb"(?:^|[\r\n\x00\s])Host:\s*([a-zA-Z0-9_\-\.]+)", current_buffer, re.IGNORECASE)
                    for hm in host_matches:
                        h_str = hm.group(1).decode("ascii", errors="ignore").strip()
                        if h_str and "." in h_str:
                            if "web_ir_killchain" not in results:
                                results["web_ir_killchain"] = {
                                    "target_hosts": set(),
                                    "attacker_ips": {},
                                    "failed_logins": 0,
                                    "exploited_endpoints": set(),
                                    "cve_mentions": set(),
                                    "webshells": set(),
                                    "rce_parameters": set(),
                                    "executed_commands": []
                                }
                            results["web_ir_killchain"]["target_hosts"].add(h_str)

                    cve_matches = re.finditer(rb"CVE-\d{4}-\d{4,7}", current_buffer, re.IGNORECASE)
                    for cm in cve_matches:
                        cve_str = cm.group(0).decode("ascii").upper()
                        if "web_ir_killchain" not in results:
                            results["web_ir_killchain"] = {
                                "target_hosts": set(),
                                "attacker_ips": {},
                                "failed_logins": 0,
                                "exploited_endpoints": set(),
                                "cve_mentions": set(),
                                "webshells": set(),
                                "rce_parameters": set(),
                                "executed_commands": []
                            }
                        results["web_ir_killchain"]["cve_mentions"].add(cve_str)

                    ws_exec_matches = re.finditer(rb"(?:shell_exec|system|passthru|eval)\s*\(\s*\$_(?:REQUEST|GET|POST)\[['\"]([a-zA-Z0-9_\-]+)['\"]\]", current_buffer)
                    for wsm in ws_exec_matches:
                        param = wsm.group(1).decode("ascii", errors="ignore")
                        if "web_ir_killchain" not in results:
                            results["web_ir_killchain"] = {
                                "target_hosts": set(),
                                "attacker_ips": {},
                                "failed_logins": 0,
                                "exploited_endpoints": set(),
                                "cve_mentions": set(),
                                "webshells": set(),
                                "rce_parameters": set(),
                                "executed_commands": []
                            }
                        results["web_ir_killchain"]["rce_parameters"].add(param)

                    param_call_matches = re.finditer(rb"[?&]([a-zA-Z0-9_\-]+)=([a-zA-Z0-9_\-\.%]{1,60})\s+HTTP/1\.[01]", current_buffer)
                    for pcm in param_call_matches:
                        p_name = pcm.group(1).decode("ascii", errors="ignore")
                        p_cmd = pcm.group(2).decode("ascii", errors="ignore")
                        if p_name in ("wpc_diag", "cmd", "exec", "c", "shell", "run") or p_cmd in ("id", "whoami", "uname", "ls", "cat"):
                            if "web_ir_killchain" not in results:
                                results["web_ir_killchain"] = {
                                    "target_hosts": set(),
                                    "attacker_ips": {},
                                    "failed_logins": 0,
                                    "exploited_endpoints": set(),
                                    "cve_mentions": set(),
                                    "webshells": set(),
                                    "rce_parameters": set(),
                                    "executed_commands": []
                                }
                            results["web_ir_killchain"]["rce_parameters"].add(p_name)
                            if p_cmd not in results["web_ir_killchain"]["executed_commands"]:
                                results["web_ir_killchain"]["executed_commands"].append(p_cmd)

                    prev_overlap = chunk[-self.overlap:] if len(chunk) >= self.overlap else chunk

        except Exception as e:
            results["error"] = f"Streaming memory error: {str(e)}"

        if "web_ir_killchain" in results:
            wk = results["web_ir_killchain"]
            if isinstance(wk.get("target_hosts"), set):
                wk["target_hosts"] = sorted(list(wk["target_hosts"]))
            if isinstance(wk.get("exploited_endpoints"), set):
                wk["exploited_endpoints"] = sorted(list(wk["exploited_endpoints"]))
            if isinstance(wk.get("cve_mentions"), set):
                wk["cve_mentions"] = sorted(list(wk["cve_mentions"]))
            if isinstance(wk.get("webshells"), set):
                wk["webshells"] = sorted(list(wk["webshells"]))
            if isinstance(wk.get("rce_parameters"), set):
                wk["rce_parameters"] = sorted(list(wk["rce_parameters"]))

        return results

    def scan_raw_framebuffer(
        self,
        filepath_or_data,
        output_dir: Optional[str] = None,
        widths: Tuple[int, ...] = (1920, 1366, 1280, 1024),
        height: int = 120,
        max_frames: int = 5
    ) -> Dict[str, Any]:
        """
        GIMP Raw Memory Dump Visual Inspection (INShAck 2018):
        - Scans memory dump for framebuffer desktop/browser pixel data.
        - Analyzes pixel variance to find non-zero, non-noise candidate frames.
        - Exports recovered candidate frames as uncompressed 24-bit BMP images (pure Python).
        """
        results: Dict[str, Any] = {
            "candidate_frames": [],
            "saved_images": []
        }

        data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            try:
                with open(filepath_or_data, "rb") as f:
                    data = f.read(100 * 1024 * 1024)
            except Exception:
                return results
        elif isinstance(filepath_or_data, bytes):
            data = filepath_or_data[:100 * 1024 * 1024]
        else:
            return results

        out_dir = output_dir or "extracted_artifacts"
        os.makedirs(out_dir, exist_ok=True)

        for width in widths:
            row_size = width * 3
            frame_size = row_size * height
            step = frame_size * 2

            for off in range(0, len(data) - frame_size + 1, step):
                chunk = data[off:off + frame_size]
                if len(chunk) < frame_size:
                    break

                sample = chunk[::max(1, len(chunk) // 500)]
                mean = sum(sample) / len(sample)
                variance = sum((x - mean) ** 2 for x in sample) / len(sample)
                std = variance ** 0.5

                if 20 < mean < 235 and std > 25:
                    bmp_name = f"framebuffer_w{width}_off0x{off:x}.bmp"
                    bmp_path = os.path.join(out_dir, bmp_name)

                    pad_bytes = (4 - (row_size % 4)) % 4
                    img_bytes_total = (row_size + pad_bytes) * height
                    file_size = 54 + img_bytes_total

                    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
                    dib_header = struct.pack("<IIIHHIIIIII", 40, width, height, 1, 24, 0, img_bytes_total, 2835, 2835, 0, 0)

                    pixel_data = bytearray()
                    for r in range(height - 1, -1, -1):
                        r_start = r * row_size
                        r_slice = chunk[r_start:r_start + row_size]
                        for c in range(0, len(r_slice), 3):
                            p = r_slice[c:c + 3]
                            if len(p) == 3:
                                pixel_data.extend([p[2], p[1], p[0]])
                        if pad_bytes:
                            pixel_data.extend(b"\x00" * pad_bytes)

                    try:
                        with open(bmp_path, "wb") as bf:
                            bf.write(file_header + dib_header + bytes(pixel_data))
                        results["saved_images"].append(bmp_path)
                        results["candidate_frames"].append({
                            "width": width,
                            "height": height,
                            "offset": off,
                            "path": bmp_path,
                            "mean": round(mean, 1),
                            "std": round(std, 1)
                        })
                    except Exception:
                        pass

                    if len(results["candidate_frames"]) >= max_frames:
                        return results

        return results

