#!/usr/bin/env python3
"""
memodump.py - Memory Dump Analyzer
Scans .lime, .raw, .dmp, .vmem memory dumps for flags, bash history, env vars, SSH keys.

Usage:
    python memodump.py memory.lime
    python memodump.py memory.lime --no-stop
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.memory_streamer import MemoryStreamer
from core.string_hunter import StringHunter


def main():
    if len(sys.argv) < 2:
        print("Usage: python memodump.py <dump_file> [--no-stop]")
        print("  --no-stop   Terus scan meski sudah nemu flag")
        sys.exit(1)

    filepath = os.path.abspath(sys.argv[1])
    if not os.path.exists(filepath):
        print(f"[-] File tidak ditemukan: {filepath}")
        sys.exit(1)

    stop_on_flag = "--no-stop" not in sys.argv
    file_size = os.path.getsize(filepath)
    streamer = MemoryStreamer()
    hunter = StringHunter()

    print("=" * 60)
    print(f"[*] Memory Dump Analyzer")
    print(f"[*] Target : {os.path.basename(filepath)}")
    print(f"[*] Ukuran : {file_size / (1024**3):.2f} GB ({file_size:,} bytes)")
    print("=" * 60)

    # --- Step 1: WSL strings | grep (tercepat) ---
    print("\n[*] Step 1: WSL strings|grep cepat untuk flag...")
    grep_pats = "HackToday26{|HackToday25{|HackToday{|hacktoday{|picoCTF{|PicoCTF{|flag{|FLAG{|CTF{|COMPFEST{|ITToday{"
    wsl_path = filepath.replace("\\", "/")
    if len(wsl_path) >= 2 and wsl_path[1] == ":":
        wsl_path = f"/mnt/{wsl_path[0].lower()}" + wsl_path[2:]
    _found_wsl = False
    for distro in ["kali-linux", "Ubuntu", "Debian"]:
        try:
            cmd = ["wsl", "-d", distro, "bash", "-c",
                   f"strings -n 6 '{wsl_path}' | grep -aEi '({grep_pats})' | head -200"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if proc.returncode == 0 and proc.stdout.strip():
                print(f"[!] WSL strings ({distro}) menemukan:")
                for line in proc.stdout.strip().splitlines():
                    print(f"    >> {line.strip()}")
                _found_wsl = True
                break
        except Exception:
            pass
    if not _found_wsl:
        print("[*] WSL tidak tersedia atau tidak ada hasil, lanjut ke Python engine...")

    # --- Step 2: Python streaming engine ---
    print(f"\n[*] Step 2: Python Streaming Engine (32MB window, full scan)...")
    flags_found = []

    def on_flag(fl):
        flags_found.append(fl)
        print(f"\n  [!!!] FLAG DITEMUKAN: {fl['flag']}  ({fl['encoding']})")
        if stop_on_flag:
            print("  (Gunakan --no-stop untuk scan tuntas)")

    res = streamer.scan_memory_dump(
        filepath,
        max_bytes=None,
        on_flag_found=on_flag,
        early_stop=stop_on_flag
    )

    print("\n" + "=" * 60)
    print("[+] HASIL ANALISIS MEMORY DUMP")
    print("=" * 60)

    if res.get("kernel_banner"):
        print(f"\n[*] Kernel Banner: {res['kernel_banner'][:120]}")
        m = re.search(r"(\d+\.\d+\.\d+)", res["kernel_banner"])
        if m:
            print(f"[*] Kernel Version: {m.group(1)}")

    if res.get("flags_found") or flags_found:
        all_flags = res.get("flags_found", []) + [f for f in flags_found if f not in res.get("flags_found", [])]
        print(f"\n[!] FLAG DITEMUKAN ({len(all_flags)} total):")
        for fl in all_flags:
            print(f"    [FLAG] {fl['flag']}  ({fl['encoding']})")

    if res.get("bash_commands"):
        cmds = res["bash_commands"]
        print(f"\n[+] Bash History ({len(cmds)} perintah):")
        for cmd in cmds[:20]:
            print(f"    $ {cmd}")

    if res.get("env_vars"):
        print(f"\n[+] Environment Variables ({len(res['env_vars'])} ditemukan):")
        for ev in res["env_vars"][:15]:
            print(f"    {ev}")

    if res.get("ssh_keys"):
        print(f"\n[!] SSH Private Key ditemukan: {len(res['ssh_keys'])} kunci!")
        for i, k in enumerate(res["ssh_keys"][:2], 1):
            print(f"    Key #{i}: {k[:80]}...")

    if res.get("scripts_found"):
        print(f"\n[+] Script/File Reference ditemukan: {len(res['scripts_found'])}")
        for sc in res["scripts_found"][:5]:
            print(f"    {sc[:100]}")

    print(f"\n[*] Volatility 3 — Command yang disarankan:")
    for vc in res.get("volatility_recommendations", []):
        print(f"    {vc}")


if __name__ == "__main__":
    main()
