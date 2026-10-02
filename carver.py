import sys
import os
from core.magic_carver import MagicCarver

def main():
    if len(sys.argv) < 2:
        print("Usage: python carver.py <file>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    outdir = "results"
    os.makedirs(outdir, exist_ok=True)

    carver = MagicCarver(outdir)
    print(f"[*] Scanning file signatures and carving: {filepath}...")
    fmt = carver.identify_format(filepath)
    print(f"[*] Detected format: {fmt.get('primary', {}).get('name', 'Unknown')}")

    carved = carver.carve_embedded_files(filepath)
    print("=" * 60)
    print(f"[+] CARVING RESULTS: {len(carved)} files carved")
    print("=" * 60)
    for c in carved:
        print(f"    -> Extracted: {c['path']} ({c['format']} at offset {c['offset']})")

if __name__ == "__main__":
    main()
