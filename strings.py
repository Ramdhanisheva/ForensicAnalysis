import sys
import os
from core.string_hunter import StringHunter

def main():
    if len(sys.argv) < 2:
        print("Usage: python strings.py <file>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        data = f.read(10 * 1024 * 1024)

    hunter = StringHunter()
    print("[*] Hunting flags with multi-encoding regex (Plaintext, B64, Hex, XOR, ROT13)...")
    flags = hunter.hunt_flags(data)

    print("=" * 60)
    print(f"[+] STRINGS RESULTS: {len(flags)} flags found")
    print("=" * 60)
    for fl in flags:
        print(f" [!] {fl['flag']} ({fl['encoding']})")

if __name__ == "__main__":
    main()
