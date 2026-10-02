import sys
import os
from core.disk_inspector import DiskInspector

def main():
    if len(sys.argv) < 2:
        print("Usage: python disk.py <disk_or_artifact_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    outdir = "results"
    os.makedirs(outdir, exist_ok=True)

    inspector = DiskInspector(outdir)
    print(f"[*] Analyzing disk structures: {filepath}...")
    res = inspector.inspect_disk_artifacts(filepath)

    print("=" * 60)
    print("[+] DISK ANALYSIS RESULTS")
    print("=" * 60)
    if res.get("flags_found"):
        for fl in res["flags_found"]:
            print(f" [!] FLAG: {fl['flag']} ({fl.get('encoding', 'disk')})")
    if res.get("gpt_guid_payload"):
        print("[*] Decoded GPT Partition GUID data found!")
    if res.get("apfs_snapshots"):
        print(f"[*] APFS Snapshots: {len(res['apfs_snapshots'])} found")

if __name__ == "__main__":
    main()
