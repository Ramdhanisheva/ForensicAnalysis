import time
import os
import py7zr

def main():
    archive_path = r"c:\Users\ramdh\Documents\A-FinalisHackToday\Forensic\memory.7z"
    dest_dir = r"c:\Users\ramdh\Documents\A-FinalisHackToday\Forensic"
    output_file = os.path.join(dest_dir, "memory.lime")
    
    if os.path.exists(output_file) and os.path.getsize(output_file) > 1024 * 1024 * 1024:
        print(f"[+] memory.lime already extracted: {os.path.getsize(output_file):,} bytes")
        return

    print(f"[*] Extracting {archive_path} using password 'hacktoday'...")
    t0 = time.time()
    with py7zr.SevenZipFile(archive_path, mode="r", password="hacktoday") as z:
        z.extractall(path=dest_dir)
    elapsed = time.time() - t0
    print(f"[+] Extraction complete in {elapsed:.2f} seconds!")
    if os.path.exists(output_file):
        print(f"[+] Result: {output_file} ({os.path.getsize(output_file):,} bytes)")

if __name__ == "__main__":
    main()
