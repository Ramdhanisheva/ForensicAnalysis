import sys
import os
from core.pcap_analyzer import PcapAnalyzer

def main():
    if len(sys.argv) < 2:
        print("Usage: python pcap.py <capture_file.pcap/.pcapng>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    outdir = "results"
    os.makedirs(outdir, exist_ok=True)

    analyzer = PcapAnalyzer(outdir)
    print(f"[*] Parsing PCAP: {filepath}...")
    res = analyzer.analyze_pcap(filepath)

    print("=" * 60)
    print("[+] PCAP ANALYSIS RESULTS")
    print("=" * 60)
    if res.get("flags_found"):
        for fl in res["flags_found"]:
            print(f" [!] FLAG: {fl['flag']} ({fl.get('encoding', 'network')})")
    if res.get("credentials"):
        print(f"[*] Plaintext Credentials: {len(res['credentials'])} found")
        for cred in res["credentials"]:
            print(f"    - {cred}")
    if res.get("usb_hid_keystrokes"):
        print(f"[*] USB Keystrokes: {res['usb_hid_keystrokes']}")
    if res.get("usb_mouse_drawing"):
        print(f"[*] USB Mouse Drawing saved: {res['usb_mouse_drawing']}")
    if res.get("tcp_flags_covert"):
        print(f"[*] TCP Flags Covert: {res['tcp_flags_covert']}")
    if res.get("timing_stego"):
        print(f"[*] Timing Interval Stego: {res['timing_stego']}")

if __name__ == "__main__":
    main()
