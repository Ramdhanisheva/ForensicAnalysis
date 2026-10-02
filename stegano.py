import sys
import os
from core.stego_engine import StegoEngine
from core.signal_engine import SignalEngine

def main():
    if len(sys.argv) < 2:
        print("Usage: python stegano.py <image_or_audio_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)

    outdir = "results"
    os.makedirs(outdir, exist_ok=True)

    print(f"[*] Analyzing steganography in: {filepath}...")
    stego = StegoEngine(outdir)
    res = stego.audit_image_steganography(filepath)

    sig = SignalEngine(outdir)
    audio_res = sig.inspect_audio_signals(filepath)

    print("=" * 60)
    print("[+] STEGANOGRAPHY ANALYSIS RESULTS")
    print("=" * 60)

    all_flags = []
    if res.get("flags_found"):
        all_flags.extend(res["flags_found"])
    if audio_res.get("flags_found"):
        all_flags.extend(audio_res["flags_found"])

    if all_flags:
        for fl in all_flags:
            print(f" [!] FLAG: {fl['flag']} ({fl.get('encoding', 'stego')})")
    else:
        print(" [-] No direct flag extracted via standard LSB/DQT.")

    if res.get("anomalies"):
        print("[*] Image Anomalies:")
        for a in res["anomalies"]:
            print(f"    - {a}")
    if audio_res.get("dtmf_digits"):
        print(f"[*] DTMF Tones Decoded: {audio_res['dtmf_digits']}")

if __name__ == "__main__":
    main()
