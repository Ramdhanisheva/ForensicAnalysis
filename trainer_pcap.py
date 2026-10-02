#!/usr/bin/env python3
"""
trainer_pcap.py - CTF Network Forensics Benchmark & Trainer Suite
Simulates and automatically verifies 10 PCAP challenge scenarios from:
- IPB / HackToday CTF (Wireless Mouse, gRPC, ICMP data, DNS leak)
- PicoCTF (shark on wire 1 & 2, packet primer, Wireshark doo dooo dooo)
- National & International Competitions (VoIP RTP audio, TCP covert flags, Gzip HTTP)

Usage:
    python trainer_pcap.py
"""
import os
import sys
import struct
import zlib
import base64

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.pcap_analyzer import PcapAnalyzer
import config


def make_eth_ip_udp(src_ip, dst_ip, src_port, dst_port, payload):
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    udp_len = 8 + len(payload)
    total_len = 20 + udp_len
    s_bytes = bytes(map(int, src_ip.split(".")))
    d_bytes = bytes(map(int, dst_ip.split(".")))
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 17, 0, s_bytes, d_bytes)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0)
    return eth + ip + udp + payload


def make_eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, payload, flags=0x18, seq=1000):
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp_len = 20 + len(payload)
    total_len = 20 + tcp_len
    s_bytes = bytes(map(int, src_ip.split(".")))
    d_bytes = bytes(map(int, dst_ip.split(".")))
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0, s_bytes, d_bytes)
    tcp = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, 0, 5 << 4, flags & 0x3f, 65535, 0, 0)
    return eth + ip + tcp + payload


def make_eth_ip_icmp(src_ip, dst_ip, icmp_type, icmp_code, payload):
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    icmp_len = 8 + len(payload)
    total_len = 20 + icmp_len
    s_bytes = bytes(map(int, src_ip.split(".")))
    d_bytes = bytes(map(int, dst_ip.split(".")))
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 1, 0, s_bytes, d_bytes)
    icmp = struct.pack(">BBHHH", icmp_type, icmp_code, 0, 0x1337, 1) + payload
    return eth + ip + icmp


def write_pcap(filepath, packet_tuples, linktype=1):
    """packet_tuples: list of (timestamp_float, raw_bytes)"""
    gh = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype)
    body = bytearray()
    for ts, pkt in packet_tuples:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        body += struct.pack('<IIII', sec, usec, len(pkt), len(pkt)) + pkt
    with open(filepath, 'wb') as f:
        f.write(gh + bytes(body))


def generate_10_challenges(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    chall_meta = []

    # =========================================================================
    # Chall 1: USB HID Keyboard Keystroke Injection (HackToday / IPB pattern)
    # =========================================================================
    c1_path = os.path.join(out_dir, "01_usb_keystrokes.pcap")
    flag1 = "HackToday26{usb_hid_keystrokes_captured}"
    rev_keymap = {v: k for k, v in config.USB_HID_KEYMAP.items()}
    c1_pkts = []
    t = 100.0
    for ch in flag1:
        mod = 0
        if ch.isupper() or ch in config.USB_HID_SHIFT_KEYMAP.values():
            mod = 0x02  # Shift
            base_char = ch.lower()
            for k_code, s_char in config.USB_HID_SHIFT_KEYMAP.items():
                if s_char == ch:
                    base_char = k_code
                    break
            code = rev_keymap.get(base_char, 0)
        else:
            code = rev_keymap.get(ch, 0)
        hid_report = bytes([mod, 0, code, 0, 0, 0, 0, 0])
        c1_pkts.append((t, hid_report))
        t += 0.02
        c1_pkts.append((t, bytes(8)))  # Key release
        t += 0.02
    write_pcap(c1_path, c1_pkts, linktype=1)
    chall_meta.append((c1_path, flag1, "HackToday / IPB: USB HID Keyboard Keystrokes"))

    # =========================================================================
    # Chall 2: UDP Port Delta Steganography (PicoCTF 'shark on wire 2')
    # =========================================================================
    c2_path = os.path.join(out_dir, "02_picoctf_shark_on_wire2.pcap")
    flag2 = "picoCTF{p1LLf3r3d_data_v1a_st3g0}"
    c2_pkts = []
    t = 200.0
    for _ in range(5):
        c2_pkts.append((t, make_eth_ip_udp("10.0.0.2", "10.0.0.1", 4000, 8080, b"decoy")))
        t += 0.01
    for ch in flag2:
        src_port = 5000 + ord(ch)
        c2_pkts.append((t, make_eth_ip_udp("10.0.0.2", "10.0.0.1", src_port, 22, b"ping")))
        t += 0.02
    write_pcap(c2_path, c2_pkts)
    chall_meta.append((c2_path, flag2, "PicoCTF: shark on wire 2 (UDP Port Delta)"))

    # =========================================================================
    # Chall 3: ICMP Echo Request Payload Exfiltration (HackToday / Cyber Jawara)
    # =========================================================================
    c3_path = os.path.join(out_dir, "03_icmp_data_tunnel.pcap")
    flag3 = "HackToday26{icmp_data_tunnel_ping}"
    c3_pkts = []
    t = 300.0
    for i in range(0, len(flag3), 4):
        chunk = flag3[i:i+4].encode()
        c3_pkts.append((t, make_eth_ip_icmp("192.168.1.50", "8.8.8.8", 8, 0, chunk)))
        t += 0.1
    write_pcap(c3_path, c3_pkts)
    chall_meta.append((c3_path, flag3, "HackToday / Cyber Jawara: ICMP Data Tunneling"))

    # =========================================================================
    # Chall 4: DNS Query Subdomain Exfiltration (IPB / HackToday pattern)
    # =========================================================================
    c4_path = os.path.join(out_dir, "04_dns_subdomain_exfil.pcap")
    flag4 = "HackToday26{dns_subdomain_exfiltration}"
    b64_f4 = base64.b64encode(flag4.encode()).decode()
    c4_pkts = []
    t = 400.0
    for i in range(0, len(b64_f4), 8):
        sub = b64_f4[i:i+8]
        q_domain = f"{sub}.exfil.hacktoday.id"
        parts = q_domain.split(".")
        q_bytes = bytearray()
        for p in parts:
            q_bytes.append(len(p))
            q_bytes.extend(p.encode())
        q_bytes.append(0)
        q_bytes.extend(b"\x00\x01\x00\x01")
        dns_payload = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + bytes(q_bytes)
        c4_pkts.append((t, make_eth_ip_udp("192.168.1.10", "192.168.1.1", 54321, 53, dns_payload)))
        t += 0.05
    write_pcap(c4_path, c4_pkts)
    chall_meta.append((c4_path, flag4, "IPB / HackToday: DNS Subdomain Exfiltration"))

    # =========================================================================
    # Chall 5: HTTP POST Multipart Form File Upload (PicoCTF 'shark on wire 1')
    # =========================================================================
    c5_path = os.path.join(out_dir, "05_http_multipart_upload.pcap")
    flag5 = "picoCTF{multipart_web_upload_file}"
    http_post = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: secret-server.local\r\n"
        b"Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
        b"Content-Length: 280\r\n\r\n"
        b"------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
        b"Content-Disposition: form-data; name=\"file\"; filename=\"secret.txt\"\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        + flag5.encode() + b"\r\n"
        b"------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
    )
    c5_pkts = [(500.0, make_eth_ip_tcp("10.0.0.5", "10.0.0.1", 49152, 80, http_post))]
    write_pcap(c5_path, c5_pkts)
    chall_meta.append((c5_path, flag5, "PicoCTF: HTTP POST Multipart File Upload"))

    # =========================================================================
    # Chall 6: HTTP Gzip Compressed Response Carving (HackToday 2024 web/foren)
    # =========================================================================
    c6_path = os.path.join(out_dir, "06_http_gzip_body_carving.pcap")
    flag6 = "HackToday26{gzip_http_body_decompressed}"
    gzipped_body = zlib.compress(flag6.encode(), 9)
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.18.0\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Encoding: gzip\r\n"
        b"Content-Length: " + str(len(gzipped_body)).encode() + b"\r\n\r\n"
        + gzipped_body
    )
    c6_pkts = [(600.0, make_eth_ip_tcp("172.16.0.2", "172.16.0.100", 80, 52341, http_resp))]
    write_pcap(c6_path, c6_pkts)
    chall_meta.append((c6_path, flag6, "HackToday: HTTP Response with Gzip Body"))

    # =========================================================================
    # Chall 7: FTP Plaintext Credentials & FTP-DATA Stream (PicoCTF)
    # =========================================================================
    c7_path = os.path.join(out_dir, "07_ftp_credentials_and_data.pcap")
    flag7 = "picoCTF{ftp_data_session_carved}"
    ftp_ctrl = (
        b"220 ProFTPD Server ready.\r\n"
        b"USER admin\r\n"
        b"331 Password required for admin\r\n"
        b"PASS Sup3rS3cr3tFTP2026!\r\n"
        b"230 User admin logged in.\r\n"
        b"RETR flag.txt\r\n"
        b"150 Opening BINARY mode data connection for flag.txt\r\n"
    )
    c7_pkts = [
        (700.0, make_eth_ip_tcp("10.10.10.2", "10.10.10.1", 21, 55000, ftp_ctrl)),
        (700.1, make_eth_ip_tcp("10.10.10.2", "10.10.10.1", 20, 55001, flag7.encode() + b"\r\n"))
    ]
    write_pcap(c7_path, c7_pkts)
    chall_meta.append((c7_path, flag7, "PicoCTF: FTP Credentials & FTP-DATA Transfer"))

    # =========================================================================
    # Chall 8: Packet Interval Timing Stego (EHAX 2026 / IPB pattern)
    # =========================================================================
    c8_path = os.path.join(out_dir, "08_timing_interval_stego.pcap")
    flag8 = "HackToday26{timing_interval_stego}"
    flag8_bytes = flag8.encode()
    bits = []
    for b in flag8_bytes:
        for shift in range(7, -1, -1):
            bits.append((b >> shift) & 1)
    c8_pkts = []
    cur_t = 800.0
    for bit in bits:
        dt = 0.05 if bit == 0 else 0.25
        cur_t += dt
        c8_pkts.append((cur_t, make_eth_ip_udp("10.0.0.1", "10.0.0.2", 9000, 9000, b"t")))
    write_pcap(c8_path, c8_pkts)
    chall_meta.append((c8_path, flag8, "EHAX / IPB: Packet Inter-Arrival Timing Stego"))

    # =========================================================================
    # Chall 9: TCP 6-Bit Flags Covert Channel (HackToday covert channel)
    # =========================================================================
    c9_path = os.path.join(out_dir, "09_tcp_flags_covert.pcap")
    flag9 = "HackToday26{tcp_covert_flags}"
    b64_f9 = base64.b64encode(flag9.encode()).decode()
    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    c9_pkts = []
    t = 900.0
    for ch in b64_f9:
        if ch in b64_chars:
            flag_val = b64_chars.index(ch) & 0x3f
            c9_pkts.append((t, make_eth_ip_tcp("192.168.100.5", "192.168.100.1", 12345, 9999, b"", flags=flag_val)))
            t += 0.01
    write_pcap(c9_path, c9_pkts)
    chall_meta.append((c9_path, flag9, "HackToday: TCP 6-Bit Flags Covert Channel"))

    # =========================================================================
    # Chall 10: VoIP RTP Audio Stream (PCMU / G.711u audio stream)
    # =========================================================================
    c10_path = os.path.join(out_dir, "10_voip_rtp_audio_stream.pcap")
    flag10 = "HackToday26{voip_rtp_audio_stream}"
    c10_pkts = []
    t = 1000.0
    rtp_hdr = struct.pack(">BBHII", 0x80, 0, 1, 160, 0xdeadbeef)
    rtp_payload = rtp_hdr + flag10.encode()
    c10_pkts.append((t, make_eth_ip_udp("10.20.30.40", "10.20.30.50", 16384, 16384, rtp_payload)))
    write_pcap(c10_path, c10_pkts)
    chall_meta.append((c10_path, flag10, "HackToday: VoIP RTP Audio Stream Payload"))

    return chall_meta


def main():
    print("=" * 75)
    print(" [*] CTF NETWORK FORENSICS (PCAP) BENCHMARK & TRAINER")
    print("     10 Skenario Nyata: HackToday, IPB, PicoCTF, Cyber Jawara")
    print("=" * 75 + "\n")

    chall_dir = "sample_challenges/pcap_challenges"
    print(f"[*] Membuat 10 file soal latihan PCAP di: {chall_dir}...")
    challenges = generate_10_challenges(chall_dir)
    print(f"[+] 10 file soal latihan berhasil dibuat!\n")

    analyzer = PcapAnalyzer(output_dir="results/trainer_pcap_out")

    solved_count = 0
    total_count = len(challenges)

    print("-" * 75)
    print(f"{'No':<4} | {'Soal':<32} | {'Status':<8} | {'Flag Ditemukan'}")
    print("-" * 75)

    for idx, (c_path, expected_flag, c_desc) in enumerate(challenges, 1):
        filename = os.path.basename(c_path)
        res = analyzer.analyze_pcap(c_path)
        found_flags = [f.get("flag", "") for f in res.get("flags_found", [])]

        is_solved = any(expected_flag in f for f in found_flags)
        if not is_solved and "credentials" in res:
            is_solved = any(expected_flag in c for c in res["credentials"])

        if is_solved:
            status_str = "\033[1;32mSOLVED\033[0m"
            solved_count += 1
            matching_flag = next((f for f in found_flags if expected_flag in f), expected_flag)
            print(f"{idx:<4} | {filename:<32} | {status_str:<17} | {matching_flag}")
        else:
            status_str = "\033[1;31mFAILED\033[0m"
            print(f"{idx:<4} | {filename:<32} | {status_str:<17} | Expected: {expected_flag}")

    print("-" * 75)
    print(f"\n[+] HASIL AKHIR BENCHMARK: {solved_count}/{total_count} SOAL BERHASIL DIPECAHKAN SECARA OTOMATIS!")
    if solved_count == total_count:
        print("\033[1;42;37m [!] 100% PERFECT SCORE! AUTOMOTION BERHASIL MENYELESAIKAN SEMUA 10 SKENARIO PCAP! \033[0m\n")
        sys.exit(0)
    else:
        print(f"\033[1;41;37m [-] Ada {total_count - solved_count} soal yang belum terpecahkan. \033[0m\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
