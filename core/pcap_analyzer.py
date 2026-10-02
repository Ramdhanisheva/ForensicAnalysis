"""
Automotion Forensics - Advanced PCAP & PCAPNG Engine
Pure-Python standalone packet parser with automatic tshark integration.
Features:
- USB HID Keyboard keystroke decoder (Modifier + keycodes to ASCII)
- USB Mouse movement detection
- ICMP data tunneling & exfiltration extractor
- DNS exfiltration reassembly (Base64/Hex subdomains)
- HTTP credentials, streams & object extraction
- Deep payload grep across all TCP/UDP streams
"""

import base64
import os
import re
import shutil
import struct
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

import config
from core.peripheral_hunter import PeripheralHunter
from core.string_hunter import StringHunter


def to_wsl_path(win_path: str) -> str:
    """Convert Windows path to WSL /mnt/<drive>/... path."""
    abs_p = os.path.abspath(win_path)
    drive, rest = os.path.splitdrive(abs_p)
    clean_rest = rest.replace("\\", "/")
    if drive:
        return f"/mnt/{drive[0].lower()}" + clean_rest
    return clean_rest


def find_tshark_cmd() -> Optional[List[str]]:
    """Locate tshark binary on Windows or inside WSL Kali."""
    if shutil.which("tshark"):
        return ["tshark"]
    for prog in [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
        if os.path.exists(prog):
            return [prog]
    try:
        chk = subprocess.run(["wsl", "-u", "root", "-d", "kali-linux", "which", "tshark"], capture_output=True, text=True, timeout=5)
        if chk.returncode == 0 and "tshark" in chk.stdout:
            return ["wsl", "-u", "root", "-d", "kali-linux", "tshark"]
    except Exception:
        pass
    return None


class PcapAnalyzer:
    """Analyzes PCAP and PCAPNG files with pure Python and tshark acceleration."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()
        self.peripheral_hunter = PeripheralHunter(self.output_dir)
        self.tshark_cmd = find_tshark_cmd()
        self.has_tshark = self.tshark_cmd is not None

    def analyze(self, filepath: str) -> Dict[str, Any]:
        """Perform comprehensive network forensics triage on a capture file."""
        return self._analyze_impl(filepath)

    analyze_pcap = analyze

    def _analyze_impl(self, filepath: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "source": filepath,
            "engine": "native_python",
            "packet_count": 0,
            "protocols": set(),
            "streams_found": 0,
            "flags_found": [],
            "usb_hid_keystrokes": "",
            "icmp_exfil_data": None,
            "dns_exfil_data": None,
            "credentials": [],
            "suspicious_patterns": {},
            "tshark_summary": None
        }

        # 1. Native Pure-Python PCAP/PCAPNG parsing (Fast native triage)
        try:
            with open(filepath, "rb") as f:
                header = f.read(4)
                f.seek(0)
                if header in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                    self._parse_libpcap(f, results)
                elif header == b"\n\r\r\n":
                    self._parse_pcapng(f, results)
                else:
                    results["error"] = "Unrecognized PCAP magic header"
        except Exception as e:
            results["error"] = f"PCAP parsing exception: {str(e)}"

        # 2. Run tshark analysis if available and needed
        if self.has_tshark and not results.get("flags_found"):
            try:
                results["tshark_summary"] = self._run_tshark_triage(filepath, results)
                results["engine"] = "hybrid (native + tshark)"
            except Exception:
                pass

        # Convert set of protocols to sorted list for JSON serialization
        if isinstance(results["protocols"], set):
            results["protocols"] = sorted(list(results["protocols"]))

        return results

    def _parse_libpcap(self, f, results: Dict[str, Any]):
        """Parse standard Libpcap 24-byte header and records."""
        global_hdr = f.read(24)
        if len(global_hdr) < 24:
            return

        magic = global_hdr[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        linktype = struct.unpack(f"{endian}I", global_hdr[20:24])[0]

        packets_raw = []
        timestamps = []
        while True:
            rec_hdr = f.read(16)
            if len(rec_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", rec_hdr)
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                break
            packets_raw.append(packet_data)
            timestamps.append(ts_sec + (ts_usec / 1_000_000.0))
            results["packet_count"] += 1

        self._process_packets(packets_raw, linktype, results, timestamps)

    def _parse_pcapng(self, f, results: Dict[str, Any]):
        """Parse PCAPNG Enhanced Packet Blocks (EPB) and Section Blocks."""
        packets_raw = []
        timestamps = []
        linktype = 1  # Default Ethernet

        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_total_len = struct.unpack("<II", block_hdr)
            if block_total_len < 12:
                break

            body_len = block_total_len - 12
            body = f.read(body_len)
            f.read(4)  # Trailing block total len

            # Interface Description Block (Type 0x00000001)
            if block_type == 0x00000001 and len(body) >= 4:
                linktype = struct.unpack("<H", body[:2])[0]
                results["protocols"].add(f"LinkType_{linktype}")

            # Enhanced Packet Block (Type 0x00000006)
            elif block_type == 0x00000006 and len(body) >= 20:
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack("<IIIII", body[:20])
                pkt_data = body[20:20 + cap_len]
                packets_raw.append(pkt_data)
                timestamps.append(((ts_high << 32) | ts_low) / 1_000_000.0)
                results["packet_count"] += 1

        self._process_packets(packets_raw, linktype, results, timestamps)

    def _process_packets(self, packets: List[bytes], linktype: int, results: Dict[str, Any], timestamps: Optional[List[float]] = None):
        """Dissect packet payloads: Ethernet, IP, TCP, UDP, ICMP, USB HID."""
        tcp_streams: Dict[Tuple, bytearray] = {}
        icmp_payloads: List[bytes] = []
        dns_queries: List[str] = []
        hid_reports: List[bytes] = []
        udp_port_seqs: Dict[Tuple[str, int], List[int]] = {}
        rtp_payloads: List[bytes] = []
        eapol_count = 0

        # Linktype 1: Ethernet; Linktype 220: USB Linux; Linktype 249: USBPcap
        is_usb = linktype in (220, 249)

        tcp_flags_seq: Dict[str, List[int]] = {}

        for pkt in packets:
            if is_usb or (len(pkt) >= 8 and (pkt.startswith(b"\x00\x00\x00") or len(pkt) in (8, 27, 64))):
                # Check for USB HID payload
                hid_cand = self._extract_usb_hid_candidate(pkt)
                if hid_cand:
                    hid_reports.append(hid_cand)
                    results["protocols"].add("USB_HID")
                    continue

            # Check EAPOL / WPA Handshake (802.1X EtherType 0x888e)
            if len(pkt) >= 14 and pkt[12:14] == b"\x88\x8e":
                results["protocols"].add("EAPOL_WPA")
                eapol_count += 1

            # Check Ethernet (14 bytes header)
            if len(pkt) > 14 and pkt[12:14] == b"\x08\x00":  # IPv4
                results["protocols"].add("IPv4")
                ip_hdr = pkt[14:]
                if len(ip_hdr) < 20:
                    continue
                proto = ip_hdr[9]
                ihl = (ip_hdr[0] & 0x0f) * 4
                src_ip = ".".join(map(str, ip_hdr[12:16]))
                dst_ip = ".".join(map(str, ip_hdr[16:20]))
                l4_data = ip_hdr[ihl:]

                # TCP (Proto 6)
                if proto == 6 and len(l4_data) >= 20:
                    results["protocols"].add("TCP")
                    src_port, dst_port = struct.unpack(">HH", l4_data[:4])
                    data_offset = ((l4_data[12] >> 4) & 0x0f) * 4
                    tcp_payload = l4_data[data_offset:]

                    # Track 6 TCP flag bits (FIN, SYN, RST, PSH, ACK, URG) for covert channels
                    flag_val = l4_data[13] & 0x3f
                    dest_key = f"{dst_ip}:{dst_port}"
                    if dest_key not in tcp_flags_seq:
                        tcp_flags_seq[dest_key] = []
                    tcp_flags_seq[dest_key].append(flag_val)

                    if tcp_payload:
                        stream_id = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
                        if stream_id not in tcp_streams:
                            tcp_streams[stream_id] = bytearray()
                        tcp_streams[stream_id].extend(tcp_payload)

                        # Check HTTP
                        if tcp_payload.startswith((b"GET ", b"POST ", b"HTTP/1.", b"PUT ", b"HEAD ")):
                            results["protocols"].add("HTTP")
                            self._extract_http_creds(tcp_payload, results)

                        # Check FTP (Port 21 or FTP command strings)
                        if dst_port == 21 or src_port == 21:
                            results["protocols"].add("FTP")
                            for fc in re.findall(r"(?:USER|PASS|RETR|STOR)\s+([^\r\n]+)", tcp_payload.decode("latin-1", errors="ignore"), re.IGNORECASE):
                                results["credentials"].append(f"FTP: {fc.strip()}")

                # UDP (Proto 17)
                elif proto == 17 and len(l4_data) >= 8:
                    results["protocols"].add("UDP")
                    src_port, dst_port = struct.unpack(">HH", l4_data[:4])
                    udp_payload = l4_data[8:]

                    # Track UDP source ports for covert channel (PicoCTF 'shark on wire 2' pattern)
                    dest_ep = (dst_ip, dst_port)
                    if dest_ep not in udp_port_seqs:
                        udp_port_seqs[dest_ep] = []
                    udp_port_seqs[dest_ep].append(src_port)

                    # DNS (Port 53)
                    if dst_port == 53 or src_port == 53:
                        results["protocols"].add("DNS")
                        query = self._extract_dns_query(udp_payload)
                        if query:
                            dns_queries.append(query)

                    # VoIP RTP Audio (Payload Type 0=PCMU or 8=PCMA)
                    if len(udp_payload) >= 12 and udp_payload[0] == 0x80 and (udp_payload[1] & 0x7f) in (0, 8):
                        results["protocols"].add("VoIP_RTP")
                        rtp_payloads.append(udp_payload[12:])

                # ICMP (Proto 1)
                elif proto == 1 and len(l4_data) >= 8:
                    results["protocols"].add("ICMP")
                    icmp_type = l4_data[0]
                    # Echo Request (8) or Echo Reply (0)
                    if icmp_type in (8, 0) and len(l4_data) > 8:
                        icmp_payloads.append(l4_data[8:])

        if eapol_count >= 4:
            results["wpa_handshake_detected"] = True
            results["suspicious_patterns"]["WPA_Handshake"] = [
                f"Ditemukan {eapol_count} EAPOL frames (WPA 4-way handshake). Rekomendasi: `aircrack-ng <file> -w /path/to/wordlist.txt`"
            ]

        results["streams_found"] = len(tcp_streams)

        # 1. Fast Grep across all assembled TCP streams
        for stream_id, payload in tcp_streams.items():
            p_bytes = bytes(payload)[:128 * 1024]
            flags = self.string_hunter.hunt_flags(p_bytes, fast_only=True)
            for f in flags:
                f["context"] = f"[Stream {stream_id[0][0]}:{stream_id[0][1]} <-> {stream_id[1][0]}:{stream_id[1][1]}] {f['context']}"
                results["flags_found"].append(f)

            sus = self.string_hunter.hunt_suspicious_patterns(p_bytes, limit_per_type=2)
            for k, v in sus.items():
                if k not in results["suspicious_patterns"]:
                    results["suspicious_patterns"][k] = []
                results["suspicious_patterns"][k].extend(v)

        # Deep Cipher Hunt only on candidate streams if no flags discovered yet
        if not results["flags_found"] and tcp_streams:
            for stream_id, payload in list(tcp_streams.items())[:5]:
                p_bytes = bytes(payload)[:64 * 1024]
                deep_flags = self.string_hunter.hunt_flags(p_bytes, early_stop=True)
                for f in deep_flags:
                    f["context"] = f"[Stream {stream_id[0][0]}:{stream_id[0][1]} <-> {stream_id[1][0]}:{stream_id[1][1]}] {f['context']}"
                    results["flags_found"].append(f)
                if results["flags_found"]:
                    break

        # 2. Decode USB HID Keyboard keystrokes
        if hid_reports:
            keystrokes = self._decode_hid_reports(hid_reports)
            if keystrokes.strip():
                results["usb_hid_keystrokes"] = keystrokes.strip()
                flags = self.string_hunter.hunt_flags(keystrokes)
                for f in flags:
                    f["encoding"] = f"USB HID ({f['encoding']})"
                    results["flags_found"].append(f)

        # 3. Analyze ICMP Exfiltration
        if icmp_payloads:
            full_icmp = b"".join(icmp_payloads)
            results["icmp_exfil_data"] = {
                "packet_count": len(icmp_payloads),
                "total_bytes": len(full_icmp),
                "sample_hex": full_icmp[:64].hex()
            }
            flags = self.string_hunter.hunt_flags(full_icmp)
            for f in flags:
                f["encoding"] = f"ICMP Tunnel ({f['encoding']})"
                results["flags_found"].append(f)

        # 4. Analyze DNS Exfiltration & Trailing Bytes
        if dns_queries:
            dns_assembled = self._reassemble_dns_exfil(dns_queries)
            if dns_assembled:
                results["dns_exfil_data"] = dns_assembled
                flags = self.string_hunter.hunt_flags(dns_assembled.get("decoded", ""))
                for f in flags:
                    f["encoding"] = f"DNS Exfil ({f['encoding']})"
                    results["flags_found"].append(f)

            # DNS Trailing Byte Steganography (UTCTF 2026)
            trailing_chars = [q.rstrip(".")[-1] for q in dns_queries if q.rstrip(".")]
            trailing_str = "".join(trailing_chars)
            for fl in self.string_hunter.hunt_flags(trailing_str):
                fl["encoding"] = f"DNS Trailing Byte ({fl['encoding']})"
                results["flags_found"].append(fl)

        # 5. Analyze TCP Flags Covert Channel (6 bits = Base64 index)
        b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        for dest_key, f_seq in tcp_flags_seq.items():
            if len(f_seq) >= 6:
                b64_str = "".join(b64_chars[v] for v in f_seq if v < 64)
                for fl in self.string_hunter.hunt_flags(b64_str):
                    fl["encoding"] = f"TCP Flags Covert ({fl['encoding']})"
                    fl["context"] = f"[{dest_key}] {fl['context']}"
                    results["flags_found"].append(fl)

        # 6. Check USB HID Mouse/Pen Drawing
        if hid_reports:
            mouse_res = self.peripheral_hunter.decode_mouse_pen_drawing(hid_reports)
            if mouse_res.get("is_mouse_drawing"):
                results["usb_mouse_drawing"] = mouse_res
                for fl in mouse_res.get("flags_found", []):
                    results["flags_found"].append(fl)

        # 7. Check Packet Interval Timing Stego (EHAX 2026 pattern from network-advanced.md)
        if timestamps:
            self._decode_timing_interval_stego(timestamps, results)

        # 8. Check UDP Port Delta Covert Stego (PicoCTF 'shark on wire 2' pattern)
        if udp_port_seqs:
            self._decode_udp_port_stego(udp_port_seqs, results)

        # 9. Carve HTTP Response Bodies (Images, Archives, Gzip decompressed files)
        if tcp_streams:
            self._carve_http_bodies(tcp_streams, results)

        # 10. Process VoIP RTP Audio Payload
        if rtp_payloads:
            self._process_rtp_audio(rtp_payloads, results)

    def _decode_udp_port_stego(self, udp_port_seqs: Dict[Tuple[str, int], List[int]], results: Dict[str, Any]):
        """
        PicoCTF 'shark on wire 2' UDP Port Stego Solver:
        - Detects flags encoded in UDP source ports to a destination (e.g. port - 5000 = ASCII)
        """
        for (dst_ip, dst_port), src_ports in udp_port_seqs.items():
            if len(src_ports) < 8:
                continue

            # Try candidate port offsets: 5000 (PicoCTF), 20000, 10000, 0, or modulo 256
            for offset in (5000, 10000, 20000, 0):
                chars = []
                for p in src_ports:
                    val = p - offset if offset else p % 256
                    if 32 <= val <= 126:
                        chars.append(chr(val))
                    elif val in (10, 13):
                        chars.append(" ")

                if len(chars) >= 8:
                    candidate_str = "".join(chars)
                    flags = self.string_hunter.hunt_flags(candidate_str)
                    for fl in flags:
                        fl["encoding"] = f"UDP Port Delta (offset {offset}) ({fl['encoding']})"
                        fl["context"] = f"Dst {dst_ip}:{dst_port} sequence of {len(src_ports)} packets: {fl.get('context', '')}"
                        results["flags_found"].append(fl)

    def _carve_http_bodies(self, tcp_streams: Dict, results: Dict[str, Any]):
        """
        Carve and decompress transferred files (PNG, ZIP, gzip) from HTTP response streams.
        """
        import zlib
        for stream_id, payload in tcp_streams.items():
            payload_bytes = bytes(payload)
            # Find HTTP responses (HTTP/1.0 200 OK or HTTP/1.1 200 OK)
            for m in re.finditer(rb"HTTP/1\.[01]\s+\d{3}[^\r\n]*\r\n", payload_bytes):
                h_start = m.start()
                h_end = payload_bytes.find(b"\r\n\r\n", h_start)
                if h_end == -1:
                    continue
                header_text = payload_bytes[h_start:h_end].decode("latin-1", errors="ignore")
                body_start = h_end + 4

                # Determine body length
                m_len = re.search(r"Content-Length:\s*(\d+)", header_text, re.IGNORECASE)
                if m_len:
                    b_len = int(m_len.group(1))
                    body = payload_bytes[body_start : body_start + b_len]
                else:
                    body = payload_bytes[body_start:]

                # Decompress gzip/deflate/zlib if applicable
                is_gzip = "gzip" in header_text.lower() or "deflate" in header_text.lower() or body.startswith(b"\x1f\x8b\x08") or body.startswith(b"\x78\x9c")
                if is_gzip:
                    try:
                        import gzip
                        decompressed = gzip.decompress(body)
                        body = decompressed
                    except Exception:
                        try:
                            decompressed = zlib.decompress(body, 16 + zlib.MAX_WBITS)
                            body = decompressed
                        except Exception:
                            try:
                                body = zlib.decompress(body, -15)
                            except Exception:
                                try:
                                    body = zlib.decompress(body)
                                except Exception:
                                    pass

                # Scan flags in the carved body (fast scan first)
                for fl in self.string_hunter.hunt_flags(body[:256 * 1024], fast_only=True):
                    fl["encoding"] = f"HTTP Carved Body ({fl['encoding']})"
                    fl["context"] = f"Stream {stream_id[0]} <-> {stream_id[1]}: {fl.get('context', '')}"
                    results["flags_found"].append(fl)

    def _process_rtp_audio(self, rtp_payloads: List[bytes], results: Dict[str, Any]):
        """Extract VoIP RTP audio stream bytes and check for flags."""
        full_audio = b"".join(rtp_payloads)
        results["rtp_audio_bytes"] = len(full_audio)
        for fl in self.string_hunter.hunt_flags(full_audio):
            fl["encoding"] = f"VoIP RTP Audio ({fl['encoding']})"
            results["flags_found"].append(fl)

    def _decode_timing_interval_stego(self, timestamps: List[float], results: Dict[str, Any]):
        """
        Packet Interval Timing-Based Encoding (EHAX 2026):
        - Detects binary data encoded in inter-packet delay intervals
        - Clustered thresholding into binary bits -> bytes -> flag check
        """
        if len(timestamps) < 24:
            return

        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        positive_intervals = [dt for dt in intervals if dt > 0.0001]
        if len(positive_intervals) < 24:
            return

        min_dt = min(positive_intervals)
        max_dt = max(positive_intervals)

        if max_dt > min_dt * 1.5:
            threshold = (min_dt + max_dt) / 2.0
            raw_bits = [0 if dt < threshold else 1 for dt in positive_intervals]

            for candidate_bits in (raw_bits, [0] + raw_bits, [1] + raw_bits):
                byte_list = []
                for b_idx in range(0, len(candidate_bits) - 7, 8):
                    b_val = int("".join(str(b) for b in candidate_bits[b_idx:b_idx + 8]), 2)
                    byte_list.append(b_val)
                decoded_bytes = bytes(byte_list)

                for fl in self.string_hunter.hunt_flags(decoded_bytes):
                    fl["encoding"] = f"PCAP Packet Interval Timing ({fl['encoding']})"
                    results["flags_found"].append(fl)

    def _extract_usb_hid_candidate(self, pkt: bytes) -> Optional[bytes]:
        """Extract 8-byte HID keyboard report candidate."""
        # Standalone 8-byte payload
        if len(pkt) == 8:
            return pkt
        # USB Linux URB (last 8 bytes)
        if len(pkt) >= 64:
            return pkt[-8:]
        # USBPcap buffer
        if len(pkt) >= 27:
            return pkt[-8:]
        return None

    def _decode_hid_reports(self, reports: List[bytes]) -> str:
        """Convert USB HID reports (modifier byte + scan codes) into typed text."""
        typed_chars = []
        for rep in reports:
            if len(rep) < 3:
                continue
            modifier = rep[0]
            # First keycode is at index 2 (or index 1 on some Linux USB sniffers)
            keycode = rep[2] if rep[1] == 0x00 and len(rep) >= 3 else rep[1]
            if keycode == 0:
                continue

            char = config.USB_HID_KEYMAP.get(keycode, "")
            if modifier & 0x22:  # Left or Right Shift
                char = config.USB_HID_SHIFT_KEYMAP.get(char, char.upper())

            if char == '\b':
                if typed_chars:
                    typed_chars.pop()
            elif char:
                typed_chars.append(char)

        return "".join(typed_chars)

    def _extract_http_creds(self, payload: bytes, results: Dict[str, Any]):
        """Extract HTTP Authorization headers, cookies, and login parameters."""
        text = payload[:2048].decode("latin-1", errors="ignore")
        # Basic Auth
        m_auth = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE)
        if m_auth:
            b64_val = m_auth.group(1)
            try:
                dec = base64.b64decode(b64_val).decode("latin-1", errors="ignore")
                results["credentials"].append(f"HTTP Basic Auth: {dec} (raw: {b64_val})")
            except Exception:
                results["credentials"].append(f"HTTP Basic Auth (raw): {b64_val}")

        # Cookie
        m_cookie = re.search(r"Cookie:\s*([^\r\n]+)", text, re.IGNORECASE)
        if m_cookie:
            results["credentials"].append(f"HTTP Cookie: {m_cookie.group(1)[:80]}")

    def _extract_dns_query(self, udp_payload: bytes) -> Optional[str]:
        """Extract DNS query domain name from payload."""
        if len(udp_payload) < 12:
            return None
        # Skip 12-byte DNS header
        pos = 12
        parts = []
        while pos < len(udp_payload):
            length = udp_payload[pos]
            if length == 0:
                break
            if length > 63 or pos + 1 + length > len(udp_payload):
                return None
            pos += 1
            parts.append(udp_payload[pos:pos + length].decode("latin-1", errors="ignore"))
            pos += length
        return ".".join(parts) if parts else None

    def _reassemble_dns_exfil(self, queries: List[str]) -> Optional[Dict[str, Any]]:
        """Identify and reassemble exfiltrated data across DNS subdomains."""
        subdomain_chunks = []
        for q in queries:
            parts = q.split(".")
            if len(parts) >= 2:
                # First part is typically the exfiltrated chunk
                chunk = parts[0]
                if re.match(r"^[A-Za-z0-9+/=_-]{4,}$", chunk):
                    if chunk not in subdomain_chunks:
                        subdomain_chunks.append(chunk)

        if not subdomain_chunks:
            return None

        joined = "".join(subdomain_chunks)
        # Attempt Base64, Hex, or Base32 decode
        decoded_text = ""
        # 1. Base64
        try:
            pad = (4 - len(joined) % 4) % 4
            d_b64 = base64.b64decode(joined + ("=" * pad)).decode("latin-1", errors="ignore")
            if any(p in d_b64 for p in ("HackToday", "flag{", "{")):
                decoded_text = d_b64
        except Exception:
            pass

        # 2. Hex
        if not decoded_text:
            try:
                d_hex = bytes.fromhex(joined).decode("latin-1", errors="ignore")
                if any(p in d_hex for p in ("HackToday", "flag{", "{")):
                    decoded_text = d_hex
            except Exception:
                pass

        return {
            "chunks_count": len(subdomain_chunks),
            "joined_raw": joined[:100],
            "decoded": decoded_text or joined
        }

    def _run_tshark_triage(self, filepath: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tshark commands to pull protocol hierarchy, export HTTP objects, and decrypt TLS."""
        tshark_info = {}
        is_wsl = bool(self.tshark_cmd and self.tshark_cmd[0] == "wsl")
        target_path = to_wsl_path(filepath) if is_wsl else os.path.abspath(filepath)

        # 1. Protocol Hierarchy
        try:
            cmd = list(self.tshark_cmd) + ["-r", target_path, "-qz", "io,phs"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if p.returncode == 0:
                tshark_info["hierarchy"] = p.stdout.strip()
        except Exception:
            pass

        # 2. Export HTTP Objects
        http_export_dir = os.path.join(self.output_dir, "tshark_http_objects")
        os.makedirs(http_export_dir, exist_ok=True)
        wsl_export_dir = to_wsl_path(http_export_dir) if is_wsl else http_export_dir

        try:
            cmd = list(self.tshark_cmd) + ["-r", target_path, "--export-objects", f"http,{wsl_export_dir}"]
            subprocess.run(cmd, capture_output=True, timeout=6)
            exported = os.listdir(http_export_dir)
            if exported:
                tshark_info["http_objects_exported"] = exported
                keylog_file = None
                nested_pcaps = []

                for obj_name in exported:
                    obj_path = os.path.join(http_export_dir, obj_name)
                    if not os.path.isfile(obj_path):
                        continue
                    try:
                        with open(obj_path, "rb") as of:
                            content = of.read()
                        for fl in self.string_hunter.hunt_flags(content[:256 * 1024], fast_only=True):
                            fl["source_file"] = obj_name
                            results["flags_found"].append(fl)

                        if any(marker in content for marker in (b"CLIENT_RANDOM", b"CLIENT_HANDSHAKE_TRAFFIC_SECRET", b"SERVER_HANDSHAKE_TRAFFIC_SECRET")) or "sslkey" in obj_name.lower():
                            keylog_file = obj_path

                        if content.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")):
                            nested_pcaps.append(obj_path)
                    except Exception:
                        pass

                # If keylog was found, decrypt nested captures or original pcap
                if keylog_file:
                    tshark_info["ssl_keylog_detected"] = keylog_file
                    dec_dir = os.path.join(self.output_dir, "tls_decrypted_objects")
                    os.makedirs(dec_dir, exist_ok=True)
                    wsl_dec_dir = to_wsl_path(dec_dir) if is_wsl else dec_dir
                    wsl_keylog = to_wsl_path(keylog_file) if is_wsl else keylog_file

                    targets_to_decrypt = nested_pcaps if nested_pcaps else [filepath]
                    for target_pcap in targets_to_decrypt:
                        wsl_target_pcap = to_wsl_path(target_pcap) if is_wsl else target_pcap
                        try:
                            dec_cmd = list(self.tshark_cmd) + [
                                "-r", wsl_target_pcap,
                                "-o", f"tls.keylog_file:{wsl_keylog}",
                                "--export-objects", f"http,{wsl_dec_dir}"
                            ]
                            subprocess.run(dec_cmd, capture_output=True, timeout=15)
                            for dec_f in os.listdir(dec_dir):
                                df_path = os.path.join(dec_dir, dec_f)
                                if os.path.isfile(df_path):
                                    with open(df_path, "rb") as df:
                                        df_content = df.read()
                                    for fl in self.string_hunter.hunt_flags(df_content):
                                        fl["source_file"] = f"decrypted/{dec_f}"
                                        fl["encoding"] = f"TLS Decrypted HTTP ({fl['encoding']})"
                                        results["flags_found"].append(fl)
                        except Exception:
                            pass
        except Exception:
            pass

        # 3. TrevorC2 Triage
        try:
            self._triage_trevorc2(filepath, results)
        except Exception:
            pass

        return tshark_info

    def _triage_trevorc2(self, filepath: str, results: Dict[str, Any]):
        """Inspect PCAP for TrevorC2 covert communications and decrypt traffic."""
        try:
            with open(filepath, "rb") as f:
                raw_data = f.read()
        except Exception:
            return

        oldcss_matches = re.findall(rb"oldcss=([a-zA-Z0-9+/=]+)", raw_data)
        guid_matches = re.findall(rb"guid=([a-zA-Z0-9+/=]+)", raw_data)
        if not oldcss_matches and not guid_matches:
            return

        import hashlib
        try:
            from Crypto.Cipher import AES
        except ImportError:
            return

        ciphers_to_try = [
            "Tr3v0rC2R0x@nd1s@w350m3#TrevorForget",
            "Tr3v0rC2IsAlive",
            "TrevorC2",
            "Tr3v0rC2"
        ]

        decrypted_texts = []
        for cipher_pass in ciphers_to_try:
            key = hashlib.sha256(cipher_pass.encode()).digest()
            for b64_cand in set(oldcss_matches + guid_matches):
                try:
                    raw = base64.b64decode(b64_cand)
                    if len(raw) < 32 or len(raw) % 16 != 0:
                        continue
                    iv = raw[:16]
                    ct = raw[16:]
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    pt = cipher.decrypt(ct)
                    pad_len = pt[-1]
                    if isinstance(pad_len, int) and 1 <= pad_len <= 16:
                        pt = pt[:-pad_len]
                    if pt and pt != b"nothing" and any(32 <= b <= 126 for b in pt):
                        txt = pt.decode("latin-1", errors="ignore")
                        decrypted_texts.append(txt)
                        for fl in self.string_hunter.hunt_flags(pt):
                            fl["encoding"] = f"TrevorC2 Decrypted ({fl['encoding']})"
                            results["flags_found"].append(fl)
                except Exception:
                    pass

        if decrypted_texts:
            results["trevorc2_traffic"] = {
                "detected": True,
                "decrypted_snippets": decrypted_texts[:10]
            }

