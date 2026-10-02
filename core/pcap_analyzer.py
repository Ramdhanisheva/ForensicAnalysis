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


class PcapAnalyzer:
    """Analyzes PCAP and PCAPNG files with pure Python and tshark acceleration."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()
        self.peripheral_hunter = PeripheralHunter(self.output_dir)
        self.has_tshark = shutil.which("tshark") is not None

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

        # 1. Run tshark analysis if available
        if self.has_tshark:
            try:
                results["tshark_summary"] = self._run_tshark_triage(filepath)
                results["engine"] = "hybrid (native + tshark)"
            except Exception:
                pass

        # 2. Native Pure-Python PCAP/PCAPNG parsing
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

                # UDP (Proto 17)
                elif proto == 17 and len(l4_data) >= 8:
                    results["protocols"].add("UDP")
                    src_port, dst_port = struct.unpack(">HH", l4_data[:4])
                    udp_payload = l4_data[8:]
                    if dst_port == 53 or src_port == 53:
                        results["protocols"].add("DNS")
                        query = self._extract_dns_query(udp_payload)
                        if query:
                            dns_queries.append(query)

                # ICMP (Proto 1)
                elif proto == 1 and len(l4_data) >= 8:
                    results["protocols"].add("ICMP")
                    icmp_type = l4_data[0]
                    # Echo Request (8) or Echo Reply (0)
                    if icmp_type in (8, 0) and len(l4_data) > 8:
                        icmp_payloads.append(l4_data[8:])

        results["streams_found"] = len(tcp_streams)

        # 1. Deep Grep across all assembled TCP streams
        for stream_id, payload in tcp_streams.items():
            flags = self.string_hunter.hunt_flags(bytes(payload))
            for f in flags:
                f["context"] = f"[Stream {stream_id[0][0]}:{stream_id[0][1]} <-> {stream_id[1][0]}:{stream_id[1][1]}] {f['context']}"
                results["flags_found"].append(f)

            sus = self.string_hunter.hunt_suspicious_patterns(bytes(payload), limit_per_type=3)
            for k, v in sus.items():
                if k not in results["suspicious_patterns"]:
                    results["suspicious_patterns"][k] = []
                results["suspicious_patterns"][k].extend(v)

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

    def _run_tshark_triage(self, filepath: str) -> Dict[str, Any]:
        """Execute tshark commands to pull protocol hierarchy and export objects."""
        tshark_info = {}
        # Protocol Hierarchy
        try:
            p = subprocess.run(
                ["tshark", "-r", filepath, "-qz", "io,phs"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if p.returncode == 0:
                tshark_info["hierarchy"] = p.stdout.strip()
        except Exception:
            pass

        # Export HTTP Objects
        http_export_dir = os.path.join(self.output_dir, "tshark_http_objects")
        os.makedirs(http_export_dir, exist_ok=True)
        try:
            subprocess.run(
                ["tshark", "-r", filepath, "--export-objects", f"http,{http_export_dir}"],
                capture_output=True,
                timeout=10
            )
            exported = os.listdir(http_export_dir)
            if exported:
                tshark_info["http_objects_exported"] = exported
        except Exception:
            pass

        return tshark_info
