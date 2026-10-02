"""
Automotion Forensics - Comprehensive Test Suite
Validates all engines: StringHunter, MagicCarver, ExifInspector, StegoEngine,
PcapAnalyzer, AD1Parser, and MemoryStreamer against synthetic CTF challenge artifacts.
"""

import base64
import bz2
import os
import shutil
import struct
import tempfile
import unittest
import zlib

import io
import sqlite3
import zipfile

import config
from core.ad1_parser import AD1Parser
from core.archive_unpacker import ArchiveUnpacker
from core.db_inspector import DBInspector
from core.disk_inspector import DiskInspector
from core.exif_inspector import ExifInspector
from core.magic_carver import MagicCarver
from core.memory_streamer import MemoryStreamer
from core.pcap_analyzer import PcapAnalyzer
from core.peripheral_hunter import PeripheralHunter
from core.signal_engine import SignalEngine
from core.stego_engine import StegoEngine
from core.string_hunter import StringHunter
from core.system_inspector import SystemInspector


class TestAutomotionForensics(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="automotion_test_")
        self.hunter = StringHunter()
        self.carver = MagicCarver(output_dir=self.test_dir)
        self.exif = ExifInspector()
        self.stego = StegoEngine(output_dir=self.test_dir)
        self.pcap = PcapAnalyzer(output_dir=self.test_dir)
        self.ad1 = AD1Parser(output_dir=self.test_dir)
        self.mem = MemoryStreamer(chunk_size=1024 * 1024, overlap=1024)
        self.db = DBInspector(output_dir=self.test_dir)
        self.sys = SystemInspector(output_dir=self.test_dir)
        self.archive = ArchiveUnpacker(output_base=self.test_dir)
        self.disk = DiskInspector(output_dir=self.test_dir)
        self.signal = SignalEngine(output_dir=self.test_dir)
        self.peripheral = PeripheralHunter(output_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_string_hunter_multichannel(self):
        """Test plaintext, base64, hex, rot13, reverse, and XOR flag hunting."""
        # 1. Plaintext
        p_flags = self.hunter.hunt_flags("random text HackToday26{p141n_t3xt_fl4g} more text")
        self.assertTrue(any(f["flag"] == "HackToday26{p141n_t3xt_fl4g}" for f in p_flags))

        # 2. Base64
        b64_raw = base64.b64encode(b"HackToday25{b4s3_64_s0lv3d}").decode()
        b64_flags = self.hunter.hunt_flags(f"junk data {b64_raw} junk")
        self.assertTrue(any(f["flag"] == "HackToday25{b4s3_64_s0lv3d}" for f in b64_flags))

        # 3. Hex
        hex_raw = b"HackToday{h3x_fl4g_f0und}".hex()
        hex_flags = self.hunter.hunt_flags(f"trace: {hex_raw} end")
        self.assertTrue(any(f["flag"] == "HackToday{h3x_fl4g_f0und}" for f in hex_flags))

        # 4. Reverse
        rev_raw = "HackToday26{r3v3rs3_fl4g}"[::-1]
        rev_flags = self.hunter.hunt_flags(f"data {rev_raw} data")
        self.assertTrue(any(f["flag"] == "HackToday26{r3v3rs3_fl4g}" for f in rev_flags))

        # 5. ROT13 / Caesar
        # ROT13 of HackToday{caesar_shift} is UnpxGbqnl{pnrfne_fuvsg}
        rot_flags = self.hunter.hunt_flags("look at this: UnpxGbqnl{pnrfne_fuvsg}")
        self.assertTrue(any(f["flag"] == "HackToday{caesar_shift}" for f in rot_flags))

        # 6. Single-byte XOR
        key = 0x5a
        plain_xor = b"HackToday26{x0r_k3y_5a_fl4g}"
        xored_bytes = bytes(b ^ key for b in plain_xor)
        xor_flags = self.hunter.hunt_flags(b"padding before " + xored_bytes + b" padding after")
        self.assertTrue(any(f["flag"] == "HackToday26{x0r_k3y_5a_fl4g}" for f in xor_flags))

    def test_magic_carver_and_mismatch(self):
        """Test signature detection, extension mismatch, and EOF overlays."""
        # Extension Mismatch test
        mismatch_path = os.path.join(self.test_dir, "innocent.jpg")
        zip_content = b"PK\x03\x04" + b"\x00" * 30 + b"HackToday26{zip_inside_jpg}" + b"PK\x05\x06" + b"\x00" * 18
        with open(mismatch_path, "wb") as f:
            f.write(zip_content)

        fmt = self.carver.identify_format(zip_content, mismatch_path)
        self.assertIn("EXTENSION MISMATCH", fmt["mismatch_warning"])
        self.assertEqual(fmt["primary"]["ext"], "zip")

        # EOF Overlay test: JPEG with appended secret
        jpeg_header = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
        jpeg_body = b"\xff\xdb\x00C\x00" + b"\x01" * 64
        jpeg_trailer = b"\xff\xd9"
        secret_overlay = b"HackToday26{s3cr3t_tr41l1ng_0v3rl4y}"
        full_jpeg = jpeg_header + jpeg_body + jpeg_trailer + secret_overlay

        overlay_info = self.carver.check_eof_overlay(full_jpeg, {"trailer": b"\xff\xd9"})
        self.assertIsNotNone(overlay_info)
        self.assertEqual(overlay_info["overlay_size"], len(secret_overlay))
        self.assertIn(b"HackToday26", overlay_info["full_overlay"])

    def test_stego_png_tamper_solver(self):
        """Test PNG IHDR height tampering auto-solver."""
        width = 400
        true_height = 600
        tampered_height = 200

        # Calculate true CRC with true height
        ihdr_tail = b"\x08\x06\x00\x00\x00"  # 8-bit truecolor+alpha
        true_ihdr_data = b"IHDR" + struct.pack(">II", width, true_height) + ihdr_tail
        target_crc = zlib.crc32(true_ihdr_data) & 0xffffffff

        # Tampered IHDR in file
        tampered_png = (
            b"\x89PNG\r\n\x1a\n" +
            struct.pack(">I", 13) +
            b"IHDR" + struct.pack(">II", width, tampered_height) + ihdr_tail +
            struct.pack(">I", target_crc) +
            struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xffffffff)
        )

        res = self.stego.analyze_png(tampered_png)
        self.assertIsNotNone(res["ihdr_fix"])
        self.assertIn("600", res["ihdr_fix"]["repaired_dimensions"])

    def test_pcap_usb_hid_keyboard(self):
        """Test PCAP parsing with USB HID keyboard keystroke reconstruction."""
        # Create a synthetic Libpcap file containing USB HID packets
        pcap_path = os.path.join(self.test_dir, "test_usb_hid.pcap")

        # Global header: LinkType 249 (USBPcap)
        global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 249)

        # Build USB HID reports for: 'f', 'l', 'a', 'g', '{', 'h', 'i', 'd', '}'
        # Keycodes: f=0x09, l=0x0f, a=0x04, g=0x0a, {=0x2f(shift), h=0x0b, i=0x0c, d=0x07, }=0x30(shift)
        events = [
            (0x00, 0x09),  # f
            (0x00, 0x0f),  # l
            (0x00, 0x04),  # a
            (0x00, 0x0a),  # g
            (0x02, 0x2f),  # { (Shift + [)
            (0x00, 0x0b),  # h
            (0x00, 0x0c),  # i
            (0x00, 0x07),  # d
            (0x02, 0x30),  # } (Shift + ])
        ]

        packets_bytes = bytearray()
        for mod, key in events:
            # 8-byte HID report: modifier, reserved, key1, key2, key3, key4, key5, key6
            hid_rep = bytes([mod, 0x00, key, 0x00, 0x00, 0x00, 0x00, 0x00])
            # USBPcap packet header (27 bytes) + 8-byte report
            pkt_payload = b"\x00" * 19 + hid_rep
            # Packet header: ts_sec, ts_usec, caplen, origlen
            pkt_hdr = struct.pack("<IIII", 1000, 0, len(pkt_payload), len(pkt_payload))
            packets_bytes.extend(pkt_hdr + pkt_payload)

        with open(pcap_path, "wb") as f:
            f.write(global_hdr + packets_bytes)

        analysis = self.pcap.analyze(pcap_path)
        self.assertIn("flag{hid}", analysis["usb_hid_keystrokes"])
        self.assertTrue(any("flag{hid}" in fl["flag"] for fl in analysis["flags_found"]))

    def test_ad1_parser(self):
        """Test AD1 logical image parser with compressed zlib payload."""
        ad1_path = os.path.join(self.test_dir, "evidence.ad1")
        compressed_flag = zlib.compress(b"Secret Document\nFlag: HackToday26{ad1_zlib_decompressed_flag}\nEnd")
        
        # Synthetic AD1 structure: ADSEGMENTEDFILE header + directory index + compressed data
        ad1_content = (
            b"ADSEGMENTEDFILE\x00\x00\x00\x01" +
            b"C:\\Users\\admin\\Desktop\\flag.txt\x00" +
            b"\x00" * 100 +
            compressed_flag +
            b"\x00" * 100
        )

        with open(ad1_path, "wb") as f:
            f.write(ad1_content)

        ad1_res = self.ad1.parse(ad1_path)
        self.assertTrue(ad1_res["is_valid_ad1"])
        self.assertTrue(any("HackToday26{ad1_zlib_decompressed_flag}" in fl["flag"] for fl in ad1_res["flags_found"]))

    def test_memory_streamer_lime(self):
        """Test zero-OOM memory dump streaming reader on synthetic LiME dump."""
        lime_path = os.path.join(self.test_dir, "memory.lime")
        
        # LiME header magic: EMiL
        lime_header = b"EMiL" + struct.pack("<I", 1) + struct.pack("<QQ", 0, 1024 * 1024)
        
        # Synthetic RAM memory pages
        ram_content = (
            b"\x00" * 5000 +
            b"\x00export FLAG=HackToday26{lime_ram_streaming_solved}\x00" +
            b"\x00sudo bash -c 'cat /etc/shadow'\x00" +
            b"\x00" * 5000
        )

        with open(lime_path, "wb") as f:
            f.write(lime_header + ram_content)

        mem_res = self.mem.scan_memory_dump(lime_path)
        self.assertEqual(mem_res["memory_type"], "Linux LiME Memory Dump")
        self.assertTrue(any("HackToday26{lime_ram_streaming_solved}" in fl["flag"] for fl in mem_res["flags_found"]))
        self.assertTrue(any("cat /etc/shadow" in cmd for cmd in mem_res["bash_commands"]))

    def test_db_inspector(self):
        """Test SQLite inspector: table enumeration, text search, and slack carving."""
        db_path = os.path.join(self.test_dir, "test.sqlite")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT);")
        cursor.execute("INSERT INTO users VALUES (1, 'admin', 'HackToday26{sqlite_database_flag_extracted}');")
        cursor.execute("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT);")
        cursor.execute("INSERT INTO moz_places VALUES (1, 'https://hacktoday.ipb.ac.id/secret', 'Secret Page', 5);")
        conn.commit()
        conn.close()

        res = self.db.inspect_database(db_path)
        self.assertTrue(res["is_valid_db"])
        self.assertIn("users", res["tables"])
        self.assertTrue(any("HackToday26{sqlite_database_flag_extracted}" in fl["flag"] for fl in res["flags_found"]))
        self.assertTrue(any("hacktoday.ipb.ac.id" in h for h in res["browser_history"]))

    def test_system_inspector_and_keylogger(self):
        """Test EVTX PowerShell EncodedCommand decoder and Linux input_event parser."""
        # 1. PowerShell EncodedCommand test
        secret_cmd = '$flag = "HackToday26{powershell_encoded_flag_solved}"'
        enc_b64 = base64.b64encode(secret_cmd.encode("utf-16le")).decode()
        fake_log = f"EventID>4104</EventID> powershell.exe -enc {enc_b64} ProcessID 1234"
        sys_res = self.sys.analyze_evtx_or_logs(fake_log.encode())
        self.assertTrue(any(e["event_id"] == "4104" for e in sys_res["key_events"]))
        self.assertTrue(any("HackToday26{powershell_encoded_flag_solved}" in fl["flag"] for fl in sys_res["flags_found"]))

        # 2. Linux input_event keylogger test
        # Type "flag{ev}"
        # Linux keycodes: 'f' (33), 'l' (38), 'a' (30), 'g' (34), '{' (Shift+26), 'e' (18), 'v' (47), '}' (Shift+27)
        events_data = bytearray()
        def add_event(code, val, sec=100):
            # 64-bit input_event struct: sec (8), usec (8), type (2), code (2), val (4) = 24 bytes
            events_data.extend(struct.pack("<QQHHI", sec, 0, 1, code, val))

        # f, l, a, g
        for c in (33, 38, 30, 34):
            add_event(c, 1)
            add_event(c, 0)
        # Shift held, '{' (code 26 = [), Shift release
        add_event(42, 1)  # LeftShift press
        add_event(26, 1)  # '[' with Shift = '{'
        add_event(26, 0)
        add_event(42, 0)  # LeftShift release
        # e, v
        for c in (18, 47):
            add_event(c, 1)
            add_event(c, 0)
        # Shift held, '}' (code 27 = ])
        add_event(42, 1)
        add_event(27, 1)
        add_event(27, 0)
        add_event(42, 0)

        inp_res = self.sys.parse_linux_input_events(bytes(events_data))
        self.assertTrue(inp_res["is_input_event"])
        self.assertIn("flag{ev}", inp_res["reconstructed_text"])

    def test_archive_unpacker(self):
        """Test archive unpacker with ZIP and 7z."""
        zip_path = os.path.join(self.test_dir, "challenge.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("secret.txt", "HackToday26{archive_unpacker_success}")

        res = self.archive.unpack(zip_path, os.path.join(self.test_dir, "unpacked_zip"))
        self.assertTrue(res["success"])
        self.assertEqual(len(res["extracted_files"]), 1)
        self.assertEqual(res["extracted_files"][0]["filename"], "secret.txt")

    def test_gpt_partition_guid_decoding(self):
        """Test GPT partition table GUID data decoding (VuwCTF 2025)."""
        # Header at 512: 'EFI PART'
        data = bytearray(b"\x00" * 2048)
        data[512:520] = b"EFI PART"
        # Entry 0 at 1024, GUID at offset 16 (16 bytes)
        flag_chunk1 = b"HackToday26{gpt_"
        flag_chunk2 = b"guid_solved_ctf}"
        data[1024 + 16:1024 + 32] = flag_chunk1
        data[1024 + 128 + 16:1024 + 128 + 32] = flag_chunk2

        res = self.disk.inspect_gpt_partitions(bytes(data))
        self.assertTrue(res["is_gpt"])
        self.assertEqual(res["partition_count"], 2)
        self.assertTrue(any("HackToday26{gpt_guid_solved_ctf}" in fl["flag"] for fl in res["flags_found"]))

    def test_windows_recycle_bin(self):
        """Test Windows Recycle Bin $I metadata parser."""
        i_path = os.path.join(self.test_dir, "$I12345.txt")
        # Format version 2 (Win 10/11): uint64 version (2), uint64 size, uint64 filetime, uint32 path_len, utf-16le path
        original_path = "C:\\Users\\Admin\\Desktop\\HackToday26{recycle_bin_solved}.txt\x00"
        header = struct.pack("<QQQI", 2, 1024, 133000000000000000, len(original_path))
        with open(i_path, "wb") as f:
            f.write(header + original_path.encode("utf-16le"))

        res = self.disk.inspect_recycle_bin(i_path)
        self.assertTrue(res["is_recycle_i_file"])
        self.assertEqual(res["original_file_size"], 1024)
        self.assertTrue(any("HackToday26{recycle_bin_solved}" in fl["flag"] for fl in res["flags_found"]))

    def test_gcode_parser(self):
        """Test 3D printing G-code parser and comment scraper."""
        gcode_content = (
            "G28 ; Home all axes\n"
            "G1 Z0.2 F1200\n"
            ";=== SECRET_FLAG: HackToday26{3d_printing_gcode_solved} ===\n"
            "G1 X10.5 Y20.3 E1.0 F1500\n"
            "M104 S0 ; turn off temperature\n"
        )
        res = self.signal.parse_gcode(gcode_content.encode())
        self.assertTrue(res["is_gcode"])
        self.assertGreater(res["coordinates_count"], 0)
        self.assertTrue(any("HackToday26{3d_printing_gcode_solved}" in fl["flag"] for fl in res["flags_found"]))

    def test_mouse_pen_drawing(self):
        """Test USB HID mouse/pen drawing recovery to SVG."""
        # Create 20 mock 7-byte reports: btn(1), mode(1), dx(5), dy(5), wheel(0)
        reports = []
        for i in range(25):
            rep = struct.pack("<BBhhB", 1, 1, 5, 5, 0)
            reports.append(rep)

        res = self.peripheral.decode_mouse_pen_drawing(reports, filename_prefix="test_drawing")
        self.assertTrue(res["is_mouse_drawing"])
        self.assertEqual(res["total_points"], 25)
        self.assertIsNotNone(res["svg_path"])
        self.assertTrue(os.path.exists(res["svg_path"]))

    def test_gpt_bzip2_guid_decompression(self):
        """Test GPT partition table GUID auto-decompression (VuwCTF 2025 pattern)."""
        compressed = bz2.compress(b"Flag: HackToday26{gpt_guid_bzip2_decompression_success}")
        pad_len = (16 - (len(compressed) % 16)) % 16
        padded = compressed + (b"\x00" * pad_len)

        data = bytearray(b"\x00" * 4096)
        data[512:520] = b"EFI PART"

        num_chunks = len(padded) // 16
        for i in range(num_chunks):
            chunk = padded[i * 16:(i + 1) * 16]
            entry_off = 1024 + (i * 128)
            data[entry_off + 16:entry_off + 32] = chunk

        res = self.disk.inspect_gpt_partitions(bytes(data))
        self.assertTrue(res["is_gpt"])
        self.assertEqual(res["decompressed_data_type"], "bzip2")
        self.assertTrue(any("HackToday26{gpt_guid_bzip2_decompression_success}" in fl["flag"] for fl in res["flags_found"]))

    def test_raid5_xor_recovery(self):
        """Test RAID 5 missing disk recovery via XOR stream (Crypto-Cat pattern)."""
        disk1_data = b"Disk1PayloadHeader" * 100
        disk2_secret = b"Disk2Secret\x00\x00\x00HackToday26{raid5_xor_disk_reconstructed}\x00" * 50
        # Pad disk2 to equal disk1 length
        if len(disk2_secret) < len(disk1_data):
            disk2_secret = disk2_secret.ljust(len(disk1_data), b"\x00")
        else:
            disk1_data = disk1_data.ljust(len(disk2_secret), b"\x00")

        # disk3 is the parity disk: disk1 ^ disk2
        disk3_parity = bytes(a ^ b for a, b in zip(disk1_data, disk2_secret))

        p1 = os.path.join(self.test_dir, "raid_disk1.raw")
        p3 = os.path.join(self.test_dir, "raid_disk3.raw")
        recovered_p2 = os.path.join(self.test_dir, "raid_disk2_recovered.raw")

        with open(p1, "wb") as f:
            f.write(disk1_data)
        with open(p3, "wb") as f:
            f.write(disk3_parity)

        res = self.disk.recover_raid5_missing_disk([p1, p3], recovered_p2)
        self.assertTrue(res["success"])
        self.assertEqual(res["recovered_size"], len(disk2_secret))
        with open(recovered_p2, "rb") as rf:
            recovered_bytes = rf.read()
        self.assertEqual(recovered_bytes, disk2_secret)
        self.assertTrue(any("HackToday26{raid5_xor_disk_reconstructed}" in fl["flag"] for fl in res["flags_found"]))

    def test_sqlite_diff_history_reconstruction(self):
        """Test SQLite diff history reconstruction for deleted flags (Google CTF 2017)."""
        db_path = os.path.join(self.test_dir, "diff_notes.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE diffs (id INTEGER PRIMARY KEY, type TEXT, position INT, text TEXT);")
        cursor.execute("INSERT INTO diffs VALUES (1, 'insert', 0, 'Welcome to notes. ');")
        cursor.execute("INSERT INTO diffs VALUES (2, 'insert', 18, 'FLAG: HackToday26{intermediate_diff_flag_found} ');")
        cursor.execute("INSERT INTO diffs VALUES (3, 'remove', 18, 'FLAG: HackToday26{intermediate_diff_flag_found} ');")
        cursor.execute("INSERT INTO diffs VALUES (4, 'insert', 18, 'Nothing to see here.');")
        conn.commit()
        conn.close()

        res = self.db.inspect_database(db_path)
        self.assertTrue(res["is_valid_db"])
        self.assertTrue(any("HackToday26{intermediate_diff_flag_found}" in fl["flag"] for fl in res["flags_found"]))

    def test_repeating_xor_flags(self):
        """Test multi-byte repeating XOR flag deduction (srdnlenCTF, VuwCTF)."""
        flag_text = b"Secret Prefix Data... HackToday26{repeating_xor_solved_3bytes} More Suffix Data..."
        key = b"\x5a\x23\xc7"
        cipher = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag_text))

        found = self.hunter.hunt_repeating_xor_flags(cipher, key_lens=(2, 3, 4))
        self.assertTrue(any("HackToday26{repeating_xor_solved_3bytes}" in fl["flag"] for fl in found))

    def test_charset_constrained_xor(self):
        """Test WordPerfect Macro XOR brute force under CTF charset constraints."""
        flag_text = b"HackToday26{wordperfect_macro_xor}"
        key = b"\x14\x38\x52\x71"
        cipher = bytes(b ^ key[i % len(key)] for i, b in enumerate(flag_text))

        recovered = self.hunter.brute_force_charset_xor(cipher, key_len=4)
        self.assertTrue(any("HackToday26{wordperfect_macro_xor}" in r["flag"] for r in recovered))

    def test_corrupted_zip_carving(self):
        """Test ZIP local header carver without Central Directory or EOCD."""
        flag_data = b"HackToday26{corrupted_zip_local_headers_recovered}"
        comp = zlib.compress(flag_data)[2:-4]  # raw deflate stream
        filename = b"flag.txt"

        # Construct single local file header (PK\x03\x04)
        local_header = struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,  # version
            0,   # flags
            8,   # deflate
            0, 0,  # time, date
            zlib.crc32(flag_data),
            len(comp),
            len(flag_data),
            len(filename),
            0    # extra len
        ) + filename + comp

        # Truncate intentionally: NO PK\x01\x02, NO PK\x05\x06
        corrupted_zip_blob = b"RandomPrefixGarbage" + local_header + b"TrailingNoiseWithoutEOCD"
        extracted = self.carver.carve_corrupted_zip_entries(corrupted_zip_blob)
        self.assertEqual(len(extracted), 1)
        self.assertEqual(extracted[0]["name"], "flag.txt")
        self.assertIn(b"HackToday26{corrupted_zip_local_headers_recovered}", extracted[0]["payload"])

    def test_disk_structure_detection(self):
        """Test VMDK Sparse header and APFS superblock detection."""
        # 1. VMDK Sparse header
        vmdk_header = b"KDMV" + struct.pack("<IIIQQ", 1, 0, 20971520, 128, 4) + (b"\x00" * 400)
        res_vmdk = self.disk.detect_disk_structures(vmdk_header)
        self.assertEqual(res_vmdk["format"], "VMDK Sparse Disk Image")
        self.assertIsNotNone(res_vmdk["vmdk_sparse"])
        self.assertEqual(res_vmdk["vmdk_sparse"]["capacity_sectors"], 20971520)

        # 2. APFS Superblock with transaction ID (XID)
        apfs_data = bytearray(b"\x00" * 8192)
        # Block header at 0, XID at offset 16 (uint64 42), magic at offset 32
        struct.pack_into("<Q", apfs_data, 16, 42)
        apfs_data[32:36] = b"APSB"
        res_apfs = self.disk.detect_disk_structures(bytes(apfs_data))
        self.assertEqual(res_apfs["format"], "APFS Volume / Snapshots")
        self.assertEqual(len(res_apfs["apfs_snapshots"]), 1)
        self.assertEqual(res_apfs["apfs_snapshots"][0]["xid"], 42)

    def test_mft_record_parsing(self):
        """Test NTFS MFT resident data carving ($DATA attribute)."""
        record = bytearray(b"\x00" * 1024)
        record[0:4] = b"FILE"
        struct.pack_into("<H", record, 0x14, 0x38)
        struct.pack_into("<H", record, 0x16, 0x01)

        secret_payload = b"HackToday26{mft_resident_data_carved}"
        struct.pack_into("<IIBBH", record, 0x38, 0x80, 64, 0, 0, 0)
        struct.pack_into("<IH", record, 0x38 + 0x10, len(secret_payload), 24)
        record[0x38 + 24:0x38 + 24 + len(secret_payload)] = secret_payload
        struct.pack_into("<I", record, 0x38 + 64, 0xFFFFFFFF)

        res = self.sys.parse_mft_records(bytes(record))
        self.assertEqual(res["total_records"], 1)
        self.assertEqual(len(res["resident_files"]), 1)
        self.assertTrue(any("HackToday26{mft_resident_data_carved}" in fl["flag"] for fl in res["flags_found"]))

    def test_kape_triage_structure(self):
        """Test Windows KAPE triage artifact scanner (ConsoleHost_history, Amcache, etc)."""
        kape_folder = os.path.join(self.test_dir, "KAPE_Triage")
        os.makedirs(kape_folder, exist_ok=True)
        hist_file = os.path.join(kape_folder, "ConsoleHost_history.txt")
        with open(hist_file, "w") as f:
            f.write("whoami\nnet user\n$flag = 'HackToday26{kape_triage_powershell_history}'\n")

        res = self.sys.inspect_kape_triage(kape_folder)
        self.assertTrue(res["is_kape_triage"])
        self.assertTrue(any("HackToday26{kape_triage_powershell_history}" in fl["flag"] for fl in res["flags_found"]))

    def test_raw_framebuffer_carving(self):
        """Test GIMP raw memory dump visual framebuffer inspection."""
        width, height = 1024, 120
        frame_bytes = bytearray()
        for y in range(height):
            for x in range(width):
                frame_bytes.extend([(x % 256), (y % 256), ((x + y) % 256)])

        memory_blob = (b"\x00" * 4096) + bytes(frame_bytes) + (b"\x00" * 4096)
        res = self.mem.scan_raw_framebuffer(memory_blob, output_dir=self.test_dir, widths=(1024,), height=height)
        self.assertGreater(len(res["saved_images"]), 0)
        saved_bmp = res["saved_images"][0]
        self.assertTrue(os.path.exists(saved_bmp))
        with open(saved_bmp, "rb") as bf:
            bmp_head = bf.read(14)
        self.assertEqual(bmp_head[:2], b"BM")

    def test_bson_reconstruction(self):
        """Test BSON / chunked base64 stream reconstruction (IceCTF 2016)."""
        raw_secret = b"HackToday26{bson_chunked_stream_reassembled}"
        b64 = base64.b64encode(raw_secret).decode()
        half = len(b64) // 2
        chunk0 = b64[:half]
        chunk1 = b64[half:]

        fake_bson_dump = f'[{{"index": 0, "data": "{chunk0}"}}, {{"index": 1, "data": "{chunk1}"}}]'
        res = self.carver.reconstruct_bson_chunks(fake_bson_dump.encode(), base_name="test_bson")
        self.assertTrue(res["reconstructed"])
        self.assertEqual(res["chunks_found"], 2)
        self.assertTrue(any("HackToday26{bson_chunked_stream_reassembled}" in fl["flag"] for fl in res["flags_found"]))

    def test_packet_interval_timing_stego(self):
        """Test PCAP packet interval timing-based decoding (EHAX 2026 pattern)."""
        secret = b"HackToday26{timing_stego_solved}"
        # Convert bytes to bits
        bits = []
        for b in secret:
            for shift in range(7, -1, -1):
                bits.append((b >> shift) & 1)

        # 0 = 10ms (0.01s), 1 = 100ms (0.10s)
        curr_time = 1000.0
        timestamps = [curr_time]
        for bit in bits:
            dt = 0.01 if bit == 0 else 0.10
            curr_time += dt
            timestamps.append(curr_time)

        results = {"flags_found": []}
        self.pcap._decode_timing_interval_stego(timestamps, results)
        self.assertTrue(any("HackToday26{timing_stego_solved}" in fl["flag"] for fl in results["flags_found"]))

    def test_tar_duplicate_entry_preservation(self):
        """Test Tar duplicate entry attack preservation (BSidesSF 2025)."""
        import io
        import tarfile
        tar_path = os.path.join(self.test_dir, "duplicate_test.tar")
        with tarfile.open(tar_path, "w") as tf:
            # First entry has the real flag
            data1 = b"HackToday26{tar_duplicate_entry_first_version_preserved}"
            ti1 = tarfile.TarInfo(name="secret.txt")
            ti1.size = len(data1)
            tf.addfile(ti1, io.BytesIO(data1))

            # Second entry with identical name is decoy
            data2 = b"decoy_text_that_normally_overwrites"
            ti2 = tarfile.TarInfo(name="secret.txt")
            ti2.size = len(data2)
            tf.addfile(ti2, io.BytesIO(data2))

        unpacker = ArchiveUnpacker(output_base=self.test_dir)
        res = unpacker.unpack(tar_path)
        self.assertTrue(res["success"])
        self.assertEqual(len(res["extracted_files"]), 2)
        extracted_names = [f["filename"] for f in res["extracted_files"]]
        self.assertIn("secret.txt", extracted_names)
        self.assertIn("secret_dup2.txt", extracted_names)

        # Check content of first extracted file
        first_file = [f["path"] for f in res["extracted_files"] if "dup" not in f["filename"]][0]
        with open(first_file, "rb") as f:
            self.assertEqual(f.read(), data1)

    def test_foren_auto_solver_end_to_end(self):
        """Test foren.py run_forensic_solver end-to-end execution."""
        from foren import run_forensic_solver
        sample_path = os.path.join(self.test_dir, "challenge_sample.bin")
        with open(sample_path, "wb") as f:
            f.write(b"DATA\x00\x00" + b"HackToday26{foren_end_to_end_passed}")

        res = run_forensic_solver(sample_path, stop_on_flag=True, output_base=self.test_dir)
        self.assertTrue(any("HackToday26{foren_end_to_end_passed}" in fl["flag"] for fl in res.get("all_flags", [])))

    def test_picoctf_enhance_svg(self):
        """Test PicoCTF 'Enhance!' SVG <tspan> fragmented text reconstruction."""
        svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg width="500" height="100" xmlns="http://www.w3.org/2000/svg">
  <text id="secret" x="20" y="50">
    <tspan id="c1">p</tspan><tspan id="c2">i</tspan><tspan id="c3">c</tspan><tspan id="c4">o</tspan>
    <tspan id="c5">C</tspan><tspan id="c6">T</tspan><tspan id="c7">F</tspan><tspan id="c8">{</tspan>
    <tspan id="c9">3nh4nc3d_</tspan><tspan id="c10">svg_</tspan><tspan id="c11">tspan_</tspan><tspan id="c12">s0lv3d}</tspan>
  </text>
</svg>"""
        svg_path = os.path.join(self.test_dir, "enhance.svg")
        with open(svg_path, "w", encoding="utf-8") as f:
            f.write(svg_content)

        res = self.stego.analyze_svg(svg_path)
        self.assertTrue(any("picoCTF{3nh4nc3d_svg_tspan_s0lv3d}" in fl["flag"] for fl in res.get("flags_found", [])))

    def test_picoctf_pdf_stream_decompression(self):
        """Test PicoCTF 'Redaction gone wrong' / Nullcon rdctd FlateDecode stream extraction."""
        secret_stream = zlib.compress(b"BT /F1 12 Tf 100 100 Td (picoCTF{pdf_unredacted_stream_revealed}) Tj ET")
        pdf_raw = (
            b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(secret_stream)).encode() + b" /Filter /FlateDecode >>\nstream\n"
            + secret_stream + b"\nendstream\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 >>\nstartxref\n100\n%%EOF"
        )
        pdf_path = os.path.join(self.test_dir, "redacted.pdf")
        with open(pdf_path, "wb") as f:
            f.write(pdf_raw)

        res = self.stego.analyze_pdf(pdf_path)
        self.assertTrue(any("picoCTF{pdf_unredacted_stream_revealed}" in fl["flag"] for fl in res.get("flags_found", [])))

    def test_picoctf_matryoshka_recursive_carving(self):
        """Test PicoCTF 'Matryoshka doll' nested carving: PNG -> embedded ZIP -> PNG -> embedded ZIP -> flag."""
        inner_flag = b"picoCTF{matryoshka_doll_recursive_carver_passed}"
        # Inner ZIP containing secret.txt
        inner_zip_io = io.BytesIO()
        with zipfile.ZipFile(inner_zip_io, "w") as zf:
            zf.writestr("flag.txt", inner_flag)
        inner_zip_bytes = inner_zip_io.getvalue()

        # Inner PNG with appended ZIP
        dummy_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82"
        middle_png = dummy_png + inner_zip_bytes

        # Outer ZIP containing middle.png
        outer_zip_io = io.BytesIO()
        with zipfile.ZipFile(outer_zip_io, "w") as zf:
            zf.writestr("middle.png", middle_png)
        outer_zip_bytes = outer_zip_io.getvalue()

        # Outer PNG with outer ZIP appended
        outer_png = dummy_png + outer_zip_bytes
        outer_path = os.path.join(self.test_dir, "doll.png")
        with open(outer_path, "wb") as f:
            f.write(outer_png)

        res = self.carver.carve_recursive(outer_path, max_depth=5)
        self.assertTrue(any("picoCTF{matryoshka_doll_recursive_carver_passed}" in fl["flag"] for fl in res.get("flags_found", [])))

    def test_picoctf_office_macrohard(self):
        """Test PicoCTF 'MacroHard WeakEdge' Office OpenXML inspection."""
        pptx_io = io.BytesIO()
        with zipfile.ZipFile(pptx_io, "w") as zf:
            zf.writestr("ppt/slides/slide1.xml", "<p:sp><a:t>Decoy presentation</a:t></p:sp>")
            # Hidden slide with base64 encoded flag: picoCTF{m4cr0h4rd_w34kedge}
            # cGljb0NURnttNGNyMGg0cmRfdzM0a2VkZ2V9
            zf.writestr("ppt/slideMasters/hidden", "cGljb0NURnttNGNyMGg0cmRfdzM0a2VkZ2V9")

        pptx_path = os.path.join(self.test_dir, "presentation.pptx")
        with open(pptx_path, "wb") as f:
            f.write(pptx_io.getvalue())

        res = self.stego.analyze_office_document(pptx_path)
        self.assertTrue(any("picoCTF{m4cr0h4rd_w34kedge}" in fl["flag"] for fl in res.get("flags_found", [])))


if __name__ == "__main__":
    unittest.main()
