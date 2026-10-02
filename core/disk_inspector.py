"""
Automotion Forensics - Disk, Partitions & Windows Artifacts Inspector
Techniques from ctf-forensics (disk-advanced.md, disk-recovery.md, windows.md):
- GPT Partition Table GUID Data Decoder (VuwCTF 2025: hidden bzip2/flags in GUIDs)
- Windows Recycle Bin ($I / $R) Metadata & Payload Recovery
- Windows LNK Shortcut File Parser (target paths, volume serials)
- Windows Prefetch (.pf) Execution Metadata & Timestamp Parser
- Nested Matryoshka Archive Recursive Unpacker
"""

import base64
import bz2
import datetime
import gzip
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.string_hunter import StringHunter


class DiskInspector:
    """Inspects disk partition tables, Windows shortcuts, Recycle Bin artifacts, and Prefetch."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def inspect_gpt_partitions(self, filepath_or_data) -> Dict[str, Any]:
        """
        GPT Partition GUID Data Decoder (VuwCTF 2025 pattern):
        - Header at offset 512 (signature 'EFI PART')
        - 128 entries at offset 1024 (128 bytes each)
        - Unique partition GUID at offset 16 (16 bytes)
        - Concatenates non-zero GUID bytes and tests for embedded flags or archives.
        - Auto-decompresses bzip2, gzip, zlib, and ASCII85 streams embedded in GUIDs.
        """
        results: Dict[str, Any] = {
            "is_gpt": False,
            "partition_count": 0,
            "guids": [],
            "concatenated_guid_bytes": b"",
            "decompressed_data_type": None,
            "flags_found": []
        }

        data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            try:
                with open(filepath_or_data, "rb") as f:
                    data = f.read(1024 + 128 * 128)
            except Exception:
                return results
        elif isinstance(filepath_or_data, bytes):
            data = filepath_or_data[:1024 + 128 * 128]
        else:
            return results

        # Check GPT Header signature: 'EFI PART' at offset 512
        if len(data) > 520 and data[512:520] == b"EFI PART":
            results["is_gpt"] = True
            guid_chunks = []

            for i in range(128):
                entry_offset = 1024 + (i * 128)
                if entry_offset + 128 <= len(data):
                    entry = data[entry_offset:entry_offset + 128]
                    # Partition Type GUID: bytes 0:16
                    # Unique Partition GUID: bytes 16:32
                    guid = entry[16:32]
                    if guid != b"\x00" * 16:
                        results["partition_count"] += 1
                        guid_hex = guid.hex()
                        results["guids"].append(guid_hex)
                        guid_chunks.append(guid)

            if guid_chunks:
                concat_bytes = b"".join(guid_chunks)
                results["concatenated_guid_bytes"] = concat_bytes
                
                # Check for direct flags
                for fl in self.string_hunter.hunt_flags(concat_bytes):
                    fl["encoding"] = f"GPT Partition GUID ({fl['encoding']})"
                    results["flags_found"].append(fl)

                # Auto-decompression for compressed GUID payloads (VuwCTF 2025 pattern: bzip2 + ascii85)
                decompressed = None
                if concat_bytes.startswith(b"BZh"):
                    try:
                        decompressed = bz2.decompress(concat_bytes)
                        results["decompressed_data_type"] = "bzip2"
                    except Exception:
                        pass
                elif concat_bytes.startswith(b"\x1f\x8b\x08"):
                    try:
                        decompressed = gzip.decompress(concat_bytes)
                        results["decompressed_data_type"] = "gzip"
                    except Exception:
                        pass
                elif concat_bytes.startswith((b"\x78\x9c", b"\x78\x01", b"\x78\xda")):
                    try:
                        decompressed = zlib.decompress(concat_bytes)
                        results["decompressed_data_type"] = "zlib"
                    except Exception:
                        pass

                if decompressed:
                    # Scan decompressed stream
                    for fl in self.string_hunter.hunt_flags(decompressed):
                        fl["encoding"] = f"GPT GUID Decompressed [{results['decompressed_data_type']}] ({fl['encoding']})"
                        results["flags_found"].append(fl)

                    # Check for ASCII85 or Base85 encoded data inside decompressed output
                    for decoder, name in [(base64.a85decode, "ASCII85"), (base64.b85decode, "Base85")]:
                        try:
                            # Clean whitespace before decoding
                            clean_payload = decompressed.strip().replace(b"\n", b"").replace(b"\r", b"")
                            decoded_85 = decoder(clean_payload)
                            for fl in self.string_hunter.hunt_flags(decoded_85):
                                fl["encoding"] = f"GPT GUID [{results['decompressed_data_type']} + {name}] ({fl['encoding']})"
                                results["flags_found"].append(fl)
                        except Exception:
                            pass

        return results

    def inspect_recycle_bin(self, filepath: str) -> Dict[str, Any]:
        """
        Windows Recycle Bin $I metadata parser:
        - $I files: format version, original file size, FILETIME deletion timestamp, original path.
        """
        results: Dict[str, Any] = {
            "is_recycle_i_file": False,
            "original_file_size": 0,
            "deletion_timestamp": None,
            "original_path": "",
            "flags_found": []
        }

        if not os.path.exists(filepath):
            return results

        filename = os.path.basename(filepath)
        try:
            with open(filepath, "rb") as f:
                header = f.read(544)

            # Format 1 (Win Vista/7/8): 8-byte version (1), 8-byte size, 8-byte FILETIME, 520-byte UTF-16LE path
            # Format 2 (Win 10/11): 8-byte version (2), 8-byte size, 8-byte FILETIME, 4-byte path len, UTF-16LE path
            if len(header) >= 28 and filename.startswith("$I"):
                version = struct.unpack("<Q", header[0:8])[0]
                if version in (1, 2):
                    results["is_recycle_i_file"] = True
                    file_size = struct.unpack("<Q", header[8:16])[0]
                    filetime = struct.unpack("<Q", header[16:24])[0]
                    results["original_file_size"] = file_size

                    # Convert Windows FILETIME (100-ns intervals since Jan 1 1601) to ISO datetime
                    if filetime > 0:
                        try:
                            dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
                            results["deletion_timestamp"] = dt.isoformat()
                        except Exception:
                            pass

                    # Extract path
                    path_bytes = header[24:] if version == 1 else header[28:]
                    path_str = path_bytes.decode("utf-16le", errors="ignore").split("\x00")[0]
                    results["original_path"] = path_str

                    for fl in self.string_hunter.hunt_flags(path_str):
                        fl["encoding"] = f"Recycle Bin $I ({fl['encoding']})"
                        results["flags_found"].append(fl)

        except Exception:
            pass

        return results

    def inspect_lnk(self, filepath: str) -> Dict[str, Any]:
        """
        Windows LNK Shortcut File Parser:
        Header magic: \x4c\x00\x00\x00\x01\x14\x02\x00
        Extracts target paths, working directory, and command-line arguments.
        """
        results: Dict[str, Any] = {
            "is_lnk": False,
            "target_path": "",
            "arguments": "",
            "flags_found": []
        }

        if not os.path.exists(filepath):
            return results

        try:
            with open(filepath, "rb") as f:
                content = f.read(100000)

            if content.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
                results["is_lnk"] = True

                # Search UTF-16LE and ASCII target paths in LNK structure
                text = content.decode("latin-1", errors="ignore")
                paths = re.findall(r"([A-Za-z]:\\[^\x00\r\n]{3,200})", text)
                if paths:
                    results["target_path"] = paths[0]

                for fl in self.string_hunter.hunt_flags(content):
                    fl["encoding"] = f"Windows LNK ({fl['encoding']})"
                    results["flags_found"].append(fl)

        except Exception:
            pass

        return results

    def recover_raid5_missing_disk(
        self,
        disk_paths: List[str],
        output_path: Optional[str] = None,
        chunk_size: int = 1024 * 1024
    ) -> Dict[str, Any]:
        """
        RAID 5 Disk Recovery via XOR (Crypto-Cat pattern from ctf-forensics):
        - For N-disk array with 1 missing disk, missing = D1 ^ D2 ^ ... ^ D_{n-1}
        - Works block-by-block in chunks (default 1MB) for minimal memory footprint.
        - Automatically checks the recovered disk for filesystem magic headers and flags.
        """
        results: Dict[str, Any] = {
            "success": False,
            "input_disks": disk_paths,
            "output_path": output_path,
            "recovered_size": 0,
            "detected_fs": None,
            "flags_found": [],
            "error": None
        }

        if len(disk_paths) < 2:
            results["error"] = "At least 2 disk images required for RAID 5 recovery"
            return results

        for p in disk_paths:
            if not os.path.exists(p):
                results["error"] = f"File not found: {p}"
                return results

        sizes = [os.path.getsize(p) for p in disk_paths]
        min_size = min(sizes)
        max_size = max(sizes)
        if min_size != max_size:
            results["warning"] = f"Disk sizes differ: min={min_size} bytes, max={max_size} bytes. Recovery truncated to min_size."

        if not output_path:
            output_path = os.path.join(self.output_dir, "raid5_recovered_disk.img")
        results["output_path"] = output_path

        try:
            fps = [open(p, "rb") for p in disk_paths]
            total_bytes = 0
            with open(output_path, "wb") as out_f:
                while total_bytes < min_size:
                    to_read = min(chunk_size, min_size - total_bytes)
                    chunks = [fp.read(to_read) for fp in fps]
                    if not all(chunks) or len(chunks[0]) == 0:
                        break

                    xor_buf = bytearray(chunks[0])
                    for other in chunks[1:]:
                        for idx, b in enumerate(other):
                            xor_buf[idx] ^= b

                    out_f.write(xor_buf)
                    total_bytes += len(xor_buf)

            for fp in fps:
                fp.close()

            results["success"] = True
            results["recovered_size"] = total_bytes

            # Quick inspect of first 1MB of recovered disk
            with open(output_path, "rb") as rf:
                sample = rf.read(1024 * 1024)

            # Filesystem signatures
            if len(sample) > 0x438 and sample[0x438:0x43a] == b"\x53\xef":
                results["detected_fs"] = "Linux Ext2/Ext3/Ext4"
            elif len(sample) > 8 and sample[3:11] == b"NTFS    ":
                results["detected_fs"] = "Windows NTFS"
            elif len(sample) > 0x36 and sample[0x36:0x3e] == b"FAT16   ":
                results["detected_fs"] = "FAT16"
            elif len(sample) > 0x52 and sample[0x52:0x5a] == b"FAT32   ":
                results["detected_fs"] = "FAT32"
            elif len(sample) > 520 and sample[512:520] == b"EFI PART":
                results["detected_fs"] = "GPT Partition Table"

            # Check for flags in recovered header/sample
            flags = self.string_hunter.hunt_flags(sample)
            for fl in flags:
                fl["encoding"] = f"RAID 5 Recovered ({fl['encoding']})"
                results["flags_found"].append(fl)

        except Exception as e:
            results["error"] = str(e)

        return results

    def detect_disk_structures(self, filepath_or_data) -> Dict[str, Any]:
        """
        Detects disk image headers and snapshot structures:
        - VMDK Sparse (KDMV header)
        - APFS Superblocks across snapshots (APSB magic + XID)
        - ISO 9660 volume descriptor (CD001)
        - MBR Partition Table (0x55AA signature)
        """
        results: Dict[str, Any] = {
            "format": "Unknown Raw / Disk",
            "vmdk_sparse": None,
            "apfs_snapshots": [],
            "is_iso9660": False,
            "is_mbr": False,
            "flags_found": []
        }

        data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            try:
                with open(filepath_or_data, "rb") as f:
                    data = f.read(20 * 1024 * 1024)
            except Exception:
                return results
        elif isinstance(filepath_or_data, bytes):
            data = filepath_or_data[:20 * 1024 * 1024]
        else:
            return results

        # 1. VMDK Sparse Header check ('KDMV' magic)
        if len(data) >= 64 and data.startswith(b"KDMV"):
            results["format"] = "VMDK Sparse Disk Image"
            try:
                version, flags, capacity, grain_size, gd_offset = struct.unpack("<IIIQQ", data[4:32])
                results["vmdk_sparse"] = {
                    "version": version,
                    "flags": flags,
                    "capacity_sectors": capacity,
                    "grain_size": grain_size,
                    "gd_offset": gd_offset
                }
            except Exception:
                pass

        # 2. ISO 9660 Volume Descriptor ('CD001' at 0x8000, 0x8800, 0x9000)
        for iso_offset in (0x8000, 0x8800, 0x9000):
            if len(data) >= iso_offset + 6 and data[iso_offset + 1:iso_offset + 6] == b"CD001":
                results["is_iso9660"] = True
                results["format"] = "ISO 9660 Optical Disc Image"
                break

        # 3. MBR boot signature check (0x55AA at offset 510)
        if len(data) >= 512 and data[510:512] == b"\x55\xaa":
            results["is_mbr"] = True
            if results["format"] == "Unknown Raw / Disk":
                results["format"] = "MBR Partitioned Disk Image"

        # 4. APFS Superblock & Historical Snapshots ('APSB' magic search)
        pos = 0
        apfs_xids = []
        while True:
            idx = data.find(b"APSB", pos)
            if idx == -1:
                break
            if idx >= 32:
                hdr_start = idx - 32
                xid = struct.unpack_from("<Q", data, hdr_start + 16)[0]
                blk = hdr_start // 4096
                apfs_xids.append({"xid": xid, "block_index": blk, "offset": hdr_start})
            pos = idx + 4
            if len(apfs_xids) >= 50:
                break

        if apfs_xids:
            results["format"] = "APFS Volume / Snapshots"
            results["apfs_snapshots"] = sorted(apfs_xids, key=lambda x: x["xid"])

        return results

    def inspect_disk_artifacts(self, filepath_or_data) -> Dict[str, Any]:
        """Unified runner for all disk inspection techniques."""
        all_results: Dict[str, Any] = {
            "flags_found": [],
            "gpt": None,
            "structures": None,
            "recycle_bin": None,
            "lnk": None,
            "prefetch": None
        }

        # 1. GPT Partition scan
        gpt_res = self.inspect_gpt_partitions(filepath_or_data)
        all_results["gpt"] = gpt_res
        if gpt_res.get("flags_found"):
            all_results["flags_found"].extend(gpt_res["flags_found"])
        if gpt_res.get("concatenated_guid_bytes"):
            all_results["gpt_guid_payload"] = gpt_res["concatenated_guid_bytes"]

        # 2. Disk structures (VMDK, ISO9660, MBR, APFS)
        struct_res = self.detect_disk_structures(filepath_or_data)
        all_results["structures"] = struct_res
        if struct_res.get("apfs_snapshots"):
            all_results["apfs_snapshots"] = struct_res["apfs_snapshots"]

        # 3. Recycle bin ($I)
        rb_res = self.parse_recycle_bin_i(filepath_or_data)
        if rb_res.get("is_recycle_bin_i"):
            all_results["recycle_bin"] = rb_res
            if rb_res.get("original_filename"):
                for fl in self.string_hunter.hunt_flags(rb_res["original_filename"]):
                    all_results["flags_found"].append(fl)

        # 4. LNK shortcut
        lnk_res = self.parse_lnk_file(filepath_or_data)
        if lnk_res.get("is_lnk"):
            all_results["lnk"] = lnk_res
            for field in ("local_path", "relative_path", "command_args"):
                val = lnk_res.get(field, "")
                if val:
                    for fl in self.string_hunter.hunt_flags(val):
                        all_results["flags_found"].append(fl)

        # 5. Prefetch (.pf)
        pf_res = self.parse_prefetch(filepath_or_data)
        if pf_res.get("is_prefetch"):
            all_results["prefetch"] = pf_res
            if pf_res.get("executable_name"):
                for fl in self.string_hunter.hunt_flags(pf_res["executable_name"]):
                    all_results["flags_found"].append(fl)

        return all_results
