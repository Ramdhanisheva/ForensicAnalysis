"""
Automotion Forensics - Signals, Hardware & 3D Printing Engine
Techniques from ctf-forensics (signals-and-hardware.md, 3d-printing.md, stego-advanced.md):
- DTMF Audio Tone Decoder (standard library wave + Goertzel peak detection)
- Flipper Zero .sub Radio Capture Parser
- 3D Printing G-Code & PrusaSlicer Binary G-code (.g / .bgcode) Parser & Toolpath Extractor
"""

import math
import os
import re
import struct
import wave
import zlib
from typing import Any, Dict, List, Optional, Tuple

from core.string_hunter import StringHunter


class SignalEngine:
    """Decodes signals (audio DTMF, sub-GHz radio) and hardware toolpaths (G-code)."""

    DTMF_FREQUENCIES = {
        (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
        (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
        (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
        (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
    }

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def goertzel_mag(self, samples: List[float], sample_rate: int, target_freq: float) -> float:
        """Goertzel algorithm to compute magnitude of a target frequency without FFT library."""
        k = int(0.5 + ((len(samples) * target_freq) / sample_rate))
        w = (2.0 * math.pi / len(samples)) * k
        cosine = math.cos(w)
        coeff = 2.0 * cosine

        q0 = 0.0
        q1 = 0.0
        q2 = 0.0

        for sample in samples:
            q0 = coeff * q1 - q2 + sample
            q2 = q1
            q1 = q0

        return math.sqrt(q1 * q1 + q2 * q2 - q1 * q2 * coeff)

    def decode_dtmf_wav(self, wav_path: str) -> Dict[str, Any]:
        """Decode DTMF phone tones from uncompressed PCM WAV file using pure Python."""
        results: Dict[str, Any] = {
            "is_dtmf": False,
            "digits": "",
            "flags_found": []
        }

        if not os.path.exists(wav_path):
            return results

        try:
            with wave.open(wav_path, "rb") as wf:
                num_channels = wf.getnchannels()
                sample_width = wf.getsampwidth()
                sample_rate = wf.getframerate()
                num_frames = wf.getnframes()
                raw_data = wf.readframes(min(num_frames, 2000000))

            if sample_width != 2:  # 16-bit PCM expected
                return results

            # Unpack first channel
            total_samples = len(raw_data) // (2 * num_channels)
            step = num_channels * 2
            samples = [
                struct.unpack("<h", raw_data[i:i+2])[0]
                for i in range(0, total_samples * step, step)
            ]

            # 40ms block window
            block_size = int(sample_rate * 0.04)
            detected_chars = []
            prev_char = None

            row_freqs = [697, 770, 852, 941]
            col_freqs = [1209, 1336, 1477, 1633]

            for i in range(0, len(samples) - block_size, block_size):
                block = samples[i:i + block_size]

                # Check row max
                row_mags = [(f, self.goertzel_mag(block, sample_rate, f)) for f in row_freqs]
                best_row, max_row_mag = max(row_mags, key=lambda x: x[1])

                # Check col max
                col_mags = [(f, self.goertzel_mag(block, sample_rate, f)) for f in col_freqs]
                best_col, max_col_mag = max(col_mags, key=lambda x: x[1])

                # Threshold check: tone present if magnitude exceeds baseline
                if max_row_mag > 50000 and max_col_mag > 50000:
                    char = self.DTMF_FREQUENCIES.get((best_row, best_col), "")
                    if char and char != prev_char:
                        detected_chars.append(char)
                        prev_char = char
                else:
                    prev_char = None

            digits = "".join(detected_chars)
            if len(digits) >= 3:
                results["is_dtmf"] = True
                results["digits"] = digits

                for fl in self.string_hunter.hunt_flags(digits):
                    fl["encoding"] = f"DTMF Audio ({fl['encoding']})"
                    results["flags_found"].append(fl)

        except Exception:
            pass

        return results

    def parse_flipper_sub(self, filepath: str) -> Dict[str, Any]:
        """Parse Flipper Zero .sub sub-GHz radio captures."""
        results: Dict[str, Any] = {
            "is_flipper_sub": False,
            "metadata": {},
            "raw_samples_count": 0,
            "flags_found": []
        }

        if not os.path.exists(filepath):
            return results

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(500000)

            if "Flipper SubGhz" in content:
                results["is_flipper_sub"] = True
                for line in content.splitlines():
                    if ":" in line and not line.startswith("RAW_Data:"):
                        k, v = line.split(":", 1)
                        results["metadata"][k.strip()] = v.strip()

                for fl in self.string_hunter.hunt_flags(content):
                    fl["encoding"] = f"Flipper .sub ({fl['encoding']})"
                    results["flags_found"].append(fl)

        except Exception:
            pass

        return results

    def parse_gcode(self, filepath_or_data) -> Dict[str, Any]:
        """
        Parse 3D printer G-Code and PrusaSlicer binary G-code (.g / .bgcode):
        - Signature: 'GCDE' or text G-code lines (G0, G1, M104)
        - Scrapes comments for hidden flags (;=== FLAG ... ===)
        - Reconstructs XY toolpath bounding box
        """
        results: Dict[str, Any] = {
            "is_gcode": False,
            "comments_count": 0,
            "coordinates_count": 0,
            "flags_found": []
        }

        raw_data = b""
        if isinstance(filepath_or_data, str) and os.path.exists(filepath_or_data):
            try:
                with open(filepath_or_data, "rb") as f:
                    raw_data = f.read(20 * 1024 * 1024)
            except Exception:
                return results
        elif isinstance(filepath_or_data, bytes):
            raw_data = filepath_or_data
        else:
            return results

        # 1. PrusaSlicer Binary G-code (GCDE)
        if raw_data.startswith(b"GCDE"):
            results["is_gcode"] = True
            pos = 10
            while pos < len(raw_data) - 8:
                try:
                    block_type, compression, uncompressed_size = struct.unpack("<HHI", raw_data[pos:pos+8])
                    pos += 8
                    if compression != 0:
                        compressed_size = struct.unpack("<I", raw_data[pos:pos+4])[0]
                        pos += 4
                    else:
                        compressed_size = uncompressed_size

                    if block_type in (0, 1, 2, 3, 4):
                        pos += 2
                    elif block_type == 5:
                        pos += 6

                    block_data = raw_data[pos:pos+compressed_size]
                    pos += compressed_size + 4

                    if compression == 1:  # Deflate
                        try:
                            decomp = zlib.decompress(block_data)
                            for fl in self.string_hunter.hunt_flags(decomp):
                                fl["encoding"] = f"Binary G-Code Block {block_type} ({fl['encoding']})"
                                results["flags_found"].append(fl)
                        except Exception:
                            pass
                except Exception:
                    break
            return results

        # 2. Plaintext G-code
        text = raw_data.decode("latin-1", errors="ignore")
        if re.search(r"(?:^|\n)(?:G0|G1|M104|M140|G28)\s+", text):
            results["is_gcode"] = True

            comments = re.findall(r";([^\r\n]+)", text)
            results["comments_count"] = len(comments)

            for cm in comments[:100]:
                for fl in self.string_hunter.hunt_flags(cm):
                    fl["encoding"] = f"G-Code Comment ({fl['encoding']})"
                    results["flags_found"].append(fl)

            coords = re.findall(r"G[01]\s+X([0-9\.\-]+)\s+Y([0-9\.\-]+)", text)
            results["coordinates_count"] = len(coords)

        return results
