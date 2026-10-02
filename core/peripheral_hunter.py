"""
Automotion Forensics - Peripheral Capture & Hardware Hunter
Techniques from ctf-forensics (peripheral-capture.md & signals-and-hardware.md):
- USB HID Mouse/Pen Drawing Recovery (EHAX 2026): Extracts relative movement deltas (dx, dy),
  accumulates coordinates, and exports SVG drawing file.
- USB Keyboard LED Morse Code Exfiltration (BITSCTF 2017): Reconstructs Morse code from
  host-to-device Caps Lock / Num Lock LED state change intervals.
- USB HID Arrow Key Navigation & Multi-line tracking (HackIT 2017).
"""

import math
import os
import struct
from typing import Any, Dict, List, Optional, Tuple

from core.string_hunter import StringHunter


class PeripheralHunter:
    """Decodes peripheral packet streams (mouse drawing, LED morse, arrow tracking)."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or "extracted_artifacts"
        os.makedirs(self.output_dir, exist_ok=True)
        self.string_hunter = StringHunter()

    def decode_mouse_pen_drawing(self, raw_capdata_list: List[bytes], filename_prefix: str = "usb_drawing") -> Dict[str, Any]:
        """
        Recover drawings from USB HID Mouse/Pen 7-byte reports:
        Byte 0: Button state (0x01/0x02 = draw / pressed)
        Byte 1: Mode/pad
        Bytes 2-3: dx (int16 LE)
        Bytes 4-5: dy (int16 LE)
        Byte 6: Wheel
        """
        results: Dict[str, Any] = {
            "is_mouse_drawing": False,
            "total_points": 0,
            "svg_path": None,
            "flags_found": []
        }

        points: List[Tuple[int, int, int, int]] = []
        x, y = 0, 0
        min_x, max_x = 0, 0
        min_y, max_y = 0, 0

        for raw in raw_capdata_list:
            if len(raw) >= 7:
                btn = raw[0]
                mode = raw[1]
                try:
                    dx, dy = struct.unpack("<hh", raw[2:6])
                    # Filter out giant spikes (e.g. initialization)
                    if abs(dx) < 1000 and abs(dy) < 1000:
                        x += dx
                        y += dy
                        points.append((x, y, btn, mode))
                        min_x = min(min_x, x)
                        max_x = max(max_x, x)
                        min_y = min(min_y, y)
                        max_y = max(max_y, y)
                except Exception:
                    pass

        if len(points) >= 10 and (max_x - min_x > 20 or max_y - min_y > 20):
            results["is_mouse_drawing"] = True
            results["total_points"] = len(points)

            # Generate SVG visualization
            width = max(100, max_x - min_x + 60)
            height = max(100, max_y - min_y + 60)
            offset_x = -min_x + 30
            offset_y = -min_y + 30

            svg_lines = [
                f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" style="background-color: white;">',
                f'<path d="'
            ]

            path_cmds = []
            is_down = False

            for px, py, btn, mode in points:
                sx = px + offset_x
                sy = py + offset_y
                # Button 1 or 2 typically indicates pen down
                pen_down = (btn in (1, 2)) or (mode in (1, 2)) or (btn == 0 and mode == 0 and len(points) < 500)
                if pen_down:
                    if not is_down:
                        path_cmds.append(f"M {sx} {sy}")
                        is_down = True
                    else:
                        path_cmds.append(f"L {sx} {sy}")
                else:
                    is_down = False

            if path_cmds:
                svg_lines.append(" ".join(path_cmds))
                svg_lines.append('" fill="none" stroke="black" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
                svg_lines.append('</svg>')

                svg_file = os.path.join(self.output_dir, f"{filename_prefix}.svg")
                try:
                    with open(svg_file, "w", encoding="utf-8") as sf:
                        sf.write("\n".join(svg_lines))
                    results["svg_path"] = svg_file
                except Exception:
                    pass

        return results

    def decode_led_morse(self, led_transitions: List[Tuple[float, int]]) -> Dict[str, Any]:
        """
        Reconstruct Morse code from keyboard LED transitions (host-to-device):
        led_transitions: list of (timestamp, led_state) where state is 1 (off) or 3 (on).
        Duration > 0.3s indicates dash (-), <= 0.3s indicates dot (.).
        """
        results: Dict[str, Any] = {
            "is_led_morse": False,
            "morse_string": "",
            "decoded_text": "",
            "flags_found": []
        }

        if len(led_transitions) < 4:
            return results

        MORSE_CODE_DICT = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '-..-.': '/',
            '-....-': '-', '-.--.': '(', '-.--.-': ')', '---...': ':', '-.-.-.': ';',
            '-...-': '=', '.-.-.': '+', '...-..-': '$', '.--.-.': '@'
        }

        morse_symbols = []
        for i in range(0, len(led_transitions) - 1, 2):
            t_on, state_on = led_transitions[i]
            t_off, state_off = led_transitions[i + 1]
            duration = t_off - t_on
            if duration > 0.25:
                morse_symbols.append("-")
            else:
                morse_symbols.append(".")

            # Check gap to next on-transition for letter space
            if i + 2 < len(led_transitions):
                t_next_on = led_transitions[i + 2][0]
                gap = t_next_on - t_off
                if gap > 0.6:
                    morse_symbols.append(" ")

        morse_str = "".join(morse_symbols)
        if len(morse_str.strip()) >= 5:
            results["is_led_morse"] = True
            results["morse_string"] = morse_str

            # Decode letters
            words = morse_str.split("   ")
            decoded_words = []
            for w in words:
                chars = [MORSE_CODE_DICT.get(c, "") for c in w.split()]
                decoded_words.append("".join(chars))
            decoded = " ".join(decoded_words).strip()
            results["decoded_text"] = decoded

            for fl in self.string_hunter.hunt_flags(decoded):
                fl["encoding"] = f"Keyboard LED Morse ({fl['encoding']})"
                results["flags_found"].append(fl)

        return results
