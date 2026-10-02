"""
Automotion Forensics - Configuration & Signatures
Tailored for HackToday Final (IPB IT Today 2025/2026) and national CTF competitions.
"""

import re

# Target Flag Patterns (Regex)
FLAG_PATTERNS = [
    re.compile(r"HackToday26\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"HackToday25\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"HackToday24\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"HackToday\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"hacktoday\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"sunctf25\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"sunctf\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"SunwayCTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"SWCTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"GCTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"GICTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"GIRLS\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"EQCTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"L3AK\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"bluelobster\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"picoCTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"PicoCTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"COMPFEST\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"CJ\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"flag\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"FLAG\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"CTF\{[ -~]{3,120}\}", re.IGNORECASE),
    re.compile(r"ITToday\{[ -~]{3,120}\}", re.IGNORECASE),
]

# Prefixes for partial/fragment search
FLAG_PREFIXES = [
    b"HackToday26{",
    b"HackToday25{",
    b"HackToday24{",
    b"HackToday{",
    b"hacktoday{",
    b"sunctf25{",
    b"sunctf{",
    b"SunwayCTF{",
    b"SWCTF{",
    b"GCTF{",
    b"GICTF{",
    b"GIRLS{",
    b"EQCTF{",
    b"L3AK{",
    b"bluelobster{",
    b"picoCTF{",
    b"PicoCTF{",
    b"COMPFEST{",
    b"CJ{",
    b"flag{",
    b"FLAG{",
    b"CTF{",
    b"ITToday{",
]

# Suspicious Strings to Hunt for CTF Forensics
SUSPICIOUS_REGEX = [
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "Private Key"),
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\$@!#%^&*+=]{4,64})['\"]?", re.IGNORECASE), "Plaintext Password"),
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "Long Base64 Token"),
    (re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"), "IPv4 Address"),
    (re.compile(r"https?://[^\s\"'<>]+"), "HTTP/HTTPS URL"),
    (re.compile(r"[a-z2-7]{16,56}\.onion\b", re.IGNORECASE), "Tor Onion Address"),
    (re.compile(r"(?:sudo|curl|wget|nc|ncat|bash|sh|python|perl|ruby)\s+-[A-Za-z0-9]?", re.IGNORECASE), "Command Execution Trace"),
    (re.compile(r"powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)", re.IGNORECASE), "PowerShell EncodedCommand"),
]

# 70+ File Magic Signatures (Header Bytes & Name)
MAGIC_SIGNATURES = [
    # Images
    {"name": "PNG Image", "ext": "png", "magic": b"\x89PNG\r\n\x1a\n", "trailer": b"IEND\xaeB`\x82"},
    {"name": "JPEG Image", "ext": "jpg", "magic": b"\xff\xd8\xff", "trailer": b"\xff\xd9"},
    {"name": "GIF87a Image", "ext": "gif", "magic": b"GIF87a", "trailer": b"\x00\x3b"},
    {"name": "GIF89a Image", "ext": "gif", "magic": b"GIF89a", "trailer": b"\x00\x3b"},
    {"name": "BMP Image", "ext": "bmp", "magic": b"BM", "trailer": None},
    {"name": "TIFF (LE)", "ext": "tiff", "magic": b"II*\x00", "trailer": None},
    {"name": "TIFF (BE)", "ext": "tiff", "magic": b"MM\x00*", "trailer": None},
    {"name": "WEBP Image", "ext": "webp", "magic": b"RIFF....WEBP", "trailer": None},

    # Archives & Compressed
    {"name": "ZIP Archive / OpenXML", "ext": "zip", "magic": b"PK\x03\x04", "trailer": b"PK\x05\x06"},
    {"name": "ZIP Empty / Spanned", "ext": "zip", "magic": b"PK\x05\x06", "trailer": None},
    {"name": "7-Zip Archive", "ext": "7z", "magic": b"7z\xbc\xaf\x27\x1c", "trailer": None},
    {"name": "RAR Archive v4", "ext": "rar", "magic": b"Rar!\x1a\x07\x00", "trailer": None},
    {"name": "RAR Archive v5", "ext": "rar", "magic": b"Rar!\x1a\x07\x01\x00", "trailer": None},
    {"name": "GZIP Archive", "ext": "gz", "magic": b"\x1f\x8b\x08", "trailer": None},
    {"name": "BZIP2 Archive", "ext": "bz2", "magic": b"BZh", "trailer": None},
    {"name": "XZ Archive", "ext": "xz", "magic": b"\xfd7zXZ\x00", "trailer": None},
    {"name": "TAR Archive", "ext": "tar", "offset": 257, "magic": b"ustar", "trailer": None},

    # Network / PCAP
    {"name": "PCAP (Little Endian)", "ext": "pcap", "magic": b"\xd4\xc3\xb2\xa1", "trailer": None},
    {"name": "PCAP (Big Endian)", "ext": "pcap", "magic": b"\xa1\xb2\xc3\xd4", "trailer": None},
    {"name": "PCAP (Nanosecond LE)", "ext": "pcap", "magic": b"\x4d\x3c\xb2\xa1", "trailer": None},
    {"name": "PCAP (Nanosecond BE)", "ext": "pcap", "magic": b"\xa1\xb2\x3c\x4d", "trailer": None},
    {"name": "PCAPNG", "ext": "pcapng", "magic": b"\n\r\r\n", "trailer": None},

    # Memory / Disk
    {"name": "LiME Memory Dump", "ext": "lime", "magic": b"EMiL", "trailer": None},
    {"name": "AccessData FTK AD1 Image", "ext": "ad1", "magic": b"ADSEGMENTEDFILE", "trailer": None},
    {"name": "Expert Witness Format (E01)", "ext": "e01", "magic": b"EVF\t\r\n\xff\x00", "trailer": None},
    {"name": "VirtualBox VDI", "ext": "vdi", "magic": b"<<< Oracle VM VirtualBox Disk Image >>>", "trailer": None},
    {"name": "VMware VMDK", "ext": "vmdk", "magic": b"KDMV", "trailer": None},

    # Executables & Binaries
    {"name": "ELF Executable", "ext": "elf", "magic": b"\x7fELF", "trailer": None},
    {"name": "Windows PE Executable", "ext": "exe", "magic": b"MZ", "trailer": None},
    {"name": "Mach-O 32-bit (LE)", "ext": "macho", "magic": b"\xce\xfa\xed\xfe", "trailer": None},
    {"name": "Mach-O 64-bit (LE)", "ext": "macho", "magic": b"\xcf\xfa\xed\xfe", "trailer": None},
    {"name": "Java Class File", "ext": "class", "magic": b"\xca\xfe\xba\xbe", "trailer": None},
    {"name": "WebAssembly (WASM)", "ext": "wasm", "magic": b"\x00asm", "trailer": None},

    # Documents & Media
    {"name": "PDF Document", "ext": "pdf", "magic": b"%PDF-", "trailer": b"%%EOF"},
    {"name": "SQLite Database v3", "ext": "sqlite", "magic": b"SQLite format 3\x00", "trailer": None},
    {"name": "WAV Audio", "ext": "wav", "magic": b"RIFF....WAVE", "trailer": None},
    {"name": "MP3 Audio", "ext": "mp3", "magic": b"ID3", "trailer": None},
    {"name": "FLAC Audio", "ext": "flac", "magic": b"fLaC", "trailer": None},
    {"name": "Windows Event Log (EVTX)", "ext": "evtx", "magic": b"ElfFile\x00", "trailer": None},
    {"name": "Registry Hive (REGF)", "ext": "dat", "magic": b"regf", "trailer": None},
]

# USB HID Keycode to ASCII mapping (Standard USB HID Keyboard scan codes)
USB_HID_KEYMAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e',
    0x09: 'f', 0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j',
    0x0e: 'k', 0x0f: 'l', 0x10: 'm', 0x11: 'n', 0x12: 'o',
    0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
    0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x', 0x1c: 'y',
    0x1d: 'z', 0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4',
    0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9',
    0x27: '0', 0x28: '\n', 0x2a: '\b', 0x2c: ' ', 0x2d: '-',
    0x2e: '=', 0x2f: '[', 0x30: ']', 0x31: '\\', 0x33: ';',
    0x34: "'", 0x35: '`', 0x36: ',', 0x37: '.', 0x38: '/',
}

USB_HID_SHIFT_KEYMAP = {
    'a': 'A', 'b': 'B', 'c': 'C', 'd': 'D', 'e': 'E',
    'f': 'F', 'g': 'G', 'h': 'H', 'i': 'I', 'j': 'J',
    'k': 'K', 'l': 'L', 'm': 'M', 'n': 'N', 'o': 'O',
    'p': 'P', 'q': 'Q', 'r': 'R', 's': 'S', 't': 'T',
    'u': 'U', 'v': 'V', 'w': 'W', 'x': 'X', 'y': 'Y',
    'z': 'Z', '1': '!', '2': '@', '3': '#', '4': '$',
    '5': '%', '6': '^', '7': '&', '8': '*', '9': '(',
    '0': ')', '-': '_', '=': '+', '[': '{', ']': '}',
    '\\': '|', ';': ':', "'": '"', '`': '~', ',': '<',
    '.': '>', '/': '?',
}

# Buffer chunking configuration (16MB per chunk with 64KB overlap)
CHUNK_SIZE = 16 * 1024 * 1024
CHUNK_OVERLAP = 64 * 1024
MAX_CARVE_FILE_SIZE = 50 * 1024 * 1024  # 50MB max carved file to prevent disk fill
