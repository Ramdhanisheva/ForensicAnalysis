"""
CTF Challenge Generator for Forensics Automation Testing
Generates 'chall_final_hacktoday.png' featuring:
1. Valid PNG container
2. Obfuscated Base64 passphrase inside PNG metadata chunk
3. Trailing password-protected ZIP container appended after PNG EOF
4. Flag hidden inside the encrypted container
"""

import base64
import struct
import zlib
import os

def make_chunk(chunk_type: bytes, chunk_data: bytes) -> bytes:
    length = len(chunk_data)
    crc = zlib.crc32(chunk_type + chunk_data) & 0xffffffff
    return struct.pack('>I', length) + chunk_type + chunk_data + struct.pack('>I', crc)

def make_encrypted_zip(files_dict: dict, password: str) -> bytes:
    pw_bytes = password.encode('utf-8')
    
    # ZipCrypto implementation
    def get_cryptor():
        k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
        def update(b):
            nonlocal k0, k1, k2
            k0 = (zlib.crc32(bytes([b]), k0 ^ 0xffffffff) ^ 0xffffffff) & 0xffffffff
            k1 = ((k1 + (k0 & 0xff)) * 134775813 + 1) & 0xffffffff
            k2 = (zlib.crc32(bytes([(k1 >> 24) & 0xff]), k2 ^ 0xffffffff) ^ 0xffffffff) & 0xffffffff
        for b in pw_bytes:
            update(b)
        def encrypt(data_bytes):
            out = bytearray()
            for b in data_bytes:
                temp = (k2 | 2) & 0xffff
                k = ((temp * (temp ^ 1)) >> 8) & 0xff
                update(b)
                out.append(b ^ k)
            return bytes(out)
        return encrypt

    lfh_records = bytearray()
    cd_records = bytearray()
    
    for fname, fdata in files_dict.items():
        encrypt = get_cryptor()
        crc = zlib.crc32(fdata) & 0xffffffff
        enc_header = b'\x55' * 11 + bytes([(crc >> 24) & 0xff])
        enc_payload = encrypt(enc_header + fdata)
        
        fn_bytes = fname.encode('utf-8')
        lfh_offset = len(lfh_records)
        
        # Local File Header
        lfh = (
            b'PK\x03\x04' +
            struct.pack('<HHHHHIIIHH',
                20, 1, 0, 0, 0, crc,
                len(enc_payload), len(fdata),
                len(fn_bytes), 0
            ) +
            fn_bytes + enc_payload
        )
        lfh_records.extend(lfh)
        
        # Central Directory Header
        cd = (
            b'PK\x01\x02' +
            struct.pack('<HHHHHHIIIHHHHHII',
                20, 20, 1, 0, 0, 0, crc,
                len(enc_payload), len(fdata),
                len(fn_bytes), 0, 0, 0, 0, 0,
                lfh_offset
            ) +
            fn_bytes
        )
        cd_records.extend(cd)

    eocd = (
        b'PK\x05\x06' +
        struct.pack('<HHHHIIH',
            0, 0, len(files_dict), len(files_dict),
            len(cd_records), len(lfh_records), 0
        )
    )
    return bytes(lfh_records + cd_records + eocd)

def create_challenge(output_path: str = "chall_final_hacktoday.png"):
    passphrase = "h4ck70day_f1n4l_s3cr3t_p4ss2026"
    flag = "HackToday26{ch41n3d_m3t4d4t4_k3y_c4rv1ng_pwn3d_2026}"
    
    # 1. Construct PNG
    sig = b'\x89PNG\r\n\x1a\n'
    w, h = 64, 64
    ihdr_data = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)
    
    # Metadata comment with Base64 obfuscated password
    raw_comment = f"Security backup archive note: password: {passphrase}"
    b64_comment = base64.b64encode(raw_comment.encode('utf-8')).decode('utf-8')
    text_data = b'Comment\x00' + b64_comment.encode('utf-8')
    text_chunk = make_chunk(b'tEXt', text_data)
    
    # Red gradient pixels
    raw_pixels = bytearray()
    for y in range(h):
        raw_pixels.append(0)  # filter type 0
        for x in range(w):
            raw_pixels.extend([x * 4 % 256, y * 4 % 256, 128, 255])
    idat = make_chunk(b'IDAT', zlib.compress(bytes(raw_pixels)))
    iend = make_chunk(b'IEND', b'')
    
    png_bytes = sig + ihdr + text_chunk + idat + iend
    
    # 2. Construct encrypted ZIP archive payload
    zip_files = {
        "incident_log.txt": (
            b"[+] INCIDENT INVESTIGATION REPORT\n"
            b"[*] Target: Compromised server exfiltration\n"
            b"[*] Status: Suspicious encrypted blob identified.\n"
        ),
        "evidence_flag.txt": f"Congratulations! Flag: {flag}\n".encode('utf-8')
    }
    zip_bytes = make_encrypted_zip(zip_files, passphrase)
    
    # 3. Combine: PNG + Appended Trailing ZIP (EOF Overlay)
    full_challenge = png_bytes + zip_bytes
    
    with open(output_path, "wb") as f:
        f.write(full_challenge)
        
    print(f"[+] Challenge created successfully: {output_path}")
    print(f"    - Total size: {len(full_challenge):,} bytes (PNG: {len(png_bytes)}, ZIP: {len(zip_bytes)})")
    print(f"    - Passphrase: {passphrase}")
    print(f"    - Flag:       {flag}")

if __name__ == "__main__":
    create_challenge()
