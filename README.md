# Forensic CTF Solver

Script otomatis untuk analisa soal forensik CTF.

## Cara Pakai

```bash
# Analisa otomatis (otomatis deteksi jenis soal dan ekstrak file jika ada)
foren <file_soal>

# Tentukan folder output untuk file hasil ekstraksi (gambar/dokumen/dump)
foren <file_soal> -o ./output

# Scan mendalam tanpa berhenti di flag pertama
foren <file_soal> --no-stop
```

### Opsi CLI
- `<target>`: Path file target yang dianalisa.
- `-o, --output`: Folder output penyimpanan artefak hasil ekstraksi (dibuat otomatis jika belum ada).
- `--no-stop`: Menjalankan seluruh tahapan scan tanpa berhenti di temuan flag pertama.
- `--delime`: Ekstrak / konversi format LiME `.lime` ke flat physical memory `.raw`.

## Setup (Linux / WSL)

```bash
# Install dependencies
pip install -r requirements.txt

# Shortcut command
chmod +x foren.py
sudo ln -sf $(pwd)/foren.py /usr/local/bin/foren
```
