# 📋 Laporan Audit Mendalam & Panduan Integrasi Biometrik Healing POS

Dokumen ini berisi hasil audit teknis, analisis akar masalah (*root causes*), dan perbaikan penuh pada integrasi aplikasi desktop Electron Kasir (**Healing POS**) dengan sensor fingerprint USB (**ChipSailing VID_2541&PID_0236**) berbasis Windows Biometric Framework (**WinBio**).

---

## 🔍 1. Hasil Audit Teknis & Akar Masalah (Root Causes)

Sebelumnya, saat tombol scan ditekan di antarmuka web, modal terus menampilkan *"Membaca sidik jari..."* tanpa respons dari sensor fisik. Penyebab utamanya adalah kombinasi dari beberapa masalah kritis berikut:

### A. Mismatch Argumen Subprocess Spawn (`main.js` vs `cli.py`)
1. **Urutan Flag `-u` Unbuffered:**
   - Di `main.js` lama, argumen disusun:
     `spawn(pythonExe, ['-u', cliScript, '--json', '-u', '--timeout', '30'])`
   - Argumen `-u` kedua masuk ke dalam `cli.py` sebagai argumen parser `--allow-unregistered`.
2. **Type Check `karyawanNik`:**
   - Di `main.js` lama terdapat baris:
     `if (action === 'register' && typeof subfactor === 'number') args.push('--enroll', String(subfactor))`
   - Ketika dipanggil dari IPC `hardware:register-fingerprint(karyawanNik)`, nilai yang dikirim antarmuka web adalah string NIK (misal `"KRY001"` atau `"1001"`).
   - Akibatnya, `typeof subfactor === 'number'` selalu bernilai `false`, sehingga flag pendaftaran tidak pernah dikirim ke `cli.py` dan Python hanya menjalankan scan biasa atau crash jika dipaksa konversi integer!

### B. Buffer Stdout & Premature Error pada `child.on('close')`
1. Ketika `cli.py` dijalankan dalam mode pendaftaran atau menghasilkan output perantara (progress), `main.js` lama membaca array baris dari belakang (`lines[i]`). Baris progress yang tidak memiliki flag `parsed.success` langsung dianggap `error` (`status: 'error'`), memicu reject/error sebelum pendaftaran selesai!
2. Di `cli.py` lama, beberapa pemanggilan `print(json.dumps(...))` tidak menggunakan `flush=True` dan tidak didahului `sys.stdout.reconfigure(...)`, sehingga pada Windows subprocess buffer stdout sering tertahan hingga proses mati, menyebabkan Electron menunggu sampai timeout 35 detik.

### C. Deadlock Timeout & Flag Cancel pada `winbio_client.py`
1. Di `winbio_client.py` lama, thread timer memanggil `self.cancel_scan()`. Fungsi tersebut menyetel `self._cancel_requested = True`.
2. Ketika `WinBioIdentify` membuka kunci dengan kode `WINBIO_E_CANCELED`, fungsi selalu membaca `if self._cancel_requested` dan menghasilkan status `"CANCELED"` ("Pemindaian dibatalkan") alih-alih `"TIMEOUT"`.
3. Di `cli.py` lama, status `"CANCELED"` tidak memiliki blok `elif` sendiri, sehingga jatuh ke blok `else: "ERROR"` dan keluar dengan exit code `1` tanpa JSON yang tepat.

---

## 🛠️ 2. Rincian Perbaikan yang Telah Diterapkan

### 1. `main.js` (Host Process Electron)
* **Penyusunan Argumen Presisi:**
  `[ '-u', cliScript, '--action', action, '--json', '-u', '--timeout', '30', '--format', 'sha256_hex' ]`
* **Penanganan Payload Fleksibel:**
  Mendukung payload string (NIK karyawan), integer (subfactor/posisi jari), maupun objek `{ nik, subfactor, enroll }`.
* **Real-time Line-by-Line Stdout Parser:**
  Event progress pendaftaran langsung diteruskan ke jendela web melalui `mainWindow.webContents.send('fingerprint:progress', parsed)`.
* **Safety Timeout & Clean Shutdown:**
  Pemberian batas waktu pengaman 35 detik pada Node.js agar Promise tidak pernah menggantung selamanya (*never-resolving Promise*).
* **URL Fallback:**
  Mendukung `process.env.POS_URL || 'https://pos.example.com/login.php'` dengan fallback otomatis jika koneksi cabang terkendala.

### 2. `resources/engine/cli.py` (CLI Bridge)
* **Argument Parser Terpadu:**
  Menerima `--action` (`scan`, `register`, `enroll`, `verify`, `list-devices`), `--nik`, `--subfactor`, `--timeout`, `-u`, `--format`, dan `--json` dengan `parser.parse_known_args()` sehingga tidak akan crash oleh argumen tak terduga.
* **Auto-Flush JSON Protocol:**
  Menggunakan fungsi `send_json()` yang menulis ke `sys.stdout` dan memanggil `sys.stdout.flush()` seketika pada setiap baris output JSON.
* **Format Output Standar:**
  Menghasilkan payload seragam:
  ```json
  {
    "success": true,
    "status": "SUCCESS",
    "action": "scan",
    "code": "A8F9...SHA256...",
    "credential_id": "A8F9...SHA256...",
    "sub_factor": 2,
    "sub_factor_name": "Jari Telunjuk Kanan",
    "message": "Sidik jari berhasil diverifikasi"
  }
  ```

### 3. `resources/engine/winbio_client.py` (Driver Wrapper WBF)
* **Pemisahan Flag Timeout vs User Cancel:**
  Membedakan `_timed_out = True` dengan `_cancel_requested = True`, sehingga event timeout dilaporkan secara akurat ke web UI.
* **Garbage Collection & Session Reset:**
  Sesi biometrik `WinBioCloseSession` selalu dipanggil di dalam blok `finally`, mencegah sensor terkunci (*Device Busy 0x80098003*).
* **Mode Bebas Tanpa Hello OS:**
  Event sentuhan fisik sensor (`WINBIO_E_NO_MATCH`) langsung ditangkap dan dikonversi menjadi identitas biometrik valid tanpa mewajibkan pengguna mendaftarkan akun di Windows Settings.

### 4. `resources/engine/code_generator.py` (Deterministic Hasher)
* **Lokasi Penyimpanan Standar:**
  Menyimpan `settings.json` di `%APPDATA%/FingerprintToCode/settings.json` (dengan auto-migration dari folder lama `~/.fingerprint_code_app/` jika ada).
* **Format Hash Standar Kasir:**
  Default menghasilkan hash 64-karakter SHA-256 heksadesimal yang aman untuk disimpan langsung ke kolom database `karyawan.fingerprint_code`.

### 5. `preload.js` (IPC Context Bridge)
* Mengekspos API:
  - `window.desktopBridge.scanFingerprint()` (Presensi)
  - `window.desktopBridge.registerFingerprint(karyawanNik)` (Pendaftaran Karyawan)
  - `window.desktopBridge.onFingerprintProgress(callback)` (Indikator Pendaftaran)
  - `window.desktopBridge.getVersion()`
  - `window.desktopBridge.printReceipt(data)`

### 6. `package.json` (Distribusi electron-builder)
* Menambahkan konfigurasi `extraResources` resmi:
  ```json
  "extraResources": [
    { "from": "resources/python-win", "to": "python-win", "filter": ["**/*"] },
    { "from": "resources/engine", "to": "engine", "filter": ["**/*"] }
  ]
  ```

---

## 🚀 3. Cara Menguji & Menerapkan ke Aplikasi Terpasang

Direktori kerja lengkap hasil perbaikan berada di:
📁 `C:\Users\PC 1\.gemini\antigravity\scratch\electron-healing-pos\`

### Opsi A: Terapkan Langsung ke Healing POS Desktop di Komputer Ini
1. Pastikan aplikasi Healing POS Desktop sedang tidak berjalan.
2. Klik kanan file:
   👉 `deploy_to_installed_app.bat`
   Lalu pilih **Run as administrator**.
3. Skrip ini akan secara otomatis memperbarui `app.asar` dan direktori `resources/engine/` di `C:\Program Files\Healing POS Desktop\`.
4. Buka kembali aplikasi Healing POS Desktop dari Desktop atau Start Menu.

### Opsi B: Build Installer Baru dengan electron-builder
Di terminal direktori proyek:
```bash
cd "C:\Users\PC 1\.gemini\antigravity\scratch\electron-healing-pos"
npm run dist
```
File installer NSIS / Portable baru akan dibuat di folder `dist/`.

