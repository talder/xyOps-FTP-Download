<p align="center"><img src="https://raw.githubusercontent.com/talder/xyOps-FTP-Download/refs/heads/main/logo.png" height="108" alt="xyOps FTP Download Logo"/></p>
<h1 align="center">xyOps FTP Download</h1>

# xyOps FTP Download Event Plugin

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/xyOps-tools/xyOps-FTP-Download/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-7.0+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)]()

Download files from remote servers via **FTP**, **FTPS** (Explicit & Implicit TLS), or **SFTP** (SSH). This is an **event plugin** — use it as a step in an xyOps workflow to download files from remote servers for processing, archiving, or integration with other workflow steps.

**Key Features:**
- 3 protocols: FTP, FTPS (Explicit/Implicit), SFTP
- 3 download modes: single file, folder (recursive), pattern match (glob)
- 2 destination options: CWD or custom local path
- 4 if-exists behaviors: overwrite, skip, error, rename (timestamp)
- Optional delete after download
- 6 secrets in the xyOps Secret Vault (all overridable via parameters)
- Auto-install of Posh-SSH module on first SFTP use
- Downloaded files automatically declared for downstream workflow steps
- Comprehensive error handling with categorised diagnostics
- Structured output data for downstream job chaining

## Disclaimer

**USE AT YOUR OWN RISK.** This software is provided "as is", without warranty of any kind, express or implied. The author and contributors are not responsible for any damages, data loss, or other issues that may arise from the use of this software. Always test in non-production environments first.

---

## Table of Contents

- [xyOps FTP Download Event Plugin](#xyops-ftp-download-event-plugin)
  - [Disclaimer](#disclaimer)
  - [Table of Contents](#table-of-contents)
  - [Quick Start](#quick-start)
  - [Installation](#installation)
    - [From xyOps Marketplace](#from-xyops-marketplace)
    - [Manual Installation](#manual-installation)
  - [Secrets Configuration](#secrets-configuration)
  - [Protocols](#protocols)
    - [FTP — Plain File Transfer](#ftp--plain-file-transfer)
    - [FTPS — FTP over TLS/SSL](#ftps--ftp-over-tlsssl)
      - [Explicit FTPS (Recommended)](#explicit-ftps-recommended)
      - [Implicit FTPS (Legacy)](#implicit-ftps-legacy)
    - [SFTP — SSH File Transfer](#sftp--ssh-file-transfer)
  - [Parameters Reference](#parameters-reference)
  - [Download Modes](#download-modes)
    - [Single File](#single-file)
    - [Folder (Recursive)](#folder-recursive)
    - [Pattern Match](#pattern-match)
  - [File Exists Behaviour](#file-exists-behaviour)
  - [Delete After Download](#delete-after-download)
  - [Examples \& Use Cases](#examples--use-cases)
    - [Example 1 — Download a Single File via SFTP](#example-1--download-a-single-file-via-sftp)
    - [Example 2 — Download All Logs via FTP](#example-2--download-all-logs-via-ftp)
    - [Example 3 — Download and Archive Backups via FTPS](#example-3--download-and-archive-backups-via-ftps)
    - [Example 4 — Download Reports for Processing](#example-4--download-reports-for-processing)
    - [Example 5 — Download with SSH Key Auth](#example-5--download-with-ssh-key-auth)
    - [Example 6 — FTPS Implicit (Legacy Server)](#example-6--ftps-implicit-legacy-server)
  - [Error Handling](#error-handling)
    - [Error Categories](#error-categories)
  - [Output Data Reference](#output-data-reference)
  - [Downstream Chaining](#downstream-chaining)
  - [Dependencies](#dependencies)
  - [Testing Locally](#testing-locally)
  - [License](#license)
  - [Author](#author)
  - [Version History](#version-history)
    - [v1.0.0 (2026-02-21)](#v100-2026-02-21)

---

## Quick Start

1. Install the plugin in xyOps (copy to plugins directory or install from Marketplace)
2. Configure secrets in the Secret Vault (see [Secrets Configuration](#secrets-configuration))
3. Create a workflow and add **FTP Download** as an event plugin step
4. Select protocol, set remote path, choose download mode
5. Run the workflow — downloaded files are automatically available to downstream steps

---

## Installation

### From xyOps Marketplace

1. Navigate to xyOps Marketplace
2. Search for "FTP Download"
3. Click Install

### Manual Installation

```bash
cd /opt/xyops/plugins
git clone https://github.com/xyOps-tools/xyOps-FTP-Download.git
```

---

## Secrets Configuration

Configure the following secrets in the **xyOps Secret Vault**. All secrets are optional — parameters always override secrets when provided.

| Secret Name | Description | Used By |
|-------------|-------------|---------|
| `FTP_HOST` | Server hostname or IP address | All protocols |
| `FTP_PORT` | Server port number | All protocols |
| `FTP_USERNAME` | Login username | All protocols |
| `FTP_PASSWORD` | Login password | All protocols |
| `FTP_SSH_KEY_PATH` | Path to SSH private key file | SFTP only |
| `FTP_SSH_KEY_PASSPHRASE` | Passphrase for encrypted SSH key | SFTP only |

**Priority:** Parameter value → Secret vault → Error if required

**Example:** If you set `FTP_HOST = ftp.company.com` in the vault and leave the Host parameter empty, the plugin uses `ftp.company.com`. If you then enter `ftp2.company.com` in the Host parameter, the parameter wins.

---

## Protocols

### FTP — Plain File Transfer

| Property | Value |
|----------|-------|
| Default Port | 21 |
| Encryption | None (plain text) |
| Backend | .NET `System.Net.FtpWebRequest` |
| Auth | Username + Password |

Standard FTP with no encryption. Use only on trusted networks or for non-sensitive data.

**When to use:**
- Internal transfers on isolated networks
- Legacy systems that don't support TLS
- Testing and development

### FTPS — FTP over TLS/SSL

FTPS adds TLS encryption to the FTP protocol. Two modes are available:

#### Explicit FTPS (Recommended)

| Property | Value |
|----------|-------|
| Default Port | 21 |
| Encryption | STARTTLS upgrade on port 21 |
| Backend | .NET `System.Net.FtpWebRequest` with `EnableSsl` |
| Auth | Username + Password |

The client connects on port 21 (plain text), then sends `AUTH TLS` to upgrade the connection to TLS. This is the modern, recommended approach.

**When to use:**
- Most modern FTP servers with TLS support
- Servers that support both plain FTP and FTPS on port 21
- When the server administrator has enabled STARTTLS

#### Implicit FTPS (Legacy)

| Property | Value |
|----------|-------|
| Default Port | 990 |
| Encryption | Direct TLS on connect |
| Backend | Custom `TcpClient` + `SslStream` implementation |
| Auth | Username + Password |

The client connects directly with TLS — no plain text phase. This is a legacy approach (RFC 4217 deprecated it), but some older servers require it.

**When to use:**
- Older servers that only support Implicit FTPS on port 990
- Banking/financial systems with legacy FTPS infrastructure
- When Explicit FTPS fails and the server admin confirms Implicit mode

### SFTP — SSH File Transfer

| Property | Value |
|----------|-------|
| Default Port | 22 |
| Encryption | SSH tunnel (full session encryption) |
| Backend | [Posh-SSH](https://github.com/darkoperator/Posh-SSH) module (auto-installed) |
| Auth | Password or SSH key (RSA, ED25519, ECDSA, DSA) |

SFTP runs over SSH — it is **not** related to FTP/FTPS. It provides strong encryption and is the most secure option.

**When to use:**
- Any server with SSH access (Linux/Unix servers)
- Secure file transfers from cloud infrastructure
- When SSH key authentication is required
- Partner/vendor file exchanges

**Supported key types:** RSA, ED25519, ECDSA, DSA

**Auto-install:** If the Posh-SSH module is not installed, the plugin automatically installs it on first SFTP use (`Install-Module -Name Posh-SSH -Scope CurrentUser`). No manual setup required.

---

## Parameters Reference

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| **Protocol** | Select | FTP | No | `FTP`, `FTPS`, or `SFTP` |
| **Host** | Text | — | Yes* | Server hostname or IP. Overrides `FTP_HOST` secret. |
| **Port** | Text | Auto | No | Server port. Auto-detects: 21 (FTP/FTPS Explicit), 990 (FTPS Implicit), 22 (SFTP). Overrides `FTP_PORT` secret. |
| **Username** | Text | — | Yes* | Login username. Overrides `FTP_USERNAME` secret. |
| **Password** | Text | — | Cond. | Login password. Required for FTP/FTPS and SFTP password auth. Overrides `FTP_PASSWORD` secret. |
| **FTPS Mode** | Select | Explicit | No | `Explicit` (STARTTLS, port 21) or `Implicit` (direct TLS, port 990). Only for FTPS. |
| **SSH Key Path** | Text | — | No | Path to SSH private key file. SFTP only. Overrides `FTP_SSH_KEY_PATH` secret. |
| **SSH Key Passphrase** | Text | — | No | Passphrase for encrypted SSH key. SFTP only. Overrides `FTP_SSH_KEY_PASSPHRASE` secret. |
| **Remote Path** | Text | — | Yes | File or folder path to download from remote server. Supports glob patterns (e.g., `/logs/*.log`). |
| **Local Path** | Text | — | No | Local directory to save files. Leave empty to save in plugin working directory (CWD). |
| **Download Mode** | Select | Single file | No | `Single file`, `Folder (recursive)`, or `Pattern match`. |
| **If File Exists** | Select | Overwrite | No | `Overwrite`, `Skip`, `Error`, or `Rename` (with timestamp). |
| **Delete After Download** | Checkbox | ✗ | No | Delete files from remote server after successful download. |
| **Create Local Dirs** | Checkbox | ✓ | No | Auto-create local directories if they don't exist. |
| **Passive Mode** | Checkbox | ✓ | No | Use passive mode for FTP/FTPS. Recommended for firewalls/NAT. |

\* Required via parameter or secret vault.

---

## Download Modes

### Single File

Download a single file from the remote server.

**Remote Path:** `/reports/daily-report.csv`

**Result:** Downloads `daily-report.csv` to the local directory.

---

### Folder (Recursive)

Download an entire folder and all its subfolders from the remote server.

**Remote Path:** `/backups/2026-02`

**Result:** All files in `/backups/2026-02/` and its subdirectories are downloaded, preserving the directory structure locally.

**Example structure:**
```
Remote:                                  Local (CWD):
/backups/2026-02/                        ./
├── db-backup.sql.gz    ──────────►      ├── db-backup.sql.gz
├── configs/                             ├── configs/
│   └── app.conf        ──────────►      │   └── app.conf
└── logs/                                └── logs/
    └── error.log       ──────────►          └── error.log
```

---

### Pattern Match

Download files matching a glob pattern.

**Remote Path:** `/logs/*.log`

**Result:** All `.log` files in `/logs/` are downloaded (not recursive — only the specified directory).

**Supported patterns:**
- `*.csv` — all CSV files
- `report_*.pdf` — all files starting with `report_`
- `backup_202602??.tar.gz` — all February 2026 daily backups

---

## File Exists Behaviour

| Option | Behaviour |
|--------|-----------|
| **Overwrite** (default) | Replace the existing local file with the downloaded file |
| **Skip** | Leave the existing file untouched, continue with next file |
| **Error** | Fail the entire job immediately if any file already exists locally |
| **Rename** | Add timestamp to filename (e.g., `report.csv` → `report_20260221_143022.csv`) |

The **Skip** option is useful for idempotent downloads — you can safely re-run a job without re-downloading existing files. The download results table shows which files were downloaded and which were skipped.

The **Rename** option is useful when you need to preserve both versions of a file.

---

## Delete After Download

When **Delete After Download** is enabled, files are deleted from the remote server after successful download. This is useful for:
- Archiving files from a production server to backup storage
- Processing files that should not remain on the remote server
- Implementing a "pull and clean" workflow

**Important:** Files are only deleted if the download succeeds. If a download fails, the remote file is not deleted.

---

## Examples & Use Cases

### Example 1 — Download a Single File via SFTP

Download a daily export file from a partner's SFTP server.

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `sftp.partner.com` |
| Username | `automation` |
| SSH Key Path | `/opt/xyops/keys/partner_ed25519` |
| Remote Path | `/exports/daily-orders.csv` |
| Download Mode | Single file |
| If File Exists | Rename |

**Result:** Downloads `daily-orders.csv` to the plugin working directory. If it already exists, renames it with a timestamp (e.g., `daily-orders_20260221_143022.csv`).

---

### Example 2 — Download All Logs via FTP

Download all log files from an FTP server for analysis.

| Parameter | Value |
|-----------|-------|
| Protocol | FTP — Plain FTP |
| Host | `ftp.logs.internal` |
| Username | `logfetch` |
| Password | `(from FTP_PASSWORD secret)` |
| Remote Path | `/var/log/*.log` |
| Download Mode | Pattern match |
| If File Exists | Skip |
| Delete After Download | ✗ |

**Result:** Downloads all `.log` files from `/var/log/`. Existing files are skipped.

**Output table:**
```
┌───┬──────────────────────┬──────────────┬──────────────┐
│ # │ File                 │ Size         │ Status       │
├───┼──────────────────────┼──────────────┼──────────────┤
│ 1 │ app.log              │ 12,450 bytes │ Downloaded   │
│ 2 │ error.log            │  8,230 bytes │ Skipped      │
│ 3 │ access.log           │ 15,780 bytes │ Downloaded   │
└───┴──────────────────────┴──────────────┴──────────────┘
2 downloaded, 1 skipped, 28,230 bytes total
```

---

### Example 3 — Download and Archive Backups via FTPS

Download backup files from a secure FTPS server and delete them after successful download.

| Parameter | Value |
|-----------|-------|
| Protocol | FTPS — FTP over TLS/SSL |
| FTPS Mode | Explicit — STARTTLS on port 21 |
| Host | `ftps.backups.company.com` |
| Username | `backup_agent` |
| Password | `(from FTP_PASSWORD secret)` |
| Remote Path | `/daily-backups/2026-02/` |
| Local Path | `/mnt/archive/backups/2026-02/` |
| Download Mode | Folder (recursive) |
| If File Exists | Error |
| Delete After Download | ✓ |

**Result:** All files in `/daily-backups/2026-02/` are downloaded recursively to `/mnt/archive/backups/2026-02/`. After successful download, files are deleted from the remote server. If any file already exists locally, the job fails (to prevent accidental overwrites).

---

### Example 4 — Download Reports for Processing

Download CSV reports from an SFTP server, process them in the next workflow step.

**Workflow:**
1. **Step 1:** xyOps FTP Download → Download CSV reports
2. **Step 2:** xyOps Data Processing → Process downloaded CSV files

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `reports.vendor.com` |
| Port | `2222` |
| Username | `integration` |
| Password | `(from FTP_PASSWORD secret)` |
| Remote Path | `/exports/reports/*.csv` |
| Download Mode | Pattern match |
| If File Exists | Overwrite |

**Result:** All CSV files from `/exports/reports/` are downloaded to the plugin working directory. The files are automatically declared as output and passed to the next workflow step for processing.

**Next step receives:**
```json
{
  "files": [
    {
      "filename": "sales_report.csv",
      "id": "...",
      "size": 45000
    },
    {
      "filename": "inventory_report.csv",
      "id": "...",
      "size": 32000
    }
  ]
}
```

---

### Example 5 — Download with SSH Key Auth

Download files using SSH key authentication (no password).

| Parameter | Value |
|-----------|-------|
| Protocol | SFTP — SSH File Transfer |
| Host | `secure.datacenter.com` |
| Username | `automation` |
| SSH Key Path | `/opt/xyops/keys/automation_rsa` |
| SSH Key Passphrase | `(from FTP_SSH_KEY_PASSPHRASE secret)` |
| Remote Path | `/data/exports/` |
| Download Mode | Folder (recursive) |

**Result:** All files in `/data/exports/` are downloaded using SSH key authentication with an encrypted key.

---

### Example 6 — FTPS Implicit (Legacy Server)

Download from a legacy banking server that only supports FTPS Implicit.

| Parameter | Value |
|-----------|-------|
| Protocol | FTPS — FTP over TLS/SSL |
| FTPS Mode | Implicit — Direct TLS on port 990 |
| Host | `ftps.bank-legacy.com` |
| Port | `990` |
| Username | `partner_download` |
| Password | `(from FTP_PASSWORD secret)` |
| Remote Path | `/statements/monthly_20260201.pdf` |
| Download Mode | Single file |

**Result:** Downloads the PDF via FTPS Implicit (direct TLS handshake on port 990).

---

## Error Handling

The plugin provides **comprehensive, categorised error handling**. When an error occurs, a detailed diagnostics table is displayed:

| Property | Example Value |
|----------|---------------|
| **Category** | `Connection — DNS Resolution` |
| **Phase** | `Connection` |
| **Protocol** | `SFTP` |
| **Details** | `No such host is known (sftp.example.invalid)` |
| **Suggestion** | `Verify the hostname is correct and DNS is reachable` |

### Error Categories

| Category | Phase | Common Causes |
|----------|-------|---------------|
| **Connection — DNS Resolution** | Connection | Typo in hostname, DNS server unreachable |
| **Connection — Refused** | Connection | Server not running, wrong port, firewall blocking |
| **Connection — Timeout** | Connection | Network issues, firewall dropping packets |
| **Connection — Unreachable** | Connection | No route to host, VPN not connected |
| **Authentication — Failed** | Authentication | Wrong username/password, account locked |
| **Authentication — SSH Key Error** | Authentication | Key file not found, wrong format, permissions |
| **Authentication — Key Passphrase** | Authentication | Wrong passphrase for encrypted key |
| **Permission — Access Denied** | Permission | No read permission on remote directory |
| **Permission — Path Not Found** | Permission | Remote directory doesn't exist |
| **Transfer — Disk Full** | Transfer | Local disk out of space |
| **Transfer — Failed** | Transfer | Connection dropped during download, server error |
| **Protocol — TLS/SSL Error** | Protocol | Certificate issues, TLS version mismatch |
| **Protocol — STARTTLS Failed** | Protocol | Server doesn't support Explicit FTPS |

---

## Output Data Reference

All downloads produce structured output data accessible to downstream jobs via `data.*` paths.

**Output structure:**
```json
{
  "tool": "ftpDownload",
  "success": true,
  "protocol": "sftp",
  "host": "sftp.example.com",
  "port": 22,
  "remotePath": "/exports/*.csv",
  "localPath": "/opt/xyops/satellite/temp/jobs/abc123",
  "files": [
    {
      "name": "report1.csv",
      "localPath": "/opt/xyops/satellite/temp/jobs/abc123/report1.csv",
      "size": 12450,
      "status": "downloaded"
    },
    {
      "name": "report2.csv",
      "localPath": "/opt/xyops/satellite/temp/jobs/abc123/report2.csv",
      "size": 8230,
      "status": "skipped"
    }
  ],
  "downloadedFiles": ["report1.csv"],
  "totalFiles": 1,
  "totalSize": 12450,
  "skippedFiles": 1,
  "deletedRemote": false,
  "timestamp": "2026-02-21T14:30:00.0000000Z"
}
```

**Key output fields:**

| Data Path | Type | Description |
|-----------|------|-------------|
| `data.tool` | String | Always `ftpDownload` |
| `data.success` | Boolean | `true` if download completed |
| `data.protocol` | String | Protocol used (`ftp`, `ftps`, `sftp`) |
| `data.host` | String | Server hostname |
| `data.port` | Number | Server port |
| `data.remotePath` | String | Remote path downloaded from |
| `data.localPath` | String | Local directory where files were saved |
| `data.files` | Array | Details of each file processed |
| `data.files[].name` | String | Filename |
| `data.files[].localPath` | String | Full local path of the file |
| `data.files[].size` | Number | File size in bytes |
| `data.files[].status` | String | `downloaded` or `skipped` |
| `data.downloadedFiles` | Array | List of downloaded filenames |
| `data.totalFiles` | Number | Count of successfully downloaded files |
| `data.totalSize` | Number | Total bytes downloaded |
| `data.skippedFiles` | Number | Count of skipped files |
| `data.deletedRemote` | Boolean | Whether remote files were deleted |
| `data.timestamp` | String | ISO 8601 UTC timestamp |

---

## Downstream Chaining

Downloaded files are automatically declared as output and available to subsequent workflow steps via the `files` array.

**Example workflow:**
1. **Step 1:** FTP Download → Downloads `report1.csv`, `report2.csv`
2. **Step 2:** Data Processing Plugin → Receives files automatically

The next step receives:
```json
{
  "files": [
    {
      "filename": "report1.csv",
      "id": "fmktcdzp1skybhk9",
      "size": 12450
    },
    {
      "filename": "report2.csv",
      "id": "fmktcdzpasm25ncs",
      "size": 8230
    }
  ]
}
```

You can also access output data:
- `data.totalFiles` — number of files downloaded
- `data.skippedFiles` — number of files skipped
- `data.success` — overall success/failure

---

## Dependencies

| Dependency | Required For | Installation |
|------------|-------------|--------------|
| [PowerShell 7.0+](https://github.com/PowerShell/PowerShell) | All protocols | Manual (pre-requisite) |
| [Posh-SSH](https://github.com/darkoperator/Posh-SSH) (v3.2.7+) | SFTP only | **Auto-installed** on first SFTP use |
| .NET `System.Net.FtpWebRequest` | FTP / FTPS Explicit | Built-in (part of .NET runtime) |
| .NET `System.Net.Sockets.TcpClient` | FTPS Implicit | Built-in (part of .NET runtime) |

**Posh-SSH auto-installation:** When you first run an SFTP download, the plugin checks if `Posh-SSH` is installed. If not, it automatically runs `Install-Module -Name Posh-SSH -Scope CurrentUser -Force`. This is a one-time operation. Subsequent runs skip the installation check.

---

## Testing Locally

You can test the plugin locally by piping a JSON job object to the script:

```bash
pwsh -NoProfile -ExecutionPolicy Bypass -File ./ftp.ps1 < job.json
```

**Example `job.json` for single file download:**
```json
{
  "params": {
    "protocol": "sftp",
    "host": "sftp.example.com",
    "username": "testuser",
    "password": "testpass",
    "remotePath": "/reports/daily.csv",
    "downloadMode": "file",
    "ifFileExists": "overwrite"
  }
}
```

**Example `job.json` for pattern match download:**
```json
{
  "params": {
    "protocol": "ftp",
    "host": "ftp.example.com",
    "username": "ftpuser",
    "password": "ftppass",
    "remotePath": "/logs/*.log",
    "localPath": "/tmp/downloads",
    "downloadMode": "pattern",
    "ifFileExists": "skip",
    "deleteAfterDownload": false
  }
}
```

**Example `job.json` for folder download with delete:**
```json
{
  "params": {
    "protocol": "sftp",
    "host": "192.168.1.100",
    "username": "automation",
    "sshKeyPath": "/home/user/.ssh/id_ed25519",
    "remotePath": "/backups/daily/",
    "downloadMode": "folder",
    "ifFileExists": "rename",
    "deleteAfterDownload": true
  }
}
```

---

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE.md) file for details.

---

## Author

**Tim Alderweireldt**
- Plugin: xyOps FTP Download
- Year: 2026

---

## Version History

### v1.0.1 (2026-02-21)
- **Bug fix:** Fixed missing `.Size` property error when downloading a single file
- Single file downloads now correctly initialize file objects with `Size = 0` before download
- Actual file size is captured after download completes
- Affects all protocols: FTP, FTPS (Explicit/Implicit), SFTP

### v1.0.0 (2026-02-21)
- Initial release
- **3 protocols:** FTP (plain), FTPS (Explicit + Implicit TLS), SFTP (SSH)
- **3 download modes:** Single file, Folder (recursive), Pattern match (glob)
- **4 if-exists behaviors:** Overwrite, Skip, Error, Rename (with timestamp)
- **Delete after download** option
- **6 secrets** in xyOps Secret Vault with parameter override
- Posh-SSH auto-installation for SFTP
- Remote file listing and pattern matching for all protocols
- Recursive folder download with directory structure preservation
- Local directory auto-creation
- Downloaded files declared as output for downstream workflow steps
- Passive mode support for FTP/FTPS
- Comprehensive error handling with 13 error categories
- Structured output data for downstream job chaining
- 15 configurable parameters
- Cross-platform: Linux, Windows, macOS

---

**Need help?** Open an issue on GitHub or contact the author.
