# Changelog

All notable changes to the **xyOps FTP Download** plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.0.0] — 2026-02-21

### Added
- Initial release
- **3 protocols:** FTP (plain), FTPS (Explicit + Implicit TLS), SFTP (SSH)
- **3 download modes:** Single file, Folder (recursive), Pattern match (glob)
- **2 destination options:** Plugin working directory (CWD) or custom local path
- **4 if-exists behaviors:** Overwrite, Skip, Error, Rename (with timestamp)
- **Delete after download** — Optional remote file deletion after successful download
- **6 secrets** in xyOps Secret Vault (`FTP_HOST`, `FTP_PORT`, `FTP_USERNAME`, `FTP_PASSWORD`, `FTP_SSH_KEY_PATH`, `FTP_SSH_KEY_PASSPHRASE`) — all overridable via parameters
- **15 configurable parameters** for full control over download behaviour
- **Posh-SSH auto-installation** — automatically installs the Posh-SSH module on first SFTP use
- **FTP/FTPS Explicit** via .NET `System.Net.FtpWebRequest` (port 21, STARTTLS)
- **FTPS Implicit** via custom `TcpClient` + `SslStream` implementation (port 990, direct TLS)
- **SFTP** via Posh-SSH module with password and SSH key auth (RSA, ED25519, ECDSA, DSA)
- Recursive folder download with directory structure discovery
- Remote file listing and glob pattern matching for all protocols
- Local directory auto-creation (recursive mkdir)
- Passive mode support for FTP/FTPS (default: enabled)
- Downloaded files declared as output for downstream workflow steps
- Comprehensive error handling with categorised error types (connection, auth, permission, transfer, protocol)
- Structured JSON output data for downstream job chaining
- Progress reporting throughout the download process
- Cross-platform support: Linux, Windows, macOS

### Notes
- Requires PowerShell 7.0+
- Requires secrets configured in the xyOps Secret Vault (or parameters provided directly)
- Posh-SSH module is auto-installed; no manual setup needed for SFTP
- Downloaded files are automatically declared for downstream workflow steps via `files` output
