<p align="center">
  <img src="https://img.shields.io/badge/Node.js-16%2B-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js 16+"/>
  <img src="https://img.shields.io/badge/AES--256--GCM-Encrypted-764ABC?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="AES-256-GCM"/>
  <img src="https://img.shields.io/badge/PBKDF2-600K_Iterations-FF6F00?style=for-the-badge&logo=keybase&logoColor=white" alt="PBKDF2"/>
  <img src="https://img.shields.io/badge/License-GPL%20v3-blue?style=for-the-badge&logo=gnu&logoColor=white" alt="GPL v3"/>
  <img src="https://img.shields.io/badge/Platform-Win%20%7C%20Mac%20%7C%20Linux-lightgrey?style=for-the-badge" alt="Cross-platform"/>
</p>

<h1 align="center">🔐 VaultSecureCLI</h1>

<p align="center">
  <b>A maximum-security password vault for your terminal.</b><br/>
  <sub>Zero-knowledge · Offline-first · No cloud · No tracking · Your passwords never leave your machine.</sub>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-security-architecture">Security</a> •
  <a href="#-configuration">Configuration</a> •
  <a href="#-import--export">Import/Export</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## ✨ Features

### 🛡️ Military-Grade Encryption
- **AES-256-GCM** authenticated encryption with unique IVs per operation
- **PBKDF2-SHA512** key derivation at **600,000 iterations**
- Per-entry password encryption with individual salts
- HMAC integrity verification on every vault read
- Constant-time comparisons against timing attacks

### 🔑 Authentication & Access Control
- Master password with enforced complexity (8+ chars, upper + lower + digit)
- **TOTP two-factor authentication** (Google Authenticator compatible)
- Brute-force protection with progressive lockout (encrypted lockout state)
- Session timeout with automatic vault locking
- Session watchdog timer running in the background
- Re-authentication required before destructive operations

### 🕵️ Stealth & Plausible Deniability
- **Decoy vault** — a separate, fully functional vault activated by a different password
- Decoy and real vault are cryptographically indistinguishable
- Identical menus prevent visual detection

### 🔍 Password Intelligence
- **Breach checking** against known compromised password databases
- **Password strength meter** with real-time scoring at entry time
- Password health audit (weak, reused, old passwords)
- Customizable password generator (length, symbols, exclusions)
- Password history tracking per entry

### 📦 Import & Export
- **Import from:** CSV, JSON, KeePass XML, 1Password, Bitwarden, LastPass
- **Export to:** Encrypted JSON, CSV, plaintext (with re-authentication)
- Formula injection protection on CSV exports
- Optional timestamp stripping for privacy
- Atomic file writes prevent data corruption

### 🎨 Beautiful Terminal UI
- Animated ASCII boot sequence and unlocking effects
- Color-coded interface with multiple themes
- Interactive fuzzy search across all entries
- Categorized password organization
- Tabular display with `cli-table3`

### 🛡️ Privacy Hardening
- **Emergency wipe** — panic command to securely destroy all vault data
- Privacy-aware timestamps (rounded to day/hour)
- Encrypted audit log tracking all vault operations
- Buffer-based password handling (zeroized after use)
- No telemetry, no network calls, fully offline

---

## 📥 Installation

### Prerequisites

| Requirement | Version |
|------------|---------|
| **Node.js** | 16.0 or higher |
| **npm** | 7.0 or higher |

### One-Line Install

**Linux / macOS:**
```bash
git clone https://github.com/AcerThyRacer/VaultCLI.git && cd VaultCLI && chmod +x install.sh && ./install.sh
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/AcerThyRacer/VaultCLI.git; cd VaultCLI; .\install.ps1
```

**Windows (CMD):**
```cmd
git clone https://github.com/AcerThyRacer/VaultCLI.git && cd VaultCLI && install.bat
```

### Manual Install

```bash
# Clone the repository
git clone https://github.com/AcerThyRacer/VaultCLI.git
cd VaultCLI

# Install dependencies
npm install

# Link globally (may require sudo on Linux/macOS)
npm link

# Verify installation
vault --help
```

### Run Without Installing Globally

```bash
npm start
# or
node bin/vault.js
```

---

## 🚀 Quick Start

```bash
# Launch the vault
vault

# Skip the boot animation
vault --quick
# or
vault -q
```

On first run, you'll be prompted to create a **master password**. This password:
- Must be at least 8 characters
- Must contain uppercase, lowercase, and a digit
- **Cannot be recovered if forgotten** — there is no backdoor

After setup, you'll see the main menu with all available operations.

---

## 📖 Usage

### Main Menu Options

| Action | Description |
|--------|-------------|
| 🔐 **Add Password** | Store a new credential with optional category and notes |
| 📋 **List Passwords** | View all stored entries in a formatted table |
| 🔍 **Search** | Fuzzy search across names, usernames, URLs, and categories |
| 📊 **Password Audit** | Analyze vault health — find weak, reused, or old passwords |
| 🎲 **Generate Password** | Create strong random passwords with custom rules |
| 📤 **Export** | Export vault to CSV, JSON, or encrypted format |
| 📥 **Import** | Import from CSV, JSON, KeePass, 1Password, Bitwarden, LastPass |
| 🛡️ **TOTP Setup** | Enable time-based 2FA for vault access |
| 📜 **Audit Log** | View encrypted log of all vault operations |
| 🔑 **Change Password** | Change the master password (re-encrypts entire vault) |
| 🚨 **Emergency Wipe** | Securely destroy all vault data (irreversible) |
| 🔒 **Lock** | Lock the vault without exiting |
| 🚪 **Exit** | Lock and exit with animated sequence |

### Adding a Password

```
🔐  Add Password
  Service:   GitHub
  Username:  user@example.com
  Password:  •••••••••••••
  URL:       https://github.com
  Category:  Development
  Notes:     Personal account

  ✓ Entry saved! (Strength: ████████░░ Strong)
```

### Generating a Password

```
🎲  Generate Password
  Length:           24
  Include symbols:  Yes
  Exclude chars:    0Ol1I

  Generated: x$K9m#vR2pQ&nW8jF!cT5bYz
  ✓ Copied to clipboard (auto-clears in 15s)
```

### Searching Entries

The fuzzy search matches across all fields — service name, username, URL, category, and notes:

```
🔍  Search: git

  ┌───┬──────────────┬───────────────────┬──────────┐
  │ # │ Service      │ Username          │ Category │
  ├───┼──────────────┼───────────────────┼──────────┤
  │ 1 │ GitHub       │ user@example.com  │ Dev      │
  │ 2 │ GitLab       │ admin@company.io  │ Work     │
  │ 3 │ DigitalOcean │ git-deploy        │ Cloud    │
  └───┴──────────────┴───────────────────┴──────────┘
```

---

## 🔒 Security Architecture

### Encryption Pipeline

```
Master Password
      │
      ▼
┌─────────────────────────────┐
│  PBKDF2-SHA512              │
│  600,000 iterations         │
│  Per-vault random salt      │
└──────────┬──────────────────┘
           │
           ▼
    Session Key (Buffer)
           │
     ┌─────┴─────┐
     ▼           ▼
  AES-256     HMAC-SHA512
  Encrypt     Integrity
     │           │
     ▼           ▼
  Vault.enc   Vault.hmac
```

### Key Security Properties

| Property | Implementation |
|----------|---------------|
| **Encryption** | AES-256-GCM with random 16-byte IV per write |
| **Key Derivation** | PBKDF2-SHA512, 600K iterations, random 32-byte salt |
| **Integrity** | HMAC-SHA512 verified before every vault read |
| **Timing Safety** | `crypto.timingSafeEqual()` for all secret comparisons |
| **Memory Safety** | Passwords stored as `Buffer`, zeroized after use |
| **Brute-Force** | Progressive lockout with encrypted lockout state |
| **Atomic Writes** | Temp file + rename prevents corruption on crash |
| **Per-Entry Encryption** | Individual entry passwords have per-entry salts |
| **Audit Trail** | Encrypted log of all operations and access attempts |
| **Input Sanitization** | All entries sanitized for control chars, length limits |

### Threat Model

| Threat | Mitigation |
|--------|-----------|
| Master password brute-force | 600K PBKDF2 iterations + progressive lockout |
| Memory scraping | Buffer-based password handling + session key zeroization |
| Vault file tampering | HMAC integrity verification on every read |
| Timing side-channels | Constant-time comparisons on all secrets |
| Clipboard sniffing | Auto-clear clipboard after configurable delay |
| Shoulder surfing | Password masking, screen clearing, decoy vault |
| Forensic recovery | Emergency wipe with secure file deletion |
| CSV formula injection | Field sanitization on export (`=`, `+`, `-`, `@` prefixed) |
| Crash during write | Atomic file operations (temp + rename) |

---

## ⚙️ Configuration

VaultSecureCLI stores its configuration in `~/.vaultsecure/config.json`. Available options:

| Setting | Default | Description |
|---------|---------|-------------|
| `sessionTimeoutMinutes` | `15` | Auto-lock timeout in minutes |
| `clipboardClearSeconds` | `15` | Clipboard auto-clear delay |
| `showBootAnimation` | `true` | Show ASCII boot animation on launch |
| `autoBackup` | `true` | Create backups before vault modifications |
| `maxBackups` | `5` | Number of backup files to retain |
| `theme` | `default` | UI color theme |
| `privacyTimestamps` | `false` | Round timestamps for privacy |

Configuration is HMAC-signed and validated on load to detect tampering.

---

## 📤 Import & Export

### Importing Passwords

VaultSecureCLI supports importing from all major password managers:

| Format | Source |
|--------|--------|
| CSV | Generic CSV files (auto-detected columns) |
| JSON | VaultSecureCLI encrypted exports |
| XML | KeePass export files |
| CSV | 1Password export |
| CSV | Bitwarden export |
| CSV | LastPass export |

```bash
# Place your export file in the vault directory, then use:
# Main Menu → 📥 Import → Select format
```

### Exporting Passwords

| Format | Encrypted | Notes |
|--------|-----------|-------|
| Encrypted JSON | ✅ Yes | Full backup, re-importable |
| CSV | ❌ No | For migration to other managers |
| Plaintext | ❌ No | Emergency access, use with caution |

All exports require **re-authentication** and use atomic file writes.

---

## 🗂️ Project Structure

```
VaultSecureCLI/
├── bin/
│   └── vault.js              # Entry point & session management
├── src/
│   ├── auth/
│   │   └── master.js          # Master password, lockout, session
│   ├── crypto/
│   │   └── engine.js          # AES-256-GCM, PBKDF2, HMAC
│   ├── io/
│   │   ├── exporter.js        # Export (CSV, JSON, encrypted)
│   │   └── importer.js        # Import (CSV, JSON, KeePass, etc.)
│   ├── security/
│   │   ├── auditlog.js        # Encrypted audit logging
│   │   ├── breach.js          # Breach database checking
│   │   ├── decoy.js           # Decoy vault operations
│   │   ├── integrity.js       # HMAC integrity verification
│   │   ├── totp.js            # TOTP 2FA implementation
│   │   └── wipe.js            # Emergency data wipe
│   ├── store/
│   │   └── vault.js           # Vault CRUD, per-entry encryption
│   ├── ui/
│   │   ├── ascii.js           # ASCII art & animations
│   │   ├── menu.js            # Interactive menu system
│   │   └── themes.js          # Color themes
│   └── utils/
│       ├── audit.js           # Password health auditing
│       ├── categories.js      # Entry categorization
│       ├── clipboard.js       # Secure clipboard handling
│       ├── config.js          # HMAC-signed config management
│       ├── fuzzy.js           # Fuzzy search
│       ├── sanitize.js        # Input sanitization
│       └── sleep.js           # Async sleep utility
├── test.js                    # Comprehensive test suite (102 tests)
├── install.sh                 # Linux/macOS installer
├── install.bat                # Windows CMD installer
├── install.ps1                # Windows PowerShell installer
├── package.json
├── ROADMAP.md                 # Security hardening roadmap
├── SECURITY_AUDIT.md          # Full security audit report
└── README.md
```

---

## 🧪 Testing

Run the full test suite:

```bash
npm test
```

The test suite contains **102 tests** covering:

- ✅ Cryptographic roundtrips (AES-256-GCM encrypt/decrypt)
- ✅ PBKDF2 key derivation correctness
- ✅ TOTP generation and verification
- ✅ Constant-time comparison verification
- ✅ Input sanitization (unicode, control chars, oversized input)
- ✅ Fuzzy search scoring
- ✅ CSV formula injection prevention
- ✅ Lockout and brute-force behavior
- ✅ Session timeout expiry
- ✅ Decoy vault CRUD operations
- ✅ Backup creation and pruning
- ✅ Error handling (corrupt vault, missing files)
- ✅ Configuration management
- ✅ Category system
- ✅ Theme loading

---

## 🗺️ Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| Phase 1 — Critical Crypto | ✅ Complete | PBKDF2 600K iterations, timing-safe comparisons, Buffer passwords |
| Phase 2 — Auth Hardening | ✅ Complete | Re-auth on exports, decoy validation, audit log fixes |
| Phase 3 — I/O Hardening | ✅ Complete | Atomic writes, config signing, CSV injection protection |
| Phase 4 — Privacy | ✅ Complete | Per-entry encryption, emergency wipe, privacy timestamps |
| Phase 5 — Testing | ✅ Complete | 102 tests, security-focused test coverage |
| Phase 6 — Features | 🔜 Planned | Argon2id KDF, passphrase generator, vault health dashboard |

See [ROADMAP.md](ROADMAP.md) for the full detailed roadmap and [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for the complete security audit.

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/VaultCLI.git
   ```
3. **Create a branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** and ensure all tests pass:
   ```bash
   npm test
   ```
5. **Commit** with a clear message:
   ```bash
   git commit -m "feat: add your feature description"
   ```
6. **Push** and open a Pull Request

### Contribution Guidelines

- Follow the existing code style (CommonJS, `'use strict'`)
- Add tests for any new functionality
- Security-sensitive changes require review of the [Security Audit](SECURITY_AUDIT.md)
- Keep pull requests focused on a single concern
- Use [conventional commits](https://www.conventionalcommits.org/) for commit messages

---

## ❓ FAQ

<details>
<summary><b>What happens if I forget my master password?</b></summary>
<br/>
Your vault data cannot be recovered. There is no backdoor, no reset mechanism, and no cloud backup. This is by design — it ensures that only you can access your passwords. Keep your master password in a secure physical location as a backup.
</details>

<details>
<summary><b>Is my data sent anywhere?</b></summary>
<br/>
No. VaultSecureCLI is 100% offline. No network calls, no telemetry, no analytics. Your passwords never leave your machine. The only exception is the optional breach check, which sends a partial hash prefix (k-anonymity model) — not your actual password.
</details>

<details>
<summary><b>Can I use this on multiple machines?</b></summary>
<br/>
Yes. Export your vault as an encrypted JSON file, transfer it to the other machine, and import it. The encrypted export uses the same AES-256-GCM encryption and can only be decrypted with your master password.
</details>

<details>
<summary><b>What is the decoy vault?</b></summary>
<br/>
The decoy vault is a separate, fully functional vault that activates when you enter a different password. It's designed for plausible deniability — if you're forced to reveal your vault password, you can give the decoy password instead. The decoy vault looks and behaves identically to the real vault but contains different entries.
</details>

<details>
<summary><b>How does the emergency wipe work?</b></summary>
<br/>
The emergency wipe securely deletes all vault data, including the encrypted vault, backups, configuration, audit logs, and lockout state. The files are overwritten with random data before deletion. This action is irreversible.
</details>

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with 🔒 by <a href="https://github.com/AcerThyRacer">AcerThyRacer</a></sub><br/>
  <sub>Your passwords deserve better than a sticky note.</sub>
</p>
