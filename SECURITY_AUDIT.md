# 🔒 VaultSecureCLI — Deep Security Audit & Roadmap

**Date:** 2026-02-07  
**Scope:** Full codebase scan — 20 source files, 1 test file, 1 entry point  
**Auditor:** Antigravity DeepScan

---

## Executive Summary

VaultSecureCLI has a solid foundation: AES-256-GCM encryption, PBKDF2-SHA512 key derivation at 600K iterations, constant-time password verification, atomic file writes, input sanitization, and encrypted audit logs. However, the deep scan uncovered **8 Critical**, **9 High**, **7 Medium**, and **6 Low** severity findings, plus **12 recommended new features**.

---

## 🔴 CRITICAL Vulnerabilities

### C1 · `deriveSubKey()` uses only 1 PBKDF2 iteration
**File:** [engine.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/crypto/engine.js#L155)  
**Impact:** The HMAC integrity key is derived with `pbkdf2Sync(password, purposeSalt, 1, ...)` — effectively no stretching. An attacker who obtains the vault file can brute-force the integrity key orders of magnitude faster than the main vault key.

```js
// VULNERABLE — 1 iteration
return crypto.pbkdf2Sync(password, purposeSalt, 1, KEY_LENGTH, 'sha256');
```

**Fix:** Use the same `PBKDF2_ITERATIONS` (600K) constant, or at minimum 100K iterations. Also use `sha512` for consistency.

---

### C2 · Master password lives as plaintext `string` throughout session
**File:** [vault.js (bin)](file:///c:/Users/serge/Downloads/VaultSecureCLI/bin/vault.js#L30), [menu.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/ui/menu.js#L26)  
**Impact:** JavaScript `string` values are immutable and cannot be zeroed. The master password persists in heap memory for the entire session, surviving garbage collection unpredictably. Memory-scraping malware can extract it.

**Fix:** Store the password in a `Buffer` and zero it after each use. Derive a session key at login, store only the session key, and re-derive per-operation keys from it.

---

### C3 · HMAC integrity comparison uses `===` (not constant-time)
**File:** [integrity.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/security/integrity.js#L73)  
**Impact:** String `===` comparison leaks timing information proportional to the shared prefix. An attacker with local access can forge vault modifications and brute-force the HMAC via timing side-channel.

```js
// VULNERABLE
if (currentHMAC === record.hmac) {
```

**Fix:** Convert both HMACs to Buffers and use `crypto.timingSafeEqual()`.

---

### C4 · TOTP verification uses `===` (not constant-time)
**File:** [totp.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/security/totp.js#L170)  
**Impact:** TOTP code comparison via `===` leaks timing info. While the 30-second window limits practical exploitation, this violates RFC 6238 best practices.

```js
// VULNERABLE
if (expected === code) return true;
```

**Fix:** Pad both strings to equal length and use `crypto.timingSafeEqual()`.

---

### C5 · `handleChangeMasterPassword()` compares passwords with `!==`
**File:** [menu.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/ui/menu.js#L552)  
**Impact:** Re-authentication during password change uses a direct string comparison against the in-memory master password instead of `verifyMasterPassword()`. This both leaks timing and bypasses the proper KDF-based verification.

```js
// VULNERABLE
if (currentPw !== masterPassword) { ... }
```

**Fix:** Use `verifyMasterPassword(currentPw)` for proper constant-time verification.

---

### C6 · No re-authentication before destructive operations
**Files:** [menu.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/ui/menu.js) — `handleExport`, `handleDelete`, `handleAuditLog` (clear)  
**Impact:** Once authenticated, any vault export, mass deletion, or audit log clearing proceeds without re-verifying identity. If a user walks away from an unlocked session, a walk-up attacker can exfiltrate the entire vault.

**Fix:** Require master password re-entry before: export (all formats), bulk delete, audit log clear, and master password change.

---

### C7 · Lockout key is deterministic and reversible
**File:** [master.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/auth/master.js#L26-L29)  
**Impact:** The lockout encryption key is `SHA256(lockout-{hostname}-{homedir})`. An attacker who knows the user's hostname and home directory (trivial on shared systems) can decrypt and reset the lockout file, bypassing brute-force protection entirely.

```js
// VULNERABLE — deterministic from public info
const LOCKOUT_KEY = crypto.createHash('sha256')
    .update(`lockout-${os.hostname()}-${os.homedir()}`)
    .digest('hex').substring(0, 32);
```

**Fix:** Derive the lockout key from a random secret stored alongside the master hash, or use the master password hash itself as input.

---

### C8 · Passwords stored in plaintext within encrypted vault entries
**File:** [vault.js (store)](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/store/vault.js#L97)  
**Impact:** Individual entry passwords are stored as plaintext strings inside the JSON blob before encryption. When the vault is decrypted for any read operation, ALL passwords exist in memory simultaneously. Password history (line 150) also stores previous passwords in plaintext.

**Fix:** Consider encrypting individual entry passwords with a per-entry salt, so decrypting the vault index doesn't expose all credentials at once.

---

## 🟠 HIGH Severity

### H1 · Export files written non-atomically
**File:** [exporter.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/io/exporter.js#L37-L63-L87)  
**Impact:** `fs.writeFileSync()` without temp+rename means a crash mid-write produces a corrupted or partial export. The vault's own writes use `atomicWrite()` but exports don't.

**Fix:** Use `atomicWrite()` for all export operations.

---

### H2 · Config file stored unencrypted, no integrity check
**File:** [config.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/utils/config.js#L46)  
**Impact:** `config.json` is plaintext with `0o600` permissions. An attacker with file access can modify `sessionTimeoutMinutes: 9999` to keep the session permanently alive, or disable `autoBackup`.

**Fix:** Sign the config with an HMAC derived from the master password. Verify on load.

---

### H3 · Decoy vault password has weak minimum (4 chars)
**File:** [menu.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/ui/menu.js#L490)  
**Impact:** The decoy password only requires 4 characters, making it easily brute-forceable. Since decoy passwords are checked alongside the master password, a weak decoy reduces overall security.

**Fix:** Enforce the same password policy as the master password (8+ chars, upper+lower+digit).

---

### H4 · Clipboard contains plaintext passwords
**File:** [clipboard.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/utils/clipboard.js)  
**Impact:** Passwords sit in the system clipboard for up to 15 seconds. Other apps can read the clipboard freely. The `clipboardy.readSync()` comparison before clearing is also not constant-time.

**Fix:** Reduce default clear time to 10 seconds. On Windows, consider using a "clipboard sequence number" check instead of reading back the content. Add a warning when copying.

---

### H5 · CSV export vulnerable to formula injection
**File:** [exporter.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/io/exporter.js#L23-L34)  
**Impact:** If a vault entry's name/username contains `=`, `+`, `-`, or `@`, the CSV export creates a formula injection vector. Opening in Excel/Sheets executes the formula.

**Fix:** Prefix fields starting with `=`, `+`, `-`, `@`, `\t`, `\r` with a single quote `'` or tab character inside the quoted field.

---

### H6 · `autoImport()` reads file twice for JSON
**File:** [importer.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/io/importer.js#L270-L276)  
**Impact:** The file is read in `autoImport()` to check the format, then read again in `importFromJSON()`. This creates a TOCTOU (time-of-check-time-of-use) race: the file could be swapped between reads.

**Fix:** Read once, parse once, and pass the parsed data to the appropriate handler.

---

### H7 · No vault file permissions validation on startup
**File:** [master.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/auth/master.js)  
**Impact:** The vault directory and files should be `0o700`/`0o600` but this is only set at creation time. If permissions are widened later, the app doesn't warn.

**Fix:** Check and warn (or refuse) if `.vaultsecure/` has permissions wider than `0o700` on startup.

---

### H8 · Decoy vault has no input sanitization
**File:** [decoy.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/security/decoy.js#L51-L63)  
**Impact:** `addDecoyEntry()` doesn't call `sanitizeEntry()` or `validateEntry()`, unlike the real vault's `addEntry()`. Malicious input (control characters, oversized fields) goes directly into storage.

**Fix:** Apply the same `sanitizeEntry()` and `validateEntry()` pipeline.

---

### H9 · Audit log silently fails when `masterPassword` is null
**File:** [auditlog.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/security/auditlog.js#L46)  
**Impact:** Failed login events pass `null` as password (line 142 of vault.js), so `logEvent()` returns immediately without logging. Failed login attempts are the most critical events to audit.

**Fix:** Maintain a separate, non-encrypted audit log for unauthenticated events, or derive a logging key that doesn't require the master password.

---

## 🟡 MEDIUM Severity

### M1 · Backup files not encrypted separately
**File:** [vault.js (store)](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/store/vault.js#L24)  
**Impact:** Backups are byte-for-byte copies of the encrypted vault. If the master password is compromised, all backups are also compromised. No backup rotation integrity check.

---

### M2 · No password strength enforcement on entry passwords
**File:** [menu.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/ui/menu.js#L123)  
**Impact:** Users can store `"a"` as a password. The audit tool flags it after the fact, but there's no proactive warning at add-time.

**Fix:** Show a strength meter and warn (not block) when saving weak passwords.

---

### M3 · `test.js` has no security-focused tests
**File:** [test.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/test.js)  
**Impact:** No tests for: timing-safe comparison, lockout behavior, session expiry, export file permissions, sanitization edge cases, or atomic write failure recovery.

---

### M4 · Error messages may leak sensitive information
**File:** [vault.js (bin)](file:///c:/Users/serge/Downloads/VaultSecureCLI/bin/vault.js#L88)  
**Impact:** `Fatal: ${err.message}` may expose internal paths, stack traces (in debug mode), or crypto error details that help an attacker understand the system.

---

### M5 · No maximum password length on stored entries
**File:** [sanitize.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/utils/sanitize.js#L40)  
**Impact:** Passwords bypass `truncate()` — an entry with a 1MB password would bloat the vault and slow all operations.

**Fix:** Cap stored passwords at a reasonable limit (e.g., 10KB).

---

### M6 · KeePass XML import uses regex-based parsing
**File:** [importer.js](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/io/importer.js#L228-L230)  
**Impact:** Regex XML parsing can be confused by CDATA sections, nested elements, or XML comments. Could silently drop entries or merge fields incorrectly.

---

### M7 · TOTP secrets stored unprotected in vault entries
**File:** [vault.js (store)](file:///c:/Users/serge/Downloads/VaultSecureCLI/src/store/vault.js#L103)  
**Impact:** TOTP secrets are stored as plaintext strings alongside passwords. If the vault is decrypted, all 2FA seeds are exposed immediately, defeating the purpose of 2FA as a separate factor.

---

## 🟢 LOW Severity

### L1 · `sleep()` defined in multiple files
Duplicated in `ascii.js`, `breach.js`. Should be a shared utility.

### L2 · `clipboardClearSeconds` config not used by clipboard module
`clipboard.js` hardcodes `CLEAR_DELAY_MS = 15000` instead of reading from config.

### L3 · Fuzzy search scores leak through `_score` and `_matchField` on entries
Internal scoring metadata is attached directly to entry objects, polluting the data model.

### L4 · `ora` is `require()`'d inline in multiple handlers
Should be imported once at the top of the file.

### L5 · `.gitignore` is minimal
Only 28 bytes. Missing: `.vaultsecure/`, `*.enc`, `*.bak`, `*.csv` exports, `.env`, OS files.

### L6 · No `package-lock.json` integrity verification
Supply chain attack vector — dependencies aren't pinned with `npm ci` in any script.

---

## 🔵 Privacy Improvements

| # | Finding | Recommendation |
|---|---------|----------------|
| P1 | Audit log timestamps expose usage patterns | Add option to use fuzzy timestamps (e.g., "morning", "afternoon") |
| P2 | Entry `createdAt`/`updatedAt` precise to millisecond | Round to day or hour for privacy |
| P3 | Export includes full timestamps | Strip or anonymize timestamps in exports |
| P4 | Hostname in lockout key reveals machine identity | Use random machine ID instead |
| P5 | No "wipe all data" emergency function | Add panic/wipe command |
| P6 | No data-at-rest encryption for config, integrity salt, HMAC files | Encrypt all vault-adjacent files |

---

## 📋 Missing Feature Recommendations

| # | Feature | Priority | Description |
|---|---------|----------|-------------|
| F1 | **Argon2id KDF** | High | Replace PBKDF2 with Argon2id for memory-hard key derivation (via `argon2` npm package) |
| F2 | **Passphrase generator** | Medium | Generate diceware-style passphrases alongside random passwords |
| F3 | **Password sharing** | Medium | Encrypted password sharing via one-time links |
| F4 | **Auto-lock on screen lock** | Medium | Listen for OS screen lock events and auto-lock vault |
| F5 | **Vault migration/versioning** | Medium | Schema version in vault format + migration system |
| F6 | **Multi-vault support** | Low | Named vault profiles (personal, work, etc.) |
| F7 | **YubiKey/WebAuthn** | Low | Hardware key support for vault unlock |
| F8 | **Browser extension bridge** | Low | Local API for browser autofill extension |
| F9 | **zxcvbn password scoring** | Medium | Use Dropbox's zxcvbn for more accurate strength estimation |
| F10 | **Encrypted clipboard** | Low | Use OS secure clipboard APIs where available |
| F11 | **Offline breach database** | Medium | Bundle a bloom filter of common breached hashes for offline checking |
| F12 | **Vault health dashboard** | Medium | Comprehensive dashboard with password age chart, category breakdown, 2FA coverage |

---

## Test Coverage Gaps

Current test suite covers: crypto roundtrips, TOTP generation, fuzzy search, categories, config, themes, and module loading. **Missing:**

- [ ] Lockout/brute-force behavior
- [ ] Session timeout expiry
- [ ] Atomic write crash recovery
- [ ] Sanitization with adversarial input (control chars, unicode, oversized)
- [ ] CSV formula injection in exports
- [ ] Import size limit enforcement
- [ ] Constant-time comparison verification
- [ ] Decoy vault CRUD operations
- [ ] Backup creation and pruning
- [ ] Re-encryption during master password change
- [ ] Error handling paths (corrupt vault, missing files, disk full)

---

## Severity Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 Critical | 8 | Must fix before any production use |
| 🟠 High | 9 | Address in next release |
| 🟡 Medium | 7 | Plan for near-term |
| 🟢 Low | 6 | Quality-of-life improvements |
| 🔵 Privacy | 6 | Privacy-hardening recommendations |
| 📋 Features | 12 | Recommended enhancements |
| 🧪 Test Gaps | 11 | Missing test coverage areas |

