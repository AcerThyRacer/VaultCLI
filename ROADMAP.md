# 🗺️ VaultSecureCLI — Security Hardening Roadmap

> Prioritized plan derived from the [Security Audit](./SECURITY_AUDIT.md) deep scan.  
> Each phase is self-contained and testable. Ship after each phase.

---

## Phase 1 — Critical Crypto & Memory Fixes
**Priority:** 🔴 CRITICAL · **Target:** Immediate  
**Estimated effort:** 4-6 hours

| # | Task | File(s) | Audit Ref |
|---|------|---------|-----------|
| 1.1 | Increase `deriveSubKey()` to 600K PBKDF2 iterations, switch to SHA-512 | `crypto/engine.js` | C1 |
| 1.2 | Use `crypto.timingSafeEqual()` for HMAC comparison in `verifyIntegrity()` | `security/integrity.js` | C3 |
| 1.3 | Use `crypto.timingSafeEqual()` for TOTP code comparison | `security/totp.js` | C4 |
| 1.4 | Replace `!==` with `verifyMasterPassword()` in `handleChangeMasterPassword()` | `ui/menu.js` | C5 |
| 1.5 | Derive lockout key from stored random secret instead of hostname | `auth/master.js` | C7 |
| 1.6 | Store master password as `Buffer` and zero after key derivation | `bin/vault.js`, `ui/menu.js` | C2 |

**Verification:**
- [ ] Unit tests for constant-time comparisons
- [ ] Lockout key no longer derived from public machine info
- [ ] `deriveSubKey` now uses 600K iterations
- [ ] Memory test: no plaintext passwords in heap dump after operations

---

## Phase 2 — Authentication & Authorization Hardening  
**Priority:** 🔴 CRITICAL → 🟠 HIGH · **Target:** Week 1  
**Estimated effort:** 3-4 hours

| # | Task | File(s) | Audit Ref |
|---|------|---------|-----------|
| 2.1 | Add re-authentication before export, clear audit log, bulk delete | `ui/menu.js` | C6 |
| 2.2 | Enforce same password policy on decoy vault (8+ chars, complexity) | `ui/menu.js` | H3 |
| 2.3 | Add input sanitization to decoy vault entries | `security/decoy.js` | H8 |
| 2.4 | Log failed login events without requiring master password | `security/auditlog.js` | H9 |
| 2.5 | Validate vault directory permissions on startup (warn if too open) | `auth/master.js` | H7 |

**Verification:**
- [ ] Cannot export without re-entering master password
- [ ] Decoy vault rejects weak passwords
- [ ] Failed logins appear in audit log even before authentication

---

## Phase 3 — Data Integrity & I/O Hardening
**Priority:** 🟠 HIGH · **Target:** Week 2  
**Estimated effort:** 3-4 hours

| # | Task | File(s) | Audit Ref |
|---|------|---------|-----------|
| 3.1 | Use `atomicWrite()` for all export operations | `io/exporter.js` | H1 |
| 3.2 | Sign config with HMAC, verify on load | `utils/config.js` | H2 |
| 3.3 | Fix CSV formula injection (prefix `=+\-@` with tab) | `io/exporter.js` | H5 |
| 3.4 | Fix TOCTOU in `autoImport()` — read file once | `io/importer.js` | H6 |
| 3.5 | Cap stored password length at 10KB | `utils/sanitize.js` | M5 |
| 3.6 | Encrypt integrity salt and HMAC files | `security/integrity.js` | P6 |

**Verification:**
- [ ] CSV exports safe to open in Excel (no formula execution)
- [ ] Config tampering detected on load
- [ ] Export files survive simulated crash (atomic writes)

---

## Phase 4 — Privacy & Data Protection
**Priority:** 🟡 MEDIUM · **Target:** Week 3  
**Estimated effort:** 3-4 hours

| # | Task | File(s) | Audit Ref |
|---|------|---------|-----------|
| 4.1 | Add per-entry password encryption (per-entry salt within vault) | `store/vault.js` | C8 |
| 4.2 | Add emergency wipe command ("panic mode") | `bin/vault.js`, new `security/wipe.js` | P5 |
| 4.3 | Add privacy mode for timestamps (round to day/hour) | `store/vault.js`, `security/auditlog.js` | P1, P2 |
| 4.4 | Strip timestamps from exports (option) | `io/exporter.js` | P3 |
| 4.5 | Use random machine ID instead of hostname in any derived keys | `auth/master.js` | P4 |
| 4.6 | Show password strength meter at add-time (warn, don't block) | `ui/menu.js` | M2 |

**Verification:**
- [ ] Panic wipe securely deletes all vault data
- [ ] Decrypting vault doesn't expose all passwords at once
- [ ] Export timestamps can be stripped

---

## Phase 5 — Quality & Testing  
**Priority:** 🟡 MEDIUM · **Target:** Week 4  
**Estimated effort:** 4-6 hours

| # | Task | File(s) | Audit Ref |
|---|------|---------|-----------|
| 5.1 | Add lockout/brute-force behavior tests | `test.js` | M3 |
| 5.2 | Add session timeout expiry tests | `test.js` | M3 |
| 5.3 | Add CSV formula injection test | `test.js` | M3 |
| 5.4 | Add sanitization edge case tests (unicode, oversized, control chars) | `test.js` | M3 |
| 5.5 | Add decoy vault CRUD tests | `test.js` | M3 |
| 5.6 | Add backup creation/pruning tests | `test.js` | M3 |
| 5.7 | Add error handling tests (corrupt vault, missing files) | `test.js` | M3 |
| 5.8 | Deduplicate `sleep()` into shared util | `breach.js`, `ascii.js` | L1 |
| 5.9 | Read `clipboardClearSeconds` from config | `utils/clipboard.js` | L2 |
| 5.10 | Harden `.gitignore` | `.gitignore` | L5 |

**Verification:**
- [ ] All new tests pass
- [ ] > 80% code coverage on security-critical modules

---

## Phase 6 — Feature Enhancements
**Priority:** 🟢 LOW → 🟡 MEDIUM · **Target:** Month 2+  
**Estimated effort:** 8-12 hours (spread across features)

| # | Feature | Description | Audit Ref |
|---|---------|-------------|-----------|
| 6.1 | **Argon2id KDF** | Memory-hard key derivation via `argon2` npm package | F1 |
| 6.2 | **Passphrase generator** | Diceware/EFF wordlist passphrases | F2 |
| 6.3 | **zxcvbn scoring** | Dropbox's realistic password strength estimation | F9 |
| 6.4 | **Vault health dashboard** | Password age chart, 2FA coverage, category breakdown | F12 |
| 6.5 | **Offline breach bloom filter** | Bundle HIBP breach hash subset for offline checking | F11 |
| 6.6 | **Auto-lock on screen lock** | OS event listener for screen lock/sleep | F4 |
| 6.7 | **Vault schema versioning** | Format version field + migration system | F5 |
| 6.8 | **Multi-vault profiles** | Named vaults (personal, work, etc.) | F6 |

---

## Architecture Improvements (ongoing)

- [ ] Consolidate inline `require('ora')` to top-level import
- [ ] Remove internal `_score`/`_matchField` pollution from entry objects  
- [ ] Add `npm ci` to CI/CD pipeline for supply-chain integrity
- [ ] Consider TypeScript migration for type safety
- [ ] Implement proper error classes instead of string matching

---

## Progress Tracker

| Phase | Status | Completion |
|-------|--------|------------|
| Phase 1 — Critical Crypto | ✅ Complete | 100% |
| Phase 2 — Auth Hardening | ✅ Complete | 100% |
| Phase 3 — I/O Hardening | ✅ Complete | 100% |
| Phase 4 — Privacy | ✅ Complete | 100% |
| Phase 5 — Testing | ✅ Complete | 100% |
| Phase 6 — Features | ⬜ Not Started | 0% |

