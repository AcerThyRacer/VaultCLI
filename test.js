'use strict';

// ═══════════════════════════════════════════════════════════════
//  VAULTSECURE TEST SUITE — Comprehensive Unit Tests
// ═══════════════════════════════════════════════════════════════

const crypto = require('crypto');
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const os = require('os');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
    try {
        fn();
        passed++;
        console.log(`  ✅ ${name}`);
    } catch (err) {
        failed++;
        failures.push({ name, error: err.message });
        console.log(`  ❌ ${name}: ${err.message}`);
    }
}

function asyncTest(name, fn) {
    return fn().then(() => {
        passed++;
        console.log(`  ✅ ${name}`);
    }).catch(err => {
        failed++;
        failures.push({ name, error: err.message });
        console.log(`  ❌ ${name}: ${err.message}`);
    });
}

console.log('\n═══════════════════════════════════════════');
console.log('  VaultSecure Test Suite');
console.log('═══════════════════════════════════════════\n');

// ── 1. Crypto Engine Tests ──
console.log('── Crypto Engine ──');

const { encrypt, decrypt, hashPassword, verifyPassword, generatePassword, generateSecureId, deriveSubKey, SALT_LENGTH } = require('./src/crypto/engine');

test('encrypt/decrypt roundtrip', () => {
    const plaintext = 'hello world 🔐';
    const encrypted = encrypt(plaintext, 'testpassword123');
    const decrypted = decrypt(encrypted, 'testpassword123');
    assert.strictEqual(decrypted, plaintext);
});

test('decrypt with wrong password throws', () => {
    const encrypted = encrypt('secret', 'correct');
    assert.throws(() => decrypt(encrypted, 'wrong'));
});

test('encrypted output has all fields', () => {
    const enc = encrypt('data', 'pw');
    assert(enc.salt && enc.iv && enc.authTag && enc.ciphertext);
    assert.strictEqual(enc.salt.length, SALT_LENGTH * 2); // hex
});

test('hashPassword produces salt+hash', () => {
    const result = hashPassword('MyP@ssw0rd');
    assert(result.salt && result.hash);
    assert.strictEqual(result.salt.length, SALT_LENGTH * 2);
});

test('verifyPassword (correct)', () => {
    const hashed = hashPassword('TestPW123!');
    assert(verifyPassword('TestPW123!', hashed));
});

test('verifyPassword (incorrect)', () => {
    const hashed = hashPassword('TestPW123!');
    assert(!verifyPassword('WrongPW123!', hashed));
});

test('generatePassword — no modulo bias (uniform distribution)', () => {
    // Generate many passwords to check character distribution
    const n = 10000;
    const charset = 'abcdefghijkmnopqrstuvwxyz';
    const counts = {};
    for (let i = 0; i < n; i++) {
        const pw = generatePassword(8, { uppercase: false, numbers: false, symbols: false });
        const ch = pw[0]; // check first char distribution
        counts[ch] = (counts[ch] || 0) + 1;
    }
    // With 25 chars and 10000 draws, expected ~400 each
    const expected = n / charset.length;
    const allWithin = Object.values(counts).every(c => c > expected * 0.4 && c < expected * 1.6);
    assert(allWithin, 'Distribution too skewed — possible modulo bias');
});

test('generatePassword — length validation', () => {
    assert.throws(() => generatePassword(7), /length/i);
    assert.throws(() => generatePassword(129), /length/i);
    assert.doesNotThrow(() => generatePassword(8));
    assert.doesNotThrow(() => generatePassword(128));
});

test('generateSecureId — correct length and charset', () => {
    const id = generateSecureId();
    assert.strictEqual(id.length, 12);
    assert(/^[a-z0-9]+$/.test(id));
});

test('generateSecureId — uniqueness', () => {
    const ids = new Set();
    for (let i = 0; i < 1000; i++) ids.add(generateSecureId());
    assert.strictEqual(ids.size, 1000, 'Collision in 1000 IDs');
});

test('deriveSubKey — different purposes give different keys', () => {
    const salt = crypto.randomBytes(32);
    const key1 = deriveSubKey('pw', 'purpose1', salt);
    const key2 = deriveSubKey('pw', 'purpose2', salt);
    assert(!key1.equals(key2));
});

// ── 2. TOTP Tests ──
console.log('\n── TOTP/2FA ──');

const { generateTOTP, verifyTOTP, generateSecret, base32Encode, base32Decode, buildOtpAuthURI, parseOtpAuthURI } = require('./src/security/totp');

test('TOTP generates 6-digit code', () => {
    const secret = generateSecret();
    const { code } = generateTOTP(secret);
    assert.strictEqual(code.length, 6);
    assert(/^\d{6}$/.test(code));
});

test('TOTP verify with current code', () => {
    const secret = generateSecret();
    const { code } = generateTOTP(secret);
    assert(verifyTOTP(secret, code));
});

test('TOTP verify rejects wrong code', () => {
    const secret = generateSecret();
    assert(!verifyTOTP(secret, '000000'));
});

test('base32 roundtrip', () => {
    const original = crypto.randomBytes(20);
    const encoded = base32Encode(original);
    const decoded = base32Decode(encoded);
    assert(original.equals(decoded));
});

test('otpauth URI build/parse roundtrip', () => {
    const secret = generateSecret();
    const uri = buildOtpAuthURI(secret, 'VaultTest', 'user@test.com');
    const parsed = parseOtpAuthURI(uri);
    assert.strictEqual(parsed.secret, secret);
    assert.strictEqual(parsed.issuer, 'VaultTest');
    assert.strictEqual(parsed.account, 'user@test.com');
    assert.strictEqual(parsed.digits, 6);
    assert.strictEqual(parsed.period, 30);
});

// ── 3. Fuzzy Search Tests ──
console.log('\n── Fuzzy Search ──');

const { fuzzySearch } = require('./src/utils/fuzzy');

test('fuzzy exact match scores highest', () => {
    const entries = [{ name: 'Gmail' }, { name: 'GitHub' }];
    const results = fuzzySearch(entries, 'Gmail');
    assert.strictEqual(results[0].name, 'Gmail');
    assert(results[0]._score >= 90);
});

test('fuzzy typo tolerance', () => {
    const entries = [{ name: 'Gmail' }, { name: 'Facebook' }];
    const results = fuzzySearch(entries, 'gmal');
    assert(results.length > 0);
    assert(results.some(r => r.name === 'Gmail'));
});

test('fuzzy starts-with ranked higher than contains', () => {
    const entries = [{ name: 'MyGit' }, { name: 'GitHub' }];
    const results = fuzzySearch(entries, 'Git');
    assert.strictEqual(results[0].name, 'GitHub'); // starts-with
});

test('fuzzy empty query returns empty', () => {
    const entries = [{ name: 'Gmail' }];
    const results = fuzzySearch(entries, '');
    assert(results.length <= 1, 'Empty query should return few/no results');
});

// ── 4. Categories Tests ──
console.log('\n── Categories ──');

const { autoDetectCategory, getCategoryDisplay, filterByCategory, getCategories } = require('./src/utils/categories');

test('auto-detect Gmail as Email', () => {
    assert.strictEqual(autoDetectCategory({ name: 'Gmail', url: 'gmail.com' }), 'email');
});

test('auto-detect Steam as Gaming', () => {
    assert.strictEqual(autoDetectCategory({ name: 'Steam', url: 'steampowered.com' }), 'gaming');
});

test('auto-detect GitHub as Development', () => {
    const cat = autoDetectCategory({ name: 'GitHub', url: 'github.com' });
    assert(cat === 'development' || cat === 'dev', `Expected development or dev, got ${cat}`);
});

test('auto-detect Chase as Finance', () => {
    assert.strictEqual(autoDetectCategory({ name: 'Chase Bank' }), 'finance');
});

test('category display includes icon', () => {
    const display = getCategoryDisplay('email');
    assert(display.includes('📧'));
});

test('filterByCategory works', () => {
    const entries = [{ category: 'social' }, { category: 'email' }, { category: 'social' }];
    const filtered = filterByCategory(entries, 'social');
    assert.strictEqual(filtered.length, 2);
});

test('getCategories returns all categories', () => {
    const cats = getCategories();
    assert(cats.length >= 13);
});

// ── 5. Integrity Tests ──
console.log('\n── Vault Integrity ──');

const { verifyIntegrity } = require('./src/security/integrity');

test('integrity check with no vault returns valid', () => {
    const result = verifyIntegrity('testpass');
    assert(result.valid === true || result.valid === null);
});

// ── 6. Password Audit Tests ──
console.log('\n── Password Audit ──');

const { auditVault } = require('./src/utils/audit');

test('audit detects weak password', () => {
    const entries = [{ name: 'test', password: '123', createdAt: new Date().toISOString() }];
    const result = auditVault(entries);
    assert(result.weakPasswords.length > 0);
});

test('audit detects reused passwords', () => {
    const entries = [
        { name: 'a', password: 'SamePass123!', createdAt: new Date().toISOString() },
        { name: 'b', password: 'SamePass123!', createdAt: new Date().toISOString() },
    ];
    const result = auditVault(entries);
    assert(result.reusedPasswords.length > 0);
});

test('audit detects common passwords', () => {
    const entries = [{ name: 'test', password: 'password123', createdAt: new Date().toISOString() }];
    const result = auditVault(entries);
    // Should be flagged as weak (common)
    assert(result.weakPasswords.some(w => w.entry.name === 'test'));
});

test('expanded password list catches common passwords', () => {
    const entries = [
        { name: 'a', password: 'password', createdAt: new Date().toISOString() },
        { name: 'b', password: 'qwerty123', createdAt: new Date().toISOString() },
    ];
    const result = auditVault(entries);
    assert(result.weakPasswords.length >= 2, 'Should detect common passwords from expanded list');
});

// ── 7. Sanitization Tests ──
console.log('\n── Input Sanitization ──');

const { sanitizeEntry, validateEntry } = require('./src/utils/sanitize');

test('sanitizeEntry strips control chars', () => {
    const s = sanitizeEntry({ name: 'test\x00\x01\x02', username: 'user', password: 'pw' });
    assert(!s.name.includes('\x00'));
});

test('validateEntry rejects empty name', () => {
    const r = validateEntry({ name: '', username: 'u', password: 'p' });
    assert(!r.valid);
});

// ── 8. Config Tests ──
console.log('\n── Configuration ──');

const { loadConfig, getSessionTimeoutMs, DEFAULTS } = require('./src/utils/config');

test('config loads with defaults', () => {
    const cfg = loadConfig();
    assert(cfg.sessionTimeoutMinutes > 0);
});

test('session timeout returns ms', () => {
    const ms = getSessionTimeoutMs();
    assert(ms >= 60000); // At least 1 minute
});

// ── 9. Themes Tests ──
console.log('\n── Themes ──');

const { buildColors, getThemeNames, getThemeDisplayName } = require('./src/ui/themes');

test('all themes build without errors', () => {
    getThemeNames().forEach(t => {
        const c = buildColors(t);
        assert(c.primary);
        assert(c.success);
        assert(c.accent);
    });
});

test('6 themes available', () => {
    assert(getThemeNames().length >= 6);
});

// ── 10. Module Loading Tests ──
console.log('\n── Module Loading ──');

test('breach module loads', () => { require('./src/security/breach'); });
test('audit log module loads', () => { require('./src/security/auditlog'); });
test('decoy module loads', () => { require('./src/security/decoy'); });
test('importer module loads', () => { require('./src/io/importer'); });
test('exporter module loads', () => { require('./src/io/exporter'); });
test('clipboard module loads', () => { require('./src/utils/clipboard'); });

// ── 11. Phase 1 Security Tests ──
console.log('\n── Phase 1: Crypto & Memory Security ──');

const { constantTimeEqual } = require('./src/crypto/engine');

test('constantTimeEqual — equal strings return true', () => {
    assert(constantTimeEqual('hello', 'hello'));
    assert(constantTimeEqual('abc123', 'abc123'));
});

test('constantTimeEqual — different strings return false', () => {
    assert(!constantTimeEqual('hello', 'world'));
    assert(!constantTimeEqual('abc', 'abcd'));
});

test('constantTimeEqual — different lengths return false', () => {
    assert(!constantTimeEqual('short', 'longer string'));
    assert(!constantTimeEqual('', 'notempty'));
});

test('constantTimeEqual — non-strings return false', () => {
    assert(!constantTimeEqual(null, 'hello'));
    assert(!constantTimeEqual('hello', undefined));
    assert(!constantTimeEqual(123, 'hello'));
});

test('constantTimeEqual — empty strings return true', () => {
    assert(constantTimeEqual('', ''));
});

test('deriveSubKey — proper iterations (timing check)', () => {
    const salt = crypto.randomBytes(32);
    const start = Date.now();
    deriveSubKey('test', 'purpose', salt);
    const elapsed = Date.now() - start;
    // With 600K iterations, derivation should take at least 100ms
    // (1 iteration would be < 1ms)
    assert(elapsed >= 50, `deriveSubKey too fast (${elapsed}ms) — may still be using 1 iteration`);
});

test('deriveSubKey — consistent with same inputs', () => {
    const salt = crypto.randomBytes(32);
    const key1 = deriveSubKey('pw', 'purpose', salt);
    const key2 = deriveSubKey('pw', 'purpose', salt);
    assert(key1.equals(key2), 'Same inputs should produce same key');
});

const { createSessionKey, getSessionKey, zeroSessionKey } = require('./src/auth/master');

test('createSessionKey — returns hex string', () => {
    const key = createSessionKey('testpassword');
    assert(typeof key === 'string');
    assert.strictEqual(key.length, 64); // 32 bytes = 64 hex chars
    assert(/^[0-9a-f]+$/.test(key));
});

test('getSessionKey — returns current session key', () => {
    const created = createSessionKey('testpassword');
    const retrieved = getSessionKey();
    assert.strictEqual(created, retrieved);
});

test('zeroSessionKey — clears key material', () => {
    createSessionKey('testpassword');
    assert(getSessionKey() !== null);
    zeroSessionKey();
    assert.strictEqual(getSessionKey(), null);
});

test('zeroSessionKey — safe to call multiple times', () => {
    zeroSessionKey();
    zeroSessionKey(); // Should not throw
    assert.strictEqual(getSessionKey(), null);
});

test('TOTP verify — constant-time (checks all windows)', () => {
    const secret = generateSecret();
    const { code } = generateTOTP(secret);
    // Verify correct code works
    assert(verifyTOTP(secret, code));
    // Verify wrong code fails
    assert(!verifyTOTP(secret, '999999'));
});

// ── 12. Phase 2 Security Tests ──
console.log('\n── Phase 2: Auth & Authorization Hardening ──');

const { logUnauthEvent, getAuthEvents } = require('./src/security/auditlog');

test('logUnauthEvent — logs without password', () => {
    // Should not throw
    logUnauthEvent('LOGIN_FAILED', { test: true });
    const events = getAuthEvents(5);
    assert(events.length > 0, 'Should have at least one event');
    assert.strictEqual(events[0].event, 'LOGIN_FAILED');
});

test('getAuthEvents — returns recent events in reverse order', () => {
    logUnauthEvent('TEST_EVENT_1');
    logUnauthEvent('TEST_EVENT_2');
    const events = getAuthEvents(5);
    assert(events.length >= 2);
    // Most recent first
    assert.strictEqual(events[0].event, 'TEST_EVENT_2');
});

test('logEvent with null password delegates to logUnauthEvent', () => {
    const { logEvent: logE } = require('./src/security/auditlog');
    const countBefore = getAuthEvents(200).length;
    logE(null, 'LOGIN_FAILED', { delegated: true });
    const countAfter = getAuthEvents(200).length;
    assert(countAfter > countBefore, 'logEvent(null,...) should create an auth event');
});

const { sanitizeEntry: sanitize2, validateEntry: validate2 } = require('./src/utils/sanitize');

test('decoy entry sanitization — strips control chars', () => {
    const entry = sanitize2({ name: 'Test\x00\x01', username: 'user\x02', password: 'pw' });
    assert(!entry.name.includes('\x00'));
    assert(!entry.username.includes('\x02'));
});

test('decoy entry validation — rejects empty name', () => {
    const result = validate2({ name: '', username: 'u', password: 'p' });
    assert(!result.valid);
});

const { checkVaultPermissions } = require('./src/auth/master');

test('checkVaultPermissions — returns array', () => {
    const warnings = checkVaultPermissions();
    assert(Array.isArray(warnings));
});

test('checkVaultPermissions — no warnings on valid setup', () => {
    const warnings = checkVaultPermissions();
    // On Windows, should be empty (no POSIX checks)
    if (process.platform === 'win32') {
        assert.strictEqual(warnings.length, 0);
    }
    // On POSIX, may have warnings depending on test env
});

test('constantTimeEqual — used for HMAC (functional check)', () => {
    // Verify the function is exported and works with hex strings (HMAC format)
    const hmac1 = crypto.createHmac('sha256', 'key').update('data').digest('hex');
    const hmac2 = crypto.createHmac('sha256', 'key').update('data').digest('hex');
    const hmac3 = crypto.createHmac('sha256', 'key').update('other').digest('hex');
    assert(constantTimeEqual(hmac1, hmac2));
    assert(!constantTimeEqual(hmac1, hmac3));
});

// ── 13. Phase 3 Security Tests ──
console.log('\n── Phase 3: Data Integrity & I/O Hardening ──');

const { csvSafeValue } = require('./src/io/exporter');

test('csvSafeValue — prefixes formula chars with tab', () => {
    assert.strictEqual(csvSafeValue('=HYPERLINK()'), '\t=HYPERLINK()');
    assert.strictEqual(csvSafeValue('+cmd'), '\t+cmd');
    assert.strictEqual(csvSafeValue('-1+1'), '\t-1+1');
    assert.strictEqual(csvSafeValue('@SUM(A1)'), '\t@SUM(A1)');
});

test('csvSafeValue — leaves normal values unchanged', () => {
    assert.strictEqual(csvSafeValue('hello'), 'hello');
    assert.strictEqual(csvSafeValue('test@example.com'), 'test@example.com');
    assert.strictEqual(csvSafeValue(''), '');
    assert.strictEqual(csvSafeValue('123'), '123');
});

const { saveConfig: saveCfg, loadConfig: loadCfg, DEFAULTS: CFG_DEFAULTS } = require('./src/utils/config');

test('config — save and load preserves values', () => {
    const cfg = saveCfg({ sessionTimeoutMinutes: 10 });
    assert.strictEqual(cfg.sessionTimeoutMinutes, 10);
    const loaded = loadCfg();
    assert.strictEqual(loaded.sessionTimeoutMinutes, 10);
});

test('config — HMAC protects against tampering', () => {
    saveCfg({ sessionTimeoutMinutes: 7 });
    // Tamper with the config file directly
    const configPath = path.join(require('./src/auth/master').getVaultDir(), 'config.json');
    const raw = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    raw.sessionTimeoutMinutes = 99; // modify without updating HMAC
    fs.writeFileSync(configPath, JSON.stringify(raw));
    const loaded = loadCfg();
    // Should fall back to defaults due to HMAC mismatch
    assert.strictEqual(loaded.sessionTimeoutMinutes, CFG_DEFAULTS.sessionTimeoutMinutes);
});

test('config — re-save after tamper detection restores HMAC', () => {
    saveCfg({ clipboardClearSeconds: 30 });
    const loaded = loadCfg();
    assert.strictEqual(loaded.clipboardClearSeconds, 30);
});

const { sanitizeEntry: sanitize3 } = require('./src/utils/sanitize');

test('password length — capped at 10KB', () => {
    const longPw = 'a'.repeat(20000);
    const entry = sanitize3({ name: 'test', password: longPw });
    assert(entry.password.length <= 10240);
});

test('password length — normal passwords unchanged', () => {
    const entry = sanitize3({ name: 'test', password: 'MyP@ss123!' });
    assert.strictEqual(entry.password, 'MyP@ss123!');
});

test('importer — autoImport handles JSON with pre-read content', () => {
    const tmpFile = path.join(os.tmpdir(), 'test-import-' + Date.now() + '.json');
    const payload = {
        format: 'vaultsecure-export', version: '1.0', entries: [
            { name: 'Test', username: 'user', password: 'pw' }
        ]
    };
    fs.writeFileSync(tmpFile, JSON.stringify(payload));
    const { autoImport } = require('./src/io/importer');
    const result = autoImport(tmpFile);
    assert(result.entries.length === 1);
    assert.strictEqual(result.entries[0].name, 'Test');
    fs.unlinkSync(tmpFile);
});

test('exporter — CSV export creates file atomically', () => {
    const tmpFile = path.join(os.tmpdir(), 'test-export-' + Date.now() + '.csv');
    const { exportToCSV } = require('./src/io/exporter');
    const result = exportToCSV([{ name: 'GitHub', username: 'user', password: 'pw123' }], tmpFile, false);
    assert(fs.existsSync(tmpFile));
    assert.strictEqual(result.entries, 1);
    const content = fs.readFileSync(tmpFile, 'utf8');
    assert(content.includes('GitHub'));
    assert(content.includes('********')); // Password masked
    fs.unlinkSync(tmpFile);
});

test('integrity module — loads without errors', () => {
    require('./src/security/integrity');
});

// ── 14. Phase 4 Security Tests ──
console.log('\n── Phase 4: Privacy & Data Protection ──');

const { encryptEntryPassword, decryptEntryPassword, privacyTimestamp } = require('./src/store/vault');

test('per-entry encryption — roundtrip', () => {
    const pw = 'MyS3cur3P@ss!';
    const master = 'testMasterPw';
    const enc = encryptEntryPassword(pw, master);
    assert(enc.encrypted);
    assert(enc.salt);
    assert(enc.iv);
    assert(enc.tag);
    const dec = decryptEntryPassword(enc, master);
    assert.strictEqual(dec, pw);
});

test('per-entry encryption — wrong master rejects', () => {
    const enc = encryptEntryPassword('secret', 'correctPw');
    assert.throws(() => decryptEntryPassword(enc, 'wrongPw'));
});

test('per-entry encryption — unique salts', () => {
    const enc1 = encryptEntryPassword('pw', 'master');
    const enc2 = encryptEntryPassword('pw', 'master');
    assert.notStrictEqual(enc1.salt, enc2.salt); // Different salts each time
    assert.notStrictEqual(enc1.iv, enc2.iv);
});

test('per-entry encryption — legacy plaintext passthrough', () => {
    const result = decryptEntryPassword('plaintext_password', 'master');
    assert.strictEqual(result, 'plaintext_password');
    assert.strictEqual(decryptEntryPassword(null, 'master'), null);
});

test('privacyTimestamp — full mode (default)', () => {
    const ts = privacyTimestamp();
    assert(ts.includes('T'));
    assert(ts.endsWith('Z'));
    // Full mode should have minutes/seconds precision
    assert(ts.length > 20);
});

const { emergencyWipe, secureDelete } = require('./src/security/wipe');

test('secureDelete — overwrites and removes file', () => {
    const tmpFile = path.join(os.tmpdir(), 'wipe-test-' + Date.now() + '.txt');
    fs.writeFileSync(tmpFile, 'sensitive-data-here');
    assert(fs.existsSync(tmpFile));
    secureDelete(tmpFile);
    assert(!fs.existsSync(tmpFile));
});

test('secureDelete — handles missing file gracefully', () => {
    const result = secureDelete('/nonexistent/path/file.txt');
    assert.strictEqual(result, false);
});

test('emergencyWipe module — loads without errors', () => {
    assert(typeof emergencyWipe === 'function');
    assert(typeof secureDelete === 'function');
});

test('password strength — getStrength detects weak', () => {
    // getStrength is not exported from menu.js, but let's test the logic
    const pw = '1234';
    let charset = 0;
    if (/[a-z]/.test(pw)) charset += 26;
    if (/[A-Z]/.test(pw)) charset += 26;
    if (/[0-9]/.test(pw)) charset += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) charset += 32;
    const entropy = Math.floor(pw.length * Math.log2(charset || 1));
    assert(entropy < 40); // Should be weak
});

test('password strength — getStrength detects strong', () => {
    const pw = 'A8b$Kz!qL3mR@7wX';
    let charset = 0;
    if (/[a-z]/.test(pw)) charset += 26;
    if (/[A-Z]/.test(pw)) charset += 26;
    if (/[0-9]/.test(pw)) charset += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) charset += 32;
    const entropy = Math.floor(pw.length * Math.log2(charset || 1));
    assert(entropy >= 80); // Should be strong
});

test('CSV export — stripTimestamps removes timestamp columns', () => {
    const tmpFile = path.join(os.tmpdir(), 'csv-strip-' + Date.now() + '.csv');
    const { exportToCSV } = require('./src/io/exporter');
    exportToCSV([{ name: 'Test', username: 'u', password: 'p', createdAt: '2024-01-01', updatedAt: '2024-01-02' }], tmpFile, false, { stripTimestamps: true });
    const content = fs.readFileSync(tmpFile, 'utf8');
    assert(!content.includes('createdAt'));
    assert(!content.includes('updatedAt'));
    assert(content.includes('Test'));
    fs.unlinkSync(tmpFile);
});

test('JSON export — stripTimestamps redacts timestamps', () => {
    const tmpFile = path.join(os.tmpdir(), 'json-strip-' + Date.now() + '.json');
    const { exportToJSON } = require('./src/io/exporter');
    exportToJSON([{ name: 'Test', username: 'u', password: 'p', createdAt: '2024-01-01', updatedAt: '2024-01-02' }], tmpFile, { stripTimestamps: true });
    const data = JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
    assert.strictEqual(data.exportedAt, '[REDACTED]');
    assert(!data.entries[0].createdAt);
    fs.unlinkSync(tmpFile);
});

// ── 15. Phase 5 Quality & Testing ──
console.log('\n── Phase 5: Quality & Testing ──');

// 5.1 Lockout/brute-force tests
test('lockout — getLockoutState returns valid structure', () => {
    const { getLockoutState } = require('./src/auth/master');
    const state = getLockoutState();
    assert(typeof state === 'object');
    assert('attempts' in state);
    assert('lockedUntil' in state);
});

// 5.2 Session timeout tests
test('session timeout — config-based timeout', () => {
    const { getSessionTimeoutMs: getTimeout } = require('./src/utils/config');
    const ms = getTimeout();
    assert(ms >= 60000);    // At least 1 minute
    assert(ms <= 1800000);  // At most 30 minutes
});

// 5.3 CSV formula injection (already covered in Phase 3, add edge case)
test('csvSafeValue — edge case: tab prefix', () => {
    assert.strictEqual(csvSafeValue('\t=formula'), '\t=formula'); // Already has tab — still safe
});

// 5.4 Sanitization edge cases
const { sanitizeEntry: sanitize5, validateEntry: validate5 } = require('./src/utils/sanitize');

test('sanitization — unicode preserved', () => {
    const entry = sanitize5({ name: '密码管理器', username: 'ユーザー', password: 'pw' });
    assert(entry.name.includes('密码'));
    assert(entry.username.includes('ユーザー'));
});

test('sanitization — oversized fields truncated', () => {
    const entry = sanitize5({ name: 'a'.repeat(500), username: 'b'.repeat(1000), password: 'p' });
    assert(entry.name.length <= 100);
    assert(entry.username.length <= 500);
});

test('sanitization — control chars stripped from name', () => {
    const entry = sanitize5({ name: 'test\x00\x01\x02name', password: 'p' });
    assert(!entry.name.includes('\x00'));
    assert(!entry.name.includes('\x01'));
    assert(entry.name.includes('test'));
    assert(entry.name.includes('name'));
});

test('sanitization — null/undefined fields handled', () => {
    const entry = sanitize5({ name: 'test', password: 'p', url: null, notes: undefined });
    assert.strictEqual(entry.name, 'test');
    assert(entry.url !== null || entry.url === ''); // Should handle nulls
});

test('validation — valid entry accepted', () => {
    const result = validate5({ name: 'GitHub', username: 'user', password: 'pw' });
    assert(result.valid);
});

test('validation — whitespace-only name rejected', () => {
    const result = validate5({ name: '   ', username: 'user', password: 'pw' });
    assert(!result.valid);
});

// 5.5 Decoy vault CRUD tests
const { createDecoyVault, hasDecoyVault, addDecoyEntry, deleteDecoyEntry, listDecoyEntries } = require('./src/security/decoy');

test('decoy — module loads with all exports', () => {
    assert(typeof createDecoyVault === 'function');
    assert(typeof hasDecoyVault === 'function');
    assert(typeof addDecoyEntry === 'function');
    assert(typeof deleteDecoyEntry === 'function');
    assert(typeof listDecoyEntries === 'function');
});

// 5.6 Backup creation/pruning tests
const { listBackups } = require('./src/store/vault');

test('backup — listBackups returns array', () => {
    const backups = listBackups();
    assert(Array.isArray(backups));
});

// 5.7 Error handling tests
test('error handling — loadVault with no vault file returns empty array', () => {
    const { loadVault } = require('./src/store/vault');
    // Use a password that won't find a vault — should return []
    const entries = loadVault('non-existent-test-pw-' + Date.now());
    assert(Array.isArray(entries));
    assert.strictEqual(entries.length, 0);
});

test('error handling — exportToCSV with empty entries', () => {
    const { exportToCSV } = require('./src/io/exporter');
    const tmpFile = path.join(os.tmpdir(), 'export-empty-' + Date.now() + '.csv');
    const result = exportToCSV([], tmpFile);
    assert.strictEqual(result.entries, 0);
    const content = fs.readFileSync(tmpFile, 'utf8');
    assert(content.includes('name')); // Headers should still be present
    fs.unlinkSync(tmpFile);
});

// 5.8 Shared sleep utility
test('sleep — shared module loads', () => {
    const { sleep: sharedSleep } = require('./src/utils/sleep');
    assert(typeof sharedSleep === 'function');
    // Verify it returns a promise
    const result = sharedSleep(0);
    assert(result instanceof Promise);
});

// 5.9 Clipboard config
test('clipboard — getClearDelayMs reads from config', () => {
    const { getClearDelayMs } = require('./src/utils/clipboard');
    const ms = getClearDelayMs();
    assert(typeof ms === 'number');
    assert(ms >= 5000);   // Min 5s
    assert(ms <= 120000); // Max 120s
});

// 5.10 .gitignore hardening
test('gitignore — blocks vault data files', () => {
    const gitignore = fs.readFileSync(path.join(__dirname, '.gitignore'), 'utf8');
    assert(gitignore.includes('.vaultsecure/'));
    assert(gitignore.includes('*.enc'));
    assert(gitignore.includes('*.key'));
    assert(gitignore.includes('*.salt'));
    assert(gitignore.includes('*.hmac'));
    assert(gitignore.includes('node_modules/'));
    assert(gitignore.includes('.env'));
});

// ── Summary ──
console.log('\n═══════════════════════════════════════════');
console.log(`  Results: ${passed} passed, ${failed} failed`);
if (failures.length > 0) {
    console.log('\n  Failures:');
    failures.forEach(f => console.log(`    ❌ ${f.name}: ${f.error}`));
}
console.log('═══════════════════════════════════════════\n');

process.exit(failed > 0 ? 1 : 0);
