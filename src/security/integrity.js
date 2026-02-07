'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { encrypt, decrypt, deriveSubKey, constantTimeEqual, SALT_LENGTH } = require('../crypto/engine');
const { getVaultDir, ensureVaultDir, atomicWrite } = require('../auth/master');

// ═══════════════════════════════════════════════════════════════
//  VAULT INTEGRITY — HMAC with derived key (no raw password)
// ═══════════════════════════════════════════════════════════════

const INTEGRITY_FILE = path.join(getVaultDir(), 'vault.hmac');
const INTEGRITY_PURPOSE = 'vault-integrity-hmac-v1';
const INTEGRITY_KEY_FILE = path.join(getVaultDir(), 'integrity.key');

/**
 * Compute HMAC-SHA256 using a properly derived key (not raw password).
 */
function computeHMAC(data, derivedKey) {
    return crypto.createHmac('sha256', derivedKey).update(data).digest('hex');
}

/**
 * Get or create the integrity encryption key (for encrypting the salt).
 */
function getIntegrityEncKey() {
    ensureVaultDir();
    if (fs.existsSync(INTEGRITY_KEY_FILE)) {
        return fs.readFileSync(INTEGRITY_KEY_FILE, 'utf8').trim();
    }
    const key = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(INTEGRITY_KEY_FILE, key, { mode: 0o600 });
    return key;
}

/**
 * Get or create an integrity salt (persisted alongside the HMAC).
 * Salt is encrypted at rest using a dedicated key.
 */
function getIntegritySalt() {
    const saltFile = path.join(getVaultDir(), 'integrity.salt');
    if (fs.existsSync(saltFile)) {
        try {
            const raw = fs.readFileSync(saltFile, 'utf8');
            const encKey = getIntegrityEncKey();
            // Try to decrypt (new encrypted format)
            const parsed = JSON.parse(raw);
            if (parsed.iv && parsed.tag) {
                const decrypted = decrypt(parsed, encKey);
                return Buffer.from(decrypted, 'hex');
            }
        } catch {
            // Fallback: might be legacy plaintext hex
            try {
                const raw = fs.readFileSync(saltFile, 'utf8').trim();
                if (/^[0-9a-f]+$/i.test(raw)) {
                    const salt = Buffer.from(raw, 'hex');
                    // Migrate to encrypted format
                    const encKey = getIntegrityEncKey();
                    const encrypted = encrypt(salt.toString('hex'), encKey);
                    atomicWrite(saltFile, JSON.stringify(encrypted));
                    return salt;
                }
            } catch { /* fall through to generate new */ }
        }
    }
    // Generate new salt and encrypt it
    const salt = crypto.randomBytes(SALT_LENGTH);
    const encKey = getIntegrityEncKey();
    const encrypted = encrypt(salt.toString('hex'), encKey);
    atomicWrite(saltFile, JSON.stringify(encrypted));
    return salt;
}

/**
 * Save integrity HMAC after a vault write.
 * Key is derived from master password + purpose salt (never raw password).
 */
function saveIntegrity(masterPassword) {
    ensureVaultDir();
    const vaultFile = path.join(getVaultDir(), 'vault.enc');
    if (!fs.existsSync(vaultFile)) return;

    const salt = getIntegritySalt();
    const integrityKey = deriveSubKey(masterPassword, INTEGRITY_PURPOSE, salt);
    const data = fs.readFileSync(vaultFile, 'utf8');
    const hmac = computeHMAC(data, integrityKey);

    integrityKey.fill(0); // Zero derived key

    const record = { hmac, timestamp: new Date().toISOString(), fileSize: data.length };
    atomicWrite(INTEGRITY_FILE, JSON.stringify(record, null, 2));
}

/**
 * Verify vault file integrity.
 */
function verifyIntegrity(masterPassword) {
    const vaultFile = path.join(getVaultDir(), 'vault.enc');
    if (!fs.existsSync(vaultFile)) return { valid: true, details: 'No vault file exists yet.' };
    if (!fs.existsSync(INTEGRITY_FILE)) return { valid: null, details: 'No integrity record found. Run a write to create one.' };

    try {
        const record = JSON.parse(fs.readFileSync(INTEGRITY_FILE, 'utf8'));
        const salt = getIntegritySalt();
        const integrityKey = deriveSubKey(masterPassword, INTEGRITY_PURPOSE, salt);
        const data = fs.readFileSync(vaultFile, 'utf8');
        const currentHMAC = computeHMAC(data, integrityKey);

        integrityKey.fill(0);

        if (constantTimeEqual(currentHMAC, record.hmac)) {
            return { valid: true, details: `Vault integrity verified. Last: ${record.timestamp}`, timestamp: record.timestamp };
        } else {
            return { valid: false, details: 'INTEGRITY VIOLATION: Vault modified outside VaultSecure!', expectedSize: record.fileSize, actualSize: data.length };
        }
    } catch (err) {
        return { valid: false, details: `Integrity error: ${err.message}` };
    }
}

module.exports = { saveIntegrity, verifyIntegrity, computeHMAC };
