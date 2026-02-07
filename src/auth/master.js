'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { hashPassword, verifyPassword, encrypt, decrypt } = require('../crypto/engine');

// ═══════════════════════════════════════════════════════════════
//  MASTER PASSWORD AUTHENTICATION (Hardened)
//  Fixes: encrypted lockout, constant-time decoy check
// ═══════════════════════════════════════════════════════════════

// ── Named Constants ──
const VAULT_DIR = path.join(os.homedir(), '.vaultsecure');
const MASTER_FILE = path.join(VAULT_DIR, 'master.hash');
const LOCKOUT_FILE = path.join(VAULT_DIR, 'lockout.enc');

const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 60 * 1000;  // 60 seconds
let SESSION_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes default

let lastActivityTime = Date.now();

const LOCKOUT_SECRET_FILE = path.join(VAULT_DIR, 'lockout.key');

/**
 * Get the lockout encryption key from a stored random secret.
 * Generated once on first use — NOT derived from hostname or other public info.
 */
function getLockoutKey() {
    ensureVaultDir();
    if (fs.existsSync(LOCKOUT_SECRET_FILE)) {
        return fs.readFileSync(LOCKOUT_SECRET_FILE, 'utf8').trim();
    }
    // First-time: generate a random 32-byte hex key and persist it
    const secret = crypto.randomBytes(32).toString('hex').substring(0, 32);
    fs.writeFileSync(LOCKOUT_SECRET_FILE, secret, { mode: 0o600 });
    return secret;
}

function ensureVaultDir() {
    if (!fs.existsSync(VAULT_DIR)) {
        fs.mkdirSync(VAULT_DIR, { recursive: true, mode: 0o700 });
    }
}

function isFirstRun() {
    return !fs.existsSync(MASTER_FILE);
}

function setupMasterPassword(password) {
    ensureVaultDir();
    const hashed = hashPassword(password);
    atomicWrite(MASTER_FILE, JSON.stringify(hashed, null, 2));
    resetLockout();
    refreshActivity();
    return true;
}

/**
 * Verify the master password against saved hash.
 * Also checks decoy in constant time to prevent timing attacks.
 */
function verifyMasterPassword(password) {
    if (isLockedOut()) {
        const remaining = getLockoutRemaining();
        return { success: false, locked: true, remaining };
    }

    const stored = JSON.parse(fs.readFileSync(MASTER_FILE, 'utf8'));
    const valid = verifyPassword(password, stored);

    // Always check decoy too (constant-time — both checks always run)
    let isDecoy = false;
    try {
        const decoyHashFile = path.join(VAULT_DIR, 'decoy.hash');
        if (fs.existsSync(decoyHashFile)) {
            const decoyStored = JSON.parse(fs.readFileSync(decoyHashFile, 'utf8'));
            isDecoy = verifyPassword(password, decoyStored);
        }
    } catch { /* ignore */ }

    if (valid) {
        resetLockout();
        refreshActivity();
        return { success: true, isDecoy: false };
    }

    if (isDecoy) {
        resetLockout();
        refreshActivity();
        return { success: true, isDecoy: true };
    }

    // Neither matched
    incrementAttempts();
    const attempts = getAttempts();
    const remaining = MAX_ATTEMPTS - attempts;
    if (remaining <= 0) {
        triggerLockout();
        return { success: false, locked: true, remaining: LOCKOUT_DURATION_MS };
    }
    return { success: false, locked: false, attemptsLeft: remaining };
}

function changeMasterPassword(oldPassword, newPassword) {
    const stored = JSON.parse(fs.readFileSync(MASTER_FILE, 'utf8'));
    if (!verifyPassword(oldPassword, stored)) return false;
    const newHash = hashPassword(newPassword);
    atomicWrite(MASTER_FILE, JSON.stringify(newHash, null, 2));
    return true;
}

// ── Encrypted Lockout Management ──

function getLockoutData() {
    if (!fs.existsSync(LOCKOUT_FILE)) return { attempts: 0, lockedUntil: 0 };
    try {
        const raw = fs.readFileSync(LOCKOUT_FILE, 'utf8');
        const encData = JSON.parse(raw);
        const decrypted = decrypt(encData, getLockoutKey());
        return JSON.parse(decrypted);
    } catch {
        return { attempts: 0, lockedUntil: 0 };
    }
}

function saveLockout(data) {
    ensureVaultDir();
    const encrypted = encrypt(JSON.stringify(data), getLockoutKey());
    atomicWrite(LOCKOUT_FILE, JSON.stringify(encrypted));
}

function isLockedOut() {
    const data = getLockoutData();
    if (data.lockedUntil > Date.now()) return true;
    if (data.lockedUntil > 0 && data.lockedUntil <= Date.now()) resetLockout();
    return false;
}

function getLockoutRemaining() {
    const data = getLockoutData();
    return Math.max(0, data.lockedUntil - Date.now());
}

function getAttempts() { return getLockoutData().attempts; }

function incrementAttempts() {
    const data = getLockoutData();
    data.attempts = (data.attempts || 0) + 1;
    saveLockout(data);
}

function triggerLockout() {
    saveLockout({ attempts: MAX_ATTEMPTS, lockedUntil: Date.now() + LOCKOUT_DURATION_MS });
}

function resetLockout() {
    saveLockout({ attempts: 0, lockedUntil: 0 });
}

/**
 * Public accessor for lockout state (for testing/monitoring).
 */
function getLockoutState() {
    return getLockoutData();
}

// ── Session Management ──

let sessionKey = null; // Buffer — zeroed on lock/exit

function refreshActivity() { lastActivityTime = Date.now(); }
function isSessionExpired() { return (Date.now() - lastActivityTime) > SESSION_TIMEOUT_MS; }
function setSessionTimeout(ms) { SESSION_TIMEOUT_MS = ms; }
function getVaultDir() { return VAULT_DIR; }

/**
 * Create a session key from the master password.
 * The session key is a 256-bit Buffer derived via PBKDF2 that serves
 * as a password-equivalent during the session. This allows the raw
 * password string to be discarded as early as possible.
 *
 * The session key is stored as a Buffer and can be zeroed on lock/exit,
 * unlike JavaScript strings which are immutable and persist in memory.
 */
function createSessionKey(password) {
    const salt = Buffer.from('vaultsecure-session-key-v1', 'utf8');
    sessionKey = crypto.pbkdf2Sync(
        Buffer.from(password, 'utf8'),
        salt,
        1, // Single iteration — this is key derivation from already-verified password, not stretching
        32,
        'sha256'
    );
    return sessionKey.toString('hex');
}

/**
 * Get the current session key as a hex string.
 * Returns null if no session is active.
 */
function getSessionKey() {
    if (!sessionKey) return null;
    return sessionKey.toString('hex');
}

/**
 * Zero the session key buffer and clear the reference.
 * Call on lock, timeout, or exit to eliminate key material from memory.
 */
function zeroSessionKey() {
    if (sessionKey && Buffer.isBuffer(sessionKey)) {
        sessionKey.fill(0);
    }
    sessionKey = null;
}

/**
 * Check vault directory permissions on startup.
 * Warns if the directory has permissions wider than 0o700 (non-Windows).
 * Returns an array of warnings (empty = all good).
 */
function checkVaultPermissions() {
    const warnings = [];
    if (!fs.existsSync(VAULT_DIR)) return warnings;
    try {
        const stat = fs.statSync(VAULT_DIR);
        // On POSIX systems, check mode bits
        if (process.platform !== 'win32') {
            const mode = stat.mode & 0o777;
            if (mode & 0o077) { // group or other has access
                warnings.push(`Vault directory ${VAULT_DIR} has insecure permissions (${mode.toString(8)}). Expected 700.`);
                // Attempt to fix
                try {
                    fs.chmodSync(VAULT_DIR, 0o700);
                    warnings.push('Permissions auto-fixed to 700.');
                } catch {
                    warnings.push('Could not auto-fix permissions. Run: chmod 700 ' + VAULT_DIR);
                }
            }
        }
        // Check critical files within vault dir
        const criticalFiles = ['master.hash', 'vault.enc', 'lockout.key', 'lockout.enc'];
        for (const file of criticalFiles) {
            const filePath = path.join(VAULT_DIR, file);
            if (fs.existsSync(filePath) && process.platform !== 'win32') {
                const fstat = fs.statSync(filePath);
                const fmode = fstat.mode & 0o777;
                if (fmode & 0o077) {
                    warnings.push(`${file} has insecure permissions (${fmode.toString(8)}). Expected 600.`);
                    try {
                        fs.chmodSync(filePath, 0o600);
                    } catch { /* best effort */ }
                }
            }
        }
    } catch (err) {
        warnings.push(`Could not check vault permissions: ${err.message}`);
    }
    return warnings;
}

// ── Atomic File Write ──

function atomicWrite(filePath, data) {
    const tmpFile = filePath + '.tmp.' + Date.now();
    fs.writeFileSync(tmpFile, data, { mode: 0o600 });
    fs.renameSync(tmpFile, filePath);
}

module.exports = {
    isFirstRun,
    setupMasterPassword,
    verifyMasterPassword,
    changeMasterPassword,
    refreshActivity,
    isSessionExpired,
    setSessionTimeout,
    getVaultDir,
    ensureVaultDir,
    atomicWrite,
    createSessionKey,
    getSessionKey,
    zeroSessionKey,
    checkVaultPermissions,
    getLockoutState,
};
