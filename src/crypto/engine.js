'use strict';

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════
//  CRYPTO ENGINE — AES-256-GCM + PBKDF2 (Hardened)
//  Fixes: modulo bias, Buffer-based password handling, key zeroing
// ═══════════════════════════════════════════════════════════════

// ── Named Constants ──
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_DIGEST = 'sha512';
const KEY_LENGTH = 32;          // 256 bits
const SALT_LENGTH = 32;         // 256 bits
const IV_LENGTH = 12;           // 96 bits (GCM recommended)
const AUTH_TAG_LENGTH = 16;     // 128 bits
const DEFAULT_PASSWORD_LENGTH = 20;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;
const ID_LENGTH = 12;
const ID_CHARSET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/**
 * Derive a 256-bit key from a password using PBKDF2.
 * Accepts string or Buffer password.
 */
function deriveKey(password, salt) {
    const pw = typeof password === 'string' ? Buffer.from(password, 'utf8') : password;
    const key = crypto.pbkdf2Sync(pw, salt, PBKDF2_ITERATIONS, KEY_LENGTH, PBKDF2_DIGEST);
    // Zero the password buffer if we created it
    if (typeof password === 'string') pw.fill(0);
    return key;
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns { salt, iv, authTag, ciphertext } — all hex-encoded.
 */
function encrypt(plaintext, password) {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = deriveKey(password, salt);
    const iv = crypto.randomBytes(IV_LENGTH);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_LENGTH });
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    key.fill(0);

    return {
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: encrypted,
    };
}

/**
 * Decrypt ciphertext encrypted with AES-256-GCM.
 */
function decrypt(encryptedData, password) {
    const salt = Buffer.from(encryptedData.salt, 'hex');
    const iv = Buffer.from(encryptedData.iv, 'hex');
    const authTag = Buffer.from(encryptedData.authTag, 'hex');
    const key = deriveKey(password, salt);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    key.fill(0);
    return decrypted;
}

/**
 * Hash a master password for storage (verification only).
 * Returns { salt, hash } — hex-encoded.
 */
function hashPassword(password) {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const hash = deriveKey(password, salt);
    const result = { salt: salt.toString('hex'), hash: hash.toString('hex') };
    hash.fill(0);
    return result;
}

/**
 * Verify a password against a stored hash (constant-time).
 */
function verifyPassword(password, stored) {
    const salt = Buffer.from(stored.salt, 'hex');
    const derived = deriveKey(password, salt);
    const expected = Buffer.from(stored.hash, 'hex');
    const match = crypto.timingSafeEqual(derived, expected);
    derived.fill(0);
    return match;
}

/**
 * Generate a cryptographically secure random password.
 * Uses crypto.randomInt() to avoid modulo bias.
 */
function generatePassword(length = DEFAULT_PASSWORD_LENGTH, options = {}) {
    const {
        uppercase = true,
        lowercase = true,
        numbers = true,
        symbols = true,
    } = options;

    if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
        throw new Error(`Password length must be ${MIN_PASSWORD_LENGTH}–${MAX_PASSWORD_LENGTH}`);
    }

    let charset = '';
    if (lowercase) charset += 'abcdefghijkmnopqrstuvwxyz';
    if (uppercase) charset += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    if (numbers) charset += '23456789';
    if (symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) charset = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*';

    // Use crypto.randomInt() — uniform distribution, no modulo bias
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset[crypto.randomInt(charset.length)];
    }
    return password;
}

/**
 * Generate a cryptographically secure random ID.
 * Uses crypto.randomInt() to avoid modulo bias.
 */
function generateSecureId(length = ID_LENGTH) {
    let id = '';
    for (let i = 0; i < length; i++) {
        id += ID_CHARSET[crypto.randomInt(ID_CHARSET.length)];
    }
    return id;
}

/**
 * Derive a purpose-specific key from master password.
 * Used for HMAC integrity keys, etc.
 * Uses full PBKDF2 iterations for proper key stretching.
 */
function deriveSubKey(password, purpose, salt) {
    const purposeSalt = Buffer.concat([
        salt || crypto.randomBytes(SALT_LENGTH),
        Buffer.from(purpose, 'utf8'),
    ]);
    return crypto.pbkdf2Sync(password, purposeSalt, PBKDF2_ITERATIONS, KEY_LENGTH, PBKDF2_DIGEST);
}

/**
 * Constant-time string comparison.
 * Converts both strings to equal-length Buffers and uses timingSafeEqual.
 * Returns false if either is not a string.
 */
function constantTimeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

module.exports = {
    encrypt,
    decrypt,
    hashPassword,
    verifyPassword,
    generatePassword,
    generateSecureId,
    deriveSubKey,
    constantTimeEqual,
    // Constants exported for other modules
    SALT_LENGTH,
    KEY_LENGTH,
};
