'use strict';

const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════
//  TOTP — Time-based One-Time Password (RFC 6238)
//  Pure Node.js implementation — no external dependencies
// ═══════════════════════════════════════════════════════════════

const DEFAULT_PERIOD = 30;   // seconds
const DEFAULT_DIGITS = 6;
const DEFAULT_ALGORITHM = 'sha1';

/**
 * Decode a base32 string into a Buffer.
 */
function base32Decode(encoded) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleaned = encoded.replace(/[\s=-]/g, '').toUpperCase();

    let bits = '';
    for (const char of cleaned) {
        const val = alphabet.indexOf(char);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }

    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.substring(i, i + 8), 2));
    }

    return Buffer.from(bytes);
}

/**
 * Encode a Buffer to base32.
 */
function base32Encode(buffer) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const byte of buffer) {
        bits += byte.toString(2).padStart(8, '0');
    }

    let result = '';
    for (let i = 0; i < bits.length; i += 5) {
        const chunk = bits.substring(i, i + 5).padEnd(5, '0');
        result += alphabet[parseInt(chunk, 2)];
    }

    return result;
}

/**
 * Generate HMAC-based OTP value.
 */
function generateHOTP(secret, counter, digits = DEFAULT_DIGITS, algorithm = DEFAULT_ALGORITHM) {
    const key = base32Decode(secret);

    // Counter as 8-byte big-endian buffer
    const counterBuf = Buffer.alloc(8);
    let c = counter;
    for (let i = 7; i >= 0; i--) {
        counterBuf[i] = c & 0xff;
        c = Math.floor(c / 256);
    }

    const hmac = crypto.createHmac(algorithm, key);
    hmac.update(counterBuf);
    const hash = hmac.digest();

    // Dynamic truncation
    const offset = hash[hash.length - 1] & 0x0f;
    const code = (
        ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        (hash[offset + 3] & 0xff)
    ) % (10 ** digits);

    return String(code).padStart(digits, '0');
}

/**
 * Generate a TOTP code for the current time.
 */
function generateTOTP(secret, options = {}) {
    const {
        period = DEFAULT_PERIOD,
        digits = DEFAULT_DIGITS,
        algorithm = DEFAULT_ALGORITHM,
        timestamp = Date.now(),
    } = options;

    const counter = Math.floor(timestamp / 1000 / period);
    const code = generateHOTP(secret, counter, digits, algorithm);

    // Time remaining
    const elapsed = (timestamp / 1000) % period;
    const remaining = Math.ceil(period - elapsed);

    return { code, remaining, period };
}

/**
 * Generate a new random TOTP secret.
 */
function generateSecret(length = 20) {
    const bytes = crypto.randomBytes(length);
    return base32Encode(bytes);
}

/**
 * Build an otpauth:// URI for QR code generation.
 */
function buildOtpAuthURI(secret, issuer, account, options = {}) {
    const {
        period = DEFAULT_PERIOD,
        digits = DEFAULT_DIGITS,
        algorithm = DEFAULT_ALGORITHM,
    } = options;

    const label = encodeURIComponent(`${issuer}:${account}`);
    const params = new URLSearchParams({
        secret,
        issuer: encodeURIComponent(issuer),
        algorithm: algorithm.toUpperCase(),
        digits: String(digits),
        period: String(period),
    });

    return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Parse an otpauth:// URI.
 */
function parseOtpAuthURI(uri) {
    try {
        const url = new URL(uri);
        if (url.protocol !== 'otpauth:') return null;

        const label = decodeURIComponent(url.pathname.replace(/^\/\/totp\//, ''));
        const parts = label.split(':');

        return {
            type: 'totp',
            issuer: url.searchParams.get('issuer') || (parts.length > 1 ? parts[0] : ''),
            account: parts.length > 1 ? parts[1] : parts[0],
            secret: url.searchParams.get('secret') || '',
            algorithm: (url.searchParams.get('algorithm') || 'SHA1').toLowerCase(),
            digits: parseInt(url.searchParams.get('digits') || '6', 10),
            period: parseInt(url.searchParams.get('period') || '30', 10),
        };
    } catch {
        return null;
    }
}

/**
 * Verify a TOTP code (allows ±1 window for clock skew).
 * Uses constant-time comparison to prevent timing side-channel attacks.
 */
function verifyTOTP(secret, code, options = {}) {
    const { period = DEFAULT_PERIOD, digits = DEFAULT_DIGITS, algorithm = DEFAULT_ALGORITHM, window = 1 } = options;
    const now = Math.floor(Date.now() / 1000 / period);

    // Constant-time comparison helper
    const safeEqual = (a, b) => {
        const bufA = Buffer.from(String(a), 'utf8');
        const bufB = Buffer.from(String(b), 'utf8');
        if (bufA.length !== bufB.length) return false;
        return crypto.timingSafeEqual(bufA, bufB);
    };

    // Must check ALL windows to avoid early-exit timing leak
    let matched = false;
    for (let i = -window; i <= window; i++) {
        const expected = generateHOTP(secret, now + i, digits, algorithm);
        if (safeEqual(expected, code)) matched = true;
    }
    return matched;
}

module.exports = {
    generateTOTP,
    generateHOTP,
    generateSecret,
    verifyTOTP,
    buildOtpAuthURI,
    parseOtpAuthURI,
    base32Decode,
    base32Encode,
};
