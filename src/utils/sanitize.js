'use strict';

// ═══════════════════════════════════════════════════════════════
//  INPUT SANITIZATION
// ═══════════════════════════════════════════════════════════════

const MAX_FIELD_LENGTH = 500;
const MAX_NAME_LENGTH = 100;
const MAX_URL_LENGTH = 2048;
const MAX_NOTES_LENGTH = 2000;
const MAX_PASSWORD_LENGTH = 10240; // 10KB cap to prevent vault bloat

/**
 * Strip control characters (except newlines in notes).
 */
function stripControl(str, allowNewlines = false) {
    if (typeof str !== 'string') return '';
    if (allowNewlines) {
        // Keep \n and \r\n but strip other control chars
        return str.replace(/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F]/g, '');
    }
    return str.replace(/[\x00-\x1F\x7F]/g, '');
}

/**
 * Truncate string to max length.
 */
function truncate(str, maxLen) {
    if (typeof str !== 'string') return '';
    return str.length > maxLen ? str.substring(0, maxLen) : str;
}

/**
 * Sanitize a vault entry before storage.
 */
function sanitizeEntry(entry) {
    return {
        ...entry,
        name: truncate(stripControl(entry.name || ''), MAX_NAME_LENGTH),
        username: truncate(stripControl(entry.username || ''), MAX_FIELD_LENGTH),
        password: truncate(entry.password || '', MAX_PASSWORD_LENGTH), // Cap at 10KB, don't strip special chars
        url: truncate(stripControl(entry.url || ''), MAX_URL_LENGTH),
        notes: truncate(stripControl(entry.notes || '', true), MAX_NOTES_LENGTH),
    };
}

/**
 * Validate an entry has required fields.
 */
function validateEntry(entry) {
    const errors = [];
    if (!entry.name || entry.name.trim() === '') {
        errors.push('Service name is required');
    }
    return { valid: errors.length === 0, errors };
}

module.exports = { sanitizeEntry, validateEntry, stripControl, truncate };
