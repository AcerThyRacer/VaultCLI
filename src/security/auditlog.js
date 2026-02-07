'use strict';

const fs = require('fs');
const path = require('path');
const { encrypt, decrypt } = require('../crypto/engine');
const { getVaultDir, ensureVaultDir, atomicWrite } = require('../auth/master');

// ═══════════════════════════════════════════════════════════════
//  AUDIT LOG — Encrypted, with stderr fallback on failure
// ═══════════════════════════════════════════════════════════════

const LOG_FILE = path.join(getVaultDir(), 'audit.log.enc');
const AUTH_EVENTS_FILE = path.join(getVaultDir(), 'auth-events.log');
const MAX_LOG_ENTRIES = 500;
const MAX_AUTH_LOG_ENTRIES = 200;

const EVENT_TYPES = {
    LOGIN_SUCCESS: 'LOGIN_SUCCESS', LOGIN_FAILED: 'LOGIN_FAILED',
    LOCKOUT: 'LOCKOUT', VAULT_UNLOCK: 'VAULT_UNLOCK', VAULT_LOCK: 'VAULT_LOCK',
    ENTRY_ADD: 'ENTRY_ADD', ENTRY_VIEW: 'ENTRY_VIEW', ENTRY_EDIT: 'ENTRY_EDIT',
    ENTRY_DELETE: 'ENTRY_DELETE', PASSWORD_REVEAL: 'PASSWORD_REVEAL',
    PASSWORD_COPY: 'PASSWORD_COPY', PASSWORD_GENERATE: 'PASSWORD_GENERATE',
    MASTER_PW_CHANGE: 'MASTER_PW_CHANGE', EXPORT: 'EXPORT', IMPORT: 'IMPORT',
    SETTINGS_CHANGE: 'SETTINGS_CHANGE', INTEGRITY_CHECK: 'INTEGRITY_CHECK',
    SESSION_TIMEOUT: 'SESSION_TIMEOUT', BREACH_CHECK: 'BREACH_CHECK',
};

function loadLog(masterPassword) {
    ensureVaultDir();
    if (!fs.existsSync(LOG_FILE)) return [];
    try {
        const raw = fs.readFileSync(LOG_FILE, 'utf8');
        return JSON.parse(decrypt(JSON.parse(raw), masterPassword));
    } catch { return []; }
}

function saveLog(entries, masterPassword) {
    ensureVaultDir();
    const trimmed = entries.slice(-MAX_LOG_ENTRIES);
    const encrypted = encrypt(JSON.stringify(trimmed), masterPassword);
    atomicWrite(LOG_FILE, JSON.stringify(encrypted, null, 2));
}

/**
 * Record an audit event. Logs to stderr on failure instead of silently swallowing.
 * When masterPassword is null, delegates to logUnauthEvent for critical auth events.
 */
function logEvent(masterPassword, eventType, details = {}) {
    if (!masterPassword) {
        // Delegate to unauthenticated log for auth-related events
        logUnauthEvent(eventType, details);
        return;
    }
    try {
        const log = loadLog(masterPassword);
        log.push({
            timestamp: new Date().toISOString(),
            event: eventType,
            details: typeof details === 'string' ? { message: details } : details,
        });
        saveLog(log, masterPassword);
    } catch (err) {
        // Log failure to stderr — never silently swallow security events
        process.stderr.write(`[VaultSecure] Audit log failure: ${err.message}\n`);
    }
}

/**
 * Log an authentication event WITHOUT requiring the master password.
 * Used for failed logins and lockouts — the most critical events to audit.
 * Stored in a separate plaintext file (no sensitive vault data).
 */
function logUnauthEvent(eventType, details = {}) {
    try {
        ensureVaultDir();
        let entries = [];
        if (fs.existsSync(AUTH_EVENTS_FILE)) {
            try {
                entries = JSON.parse(fs.readFileSync(AUTH_EVENTS_FILE, 'utf8'));
            } catch { entries = []; }
        }
        entries.push({
            timestamp: new Date().toISOString(),
            event: eventType,
            details: typeof details === 'string' ? { message: details } : details,
        });
        // Trim to max entries
        if (entries.length > MAX_AUTH_LOG_ENTRIES) {
            entries = entries.slice(-MAX_AUTH_LOG_ENTRIES);
        }
        atomicWrite(AUTH_EVENTS_FILE, JSON.stringify(entries, null, 2));
    } catch (err) {
        process.stderr.write(`[VaultSecure] Auth event log failure: ${err.message}\n`);
    }
}

/**
 * Load unauthenticated auth events (no password required).
 */
function getAuthEvents(count = 20) {
    if (!fs.existsSync(AUTH_EVENTS_FILE)) return [];
    try {
        const entries = JSON.parse(fs.readFileSync(AUTH_EVENTS_FILE, 'utf8'));
        return entries.slice(-count).reverse();
    } catch { return []; }
}

function getRecentEvents(masterPassword, count = 20) {
    return loadLog(masterPassword).slice(-count).reverse();
}

function getEventsByType(masterPassword, eventType) {
    return loadLog(masterPassword).filter(e => e.event === eventType).reverse();
}

function getSecuritySummary(masterPassword) {
    const log = loadLog(masterPassword);
    const authLog = getAuthEvents(200);
    const now = Date.now();
    const last24h = log.filter(e => now - new Date(e.timestamp).getTime() < 86400000);
    const last7d = log.filter(e => now - new Date(e.timestamp).getTime() < 604800000);
    return {
        totalEvents: log.length, last24h: last24h.length, last7d: last7d.length,
        failedLogins: authLog.filter(e => e.event === EVENT_TYPES.LOGIN_FAILED).length,
        lockouts: authLog.filter(e => e.event === EVENT_TYPES.LOCKOUT).length,
        passwordReveals: log.filter(e => e.event === EVENT_TYPES.PASSWORD_REVEAL).length,
        exports: log.filter(e => e.event === EVENT_TYPES.EXPORT).length,
        lastLogin: log.filter(e => e.event === EVENT_TYPES.LOGIN_SUCCESS).pop(),
    };
}

function clearLog(masterPassword) { saveLog([], masterPassword); }

module.exports = { EVENT_TYPES, logEvent, logUnauthEvent, getAuthEvents, getRecentEvents, getEventsByType, getSecuritySummary, clearLog };
