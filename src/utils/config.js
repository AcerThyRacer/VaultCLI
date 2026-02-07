'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { getVaultDir, ensureVaultDir, atomicWrite } = require('../auth/master');

// ═══════════════════════════════════════════════════════════════
//  CONFIGURATION — User-adjustable settings with HMAC integrity
// ═══════════════════════════════════════════════════════════════

const CONFIG_FILE = path.join(getVaultDir(), 'config.json');
const CONFIG_KEY_FILE = path.join(getVaultDir(), 'config.key');

const DEFAULTS = {
    sessionTimeoutMinutes: 5,       // 1–30 minutes
    clipboardClearSeconds: 15,      // 5–120 seconds
    showBootAnimation: true,        // true/false
    colorTheme: 'cyberpunk',        // cyberpunk, minimal, retro, neon
    autoBackup: true,               // auto-backup vault before writes
    maxBackups: 5,                  // keep up to N backup files
    passwordAuditOnStart: false,    // auto-run audit on unlock
    privacyTimestamps: 'full',      // full, hour, or day
};

/**
 * Get or create a config signing key (random, stored locally).
 */
function getConfigKey() {
    ensureVaultDir();
    if (fs.existsSync(CONFIG_KEY_FILE)) {
        return fs.readFileSync(CONFIG_KEY_FILE, 'utf8').trim();
    }
    const key = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(CONFIG_KEY_FILE, key, { mode: 0o600 });
    return key;
}

/**
 * Compute HMAC for config data.
 */
function computeConfigHMAC(data) {
    const key = getConfigKey();
    return crypto.createHmac('sha256', key).update(data).digest('hex');
}

/**
 * Load config from disk, merged with defaults.
 * Verifies HMAC integrity — resets to defaults if tampered.
 */
function loadConfig() {
    ensureVaultDir();
    if (!fs.existsSync(CONFIG_FILE)) {
        return { ...DEFAULTS };
    }
    try {
        const raw = fs.readFileSync(CONFIG_FILE, 'utf8');
        const envelope = JSON.parse(raw);

        // Verify HMAC if present
        if (envelope._hmac) {
            const { _hmac, ...configData } = envelope;
            const expected = computeConfigHMAC(JSON.stringify(configData));
            if (!crypto.timingSafeEqual(Buffer.from(_hmac, 'hex'), Buffer.from(expected, 'hex'))) {
                process.stderr.write('[VaultSecure] Config HMAC mismatch — possible tampering. Using defaults.\n');
                return { ...DEFAULTS };
            }
            return { ...DEFAULTS, ...configData };
        }

        // Legacy config without HMAC — migrate by accepting and re-signing on next save
        return { ...DEFAULTS, ...envelope };
    } catch {
        return { ...DEFAULTS };
    }
}

/**
 * Save config to disk with HMAC signature.
 */
function saveConfig(config) {
    ensureVaultDir();
    const merged = { ...DEFAULTS, ...config };
    // Remove any existing _hmac before computing new one
    delete merged._hmac;
    const hmac = computeConfigHMAC(JSON.stringify(merged));
    const signed = { ...merged, _hmac: hmac };
    atomicWrite(CONFIG_FILE, JSON.stringify(signed, null, 2));
    return merged;
}

/**
 * Get a single config value.
 */
function getConfigValue(key) {
    const config = loadConfig();
    return config[key] !== undefined ? config[key] : DEFAULTS[key];
}

/**
 * Update a single config value.
 */
function setConfigValue(key, value) {
    const config = loadConfig();
    config[key] = value;
    return saveConfig(config);
}

/**
 * Get session timeout in milliseconds.
 */
function getSessionTimeoutMs() {
    const minutes = getConfigValue('sessionTimeoutMinutes');
    return Math.max(1, Math.min(30, minutes)) * 60 * 1000;
}

/**
 * Get clipboard clear delay in milliseconds.
 */
function getClipboardClearMs() {
    const seconds = getConfigValue('clipboardClearSeconds');
    return Math.max(5, Math.min(120, seconds)) * 1000;
}

module.exports = {
    loadConfig,
    saveConfig,
    getConfigValue,
    setConfigValue,
    getSessionTimeoutMs,
    getClipboardClearMs,
    DEFAULTS,
};

