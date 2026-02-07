'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { encrypt, decrypt, generateSecureId } = require('../crypto/engine');
const { getVaultDir, ensureVaultDir, atomicWrite } = require('../auth/master');
const { sanitizeEntry, validateEntry } = require('../utils/sanitize');
const { getConfigValue } = require('../utils/config');

// ═══════════════════════════════════════════════════════════════
//  ENCRYPTED VAULT STORE (Hardened — Per-Entry Salt, Privacy)
// ═══════════════════════════════════════════════════════════════

const VAULT_FILE = path.join(getVaultDir(), 'vault.enc');
const MAX_BACKUPS = 5;
const MAX_HISTORY = 5;

/**
 * Encrypt a password with a per-entry salt.
 * Returns { encrypted: hex, salt: hex, iv: hex, tag: hex }
 */
function encryptEntryPassword(password, masterPassword) {
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, 'sha256');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let enc = cipher.update(password, 'utf8', 'hex');
    enc += cipher.final('hex');
    const tag = cipher.getAuthTag();
    return { encrypted: enc, salt: salt.toString('hex'), iv: iv.toString('hex'), tag: tag.toString('hex') };
}

/**
 * Decrypt a per-entry encrypted password.
 */
function decryptEntryPassword(encData, masterPassword) {
    if (!encData || !encData.encrypted) return encData; // Not encrypted (legacy)
    const key = crypto.pbkdf2Sync(masterPassword, Buffer.from(encData.salt, 'hex'), 100000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encData.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(encData.tag, 'hex'));
    let dec = decipher.update(encData.encrypted, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
}

/**
 * Create a privacy-aware timestamp.
 * Privacy mode rounds timestamps to reduce precision.
 */
function privacyTimestamp() {
    const mode = getConfigValue('privacyTimestamps') || 'full';
    const now = new Date();
    if (mode === 'day') {
        return now.toISOString().split('T')[0] + 'T00:00:00.000Z';
    } else if (mode === 'hour') {
        now.setMinutes(0, 0, 0);
        return now.toISOString();
    }
    return now.toISOString();
}

// ── Backup System ──

function createBackup() {
    if (!fs.existsSync(VAULT_FILE)) return;
    const backupDir = path.join(getVaultDir(), 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    try { fs.copyFileSync(VAULT_FILE, path.join(backupDir, `vault-${timestamp}.enc.bak`)); } catch { }
    pruneBackups(backupDir);
}

function pruneBackups(backupDir) {
    try {
        const files = fs.readdirSync(backupDir)
            .filter(f => f.endsWith('.enc.bak'))
            .map(f => ({ name: f, path: path.join(backupDir, f), time: fs.statSync(path.join(backupDir, f)).mtimeMs }))
            .sort((a, b) => b.time - a.time);
        if (files.length > MAX_BACKUPS) files.slice(MAX_BACKUPS).forEach(f => { try { fs.unlinkSync(f.path); } catch { } });
    } catch { }
}

function listBackups() {
    const backupDir = path.join(getVaultDir(), 'backups');
    if (!fs.existsSync(backupDir)) return [];
    return fs.readdirSync(backupDir).filter(f => f.endsWith('.enc.bak'))
        .map(f => { const s = fs.statSync(path.join(backupDir, f)); return { name: f, path: path.join(backupDir, f), size: s.size, date: s.mtime }; })
        .sort((a, b) => b.date - a.date);
}

function restoreBackup(backupPath) {
    if (!fs.existsSync(backupPath)) return false;
    createBackup();
    fs.copyFileSync(backupPath, VAULT_FILE);
    return true;
}

// ── Core CRUD (Atomic Writes) ──

function loadVault(masterPassword) {
    ensureVaultDir();
    if (!fs.existsSync(VAULT_FILE)) return [];
    try {
        const raw = fs.readFileSync(VAULT_FILE, 'utf8');
        const encryptedData = JSON.parse(raw);
        const decrypted = decrypt(encryptedData, masterPassword);
        return JSON.parse(decrypted);
    } catch (err) {
        if (err.message && err.message.includes('Unsupported state')) throw new Error('DECRYPTION_FAILED');
        throw err;
    }
}

/**
 * Save vault with atomic write (temp + rename) to prevent corruption.
 */
function saveVault(entries, masterPassword) {
    ensureVaultDir();
    createBackup();
    const plaintext = JSON.stringify(entries, null, 2);
    const encrypted = encrypt(plaintext, masterPassword);
    atomicWrite(VAULT_FILE, JSON.stringify(encrypted, null, 2));
}

function addEntry(masterPassword, entry) {
    const sanitized = sanitizeEntry(entry);
    const validation = validateEntry(sanitized);
    if (!validation.valid) throw new Error(validation.errors.join(', '));

    const entries = loadVault(masterPassword);

    // Duplicate detection
    const dupe = entries.find(e =>
        e.name.toLowerCase() === sanitized.name.toLowerCase() &&
        (e.username || '').toLowerCase() === (sanitized.username || '').toLowerCase()
    );

    const newEntry = {
        id: generateSecureId(),
        name: sanitized.name,
        username: sanitized.username,
        password: encryptEntryPassword(sanitized.password, masterPassword),
        url: sanitized.url,
        notes: sanitized.notes,
        category: entry.category || 'none',
        favorite: entry.favorite || false,
        tags: entry.tags || [],
        totp: entry.totp || null,
        secureNotes: entry.secureNotes || null,
        expiryDays: entry.expiryDays || null,
        history: [],
        createdAt: privacyTimestamp(),
        updatedAt: privacyTimestamp(),
        _isDuplicate: !!dupe, // flag for menu to warn
    };
    entries.push(newEntry);
    saveVault(entries, masterPassword);
    return newEntry;
}

function bulkAddEntries(masterPassword, newEntries) {
    const entries = loadVault(masterPassword);
    const added = [];
    newEntries.forEach(entry => {
        const sanitized = sanitizeEntry(entry);
        const newEntry = {
            id: generateSecureId(),
            name: sanitized.name || 'Unnamed',
            username: sanitized.username,
            password: encryptEntryPassword(sanitized.password, masterPassword),
            url: sanitized.url,
            notes: sanitized.notes,
            category: entry.category || 'none',
            favorite: false, tags: [], totp: null, secureNotes: null,
            expiryDays: null, history: [],
            createdAt: privacyTimestamp(),
            updatedAt: privacyTimestamp(),
        };
        entries.push(newEntry);
        added.push(newEntry);
    });
    saveVault(entries, masterPassword);
    return added;
}

function updateEntry(masterPassword, id, updates) {
    const entries = loadVault(masterPassword);
    const idx = entries.findIndex(e => e.id === id);
    if (idx === -1) return null;
    const old = entries[idx];

    // Track password history (encrypt if changing)
    if (updates.password) {
        if (!old.history) old.history = [];
        old.history.push({ password: old.password, changedAt: privacyTimestamp() });
        if (old.history.length > MAX_HISTORY) old.history = old.history.slice(-MAX_HISTORY);
        updates.password = encryptEntryPassword(updates.password, masterPassword);
    }

    const sanitized = sanitizeEntry({ ...old, ...updates });
    entries[idx] = {
        ...old, ...sanitized,
        password: updates.password || old.password, // Keep encrypted password
        category: updates.category !== undefined ? updates.category : old.category,
        favorite: updates.favorite !== undefined ? updates.favorite : old.favorite,
        tags: updates.tags !== undefined ? updates.tags : (old.tags || []),
        totp: updates.totp !== undefined ? updates.totp : old.totp,
        secureNotes: updates.secureNotes !== undefined ? updates.secureNotes : old.secureNotes,
        expiryDays: updates.expiryDays !== undefined ? updates.expiryDays : old.expiryDays,
        history: old.history || [],
        updatedAt: privacyTimestamp(),
    };
    delete entries[idx]._isDuplicate;
    saveVault(entries, masterPassword);
    return entries[idx];
}

function listEntries(masterPassword) { return loadVault(masterPassword); }

function searchEntries(masterPassword, query) {
    const entries = loadVault(masterPassword);
    const q = query.toLowerCase();
    return entries.filter(e =>
        (e.name && e.name.toLowerCase().includes(q)) ||
        (e.username && e.username.toLowerCase().includes(q)) ||
        (e.url && e.url.toLowerCase().includes(q)) ||
        (e.category && e.category.toLowerCase().includes(q)) ||
        (e.tags && e.tags.some(t => t.toLowerCase().includes(q)))
    );
}

function getEntry(masterPassword, id) {
    return loadVault(masterPassword).find(e => e.id === id) || null;
}

function deleteEntry(masterPassword, id) {
    const entries = loadVault(masterPassword);
    const idx = entries.findIndex(e => e.id === id);
    if (idx === -1) return false;
    entries.splice(idx, 1);
    saveVault(entries, masterPassword);
    return true;
}

function toggleFavorite(masterPassword, id) {
    const entries = loadVault(masterPassword);
    const idx = entries.findIndex(e => e.id === id);
    if (idx === -1) return null;
    entries[idx].favorite = !entries[idx].favorite;
    entries[idx].updatedAt = privacyTimestamp();
    saveVault(entries, masterPassword);
    return entries[idx];
}

function getExpiringEntries(masterPassword) {
    const entries = loadVault(masterPassword);
    const now = Date.now();
    return entries.filter(e => {
        if (!e.expiryDays) return false;
        const updated = new Date(e.updatedAt || e.createdAt).getTime();
        return (now - updated) >= (e.expiryDays * 86400000);
    }).map(e => {
        const ageDays = Math.floor((now - new Date(e.updatedAt || e.createdAt).getTime()) / 86400000);
        return { ...e, ageDays, overdueDays: ageDays - (e.expiryDays || 90) };
    });
}

function getStats(masterPassword) {
    const entries = loadVault(masterPassword);
    const categories = {};
    let favorites = 0, withTotp = 0;
    entries.forEach(e => {
        categories[e.category || 'none'] = (categories[e.category || 'none'] || 0) + 1;
        if (e.favorite) favorites++;
        if (e.totp) withTotp++;
    });
    return {
        totalEntries: entries.length, favorites, withTotp, categories,
        lastModified: entries.length > 0 ? entries.reduce((l, e) => e.updatedAt > l ? e.updatedAt : l, entries[0].updatedAt) : null
    };
}

function reEncryptVault(oldPassword, newPassword) {
    const entries = loadVault(oldPassword);
    saveVault(entries, newPassword);
    return entries.length;
}

module.exports = {
    addEntry, bulkAddEntries, listEntries, searchEntries, getEntry, updateEntry,
    deleteEntry, toggleFavorite, getExpiringEntries, getStats, reEncryptVault,
    listBackups, restoreBackup, loadVault, saveVault,
    encryptEntryPassword, decryptEntryPassword, privacyTimestamp,
};
