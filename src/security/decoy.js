'use strict';

const fs = require('fs');
const path = require('path');
const { encrypt, decrypt, hashPassword, verifyPassword, generateSecureId } = require('../crypto/engine');
const { getVaultDir, ensureVaultDir, atomicWrite } = require('../auth/master');
const { sanitizeEntry, validateEntry } = require('../utils/sanitize');

// ═══════════════════════════════════════════════════════════════
//  DECOY VAULT — Fully functional plausible deniability
// ═══════════════════════════════════════════════════════════════

const DECOY_VAULT_FILE = path.join(getVaultDir(), 'vault.decoy.enc');
const DECOY_HASH_FILE = path.join(getVaultDir(), 'decoy.hash');

function hasDecoyVault() { return fs.existsSync(DECOY_HASH_FILE); }

function createDecoyVault(decoyPassword) {
    ensureVaultDir();
    const hashed = hashPassword(decoyPassword);
    atomicWrite(DECOY_HASH_FILE, JSON.stringify(hashed, null, 2));
    const encrypted = encrypt('[]', decoyPassword);
    atomicWrite(DECOY_VAULT_FILE, JSON.stringify(encrypted, null, 2));
    return true;
}

function isDecoyPassword(password) {
    if (!hasDecoyVault()) return false;
    try {
        const stored = JSON.parse(fs.readFileSync(DECOY_HASH_FILE, 'utf8'));
        return verifyPassword(password, stored);
    } catch { return false; }
}

// ── Full CRUD for decoy vault ──

function loadDecoyVault(decoyPassword) {
    if (!fs.existsSync(DECOY_VAULT_FILE)) return [];
    try {
        const raw = fs.readFileSync(DECOY_VAULT_FILE, 'utf8');
        const encrypted = JSON.parse(raw);
        return JSON.parse(decrypt(encrypted, decoyPassword));
    } catch { return []; }
}

function saveDecoyVault(entries, decoyPassword) {
    ensureVaultDir();
    const encrypted = encrypt(JSON.stringify(entries, null, 2), decoyPassword);
    atomicWrite(DECOY_VAULT_FILE, JSON.stringify(encrypted, null, 2));
}

function addDecoyEntry(decoyPassword, entry) {
    // Apply same sanitization as real vault
    const sanitized = sanitizeEntry(entry);
    const validation = validateEntry(sanitized);
    if (!validation.valid) {
        throw new Error(`Invalid entry: ${validation.errors.join(', ')}`);
    }

    const entries = loadDecoyVault(decoyPassword);
    const newEntry = {
        id: generateSecureId(),
        name: sanitized.name || '', username: sanitized.username || '',
        password: sanitized.password || '', url: sanitized.url || '',
        notes: sanitized.notes || '', category: 'none', favorite: false,
        tags: [], totp: null, secureNotes: null, expiryDays: null, history: [],
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    entries.push(newEntry);
    saveDecoyVault(entries, decoyPassword);
    return newEntry;
}

function deleteDecoyEntry(decoyPassword, id) {
    const entries = loadDecoyVault(decoyPassword);
    const idx = entries.findIndex(e => e.id === id);
    if (idx === -1) return false;
    entries.splice(idx, 1);
    saveDecoyVault(entries, decoyPassword);
    return true;
}

function listDecoyEntries(decoyPassword) { return loadDecoyVault(decoyPassword); }

module.exports = {
    hasDecoyVault, createDecoyVault, isDecoyPassword,
    loadDecoyVault, saveDecoyVault, addDecoyEntry,
    deleteDecoyEntry, listDecoyEntries,
};
