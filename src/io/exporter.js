'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { encrypt, decrypt } = require('../crypto/engine');
const { getVaultDir, ensureVaultDir, atomicWrite } = require('../auth/master');

// ═══════════════════════════════════════════════════════════════
//  EXPORTER — CSV and Encrypted JSON Export
// ═══════════════════════════════════════════════════════════════

/**
 * Sanitize a CSV cell value to prevent formula injection.
 * Prefixes cells starting with =, +, -, or @ with a tab character
 * so spreadsheet apps don't interpret them as formulas.
 */
function csvSafeValue(val) {
    const str = String(val);
    if (/^[=+\-@]/.test(str)) {
        return '\t' + str;
    }
    return str;
}

/**
 * Export vault entries to CSV format.
 * @param {Array} entries - Decrypted vault entries
 * @param {string} outputPath - Where to save the CSV
 * @param {boolean} includePasswords - Whether to include plaintext passwords
 */
function exportToCSV(entries, outputPath, includePasswords = false, options = {}) {
    let headers = ['name', 'username', 'password', 'url', 'notes', 'createdAt', 'updatedAt'];
    if (options.stripTimestamps) {
        headers = headers.filter(h => h !== 'createdAt' && h !== 'updatedAt');
    }
    const rows = [headers.join(',')];

    entries.forEach(entry => {
        const row = headers.map(h => {
            let val = entry[h] || '';
            if (h === 'password' && !includePasswords) {
                val = '********';
            }
            // Sanitize against formula injection, then escape CSV
            val = csvSafeValue(val);
            val = String(val).replace(/"/g, '""');
            return `"${val}"`;
        });
        rows.push(row.join(','));
    });

    const csv = rows.join('\n');
    atomicWrite(outputPath, csv);
    return { path: outputPath, entries: entries.length, includesPasswords: includePasswords };
}

/**
 * Export vault entries to encrypted JSON.
 * Uses a separate export password for portability.
 */
function exportToEncryptedJSON(entries, outputPath, exportPassword, options = {}) {
    const payload = {
        format: 'vaultsecure-export',
        version: '1.0',
        exportedAt: options.stripTimestamps ? '[REDACTED]' : new Date().toISOString(),
        entryCount: entries.length,
        entries: options.stripTimestamps ? entries.map(e => {
            const { createdAt, updatedAt, ...rest } = e;
            return rest;
        }) : entries,
    };

    const plaintext = JSON.stringify(payload, null, 2);
    const encrypted = encrypt(plaintext, exportPassword);

    const exportData = {
        format: 'vaultsecure-encrypted-export',
        version: '1.0',
        data: encrypted,
    };

    // Atomic write: write to temp file first, then rename
    atomicWrite(outputPath, JSON.stringify(exportData, null, 2));
    return { path: outputPath, entries: entries.length };
}

/**
 * Export vault entries to plaintext JSON (unencrypted — for advanced users).
 */
function exportToJSON(entries, outputPath, options = {}) {
    const payload = {
        format: 'vaultsecure-export',
        version: '1.0',
        exportedAt: options.stripTimestamps ? '[REDACTED]' : new Date().toISOString(),
        entryCount: entries.length,
        entries: entries.map(e => {
            const base = {
                name: e.name,
                username: e.username,
                password: e.password,
                url: e.url,
                notes: e.notes,
            };
            if (!options.stripTimestamps) {
                base.createdAt = e.createdAt;
                base.updatedAt = e.updatedAt;
            }
            return base;
        }),
    };

    // Atomic write: write to temp file first, then rename
    atomicWrite(outputPath, JSON.stringify(payload, null, 2));
    return { path: outputPath, entries: entries.length };
}

/**
 * Get default export directory (Desktop or home).
 */
function getDefaultExportDir() {
    const desktop = path.join(os.homedir(), 'Desktop');
    if (fs.existsSync(desktop)) return desktop;
    return os.homedir();
}

module.exports = { exportToCSV, exportToEncryptedJSON, exportToJSON, getDefaultExportDir, csvSafeValue };

