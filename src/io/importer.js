'use strict';

const fs = require('fs');
const path = require('path');
const { decrypt } = require('../crypto/engine');

// ═══════════════════════════════════════════════════════════════
//  IMPORTER — CSV, JSON, and KeePass XML Import (Hardened)
// ═══════════════════════════════════════════════════════════════

const MAX_IMPORT_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_IMPORT_ENTRIES = 10000;

/**
 * Validate file size before reading.
 */
function validateFileSize(filePath) {
    const stats = fs.statSync(filePath);
    if (stats.size > MAX_IMPORT_SIZE) {
        throw new Error(`File too large (${(stats.size / 1024 / 1024).toFixed(1)}MB). Max: 10MB`);
    }
    if (stats.size === 0) {
        throw new Error('File is empty');
    }
}

/**
 * Parse CSV text into an array of objects.
 * Handles quoted fields with commas and escaped quotes.
 */
function parseCSV(csvText) {
    const lines = csvText.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 2) return [];

    const headers = parseCSVLine(lines[0]);
    const records = [];

    for (let i = 1; i < lines.length; i++) {
        const values = parseCSVLine(lines[i]);
        const record = {};
        headers.forEach((h, idx) => {
            record[h.trim().toLowerCase()] = values[idx] || '';
        });
        records.push(record);
    }

    return records;
}

/**
 * Parse a single CSV line, handling quoted fields.
 */
function parseCSVLine(line) {
    const fields = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        const next = line[i + 1];

        if (inQuotes) {
            if (char === '"' && next === '"') {
                current += '"';
                i++; // Skip escaped quote
            } else if (char === '"') {
                inQuotes = false;
            } else {
                current += char;
            }
        } else {
            if (char === '"') {
                inQuotes = true;
            } else if (char === ',') {
                fields.push(current);
                current = '';
            } else {
                current += char;
            }
        }
    }
    fields.push(current);
    return fields;
}

/**
 * Import from a generic CSV file.
 * Supports Chrome, Firefox, Bitwarden, 1Password, and VaultSecure CSV formats.
 * Returns normalized entries.
 */
function importFromCSV(filePath, preReadContent) {
    if (!preReadContent) validateFileSize(filePath);
    const content = preReadContent || fs.readFileSync(filePath, 'utf8');
    const records = parseCSV(content);

    if (records.length === 0) {
        return { entries: [], format: 'unknown', errors: ['No records found in CSV'] };
    }

    // Detect format by headers
    const firstRecord = records[0];
    const keys = Object.keys(firstRecord);
    let format = 'generic';

    if (keys.includes('login_uri') || keys.includes('login_username')) {
        format = 'bitwarden';
    } else if (keys.includes('web address') || keys.includes('title')) {
        format = '1password';
    } else if (keys.includes('url') && keys.includes('username') && keys.includes('password')) {
        // Chrome or generic
        if (keys.includes('name') || keys.includes('title')) {
            format = 'chrome';
        } else {
            format = 'generic';
        }
    }

    const entries = records.map(record => normalizeRecord(record, format)).filter(Boolean).slice(0, MAX_IMPORT_ENTRIES);
    const errors = records.length > MAX_IMPORT_ENTRIES ? [`Capped at ${MAX_IMPORT_ENTRIES} entries (${records.length} found)`] : [];
    return { entries, format, errors };
}

/**
 * Normalize a record from various formats to VaultSecure format.
 */
function normalizeRecord(record, format) {
    let entry = { name: '', username: '', password: '', url: '', notes: '' };

    switch (format) {
        case 'bitwarden':
            entry.name = record['name'] || record['folder'] || '';
            entry.username = record['login_username'] || '';
            entry.password = record['login_password'] || '';
            entry.url = record['login_uri'] || '';
            entry.notes = record['notes'] || '';
            break;

        case '1password':
            entry.name = record['title'] || '';
            entry.username = record['username'] || '';
            entry.password = record['password'] || '';
            entry.url = record['url'] || record['web address'] || '';
            entry.notes = record['notes'] || record['notesplain'] || '';
            break;

        case 'chrome':
            entry.name = record['name'] || record['title'] || extractDomain(record['url'] || '');
            entry.username = record['username'] || '';
            entry.password = record['password'] || '';
            entry.url = record['url'] || '';
            break;

        default:
            // Generic — try common field names
            entry.name = record['name'] || record['title'] || record['service'] || record['site'] || '';
            entry.username = record['username'] || record['user'] || record['email'] || record['login'] || '';
            entry.password = record['password'] || record['pass'] || record['pwd'] || '';
            entry.url = record['url'] || record['uri'] || record['website'] || record['web address'] || '';
            entry.notes = record['notes'] || record['note'] || record['comments'] || '';
            break;
    }

    // Skip entries with no useful data
    if (!entry.name && !entry.username && !entry.password) return null;

    // Auto-generate name from URL if missing
    if (!entry.name && entry.url) {
        entry.name = extractDomain(entry.url);
    }
    if (!entry.name) entry.name = 'Unnamed Import';

    return entry;
}

/**
 * Import from encrypted VaultSecure JSON export.
 */
function importFromEncryptedJSON(filePath, exportPassword) {
    validateFileSize(filePath);
    const content = fs.readFileSync(filePath, 'utf8');
    const exportData = JSON.parse(content);

    if (exportData.format !== 'vaultsecure-encrypted-export') {
        return { entries: [], errors: ['Not a VaultSecure encrypted export file'] };
    }

    try {
        const decrypted = decrypt(exportData.data, exportPassword);
        const payload = JSON.parse(decrypted);
        return { entries: payload.entries || [], format: 'vaultsecure', errors: [] };
    } catch (err) {
        return { entries: [], errors: ['Failed to decrypt — wrong password?'] };
    }
}

/**
 * Import from plaintext VaultSecure JSON export.
 */
function importFromJSON(filePath, preReadContent) {
    if (!preReadContent) validateFileSize(filePath);
    const content = preReadContent || fs.readFileSync(filePath, 'utf8');
    const data = JSON.parse(content);

    if (data.format === 'vaultsecure-export') {
        return { entries: data.entries || [], format: 'vaultsecure', errors: [] };
    }

    // Try to parse as a generic array
    if (Array.isArray(data)) {
        const entries = data.map(r => normalizeRecord(r, 'generic')).filter(Boolean);
        return { entries, format: 'generic-json', errors: [] };
    }

    return { entries: [], errors: ['Unrecognized JSON format'] };
}

/**
 * Import from KeePass XML export.
 * Parses the basic XML structure without external dependencies.
 */
function importFromKeePassXML(filePath, preReadContent) {
    if (!preReadContent) validateFileSize(filePath);
    const content = preReadContent || fs.readFileSync(filePath, 'utf8');
    const entries = [];
    const errors = [];

    // Simple XML parsing for KeePass export (no external deps)
    const entryRegex = /<Entry>([\s\S]*?)<\/Entry>/g;
    const stringRegex = /<String>\s*<Key>(.*?)<\/Key>\s*<Value[^>]*>(.*?)<\/Value>\s*<\/String>/g;

    let entryMatch;
    while ((entryMatch = entryRegex.exec(content)) !== null) {
        const entryXml = entryMatch[1];
        const fields = {};

        let stringMatch;
        const localRegex = new RegExp(stringRegex.source, 'g');
        while ((stringMatch = localRegex.exec(entryXml)) !== null) {
            const key = stringMatch[1].trim();
            const value = decodeXMLEntities(stringMatch[2].trim());
            fields[key] = value;
        }

        if (fields['Title'] || fields['UserName'] || fields['Password']) {
            entries.push({
                name: fields['Title'] || 'Unnamed',
                username: fields['UserName'] || '',
                password: fields['Password'] || '',
                url: fields['URL'] || '',
                notes: fields['Notes'] || '',
            });
        }
    }

    if (entries.length === 0 && content.includes('<KeePassFile>')) {
        errors.push('KeePass XML detected but no entries parsed. Ensure you exported as "KeePass XML 2.x".');
    }

    return { entries, format: 'keepass', errors };
}

/**
 * Auto-detect file format and import.
 * Reads file ONCE to prevent TOCTOU race conditions — the same buffer
 * is used for format detection and parsing.
 */
function autoImport(filePath) {
    const ext = path.extname(filePath).toLowerCase();

    // Read file once — all subsequent operations use this snapshot
    validateFileSize(filePath);
    const content = fs.readFileSync(filePath, 'utf8');

    if (ext === '.csv') {
        return importFromCSV(filePath, content);
    } else if (ext === '.json') {
        const data = JSON.parse(content);
        if (data.format === 'vaultsecure-encrypted-export') {
            return { needsPassword: true, format: 'vaultsecure-encrypted' };
        }
        return importFromJSON(filePath, content);
    } else if (ext === '.xml' || ext === '.kdbx') {
        if (ext === '.kdbx') {
            return { entries: [], errors: ['Cannot import .kdbx directly. Export from KeePass as XML first.'] };
        }
        return importFromKeePassXML(filePath, content);
    }

    return { entries: [], errors: [`Unsupported file format: ${ext}`] };
}

// ── Helpers ──

function extractDomain(url) {
    try {
        const u = new URL(url);
        return u.hostname.replace(/^www\./, '');
    } catch {
        return url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
    }
}

function decodeXMLEntities(str) {
    return str
        .replace(/&amp;/g, '&')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'");
}

module.exports = {
    importFromCSV,
    importFromEncryptedJSON,
    importFromJSON,
    importFromKeePassXML,
    autoImport,
    parseCSV,
};
