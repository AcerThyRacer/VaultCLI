'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getVaultDir } = require('../auth/master');

// ═══════════════════════════════════════════════════════════════
//  EMERGENCY WIPE — Panic Mode (Secure Data Destruction)
// ═══════════════════════════════════════════════════════════════

/**
 * Securely overwrite a file with random data before unlinking.
 * Performs 3-pass overwrite: random, zeros, random.
 */
function secureDelete(filePath) {
    if (!fs.existsSync(filePath)) return false;
    try {
        const stat = fs.statSync(filePath);
        const size = Math.max(stat.size, 1024); // At least 1KB overwrite
        // Pass 1: random data
        fs.writeFileSync(filePath, crypto.randomBytes(size));
        // Pass 2: zeros
        fs.writeFileSync(filePath, Buffer.alloc(size, 0));
        // Pass 3: random data
        fs.writeFileSync(filePath, crypto.randomBytes(size));
        // Finally unlink
        fs.unlinkSync(filePath);
        return true;
    } catch {
        // Best-effort: try regular delete if secure delete fails
        try { fs.unlinkSync(filePath); } catch { /* ignore */ }
        return false;
    }
}

/**
 * Emergency wipe — destroy ALL vault data.
 * Securely overwrites every file in the vault directory.
 * Returns a report of what was deleted.
 */
function emergencyWipe() {
    const vaultDir = getVaultDir();
    const report = { deleted: [], failed: [], totalFiles: 0 };

    if (!fs.existsSync(vaultDir)) {
        return { ...report, message: 'No vault directory found.' };
    }

    // Recursively find all files
    const files = getAllFiles(vaultDir);
    report.totalFiles = files.length;

    files.forEach(filePath => {
        if (secureDelete(filePath)) {
            report.deleted.push(path.relative(vaultDir, filePath));
        } else {
            report.failed.push(path.relative(vaultDir, filePath));
        }
    });

    // Remove empty subdirectories (bottom-up)
    const dirs = getAllDirs(vaultDir).reverse();
    dirs.forEach(dir => {
        try { fs.rmdirSync(dir); } catch { /* not empty or permission error */ }
    });

    // Remove vault directory itself
    try { fs.rmdirSync(vaultDir); } catch { /* may not be empty */ }

    report.message = `Wiped ${report.deleted.length}/${report.totalFiles} files.`;
    return report;
}

/**
 * Get all files recursively in a directory.
 */
function getAllFiles(dir) {
    const results = [];
    if (!fs.existsSync(dir)) return results;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    entries.forEach(entry => {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(...getAllFiles(fullPath));
        } else {
            results.push(fullPath);
        }
    });
    return results;
}

/**
 * Get all subdirectories recursively.
 */
function getAllDirs(dir) {
    const results = [];
    if (!fs.existsSync(dir)) return results;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    entries.forEach(entry => {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            results.push(fullPath);
            results.push(...getAllDirs(fullPath));
        }
    });
    return results;
}

module.exports = { emergencyWipe, secureDelete };
