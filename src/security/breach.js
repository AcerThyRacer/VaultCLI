'use strict';

const crypto = require('crypto');
const https = require('https');

// ═══════════════════════════════════════════════════════════════
//  BREACH CHECKER — HaveIBeenPwned k-Anonymity API
//  Checks passwords against known breaches without revealing them
// ═══════════════════════════════════════════════════════════════

const HIBP_API = 'https://api.pwnedpasswords.com/range/';
const TIMEOUT_MS = 5000;

/**
 * Check if a password has been found in known data breaches.
 * Uses k-anonymity: only first 5 chars of SHA-1 hash are sent.
 * Returns { breached: boolean, count: number }
 */
async function checkBreach(password) {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    try {
        const body = await httpGet(`${HIBP_API}${prefix}`);
        const lines = body.split('\n');

        for (const line of lines) {
            const [hash, count] = line.trim().split(':');
            if (hash === suffix) {
                return { breached: true, count: parseInt(count, 10) };
            }
        }
        return { breached: false, count: 0 };
    } catch (err) {
        return { breached: null, count: 0, error: err.message };
    }
}

/**
 * Batch check multiple entries for breaches.
 * Rate-limits to avoid hammering the API.
 */
async function checkBreaches(entries, onProgress) {
    const results = [];
    for (let i = 0; i < entries.length; i++) {
        const entry = entries[i];
        if (!entry.password) {
            results.push({ entry, breached: false, count: 0 });
            continue;
        }

        const result = await checkBreach(entry.password);
        results.push({ entry, ...result });

        if (onProgress) onProgress(i + 1, entries.length, entry.name, result);

        // Rate limit: 100ms between requests
        if (i < entries.length - 1) await sleep(100);
    }

    return {
        total: entries.length,
        breached: results.filter(r => r.breached).length,
        safe: results.filter(r => r.breached === false).length,
        errors: results.filter(r => r.breached === null).length,
        results: results.sort((a, b) => (b.count || 0) - (a.count || 0)),
    };
}

// ── Helpers ──

function httpGet(url) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { timeout: TIMEOUT_MS }, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode}`));
                res.resume();
                return;
            }
            let data = '';
            res.on('data', chunk => { data += chunk; });
            res.on('end', () => resolve(data));
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
}

const { sleep } = require('../utils/sleep');

module.exports = { checkBreach, checkBreaches };
