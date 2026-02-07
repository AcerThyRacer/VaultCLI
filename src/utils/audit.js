'use strict';

const { COLORS } = require('../ui/ascii');

// ═══════════════════════════════════════════════════════════════
//  PASSWORD AUDIT — Scan for weak, reused, and old passwords
// ═══════════════════════════════════════════════════════════════

// Common weak passwords — top 200+ most breached (expanded from 31)
const COMMON_PASSWORDS = new Set([
    // Top 50
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 'master',
    'dragon', '111111', 'baseball', 'iloveyou', 'trustno1', 'sunshine',
    'letmein', 'football', 'shadow', '123123', '654321', 'superman',
    'qazwsx', 'michael', 'password1', 'password123', 'admin', 'welcome',
    'login', 'princess', 'starwars', 'passw0rd', 'hello', 'charlie',
    // 51–100
    'donald', 'login', 'admin123', 'qwerty123', '1q2w3e4r', 'master123',
    '1234', '12345', '123456789', '1234567890', 'nothing', 'access',
    'flower', 'hottie', 'loveme', 'zaq12wsx', 'jordan', 'robert',
    'matthew', 'daniel', 'andrew', 'joshua', 'ashley', 'pepper',
    'mustang', 'thomas', 'hockey', 'ranger', 'mercedes', 'secret',
    'hannah', 'amanda', 'banana', 'summer', 'ginger', 'jessica',
    'jennifer', 'michelle', 'alexander', 'thunder', 'nicole', 'monster',
    'silver', 'maggie', 'soccer', 'buster', 'bailey', 'killer',
    // 101–150
    'george', 'harley', 'orange', 'purple', 'sparky', 'cowboy',
    'camaro', 'matrix', 'falcon', 'cheese', 'cookie', 'coffee',
    'guitar', 'hunter', 'maverick', 'phoenix', 'midnight', 'morgan',
    'freedom', 'diamond', 'dallas', 'creative', 'internet', 'windows',
    'computer', 'corvette', 'ferrari', 'merlin', 'batman', 'eagle',
    'prince', 'junior', 'heaven', 'yankees', 'compaq', 'jasmine',
    'austin', 'bigdog', 'taylor', 'golfer', 'hammer', 'scooter',
    'jackie', 'golden', 'chicken', 'peanut', 'angel1', 'tiger',
    // 151–200+
    'samantha', 'brandon', 'william', 'raiders', 'patrick', 'yankee',
    'p@ssw0rd', 'P@ssw0rd', 'P@ssword1', 'Qwerty123', 'Password1',
    'Pass@123', 'Admin@123', 'Root@123', 'Test@123', 'User@123',
    'abcdef', 'abcd1234', 'aa123456', 'azerty', 'changeme', 'fuckyou',
    'trustno1', 'iloveu', 'passpass', 'test', 'test1', 'test123',
    'root', 'toor', 'passwd', 'default', 'guest', 'user',
    '1qaz2wsx', 'qwe123', 'zxcvbnm', 'asdfghjkl', 'qwertyuiop',
    '12341234', '11111111', '00000000', '88888888', '99999999',
    'letmein1', 'welcome1', 'password12', 'monkey123', 'dragon123',
    'shadow123', 'matrix1', 'master1', 'love', 'baby', 'angel',
    'rockyou', 'solo', 'star', 'ashley1', 'michael1', 'pass1',
]);

/**
 * Analyze a single password's strength.
 */
function analyzePassword(password) {
    const issues = [];
    let score = 100;

    // Length check
    if (password.length < 8) {
        issues.push({ severity: 'critical', message: 'Too short (< 8 chars)' });
        score -= 40;
    } else if (password.length < 12) {
        issues.push({ severity: 'warning', message: 'Short (< 12 chars)' });
        score -= 15;
    }

    // Character diversity
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);
    const diversity = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;

    if (diversity === 1) {
        issues.push({ severity: 'critical', message: 'Only one character type' });
        score -= 30;
    } else if (diversity === 2) {
        issues.push({ severity: 'warning', message: 'Low character diversity' });
        score -= 15;
    }

    // Common password check
    if (COMMON_PASSWORDS.has(password.toLowerCase())) {
        issues.push({ severity: 'critical', message: 'Common password detected' });
        score -= 50;
    }

    // Sequential/repeated characters
    if (/(.)\1{3,}/.test(password)) {
        issues.push({ severity: 'warning', message: 'Repeated characters (4+ in a row)' });
        score -= 15;
    }

    // Sequential numbers
    if (/(?:012|123|234|345|456|567|678|789|890)/.test(password)) {
        issues.push({ severity: 'warning', message: 'Sequential numbers detected' });
        score -= 10;
    }

    // Keyboard patterns
    const kbPatterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qwertz', 'azerty'];
    if (kbPatterns.some(p => password.toLowerCase().includes(p))) {
        issues.push({ severity: 'warning', message: 'Keyboard pattern detected' });
        score -= 15;
    }

    // Entropy calculation
    let charset = 0;
    if (hasLower) charset += 26;
    if (hasUpper) charset += 26;
    if (hasDigit) charset += 10;
    if (hasSymbol) charset += 32;
    const entropy = Math.floor(password.length * Math.log2(charset || 1));

    score = Math.max(0, Math.min(100, score));

    let rating;
    if (score >= 80) rating = 'STRONG';
    else if (score >= 60) rating = 'GOOD';
    else if (score >= 40) rating = 'FAIR';
    else if (score >= 20) rating = 'WEAK';
    else rating = 'CRITICAL';

    return { score, rating, issues, entropy, diversity };
}

/**
 * Run a full audit on all vault entries.
 */
function auditVault(entries) {
    const results = {
        totalEntries: entries.length,
        weakPasswords: [],
        reusedPasswords: [],
        oldPasswords: [],
        noPassword: [],
        summary: { critical: 0, warning: 0, strong: 0 },
    };

    // Track password reuse
    const passwordMap = new Map(); // password -> [entry names]

    const now = Date.now();
    const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

    entries.forEach(entry => {
        if (!entry.password || entry.password.trim() === '') {
            results.noPassword.push(entry);
            return;
        }

        // Strength check
        const analysis = analyzePassword(entry.password);
        if (analysis.score < 60) {
            results.weakPasswords.push({ entry, analysis });
        }

        // Reuse tracking
        const pwKey = entry.password;
        if (!passwordMap.has(pwKey)) {
            passwordMap.set(pwKey, []);
        }
        passwordMap.get(pwKey).push(entry);

        // Age check
        const updatedAt = new Date(entry.updatedAt || entry.createdAt).getTime();
        if (now - updatedAt > NINETY_DAYS_MS) {
            results.oldPasswords.push({
                entry,
                ageDays: Math.floor((now - updatedAt) / (24 * 60 * 60 * 1000)),
            });
        }
    });

    // Find reused passwords (more than 1 entry using the same password)
    for (const [pw, entriesUsingPw] of passwordMap) {
        if (entriesUsingPw.length > 1) {
            results.reusedPasswords.push({
                entries: entriesUsingPw,
                count: entriesUsingPw.length,
            });
        }
    }

    // Summary counts (use Sets to avoid double-counting entries with multiple issues)
    const criticalIds = new Set();
    const warningIds = new Set();

    results.weakPasswords.forEach(w => {
        if (w.analysis.score < 40) criticalIds.add(w.entry.id || w.entry.name);
        else warningIds.add(w.entry.id || w.entry.name);
    });
    results.noPassword.forEach(e => criticalIds.add(e.id || e.name));
    results.reusedPasswords.forEach(({ entries: reused }) => {
        reused.forEach(e => {
            if (!criticalIds.has(e.id || e.name)) warningIds.add(e.id || e.name);
        });
    });
    results.oldPasswords.forEach(({ entry }) => {
        if (!criticalIds.has(entry.id || entry.name)) warningIds.add(entry.id || entry.name);
    });

    results.summary.critical = criticalIds.size;
    results.summary.warning = warningIds.size;
    results.summary.strong = Math.max(0, entries.length - criticalIds.size - warningIds.size);

    return results;
}

/**
 * Format audit results for display.
 */
function formatAuditReport(results) {
    const lines = [];

    // Overall score
    const totalIssues = results.summary.critical + results.summary.warning;
    const overallScore = results.totalEntries > 0
        ? Math.round(((results.totalEntries - totalIssues) / results.totalEntries) * 100)
        : 100;

    let scoreColor;
    if (overallScore >= 80) scoreColor = COLORS.success;
    else if (overallScore >= 50) scoreColor = COLORS.warning;
    else scoreColor = COLORS.accent;

    lines.push(scoreColor(`\n  ╔════════════════════════════════════════════╗`));
    lines.push(scoreColor(`  ║     VAULT SECURITY SCORE: ${overallScore}%${' '.repeat(Math.max(0, 15 - String(overallScore).length))}║`));
    lines.push(scoreColor(`  ╚════════════════════════════════════════════╝\n`));

    lines.push(COLORS.dim(`  Total entries: ${results.totalEntries}`));
    lines.push(COLORS.success(`  ✓ Strong:   ${results.summary.strong}`));
    lines.push(COLORS.warning(`  ⚠ Warning:  ${results.summary.warning}`));
    lines.push(COLORS.accent(`  ✗ Critical: ${results.summary.critical}`));
    lines.push('');

    // Weak passwords
    if (results.weakPasswords.length > 0) {
        lines.push(COLORS.accent('  ── WEAK PASSWORDS ──'));
        results.weakPasswords.forEach(({ entry, analysis }) => {
            const icon = analysis.score < 40 ? COLORS.accent('✗') : COLORS.warning('⚠');
            lines.push(`  ${icon} ${COLORS.white(entry.name)} ${COLORS.dim(`(${entry.username || '—'})`)} — ${COLORS.dim(`Score: ${analysis.score}/100`)}`);
            analysis.issues.forEach(issue => {
                const issueColor = issue.severity === 'critical' ? COLORS.accent : COLORS.warning;
                lines.push(`    ${issueColor('→')} ${COLORS.dim(issue.message)}`);
            });
        });
        lines.push('');
    }

    // Reused passwords
    if (results.reusedPasswords.length > 0) {
        lines.push(COLORS.warning('  ── REUSED PASSWORDS ──'));
        results.reusedPasswords.forEach(({ entries, count }) => {
            lines.push(COLORS.warning(`  ⚠ ${count} entries share the same password:`));
            entries.forEach(e => {
                lines.push(COLORS.dim(`    → ${e.name} (${e.username || '—'})`));
            });
        });
        lines.push('');
    }

    // Old passwords
    if (results.oldPasswords.length > 0) {
        lines.push(COLORS.warning('  ── PASSWORDS OLDER THAN 90 DAYS ──'));
        results.oldPasswords.forEach(({ entry, ageDays }) => {
            lines.push(COLORS.warning(`  ⚠ ${COLORS.white(entry.name)} ${COLORS.dim(`— ${ageDays} days old`)}`));
        });
        lines.push('');
    }

    // No password entries
    if (results.noPassword.length > 0) {
        lines.push(COLORS.accent('  ── MISSING PASSWORDS ──'));
        results.noPassword.forEach(entry => {
            lines.push(COLORS.accent(`  ✗ ${entry.name} ${COLORS.dim('— no password set')}`));
        });
        lines.push('');
    }

    if (totalIssues === 0) {
        lines.push(COLORS.success('  ✦ All passwords are strong! No issues found.\n'));
    }

    return lines.join('\n');
}

module.exports = { analyzePassword, auditVault, formatAuditReport };
