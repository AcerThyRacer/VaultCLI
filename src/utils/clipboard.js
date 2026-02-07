'use strict';

const clipboardy = require('clipboardy');
const { COLORS } = require('../ui/ascii');

// ═══════════════════════════════════════════════════════════════
//  CLIPBOARD UTILITY — Copy + Auto-Clear
// ═══════════════════════════════════════════════════════════════

/**
 * Get clipboard clear delay from config (or default 15s).
 */
function getClearDelayMs() {
    try {
        const { getClipboardClearMs } = require('./config');
        return getClipboardClearMs();
    } catch {
        return 15000;
    }
}

let clearTimer = null;

/**
 * Copy text to clipboard and auto-clear after 15 seconds.
 * Returns true on success.
 */
function copyToClipboard(text) {
    try {
        clipboardy.writeSync(text);
        scheduleClipboardClear(text);
        return true;
    } catch (err) {
        return false;
    }
}

/**
 * Schedule clipboard clear after CLEAR_DELAY_MS.
 * Only clears if clipboard still contains the copied password.
 */
function scheduleClipboardClear(originalText) {
    // Cancel any previous timer
    if (clearTimer) {
        clearTimeout(clearTimer);
    }

    clearTimer = setTimeout(() => {
        try {
            const current = clipboardy.readSync();
            if (current === originalText) {
                clipboardy.writeSync('');
                process.stdout.write(COLORS.dim('\n  🧹 Clipboard auto-cleared for security.\n'));
            }
        } catch {
            // Silently fail — clipboard may be unavailable
        }
        clearTimer = null;
    }, getClearDelayMs());

    // Don't hold the process open
    if (clearTimer && clearTimer.unref) {
        clearTimer.unref();
    }
}

/**
 * Immediately clear the clipboard.
 */
function clearClipboard() {
    try {
        clipboardy.writeSync('');
        if (clearTimer) {
            clearTimeout(clearTimer);
            clearTimer = null;
        }
        return true;
    } catch {
        return false;
    }
}

module.exports = { copyToClipboard, clearClipboard, getClearDelayMs };
