'use strict';

const chalk = require('chalk');

// ═══════════════════════════════════════════════════════════════
//  ASCII ART & BOOT ANIMATION
// ═══════════════════════════════════════════════════════════════

const VAULT_BANNER = [
    '',
    '  ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗',
    '  ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝',
    '  ██║   ██║███████║██║   ██║██║     ██║   ',
    '  ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ',
    '   ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ',
    '    ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ',
    '',
];

const LOCK_CLOSED = [
    '          ┌──────────┐',
    '          │  ┌────┐  │',
    '          │  │    │  │',
    '          ├──┘    └──┤',
    '          │ ████████ │',
    '          │ ██ 🔒 ██ │',
    '          │ ████████ │',
    '          │ ████████ │',
    '          └──────────┘',
];

const LOCK_OPEN = [
    '             ┌────┐   ',
    '             │    │   ',
    '             │    │   ',
    '          ┌──┘    └──┐',
    '          │ ████████ │',
    '          │ ██ 🔓 ██ │',
    '          │ ████████ │',
    '          │ ████████ │',
    '          └──────────┘',
];

const MATRIX_CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';

const COLORS = {
    primary: chalk.hex('#00F5FF'),      // Electric cyan
    secondary: chalk.hex('#7B68EE'),    // Medium slate blue
    accent: chalk.hex('#FF6B6B'),       // Coral red
    success: chalk.hex('#00FF88'),      // Neon green
    warning: chalk.hex('#FFD93D'),      // Golden yellow
    dim: chalk.hex('#4A5568'),          // Slate gray
    white: chalk.hex('#E2E8F0'),        // Light gray
    gradient1: chalk.hex('#00F5FF'),
    gradient2: chalk.hex('#0EA5E9'),
    gradient3: chalk.hex('#7B68EE'),
    gradient4: chalk.hex('#A855F7'),
    gradient5: chalk.hex('#EC4899'),
};

const GRADIENT = [COLORS.gradient1, COLORS.gradient2, COLORS.gradient3, COLORS.gradient4, COLORS.gradient5];

const { sleep } = require('../utils/sleep');

/**
 * Apply gradient coloring to a line of text.
 */
function gradientLine(text, lineIndex) {
    const colorFn = GRADIENT[lineIndex % GRADIENT.length];
    return colorFn(text);
}

/**
 * Clear the terminal screen.
 */
function clearScreen() {
    process.stdout.write('\x1B[2J\x1B[3J\x1B[H');
}

/**
 * Brief matrix rain effect (visual flair).
 */
async function matrixRain(durationMs = 800, columns = 50) {
    const rows = 12;
    const grid = Array.from({ length: rows }, () =>
        Array.from({ length: columns }, () => ' ')
    );
    const drops = Array.from({ length: columns }, () => Math.floor(Math.random() * -rows));
    const startTime = Date.now();

    while (Date.now() - startTime < durationMs) {
        // Update drops
        for (let c = 0; c < columns; c++) {
            if (drops[c] >= 0 && drops[c] < rows) {
                grid[drops[c]][c] = MATRIX_CHARS[Math.floor(Math.random() * MATRIX_CHARS.length)];
            }
            if (drops[c] - 1 >= 0 && drops[c] - 1 < rows) {
                // Dim previous character
            }
            drops[c]++;
            if (drops[c] > rows + Math.random() * rows) {
                drops[c] = Math.floor(Math.random() * -4);
            }
        }

        // Render
        process.stdout.write('\x1B[H');
        for (let r = 0; r < rows; r++) {
            let line = '';
            for (let c = 0; c < columns; c++) {
                const char = grid[r][c];
                if (char !== ' ') {
                    if (r === drops.find((_, idx) => idx === c && drops[idx] - 1 === r)) {
                        line += COLORS.success.bold(char);
                    } else {
                        line += COLORS.dim(char);
                    }
                    // Fade out
                    if (Math.random() > 0.7) grid[r][c] = ' ';
                } else {
                    line += ' ';
                }
            }
            process.stdout.write(line + '\n');
        }
        await sleep(50);
    }
}

/**
 * Typewriter effect for a single line.
 */
async function typewriter(text, delay = 8) {
    for (const char of text) {
        process.stdout.write(char);
        await sleep(delay);
    }
    process.stdout.write('\n');
}

/**
 * Play the full boot animation.
 */
async function bootAnimation() {
    clearScreen();

    // Phase 1: Quick matrix rain
    await matrixRain(600, Math.min(process.stdout.columns || 50, 60));

    clearScreen();

    // Phase 2: Vault banner reveal (line by line with gradient)
    for (let i = 0; i < VAULT_BANNER.length; i++) {
        const colored = gradientLine(VAULT_BANNER[i], i);
        process.stdout.write(colored + '\n');
        await sleep(60);
    }

    // Phase 3: Lock animation
    const lockLines = LOCK_CLOSED;
    for (const line of lockLines) {
        process.stdout.write(COLORS.primary(line) + '\n');
        await sleep(40);
    }

    await sleep(200);

    // Phase 4: Tagline
    const tagline = '  ⚡ Maximum Security Password Vault ⚡';
    await typewriter(COLORS.secondary(tagline), 15);

    const version = COLORS.dim('  v1.0.0 | AES-256-GCM | PBKDF2-SHA512');
    process.stdout.write(version + '\n');
    await sleep(100);

    const divider = COLORS.dim('  ' + '─'.repeat(44));
    process.stdout.write(divider + '\n\n');
    await sleep(200);
}

/**
 * Show the vault unlocked animation.
 */
async function unlockAnimation() {
    console.log('');
    for (const line of LOCK_OPEN) {
        process.stdout.write(COLORS.success(line) + '\n');
        await sleep(30);
    }
    console.log('');
    await typewriter(COLORS.success('  ✓ Vault Unlocked Successfully'), 12);
    console.log('');
    await sleep(300);
}

/**
 * Display a styled header.
 */
function sectionHeader(title) {
    const width = 48;
    const pad = Math.max(0, Math.floor((width - title.length - 4) / 2));
    const line = '═'.repeat(width);
    console.log('');
    console.log(COLORS.primary('  ╔' + line + '╗'));
    console.log(COLORS.primary('  ║' + ' '.repeat(pad) + '  ' + title + ' '.repeat(width - pad - title.length - 2) + '║'));
    console.log(COLORS.primary('  ╚' + line + '╝'));
    console.log('');
}

/**
 * Show exit animation.
 */
async function exitAnimation() {
    console.log('');
    for (const line of LOCK_CLOSED) {
        process.stdout.write(COLORS.accent(line) + '\n');
        await sleep(25);
    }
    await typewriter(COLORS.accent('\n  🔒 Vault Sealed. Stay Secure.\n'), 20);
    await sleep(400);
}

module.exports = {
    bootAnimation,
    unlockAnimation,
    exitAnimation,
    sectionHeader,
    clearScreen,
    COLORS,
    sleep,
    VAULT_BANNER,
};
