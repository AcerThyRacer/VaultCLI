#!/usr/bin/env node

'use strict';

const inquirer = require('inquirer');
const { bootAnimation, unlockAnimation, exitAnimation, COLORS, clearScreen, sleep } = require('../src/ui/ascii');
const { isFirstRun, setupMasterPassword, verifyMasterPassword, isSessionExpired, setSessionTimeout, refreshActivity, createSessionKey, zeroSessionKey, checkVaultPermissions } = require('../src/auth/master');
const { mainMenu } = require('../src/ui/menu');
const { getConfigValue, getSessionTimeoutMs } = require('../src/utils/config');
const { logEvent, EVENT_TYPES } = require('../src/security/auditlog');

// ═══════════════════════════════════════════════════════════════
//  VAULT — SECURE PASSWORD MANAGER CLI (Hardened)
//  Functional decoy vault, --quick flag, session watchdog
// ═══════════════════════════════════════════════════════════════

const args = process.argv.slice(2);
const quickMode = args.includes('--quick') || args.includes('-q');

async function main() {
    try {
        setSessionTimeout(getSessionTimeoutMs());

        // Check vault directory permissions on startup
        const permWarnings = checkVaultPermissions();
        if (permWarnings.length > 0) {
            permWarnings.forEach(w => console.log(COLORS.warning(`  ⚠ ${w}`)));
            console.log('');
        }

        if (!quickMode && getConfigValue('showBootAnimation')) {
            await bootAnimation();
        } else {
            clearScreen();
        }

        let masterPassword = null;
        let isDecoyMode = false;

        if (isFirstRun()) {
            masterPassword = await handleFirstRun();
        } else {
            const loginResult = await handleLogin();
            masterPassword = loginResult.password;
            isDecoyMode = loginResult.isDecoy;
        }

        if (!masterPassword) {
            console.log(COLORS.accent('\n  Access denied.\n'));
            process.exit(1);
        }

        // Derive session key from master password (Buffer-based, zeroable)
        // The session key replaces the raw password for crypto operations
        const sessionPassword = createSessionKey(masterPassword);
        masterPassword = sessionPassword; // Use session key going forward

        logEvent(masterPassword, EVENT_TYPES.LOGIN_SUCCESS);
        await unlockAnimation();

        // Session watchdog — check timeout every 30s in background
        const watchdog = setInterval(() => {
            if (isSessionExpired()) {
                clearInterval(watchdog);
                // Session expired — process will handle on next menu iteration
            }
        }, 30000);
        watchdog.unref();

        let status = 'continue';
        while (status !== 'exit') {
            if (isDecoyMode) {
                // Functional decoy vault — separate menu flow
                status = await runDecoyMenu(masterPassword);
            } else {
                status = await mainMenu(masterPassword);
            }

            if (status === 'timeout' || status === 'lock') {
                clearInterval(watchdog);
                zeroSessionKey(); // Zero key material on lock/timeout
                clearScreen();
                console.log(status === 'timeout'
                    ? COLORS.warning('\n  ⏱  Session timed out.\n')
                    : COLORS.warning('\n  🔒 Vault locked.\n'));
                const loginResult = await handleLogin();
                masterPassword = loginResult.password;
                isDecoyMode = loginResult.isDecoy;
                if (!masterPassword) { console.log(COLORS.accent('\n  Access denied.\n')); process.exit(1); }
                // Re-derive session key for new session
                const newSessionPw = createSessionKey(masterPassword);
                masterPassword = newSessionPw;
                logEvent(masterPassword, EVENT_TYPES.LOGIN_SUCCESS);
                await unlockAnimation();
                status = 'continue';
            }
        }
    } catch (err) {
        if (err.isTtyError) {
            console.error(COLORS.accent('\n  Requires interactive terminal.\n'));
        } else if (err.message === 'User force closed the prompt') {
            await exitAnimation();
        } else {
            console.error(COLORS.accent(`\n  Fatal: ${err.message}\n`));
            if (process.env.VAULT_DEBUG) console.error(err.stack);
        }
        process.exit(1);
    }
}

async function handleFirstRun() {
    console.log(COLORS.success('  ✦ Welcome to Vault! Set up your master password.\n'));
    console.log(COLORS.warning('  ⚠ If you forget it, your vault CANNOT be recovered.\n'));

    const { password } = await inquirer.prompt([{
        type: 'password', name: 'password', message: COLORS.primary('Create master password:'), mask: '•',
        validate: v => v.length >= 8 && /[A-Z]/.test(v) && /[a-z]/.test(v) && /[0-9]/.test(v) ? true : 'Min 8, upper+lower+digit',
    }]);
    await inquirer.prompt([{
        type: 'password', name: 'confirm', message: COLORS.primary('Confirm:'), mask: '•',
        validate: v => v === password ? true : 'No match',
    }]);

    const ora = require('ora');
    const spinner = ora({ text: COLORS.dim(' Deriving key (PBKDF2 · 600K)...'), spinner: 'dots12', color: 'cyan' }).start();
    setupMasterPassword(password);
    await sleep(1500);
    spinner.succeed(COLORS.success(' Master password set!'));
    console.log('');
    return password;
}

/**
 * Login with constant-time decoy check (handled in master.js).
 * Returns { password, isDecoy }.
 */
async function handleLogin() {
    for (let attempt = 0; attempt < 5; attempt++) {
        const { password } = await inquirer.prompt([{
            type: 'password', name: 'password', message: COLORS.primary('🔑 Master password:'), mask: '•',
        }]);

        const result = verifyMasterPassword(password);

        if (result.success) {
            return { password, isDecoy: result.isDecoy || false };
        }

        if (result.locked) {
            const secs = Math.ceil(result.remaining / 1000);
            logEvent(null, EVENT_TYPES.LOCKOUT);
            console.log(COLORS.accent(`\n  🚫 Locked for ${secs}s.\n`));
            const ora = require('ora');
            const spinner = ora({ text: COLORS.dim(` Waiting ${secs}s...`), spinner: 'clock', color: 'red' }).start();
            await sleep(result.remaining + 500);
            spinner.stop();
        } else {
            logEvent(null, EVENT_TYPES.LOGIN_FAILED);
            console.log(COLORS.accent(`  ✗ Wrong. ${result.attemptsLeft} left.\n`));
        }
    }
    return { password: null, isDecoy: false };
}

/**
 * Decoy vault menu — a simplified, functional menu for the decoy vault.
 * Looks identical to the real menu to avoid suspicion.
 */
async function runDecoyMenu(decoyPassword) {
    const { listDecoyEntries, addDecoyEntry, deleteDecoyEntry } = require('../src/security/decoy');
    const Table = require('cli-table3');

    while (true) {
        if (isSessionExpired()) {
            console.log(COLORS.warning('\n  ⚠ Session expired.\n'));
            return 'timeout';
        }
        refreshActivity();

        const { action } = await inquirer.prompt([{
            type: 'list', name: 'action', message: COLORS.primary('Select an action:'),
            choices: [
                { name: COLORS.success('🔐  Add Password'), value: 'add' },
                { name: COLORS.primary('📋  List Passwords'), value: 'list' },
                { name: COLORS.accent('🗑️   Delete Entry'), value: 'delete' },
                new inquirer.Separator(COLORS.dim('─── System ───')),
                { name: COLORS.dim('🔒  Lock'), value: 'lock' },
                { name: COLORS.dim('🚪  Exit'), value: 'exit' },
            ], pageSize: 8,
        }]);

        if (action === 'exit') { await exitAnimation(); return 'exit'; }
        if (action === 'lock') return 'lock';

        if (action === 'list') {
            const entries = listDecoyEntries(decoyPassword);
            if (!entries.length) { console.log(COLORS.dim('\n  No entries.\n')); continue; }
            const table = new Table({
                head: ['#', 'Service', 'Username', 'Password'],
                colWidths: [5, 24, 24, 20], style: { border: ['cyan'] },
            });
            entries.forEach((e, i) => table.push([i + 1, e.name, e.username || '—', '••••••']));
            console.log(table.toString());
            await inquirer.prompt([{ type: 'input', name: 'c', message: COLORS.dim('Press Enter...') }]);
        }

        if (action === 'add') {
            const a = await inquirer.prompt([
                { type: 'input', name: 'name', message: COLORS.primary('Service:'), validate: v => v.trim() ? true : 'Required' },
                { type: 'input', name: 'username', message: COLORS.primary('Username:') },
                { type: 'password', name: 'password', message: COLORS.primary('Password:'), mask: '•' },
            ]);
            addDecoyEntry(decoyPassword, a);
            console.log(COLORS.success('\n  ✓ Saved!\n'));
        }

        if (action === 'delete') {
            const entries = listDecoyEntries(decoyPassword);
            if (!entries.length) { console.log(COLORS.dim('\n  No entries.\n')); continue; }
            const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.accent('Delete:'), choices: entries.map(e => ({ name: e.name, value: e.id })) }]);
            deleteDecoyEntry(decoyPassword, id);
            console.log(COLORS.success('\n  ✓ Deleted.\n'));
        }
    }
}

process.on('SIGINT', async () => { zeroSessionKey(); console.log(''); await exitAnimation(); process.exit(0); });
process.on('SIGTERM', async () => { zeroSessionKey(); await exitAnimation(); process.exit(0); });
process.on('exit', () => { zeroSessionKey(); });

main();
