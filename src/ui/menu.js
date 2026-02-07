'use strict';

const inquirer = require('inquirer');
const path = require('path');
const fs = require('fs');
const Table = require('cli-table3');
const { COLORS, sectionHeader, exitAnimation, sleep } = require('./ascii');
const { generatePassword } = require('../crypto/engine');
const { refreshActivity, isSessionExpired, changeMasterPassword } = require('../auth/master');
const vault = require('../store/vault');
const { copyToClipboard } = require('../utils/clipboard');
const { auditVault, formatAuditReport } = require('../utils/audit');
const { loadConfig, saveConfig, DEFAULTS } = require('../utils/config');
const { exportToCSV, exportToEncryptedJSON, exportToJSON, getDefaultExportDir } = require('../io/exporter');
const { autoImport, importFromEncryptedJSON } = require('../io/importer');
const { fuzzySearch } = require('../utils/fuzzy');
const { getCategoryChoices, getCategoryDisplay, filterByCategory, autoDetectCategory, getCategories } = require('../utils/categories');
const { generateTOTP, generateSecret, parseOtpAuthURI } = require('../security/totp');
const { logEvent, EVENT_TYPES, getRecentEvents, getSecuritySummary } = require('../security/auditlog');
const { verifyIntegrity, saveIntegrity } = require('../security/integrity');
const { hasDecoyVault, createDecoyVault, isDecoyPassword } = require('../security/decoy');
const { checkBreaches } = require('../security/breach');

const PAGE_SIZE = 15;

async function mainMenu(masterPassword) {
    let running = true;
    // Check expiring passwords on first load
    const expiring = vault.getExpiringEntries(masterPassword);
    if (expiring.length > 0) {
        console.log(COLORS.warning(`\n  ⚠ ${expiring.length} password(s) need rotation:`));
        expiring.slice(0, 3).forEach(e => console.log(COLORS.dim(`    → ${e.name} (${e.overdueDays}d overdue)`)));
        if (expiring.length > 3) console.log(COLORS.dim(`    ... and ${expiring.length - 3} more`));
        console.log('');
    }

    while (running) {
        if (isSessionExpired()) {
            logEvent(masterPassword, EVENT_TYPES.SESSION_TIMEOUT);
            console.log(COLORS.warning('\n  ⚠ Session expired.\n'));
            return 'timeout';
        }
        refreshActivity();

        const { action } = await inquirer.prompt([{
            type: 'list', name: 'action', message: COLORS.primary('Select an action:'),
            choices: [
                { name: COLORS.success('🔐  Add Password'), value: 'add' },
                { name: COLORS.primary('📋  List Passwords'), value: 'list' },
                { name: COLORS.secondary('🔍  Search (Fuzzy)'), value: 'search' },
                { name: COLORS.warning('✏️   Edit Entry'), value: 'edit' },
                { name: COLORS.accent('🗑️   Delete Entry'), value: 'delete' },
                { name: COLORS.gradient4('🎲  Generate Password'), value: 'generate' },
                new inquirer.Separator(COLORS.dim('─── Organize ───')),
                { name: COLORS.success('⭐  Favorites'), value: 'favorites' },
                { name: COLORS.primary('📁  Browse by Category'), value: 'categories' },
                new inquirer.Separator(COLORS.dim('─── Security ───')),
                { name: COLORS.primary('🛡️   Security Audit'), value: 'audit' },
                { name: COLORS.accent('🔓  Breach Check (HIBP)'), value: 'breach' },
                { name: COLORS.secondary('🔑  TOTP / 2FA Codes'), value: 'totp' },
                { name: COLORS.warning('📝  Secure Notes'), value: 'securenotes' },
                { name: COLORS.secondary('🔑  Change Master PW'), value: 'changepw' },
                new inquirer.Separator(COLORS.dim('─── Advanced ───')),
                { name: COLORS.success('📤  Export Vault'), value: 'export' },
                { name: COLORS.success('📥  Import Passwords'), value: 'import' },
                { name: COLORS.dim('🔒  Vault Integrity'), value: 'integrity' },
                { name: COLORS.dim('📊  Audit Log'), value: 'auditlog' },
                { name: COLORS.dim('🎭  Decoy Vault'), value: 'decoy' },
                new inquirer.Separator(COLORS.dim('─── System ───')),
                { name: COLORS.dim('🎨  Themes'), value: 'themes' },
                { name: COLORS.dim('⚙️   Settings'), value: 'settings' },
                { name: COLORS.dim('🔒  Lock'), value: 'lock' },
                { name: COLORS.dim('🚪  Exit'), value: 'exit' },
            ], pageSize: 26,
        }]);

        switch (action) {
            case 'add': await handleAdd(masterPassword); break;
            case 'list': await handleList(masterPassword); break;
            case 'search': await handleSearch(masterPassword); break;
            case 'edit': await handleEdit(masterPassword); break;
            case 'delete': await handleDelete(masterPassword); break;
            case 'generate': await handleGenerate(); break;
            case 'favorites': await handleFavorites(masterPassword); break;
            case 'categories': await handleCategories(masterPassword); break;
            case 'audit': await handleAudit(masterPassword); break;
            case 'breach': await handleBreachCheck(masterPassword); break;
            case 'totp': await handleTOTP(masterPassword); break;
            case 'securenotes': await handleSecureNotes(masterPassword); break;
            case 'changepw': masterPassword = await handleChangeMasterPassword(masterPassword); break;
            case 'export': await handleExport(masterPassword); break;
            case 'import': await handleImport(masterPassword); break;
            case 'integrity': await handleIntegrity(masterPassword); break;
            case 'auditlog': await handleAuditLog(masterPassword); break;
            case 'decoy': await handleDecoy(masterPassword); break;
            case 'themes': await handleThemes(); break;
            case 'settings': await handleSettings(); break;
            case 'lock': logEvent(masterPassword, EVENT_TYPES.VAULT_LOCK); return 'lock';
            case 'exit': await exitAnimation(); return 'exit';
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  CORE HANDLERS
// ═══════════════════════════════════════════════════════════════

async function handleAdd(masterPassword) {
    sectionHeader('ADD NEW PASSWORD');
    const answers = await inquirer.prompt([
        { type: 'input', name: 'name', message: COLORS.primary('Service name:'), validate: v => v.trim() ? true : 'Required' },
        { type: 'input', name: 'username', message: COLORS.primary('Username / Email:') },
        { type: 'list', name: 'passwordChoice', message: COLORS.primary('Password:'), choices: [{ name: 'Enter manually', value: 'manual' }, { name: 'Generate secure password', value: 'generate' }] },
    ]);

    let password;
    if (answers.passwordChoice === 'generate') {
        const { length } = await inquirer.prompt([{ type: 'number', name: 'length', message: COLORS.primary('Length:'), default: 24, validate: v => v >= 8 && v <= 128 ? true : '8–128' }]);
        password = generatePassword(length);
        console.log(COLORS.success(`\n  Generated: ${COLORS.white.bold(password)}`));
        if (copyToClipboard(password)) console.log(COLORS.dim('  📋 Copied (auto-clears 15s)\n'));
    } else {
        const { pw } = await inquirer.prompt([{ type: 'password', name: 'pw', message: COLORS.primary('Password:'), mask: '•', validate: v => v.trim() ? true : 'Required' }]);
        password = pw;
        // Show password strength meter (warn, don't block)
        const { bar, label, entropy } = getStrength(password);
        console.log(`\n  Strength: ${bar} ${label} (${entropy}-bit entropy)`);
        if (entropy < 40) console.log(COLORS.warning('  ⚠ Consider using a stronger password or generating one.'));
    }

    const extra = await inquirer.prompt([
        { type: 'input', name: 'url', message: COLORS.primary('URL (optional):') },
        { type: 'list', name: 'category', message: COLORS.primary('Category:'), choices: getCategoryChoices(), default: autoDetectCategory({ name: answers.name, url: '' }) },
        { type: 'input', name: 'notes', message: COLORS.primary('Notes (optional):') },
        { type: 'number', name: 'expiryDays', message: COLORS.primary('Password rotation (days, 0=none):'), default: 0 },
    ]);

    try {
        const entry = vault.addEntry(masterPassword, { name: answers.name, username: answers.username, password, url: extra.url, notes: extra.notes, category: extra.category, expiryDays: extra.expiryDays || null });
        logEvent(masterPassword, EVENT_TYPES.ENTRY_ADD, { name: entry.name });
        if (entry._isDuplicate) console.log(COLORS.warning('\n  ⚠ Duplicate detected — entry with same name+username already exists.'));
        console.log(COLORS.success(`\n  ✓ Saved! ${getCategoryDisplay(extra.category)} · ID: ${COLORS.dim(entry.id)}\n`));
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleList(masterPassword, filterCat = null, favoritesOnly = false) {
    sectionHeader(favoritesOnly ? 'FAVORITES' : filterCat ? `CATEGORY: ${getCategoryDisplay(filterCat)}` : 'ALL PASSWORDS');
    try {
        let entries = vault.listEntries(masterPassword);
        if (favoritesOnly) entries = entries.filter(e => e.favorite);
        if (filterCat) entries = filterByCategory(entries, filterCat);

        // Sort: favorites first, then alphabetical
        entries.sort((a, b) => {
            if (a.favorite && !b.favorite) return -1;
            if (!a.favorite && b.favorite) return 1;
            return (a.name || '').localeCompare(b.name || '');
        });

        if (entries.length === 0) {
            console.log(COLORS.dim('  No entries found.\n'));
            await pause(); return;
        }

        // Paginate
        let page = 0;
        const totalPages = Math.ceil(entries.length / PAGE_SIZE);

        while (true) {
            const start = page * PAGE_SIZE;
            const pageEntries = entries.slice(start, start + PAGE_SIZE);

            const table = new Table({
                head: [COLORS.primary('#'), COLORS.primary(''), COLORS.primary('Service'), COLORS.primary('User'), COLORS.primary('Category'), COLORS.primary('PW')],
                colWidths: [5, 3, 20, 20, 16, 10], style: { border: ['cyan'] },
            });
            pageEntries.forEach((e, i) => {
                table.push([COLORS.dim(String(start + i + 1)), e.favorite ? '⭐' : ' ', COLORS.white(truncate(e.name, 18)), COLORS.secondary(truncate(e.username || '—', 18)), COLORS.dim(truncate(getCategoryDisplay(e.category || 'none'), 14)), COLORS.dim('••••••')]);
            });
            console.log(table.toString());
            if (totalPages > 1) console.log(COLORS.dim(`  Page ${page + 1}/${totalPages} (${entries.length} entries)\n`));

            const choices = [
                { name: '📋 Copy password', value: 'copy' },
                { name: '👁️  Reveal password', value: 'reveal' },
                { name: '⭐ Toggle favorite', value: 'fav' },
            ];
            if (page > 0) choices.push({ name: '◀ Previous page', value: 'prev' });
            if (page < totalPages - 1) choices.push({ name: '▶ Next page', value: 'next' });
            choices.push({ name: '← Back', value: 'back' });

            const { act } = await inquirer.prompt([{ type: 'list', name: 'act', message: COLORS.primary('Action:'), choices }]);

            if (act === 'back') break;
            if (act === 'prev') { page--; continue; }
            if (act === 'next') { page++; continue; }

            const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.primary('Select:'), choices: pageEntries.map(e => ({ name: `${e.favorite ? '⭐ ' : ''}${e.name} (${e.username || '—'})`, value: e.id })) }]);
            const entry = pageEntries.find(e => e.id === id);
            if (!entry) continue;

            if (act === 'copy') {
                if (copyToClipboard(entry.password)) { console.log(COLORS.success('\n  ✓ Copied! (auto-clears 15s)\n')); logEvent(masterPassword, EVENT_TYPES.PASSWORD_COPY, { name: entry.name }); }
            } else if (act === 'reveal') {
                console.log(COLORS.success(`\n  Password: ${COLORS.white.bold(entry.password)}\n`));
                logEvent(masterPassword, EVENT_TYPES.PASSWORD_REVEAL, { name: entry.name });
            } else if (act === 'fav') {
                vault.toggleFavorite(masterPassword, id);
                entries = vault.listEntries(masterPassword); // reload
                if (favoritesOnly) entries = entries.filter(e => e.favorite);
                if (filterCat) entries = filterByCategory(entries, filterCat);
                console.log(COLORS.success(`\n  ✓ Toggled favorite for ${entry.name}\n`));
            }
        }
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleSearch(masterPassword) {
    sectionHeader('FUZZY SEARCH');
    const { query } = await inquirer.prompt([{ type: 'input', name: 'query', message: COLORS.primary('Search:'), validate: v => v.trim() ? true : 'Enter a term' }]);
    try {
        const results = fuzzySearch(vault.listEntries(masterPassword), query);
        if (results.length === 0) { console.log(COLORS.dim(`\n  No results for "${query}"\n`)); await pause(); return; }

        console.log(COLORS.success(`\n  ${results.length} result(s) (ranked by relevance):\n`));
        results.slice(0, 20).forEach((e, i) => {
            const score = e._score >= 80 ? COLORS.success(`${e._score}%`) : e._score >= 50 ? COLORS.warning(`${e._score}%`) : COLORS.dim(`${e._score}%`);
            console.log(`  ${COLORS.dim(String(i + 1) + '.')} ${e.favorite ? '⭐ ' : ''}${COLORS.white(e.name)} ${COLORS.dim(`(${e.username || '—'})`)} ${score}`);
        });
        console.log('');

        const { act } = await inquirer.prompt([{ type: 'list', name: 'act', message: COLORS.primary('Action:'), choices: [{ name: '📋 Copy password', value: 'copy' }, { name: '👁️  Reveal', value: 'reveal' }, { name: '← Back', value: 'back' }] }]);
        if (act !== 'back') {
            const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.primary('Select:'), choices: results.slice(0, 20).map(e => ({ name: `${e.name} (${e.username || '—'})`, value: e.id })) }]);
            const entry = results.find(e => e.id === id);
            if (entry && act === 'copy') { copyToClipboard(entry.password); console.log(COLORS.success('\n  ✓ Copied!\n')); logEvent(masterPassword, EVENT_TYPES.PASSWORD_COPY, { name: entry.name }); }
            else if (entry) { console.log(COLORS.success(`\n  Password: ${COLORS.white.bold(entry.password)}\n`)); logEvent(masterPassword, EVENT_TYPES.PASSWORD_REVEAL, { name: entry.name }); }
        }
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleEdit(masterPassword) {
    sectionHeader('EDIT ENTRY');
    try {
        const entries = vault.listEntries(masterPassword);
        if (!entries.length) { console.log(COLORS.dim('  No entries.\n')); await pause(); return; }
        const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.primary('Select:'), choices: entries.map(e => ({ name: `${e.name} (${e.username || '—'})`, value: e.id })) }]);
        const entry = entries.find(e => e.id === id);
        console.log(COLORS.dim(`\n  Editing: ${COLORS.white.bold(entry.name)} (blank = keep)\n`));

        const u = await inquirer.prompt([
            { type: 'input', name: 'name', message: COLORS.primary(`Name [${entry.name}]:`), default: entry.name },
            { type: 'input', name: 'username', message: COLORS.primary(`User [${entry.username || '—'}]:`), default: entry.username },
            { type: 'password', name: 'password', message: COLORS.primary('New PW (blank=keep):'), mask: '•' },
            { type: 'input', name: 'url', message: COLORS.primary(`URL [${entry.url || '—'}]:`), default: entry.url },
            { type: 'list', name: 'category', message: COLORS.primary('Category:'), choices: getCategoryChoices(), default: entry.category || 'none' },
            { type: 'number', name: 'expiryDays', message: COLORS.primary(`Rotation days [${entry.expiryDays || 0}]:`), default: entry.expiryDays || 0 },
            { type: 'input', name: 'notes', message: COLORS.primary(`Notes:`), default: entry.notes },
        ]);
        if (!u.password) delete u.password;
        u.expiryDays = u.expiryDays || null;

        vault.updateEntry(masterPassword, id, u);
        logEvent(masterPassword, EVENT_TYPES.ENTRY_EDIT, { name: u.name });

        // Show history if password was changed
        if (u.password) {
            const updated = vault.getEntry(masterPassword, id);
            if (updated.history && updated.history.length > 0) {
                console.log(COLORS.dim(`\n  📜 ${updated.history.length} previous password(s) in history`));
            }
        }
        console.log(COLORS.success('\n  ✓ Updated!\n'));
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleDelete(masterPassword) {
    sectionHeader('DELETE ENTRY');
    try {
        const entries = vault.listEntries(masterPassword);
        if (!entries.length) { console.log(COLORS.dim('  No entries.\n')); await pause(); return; }
        const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.accent('Select to DELETE:'), choices: entries.map(e => ({ name: `${COLORS.accent('✗')} ${e.name}`, value: e.id })) }]);
        const entry = entries.find(e => e.id === id);
        const { confirm } = await inquirer.prompt([{ type: 'confirm', name: 'confirm', message: COLORS.accent(`Delete "${entry.name}"?`), default: false }]);
        if (confirm) { vault.deleteEntry(masterPassword, id); logEvent(masterPassword, EVENT_TYPES.ENTRY_DELETE, { name: entry.name }); console.log(COLORS.success('\n  ✓ Deleted.\n')); }
        else console.log(COLORS.dim('\n  Cancelled.\n'));
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleGenerate() {
    sectionHeader('GENERATE PASSWORD');
    const { length } = await inquirer.prompt([{ type: 'number', name: 'length', message: COLORS.primary('Length:'), default: 24, validate: v => v >= 8 && v <= 128 ? true : '8–128' }]);
    const pw = generatePassword(length);
    const s = getStrength(pw);
    console.log(`\n  ${COLORS.white.bold(pw)}\n\n  Strength: ${s.bar}  ${s.label}\n  Entropy: ~${s.entropy} bits\n`);
    const { copyIt } = await inquirer.prompt([{ type: 'confirm', name: 'copyIt', message: COLORS.primary('Copy?'), default: true }]);
    if (copyIt && copyToClipboard(pw)) console.log(COLORS.success('\n  ✓ Copied! (15s auto-clear)\n'));
    await pause();
}

// ═══════════════════════════════════════════════════════════════
//  PHASE 3 HANDLERS
// ═══════════════════════════════════════════════════════════════

async function handleFavorites(masterPassword) {
    await handleList(masterPassword, null, true);
}

async function handleCategories(masterPassword) {
    sectionHeader('BROWSE BY CATEGORY');
    const entries = vault.listEntries(masterPassword);
    const cats = getCategories();
    const choices = cats.filter(c => entries.some(e => (e.category || 'none') === c.id)).map(c => {
        const count = entries.filter(e => (e.category || 'none') === c.id).length;
        return { name: `${c.icon}  ${c.name} (${count})`, value: c.id };
    });
    if (!choices.length) { console.log(COLORS.dim('  No categorized entries.\n')); await pause(); return; }
    choices.push({ name: COLORS.dim('← Back'), value: 'back' });
    const { cat } = await inquirer.prompt([{ type: 'list', name: 'cat', message: COLORS.primary('Category:'), choices }]);
    if (cat !== 'back') await handleList(masterPassword, cat);
}

async function handleThemes() {
    sectionHeader('COLOR THEMES');
    const { buildColors, getThemeNames, getThemeDisplayName, setCurrentTheme, getCurrentTheme } = require('./themes');
    const config = loadConfig();
    const current = config.colorTheme || 'cyberpunk';
    const { theme } = await inquirer.prompt([{ type: 'list', name: 'theme', message: COLORS.primary('Select theme:'), choices: getThemeNames().map(t => ({ name: `${t === current ? '✓ ' : '  '}${getThemeDisplayName(t)}`, value: t })) }]);
    config.colorTheme = theme;
    saveConfig(config);
    setCurrentTheme(theme);
    console.log(COLORS.success(`\n  ✓ Theme: ${getThemeDisplayName(theme)} (restart for full effect)\n`));
    await pause();
}

// ═══════════════════════════════════════════════════════════════
//  PHASE 4 HANDLERS — Security
// ═══════════════════════════════════════════════════════════════

async function handleTOTP(masterPassword) {
    sectionHeader('TOTP / 2FA CODES');
    try {
        const entries = vault.listEntries(masterPassword).filter(e => e.totp);
        const { act } = await inquirer.prompt([{
            type: 'list', name: 'act', message: COLORS.primary('Action:'), choices: [
                { name: `📟 View codes (${entries.length} configured)`, value: 'view' },
                { name: '➕ Add TOTP to entry', value: 'add' },
                { name: '← Back', value: 'back' },
            ]
        }]);
        if (act === 'back') return;

        if (act === 'view') {
            if (!entries.length) { console.log(COLORS.dim('\n  No TOTP entries. Add one first!\n')); await pause(); return; }
            entries.forEach(e => {
                const { code, remaining } = generateTOTP(e.totp);
                const bar = '█'.repeat(Math.ceil(remaining / 3)) + '░'.repeat(10 - Math.ceil(remaining / 3));
                console.log(`\n  ${COLORS.white.bold(e.name)} ${COLORS.dim(`(${e.username || '—'})`)}`);
                console.log(`  Code: ${COLORS.success.bold(code)}  ${COLORS.dim(`${bar} ${remaining}s`)}`);
            });
            console.log('');

            const { copyId } = await inquirer.prompt([{ type: 'list', name: 'copyId', message: COLORS.primary('Copy code?'), choices: [...entries.map(e => ({ name: e.name, value: e.id })), { name: '← Back', value: 'back' }] }]);
            if (copyId !== 'back') {
                const e = entries.find(x => x.id === copyId);
                if (e) { const { code } = generateTOTP(e.totp); copyToClipboard(code); console.log(COLORS.success('\n  ✓ Code copied!\n')); }
            }
        } else {
            const all = vault.listEntries(masterPassword).filter(e => !e.totp);
            if (!all.length) { console.log(COLORS.dim('\n  All entries already have TOTP.\n')); await pause(); return; }
            const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.primary('Add TOTP to:'), choices: all.map(e => ({ name: `${e.name} (${e.username || '—'})`, value: e.id })) }]);
            const { method } = await inquirer.prompt([{ type: 'list', name: 'method', message: COLORS.primary('How?'), choices: [{ name: 'Paste secret key (base32)', value: 'key' }, { name: 'Paste otpauth:// URI', value: 'uri' }] }]);

            let secret;
            if (method === 'uri') {
                const { uri } = await inquirer.prompt([{ type: 'input', name: 'uri', message: COLORS.primary('otpauth:// URI:') }]);
                const parsed = parseOtpAuthURI(uri);
                if (!parsed) { console.log(COLORS.accent('\n  ✗ Invalid URI\n')); await pause(); return; }
                secret = parsed.secret;
            } else {
                const { key } = await inquirer.prompt([{ type: 'input', name: 'key', message: COLORS.primary('Base32 secret:'), validate: v => v.trim().length >= 16 ? true : 'Too short' }]);
                secret = key.replace(/\s/g, '').toUpperCase();
            }

            vault.updateEntry(masterPassword, id, { totp: secret });
            const { code } = generateTOTP(secret);
            console.log(COLORS.success(`\n  ✓ TOTP added! Current code: ${COLORS.white.bold(code)}\n`));
        }
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleSecureNotes(masterPassword) {
    sectionHeader('SECURE NOTES');
    try {
        const entries = vault.listEntries(masterPassword);
        const withNotes = entries.filter(e => e.secureNotes);
        const { act } = await inquirer.prompt([{
            type: 'list', name: 'act', message: COLORS.primary('Action:'), choices: [
                { name: `📝 View notes (${withNotes.length} entries)`, value: 'view' },
                { name: '➕ Add/edit note', value: 'add' },
                { name: '← Back', value: 'back' },
            ]
        }]);
        if (act === 'back') return;

        if (act === 'view') {
            if (!withNotes.length) { console.log(COLORS.dim('\n  No secure notes yet.\n')); await pause(); return; }
            const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.primary('Select:'), choices: withNotes.map(e => ({ name: `📝 ${e.name}`, value: e.id })) }]);
            const e = withNotes.find(x => x.id === id);
            console.log(COLORS.primary(`\n  ── ${COLORS.white.bold(e.name)} ──\n`));
            console.log(COLORS.white(`  ${e.secureNotes}\n`));
        } else {
            const { id } = await inquirer.prompt([{ type: 'list', name: 'id', message: COLORS.primary('Entry:'), choices: entries.map(e => ({ name: `${e.secureNotes ? '📝 ' : ''}${e.name}`, value: e.id })) }]);
            const entry = entries.find(e => e.id === id);
            console.log(COLORS.dim('\n  Multi-line: type your note, end with an empty line.\n'));
            const { note } = await inquirer.prompt([{ type: 'editor', name: 'note', message: COLORS.primary('Secure note:'), default: entry.secureNotes || '' }]);
            vault.updateEntry(masterPassword, id, { secureNotes: note.trim() || null });
            console.log(COLORS.success('\n  ✓ Secure note saved!\n'));
        }
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleIntegrity(masterPassword) {
    sectionHeader('VAULT INTEGRITY CHECK');
    const ora = require('ora');
    const spinner = ora({ text: COLORS.dim(' Verifying vault integrity...'), spinner: 'dots12', color: 'cyan' }).start();
    await sleep(600);
    const result = verifyIntegrity(masterPassword);
    logEvent(masterPassword, EVENT_TYPES.INTEGRITY_CHECK, { valid: result.valid });
    spinner.stop();

    if (result.valid === true) console.log(COLORS.success(`\n  ✓ ${result.details}\n`));
    else if (result.valid === false) console.log(COLORS.accent(`\n  ✗ ${result.details}\n`));
    else console.log(COLORS.warning(`\n  ⚠ ${result.details}\n`));

    const { action } = await inquirer.prompt([{ type: 'list', name: 'action', message: COLORS.primary('Action:'), choices: [{ name: '🔄 Update integrity record', value: 'update' }, { name: '← Back', value: 'back' }] }]);
    if (action === 'update') { saveIntegrity(masterPassword); console.log(COLORS.success('\n  ✓ Integrity record updated.\n')); }
    await pause();
}

async function handleAuditLog(masterPassword) {
    sectionHeader('AUDIT LOG');
    const { act } = await inquirer.prompt([{ type: 'list', name: 'act', message: COLORS.primary('View:'), choices: [{ name: '📊 Security summary', value: 'summary' }, { name: '📜 Recent events', value: 'recent' }, { name: '🗑️  Clear log', value: 'clear' }, { name: '← Back', value: 'back' }] }]);
    if (act === 'back') return;

    if (act === 'summary') {
        const s = getSecuritySummary(masterPassword);
        console.log(COLORS.primary('\n  ── SECURITY SUMMARY ──\n'));
        console.log(COLORS.white(`  Total events:     ${s.totalEvents}`));
        console.log(COLORS.white(`  Last 24h:         ${s.last24h}`));
        console.log(COLORS.white(`  Last 7 days:      ${s.last7d}`));
        console.log(COLORS.warning(`  Failed logins:    ${s.failedLogins}`));
        console.log(COLORS.accent(`  Lockouts:         ${s.lockouts}`));
        console.log(COLORS.white(`  PW reveals:       ${s.passwordReveals}`));
        console.log(COLORS.white(`  Exports:          ${s.exports}`));
        if (s.lastLogin) console.log(COLORS.dim(`  Last login:       ${s.lastLogin.timestamp}`));
        console.log('');
    } else if (act === 'recent') {
        const events = getRecentEvents(masterPassword, 25);
        if (!events.length) { console.log(COLORS.dim('\n  No events logged yet.\n')); await pause(); return; }
        console.log(COLORS.primary('\n  ── RECENT EVENTS ──\n'));
        events.forEach(e => {
            const time = e.timestamp.replace('T', ' ').substring(0, 19);
            const icon = e.event.includes('FAIL') || e.event.includes('LOCK') ? COLORS.accent('✗') : COLORS.dim('•');
            const detail = e.details && e.details.name ? ` → ${e.details.name}` : '';
            console.log(`  ${icon} ${COLORS.dim(time)}  ${COLORS.white(e.event)}${COLORS.dim(detail)}`);
        });
        console.log('');
    } else {
        const { confirm } = await inquirer.prompt([{ type: 'confirm', name: 'confirm', message: COLORS.accent('Clear entire audit log?'), default: false }]);
        if (confirm) {
            // Re-authenticate before destructive operation
            const reAuth = await requireReAuth('Confirm identity to clear audit log');
            if (!reAuth) { console.log(COLORS.accent('\n  ✗ Authentication failed.\n')); await pause(); return; }
            const { clearLog } = require('../security/auditlog'); clearLog(masterPassword); console.log(COLORS.success('\n  ✓ Log cleared.\n'));
        }
    }
    await pause();
}

async function handleDecoy(masterPassword) {
    sectionHeader('DECOY VAULT');
    console.log(COLORS.dim('  A decoy vault lets you reveal a fake password under duress.'));
    console.log(COLORS.dim('  Enter the decoy password at login to open harmless dummy entries.\n'));

    if (hasDecoyVault()) {
        console.log(COLORS.success('  ✓ Decoy vault is configured.\n'));
        const { act } = await inquirer.prompt([{ type: 'list', name: 'act', message: COLORS.primary('Action:'), choices: [{ name: '🔄 Re-create decoy vault', value: 'recreate' }, { name: '← Back', value: 'back' }] }]);
        if (act === 'back') { await pause(); return; }
    }

    const { decoyPw } = await inquirer.prompt([{ type: 'password', name: 'decoyPw', message: COLORS.primary('Set decoy password:'), mask: '•', validate: v => v.length >= 8 && /[A-Z]/.test(v) && /[a-z]/.test(v) && /[0-9]/.test(v) ? true : 'Min 8 chars, upper+lower+digit (same as master)' }]);
    const { confirmPw } = await inquirer.prompt([{ type: 'password', name: 'confirmPw', message: COLORS.primary('Confirm:'), mask: '•', validate: v => v === decoyPw ? true : 'No match' }]);
    createDecoyVault(decoyPw);
    console.log(COLORS.success('\n  ✓ Decoy vault created! Use this password at login for plausible deniability.\n'));
    await pause();
}

// ═══════════════════════════════════════════════════════════════
//  PRESERVED HANDLERS (Audit, ChangePW, Export, Import, Settings)
// ═══════════════════════════════════════════════════════════════

async function handleAudit(masterPassword) {
    sectionHeader('SECURITY AUDIT');
    const ora = require('ora');
    const spinner = ora({ text: COLORS.dim(' Scanning...'), spinner: 'dots12', color: 'cyan' }).start();
    try {
        const entries = vault.listEntries(masterPassword);
        await sleep(600); spinner.stop();
        if (!entries.length) { console.log(COLORS.dim('  No entries.\n')); await pause(); return; }
        console.log(formatAuditReport(auditVault(entries)));
    } catch (err) { spinner.stop(); console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleBreachCheck(masterPassword) {
    sectionHeader('BREACH CHECK (HAVEIBEENPWNED)');
    console.log(COLORS.dim('  Uses k-anonymity — only 5 chars of SHA-1 hash are sent.'));
    console.log(COLORS.dim('  Your actual passwords never leave your machine.\n'));
    try {
        const entries = vault.listEntries(masterPassword);
        if (!entries.length) { console.log(COLORS.dim('  No entries.\n')); await pause(); return; }
        const { confirm } = await inquirer.prompt([{ type: 'confirm', name: 'confirm', message: COLORS.primary(`Check ${entries.length} passwords against known breaches?`), default: true }]);
        if (!confirm) { await pause(); return; }

        const ora = require('ora');
        const spinner = ora({ text: COLORS.dim(` Checking 0/${entries.length}...`), spinner: 'dots12', color: 'cyan' }).start();

        const result = await checkBreaches(entries, (done, total, name) => {
            spinner.text = COLORS.dim(` Checking ${done}/${total} — ${name}...`);
        });
        spinner.stop();

        logEvent(masterPassword, EVENT_TYPES.BREACH_CHECK, { total: result.total, breached: result.breached });

        if (result.breached === 0) {
            console.log(COLORS.success(`\n  ✓ All ${result.safe} passwords are clean! No breaches found.\n`));
        } else {
            console.log(COLORS.accent(`\n  ⚠ ${result.breached} PASSWORD(S) FOUND IN DATA BREACHES:\n`));
            result.results.filter(r => r.breached).forEach(r => {
                console.log(COLORS.accent(`    ✗ ${COLORS.white.bold(r.entry.name)} (${r.entry.username || '—'})`) + COLORS.dim(` — seen ${r.count.toLocaleString()} times`));
            });
            console.log(COLORS.warning('\n  Change these passwords immediately!\n'));
        }
        if (result.errors > 0) console.log(COLORS.dim(`  (${result.errors} could not be checked — network errors)\n`));
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleChangeMasterPassword(masterPassword) {
    sectionHeader('CHANGE MASTER PASSWORD');
    console.log(COLORS.warning('  ⚠ This re-encrypts your entire vault.\n'));
    const { currentPw } = await inquirer.prompt([{ type: 'password', name: 'currentPw', message: COLORS.primary('Current:'), mask: '•' }]);
    // Use proper KDF-based verification (constant-time) instead of string comparison
    const { verifyMasterPassword } = require('../auth/master');
    const authResult = verifyMasterPassword(currentPw);
    if (!authResult.success || authResult.isDecoy) { console.log(COLORS.accent('\n  ✗ Wrong password.\n')); await pause(); return masterPassword; }
    const { newPw } = await inquirer.prompt([{ type: 'password', name: 'newPw', message: COLORS.primary('New:'), mask: '•', validate: v => v.length >= 8 && /[A-Z]/.test(v) && /[a-z]/.test(v) && /[0-9]/.test(v) && v !== currentPw ? true : 'Min 8, upper+lower+digit, different from current' }]);
    await inquirer.prompt([{ type: 'password', name: 'c', message: COLORS.primary('Confirm:'), mask: '•', validate: v => v === newPw ? true : 'No match' }]);
    const ora = require('ora');
    const spinner = ora({ text: COLORS.dim(' Re-encrypting...'), spinner: 'dots12', color: 'cyan' }).start();
    try {
        const count = vault.reEncryptVault(masterPassword, newPw);
        changeMasterPassword(masterPassword, newPw);
        // Zero old session key and derive new one from the new password
        const { createSessionKey, zeroSessionKey } = require('../auth/master');
        zeroSessionKey();
        const newSessionPw = createSessionKey(newPw);
        logEvent(newSessionPw, EVENT_TYPES.MASTER_PW_CHANGE);
        await sleep(1000); spinner.succeed(COLORS.success(` Done! ${count} entries re-encrypted.`));
        console.log(''); await pause(); return newSessionPw;
    } catch (err) { spinner.fail(COLORS.accent(` ${err.message}`)); await pause(); return masterPassword; }
}

/**
 * Re-authenticate the user before sensitive operations.
 * Returns true if verification succeeds, false otherwise.
 */
async function requireReAuth(promptMessage = 'Re-enter master password') {
    const { pw } = await inquirer.prompt([{
        type: 'password', name: 'pw',
        message: COLORS.warning(`🔐 ${promptMessage}:`),
        mask: '•',
    }]);
    const { verifyMasterPassword } = require('../auth/master');
    const result = verifyMasterPassword(pw);
    return result.success && !result.isDecoy;
}

async function handleExport(masterPassword) {
    sectionHeader('EXPORT VAULT');
    try {
        const entries = vault.listEntries(masterPassword);
        if (!entries.length) { console.log(COLORS.dim('  No entries.\n')); await pause(); return; }
        // Re-authenticate before export to prevent walk-up attacks
        const reAuth = await requireReAuth('Verify identity to export vault');
        if (!reAuth) { console.log(COLORS.accent('\n  ✗ Authentication failed. Export cancelled.\n')); await pause(); return; }
        const { format } = await inquirer.prompt([{
            type: 'list', name: 'format', message: COLORS.primary('Format:'), choices: [
                { name: '🔒 Encrypted JSON', value: 'enc' }, { name: '📄 JSON', value: 'json' },
                { name: '📊 CSV (with PW)', value: 'csv' }, { name: '📊 CSV (masked)', value: 'csvm' }, { name: '← Cancel', value: 'x' }
            ]
        }]);
        if (format === 'x') return;
        const dir = getDefaultExportDir();
        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
        let result;
        if (format === 'enc') {
            const { pw } = await inquirer.prompt([{ type: 'password', name: 'pw', message: COLORS.primary('Export password:'), mask: '•', validate: v => v.length >= 4 ? true : '4+' }]);
            await inquirer.prompt([{ type: 'password', name: 'c', message: COLORS.primary('Confirm:'), mask: '•', validate: v => v === pw ? true : 'No match' }]);
            result = exportToEncryptedJSON(entries, path.join(dir, `vault-${ts}.encrypted.json`), pw);
        } else if (format === 'json') {
            console.log(COLORS.warning('\n  ⚠ Plaintext!\n'));
            const { ok } = await inquirer.prompt([{ type: 'confirm', name: 'ok', message: COLORS.accent('Continue?'), default: false }]);
            if (!ok) return;
            result = exportToJSON(entries, path.join(dir, `vault-${ts}.json`));
        } else {
            if (format === 'csv') { console.log(COLORS.warning('\n  ⚠ Plaintext passwords!\n')); const { ok } = await inquirer.prompt([{ type: 'confirm', name: 'ok', message: COLORS.accent('Continue?'), default: false }]); if (!ok) return; }
            result = exportToCSV(entries, path.join(dir, `vault-${ts}.csv`), format === 'csv');
        }
        if (result) { logEvent(masterPassword, EVENT_TYPES.EXPORT, { format, count: result.entries }); console.log(COLORS.success(`\n  ✓ Exported ${result.entries} entries → ${COLORS.dim(result.path)}\n`)); }
    } catch (err) { console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleImport(masterPassword) {
    sectionHeader('IMPORT PASSWORDS');
    console.log(COLORS.dim('  Supports: CSV (Chrome/FF/BW/1PW), JSON, KeePass XML\n'));
    const { filePath } = await inquirer.prompt([{ type: 'input', name: 'filePath', message: COLORS.primary('File path:'), validate: v => { const c = v.trim().replace(/^["']|["']$/g, ''); return fs.existsSync(c) ? true : 'Not found'; } }]);
    const clean = filePath.trim().replace(/^["']|["']$/g, '');
    const ora = require('ora');
    const spinner = ora({ text: COLORS.dim(' Analyzing...'), spinner: 'dots12', color: 'cyan' }).start();
    try {
        let r = autoImport(clean);
        if (r.needsPassword) { spinner.stop(); const { pw } = await inquirer.prompt([{ type: 'password', name: 'pw', message: COLORS.primary('Password:'), mask: '•' }]); r = importFromEncryptedJSON(clean, pw); } else { await sleep(400); spinner.stop(); }
        if (r.errors) r.errors.forEach(e => console.log(COLORS.accent(`  ✗ ${e}`)));
        if (!r.entries || !r.entries.length) { console.log(COLORS.dim('\n  No entries found.\n')); await pause(); return; }
        console.log(COLORS.success(`\n  Found ${r.entries.length} entries (${r.format}):\n`));
        r.entries.slice(0, 8).forEach((e, i) => console.log(COLORS.dim(`  ${i + 1}. ${COLORS.white(e.name)} (${e.username || '—'})`)));
        if (r.entries.length > 8) console.log(COLORS.dim(`  ... +${r.entries.length - 8} more\n`));
        const { ok } = await inquirer.prompt([{ type: 'confirm', name: 'ok', message: COLORS.primary(`Import ${r.entries.length}?`), default: true }]);
        if (!ok) { console.log(COLORS.dim('\n  Cancelled.\n')); await pause(); return; }
        const added = vault.bulkAddEntries(masterPassword, r.entries);
        logEvent(masterPassword, EVENT_TYPES.IMPORT, { count: added.length });
        console.log(COLORS.success(`\n  ✓ Imported ${added.length} entries!\n`));
    } catch (err) { spinner.stop(); console.log(COLORS.accent(`\n  ✗ ${err.message}\n`)); }
    await pause();
}

async function handleSettings() {
    sectionHeader('SETTINGS');
    const config = loadConfig();
    console.log(COLORS.white(`  Timeout: ${COLORS.primary(config.sessionTimeoutMinutes + 'min')} · Clipboard: ${COLORS.primary(config.clipboardClearSeconds + 's')} · Boot anim: ${COLORS.primary(config.showBootAnimation ? 'ON' : 'OFF')} · Backups: ${COLORS.primary(config.autoBackup ? 'ON' : 'OFF')} (${config.maxBackups})\n`));
    const { s } = await inquirer.prompt([{
        type: 'list', name: 's', message: COLORS.primary('Change:'), choices: [
            { name: `⏱ Timeout (${config.sessionTimeoutMinutes}min)`, value: 'timeout' },
            { name: `📋 Clipboard delay (${config.clipboardClearSeconds}s)`, value: 'clip' },
            { name: `🎬 Boot animation (${config.showBootAnimation ? 'ON' : 'OFF'})`, value: 'anim' },
            { name: `💾 Auto-backup (${config.autoBackup ? 'ON' : 'OFF'})`, value: 'bak' },
            { name: COLORS.warning('🔄 Reset'), value: 'reset' },
            { name: '← Back', value: 'back' },
        ]
    }]);
    if (s === 'back') return;
    if (s === 'reset') { saveConfig(DEFAULTS); console.log(COLORS.success('\n  ✓ Reset.\n')); await pause(); return; }
    if (s === 'timeout') { const { v } = await inquirer.prompt([{ type: 'number', name: 'v', message: '1–30 min:', default: config.sessionTimeoutMinutes, validate: v => v >= 1 && v <= 30 ? true : '1–30' }]); config.sessionTimeoutMinutes = v; require('../auth/master').setSessionTimeout(v * 60000); }
    else if (s === 'clip') { const { v } = await inquirer.prompt([{ type: 'number', name: 'v', message: '5–120s:', default: config.clipboardClearSeconds, validate: v => v >= 5 && v <= 120 ? true : '5–120' }]); config.clipboardClearSeconds = v; }
    else if (s === 'anim') config.showBootAnimation = !config.showBootAnimation;
    else if (s === 'bak') config.autoBackup = !config.autoBackup;
    saveConfig(config);
    logEvent(null, EVENT_TYPES.SETTINGS_CHANGE, { setting: s });
    console.log(COLORS.success('\n  ✓ Saved.\n'));
    await pause();
}

// ═══════════════════════════════════════════════════════════════
//  UTILITIES
// ═══════════════════════════════════════════════════════════════

function getStrength(pw) {
    let charset = 0;
    if (/[a-z]/.test(pw)) charset += 26; if (/[A-Z]/.test(pw)) charset += 26;
    if (/[0-9]/.test(pw)) charset += 10; if (/[^a-zA-Z0-9]/.test(pw)) charset += 32;
    const entropy = Math.floor(pw.length * Math.log2(charset || 1));
    let bar, label;
    if (entropy >= 128) { bar = COLORS.success('█'.repeat(10)); label = COLORS.success('EXCEPTIONAL'); }
    else if (entropy >= 80) { bar = COLORS.success('█'.repeat(8) + '░░'); label = COLORS.success('STRONG'); }
    else if (entropy >= 60) { bar = COLORS.warning('█'.repeat(6) + '░░░░'); label = COLORS.warning('GOOD'); }
    else if (entropy >= 40) { bar = COLORS.warning('█'.repeat(4) + '░░░░░░'); label = COLORS.warning('FAIR'); }
    else { bar = COLORS.accent('██' + '░░░░░░░░'); label = COLORS.accent('WEAK'); }
    return { bar, label, entropy };
}

function truncate(str, max) { return str && str.length > max ? str.substring(0, max - 1) + '…' : (str || ''); }

async function pause() {
    await inquirer.prompt([{ type: 'input', name: 'c', message: COLORS.dim('Press Enter...') }]);
}

module.exports = { mainMenu };
