'use strict';

// ═══════════════════════════════════════════════════════════════
//  COLOR THEMES — Switchable color palettes
// ═══════════════════════════════════════════════════════════════

const chalk = require('chalk');

const THEMES = {
    cyberpunk: {
        name: 'Cyberpunk',
        primary: '#00F5FF',
        secondary: '#7B68EE',
        accent: '#FF6B6B',
        success: '#00FF88',
        warning: '#FFD93D',
        dim: '#4A5568',
        white: '#E2E8F0',
        gradient: ['#00F5FF', '#0EA5E9', '#7B68EE', '#A855F7', '#EC4899'],
    },
    midnight: {
        name: 'Midnight',
        primary: '#818CF8',
        secondary: '#6366F1',
        accent: '#F472B6',
        success: '#34D399',
        warning: '#FBBF24',
        dim: '#374151',
        white: '#F3F4F6',
        gradient: ['#818CF8', '#6366F1', '#4F46E5', '#7C3AED', '#A78BFA'],
    },
    retro: {
        name: 'Retro',
        primary: '#F59E0B',
        secondary: '#EF4444',
        accent: '#EC4899',
        success: '#10B981',
        warning: '#F97316',
        dim: '#6B7280',
        white: '#FEF3C7',
        gradient: ['#F59E0B', '#EF4444', '#EC4899', '#8B5CF6', '#06B6D4'],
    },
    neon: {
        name: 'Neon',
        primary: '#39FF14',
        secondary: '#FF073A',
        accent: '#FF6EC7',
        success: '#39FF14',
        warning: '#DFFF00',
        dim: '#333333',
        white: '#FFFFFF',
        gradient: ['#39FF14', '#00FFFF', '#FF073A', '#FF6EC7', '#DFFF00'],
    },
    minimal: {
        name: 'Minimal',
        primary: '#60A5FA',
        secondary: '#9CA3AF',
        accent: '#EF4444',
        success: '#6EE7B7',
        warning: '#FCD34D',
        dim: '#6B7280',
        white: '#E5E7EB',
        gradient: ['#60A5FA', '#93C5FD', '#BFDBFE', '#93C5FD', '#60A5FA'],
    },
    hacker: {
        name: 'Hacker',
        primary: '#00FF00',
        secondary: '#00CC00',
        accent: '#FF0000',
        success: '#00FF00',
        warning: '#FFFF00',
        dim: '#003300',
        white: '#00FF00',
        gradient: ['#00FF00', '#00DD00', '#00BB00', '#00DD00', '#00FF00'],
    },
};

let currentTheme = 'cyberpunk';

/**
 * Build chalk color functions from a theme.
 */
function buildColors(themeName) {
    const t = THEMES[themeName] || THEMES.cyberpunk;
    return {
        primary: chalk.hex(t.primary),
        secondary: chalk.hex(t.secondary),
        accent: chalk.hex(t.accent),
        success: chalk.hex(t.success),
        warning: chalk.hex(t.warning),
        dim: chalk.hex(t.dim),
        white: chalk.hex(t.white),
        gradient1: chalk.hex(t.gradient[0]),
        gradient2: chalk.hex(t.gradient[1]),
        gradient3: chalk.hex(t.gradient[2]),
        gradient4: chalk.hex(t.gradient[3]),
        gradient5: chalk.hex(t.gradient[4]),
    };
}

function getThemeNames() {
    return Object.keys(THEMES);
}

function getThemeDisplayName(key) {
    return THEMES[key] ? THEMES[key].name : key;
}

function setCurrentTheme(name) {
    if (THEMES[name]) {
        currentTheme = name;
        return true;
    }
    return false;
}

function getCurrentTheme() {
    return currentTheme;
}

function getGradient(themeName) {
    const t = THEMES[themeName || currentTheme] || THEMES.cyberpunk;
    return t.gradient.map(c => chalk.hex(c));
}

module.exports = {
    THEMES,
    buildColors,
    getThemeNames,
    getThemeDisplayName,
    setCurrentTheme,
    getCurrentTheme,
    getGradient,
};
