'use strict';

// ═══════════════════════════════════════════════════════════════
//  CATEGORIES — Organize vault entries into groups
// ═══════════════════════════════════════════════════════════════

const DEFAULT_CATEGORIES = [
    { id: 'social', name: 'Social Media', icon: '🌐' },
    { id: 'finance', name: 'Finance & Banking', icon: '💳' },
    { id: 'work', name: 'Work & Business', icon: '💼' },
    { id: 'email', name: 'Email', icon: '📧' },
    { id: 'gaming', name: 'Gaming', icon: '🎮' },
    { id: 'shopping', name: 'Shopping', icon: '🛒' },
    { id: 'dev', name: 'Development', icon: '💻' },
    { id: 'crypto', name: 'Cryptocurrency', icon: '₿' },
    { id: 'health', name: 'Health & Medical', icon: '🏥' },
    { id: 'education', name: 'Education', icon: '🎓' },
    { id: 'entertainment', name: 'Entertainment', icon: '🎬' },
    { id: 'other', name: 'Other', icon: '📁' },
    { id: 'none', name: 'Uncategorized', icon: '—' },
];

/**
 * Get all available categories.
 */
function getCategories() {
    return DEFAULT_CATEGORIES;
}

/**
 * Get category by ID.
 */
function getCategoryById(id) {
    return DEFAULT_CATEGORIES.find(c => c.id === id) || DEFAULT_CATEGORIES[DEFAULT_CATEGORIES.length - 1];
}

/**
 * Get display string for a category.
 */
function getCategoryDisplay(id) {
    const cat = getCategoryById(id);
    return `${cat.icon} ${cat.name}`;
}

/**
 * Get category choices for inquirer prompts.
 */
function getCategoryChoices() {
    return DEFAULT_CATEGORIES.map(c => ({
        name: `${c.icon}  ${c.name}`,
        value: c.id,
    }));
}

/**
 * Filter entries by category.
 */
function filterByCategory(entries, categoryId) {
    if (categoryId === 'all' || !categoryId) return entries;
    return entries.filter(e => (e.category || 'none') === categoryId);
}

/**
 * Group entries by category.
 */
function groupByCategory(entries) {
    const groups = {};
    entries.forEach(e => {
        const cat = e.category || 'none';
        if (!groups[cat]) groups[cat] = [];
        groups[cat].push(e);
    });
    return groups;
}

/**
 * Auto-detect category from entry name/url.
 */
function autoDetectCategory(entry) {
    const text = `${entry.name} ${entry.url || ''}`.toLowerCase();

    const rules = [
        { pattern: /facebook|twitter|instagram|tiktok|reddit|linkedin|discord|mastodon|bluesky|snapchat/i, id: 'social' },
        { pattern: /bank|paypal|venmo|cashapp|chase|wells\s?fargo|citi|capital\s?one|stripe|wise/i, id: 'finance' },
        { pattern: /slack|jira|confluence|notion|asana|trello|zoom|teams|office|salesforce/i, id: 'work' },
        { pattern: /gmail|outlook|yahoo|proton|icloud|mail/i, id: 'email' },
        { pattern: /steam|epic|xbox|playstation|psn|nintendo|riot|battle\.net|origin|ubisoft/i, id: 'gaming' },
        { pattern: /amazon|ebay|etsy|walmart|target|shopify|aliexpress/i, id: 'shopping' },
        { pattern: /github|gitlab|bitbucket|docker|aws|azure|gcp|heroku|vercel|netlify|npm/i, id: 'dev' },
        { pattern: /coinbase|binance|kraken|metamask|ledger|bitcoin|ethereum|crypto/i, id: 'crypto' },
        { pattern: /hospital|clinic|health|medical|pharmacy|doctor/i, id: 'health' },
        { pattern: /university|school|coursera|udemy|khan|edu\b/i, id: 'education' },
        { pattern: /netflix|spotify|hulu|disney|youtube|twitch|hbo|paramount|apple\s?tv/i, id: 'entertainment' },
    ];

    for (const rule of rules) {
        if (rule.pattern.test(text)) return rule.id;
    }

    return 'none';
}

module.exports = {
    getCategories,
    getCategoryById,
    getCategoryDisplay,
    getCategoryChoices,
    filterByCategory,
    groupByCategory,
    autoDetectCategory,
};
