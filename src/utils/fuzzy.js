'use strict';

// ═══════════════════════════════════════════════════════════════
//  FUZZY SEARCH — Typo-tolerant matching with ranking
// ═══════════════════════════════════════════════════════════════

/**
 * Calculate Levenshtein distance between two strings.
 */
function levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
        for (let j = 1; j <= n; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,       // deletion
                dp[i][j - 1] + 1,       // insertion
                dp[i - 1][j - 1] + cost  // substitution
            );
        }
    }

    return dp[m][n];
}

/**
 * Score a string against a query (0 = no match, 100 = perfect).
 */
function scoreMatch(text, query) {
    if (!text || !query) return 0;
    const t = text.toLowerCase();
    const q = query.toLowerCase();

    // Exact match
    if (t === q) return 100;

    // Starts with
    if (t.startsWith(q)) return 90;

    // Contains
    if (t.includes(q)) return 80 - (t.indexOf(q) / t.length) * 10;

    // Fuzzy (Levenshtein)
    const dist = levenshtein(t, q);
    const maxLen = Math.max(t.length, q.length);
    const similarity = 1 - (dist / maxLen);

    if (similarity >= 0.7) return Math.round(similarity * 60);
    if (similarity >= 0.5) return Math.round(similarity * 40);

    // Subsequence match (all chars in order but not adjacent)
    if (isSubsequence(q, t)) return 30;

    return 0;
}

/**
 * Check if query is a subsequence of text.
 */
function isSubsequence(query, text) {
    let qi = 0;
    for (let ti = 0; ti < text.length && qi < query.length; ti++) {
        if (text[ti] === query[qi]) qi++;
    }
    return qi === query.length;
}

/**
 * Fuzzy search entries with ranked results.
 */
function fuzzySearch(entries, query, fields = ['name', 'username', 'url', 'notes', 'category']) {
    if (!query || query.trim() === '') return entries;

    const scored = entries.map(entry => {
        let bestScore = 0;
        let matchField = '';

        fields.forEach(field => {
            const val = entry[field];
            if (val) {
                const s = scoreMatch(val, query);
                if (s > bestScore) {
                    bestScore = s;
                    matchField = field;
                }
            }
        });

        return { entry, score: bestScore, matchField };
    });

    return scored
        .filter(r => r.score > 0)
        .sort((a, b) => b.score - a.score)
        .map(r => ({ ...r.entry, _score: r.score, _matchField: r.matchField }));
}

module.exports = { fuzzySearch, scoreMatch, levenshtein };
