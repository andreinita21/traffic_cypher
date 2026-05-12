'use strict';
// Pinned spec test for the esc() helper in app.js.
// The shell test grep-checks that app.js contains this exact body;
// this file asserts the body produces the expected output.

function esc(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const assert = require('assert');

// Plain text passes through.
assert.strictEqual(esc('hello'), 'hello');

// null / undefined → empty.
assert.strictEqual(esc(null), '');
assert.strictEqual(esc(undefined), '');
assert.strictEqual(esc(''), '');

// Falsy strings survive (the old `!str` guard ate "0").
assert.strictEqual(esc('0'), '0');

// Quote encoding — the whole point of the fix.
assert.strictEqual(esc('"x"'), '&quot;x&quot;');
assert.strictEqual(esc("'x'"), '&#39;x&#39;');

// Ampersand must encode first so subsequent passes don't double-process.
assert.strictEqual(esc('&'), '&amp;');
assert.strictEqual(esc('&amp;'), '&amp;amp;');

// Angle brackets.
assert.strictEqual(esc('<script>alert(1)</script>'),
                   '&lt;script&gt;alert(1)&lt;/script&gt;');

// Realistic stored-XSS payloads for HTML attribute context.
assert.strictEqual(esc('" onmouseover="alert(1)'),
                   '&quot; onmouseover=&quot;alert(1)');
assert.strictEqual(esc("' onclick='alert(1)"),
                   '&#39; onclick=&#39;alert(1)');

// Non-string coercion must not throw.
assert.strictEqual(esc(42), '42');
assert.strictEqual(esc(true), 'true');

console.log('esc() spec test: PASS (13 assertions)');
