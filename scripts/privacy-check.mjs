#!/usr/bin/env node
// Static scan that fails the build if any network-capable API or remote URL
// sneaks into the source or built output. This is Section 12.8's CI gate and
// the single most important proof this project backs up its privacy claim
// with something a recruiter (or attacker) could actually verify, not just
// a sentence in the README.
//
// No dependency is used on purpose: this script IS part of the trust
// boundary, so it should be trivially auditable by reading it top to bottom.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const FORBIDDEN_PATTERNS = [
  { name: 'fetch(', pattern: /\bfetch\s*\(/ },
  { name: 'XMLHttpRequest', pattern: /XMLHttpRequest/ },
  { name: 'WebSocket', pattern: /\bnew\s+WebSocket\s*\(/ },
  { name: 'EventSource', pattern: /\bnew\s+EventSource\s*\(/ },
  { name: 'sendBeacon', pattern: /navigator\.sendBeacon/ },
  { name: 'importScripts', pattern: /importScripts\s*\(/ },
  { name: 'remote Worker', pattern: /new\s+Worker\s*\(\s*['"`]https?:\/\// },
  { name: 'remote <script src="http', pattern: /<script[^>]+src\s*=\s*["']https?:\/\// },
  { name: 'remote <link href="http', pattern: /<link[^>]+href\s*=\s*["']https?:\/\// },
  { name: '@import url(http', pattern: /@import\s+url\(\s*['"]?https?:\/\// },
  { name: 'bare http(s):// string', pattern: /https?:\/\/\S+/ }
];

// Allow-listed files/lines where a documented http(s) string is fine - e.g.
// RFC references in comments/docs, or this script's own pattern definitions.
const ALLOWLIST_FILE_SUFFIXES = ['.md', '.test.ts', 'privacy-check.mjs'];

const SCAN_ROOTS = ['src', 'dist'];
const SCAN_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.html', '.css', '.json']);

function walk(dir, results = []) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return results; // directory may not exist yet (e.g. dist/ before build)
  }
  for (const entry of entries) {
    const full = join(dir, entry);
    const stats = statSync(full);
    if (stats.isDirectory()) {
      if (entry === 'node_modules' || entry === '.git') continue;
      walk(full, results);
    } else {
      results.push(full);
    }
  }
  return results;
}

function isAllowlisted(filePath) {
  return ALLOWLIST_FILE_SUFFIXES.some((suffix) => filePath.endsWith(suffix));
}

function scanFile(filePath) {
  const violations = [];
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  lines.forEach((line, index) => {
    for (const { name, pattern } of FORBIDDEN_PATTERNS) {
      if (pattern.test(line)) {
        violations.push({ filePath, line: index + 1, rule: name, text: line.trim() });
      }
    }
  });
  return violations;
}

function main() {
  const allViolations = [];
  for (const root of SCAN_ROOTS) {
    const files = walk(root).filter((f) => {
      const ext = f.slice(f.lastIndexOf('.'));
      return SCAN_EXTENSIONS.has(ext) && !isAllowlisted(f);
    });
    for (const file of files) {
      allViolations.push(...scanFile(file));
    }
  }

  if (allViolations.length > 0) {
    console.error('Privacy check FAILED. Forbidden network-related patterns found:\n');
    for (const v of allViolations) {
      console.error(`  ${v.filePath}:${v.line}  [${v.rule}]  ${v.text}`);
    }
    console.error(`\n${allViolations.length} violation(s). See Section 12.8 of the project spec.`);
    process.exit(1);
  }

  console.log('Privacy check passed: no forbidden network APIs or remote URLs found in src/ or dist/.');
}

main();
