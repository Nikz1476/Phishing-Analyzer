// Redirect-wrapper unwrapping - entirely local, no network.
//
// WHY: scanners and mail gateways rewrite links, and attackers abuse the same
// rewrites to hide the real destination. We peel the wrapper off so the INNER
// url can be analysed as its own url (that is where the phishing domain lives).

import { registrableDomain } from './parse';

export interface UnwrapResult {
  chain: string[]; // [wrapper, ..., inner]
  final: string;
  depth: number;
  loop: boolean;
}

const REDIRECT_PARAMS = ['url', 'u', 'q', 'target', 'dest', 'destination', 'redirect', 'next', 'continue', 'returnurl', 'redirect_uri', 'link'];

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

function unwrapOnce(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const host = url.hostname.toLowerCase();
  const reg = registrableDomain(host) ?? host;

  // Microsoft Safe Links
  if (host.endsWith('safelinks.protection.outlook.com')) {
    const target = url.searchParams.get('url');
    if (target && isHttpUrl(target)) return target;
  }

  // Facebook link shim
  if (host === 'l.facebook.com' || host === 'lm.facebook.com') {
    const target = url.searchParams.get('u');
    if (target && isHttpUrl(target)) return target;
  }

  // Google redirector
  if ((reg === 'google.com' || host.endsWith('.google.com')) && url.pathname === '/url') {
    const target = url.searchParams.get('q') ?? url.searchParams.get('url');
    if (target && isHttpUrl(target)) return target;
  }

  // Proofpoint URL Defense v2
  if (reg === 'proofpoint.com' && /\/v2\/url/.test(url.pathname)) {
    const rawParam = url.searchParams.get('u');
    if (rawParam) {
      // v2 encoding: '-' means '%', '_' means '/'.
      const restored = rawParam.replace(/-/g, '%').replace(/_/g, '/');
      const decoded = safeDecode(restored);
      if (isHttpUrl(decoded)) return decoded;
    }
  }

  // Generic redirect parameter.
  for (const param of REDIRECT_PARAMS) {
    for (const [key, value] of url.searchParams.entries()) {
      if (key.toLowerCase() === param && isHttpUrl(value)) {
        return value;
      }
    }
  }

  return null;
}

/** Peel wrappers recursively (max depth 3) with loop detection. */
export function unwrapUrl(raw: string): UnwrapResult {
  const chain: string[] = [raw];
  const seen = new Set<string>([raw]);
  let current = raw;
  let depth = 0;
  let loop = false;
  const MAX_DEPTH = 3;

  while (depth < MAX_DEPTH) {
    const next = unwrapOnce(current);
    if (!next) break;
    const normalised = next.trim();
    if (seen.has(normalised)) {
      loop = true;
      break;
    }
    seen.add(normalised);
    chain.push(normalised);
    current = normalised;
    depth += 1;
  }

  return { chain, final: current, depth, loop };
}