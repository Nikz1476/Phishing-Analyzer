// URL parsing primitives: registrable domain ("eTLD+1") and feature
// extraction. This is [LEARNER-OWNED] territory per the brief, so the reasoning
// behind every non-obvious line is spelled out.

import { multiLabelSuffixes } from '../data';

export interface UrlParts {
  raw: string;
  scheme: string;
  userinfo: string | null;
  host: string; // hostname as normalised by the URL class
  rawHost: string; // hostname exactly as written in the input
  port: string | null;
  path: string;
  query: string;
  fragment: string;
  labels: string[]; // host split on '.'
  suffix: string | null; // public suffix
  registrableDomain: string | null; // eTLD+1
  subdomainDepth: number; // labels left of the registrable domain
  isIp: boolean;
  isIpv6: boolean;
  encodedIp: boolean; // decimal/hex/octal IPv4 that URL normalised for us
  length: number;
}

const MULTI_LABEL_SET = new Set(multiLabelSuffixes.map((s) => s.toLowerCase()));

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function isIpv4(host: string): boolean {
  if (!IPV4_RE.test(host)) return false;
  return host.split('.').every((octet) => Number(octet) <= 255);
}

export function isIpv6(host: string): boolean {
  return host.includes(':') && /^[0-9a-f:.]+$/i.test(host);
}

/**
 * The public suffix of a host, using our curated subset. An unknown TLD is
 * treated as a single-label suffix (documented limitation, decision 006).
 */
export function publicSuffix(host: string): string | null {
  const labels = host.toLowerCase().split('.').filter((l) => l.length > 0);
  if (labels.length === 0) return null;
  if (isIpv4(host) || isIpv6(host)) return null;
  const two = labels.slice(-2).join('.');
  if (labels.length >= 2 && MULTI_LABEL_SET.has(two)) return two;
  return labels[labels.length - 1]!;
}

/**
 * The registrable domain: public suffix plus one more label. For an IP literal
 * the host itself is returned (there is nothing to register under).
 */
export function registrableDomain(host: string): string | null {
  if (!host) return null;
  if (isIpv4(host) || isIpv6(host)) return host.toLowerCase();
  const suffix = publicSuffix(host);
  if (!suffix) return null;
  const labels = host.toLowerCase().split('.').filter((l) => l.length > 0);
  const suffixLabels = suffix.split('.').length;
  if (labels.length <= suffixLabels) return labels.join('.');
  return labels.slice(-(suffixLabels + 1)).join('.');
}

/** Everything left of the registrable domain. */
export function subdomainDepthOf(host: string): number {
  const reg = registrableDomain(host);
  if (!reg) return 0;
  const labels = host.toLowerCase().split('.').filter((l) => l.length > 0);
  const regLabels = reg.split('.').length;
  return Math.max(0, labels.length - regLabels);
}

/**
 * Recover the host exactly as the user wrote it. WHY: the URL class silently
 * normalises decimal/hex/octal IPv4 (e.g. http://3221226029/ becomes
 * http://192.0.2.45/), so comparing the raw host against the normalised one is
 * the only way to notice the encoding trick.
 */
export function rawHostOf(raw: string): string {
  let s = raw.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  const at = s.lastIndexOf('@');
  if (at >= 0) s = s.slice(at + 1);
  s = s.split(/[/?#]/)[0] ?? '';
  s = s.replace(/:\d+$/, '');
  return s.replace(/^\[|\]$/g, '');
}

/** Parse a URL into features. Returns null when it is not a valid http(s) URL. */
export function parseUrl(raw: string): UrlParts | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  const host = url.hostname.toLowerCase();
  const rawHost = rawHostOf(raw);
  const ip = isIpv4(host);
  const ip6 = isIpv6(host);
  // Encoded-IP heuristic: the normalised host is an IPv4 literal, but what the
  // user typed was different and contained only digits/hex/octal-looking
  // characters (no letters that would make it a hostname).
  const encodedIp = ip && rawHost !== host && /^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}$/i.test(rawHost);
  const labels = host.split('.').filter((l) => l.length > 0);
  return {
    raw,
    scheme,
    userinfo: url.username || url.password ? `${url.username}:${url.password}` : null,
    host,
    rawHost,
    port: url.port || null,
    path: url.pathname,
    query: url.search,
    fragment: url.hash,
    labels,
    suffix: publicSuffix(host),
    registrableDomain: registrableDomain(host),
    subdomainDepth: subdomainDepthOf(host),
    isIp: ip || ip6,
    isIpv6: ip6,
    encodedIp,
    length: raw.length
  };
}