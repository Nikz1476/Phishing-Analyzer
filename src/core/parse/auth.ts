// Header forensics: Authentication-Results parsing, trust handling, Received
// chain analysis and LOCALLY RECOMPUTED alignment.
//
// WHY recompute alignment: `dmarc=pass` from a header can be forged, and even
// a genuine `pass` can mean "authenticated for the attacker's own domain".
// We recompute SPF/DKIM/DMARC alignment locally (registrable domains of
// smtp.mailfrom / header.d vs From) and show BOTH the reported and computed
// results.

import { parseAddressList, domainOf, headerValue } from './headers';
import { registrableDomain } from '../url/parse';
import type { AlignmentSummary, AuthResultSummary, ReceivedHop } from '../types';

interface AuthMethod {
  method: string;
  result: string;
  properties: Record<string, string>;
  comment?: string;
}

/**
 * Parse one Authentication-Results header value into its methods.
 * Grammar handled: `authserv-id [methods...]` where each method is
 * `name=result (comment) ptype.property=value ...`
 */
export function parseAuthResults(value: string): { authservId: string; methods: AuthMethod[] } {
  // Strip comments first? No - comments can be inside methods and contain
  // useful detail (e.g. `(enhanced:...)`), so we handle them inline instead.
  let rest = value.trim();

  // authserv-id is the first token (may contain dots), possibly quoted.
  let authservId = '';
  const quoted = /^"([^"]+)"\s+/.exec(rest);
  if (quoted) {
    authservId = quoted[1]!;
    rest = rest.slice(quoted[0].length);
  } else {
    const m = /^([^\s;]+)\s+/.exec(rest);
    if (m) {
      authservId = m[1]!;
      rest = rest.slice(m[0].length);
    } else {
      return { authservId: '', methods: [] };
    }
  }

  const methods: AuthMethod[] = [];
  const methodRe = /([a-z0-9_.-]+)\s*=\s*([a-z]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = methodRe.exec(rest)) !== null) {
    const method = m[1]!.toLowerCase();
    const result = m[2]!.toLowerCase();
    // Capture everything up to the next method-like token (or end).
    const tailStart = methodRe.lastIndex;
    const next = /(?:^|\s)([a-z0-9_.-]+)\s*=\s*([a-z]+)/i.exec(rest.slice(tailStart));
    const tailEnd = next ? tailStart + (next.index ?? 0) : rest.length;
    const tail = rest.slice(tailStart, tailEnd);
    const properties: Record<string, string> = {};
    const propRe = /([a-z0-9_.-]+)\.([a-z0-9_.-]+)\s*=\s*([^\s;]+)/gi;
    let p: RegExpExecArray | null;
    while ((p = propRe.exec(tail)) !== null) {
      properties[`${p[1]!.toLowerCase()}.${p[2]!.toLowerCase()}`] = stripQuotes(p[3]!);
    }
    const comment = /\(([^)]*)\)/.exec(tail)?.[1];
    methods.push(comment ? { method, result, properties, comment } : { method, result, properties });
  }

  return { authservId, methods };
}

const PRIVATE_IP_RE = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|169\.254\.|224\.|255\.)/;

function isPrivateReserved(ip: string): boolean {
  return PRIVATE_IP_RE.test(ip);
}

/** Parse one Received header (best effort). */
export function parseReceived(value: string): Omit<ReceivedHop, 'index' | 'delayMs'> {
  const notes: string[] = [];
  const fromMatch = /from\s+([^\s(]+)\s*(?:\(([^)]*)\))?/.exec(value);
  const byMatch = /by\s+([^\s(]+)\s*/.exec(value);
  const withMatch = /with\s+([^\s;]+)/.exec(value);
  const ipMatch = /\[([\d.]{3,15})\]/.exec(value) ?? /\[([0-9a-f:]{3,40})\]/i.exec(value);
  const dateMatch = /;\s*(.+)$/.exec(value);

  const from = fromMatch?.[1] ?? null;
  const rdns = fromMatch?.[2]?.replace(/\s*\[[^\]]*\]\s*/, '').trim() ?? null;
  const ip = ipMatch?.[1] ?? null;

  return {
    from,
    by: byMatch?.[1] ?? null,
    with: withMatch?.[1] ?? null,
    ip,
    rdns,
    date: dateMatch?.[1]?.trim() ?? null,
    notes
  };
}

/** Parse the full Received chain and compute inter-hop delays + anomalies. */
export function parseReceivedChain(values: string[]): ReceivedHop[] {
  // Received headers are in reverse order (newest first); reverse for display
  // oldest-first as Section 6.5 requires.
  const parsed = values.map(parseReceived);
  const reversed = [...parsed].reverse();

  const withDates = reversed.map((hop) => (hop.date ? Date.parse(hop.date) : NaN));

  reversed.forEach((hop, index) => {
    hop.notes = [];
    if (index === 0 && hop.ip && isPrivateReserved(hop.ip)) {
      hop.notes.push('First hop IP is in a private/reserved range');
    }
    const prev = withDates[index - 1] ?? Number.NaN;
    const cur = withDates[index] ?? Number.NaN;
    if (Number.isFinite(prev) && Number.isFinite(cur) && cur < prev) {
      hop.notes.push('Timestamp is earlier than the previous hop');
    }
    if (hop.from && hop.rdns && /[\d.]/.test(hop.from) && hop.rdns !== hop.from) {
      hop.notes.push('HELO does not match rDNS');
    }
  });

  const hops: ReceivedHop[] = [];
  let prev = Number.NaN;
  reversed.forEach((hop, index) => {
    const cur = hop.date ? Date.parse(hop.date) : NaN;
    const delayMs = Number.isFinite(prev) && Number.isFinite(cur) ? Math.max(0, cur - prev) : null;
    hops.push({ index, delayMs, ...hop });
    prev = cur;
  });
  return hops;
}

/**
 * Recompute alignment locally: registrable domains of the reported
 * smtp.mailfrom / header.d vs the registrable domain of the From header.
 */
export function computeAlignment(
  authResults: AuthResultSummary[],
  fromAddress: string | null,
  fromDomain: string | null
): AlignmentSummary | null {
  const trusted = authResults.filter((a) => a.trusted);
  if (trusted.length === 0) return null;

  const fromReg = fromDomain ?? (fromAddress ? domainOf(fromAddress) : null);
  const fromRegistrable = fromReg ? registrableDomain(fromReg) : null;

  const spf = trusted.find((a) => a.method === 'spf');
  const dkim = trusted.find((a) => a.method === 'dkim');
  const dmarc = trusted.find((a) => a.method === 'dmarc');

  const spfMailfrom = spf?.properties['smtp.mailfrom'] ?? spf?.properties['envelope.from'] ?? null;
  const spfDomain = spfMailfrom ? domainOf(spfMailfrom) : null;
  const spfAligned = spfDomain && fromRegistrable
    ? registrableDomain(spfDomain) === fromRegistrable
    : null;

  const dkimResults = trusted.filter((a) => a.method === 'dkim');
  const dkimDomains = dkimResults.map((a) => a.properties['header.d']).filter((v): v is string => !!v);
  const dkimAligned = dkimDomains.length > 0 && fromRegistrable
    ? dkimDomains.some((d) => registrableDomain(d) === fromRegistrable)
    : null;
  const dkimPassed = dkimResults.some((a) => a.result === 'pass');

  // DMARC passes iff (SPF pass AND aligned) OR (DKIM pass AND aligned), using
  // relaxed alignment. This is the LOCAL computation, independent of the
  // reported `dmarc=` value.
  const localDmarc =
    fromRegistrable === null
      ? null
      : (spf?.result === 'pass' && spfAligned === true) ||
        (dkimPassed && dkimAligned === true);

  const summary: AlignmentSummary = {
    spf: {
      reported: spf?.result ?? null,
      locallyAligned: spfAligned === null ? null : Boolean(spfAligned) && spf?.result === 'pass'
    },
    dkim: {
      reported: dkim?.result ?? null,
      locallyAligned: dkimAligned === null ? null : Boolean(dkimAligned) && dkimPassed
    },
    dmarc: {
      reported: dmarc?.result ?? null,
      locallyComputed: localDmarc
    }
  };
  return summary;
}

/** Convenience: the From address parsed from a header value. */
export function fromAddressOf(headers: { name: string; value: string }[]): string | null {
  const value = headerValue(headers as never, 'From');
  if (!value) return null;
  return parseAddressList(value)[0]?.address ?? null;
}

function stripQuotes(v: string): string {
  return v.replace(/^"|"$/g, '');
}

/**
 * Collect Authentication-Results across all instances of the header.
 * Per Section 6.2 we trust only the TOPMOST one (added last by the final
 * receiving server); earlier ones are recorded but marked not trusted.
 */
export function collectAuthResults(headerValuesList: string[]): AuthResultSummary[] {
  const out: AuthResultSummary[] = [];
  // headerValuesList is in document order; topmost = first occurrence.
  headerValuesList.forEach((value, index) => {
    const { authservId, methods } = parseAuthResults(value);
    for (const method of methods) {
      out.push({
        authservId,
        method: method.method,
        result: method.result,
        properties: method.properties,
        trusted: index === 0,
        ...(method.comment ? { rawComment: method.comment } : {})
      });
    }
  });
  return out;
}
