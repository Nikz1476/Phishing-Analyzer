// Indicator extraction: emails, IPs, crypto addresses and phone numbers.
// Used for the IOC panel and by a couple of rules (FIN-CRYPTO-ADDR context,
// FIN-CALLBACK).

const EMAIL_RE = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi;
const IPV4_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/g;
const CRYPTO_RE = /\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g;
const PHONE_RE = /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,5}\)[\s.-]?|\d{2,5}[\s.-])\d{3,4}[\s.-]?\d{3,4}\b/g;

function unique(matches: string[]): string[] {
  return [...new Set(matches.map((m) => m.trim()))];
}

export function extractEmails(text: string): string[] {
  return unique(text.match(EMAIL_RE) ?? []);
}

export function extractIps(text: string): string[] {
  return unique((text.match(IPV4_RE) ?? []).filter((ip) => ip.split('.').every((o) => Number(o) <= 255)));
}

export function extractCrypto(text: string): string[] {
  return unique(text.match(CRYPTO_RE) ?? []);
}

export function extractPhones(text: string): string[] {
  // Require at least 8 digits so we do not match dates or years.
  return unique((text.match(PHONE_RE) ?? []).filter((p) => (p.replace(/\D/g, '').length >= 8)));
}

export function hasCryptoAddress(text: string): boolean {
  return extractCrypto(text).length > 0;
}