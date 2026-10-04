// Metadata for every STRUCTURAL rule (URL, header, attachment, technique,
// evasion). These rules are code, not JSON, because they need real control
// flow - but they still declare the same metadata shape as the JSON phrase
// rules, so the Learn page and the report can treat both uniformly. This is
// decision record 003.

import type { Category, Confidence } from '../types';

export interface RuleMeta {
  id: string;
  category: Category;
  weight: number;
  title: string;
  why: string;
  advice: string;
  mitre: string[];
  confidence: Confidence;
}

export const STRUCTURAL_RULES: Record<string, RuleMeta> = {
  // ---------------- URL rules ----------------
  'URL-IP-HOST': {
    id: 'URL-IP-HOST', category: 'url', weight: 20,
    title: 'Link uses a raw IP address',
    why: 'Legitimate services publish domain names, not bare IP addresses. An IP host is a strong sign of throwaway infrastructure.',
    advice: 'Do not open the link. If you must check the service, type its official domain name yourself.',
    mitre: ['T1583.005'], confidence: 'medium'
  },
  'URL-IP-ENCODED': {
    id: 'URL-IP-ENCODED', category: 'url', weight: 22,
    title: 'Link uses an obfuscated IP address',
    why: 'Writing an IP as decimal, hex or octal is a deliberate trick to slip past filters and hide the real destination.',
    advice: 'Treat as hostile. This encoding has no legitimate everyday use.',
    mitre: ['T1027'], confidence: 'high'
  },
  'URL-SHORTENER': {
    id: 'URL-SHORTENER', category: 'url', weight: 10,
    title: 'Shortened link hides its destination',
    why: 'Shorteners make the real destination invisible until you click. Attackers use them to look harmless.',
    advice: 'Expand the link first, or avoid it. This tool does not visit links.',
    mitre: ['T1204.001'], confidence: 'medium'
  },
  'URL-TEXT-MISMATCH': {
    id: 'URL-TEXT-MISMATCH', category: 'url', weight: 25,
    title: 'Link text does not match the real destination',
    why: 'The visible text claims one site while the link points at another. This is a direct and deliberate deception.',
    advice: 'Do not click. Go to the site the text named by typing its address yourself.',
    mitre: ['T1036'], confidence: 'high'
  },
  'URL-USERINFO': {
    id: 'URL-USERINFO', category: 'url', weight: 20,
    title: 'Link hides its host behind user-info',
    why: 'Text before the @ is ignored by browsers; it is placed there only to make the real host look like something else (login.bank@evil.test).',
    advice: 'Treat as hostile. Read the real host after the @.',
    mitre: ['T1036'], confidence: 'high'
  },
  'URL-PUNYCODE': {
    id: 'URL-PUNYCODE', category: 'url', weight: 12,
    title: 'Link uses an internationalised (xn--) domain',
    why: 'Punycode domains are legitimate in many countries, but are also how homograph attacks hide a lookalike spelling.',
    advice: 'Check the decoded form shown here. If it imitates a brand, do not use the link.',
    mitre: ['T1036'], confidence: 'low'
  },
  'URL-MIXED-SCRIPT': {
    id: 'URL-MIXED-SCRIPT', category: 'url', weight: 25,
    title: 'Domain mixes alphabets (homograph attack)',
    why: 'Mixing Latin and another script (for example Cyrillic) in one label lets the domain look identical to a real brand while pointing elsewhere.',
    advice: 'Treat as hostile. This is a deliberate impersonation technique.',
    mitre: ['T1036'], confidence: 'high'
  },
  'URL-BRAND-IN-SUBDOMAIN': {
    id: 'URL-BRAND-IN-SUBDOMAIN', category: 'url', weight: 20,
    title: 'Brand name used as a sub-domain of a different site',
    why: 'A brand name in the sub-domain (microsoft.com.something-else.test) is there to reassure you; the real registrable domain is not the brand.',
    advice: 'Do not use the link. Reach the brand by typing its official domain.',
    mitre: ['T1583.001'], confidence: 'high'
  },
  'URL-TYPOSQUAT': {
    id: 'URL-TYPOSQUAT', category: 'url', weight: 22,
    title: 'Typosquatted lookalike domain',
    why: 'One or two characters changed (paypa1, rnicrosoft) is a classic way to register a domain that reads as the real brand.',
    advice: 'Treat as hostile. Check the real domain shown and type it yourself.',
    mitre: ['T1583.001'], confidence: 'high'
  },
  'URL-COMBOSQUAT': {
    id: 'URL-COMBOSQUAT', category: 'url', weight: 20,
    title: 'Combosquatted domain (brand plus hype words)',
    why: 'Sticking words like secure, login or verify onto a brand name creates a domain that sounds official but is not.',
    advice: 'Treat as hostile unless you have verified the domain is the brand own.',
    mitre: ['T1583.001'], confidence: 'high'
  },
  'URL-PLATFORM-ABUSE': {
    id: 'URL-PLATFORM-ABUSE', category: 'url', weight: 8,
    title: 'Redirect to a free hosting platform',
    why: 'Hosting a fake login on a reputable free platform borrows the platform reputation. On its own this is weak, so it is only scored alongside credential or impersonation findings.',
    advice: 'Be cautious; a real provider rarely hosts its sign-in on a free page builder.',
    mitre: ['T1583.006'], confidence: 'low'
  },
  'URL-WRAPPED-REDIRECT': {
    id: 'URL-WRAPPED-REDIRECT', category: 'url', weight: 8,
    title: 'Link is wrapped in a redirect',
    why: 'Redirect wrappers are legitimate in security gateways, but also hide the destination from the reader. The inner link shown here is what matters.',
    advice: 'Judge the inner destination shown, not the wrapper.',
    mitre: ['T1204.001'], confidence: 'medium'
  },
  'URL-DATA-SCHEME': {
    id: 'URL-DATA-SCHEME', category: 'url', weight: 25,
    title: 'Non-http(s) link scheme',
    why: 'data:, javascript: and vbscript: links can run code or load a page without any visible address. No legitimate email needs them.',
    advice: 'Do not click. Treat as hostile.',
    mitre: ['T1204.001'], confidence: 'high'
  },
  'URL-PERSONALISED': {
    id: 'URL-PERSONALISED', category: 'url', weight: 8,
    title: 'Link contains your address',
    why: 'Embedding the recipient address in the link is typical of targeted credential-harvesting pages and tracking.',
    advice: 'A weak signal alone; judge it with the rest of the message.',
    mitre: ['T1598.003'], confidence: 'low'
  },
  'URL-HIGH-ENTROPY': {
    id: 'URL-HIGH-ENTROPY', category: 'url', weight: 6,
    title: 'High-entropy domain label',
    why: 'Random-looking labels can be auto-generated attack domains, but also CDN and hash hostnames. Weak on its own.',
    advice: 'Judge together with other signals.',
    mitre: ['T1583.005'], confidence: 'low'
  },
  'URL-RISKY-TLD': {
    id: 'URL-RISKY-TLD', category: 'url', weight: 5,
    title: 'Top-level domain with high abuse rates',
    why: 'Some TLDs are cheap or free and disproportionately used in phishing. This is a weak signal because legitimate sites use them too.',
    advice: 'Judge together with other signals.',
    mitre: ['T1583.001'], confidence: 'low'
  },
  'URL-NONSTANDARD-PORT': {
    id: 'URL-NONSTANDARD-PORT', category: 'url', weight: 5,
    title: 'Link uses a non-standard port',
    why: 'Serving a web page on an unusual port is uncommon for real services and typical of short-lived attack servers.',
    advice: 'Weak signal; consider with the rest.',
    mitre: ['T1583.005'], confidence: 'low'
  },
  'URL-NO-TLS-LOGIN': {
    id: 'URL-NO-TLS-LOGIN', category: 'url', weight: 5,
    title: 'Sign-in link over plain HTTP',
    why: 'A login page on http:// is not encrypted, and no serious provider does this.',
    advice: 'Do not enter credentials on an http:// page.',
    mitre: ['T1598'], confidence: 'medium'
  },
  'URL-DEEP-SUBDOMAIN': {
    id: 'URL-DEEP-SUBDOMAIN', category: 'url', weight: 5,
    title: 'Very deep sub-domain nesting',
    why: 'Long sub-domain chains are used to push the real domain off the visible end of the address (a.b.c.d.e.example.test).',
    advice: 'Read the registrable domain shown, not the start of the address.',
    mitre: ['T1036'], confidence: 'low'
  },

  // ---------------- Attachment rules ----------------
  'ATT-EXECUTABLE': {
    id: 'ATT-EXECUTABLE', category: 'attachment', weight: 35,
    title: 'Executable attachment',
    why: 'A program sent as an email attachment runs if opened and is the most direct way to infect a machine.',
    advice: 'Do not open it. Report it to your IT or security team.',
    mitre: ['T1204.002', 'T1566.001'], confidence: 'high'
  },
  'ATT-DOUBLE-EXTENSION': {
    id: 'ATT-DOUBLE-EXTENSION', category: 'attachment', weight: 30,
    title: 'Double-extension attachment',
    why: 'invoice.pdf.exe looks like a PDF but is a program. The extra extension is designed to fool a quick glance.',
    advice: 'Do not open it. Treat as malware.',
    mitre: ['T1036.007'], confidence: 'high'
  },
  'ATT-RTLO': {
    id: 'ATT-RTLO', category: 'attachment', weight: 30,
    title: 'Right-to-left override in a filename',
    why: 'A hidden Unicode bidi control flips the visible filename so an .exe reads as a .doc. There is no legitimate need for this in a filename.',
    advice: 'Do not open it. Treat as hostile.',
    mitre: ['T1036.002'], confidence: 'high'
  },
  'ATT-MACRO-FILE': {
    id: 'ATT-MACRO-FILE', category: 'attachment', weight: 25,
    title: 'Macro-enabled Office document',
    why: 'Macro-enabled formats are the standard container for malicious Office macros.',
    advice: 'Do not open it or enable content. Report it.',
    mitre: ['T1204.002'], confidence: 'high'
  },
  'ATT-ARCHIVE': {
    id: 'ATT-ARCHIVE', category: 'attachment', weight: 12,
    title: 'Archive attachment',
    why: 'Archives are used to smuggle executables past filters. Not hostile by itself, but worth care.',
    advice: 'Do not extract or run files from an unexpected archive.',
    mitre: ['T1566.001'], confidence: 'low'
  },
  'ATT-DISK-IMAGE': {
    id: 'ATT-DISK-IMAGE', category: 'attachment', weight: 18,
    title: 'Disk image attachment',
    why: 'ISO/IMG/VHD files are used to bypass "mark of the web" protections so that a bundled executable runs without warning.',
    advice: 'Do not mount or open it.',
    mitre: ['T1553.005'], confidence: 'medium'
  },
  'ATT-HTML-SMUGGLING': {
    id: 'ATT-HTML-SMUGGLING', category: 'attachment', weight: 18,
    title: 'HTML/SVG attachment',
    why: 'HTML or SVG attachments can open a fake login page locally, or smuggle a program inside the markup, avoiding link scanning.',
    advice: 'Do not open it in a browser.',
    mitre: ['T1027.006'], confidence: 'medium'
  },
  'ATT-GENERIC-NAME': {
    id: 'ATT-GENERIC-NAME', category: 'attachment', weight: 4,
    title: 'Generic lure attachment name',
    why: 'Names like invoice123 or scan_2 play on routine curiosity. Weak alone, meaningful with other signals.',
    advice: 'Confirm with the sender if you did not expect it.',
    mitre: ['T1566.001'], confidence: 'low'
  },

  // ---------------- Technique / evasion ----------------
  'TECH-HIDDEN-TEXT': {
    id: 'TECH-HIDDEN-TEXT', category: 'technique', weight: 10,
    title: 'Hidden or invisible text',
    why: 'Text hidden by colour, size or position is used to slip words past filters or to pad a message to defeat simple heuristics.',
    advice: 'A sign of deliberate evasion; treat the message with suspicion.',
    mitre: ['T1027'], confidence: 'medium'
  },
  'TECH-TRACKING-PIXEL': {
    id: 'TECH-TRACKING-PIXEL', category: 'technique', weight: 2,
    title: 'Tracking pixel',
    why: 'A 1x1 remote image tells the sender when and where you opened the mail. Common in marketing, sometimes used to confirm a target is live.',
    advice: 'Informational. Block remote images if this concerns you.',
    mitre: ['T1598'], confidence: 'low'
  },
  'EVADE-ZEROWIDTH': {
    id: 'EVADE-ZEROWIDTH', category: 'evasion', weight: 8,
    title: 'Invisible characters inside words',
    why: 'Zero-width characters are inserted between letters so that "password" no longer matches a scanner keyword. There is no reason for them in normal text.',
    advice: 'Deliberate anti-scanner trickery; treat the message as hostile.',
    mitre: ['T1027.010'], confidence: 'medium'
  },
  'EVADE-HOMOGLYPH-TEXT': {
    id: 'EVADE-HOMOGLYPH-TEXT', category: 'evasion', weight: 10,
    title: 'Homoglyph characters inside words',
    why: 'Replacing letters with look-alike characters from other alphabets (Cyrillic a for Latin a) defeats keyword matching while reading normally.',
    advice: 'Deliberate anti-scanner trickery; treat the message as hostile.',
    mitre: ['T1027.010'], confidence: 'medium'
  },
  'CRED-HTML-FORM': {
    id: 'CRED-HTML-FORM', category: 'credential', weight: 25,
    title: 'Password field or form in the message',
    why: 'A real sign-in form in an email (or an HTML attachment) is almost always a phishing kit collecting credentials, especially when it posts to another site.',
    advice: 'Never type credentials into a form inside an email. Open the site directly.',
    mitre: ['T1056', 'T1566'], confidence: 'high'
  },
  'IMP-BRAND-MISMATCH': {
    id: 'IMP-BRAND-MISMATCH', category: 'impersonation', weight: 20,
    title: 'Brand claimed but no genuine infrastructure',
    why: 'The message appeals to a brand (in the subject, body or display name), yet no From domain, link domain or DKIM d= belongs to that brand. That is impersonation.',
    advice: 'Do not act on it. Contact the brand using its official app or website.',
    mitre: ['T1656', 'T1583.001'], confidence: 'medium'
  },
  'QR-URL-IN-EMAIL': {
    id: 'QR-URL-IN-EMAIL', category: 'url', weight: 10,
    title: 'QR code contains a link',
    why: 'A link inside a QR code bypasses scanners that only read text, and hides the destination from the reader.',
    advice: 'Do not scan QR codes from email; type the official address instead.',
    mitre: ['T1566.002'], confidence: 'medium'
  },

  // ---------------- Header rules ----------------
  'HDR-MULTI-FROM': {
    id: 'HDR-MULTI-FROM', category: 'header', weight: 25,
    title: 'Multiple From headers',
    why: 'A message may only have one From header. A second one is invalid and is a known trick to make one mail client display a trusted address while another routes by the other.',
    advice: 'Treat as hostile. Do not reply or act on it.',
    mitre: ['T1036'], confidence: 'high'
  },
  'HDR-REPLYTO-MISMATCH': {
    id: 'HDR-REPLYTO-MISMATCH', category: 'header', weight: 18,
    title: 'Reply-To points to a different domain',
    why: 'When the From looks corporate but replies go to a different domain, your reply is being redirected to the attacker.',
    advice: 'Do not reply to the message. Contact the sender using a known address.',
    mitre: ['T1656'], confidence: 'medium'
  },
  'HDR-REPLYTO-FREEMAIL': {
    id: 'HDR-REPLYTO-FREEMAIL', category: 'header', weight: 22,
    title: 'Reply-To is a free webmail address',
    why: 'A business message whose replies go to a personal Gmail/Outlook account is a common sign of impersonation.',
    advice: 'Do not reply. Verify the sender by phone or a known address.',
    mitre: ['T1656'], confidence: 'medium'
  },
  'HDR-REPLYTO-LOOKALIKE': {
    id: 'HDR-REPLYTO-LOOKALIKE', category: 'header', weight: 22,
    title: 'Reply-To is a lookalike of the From domain',
    why: 'The reply domain is one or two characters away from the From domain - a deliberate near-miss to catch an inattentive reply.',
    advice: 'Do not reply. Compare the two domains character by character.',
    mitre: ['T1656'], confidence: 'high'
  },
  'HDR-DISPLAY-SPOOF': {
    id: 'HDR-DISPLAY-SPOOF', category: 'header', weight: 15,
    title: 'Display name disguises the real address',
    why: 'The friendly name shows a person or brand, but the real address behind it is unrelated (often free webmail).',
    advice: 'Trust the address, not the name. Do not act on the message.',
    mitre: ['T1656'], confidence: 'medium'
  },
  'HDR-RETURNPATH-MISMATCH': {
    id: 'HDR-RETURNPATH-MISMATCH', category: 'header', weight: 6,
    title: 'Return-Path differs from From',
    why: 'A mismatch is normal for bulk senders, which is why this is weak - but combined with failures it supports a spoofing read. Halved when DKIM passes and aligns.',
    advice: 'Weak signal; consider with the rest.',
    mitre: ['T1656'], confidence: 'low'
  },
  'HDR-SPF-FAIL': {
    id: 'HDR-SPF-FAIL', category: 'header', weight: 20,
    title: 'SPF failed',
    why: 'The sending server was not authorised to send for the envelope domain. That is normal for spoofed mail.',
    advice: 'Treat with strong suspicion; do not act on the message.',
    mitre: ['T1566'], confidence: 'high'
  },
  'HDR-SPF-SOFTFAIL': {
    id: 'HDR-SPF-SOFTFAIL', category: 'header', weight: 12,
    title: 'SPF soft-failed',
    why: 'The sender is not clearly authorised but the domain asked for lenient handling. Suspicious, though forwarding can cause it.',
    advice: 'Verify the message before acting.',
    mitre: ['T1566'], confidence: 'medium'
  },
  'HDR-SPF-PERMERROR': {
    id: 'HDR-SPF-PERMERROR', category: 'header', weight: 8,
    title: 'SPF permanent error',
    why: 'The SPF record is broken or misconfigured. Weak by itself, but a common trait of throwaway domains.',
    advice: 'Consider with the rest.',
    mitre: ['T1566'], confidence: 'low'
  },
  'HDR-DKIM-FAIL': {
    id: 'HDR-DKIM-FAIL', category: 'header', weight: 18,
    title: 'DKIM failed',
    why: 'The signature did not verify, so the message (or its domain) was altered or forged. Forwarding can also break it, so this is a strong but not absolute signal.',
    advice: 'Treat with strong suspicion; confirm through another channel.',
    mitre: ['T1566'], confidence: 'medium'
  },
  'HDR-DMARC-FAIL': {
    id: 'HDR-DMARC-FAIL', category: 'header', weight: 22,
    title: 'DMARC failed',
    why: 'The domain owner published a policy saying mail like this should not exist. Failing DMARC means SPF and DKIM did not align with the visible From.',
    advice: 'Treat as likely forged; do not act on the message.',
    mitre: ['T1566'], confidence: 'high'
  },
  'HDR-AUTH-MISALIGNED': {
    id: 'HDR-AUTH-MISALIGNED', category: 'header', weight: 12,
    title: 'Authentication passed but nothing is aligned',
    why: 'SPF or DKIM may have passed for the attacker own domain, while nothing aligns with the From you see. This is the classic "authenticated for the wrong domain" case.',
    advice: 'Treat as forged; the From domain was not actually authenticated.',
    mitre: ['T1656'], confidence: 'medium'
  },
  'HDR-AUTH-FORGED': {
    id: 'HDR-AUTH-FORGED', category: 'header', weight: 10,
    title: 'Conflicting Authentication-Results headers',
    why: 'Two different servers reported different authentication outcomes. It can happen with forwarding, but a sender-injected forged header is also possible.',
    advice: 'Low confidence. Verify through another channel before acting.',
    mitre: ['T1566'], confidence: 'low'
  },
  'HDR-AUTH-ABSENT': {
    id: 'HDR-AUTH-ABSENT', category: 'header', weight: 4,
    title: 'No authentication results present',
    why: 'Neither Authentication-Results nor Received-SPF were supplied, so nothing about the sender can be checked. This is a coverage gap, not a failure.',
    advice: 'Paste the full raw headers (not the mail client summary) for a better check.',
    mitre: ['T1566'], confidence: 'low'
  },
  'HDR-MSGID-MISMATCH': {
    id: 'HDR-MSGID-MISMATCH', category: 'header', weight: 5,
    title: 'Message-ID domain differs from From',
    why: 'The Message-ID domain is usually related to the sending organisation. A large mismatch is a weak sign of a forged or relayed message.',
    advice: 'Weak signal; consider with the rest.',
    mitre: ['T1656'], confidence: 'low'
  },
  'HDR-RECEIVED-ANOMALY': {
    id: 'HDR-RECEIVED-ANOMALY', category: 'header', weight: 6,
    title: 'Anomaly in the Received chain',
    why: 'Private or reserved IPs on the first hop, a HELO/rDNS mismatch, or timestamps going backwards can indicate forged routing. These are weak signals with innocent explanations.',
    advice: 'Low confidence; weigh with the rest.',
    mitre: ['T1036'], confidence: 'low'
  },
  'HDR-DATE-ANOMALY': {
    id: 'HDR-DATE-ANOMALY', category: 'header', weight: 3,
    title: 'Implausible Date header',
    why: 'A Date far in the future or the distant past is unusual and can indicate a forged message. Time-zone issues are a common innocent cause.',
    advice: 'Weak signal; consider with the rest.',
    mitre: ['T1036'], confidence: 'low'
  }
};