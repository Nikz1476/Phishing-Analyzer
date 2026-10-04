// Central type definitions for the analysis engine.
//
// WHY these live here and not scattered per-module: every stage of the
// pipeline (parse -> normalise -> extract -> url -> rules -> score -> report)
// hands off to the next, so a single shared vocabulary of types keeps the
// hand-offs honest and makes each stage independently unit-testable. This is
// the "information contract" the brief asks us to preserve.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Category =
  | 'language'
  | 'credential'
  | 'financial'
  | 'url'
  | 'attachment'
  | 'header'
  | 'impersonation'
  | 'technique'
  | 'evasion';

export type Confidence = 'low' | 'medium' | 'high';

export type EvidenceSource = 'body' | 'header' | 'url' | 'attachment' | 'qr';

/** A snippet of the original input that supports a finding. */
export interface Evidence {
  source: EvidenceSource;
  /** The exact text as it appeared in the ORIGINAL input. */
  snippet: string;
  /** Offsets into the original text, when known. */
  start?: number;
  end?: number;
  /** Optional label, e.g. the header name or the URL this came from. */
  label?: string;
}

/** One warning sign, fully explained. */
export interface Finding {
  id: string;
  category: Category;
  severity: Severity; // derived from weight, see severityFromWeight()
  weight: number; // points this finding contributes before caps
  title: string;
  evidence: Evidence[];
  why: string; // plain-English reason it matters
  advice: string; // what the recipient should do
  mitre: string[]; // e.g. ['T1598','T1111']
  confidence: Confidence;
  /** True when this is a "negative" finding that reduces risk (a mitigation). */
  mitigation?: boolean;
  /** How many distinct occurrences of this rule fired (drives repeat factor). */
  occurrences?: number;
  /** Optional grouping key (e.g. a URL id) used by the per-URL cap. */
  groupId?: string;
  /** Optional rule-specific ceiling on the points this finding may contribute. */
  pointCap?: number;
}

export type Classification = 'Low Risk' | 'Suspicious' | 'High Risk';

export interface Coverage {
  level: 1 | 2 | 3 | 4;
  checked: string[];
  notChecked: string[];
}

export interface CategoryBreakdown {
  category: Category;
  raw: number;
  cap: number;
  applied: number;
}

export interface Combo {
  id: string;
  bonus: number;
  because: string[];
}

export interface Mitigation {
  id: string;
  delta: number; // negative or zero
  because: string;
}

export interface Iocs {
  urls: string[];
  domains: string[];
  ips: string[];
  emails: string[];
  hashes: string[];
}


export interface AnalysisResult {
  score: number; // 0..100
  classification: Classification;
  coverage: Coverage;
  findings: Finding[];
  breakdown: CategoryBreakdown[];
  combos: Combo[];
  mitigations: Mitigation[];
  iocs: Iocs;
  /** Exactly what the user pasted, for the annotated source view. */
  original: string;
  /** Findings grouped per URL (used by the URL view). */
  urlReports: UrlReport[];
  /** Parsed header summary (empty when no headers were supplied). */
  headerReport: HeaderReport | null;
  /** Optional QR extras when the input came from the QR channel. */
  qrReport: QrReport | null;
}

export interface UrlReport {
  url: string; // as extracted (raw)
  defanged: string;
  registrableDomain: string;
  scheme: string;
  host: string;
  unwrapChain: string[];
  findings: Finding[];
  /** True when this URL was reached by unwrapping a redirect wrapper. */
  fromUnwrap: boolean;
}

export interface HeaderReport {
  from: string | null;
  replyTo: string | null;
  returnPath: string | null;
  messageId: string | null;
  subject: string | null;
  date: string | null;
  authResults: AuthResultSummary[];
  receivedHops: ReceivedHop[];
  /** Local alignment recomputation vs the reported results. */
  alignment: AlignmentSummary | null;
}

export interface AuthResultSummary {
  authservId: string;
  method: string;
  result: string;
  properties: Record<string, string>;
  rawComment?: string;
  /** True for the topmost (trusted) Authentication-Results header. */
  trusted: boolean;
}

export interface ReceivedHop {
  index: number; // 0 = oldest
  from: string | null;
  by: string | null;
  with: string | null;
  ip: string | null;
  rdns: string | null;
  date: string | null;
  /** Milliseconds since the previous (older) hop, when both dates parse. */
  delayMs: number | null;
  notes: string[];
}

export interface AlignmentSummary {
  spf: { reported: string | null; locallyAligned: boolean | null };
  dkim: { reported: string | null; locallyAligned: boolean | null };
  dmarc: { reported: string | null; locallyComputed: boolean | null };
}

export interface QrReport {
  payloadType: 'url' | 'tel' | 'smsto' | 'wifi' | 'mailto' | 'vcard' | 'text' | 'unknown';
  payload: string;
  defanged: string;
}

/** A parsed email message, the output of the parse stage. */
export interface ParsedMessage {
  isRaw: boolean; // did it have a header block?
  headers: Header[];
  headerMap: Map<string, string[]>; // lowercased name -> values (in order)
  bodyText: string; // best-effort plain text body
  bodyHtml: string | null; // html body if present (raw, inert)
  attachments: AttachmentInfo[];
  rawMime: string; // original raw input (for DKIM etc.)
  warnings: string[]; // non-fatal parse problems
}

export interface Header {
  name: string;
  value: string; // unfolded value
}

export interface AttachmentInfo {
  filename: string | null;
  contentType: string | null;
  size: number;
  encoding: string | null;
}

/** A normalised text plus a map back to original offsets. */
export interface NormalisedText {
  text: string; // normalised, for display + rule matching
  lower: string; // lowercased copy
  /** Homoglyph-folded + lowercased copy, SAME LENGTH as `text`, for matching. */
  match: string;
  /** For each index in `text`, the corresponding index in the original. */
  offsetMap: number[];
  /** Characters that were invisible/zero-width and were removed. */
  zeroWidthCount: number;
  /** True when homoglyph folding changed a word-internal Latin letter. */
  homoglyphFolded: boolean;
  /** Original text this was derived from. */
  original: string;
}

export interface Token {
  value: string; // normalised token text
  lower: string;
  start: number; // index in normalised text
  end: number;
  origStart: number; // index in original text
  origEnd: number;
}

export interface ExtractedUrl {
  raw: string; // as written (possibly defanged)
  defanged: string;
  displayText?: string; // anchor text when extracted from HTML
  source: 'body-text' | 'html-href' | 'markdown' | 'qr';
  start?: number; // offsets in original
  end?: number;
}
