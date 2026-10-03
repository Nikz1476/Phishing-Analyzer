// The Channel interface is what lets us claim, truthfully, that this engine
// could support SMS/voice packs later without a rewrite. v1 only ships the
// 'email' and 'qr' channels; 'sms'/'voice' are listed so the type stays
// honest about intent, but nothing implements them yet.
//
// This boundary is what Phase 3's "dummy sms channel" test (Section 11.3)
// will prove is real, not aspirational.

export type ChannelId = 'email' | 'qr' | 'sms' | 'voice';

// Placeholder types - filled in properly once src/core/parse and
// src/core/report exist (Phase 1+). Kept here so the Channel contract can be
// referenced today without circular imports.
export interface Input {
  readonly raw: string;
}

export interface Message {
  readonly channel: ChannelId;
  readonly text: string;
}

export interface Channel {
  readonly id: ChannelId;
  parse(input: Input): Message;
  readonly rulePacks: string[];
}

