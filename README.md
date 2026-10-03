# Phishing Email Analyser

A static, fully client-side phishing email triage tool. Paste a suspicious
email, get a 0–100 risk score with every contributing warning sign explained
in plain English, mapped to MITRE ATT&CK, with a clear statement of what was
*not* checked. Nothing you paste is ever uploaded or stored — verifiably so
(see "How privacy is verified" below, added in later phases).

> **Status**: Phase 0 (Foundations) complete. This is an educational /
> portfolio project built in public, phase by phase. See `docs/decisions/`
> for the reasoning behind every major choice, and `docs/THREAT-MODEL.md`
> (added in Phase 7) for what this tool deliberately does not catch.

## Why this exists

Many phishing analysers exist. This one competes on depth and rigour of
analysis (header forensics, URL forensics, evasion-resistant normalisation,
explainable scoring), not on the number of input channels. Full design spec
lives in the project's internal brief; `docs/decisions/` captures each
individual decision as it was made.

## Development

```bash
npm install
npm run dev          # local dev server
npm run test         # unit tests (Vitest)
npm run test:e2e     # offline/CSP proof (Playwright, needs a build first)
npm run lint
npm run typecheck
npm run build
npm run privacy-check  # static scan for forbidden network APIs
```

## Privacy and security posture (short version)

- All analysis runs in your browser. Email content is never sent anywhere.
- Content-Security-Policy blocks all outbound network access
  (`connect-src 'none'`).
- A CI step statically scans the source and built output for forbidden
  network APIs; a Playwright test runs the built site with the network
  physically blocked and asserts it still works.
- No analytics, telemetry, CDNs, or remote fonts/images/scripts.

Full details: `.clinerules` and `docs/decisions/002-privacy-enforcement.md`.

## Licence

MIT (added formally in Phase 7).
