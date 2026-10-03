# 002 — Privacy enforcement mechanism

**Context**: "Nothing is ever uploaded" is a claim every phishing tool makes.
We want it to be a verifiable fact, not marketing copy, since that is the
project's main differentiator for a security audience.

**Options considered**
1. Trust alone — just don't write network code, document the promise in the
   README. Cheap, but unverifiable and silently breakable by a future
   dependency or a copy-pasted snippet.
2. CSP only — a `connect-src 'none'` policy blocks the browser from making
   requests at runtime, which is strong, but doesn't prevent a static scan
   failure from an accidental network call being *written*; it only stops it
   from *executing*.
3. Defense in depth: CSP (`<meta>` + `_headers`) + a custom static-scan script
   in CI (fails the build on forbidden APIs/strings) + a Playwright test that
   runs the built site with all network requests blocked and asserts the app
   still works with zero blocked-request attempts.

**Decision**: Option 3. Three independent, automated layers: a policy that
blocks requests at runtime, a static scan that blocks the code from being
written at all, and an end-to-end test that blocks the network physically and
proves the app doesn't need it.

**Trade-off**: More CI steps and a small amount of custom tooling
(scripts/privacy-check.mjs) to write and maintain ourselves. Worth it: a
single layer could be bypassed by one mistake; three independent layers
failing simultaneously is what "verifiable" actually means.
