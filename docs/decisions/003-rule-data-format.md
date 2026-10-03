# 003 — Rule data format (JSON vs code)

**Context**: The tool has two kinds of detection logic: phrase/pattern rules
(language, credential, financial, attachment-name cues) and structural rules
(header parsing, URL feature extraction). Both need a single source of truth
that drives the engine AND the auto-generated "Learn" page, so the
documentation can never drift from what the code actually checks.

**Options considered**
1. Everything in code (TS functions) — maximum flexibility, but then the
   Learn page needs a second, hand-maintained copy of each rule's
   explanation, which *will* drift from the real logic over time.
2. Everything in JSON, including structural rules — clean single source of
   truth, but header/URL analysis genuinely needs real control flow (loops,
   recursion for redirect-unwrapping, DNS-free alignment maths) that a
   declarative format can't express without becoming its own interpreter.
3. Hybrid: phrase/pattern rules live in JSON (tokeniser interprets them,
   schema-validated in CI); structural rules live in code, but each one still
   declares the same metadata shape (id, weight, why, advice, mitre) so the
   Learn page can read metadata from both sources uniformly.

**Decision**: Option 3 (hybrid), per Section 4/8 of the spec.

**Trade-off**: Two code paths to maintain (a JSON-rule interpreter and
metadata-only structural rules) instead of one. Accepted because phrase rules
genuinely are declarative (word lists, proximity, negation) while structural
rules genuinely are not, and forcing either into the wrong shape would make
both harder to read and test.
