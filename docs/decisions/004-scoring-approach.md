# 004 — Scoring approach (additive/deterministic vs ML)

**Context**: We need a 0–100 phishing risk score that a user can trust and
that we can explain findng-by-finding, and that stays stable under an
adversary slightly rewording a phishing email.

**Options considered**
1. A trained ML classifier (e.g. logistic regression or small neural net) run
   client-side (e.g. via ONNX/TF.js) — could capture subtler patterns, but:
   it's a black box ("why did this score 61?" has no clean per-finding
   answer), it needs a model-serving dependency, and it needs a labelled
   dataset we'd have to ship or retrain against.
2. A deterministic, additive rule-engine: each finding contributes an exact,
   documented point value; category caps prevent one noisy signal from
   dominating; corroboration bonuses reward independent signals agreeing;
   small mitigations never override critical findings. Section 9 formalises
   this with explicit invariants (reconciliation, determinism, monotonicity).
3. Hybrid: additive scoring for display, ML used only offline to *suggest*
   weight calibration (Section 13.2), never shipped as a runtime model.

**Decision**: Option 3 — ship option 2's deterministic engine; use ML only as
an offline, dev-time calibration aid whose output is reviewed by a human
before `data/weights.json` is hand-edited.

**Trade-off**: We likely leave some accuracy on the table versus a tuned
classifier. We accept this because every displayed point must be explainable
and reconcilable by Section 9's invariants — explainability is the product,
not a side feature, for this specific tool's audience.
