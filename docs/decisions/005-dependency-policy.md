# 005 — Dependency policy

**Context**: A phishing tool that claims to be privacy-first and hand-reviewed
loses credibility if its dependency tree is large or unaudited. We also want
every shipped line to be something the author can explain in an interview.

**Options considered**
1. No policy, add whatever's convenient — fastest short-term, but risks
   supply-chain bloat, unreviewed transitive code, and licence surprises.
2. Zero dependencies of any kind, including dev tooling — maximally pure, but
   means hand-rolling a bundler, test runner, and browser automation harness,
   which has no learning value for this project's actual goal (phishing
   detection, not build-tool engineering).
3. Zero *runtime* (shipped) dependencies by default; dev-only tooling
   (Vite/TS/Vitest/Playwright/ESLint) is allowed freely since it never
   reaches the browser; any proposed *runtime* dependency (e.g. jsQR, tldts)
   requires an explicit ask with: what it does, why not write it ourselves,
   its size, licence, maintenance status — and its own decision record.

**Decision**: Option 3. Dev dependencies: Vite, TypeScript, Vitest,
`@vitest/coverage-v8`, jsdom, `@playwright/test`, ESLint, `typescript-eslint`
— all MIT/Apache-2.0, actively maintained, standard tooling, never shipped to
`dist/`. No runtime dependency is added in Phase 0. jsQR and tldts are
deferred to Phases 6 and 2 respectively, each pending its own decision record
and your explicit approval first.

**Trade-off**: Slower feature velocity in the URL/QR phases since we may
end up vendoring/writing subset logic (e.g. `psl-subset.json`) ourselves
before justifying a real dependency. Accepted: a small, auditable dependency
list is itself part of the portfolio story.
