# 001 — Tech stack

**Context**: We need a static, zero-backend, privacy-verifiable web app, built
and tested in a way that's easy to explain in an interview and easy for CI to
gate automatically.

**Options considered**
1. React + Create React App / Next.js — popular, but pulls in a large runtime
   and a build system heavier than a single-page tool needs. Next.js in
   particular assumes server rendering, which actively fights our
   "no server" constraint.
2. Plain TypeScript + Vite, no UI framework — minimal runtime, fast dev
   server, native ESM, first-class TS support, trivial static-site output.
3. Svelte/SolidJS — smaller runtime than React, but still a framework we'd
   need to learn and justify owning as a dependency for a tool whose UI is
   genuinely simple (a form, a report view).

**Decision**: TypeScript + Vite with hand-written DOM code (no framework),
Vitest for unit tests, Playwright for end-to-end/offline/CSP proof, ESLint
for lint. Zero runtime dependencies shipped in the bundle.

**Trade-off**: We write more DOM-manipulation boilerplate by hand than a
framework would give us for free. In exchange: zero framework runtime to
audit for the privacy story, a smaller attack surface, faster builds, and
every line in the shipped bundle is code we wrote and can explain line by
line in an interview — which is the actual point of this project.
