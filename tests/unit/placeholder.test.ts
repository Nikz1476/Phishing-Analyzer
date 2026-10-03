import { describe, expect, it } from 'vitest';

// Phase 0 sanity test: proves the Vitest + jsdom toolchain itself works
// before any real engine code exists. Will be deleted once Phase 1 lands
// real parser tests.
describe('toolchain', () => {
  it('runs in a jsdom environment with DOMParser available', () => {
    expect(typeof DOMParser).toBe('function');
  });

  it('is deterministic arithmetic, as a stand-in for scoring determinism later', () => {
    expect(1 + 1).toBe(2);
  });
});
