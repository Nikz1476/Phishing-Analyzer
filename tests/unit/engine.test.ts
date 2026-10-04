import { describe, expect, it } from 'vitest';
import { analyse } from '../../src/core/engine';

describe('engine smoke test', () => {
  it('analyses an obvious phishing body-only email and scores High Risk', () => {
    const sample = `URGENT: YOUR ACCOUNT WILL BE SUSPENDED WITHIN 24 HOURS

Dear Customer,

We detected unusual sign-in activity. You must confirm your password
immediately to keep your account. Send us your password and the 6-digit
verification code we just sent.

http://192.0.2.45/login.php

Failure to comply will result in permanent account closure.`;

    const result = analyse(sample);
    expect(result.score).toBeGreaterThanOrEqual(55);
    expect(result.classification).toBe('High Risk');
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain('CRED-PASSWORD');
    expect(ids).toContain('LANG-THREAT');
    expect(ids).toContain('URL-IP-HOST');
  });

  it('does not flag a legitimate password-reset note (negation)', () => {
    const sample = `Hello,

We will never ask for your password. Use the button below to choose a
new one: https://accounts.example.test/reset

Thanks,
The Security Team`;

    const result = analyse(sample);
    expect(result.findings.map((f) => f.id)).not.toContain('CRED-PASSWORD');
    expect(result.score).toBeLessThan(25);
  });

  it('never throws on random malformed input', () => {
    const junk = ['\u200B\u200B\u200B not a pass\u200Bword', 'From: =?UTF-8?B?bad', '>>>>> ', '', '<img src=x onerror=alert(1)>'];
    for (const j of junk) {
      expect(() => analyse(j)).not.toThrow();
    }
  });
});
