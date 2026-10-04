// RFC 3492 Punycode decoder.
//
// WHY hand-written: the WHATWG URL class only ENCODES to punycode; it does not
// give us the Unicode form back. To spot a homograph we must decode xn-- back
// to Unicode ourselves. Reference: RFC 3492 section 6.2.

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) / 2) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

/** Decode the part after "xn--". Throws on malformed input. */
export function punycodeDecode(input: string): string {
  const output: number[] = [];
  const basic = input.lastIndexOf('-');
  const basicEnd = basic < 0 ? 0 : basic;
  for (let j = 0; j < basicEnd; j += 1) output.push(input.charCodeAt(j));

  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  let idx = basicEnd > 0 ? basicEnd + 1 : 0;

  while (idx < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error('punycode: truncated input');
      const c = input.charCodeAt(idx);
      idx += 1;
      const digit =
        c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : BASE;
      if (digit >= BASE) throw new Error('punycode: invalid digit');
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n);
    i += 1;
  }
  return String.fromCodePoint(...output);
}

/** Decode a whole hostname, turning xn-- labels into Unicode. Returns input on failure. */
export function decodeHostname(host: string): string {
  return host
    .split('.')
    .map((label) =>
      label.toLowerCase().startsWith('xn--')
        ? (() => {
            try {
              return punycodeDecode(label.slice(4));
            } catch {
              return label;
            }
          })()
        : label
    )
    .join('.');
}