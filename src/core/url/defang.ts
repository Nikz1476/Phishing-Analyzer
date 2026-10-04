// Defanging. WHY: every URL the tool displays must be non-clickable and
// obviously inert, so that copying a report or reading the UI can never turn
// into an accidental visit. We also un-defang on input (see normalise) so that
// already-defanged samples are still analysed.

/** Turn a live URL/form into a defanged, non-clickable display string. */
export function defang(value: string): string {
  if (!value) return value;
  return value
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^ftp:\/\//i, 'fxp://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[at]');
}

/** Reverse of defang for a single token - used when reading pasted samples. */
export function refang(value: string): string {
  return value
    .replace(/hxxps/gi, 'https')
    .replace(/hxxp/gi, 'http')
    .replace(/\[\s*\.\s*\]/g, '.')
    .replace(/\(\s*\.\s*\)/g, '.')
    .replace(/\[\s*at\s*\]/gi, '@')
    .replace(/\[\s*:\s*\]/g, ':');
}
