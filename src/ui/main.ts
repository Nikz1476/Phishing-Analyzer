// Phase 0 placeholder entry point.
// Deliberately uses textContent, never innerHTML, even here - establishing
// the habit from commit #1 since Section 3 forbids innerHTML with any
// user-derived content anywhere in this codebase.
const app = document.querySelector<HTMLDivElement>('#app');

function renderPlaceholder(root: HTMLDivElement): void {
  const heading = document.createElement('h1');
  heading.textContent = 'Phishing Email Analyser';

  const note = document.createElement('p');
  note.textContent =
    'Foundations phase: the real analysis UI is built in Phase 4. ' +
    'Everything here runs entirely in your browser.';

  root.replaceChildren(heading, note);
}

if (app) {
  renderPlaceholder(app);
}
