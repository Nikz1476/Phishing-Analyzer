// HTML analysis. WHY DOMParser: it parses markup into an INERT document that
// is never attached to the live page, so scripts do not run and resource URLs
// are not fetched. In tests jsdom provides the same DOMParser, so this stays
// testable in Node. We never touch the live `document`/`window` here.

export interface HtmlAnchor {
  href: string;
  text: string;
}

export interface HtmlForm {
  action: string;
  method: string;
  hasPassword: boolean;
  inputNames: string[];
}

export interface HtmlImage {
  src: string;
  width: number | null;
  height: number | null;
}

export interface HtmlAnalysis {
  visibleText: string;
  hiddenText: string;
  anchors: HtmlAnchor[];
  forms: HtmlForm[];
  images: HtmlImage[];
  baseHref: string | null;
  hasPasswordField: boolean;
}

const HIDDEN_STYLE_RE = /(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|em|rem|%)?|opacity\s*:\s*0(?:\.0+)?\b|position\s*:\s*absolute\s*;\s*(?:left|top)\s*:\s*-\d{3,})/i;

function styleIsHidden(el: Element): boolean {
  const style = el.getAttribute('style') ?? '';
  if (HIDDEN_STYLE_RE.test(style)) return true;
  const hiddenAttr = el.getAttribute('hidden');
  if (hiddenAttr !== null) return true;
  // Same-colour trick: colour equals background-colour.
  const color = /color\s*:\s*([^;]+)/i.exec(style);
  const bg = /background(?:-color)?\s*:\s*([^;]+)/i.exec(style);
  if (color && bg && color[1]!.trim().toLowerCase() === bg[1]!.trim().toLowerCase()) return true;
  return false;
}

/** Analyse an HTML string into text, anchors, forms and images. */
export function analyseHtml(html: string): HtmlAnalysis {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const result: HtmlAnalysis = {
    visibleText: '',
    hiddenText: '',
    anchors: [],
    forms: [],
    images: [],
    baseHref: null,
    hasPasswordField: false
  };

  const base = doc.querySelector('base[href]');
  if (base) result.baseHref = base.getAttribute('href');

  const anchors = doc.querySelectorAll('a[href]');
  anchors.forEach((a) => {
    result.anchors.push({ href: a.getAttribute('href') ?? '', text: (a.textContent ?? '').trim() });
  });

  const forms = doc.querySelectorAll('form');
  forms.forEach((form) => {
    const inputs = form.querySelectorAll('input, select, textarea');
    const inputNames: string[] = [];
    let hasPassword = false;
    inputs.forEach((input) => {
      const name = input.getAttribute('name');
      if (name) inputNames.push(name);
      if ((input.getAttribute('type') ?? '').toLowerCase() === 'password') hasPassword = true;
    });
    if (hasPassword) result.hasPasswordField = true;
    result.forms.push({
      action: form.getAttribute('action') ?? '',
      method: (form.getAttribute('method') ?? 'get').toLowerCase(),
      hasPassword,
      inputNames
    });
  });

  const images = doc.querySelectorAll('img');
  images.forEach((img) => {
    const src = img.getAttribute('src') ?? '';
    const width = img.hasAttribute('width') ? Number(img.getAttribute('width')) : null;
    const height = img.hasAttribute('height') ? Number(img.getAttribute('height')) : null;
    result.images.push({ src, width, height });
  });

  // Walk the body, splitting visible and hidden text.
  const body = doc.body;
  if (body) {
    const visible: string[] = [];
    const hidden: string[] = [];
    const walk = (node: Node): void => {
      if (node.nodeType === Node.TEXT_NODE) {
        const text = node.textContent ?? '';
        if (!text.trim()) return;
        let parent: Node | null = node.parentElement;
        let isHidden = false;
        while (parent) {
          if (parent.nodeType === Node.ELEMENT_NODE && styleIsHidden(parent as Element)) {
            isHidden = true;
            break;
          }
          parent = parent.parentElement;
        }
        (isHidden ? hidden : visible).push(text);
        return;
      }
      if (node.nodeType === Node.ELEMENT_NODE) {
        const tag = (node as Element).tagName.toLowerCase();
        if (tag === 'script' || tag === 'style') return;
        node.childNodes.forEach(walk);
      }
    };
    walk(body);
    result.visibleText = visible.join(' ').replace(/\s+/g, ' ').trim();
    result.hiddenText = hidden.join(' ').replace(/\s+/g, ' ').trim();
  }

  return result;
}