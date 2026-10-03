// Flat ESLint config (ESLint 9+). Kept intentionally small: TypeScript's own
// strict compiler settings (tsconfig.json) catch most bugs; lint rules here
// focus on things tsc can't check - banning innerHTML, banning network APIs
// outside the privacy-check script, and standard recommended JS/TS hygiene.
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**', 'playwright-report/**', 'node_modules/**']
  },
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.ts'],
    rules: {
      // Section 3: never put hostile text into innerHTML.
      'no-restricted-properties': [
        'error',
        { object: 'document', property: 'write', message: 'document.write is forbidden.' }
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "AssignmentExpression[left.property.name='innerHTML']",
          message: 'innerHTML is forbidden; use textContent or DOM node creation (Section 3).'
        },
        {
          selector: "CallExpression[callee.name='fetch']",
          message: 'Network calls are forbidden; this app never sends data anywhere (Section 3).'
        }
      ]
    }
  }
);
