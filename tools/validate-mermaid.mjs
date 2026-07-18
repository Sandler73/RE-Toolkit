// =============================================================================
// tools/validate-mermaid.mjs
// =============================================================================
//
// Synopsis:
//     Parse every mermaid diagram in the given Markdown files and fail if any
//     of them is invalid.
//
// Description:
//     GitHub renders mermaid diagrams server-side. An invalid diagram does not
//     fail a build, it simply renders as an error box in the published page,
//     which is discovered by a reader rather than by CI. This check parses each
//     diagram with the real mermaid parser so a syntax error fails the build
//     instead.
//
//     mermaid's flowchart renderer sanitizes node labels through DOMPurify,
//     which requires a DOM. A jsdom window is installed on globalThis before
//     mermaid is imported, so parsing works in a headless CI environment.
//
// Execution Parameters:
//     <file...>   One or more Markdown files to scan for mermaid blocks.
//
// Examples:
//     node tools/validate-mermaid.mjs README.md wiki/*.md
//
// Exit Codes:
//     0    Every diagram parsed cleanly.
//     1    One or more diagrams failed to parse.
//
// Notes:
//     Requires the mermaid and jsdom packages. CI installs them on demand.
//
// Version:
//     3.7.3 - 2026-05-03
// =============================================================================

import { readFileSync } from 'fs';
import { JSDOM } from 'jsdom';

// Provide a DOM before importing mermaid: the flowchart renderer sanitizes
// node labels through DOMPurify, which requires window/document.
const dom = new JSDOM('<!DOCTYPE html><body></body>', { pretendToBeVisual: true });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, "navigator", { value: dom.window.navigator, configurable: true });
globalThis.DOMPurify = dom.window.DOMPurify;

const mermaid = (await import('mermaid')).default;
mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

let fail = 0, total = 0;
for (const file of process.argv.slice(2)) {
  const src = readFileSync(file, 'utf8');
  const blocks = [...src.matchAll(/```mermaid\n([\s\S]*?)```/g)].map(m => m[1]);
  if (blocks.length) console.log(`\n${file}`);
  for (let i = 0; i < blocks.length; i++) {
    total++;
    const head = blocks[i].trim().split('\n')[0];
    try {
      await mermaid.parse(blocks[i]);
      console.log(`  Block ${i + 1}: VALID   (${head})`);
    } catch (e) {
      fail++;
      console.log(`  Block ${i + 1}: INVALID (${head}) -> ${String(e.message).split('\n')[0]}`);
    }
  }
}
console.log(fail === 0 ? `\nAll ${total} diagram(s) parse cleanly.` : `\n${fail} of ${total} failed.`);
process.exit(fail === 0 ? 0 : 1);
