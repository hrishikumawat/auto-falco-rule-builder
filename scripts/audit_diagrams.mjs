/** Focused static publication checks for the committed standalone diagrams.
 * This is a regression guard, not a general JavaScript security analyzer.
 * Run: node scripts/audit_diagrams.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = process.argv.length > 2 ? process.argv.slice(2) : ['docs/diagrams/full-flow.html', 'docs/diagrams/builder-components.html'];
const sha = text => crypto.createHash('sha256').update(text).digest('hex');
const failures = [];
const reports = [];
function publicRepositoryLink(value) {
  try {
    const url = new URL(value);
    const prefix = '/hrishikumawat/auto-falco-rule-builder';
    return url.protocol === 'https:' && url.hostname === 'github.com' && !url.port && !url.username && !url.password &&
      (url.pathname === prefix || url.pathname.startsWith(prefix + '/'));
  } catch { return false; }
}
function checkEvidenceLinks(value, fail) {
  if (Array.isArray(value)) value.forEach(item => checkEvidenceLinks(item, fail));
  else if (value && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      if (key === 'href' && item && (typeof item !== 'string' || !publicRepositoryLink(item))) fail('unexpected embedded evidence link');
      checkEvidenceLinks(item, fail);
    }
  }
}
const deny = [
  ['HTML injection sink', /\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b|document\s*\.\s*write\s*\(/],
  ['dynamic code execution', /\beval\s*\(|\b(?:new\s+)?Function\s*\(|\bimport\s*\(/],
  ['network or messaging API', /\bfetch\s*\(|\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|\bsendBeacon\s*\(|\bpostMessage\s*\(/],
  ['device or filesystem access', /\bgetUserMedia\b|\bgeolocation\b|\bshowOpenFilePicker\b|\bshowDirectoryPicker\b|\bserviceWorker\b|\bnew\s+(?:Shared)?Worker\s*\(/],
  ['clipboard read', /clipboard\s*\.\s*read(?:Text)?\s*\(/],
  ['cookie access', /document\s*\.\s*cookie\b/],
  ['string timer', /\bset(?:Timeout|Interval)\s*\(\s*['"`]/],
];
for (const file of files) {
  const html = fs.readFileSync(path.join(root, file), 'utf8');
  const fail = message => failures.push(`${file}: ${message}`);
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
  let executable = 0;
  let jsonBlocks = 0;
  for (const [, attributes, source] of scripts) {
    if (/\bsrc\s*=/i.test(attributes)) fail('external script');
    if (/\btype\s*=\s*["']application\/json["']/i.test(attributes)) {
      try { checkEvidenceLinks(JSON.parse(source), fail); jsonBlocks++; } catch { fail('invalid embedded JSON'); }
    } else {
      executable++;
      try { new vm.Script(source, { filename: file }); } catch (error) { fail(`invalid JavaScript: ${error.message}`); }
      for (const [name, expression] of deny) if (expression.test(source)) fail(name);
    }
  }
  // Strip raw-text bodies before examining HTML attributes.
  const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, '');
  if (/<(?:iframe|object|embed|form|base)\b/i.test(markup)) fail('unexpected embedded content, form or base URL');
  for (const tagMatch of markup.matchAll(/<([a-z][a-z0-9:-]*)\b([^>]*)>/gi)) {
    const tag = tagMatch[1].toLowerCase();
    const attrs = Object.create(null);
    for (const match of tagMatch[2].matchAll(/([a-z_:][a-z0-9_:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
      attrs[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4];
    }
    for (const [name, value] of Object.entries(attrs)) {
      if (/^on/i.test(name)) fail(`inline event attribute: ${name}`);
      if (['src', 'srcset', 'poster', 'data', 'action', 'ping'].includes(name)) fail(`unexpected ${tag}.${name}`);
      if (name === 'href' || name === 'xlink:href') {
        if (!value.startsWith('#') && !publicRepositoryLink(value)) {
          fail(`unexpected navigation: ${value.slice(0, 100)}`);
        }
      }
    }
    if (tag === 'link') fail('external link resource');
    if (attrs.target === '_blank' && (!/\bnoopener\b/.test(attrs.rel || '') || !/\bnoreferrer\b/.test(attrs.rel || ''))) {
      fail('new-tab link without opener/referrer protection');
    }
  }
  const styledMarkup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '');
  for (const match of styledMarkup.matchAll(/\burl\(\s*(['"]?)(.*?)\1\s*\)/gi)) {
    const value = match[2];
    if (value.startsWith('data:image/svg+xml,')) {
      try {
        const svg = decodeURIComponent(value.slice('data:image/svg+xml,'.length));
        if (/\bon[a-z]+\s*=|\b(?:href|src)\s*=|<!DOCTYPE/i.test(svg) ||
            [...svg.matchAll(/<\/?([a-z][a-z0-9:-]*)\b/gi)].some(tag => !['svg', 'path', 'circle', 'rect', 'line', 'polyline', 'polygon', 'ellipse', 'g'].includes(tag[1].toLowerCase()))) {
          fail('unexpected active content in embedded CSS icon');
        }
      } catch { fail('invalid embedded CSS icon'); }
    } else if (!value.startsWith('data:font/woff2;base64,') && !value.startsWith('#')) fail('external CSS resource');
  }
  if (/(?:C:\\\\?Users\\|\/opt\/data\/|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})/.test(html)) {
    fail('private path or credential marker');
  }
  const sourceAttributes = [...html.matchAll(/\b(?:source|repository)(?:Link)?\s*\.\s*href\s*=\s*([^;]+);/g)].map(match => match[1]);
  // These are the only non-blob dynamic href producers in this viewer.
  if (sourceAttributes.some(value => !['repository.href', 'source.href'].includes(value.trim()))) fail('unexpected dynamic evidence link');
  reports.push({ file, sha256: sha(html), bytes: Buffer.byteLength(html), executableScripts: executable, jsonBlocks });
}
console.log(JSON.stringify({ status: failures.length ? 'failed' : 'passed', files: reports, failures,
  scope: 'Static regression checks plus JavaScript syntax parsing; manual data-flow and hosting review remain necessary.' }, null, 2));
process.exitCode = failures.length ? 1 : 0;
