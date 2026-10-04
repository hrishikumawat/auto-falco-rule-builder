# Architecture diagrams

- [Builder components](builder-components.html): local CLI components and the practical file handoff for an engineer with their own Falco deployment.
- [Full workflow](full-flow.html): the implemented builder and the proposed organization review/deployment workflow.
- [Onboarding](../onboarding.md): profile inputs, replay evidence, and manual Helm custom-rule handling.

These are standalone HTML viewers with inline SVG, scripts and embedded font/icon assets. Download and open locally, or publish the HTML on a static documentation host. GitHub's normal file view displays the source. JSON sources are included for regeneration. Their source links pin implementation evidence to commit `0729170b4b8ad8949eb193878cac81d402e79411`; they intentionally do not claim to describe later code changes.

## Regenerate

Install/use the Archify skill and replace `/path/to/archify/bin/archify.mjs` below with its installed path. Run from the repository root:

```sh
node /path/to/archify/bin/archify.mjs finalize architecture \
  docs/diagrams/full-flow.archify.json docs/diagrams/full-flow.html \
  --repo-root . --quality showcase --out-dir local_run/diagram-checks/full-flow --json

node /path/to/archify/bin/archify.mjs finalize architecture \
  docs/diagrams/builder-components.archify.json docs/diagrams/builder-components.html \
  --repo-root . --quality showcase --out-dir local_run/diagram-checks/builder-components --json

node scripts/audit_diagrams.mjs
```

If a changed candidate replaces an artifact with browser evidence, use a fresh revision directory under `local_run/diagram-checks`. Do not publish receipt sidecars: they contain local paths. Regeneration must preserve source evidence or deliberately update the pinned revision after reviewing implementation changes.

## Publication security review — 2026-10-04

Finding: **no material security issue identified in these two reviewed artifacts**. This is a focused static/data-flow inspection with syntax and Archify browser checks, not a guarantee of zero risk or a penetration test of a hosting service.

| Area | Review result |
|---|---|
| Embedded data | Public repository identity, source references, architecture descriptions and viewer metadata. No credentials, raw alerts, private keys or local filesystem paths identified. |
| Network/resource loading | No external script, stylesheet, font, image, frame, fetch/XHR, WebSocket, EventSource, beacon or messaging API. Fonts and CSS SVG icons are embedded; icons contain drawing elements only. |
| DOM/code injection | No `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, eval, Function constructor, dynamic import or string timer. Dynamic labels use text nodes/textContent. |
| URL inputs | Theme accepts light/dark; boolean viewer options test exact values. Focus/routes are checked against the diagram's node IDs, and lens values against known component kinds. Parameters are not evaluated as code or used as arbitrary resource URLs. |
| Source links | Embedded targets are HTTPS links to this public GitHub repository. Generated new-tab source anchors use noopener/noreferrer and no-referrer. |
| Storage/privacy | Local storage contains viewer preferences (theme, motion and panel placement), not telemetry or credentials. No cookie access, clipboard reads, geolocation, camera/microphone requests or file pickers identified. |
| Exports | SVG/raster/WebM exports use local SVG serialization, canvas and blob URLs. MediaRecorder records the diagram canvas, not a device or screen. Object URLs are released. Clipboard writes occur through viewer actions; no upload path identified. |
| Validation | Both artifacts passed all nine Archify showcase checks, strict artifact/provenance checks and real-browser checks. These are artifact/layout gates, not a security scanner. No perceptual visual review was performed. |
| Regression guard | `scripts/audit_diagrams.mjs` parses JavaScript syntax and embedded JSON; checks dangerous sinks/APIs, resource URLs, icon content, link protection and common secret/private-path markers. Negative controls verified rejection of added network calls, HTML injection sinks and active CSS SVG icons. The guard is intentionally narrower than a complete JavaScript analyzer. |

Reviewed HTML SHA-256:

```text
full-flow.html
b429b7f6332cfb8f9dcd12d551470eb6be5bf2c0416e0df861cd8e7c03dce5ee

builder-components.html
ff42d50505cdce9d2f7f82302d330666c530d80374c602ba6dbc0a715b5fc846
```

### Hosting limits

Publish only the reviewed HTML, and intentionally public documentation/source JSON if desired. Do not publish `local_run`, raw captures/alerts, profiles containing private configuration, or delivery/validation sidecars. The diagrams have no backend and do not connect to Falco, Kubernetes or GitHub APIs.

Host as documentation over HTTPS, preferably on an origin that does not also expose a sensitive authenticated application. The viewer is active JavaScript and runs with the hosting origin's browser privileges; absence of credential access in these exact bytes does not protect against future edits or a compromised host. Shared local-storage preference keys can also affect other Archify viewers on that origin.

Copy-link features retain the page's query string. Do not distribute diagram links containing authentication tokens or private query parameters. Clicking a source link navigates to GitHub and is a deliberate external visit.

The generated HTML does not include a restrictive CSP. When hosting, configure headers appropriate to your platform: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and restrictive CSP directives such as `connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`. A complete CSP must account for the viewer's inline scripts/styles, embedded fonts/icons and blob-based exports; script hashes should be derived from the exact artifact and refreshed after regeneration. Set `frame-ancestors` in the HTTP header according to whether embedding is intended. Server headers and deployment were not tested in this review.

References: [MDN connect-src](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src), [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP), [noopener](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Attributes/rel/noopener), [safe text insertion](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Safely_inserting_external_content_into_a_page).
