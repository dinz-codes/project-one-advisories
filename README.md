# Project One advisories

Signed bundles of vendor security advisories for the **Project One** vulnerability engine, rebuilt every day.

Each Project One server downloads the newest bundle once a day, checks its fingerprint and its Ed25519 signature
against the Project One release key, and only then uses it. Customers do nothing; the server needs outbound HTTPS to
`github.com` (a proxy in `HTTPS_PROXY` is honoured).

| File | What it is |
|---|---|
| [`latest.json`](https://github.com/dinz-codes/project-one-advisories/releases/latest/download/latest.json) | Bundle id, date, number of advisories, SHA-256 of the bundle |
| [`advisories.json`](https://github.com/dinz-codes/project-one-advisories/releases/latest/download/advisories.json) | The signed bundle |

**Offline servers:** download `advisories.json` on a connected machine and load it in Project One under
*Admin › Updates › Load advisory file*. The signature is checked the same way.

## Sources

| Vendor | Operating systems | Source |
|---|---|---|
| Cisco | IOS, IOS XE, NX-OS | Cisco PSIRT CSAF 2.0 provider (`https://www.cisco.com/.well-known/csaf/provider-metadata.json`) |
| Palo Alto Networks | PAN-OS | Palo Alto Networks security advisory API (CVE JSON 5 records) |
| Fortinet | FortiOS | Not yet: Fortinet does not publish machine-readable advisories. Until then Project One shows FortiGates as *not assessed*, never as clean. |

The advisory facts (affected and fixed versions, severity, CVEs, links) come from the vendors' public advisories;
each entry links to the vendor's page, which remains the authority. `curated/requires.json` adds, per advisory, the
configuration conditions (for example "HTTP server enabled") that let Project One tell *affected* from *not exposed*;
`curated/extra.json` holds advisories in Project One's own form for sources without a feed.

## How a bundle is built

`.github/workflows/build.yml` runs daily: `builder/` (copied from Project One's `advisories.py` and `ed25519.py`, standard
library only) reads the sources, converts them, signs the result with the release key held in the `ADVISORY_SIGNING_KEY`
repository secret, and publishes a release. The newest 30 releases are kept. A run that produces an empty bundle
publishes nothing.

Format: `project-one-advisories/1`. The signature covers the canonical JSON of the bundle without `signature`
(sorted keys, no spaces).
