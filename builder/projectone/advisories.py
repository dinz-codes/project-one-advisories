"""Vendor security advisories for the vulnerability engine: a signed bundle that Project One builds and publishes,
and that each installation imports. It works without internet access at the customer.

Bundle (JSON):
    {"format": "project-one-advisories/1", "bundle_id": "...", "built_at": "...", "sources": [...],
     "advisories": [ADVISORY, ...], "key_id": "<public key hex>", "signature": "<hex>"}
    ADVISORY = {"id", "vendor", "title", "url", "published", "updated", "severity", "cvss", "cves": [...],
                "os": "IOS XE" | "IOS" | "NX-OS" | "PAN-OS" | "FortiOS",
                "affected": {"versions": [...], "ranges": [{"introduced": v, "fixed": v} | {"introduced", "last_affected"}]},
                "fixed": [...], "requires": [CONDITION, ...], "workaround": "..."}
    CONDITION = {"feature": "HTTP server", "op": "running_config" (a configuration evidence kind),
                 "pattern": "<regex>", "present": true}   -- data, never code

The signature is Ed25519 over the canonical JSON of the bundle without "signature" (sorted keys, no spaces). A bundle
is trusted only when its key is a Project One release key (TRUSTED_KEYS) or a key the installation added
(PROJECT_ONE_ADVISORY_KEYS); an unsigned bundle is refused unless PROJECT_ONE_ADVISORY_ALLOW_UNSIGNED=1 (lab only).

Building a bundle (the publisher's machine, with internet):
    python -m projectone.advisories keygen --out ~/.project-one/advisory-signing.key
    python -m projectone.advisories build --csaf <folder or provider-metadata URL> [--csaf ...] [--extra extra.json]
                                          [--requires requires.json] --key ~/.project-one/advisory-signing.key --out bundle.json
    (--paloalto adds PAN-OS advisories from the vendor's public API; --latest writes latest.json for the update service)
Updating (each installation): automatic, daily, from the update service (projectone/advisory_feed.py); the bundle
shipped in a release (projectone/data/advisories.json) is used until then. Offline installations import a file:
    python -m projectone.advisories import bundle.json          (or Vulnerabilities > Import advisories, admin)
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import ed25519

FORMAT = 'project-one-advisories/1'
# Project One release keys (public halves). The private key lives only in the advisory repository's signing secret.
TRUSTED_KEYS: dict[str, str] = {
    'b0900af27f29c26aa3e3af2ebc152a4fc6e0bce3c97bdb5da4cfca6c2a808d77': 'Project One release key (2026-11)',
}
OS_NAMES = ('IOS XE', 'IOS', 'NX-OS', 'PAN-OS', 'FortiOS')
SEVERITIES = ('critical', 'high', 'medium', 'low', 'none')
MAX_ADVISORIES = 50000
log = logging.getLogger('projectone.advisories')


# ------------------------------------------------------------------ storage and trust
def store_dir() -> Path:
    from .credentials import secrets_dir
    return Path(os.getenv('PROJECT_ONE_ADVISORY_DIR') or (secrets_dir().parent / 'advisories')).expanduser().resolve()


def canonical(bundle: dict) -> bytes:
    body = {k: v for k, v in bundle.items() if k != 'signature'}
    return json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def trusted_keys() -> dict:
    keys = dict(TRUSTED_KEYS)
    for k in re.split(r'[\s,]+', os.getenv('PROJECT_ONE_ADVISORY_KEYS', '').strip()):
        if re.fullmatch(r'[0-9a-f]{64}', k or ''):
            keys[k] = 'added by this installation'
    return keys


def check(bundle: dict) -> dict:
    """Validate the bundle's shape and signature. Returns {'trust': 'signed' | 'unsigned (lab)', 'key': ...}."""
    if not isinstance(bundle, dict) or bundle.get('format') != FORMAT:
        raise ValueError(f'Not a Project One advisory bundle (format must be {FORMAT})')
    adv = bundle.get('advisories')
    if not isinstance(adv, list) or len(adv) > MAX_ADVISORIES:
        raise ValueError('The bundle has no advisory list, or too many advisories')
    for a in adv:
        _check_advisory(a)
    key, sig = bundle.get('key_id'), bundle.get('signature')
    if sig:
        keys = trusted_keys()
        if key not in keys:
            raise ValueError('The bundle is signed with a key this installation does not trust')
        try:
            ok = ed25519.verify(bytes.fromhex(key), canonical(bundle), bytes.fromhex(sig))
        except ValueError:
            ok = False
        if not ok:
            raise ValueError('The bundle signature does not match its content: it was changed after signing')
        return {'trust': 'signed', 'key': key, 'key_note': keys[key]}
    if os.getenv('PROJECT_ONE_ADVISORY_ALLOW_UNSIGNED') == '1':
        return {'trust': 'unsigned (lab)', 'key': None}
    raise ValueError('The bundle is not signed. Import only bundles signed with a Project One release key '
                     '(PROJECT_ONE_ADVISORY_ALLOW_UNSIGNED=1 allows unsigned bundles in a lab).')


def _check_advisory(a):
    if not isinstance(a, dict) or not isinstance(a.get('id'), str) or not a['id']:
        raise ValueError('An advisory has no id')
    if a.get('os') not in OS_NAMES:
        raise ValueError(f'Advisory {a["id"]}: unknown operating system {a.get("os")!r}')
    if a.get('severity') not in SEVERITIES:
        raise ValueError(f'Advisory {a["id"]}: unknown severity {a.get("severity")!r}')
    aff = a.get('affected') or {}
    if not isinstance(aff.get('versions', []), list) or not isinstance(aff.get('ranges', []), list):
        raise ValueError(f'Advisory {a["id"]}: affected versions must be lists')
    for c in a.get('requires') or []:
        if not isinstance(c, dict) or not isinstance(c.get('pattern'), str) or len(c['pattern']) > 300:
            raise ValueError(f'Advisory {a["id"]}: a feature condition is not valid')
        re.compile(c['pattern'])


PACKAGED = Path(__file__).resolve().parent / 'data' / 'advisories.json'
_packaged_cache: dict = {}


def packaged() -> dict | None:
    """The bundle shipped inside a Project One release (projectone/data/advisories.json), used until the installation
    has one of its own (downloaded by the daily update, or imported). Checked like any other bundle."""
    try:
        st = PACKAGED.stat()
    except OSError:
        return None
    key = (st.st_mtime_ns, st.st_size)
    if _packaged_cache.get('key') != key:
        try:
            b = json.loads(PACKAGED.read_text(encoding='utf-8'))
            trust = check(b)
            b = dict(b, _imported_at=None, _imported_by='shipped with Project One', _trust=trust['trust'], _source='packaged')
        except (OSError, ValueError) as exc:
            log.warning('The shipped advisory bundle is not usable: %s', exc)
            b = None
        _packaged_cache.update(key=key, bundle=b)
    return _packaged_cache['bundle']


def current() -> dict | None:
    """The bundle in use: the installation's own (newest downloaded or imported), else the one shipped with it."""
    try:
        own = json.loads((store_dir() / 'current.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        own = None
    ship = packaged()
    if own and ship and (ship.get('built_at') or '') > (own.get('built_at') or ''):
        return ship                                     # a newer release shipped a newer bundle
    return own or ship


def info() -> dict:
    """What the page shows about the advisories in use (no advisory content)."""
    b = current()
    if not b:
        return {'loaded': False}
    built = b.get('built_at')
    age = None
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(built)).days
    except (TypeError, ValueError):
        pass
    by_os = {}
    for a in b.get('advisories', []):
        by_os[a['os']] = by_os.get(a['os'], 0) + 1
    return {'loaded': True, 'bundle_id': b.get('bundle_id'), 'built_at': built, 'age_days': age,
            'imported_at': b.get('_imported_at'), 'imported_by': b.get('_imported_by'), 'trust': b.get('_trust'),
            'count': len(b.get('advisories', [])), 'by_os': by_os, 'sources': b.get('sources', []),
            'origin': b.get('_source') or ('update service' if b.get('_imported_by') == 'auto-update' else 'imported')}


def import_bundle(data: bytes | str, *, user='cli') -> dict:
    """Check and install a bundle for every customer of this installation. The previous one is kept beside it."""
    try:
        bundle = json.loads(data)
    except ValueError:
        raise ValueError('The file is not valid JSON') from None
    trust = check(bundle)
    d = store_dir()
    d.mkdir(parents=True, exist_ok=True)
    cur = d / 'current.json'
    if cur.exists():
        old = current() or {}
        cur.replace(d / f'previous-{old.get("bundle_id", "unknown")}.json')
    bundle = dict(bundle, _imported_at=datetime.now(timezone.utc).isoformat(), _imported_by=user, _trust=trust['trust'])
    tmp = d / 'current.tmp'
    tmp.write_text(json.dumps(bundle), encoding='utf-8')
    tmp.replace(cur)
    with (d / 'imports.jsonl').open('a', encoding='utf-8') as fh:
        fh.write(json.dumps({'at': bundle['_imported_at'], 'user': user, 'bundle_id': bundle.get('bundle_id'),
                             'built_at': bundle.get('built_at'), 'count': len(bundle['advisories']),
                             'trust': trust['trust']}) + '\n')
    log.info('Advisory bundle %s imported by %s (%s advisories, %s)', bundle.get('bundle_id'), user,
             len(bundle['advisories']), trust['trust'])
    return info()


# ------------------------------------------------------------------ building a bundle (publisher side)
OS_PRODUCTS = [(re.compile(r'\bIOS[ -]?XE\b', re.I), 'IOS XE'), (re.compile(r'\bNX-?OS\b', re.I), 'NX-OS'),
               (re.compile(r'\bPAN-?OS\b', re.I), 'PAN-OS'), (re.compile(r'\bFortiOS\b', re.I), 'FortiOS'),
               (re.compile(r'\bIOS\b(?![ -]?XE)', re.I), 'IOS')]
CVSS_SEVERITY = [(9.0, 'critical'), (7.0, 'high'), (4.0, 'medium'), (0.1, 'low')]


def _os_of(name: str):
    for rx, os_name in OS_PRODUCTS:
        if rx.search(name or ''):
            return os_name
    return None


def _walk_branches(branches, path=()):
    """CSAF product_tree branches -> (product_id, os, version-or-range, full name)."""
    for b in branches or []:
        here = path + ((b.get('category'), b.get('name')),)
        prod = b.get('product')
        if prod and isinstance(prod, dict):
            cat, name = b.get('category'), b.get('name')
            full = ' '.join(n for _, n in here if n)
            yield prod.get('product_id'), _os_of(full), cat, name, full
        yield from _walk_branches(b.get('branches'), here)


def _vers_range(text: str):
    """'vers:generic/>=7.4.0|<=7.4.4' or '>=7.4.0|<7.4.5' -> {'introduced', 'fixed' | 'last_affected'}."""
    spec = text.split('/', 1)[1] if text.startswith('vers:') else text
    out = {}
    for part in spec.split('|'):
        m = re.match(r'^\s*(>=|>|<=|<)\s*(\S+)\s*$', part)
        if not m:
            continue
        op, v = m.groups()
        if op in ('>=', '>'):
            out['introduced'] = v
        elif op == '<':
            out['fixed'] = v
        else:
            out['last_affected'] = v
    return out if 'introduced' in out and ('fixed' in out or 'last_affected' in out) else None


def from_csaf(doc: dict, vendor_hint: str = '') -> list[dict]:
    """One CSAF 2.0 document -> advisories for the operating systems Project One knows (one per OS)."""
    d = doc.get('document') or {}
    track = d.get('tracking') or {}
    products = {}
    for pid, os_name, cat, name, full in _walk_branches((doc.get('product_tree') or {}).get('branches')):
        if pid and os_name:
            products[pid] = (os_name, cat, name)
    if not products:
        return []
    url = next((r.get('url') for r in d.get('references', []) if r.get('category') == 'self'), None) or \
        next((r.get('url') for r in d.get('references', [])), None)
    vendor = vendor_hint or ((d.get('publisher') or {}).get('name') or '').split()[0].lower()
    cves, affected_ids, fixed_ids, scores = set(), set(), set(), []
    for v in doc.get('vulnerabilities') or []:
        if v.get('cve'):
            cves.add(v['cve'])
        st = v.get('product_status') or {}
        affected_ids.update(st.get('known_affected') or [])
        affected_ids.update(st.get('first_affected') or [])
        affected_ids.update(st.get('last_affected') or [])
        fixed_ids.update(st.get('fixed') or [])
        fixed_ids.update(st.get('first_fixed') or [])
        for s in v.get('scores') or []:
            c = s.get('cvss_v3') or s.get('cvss_v4') or {}
            if isinstance(c.get('baseScore'), (int, float)):
                scores.append(float(c['baseScore']))
    cvss = max(scores) if scores else None
    agg = ((d.get('aggregate_severity') or {}).get('text') or '').lower()
    severity = agg if agg in SEVERITIES else next((s for t, s in CVSS_SEVERITY if cvss is not None and cvss >= t), 'none')
    out = {}
    for pid, (os_name, cat, name) in products.items():
        if pid not in affected_ids and pid not in fixed_ids:
            continue
        a = out.setdefault(os_name, {'id': track.get('id') or d.get('title'), 'vendor': vendor, 'title': d.get('title'),
                                     'url': url, 'published': track.get('initial_release_date'),
                                     'updated': track.get('current_release_date'), 'severity': severity, 'cvss': cvss,
                                     'cves': sorted(cves), 'os': os_name,
                                     'affected': {'versions': [], 'ranges': []}, 'fixed': [], 'requires': []})
        if pid in affected_ids:
            if cat == 'product_version_range':
                r = _vers_range(name)
                if r:
                    a['affected']['ranges'].append(r)
            else:
                a['affected']['versions'].append(name)
        elif pid in fixed_ids and cat != 'product_version_range':
            a['fixed'].append(name)
    res = []
    for os_name, a in out.items():
        if len(out) > 1:
            a['id'] = f'{a["id"]}:{os_name.replace(" ", "")}'
        if a['affected']['versions'] or a['affected']['ranges']:
            a['affected']['versions'] = sorted(set(a['affected']['versions']))
            a['fixed'] = sorted(set(a['fixed']))
            res.append(a)
    return res


def _fetch(url: str, limit=20 * 1024 * 1024) -> bytes:
    if not url.startswith('https://'):
        raise ValueError('Only https sources are fetched')
    req = urllib.request.Request(url, headers={'User-Agent': 'project-one-advisory-builder', 'Accept': 'application/json'})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read(limit)


def csaf_documents(source: str, since: str | None = None):
    """CSAF documents from a local folder of .json files, or a provider (its provider-metadata.json, following the
    CSAF 2.0 directory distribution: changes.csv lists the documents)."""
    if not source.startswith('https://'):
        for f in sorted(Path(source).expanduser().rglob('*.json')):
            try:
                yield json.loads(f.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                log.warning('Skipping %s: not readable JSON', f)
        return
    meta = json.loads(_fetch(source))
    for dist in meta.get('distributions') or []:
        for feed in (dist.get('rolie') or {}).get('feeds') or []:          # ROLIE: a feed lists the documents
            if not str(feed.get('url', '')).startswith('https://'):
                continue
            entries = (json.loads(_fetch(feed['url'], 200 * 1024 * 1024)).get('feed') or {}).get('entry') or []
            urls = [e['content']['src'] for e in entries if isinstance(e.get('content'), dict) and e['content'].get('src')
                    and not (since and str(e.get('updated', ''))[:10] < since)]
            log.info('%s: %d documents to read', feed['url'], len(urls))
            yield from _fetch_many(list(dict.fromkeys(urls)))
        base = dist.get('directory_url')
        if not base:
            continue
        base = base.rstrip('/') + '/'
        changes = _fetch(urllib.parse.urljoin(base, 'changes.csv')).decode('utf-8', 'replace')
        names = [row[0] for row in csv.reader(io.StringIO(changes))
                 if len(row) >= 2 and not (since and row[1][:10] < since)]
        log.info('%s: %d documents to read', base, len(names))
        yield from _fetch_many([urllib.parse.urljoin(base, n) for n in dict.fromkeys(names)])


def _fetch_many(urls, workers=8):
    """JSON documents fetched a few at a time; one bad document never stops the build."""
    from concurrent.futures import ThreadPoolExecutor

    def one(u):
        try:
            return json.loads(_fetch(u))
        except Exception as exc:
            log.warning('Skipping %s: %s', u, exc)
            return None
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for doc in pool.map(one, urls):
            if doc is not None:
                yield doc


# ------------------------------------------------------------------ CVE JSON 5 records (Palo Alto Networks)
PAN_BASE = 'https://security.paloaltonetworks.com'


def _bump(v: str) -> str:
    """The release after a hotfix: 10.2.4-h16 -> 10.2.5 (hotfixes are fixes inside one maintenance release)."""
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)', v)
    return f'{m[1]}.{m[2]}.{int(m[3]) + 1}' if m else v


def _cvss(cna: dict):
    best = None
    for m in cna.get('metrics') or []:
        for k in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0'):
            if isinstance(m.get(k), dict) and m[k].get('baseScore') is not None:
                sc = m[k]
                best = best or (float(sc['baseScore']), str(sc.get('baseSeverity') or '').lower())
    return best


def from_cve5(rec: dict, vendor: str = 'paloalto') -> list[dict]:
    """Advisories from one CVE JSON 5 record: one per operating system named in "affected". A version entry
    {version, lessThan, status: affected, changes: [{at, status: unaffected}]} becomes affected ranges that stop at
    each fixing hotfix and start again at the next maintenance release."""
    cna = ((rec.get('containers') or {}).get('cna')) or {}
    cve = (rec.get('cveMetadata') or {}).get('cveId') or rec.get('id')
    if not cve:
        return []
    score = _cvss(cna)
    sev = score[1] if score and score[1] in SEVERITIES else (_sev_from_score(score[0]) if score else 'none')
    texts = lambda key: ' '.join(x.get('value', '') for x in cna.get(key) or [] if isinstance(x, dict)).strip()
    out = {}
    for aff in cna.get('affected') or []:
        os_name = _os_of(f'{aff.get("vendor", "")} {aff.get("product", "")}')
        if not os_name:
            continue
        a = out.setdefault(os_name, {
            'id': cve, 'vendor': vendor, 'title': (cna.get('title') or cve)[:300],
            'url': f'{PAN_BASE}/{cve}' if vendor == 'paloalto' else next((r.get('url') for r in cna.get('references') or []), ''),
            'published': cna.get('datePublic') or (rec.get('cveMetadata') or {}).get('datePublished'),
            'updated': (rec.get('cveMetadata') or {}).get('dateUpdated'),
            'severity': sev, 'cvss': score[0] if score else None, 'cves': [cve], 'os': os_name,
            'affected': {'versions': [], 'ranges': []}, 'fixed': [],
            'conditions_text': texts('configurations')[:2000] or None, 'workaround': texts('workarounds')[:2000] or None})
        for v in aff.get('versions') or []:
            if v.get('status') != 'affected' or not re.match(r'^\d', str(v.get('version', ''))):
                continue
            start, end = str(v['version']), v.get('lessThan') or v.get('lessThanOrEqual')
            if not end:
                a['affected']['versions'].append(start)
                continue
            cuts = sorted({c['at'] for c in v.get('changes') or [] if c.get('status') == 'unaffected' and c.get('at')},
                          key=_vkey)
            lo = start
            for c in cuts:
                a['affected']['ranges'].append({'introduced': lo, 'fixed': c})
                a['fixed'].append(c)
                lo = _bump(c)
            if _vkey(lo) < _vkey(end) or (v.get('lessThanOrEqual') and _vkey(lo) <= _vkey(end)):
                a['affected']['ranges'].append({'introduced': lo, 'fixed': end} if v.get('lessThan') else
                                               {'introduced': lo, 'last_affected': end})
                if v.get('lessThan'):
                    a['fixed'].append(end)
    res = []
    for os_name, a in out.items():
        if len(out) > 1:
            a['id'] = f'{cve}:{os_name.replace(" ", "")}'
        if a['affected']['versions'] or a['affected']['ranges']:
            a['fixed'] = sorted(set(a['fixed']), key=_vkey)
            res.append({k: v for k, v in a.items() if v is not None})
    return res


def version_key(v: str) -> tuple:
    """Comparable form of a software version, the same for every vendor's style:
    17.09.04a -> (17, 9, 4, 'a'); 15.2(4)E10 -> (15, 2, 4, 'e', 10); 10.2.9-h1 -> (10, 2, 9, 'h', 1); 9.3(8); 7.4.4."""
    out = []
    for tok in re.findall(r'\d+|[A-Za-z]+', str(v or '')):
        out.append((0, int(tok)) if tok.isdigit() else (1, tok.lower()))
    return tuple(out)


_vkey = version_key


def _sev_from_score(score: float) -> str:
    return next((name for floor, name in CVSS_SEVERITY if score >= floor), 'none')


def paloalto_records(product='PAN-OS', base=PAN_BASE):
    """Every advisory for a Palo Alto product as CVE JSON 5 records (the vendor's public advisory API)."""
    data = json.loads(_fetch(f'{base}/api/v1/products/{urllib.parse.quote(product)}/advisories'))
    items = data if isinstance(data, list) else (data.get('data') or data.get('advisories') or data.get('items') or [])
    log.info('%s: %d %s advisories listed', base, len(items), product)
    ids = []
    for it in items:
        if isinstance(it, dict) and it.get('containers'):
            yield it
        elif isinstance(it, dict):
            i = it.get('ID') or it.get('id') or it.get('cveId') or (it.get('cveMetadata') or {}).get('cveId')
            if i:
                ids.append(i)
        elif isinstance(it, str):
            ids.append(it)
    yield from _fetch_many([f'{base}/json/{urllib.parse.quote(i)}' for i in dict.fromkeys(ids)])


def build(csaf_sources=(), extra=None, requires=None, since=None, vendor_hints=None, paloalto=False) -> dict:
    """Assemble an unsigned bundle. ``extra``: a list of advisories in the bundle's own form (for sources without
    CSAF). ``requires``: {advisory id: [CONDITION, ...]}, the feature conditions curated by the publisher."""
    adv, sources = {}, []
    for i, src in enumerate(csaf_sources):
        n = 0
        for doc in csaf_documents(src, since):
            for a in from_csaf(doc, (vendor_hints or {}).get(src, '')):
                adv[a['id']] = a
                n += 1
        sources.append({'source': src, 'kind': 'csaf', 'advisories': n,
                        'fetched_at': datetime.now(timezone.utc).isoformat()})
    if paloalto:
        n = 0
        for rec in paloalto_records():
            for a in from_cve5(rec, 'paloalto'):
                adv[a['id']] = a
                n += 1
        sources.append({'source': PAN_BASE, 'kind': 'cve5', 'advisories': n,
                        'fetched_at': datetime.now(timezone.utc).isoformat()})
    for a in extra or []:
        _check_advisory(a)
        adv[a['id']] = a
    if extra:
        sources.append({'source': 'curated', 'kind': 'project-one', 'advisories': len(extra)})
    for aid, conds in (requires or {}).items():
        for key in [k for k in adv if k == aid or k.startswith(aid + ':')]:
            adv[key]['requires'] = conds
    now = datetime.now(timezone.utc)
    bundle = {'format': FORMAT, 'bundle_id': now.strftime('%Y%m%dT%H%M%SZ'), 'built_at': now.isoformat(),
              'sources': sources, 'advisories': sorted(adv.values(), key=lambda a: a['id'])}
    for a in bundle['advisories']:
        _check_advisory(a)
    return bundle


def sign_bundle(bundle: dict, secret: bytes) -> dict:
    b = dict(bundle, key_id=ed25519.public_key(secret).hex())
    b.pop('signature', None)
    b['signature'] = ed25519.sign(secret, canonical(b)).hex()
    return b


def _read_key(path) -> bytes:
    raw = Path(path).expanduser().read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'[0-9a-f]{64}', raw):
        raise ValueError('The signing key file must hold 64 hex characters')
    return bytes.fromhex(raw)


def main(argv=None):
    p = argparse.ArgumentParser(description='Project One advisory bundles: build, sign, import')
    sub = p.add_subparsers(dest='cmd', required=True)
    k = sub.add_parser('keygen', help='create a release signing key (keep it secret, never in git)')
    k.add_argument('--out', required=True)
    b = sub.add_parser('build', help='build and sign a bundle from CSAF sources and curated files')
    b.add_argument('--csaf', action='append', default=[], help='folder of CSAF JSON files, or a provider-metadata URL')
    b.add_argument('--extra', help='curated advisories (JSON list, bundle form)')
    b.add_argument('--requires', help='feature conditions per advisory id (JSON object)')
    b.add_argument('--since', help='only CSAF documents changed on or after YYYY-MM-DD')
    b.add_argument('--paloalto', action='store_true', help="add Palo Alto Networks' PAN-OS advisories (their public API)")
    b.add_argument('--latest', help='also write the small latest.json (bundle id, date, sha256) the update service serves')
    b.add_argument('--key', help='signing key file (omit for an unsigned lab bundle)')
    b.add_argument('--out', required=True)
    i = sub.add_parser('import', help='check and install a bundle for this installation')
    i.add_argument('file')
    sub.add_parser('info', help='the bundle in use')
    a = p.parse_args(argv)
    if a.cmd == 'keygen':
        out = Path(a.out).expanduser()
        if out.exists():
            raise SystemExit(f'{out} exists: not overwriting a signing key')
        secret = ed25519.new_secret()
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as fh:
            fh.write(secret.hex() + '\n')
        pub = ed25519.public_key(secret).hex()
        print(f'Signing key written to {out} (keep it secret; back it up offline).')
        print('Public key, to trust bundles signed with it, add to TRUSTED_KEYS in projectone/advisories.py:')
        print(f"    '{pub}': 'Project One release key ({datetime.now(timezone.utc):%Y-%m})',")
        return
    if a.cmd == 'build':
        extra = json.loads(Path(a.extra).read_text(encoding='utf-8')) if a.extra else None
        requires = json.loads(Path(a.requires).read_text(encoding='utf-8')) if a.requires else None
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        bundle = build(a.csaf, extra, requires, a.since, paloalto=a.paloalto)
        if a.key:
            bundle = sign_bundle(bundle, _read_key(a.key))
        raw = json.dumps(bundle, separators=(',', ':')).encode('utf-8')
        Path(a.out).write_bytes(raw)
        if a.latest:
            import hashlib
            Path(a.latest).write_text(json.dumps({'format': FORMAT, 'bundle_id': bundle['bundle_id'],
                                                  'built_at': bundle['built_at'], 'count': len(bundle['advisories']),
                                                  'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
                                                  'key_id': bundle.get('key_id')}, indent=1), encoding='utf-8')
        print(f'{a.out}: {len(bundle["advisories"])} advisories, ' + ('signed' if a.key else 'UNSIGNED (lab only)'))
        return
    if a.cmd == 'import':
        try:
            out = import_bundle(Path(a.file).read_bytes(), user='cli')
        except ValueError as exc:
            print(f'Refused: {exc}', file=sys.stderr)
            raise SystemExit(2)
        print(json.dumps(out, indent=2))
        return
    print(json.dumps(info(), indent=2))


if __name__ == '__main__':
    main()
