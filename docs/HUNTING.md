# Hunting with Kumo

## Passive and active modules

Determined by observation, not by reading the source: `classify_modules.py`
runs every module against a local target and records each outbound connection.
Source reading got this wrong — `scan_nuclei` looks passive because its probing
lives in a helper, and `scan_robots` looks passive because its fetch is one
line. Both are active.

| | count | behaviour |
|---|---|---|
| **passive** | 12 | never contact the target; read third-party data only |
| **active** | 15 | send traffic the target logs |

**Passive:** `breachintel`, `brute`, `censys`, `cloud_buckets`, `dns`, `dorks`,
`geo`, `osint`, `shodan`, `subdomains`, `wayback`, `whois`

**Active:** `api_fuzzer`, `content_intel`, `email_harvest`, `endpoints`,
`favicon`, `headers`, `http_inspect`, `js_secrets`, `nuclei`, `ports`,
`robots`, `screenshot`, `ssl`, `wafw00f`, `whatweb`

Request volume against the target, measured on one host:

| module | requests |
|---|---|
| `nuclei` | 1321 |
| `endpoints` | 294 |
| `api_fuzzer` | 194 |
| `ports` | 96 |
| `email_harvest` | 26 |
| everything else | under 10 each |

`nuclei` alone is over 1300 requests. That is not something to point at a host
you have not confirmed is in scope.

Two third-party calls worth knowing about, since they leave the target's name
with someone else: `screenshot` contacts `api.ransomware.live`, and
`breachintel` contacts `cavalier.hudsonrock.com` and `api.proxynova.com`.

## The harness

`hunt.py` is passive by default.

```bash
# safe at any scale — nothing reaches the target
python3 hunt.py --scope scope.txt --workers 4

# active modules, only for assets you are authorised to test
python3 hunt.py --domain target.com --active --in-scope

# resume a long run
python3 hunt.py --scope scope.txt --resume hunt-out/state.json
```

`--active` without `--in-scope` is refused. That is deliberate: it makes the
authorisation an explicit act rather than a default.

A scope file is one domain per line. Comments, blank lines, a leading `*.` and
a pasted `https://host/path` are all handled, so HackerOne and Bugcrowd scope
tables paste in directly.

## Output

- `hunt-out/<domain>.json` — full per-domain results
- `hunt-out/triage.md` — a queue, highest value first
- `hunt-out/state.json` — resume point

Ranking reflects what a triage team actually accepts: infostealer credentials
and cloud buckets above exposed files, exposed files above version-inferred
findings. A `version-inference` finding is scored at half weight, because a
version comparison is weaker evidence than a direct hit — see
[FALSE-POSITIVES.md](FALSE-POSITIVES.md).

Nothing here is a report. It is a queue to verify by hand.
