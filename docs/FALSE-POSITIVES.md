# False positives in Kumo

A recon tool is judged on what it reports, not on how much it reports. A scan
that lists thirty findings on a host that has none is worse than useless: it
burns the operator's time and trains them to ignore the output.

This note records how Kumo decides something is real, what went wrong, and how
it is tested so it stays fixed.

## The two labs

| Lab | Target | Question | Correct answer |
|---|---|---|---|
| `lab.py` | `127.0.0.1` | Does Kumo find what is planted? | 20 planted exposures |
| `fplab.py` | seven `*.fptest` vhosts | Does Kumo invent findings? | **nothing, on every host** |

`fplab.py` serves seven shapes of ordinary web host that make naive scanners
hallucinate. None has a single genuine exposure:

| Host | Behaviour |
|---|---|
| `spa.fptest` | every path returns the same 200 SPA shell (client-side router) |
| `soft404.fptest` | unknown paths return **200** with a friendly "not found" page |
| `waf.fptest` | every path returns 403 from a WAF, with a per-request trace id |
| `echo.fptest` | CMS search page: 200, `<title>` echoes the requested path |
| `jsonapi.fptest` | API gateway: 200 JSON with generic keys on every path |
| `clean.fptest` | a properly built, hardened site with honest 404s |
| `redirect.fptest` | every unknown path 302-redirects to the homepage |

Page sizes are derived from a hash of the path, so a path always answers with
the same size while different paths differ — which is what defeats size-only
catch-all detection in the real world.

```bash
python3 test_fp.py                 # all seven hosts, all exposure modules
python3 test_fp.py echo.fptest     # one host
python3 test_rules.py              # all 365 rules against 11 decoy responses
python3 test_live.py               # the vulnerable lab: did detection survive?
```

`test_fp.py` adds the vhost names to `/etc/hosts` itself and needs ports 80/443.

## What was wrong

### 1. The porting pipeline flattened nuclei's matcher conditions

`mine_templates.py` collected every `words:` block in a template into one flat
list, and `gen_rules.py` joined that list with `condition: or`. Nuclei ANDs
separate matcher blocks together and many templates set `condition: and` inside
one. The result: templates written to require several indicators fired on any
single one of them.

That is how a **critical** Langflow rule came to fire on any JSON response
containing `"timestamp":`, and an XWiki rule on anything containing `comment`.

Fixed in three places:

* `mine_templates.py` keeps each word block separate, with its own condition.
* `gen_rules.py` emits one matcher per block and preserves that condition;
  it also normalises quoting before the generic-word filter, so `"title"` is
  now recognised as the generic token `title` and dropped.
* `engine._eval_rule` applies an **evidence floor** at scan time, which retro-fits
  the 335 rules already shipped: a rule may only fire if at least one satisfied
  word matcher rested on a specific token. Generic supporting matchers
  (`<form`, `login`) are still allowed alongside a strong one — they just
  cannot carry a finding alone. `_WEAK_EVIDENCE` is the vocabulary list.

### 2. Query-only paths always hit the homepage

Probes like `/?view=log`, `/?pp=env` and `/?query=SHOW%20DATABASES` name no
resource, so every server answers them with its index page. The catch-all
baseline only sampled random **paths** (`/a1b2c3…`), whose 404 looks nothing
like the homepage, so nothing suppressed them.

On the hardened `clean.fptest` host this produced a **high-severity ClickHouse
"improper authorization"** finding — on a site running no ClickHouse at all.
It would have fired on every real site Kumo ever scanned.

`_catchall_baseline` now also samples the root with a random query string, and
`_is_catchall(r, base, path)` compares root-query probes against that homepage
baseline.

### 3. `scan_endpoints` had no brand check

The rule engine already suppressed the target's own templated pages via
`_is_site_own_page`, but the endpoint prober did not. On `echo.fptest` a search
page titled `phpinfo php · BrandMart` was reported as an exposed `phpinfo()`.
`scan_endpoints` now fetches the homepage once, derives the site brand and
applies the same check.

The brand check is used rather than a bare path echo on purpose: for real
products the path and the product name are legitimately the same, so
`/phpinfo.php` returning a page titled `phpinfo()` must still be reported.

### 4. Raw-file rules satisfied by HTML pages

A rule claiming `/.s3cfg` or `/wp-config.php.bak` is exposed could be satisfied
by an HTML page that merely mentioned `DB_PASSWORD` — a blog post about
credentials, for instance. `_eval_rule` now rejects an HTML body for any path
that names a file (`_is_rawfile_path`), while still allowing HTML for
directories, since an `Index of /…` listing is a genuine HTML finding.

### 5. Junk entries

* `/hopfully404` was mined from a nuclei template that uses it as a 404
  *baseline*, and shipped as an endpoint named "Google API Key". Removed.
* `wpconfig-aws-keys` targeted `/%c0`, an encoding probe rather than a resource.
  Repointed at `/wp-config.php.bak` with a `not_html` guard. `gen_rules.py`
  now rejects paths whose last segment is only percent-escapes or punctuation.
* `apache-zeppelin-unauth` accepted a bare `status":"OK`, so any API answering
  `{"status":"ok"}` looked like an exposed Zeppelin. It now requires the
  anonymous ticket, which is the actual evidence.

### 6. HTTPS failure aborted the probe

In `scan_endpoints`, an exception on the HTTPS attempt `break`-ed out of the
scheme loop instead of falling through to HTTP, so HTTP-only hosts were probed
once and silently skipped. Now `continue`.

## Results

| Harness | Before | After |
|---|---|---|
| Ported rules firing on decoy responses | 13 | **0** |
| Trap hosts with false findings | 5 of 7 | **0 of 7** |
| Planted exposures still detected (`lab.py`) | 20 | **20** |
| Playbook hits on the vulnerable lab | 50 | **50** |

Detection is unchanged; only the false findings are gone. The one endpoint
finding that disappeared from the vulnerable lab was `/?view=log` — the
homepage, which was never a finding.

## Second pass — what the labs found next

### 7. Fourteen rules could never fire

The anti-echo scrub strips the requested path from a response before matching,
so a server echoing the URL cannot satisfy a product matcher. But for real
products the path and the product name are legitimately the same — a rule for
`/transmission/web/` matching the word `Transmission` had its own evidence
scrubbed away before it was tested. Fourteen rules were structurally dead,
including the hand-written `docker-api` and `graphql-introspection`. That is
why the live lab only ever reported 18 of 20 expected hits.

`_rule_scrub` now keeps any token the rule itself declares as evidence. Path
echoes are still caught by the remaining scrub and by `_is_site_own_page`.

`test_rules.py` missed this because it evaluated rules **without** the scrub the
scanner applies. It now evaluates exactly as the scanner does, and carries a
dead-rule check so an unfireable rule fails the suite instead of sitting silent.

### 8. Binary bodies were mis-decoded

`requests` falls back to charset auto-detection when a response has no charset.
On a NUL-heavy binary file it guesses something like UTF-16 and returns
mojibake, so the `.DS_Store` rule never matched its own `Bud1` magic bytes.
`_resp_part` now decodes the raw bytes directly, with a latin-1 fallback that
maps every byte to a character.

### 9. URL fragments never reach the server

Seven mined templates had paths like `/#/alerts`. Everything after `#` is
stripped by the client, so those rules silently probed the homepage — the same
failure mode as the query-only probes. They are dropped, and `gen_rules.py`
rejects fragment paths.

### 10. CDN edge ports reported as the target's surface

A domain behind Cloudflare resolves to Cloudflare's edge, which accepts
connections on a fixed set of ports for **every** proxied domain — with real
TLS behind them, so banner verification confirmed them. Kumo reported those as
the target's open ports.

`_cdn_identity` recognises Cloudflare, Fastly, Sucuri, Akamai and CloudFront by
IP range first, then by response headers. Edge ports stay in the output, because
knowing a site is proxied matters, but they are labelled `via <cdn> edge`,
forced to `info`, and excluded from alerts in both UIs. The result carries
`origin_open` for the ports that are actually the target's.

## Rules of thumb for new checks

1. **Never let a status code alone be evidence.** Pair it with a word matcher.
2. **Evidence words must be specific.** If a word could appear on a marketing
   page, it is corroboration at best. Add it to `_WEAK_EVIDENCE`.
3. **A raw file must not be HTML.** Add `{"type": "dsl", "dsl": ["not_html"]}`.
4. **A probe that addresses no resource is not a probe.** Query-only paths need
   the homepage baseline; so does anything that resolves to `/`.
5. **Every new rule gets a positive fixture in `test_rules.py`** and must
   survive all 11 decoys.
6. **Then run `test_fp.py`.** Synthetic decoys miss things a real socket finds.
