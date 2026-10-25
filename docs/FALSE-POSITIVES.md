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

## Third pass — version rules and the root-path bug

### 11. Every rule with `path: "/"` was dead

Same class as the scrub bug, different mechanism. `_is_site_own_page` rejects a
response whose title carries the site's brand, to stop a CMS search page
answering for `/phpmyadmin/` from counting as product evidence. But the brand is
derived **from the homepage**, so testing the homepage against it always
matched: `jenkins-panel` and the router default-login rule were suppressed
before their matchers ran, on every real target. The lab only hid it because the
brand of `127.0.0.1` parses to `127`, which does not appear in the page.

The brand check is now skipped for the root path. The homepage legitimately *is*
the site's own page; there is nothing to suppress.

### A `version` matcher type

Some vulnerabilities have no response signature at all — the evidence is the
software's version against a fix boundary. A word matcher cannot do arithmetic,
so those could not be expressed as rules.

`{"type": "version", ...}` reads a version out of the response with a regex and
compares it against a per-branch `fixed_in` table. It is deliberately strict:

* the version must be **read** from the response. No version advertised means no
  match — never a guess, and never a finding inferred from the product merely
  being present. `X-Powered-By: PHP` with no number produces nothing.
* a version at or above its branch's fix does **not** match.
* a branch absent from `fixed_in` matches only when
  `unfixed_branches_affected` is set, which is how an end-of-life branch that
  will never get a fix is expressed.
* `min_affected` bounds the bottom, so ancient versions and garbage parses are
  excluded.

Two new `fplab.py` hosts are the negative controls: `phpfixed.fptest` runs the
**patched** release, `phphidden.fptest` advertises PHP with no version. Both
must stay silent. A version rule that fires on a patched host is worse than no
rule, because it teaches the operator to ignore it.

### php2shell scope: what PHP published vs. what is affected

PHP's own advisories (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp) enumerate only
**8.2 through 8.5**, because those are the branches it still supports. That is
not the affected range:

* **NVD records no lower bound** — every version below 8.2.35.
* PHP issued source backports for **7.4, 8.0 and 8.1**.
* Distributions patched further still: AlmaLinux shipped fixes for **7.2, 7.3
  and 7.4**.

So Kumo treats every branch without an entry in `fixed_in` as affected, which
covers 8.1, 8.0, all of 7.x and all of 5.x. `min_affected` sits at 5.0.0 purely
to reject a nonsense parse; PHP 4 predates the affected request-handling code
and appears in no advisory.

`test_versions.py` exercises all of this over real HTTP: 31 versions from 5.0.0
to 8.5.20, each through both the `X-Powered-By` and `Server` header forms.

### The backport caveat is the real limit here

Remote version detection cannot tell a patched Ubuntu or RHEL host from a
vulnerable one. **Both report the same version number** — a fixed Ubuntu 24.04
`php8.3` still reports 8.3.6, because those distributions backport the patch
onto the version they already ship. Debian is different: it ships the new
upstream release, so there the number does change.

This is not something a scanner can resolve from the network, so Kumo does two
things instead of pretending otherwise:

* every finding carries a **`confidence`** field. `confirmed` means the response
  itself held the evidence; `version-inference` means only a version number was
  compared.
* the rule description says plainly that on Ubuntu and RHEL the package version
  (`dpkg -l`, `rpm -q`) is the thing to check, not the PHP version.

A finding that cannot be confirmed remotely should say so, rather than being
dressed up as proof.

### Two rules, because they are two different facts

`php2shell-unpatched-php` (high) says the runtime predates the fix — remedy:
patch. `php-eol-runtime` (medium) says the branch gets no security releases at
all — remedy: migrate. A host on 8.2.34 gets only the first; a host on 7.4 gets
both, which is correct, because both statements are true of it and the actions
differ.

### php2shell (CVE-2026-109618 / CVE-2026-109619)

Two unauthenticated RCE bugs in the PHP runtime, both CVSS 9.2, fixed
2026-10-21 in **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**. These sit in the runtime,
not in application code, so every PHP serving web requests is affected and
sound application code does not protect a vulnerable install. Branches 8.1 and
earlier are end-of-life with no upstream fix.

Kumo reports exactly what it can see: an unpatched runtime version read from the
server's own headers, with the caveat that a distribution backporting fixes can
still advertise an older upstream version.

What Kumo does **not** do: the public proof-of-concept templates for this chain
POST a crafted multipart body and write session files on the target, and two of
them need an operator-supplied LFI path and session save path. That is
exploitation, not reconnaissance. None of it is implemented, and the miner
excludes it structurally by taking GET templates only.

## Fourth pass — the email security module

`scan_dns` read SPF, DMARC and DKIM records with substring searches. These are
tag-value records, and substring matching on them inverts findings.

### 12. `p=none` is a substring of `sp=none`

The worst of them. A domain publishing `v=DMARC1; p=reject; sp=none` was
reported as **"none (not enforcing)"** — the checks ran in the order
`p=none`, `p=quarantine`, `p=reject`, and `sp=none` satisfied the first one. A
domain with the strictest possible policy was reported as unprotected.

Records are now parsed into tags (`_parse_tags`) and the `p` tag is read
directly. `sp=none` is reported separately, as what it is: the organisational
domain is protected but subdomains are not.

### 12b. DMARC was never looked up at the organisational domain

This is the one a user reported from the field: DMARC enabled, Kumo said off.

DMARC was resolved with a single query — `_dmarc.<target>` — and nothing else.
RFC 7489 §6.6.3 requires a receiver that finds no record at the exact name to
query the **organisational domain**, which is how a policy published at
`example.com` governs mail from `www.example.com`. Kumo only ever made the
first query, so **every scan of a subdomain reported "DMARC missing — spoofing
risk"** on a domain that has DMARC enabled and enforced.

`_parent_domains` now walks up label by label, stopping before a public suffix
so `_dmarc.co.uk` is never queried and a registry suffix can never be mistaken
for a domain. The result records `found_at` and `inherited`.

One subtlety worth keeping right: for an inherited record the policy that
applies to the subdomain is `sp=` when present, falling back to `p=`. A
subdomain of a `p=reject; sp=none` domain is genuinely **not** protected, so
reporting the parent's `reject` there would overstate the posture. The scan
reports `none (not enforcing)` for the subdomain and `reject (strict)` for the
apex — both correct, from the same record.

For the record, this was not caused by a predefined list. DMARC has no list in
its path; the only predefined list in the module is `DKIM_SELECTORS`, which
affects DKIM alone (see below).

### 13. Anything at `_dmarc` counted as a policy

The test was `if "dmarc" in record.lower()`. A DMARC record must begin with
`v=DMARC1` (RFC 7489 §6.3), and other TXT records legitimately live at that
name — verification tokens, notes. Those were parsed as policies.

### 14. Multiple records are a broken config, not a working one

Two SPF records is a permerror (RFC 7208 §4.5) and receivers reject the lot.
Two DMARC records means receivers apply **no** policy (RFC 7489 §6.6.3). Kumo
read the first and reported it as the active policy, so a domain whose email
authentication was broken looked correctly configured. Both are now flagged as
invalid.

### 15. A revoked DKIM key read as a healthy one

The test was `if "p=" in record`. An empty `p=` tag means the key has been
**revoked** (RFC 6376 §3.6.1). Kumo reported it as DKIM present and working.
Key material is now required, and a revoked selector is reported as revoked.

### 16. A failed lookup was reported as a missing record

`dns_query` returned `[]` both when a record did not exist and when the lookup
failed. So a DoH hiccup produced "DMARC Missing — spoofing risk" on domains
that publish DMARC. `dns_query_ex` now distinguishes `ok` / `nxdomain` /
`error`, and a failed lookup is reported as *not determined*. Absence is only
claimed when the resolver actually answered.

### 17. Nine DKIM selectors was not enough

A DKIM selector cannot be enumerated — it is only found by guessing the name.
So "DKIM not found" only ever meant "none of the names we tried existed", and
with nine names it missed most hosted mail providers, reporting a weakness that
was not there.

The list is now **89 selectors**, covering the published defaults of Google
Workspace, Microsoft 365, Zoho, SendGrid, Mailchimp/Mandrill, Postmark,
Mailgun, SparkPost, Fastmail, Proton Mail, HubSpot, Constant Contact, Campaign
Monitor, Klaviyo, Amazon SES, Mimecast, Proofpoint, Barracuda and others.

Even so, a custom selector still cannot be found, so the result says
"no key at 89 known selectors" rather than "DKIM absent", and DKIM is excluded
from the grade's penalty side: it can earn credit, never cost it. Claiming a
weakness that rests on a guessing game is the kind of finding this whole
document exists to remove.

### Long TXT records were being corrupted

A TXT record over 255 bytes arrives as several quoted chunks that must be
joined with no separator (RFC 7208 §3.3). Long SPF and DKIM records were read
with the quotes still in them. `_txt_values` joins them the way a resolver
does.

`test_email_security.py` covers all of this: the record shapes, and `scan_dns` end to
end through a stubbed resolver, including the case where absence must NOT be
claimed.

## Fifth pass — the per-email stealer check

The card has a "Per-Email Stealer Check" section. It was checking far fewer
addresses than it looked like, and in one path, none at all.

### 18. The first per-email check was dead code

```python
employee_emails = set()
for url_entry in hr["employee_urls"][:20]:
    if isinstance(url_entry, dict):
        url_val = url_entry.get("url", "")
        pass          # <- the whole loop body
if employee_emails:   # always False
```

The set was never populated, so the block never ran and
`hr["email_stealer_checks"]` was always empty.

### 19. The harvester's addresses never reached the check

`results["sources"]["harvested_emails"]` was hardcoded to `[]` with a comment
saying the email_harvest module would fill it. Nothing ever did — that line was
the only reference to the key in the entire codebase. Meanwhile
`scan_email_harvest`'s own docstring said "stealer checks happen in breachintel
module". Each module was waiting for the other.

The practical effect: the stealer check only ever saw addresses that came back
from Chiasmodon and ProxyNova, the credential-leak sources. The company's
actual published staff addresses — scraped from the site, crt.sh and DNS, and
the ones most worth checking — were never looked up. On a domain where those
two APIs returned nothing, **zero** lookups were performed.

`_collect_domain_emails` is now a shared, cached, lock-guarded harvester that
both modules call, so the check sees every address the harvester found. The
cache matters because the two modules run concurrently in the web UI; without
it they would duplicate every request or race.

### 20. A hard cap of 20, applied silently

```python
_email_list = sorted(all_stealer_emails)[:20]
```

Alphabetical, so on a domain with 60 addresses the 40 after the twentieth went
unchecked — and nothing in the output said so. The card read "N infected / 20
checked" with no hint that 40 more existed.

The cap is now opt-in through `KUMO_MAX_EMAIL_CHECKS` (unset means check
everything), and `hr_per_email_stats` reports collected / checked / skipped
with a per-source breakdown, so the coverage is visible instead of assumed.

### 21. A rate-limited lookup counted as clean

`if _r.status_code == 200:` and nothing else — any other status fell through to
`return email, None` and the address vanished from the results. A 429 from
Hudson Rock, which is exactly what happens when you check a lot of addresses
against a free API, produced silence that read as safety.

`compromised` is now tri-state: `True`, `False`, or `None` for "not
determined", carrying the reason. The UI counts and lists those separately and
never colours them as clean. This is the same rule as the DNS module's failed
lookups: **absence of an answer is not an answer.**

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
7. **A version rule needs a patched-host control.** Add the fixed release to
   `VERSION_CASES` and assert it does *not* fire. Boundaries are off-by-one
   magnets, and the patched case is the one that matters.
8. **Detection, not exploitation.** A rule is a GET and a signature. If a check
   needs a payload, writes state on the target, or wants the operator to supply
   an exploit path, it does not belong in Kumo.
9. **Never substring-match a tag-value record.** SPF, DMARC, DKIM, MTA-STS and
   BIMI records are parsed, not searched: `p=none` is a substring of `sp=none`.
10. **A failed lookup is not an absent record.** If a check reports something
   missing, be sure the query actually succeeded first.
11. **Never cap a result set silently.** If a limit applies, report what was
   collected, what was checked and what was skipped.
12. **Don't claim absence you cannot establish.** DKIM selectors can't be
   enumerated, so a miss is "not found at the names we tried". Where absence is
   unprovable, the finding earns credit when present but costs nothing when not.
