# Kumo — themed build

## Fix: the ports card never stopped loading

On a real scan the ports pill showed **done** while the ports card sat on its
loading skeleton forever. Two defects behind it.

The CDN work introduced `if(d.cdn&&d.cdn_note)` in the ports renderer, where
the payload is `data`, not `d`. That threw a `ReferenceError` as soon as a host
had any open port, so on every real scan. **`node --check` passed it** — it is
valid JavaScript that only fails when it runs.

Worse, the failure was invisible. The pill is set before the card is filled, and
`fillCard` threw before reaching the call that clears the `running` class, so
the skeleton stayed up while the scan reported itself complete. `fillCard` now
catches, shows the error in the card, and always leaves the running state, so a
render bug can no longer present as a hang.

New `test_renderers.py` executes every renderer in Node against real engine
output, an error dict and an empty object. Put the typo back and `node --check`
still passes while this test fails.


## Subdomains: Shodan InternetDB added as a fifth source (free, no key)

Kumo already called `internetdb.shodan.io/{ip}` in the Shodan module and parsed
its `hostnames` field, then dropped it. Those hostnames are often subdomains of
the target, and the subdomain module never saw them. It now does, so crt.sh,
HackerTarget, RapidDNS, AlienVault and InternetDB all feed one list. Still no
API key required.

**The reason this needed care:** InternetDB answers per IP, and its hostname
list belongs to the *address*, not to your target. On shared hosting or behind
a CDN, one address serves many customers, so that list routinely contains other
people's domains. Adding it unfiltered would have put strangers' hostnames in
your subdomain list and presented them as findings.

Every name is checked against the target domain before it is kept, and each
one now records which source produced it. The per-source counts show in both
UIs, so a questionable entry can be traced instead of guessed at.

`test_subdomain_sources.py` feeds in a realistic shared-IP response — the
target's own names mixed with `shop.othercompany.com`, `cdn.cloudflare.net`,
`acme-corp.com.evil.net`, `evil-acme-corp.com` and `notacme-corp.com` — and
asserts only the target's own subdomains survive.


## Per-email stealer check now checks every address

The breachintel card's "Per-Email Stealer Check" was checking far fewer
addresses than it appeared to, and on many domains none at all.

Four problems, all now fixed:

1. **The first per-email block was dead code.** It built its address list in a
   loop whose body was a bare `pass`, so the list was always empty and the
   block never ran.
2. **The harvester's addresses never reached it.** `harvested_emails` was
   hardcoded to `[]` with a comment saying another module would fill it;
   nothing ever did. So the check only saw Chiasmodon and ProxyNova results,
   never the company's published staff addresses — the ones most worth
   checking. If those two APIs returned nothing, **zero** lookups ran.
3. **A silent cap of 20**, applied alphabetically. On a domain with 60
   addresses, 40 went unchecked with nothing in the output saying so.
4. **A rate-limited lookup counted as clean.** Any non-200 response made the
   address disappear from the results, and a 429 is exactly what a free API
   returns when you check a lot of addresses.

`_collect_domain_emails` is now a shared, cached harvester that both
email_harvest and breachintel call, so the check sees every address found.
There is no cap unless you set `KUMO_MAX_EMAIL_CHECKS`, and the card shows
collected / checked / clean / not-determined / skipped with a per-source
breakdown. `compromised` is tri-state, so "could not check" is displayed and
counted separately from "clean" and never looks green.

**Employees only.** The check looks up addresses at the company's own domains
and nothing else. Client addresses — the target's customers, at gmail.com or
their own employer's domain — are never queried: they are other people, out of
scope, and looking them up would be a privacy problem. `client_logins` is
counted in the summary and never fed to the lookup.

That boundary is now parsed rather than suffix-matched, which fixed two edges:
scanning a subdomain used to collect **zero** addresses (nothing ends with
`@www.acme-corp.com`), and the harvester's regex could extract a fabricated
`someone@acme-corp.com` out of `someone@acme-corp.com.evil.com`. Lookalike
domains, subdomains and malformed addresses are all rejected.

New `test_stealer_coverage.py` proves all 60 of 60 collected addresses get
checked, that no client address is ever looked up, that nothing is dropped
silently, and that a failed lookup is never reported as clean.


## Email security module rewritten

`scan_dns` read SPF, DMARC and DKIM with substring searches. On tag-value
records that inverts findings. The worst case: **`p=none` is a substring of
`sp=none`**, so a domain publishing `v=DMARC1; p=reject; sp=none` — the
strictest policy there is — was reported as *"none (not enforcing)"*.

**The one reported from the field:** DMARC was resolved with a single query to
`_dmarc.<target>`. RFC 7489 §6.6.3 requires falling back to the organisational
domain, which is how a policy at `example.com` governs `www.example.com`. Kumo
never made that second query, so **every subdomain scan reported DMARC as
missing** on domains that have it enabled. Fixed: the lookup now walks up to
the organisational domain, stopping before a public suffix, and reports where
the policy was found. An inherited policy correctly uses `sp=` when present, so
a subdomain of a `p=reject; sp=none` domain is reported as unprotected rather
than inheriting the parent's `reject`.

Seven false positives fixed:

| was | now |
|---|---|
| subdomain scans read DMARC as missing | falls back to the organisational domain (RFC 7489 §6.6.3) |
| `p=reject; sp=none` read as "not enforcing" | records parsed into tags; `sp=none` reported separately |
| any TXT at `_dmarc` read as a policy | must begin with `v=DMARC1` (RFC 7489) |
| two SPF or DMARC records read as working | flagged invalid — receivers reject both (RFC 7208/7489) |
| revoked DKIM key (`p=`) read as healthy | key material required; revocation reported (RFC 6376) |
| failed DNS lookup read as "record missing" | lookups report ok/nxdomain/error; a failure is *not determined* |
| long TXT records read with quotes embedded | chunks joined the way a resolver does (RFC 7208 §3.3) |

**DKIM selectors: 9 → 89.** A selector cannot be enumerated, so "DKIM not
found" only ever meant "none of the names we tried existed" — and nine names
missed most hosted providers, reporting a weakness that wasn't there. The list
now covers the published defaults of Google Workspace, Microsoft 365, Zoho,
SendGrid, Mailchimp, Postmark, Mailgun, SparkPost, Fastmail, Proton Mail,
HubSpot, Klaviyo, Amazon SES, Mimecast, Proofpoint, Barracuda and more.

Even then, a custom selector can't be found, so the result reads "no key at 89
known selectors" rather than "DKIM absent", and DKIM is excluded from the
grade's penalty side: present earns credit, absent costs nothing.

Also added: **MTA-STS, TLS-RPT and BIMI** detection, a `pct<100` warning (a
sampled DMARC policy is commonly mistaken for full enforcement), and an email
security **grade** the web UI already had a slot for.

New `test_email_security.py`: every record shape, plus `scan_dns` end to end through a
stubbed resolver — including the case where absence must *not* be claimed.


## php2shell (CVE-2026-109618 / 109619) and a version matcher

Two unauthenticated RCE bugs in the **PHP runtime**, both CVSS 9.2, fixed
2026-10-21 in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. They sit in the runtime rather
than in application code, so every PHP serving web requests is affected and
sound application code does not protect a vulnerable install.

Kumo detects an unpatched runtime from the version the server advertises. It
does **not** attempt the chain: the public PoC templates POST a crafted
multipart body and write session files on the target, and two of them need an
operator-supplied LFI path and session save path. That is exploitation, not
reconnaissance.

**Coverage includes the old branches.** PHP's advisories list only 8.2-8.5,
because that is what it still supports, but NVD records no lower bound, PHP
backported to 7.4/8.0/8.1, and AlmaLinux patched 7.2/7.3/7.4. So every branch
with no fix of its own is treated as affected: 8.1, 8.0, all of 7.x, all of 5.x.
`test_versions.py` checks 31 versions from 5.0.0 to 8.5.20 over real HTTP,
through both the `X-Powered-By` and `Server` header forms.

Two rules, because they are two different facts with different remedies:

| rule | severity | says | remedy |
|---|---|---|---|
| `php2shell-unpatched-php` | high | runtime predates the fix | patch |
| `php-eol-runtime` | medium | branch gets no security releases | migrate |

A host on 8.2.34 gets the first only. A host on 7.4 gets both.

This needed a new **`version` matcher type**, since a word matcher cannot do
arithmetic on a version. It is strict by design: the version must be read from
the response (no version advertised means no finding, never a guess), a release
at or above its branch's fix never matches, and end-of-life branches are opt-in.
Reusable for any version-boundary CVE.

**Read the confidence field.** Findings now carry `confidence`. `confirmed`
means the response held the evidence; `version-inference` means only a version
number was compared. That matters here: Ubuntu and RHEL backport the patch
*without* changing the version, so a fixed Ubuntu 24.04 php8.3 still reports
8.3.6 and will be flagged. On those distributions check the package version
(`dpkg -l`, `rpm -q`), not the PHP version. Debian ships the new upstream
release, so there the number does change.

Negative controls: `phpfixed.fptest` runs the patched release and
`phphidden.fptest` hides its version. Both must stay silent — a version rule
that fires on a patched host trains operators to ignore it.

## One more dead-rule bug

**Every rule with `path: "/"` was suppressed on every real site.** The
site-brand check is derived *from* the homepage and then matched against the
homepage, so it always fired. That silently killed `jenkins-panel` and the
router default-login rule. The lab hid it because the brand of `127.0.0.1`
parses to `127`. The brand check is now skipped for the root path.


## Rule playbook: 365 → 418 checks

53 new rules, every one decoy-screened before it was allowed in and verified
firing against a lab fixture:

* **27 web shell / backdoor presence signatures** (C99, R57, WSO, b374k,
  FilesMan, IndoXploit, ALFA TEaM, p0wny, Mini Shell, Marijuana, Priv8,
  AntSword proxy, JSP and ASPX shells, plus shells disguised as `404.php`,
  `wp-config.php` and a plugin file). Detection only: each matches the shell's
  own interface text. Kumo reports that a shell is present; it never talks to
  one. A hit here is an incident, not a finding to schedule.
* **26 unauthenticated-exposure and installer rules** mined fresh from
  projectdiscovery/nuclei-templates through the repaired pipeline.

Mining now also covers `http/vulnerabilities/backdoor`. Templates that prove a
backdoor by POSTing a command to it are excluded by design — the miner keeps
GET-detection templates only.

Full inventory: [`docs/CHECKS.md`](docs/CHECKS.md).

## Three more precision fixes

* **Fourteen rules could never fire.** The anti-echo scrub was stripping the
  very words those rules matched on, `docker-api` and `graphql-introspection`
  among them. `test_rules.py` never caught it because it evaluated rules
  *without* the scrub the scanner applies. It now runs them exactly as the
  scanner does and carries a dead-rule check.
* **Binary bodies were mis-decoded**, so the `.DS_Store` rule never matched its
  own `Bud1` magic bytes.
* **Cloudflare edge ports** were reported as the target's open ports. They are
  open on every proxied domain. Kumo now names the CDN, labels those ports, and
  keeps them out of alerts.


## Precision pass — false positives

Kumo now ships with a **false-positive lab** (`fplab.py`) alongside the
vulnerable lab, and a harness (`test_fp.py`) that scans seven shapes of
ordinary web host where the correct answer is always "nothing found": an SPA
catch-all, a soft-404 site, a WAF that 403s everything, a CMS search page that
echoes the requested path, a JSON API gateway, a redirect-everything host, and
a correctly hardened site.

Five of those seven produced phantom findings. They now produce none.

| | before | after |
|---|---|---|
| Ported rules firing on benign responses | 13 | **0** |
| Trap hosts with phantom findings | 5 of 7 | **0 of 7** |
| Planted exposures still detected | 20 | **20** |
| Playbook hits on the vulnerable lab | 50 | **50** |

The root cause was in the porting pipeline: `mine_templates.py` merged every
`words:` block of a nuclei template into one flat list and `gen_rules.py` joined
it with `condition: or`, so a template written to require several indicators
fired on any one of them. A **critical** Langflow rule fired on any JSON
containing `"timestamp":`. A separate bug meant query-only probes such as
`/?query=SHOW%20DATABASES` were compared against a random-path 404 baseline
rather than the homepage they actually return, so a **high**-severity ClickHouse
finding appeared on hosts running no ClickHouse at all.

Both are fixed at the source, and an evidence floor in `_eval_rule` retro-fits
the 335 rules already shipped. `test_rules.py` now covers the whole playbook —
**all 365 rules against 11 decoy responses** — not just the 30 hand-written
ones. Full write-up in [`docs/FALSE-POSITIVES.md`](docs/FALSE-POSITIVES.md).

Detection is unchanged: every planted exposure is still found.


Default theme is now **Void** everywhere (terminal and web).

## Run

```bash
pip install flask requests dnspython urllib3

python3 kumo.py                  # home screen — module menu, pick by number
python3 kumo.py --web            # web dashboard on :8888
python3 kumo.py example.com      # straight to a full scan
```

## Terminal

Running `kumo.py` with no target opens a home screen: the banner, the
**web interface** panel, then all 27 modules numbered and grouped into three
columns.

At the prompt:

| Input | Does |
|---|---|
| `1 4 12` | run those modules |
| `a` | all modules |
| `f` | fast scan (skips the slow ones) |
| `w` | launch the web interface |
| `q` | quit |

The menu is generated from `ALL_MODULES`. Any module you register that is not
placed in `CATEGORY_LAYOUT` still appears, under "Other Modules" — a new module
can never silently go missing from the list.

### Spider crawl

While modules run, a spider crawls a strand of silk, spinning it behind as
each module lands:

```
  ⠹  ═══════════/\(oo)\/···············  12/27  ·  10.8s  nuclei, subdomains +3
```

It animates on its own thread and clears its row before any module prints, so
scan output is never chewed up. It turns itself off when stdout is not a
terminal, and `--no-spider` disables it.

### Themes in the terminal

```bash
python3 kumo.py --theme web example.com
export KUMO_THEME=carbon
```

`void` (default), `glass`, `web`, `carbon` — the same four palettes as the web
UI, in 24-bit colour. `--no-color` strips everything for piping.

## Web

Four theme dots sit top-right in the header. Void is the default; the choice is
saved and survives reload. `Ctrl+Shift+T` cycles them.

## Adding a fifth theme

1. **Web** — copy a `[data-v="..."]` block in the `<style>` of `web.py`, change
   the palette, add a dot to `.theme-pick`, add the name to `THEMES` in the
   script at the bottom.
2. **Terminal** — add an entry to `THEMES` in `kumo.py`. Nothing else; every
   renderer reads its colours through the `C` class.


## Vuln scan — new unauthenticated access rules

The rule set went from **335 to 358** effective checks. 23 new
*unauthenticated / anonymous access* rules were ported from nuclei templates
added during 2025 and 2026.

WordPress `readme.txt` version probes were excluded deliberately: they are
version disclosure rather than access, and they fire on nearly every WordPress
site.

### Added

| Severity | Added | ID | Check | Probe path |
|---|---|---|---|---|
| `critical` | 2025-09-24 | `CVE-2024-40711` | Veeam Backup & Replication - Unauthenticated | `/api/v1/serverinfo` |
| `critical` | 2026-03-25 | `CVE-2026-21445` | Langflow - Broken Access Control | `/api/v1/monitor/messages` |
| `critical` | 2026-05-11 | `CVE-2026-42281` | MagicMirror <= 2.35.0 - Server-Side Request Forgery | `/cors?url=http://127.0.0.1:8080/version` |
| `critical` | 2026-05-18 | `CVE-2025-49001` | DataEase < 2.10.10 - JWT Authentication Bypass | `/de2api/user/info` |
| `critical` | 2026-08-08 | `CVE-2026-67208` | Juggle <= 1.6.0 - Unauthenticated Exposed H2 Database Console | `/h2-console/` |
| `critical` | 2026-08-10 | `CVE-2026-59774` | Gitea 1.22.1-1.27.0 - Unauthenticated Arbitrary File Read | `/api/v1/repos/search?limit=1` |
| `critical` | 2026-09-10 | `CVE-2026-18072` | Advanced Responsive Video Embedder 10.8.7/10.8.8 - Hardcoded B | `/?_wplogin=35fe7057ffed92ff7bc5a0b90f302a77fb5843ad6c972294d68da0b0553b3900` |
| `high` | 2025-07-08 | `CVE-2023-49230` | Peplink Balance Two before 8.4.0 - Unauthenticated Config Uplo | `/cgi-bin/MANGA/index.cgi` |
| `high` | 2025-11-19 | `CVE-2025-55523` | Agent-Zero 0.8.0 - 0.9.4 - Arbitrary File Download | `/download_work_dir_file?path=/etc/passwd` |
| `high` | 2026-02-09 | `CVE-2025-1232` | Site Reviews < 7.2.5 - Unauthenticated Stored XSS | `/wp-json/wp/v2/pages?per_page=100` |
| `high` | 2026-03-31 | `CVE-2026-4020` | Gravity SMTP WordPress Plugin - Sensitive Information Exposure | `/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings` |
| `high` | 2026-09-16 | `http-etcd-unauthenticated-raft` | etcd RAFT Unauthenticated API | `/members` |
| `medium` | 2025-02-11 | `CVE-2024-45591` | XWiki Platform - Unauthorized Document History Access | `/xwiki/rest/wikis/xwiki/spaces/Main/pages/WebHome/history` |
| `medium` | 2025-03-11 | `CVE-2024-54764` | ipTIME A2004 - Unauthorized Access | `/login/hostinfo2.cgi` |
| `medium` | 2025-03-26 | `CVE-2024-30570` | Netgear R6850 - Information Disclosure | `/debuginfo.htm` |
| `medium` | 2025-04-05 | `CVE-2024-13126` | WordPress Download Manager < 3.3.07 - Unauthenticated Data Exp | `/wp-content/uploads/download-manager-files/` |
| `medium` | 2026-04-07 | `CVE-2026-29066` | TinaCMS - Path Traversal | `/etc/passwd` |
| `medium` | 2026-04-23 | `CVE-2025-58226` | WordPress 3D FlipBook Plugin <= 1.16.17 - Sensitive Informatio | `/wp-admin/admin-ajax.php?action=fb3d_send_posts` |
| `medium` | 2026-08-08 | `CVE-2026-27796` | Homarr < 1.54.0 - Information Disclosure | `/api/trpc/integration.all` |
| `medium` | 2026-08-09 | `CVE-2026-6826` | Concrete CMS <9.5.1 - Unauthenticated File Usage Disclosure | `/ccm/system/dialogs/file/usage/1` |
| `medium` | 2026-08-15 | `CVE-2026-8236` | Concrete CMS <9.5.1 - Unauthenticated File-Usage Internal Meta | `/index.php/ccm/system/dialogs/file/usage/1` |
| `medium` | 2026-08-15 | `CVE-2026-0717` | LottieFiles for Gutenberg <= 3.0.0 - Unauthenticated Settings  | `/wp-json/lottiefiles/v1/settings/` |
| `medium` | 2026-09-11 | `CVE-2026-13153` | Essential Blocks < 6.4.0 - Information Disclosure | `/wp-json/essential-blocks/v1/products?per_page=20` |

### Re-running the import

```bash
git clone --filter=blob:none https://github.com/projectdiscovery/nuclei-templates
python3 mine_unauth.py --nuclei ./nuclei-templates --since 2025-01-01
python3 validate_rules.py
```

`mine_unauth.py` is the same pipeline as `mine_templates.py` -> `gen_rules.py`,
narrowed to one family and one time window. It skips anything already covered
by an existing rule id or probe path, keeps only GET-only single-path templates
with real word evidence, and drops the WordPress readme probes. The first run
walks the template history to date each file and caches the result in
`.nuclei-added-dates.json` (gitignored).

Every rule still pairs a status matcher with an evidence matcher under
`matchers_condition: and`, and passes `validate_rules.py`'s decoy suite — one
candidate (`hashicorp-consul-unauth`) was rejected for firing on the
marketing-homepage decoy.
