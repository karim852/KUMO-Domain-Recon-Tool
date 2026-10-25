# Kumo — themed build

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

Full inventory: [`docs/RULES.md`](docs/RULES.md).

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
