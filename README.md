<p align="center">
  <img src="docs/banner.jpg" alt="KUMO 蜘蛛 — Domain OSINT & Reconnaissance" width="100%">
</p>

<p align="center">
<img src="https://img.shields.io/badge/Python-3.8+-3b82f6?style=flat-square&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Modules-27-22c55e?style=flat-square">
<img src="https://img.shields.io/badge/Vuln_checks-358-ef4444?style=flat-square">
<img src="https://img.shields.io/badge/Themes-4-a855f7?style=flat-square">
<img src="https://img.shields.io/badge/API_Key-Not_required-22c55e?style=flat-square">
<img src="https://img.shields.io/badge/Interface-CLI_+_Web-0ea5e9?style=flat-square">
<img src="https://img.shields.io/badge/License-MIT-6b7280?style=flat-square">
<a href="https://ko-fi.com/k0r1m"><img src="https://img.shields.io/badge/Ko--fi-Support-FF5E5B?style=flat-square&logo=kofi&logoColor=white"></a>
</p>

---

Give Kumo a domain and it maps everything reachable about it in one pass:
**DNS and email security**, **certificates and subdomains** from CT logs,
**open ports**, **technology fingerprints**, **leaked credentials** and
infostealer infections, **cloud buckets**, and **358 vulnerability checks**
against known exposures. Twenty-seven modules run in parallel, each one
streaming its own card the moment it lands — in the terminal or in the browser.

No API key is required for any of it.

```bash
pip install flask requests dnspython urllib3

python3 kumo.py                    # home screen — pick modules by number
python3 kumo.py --web              # web dashboard → http://127.0.0.1:8888
python3 kumo.py example.com        # straight to a full scan
```

<p align="center">
  <img src="docs/dashboard.jpg" alt="Kumo web dashboard" width="100%">
  <br><sub>The dashboard mid-scan: cards stream in as each module finishes,
  glowing by severity, with the vulnerability scanner leading on findings.</sub>
</p>

---

## 📑 Table of contents

- [Installation](#-installation)
- [Running your first scan](#-running-your-first-scan)
- [The terminal](#-the-terminal)
- [The dashboard](#-the-dashboard)
- [Themes](#-themes)
- [Vulnerability scanner](#-vulnerability-scanner)
- [Modules](#-modules)
- [Optional API keys](#-optional-api-keys)
- [CLI reference](#-cli-reference)
- [Tests](#-tests)
- [Credits](#-credits)
- [Ecosystem](#-ecosystem)

---

## 📦 Installation

### Requirements

| | |
|---|---|
| OS | Linux, macOS or Windows |
| Python | 3.8+ |
| Rights | none — Kumo never needs root |
| API keys | none required |

### Install

```bash
git clone https://github.com/karim852/KUMO-Domain-Recon-Tool
cd KUMO-Domain-Recon-Tool
pip install flask requests dnspython urllib3
```

Optional extras, each used by a single module and skipped cleanly when absent:

```bash
pip install brotli zstandard playwright
```

> **Nothing to configure.** There is no config file, no key file and no
> database. Kumo reads what it needs from public sources at run time.

---

## 🚀 Running your first scan

### Step 1 — Open the home screen

```bash
python3 kumo.py
```

With no target, Kumo opens its home screen: every module numbered and grouped,
with the web interface on top.

<p align="center">
  <img src="docs/cli-home.jpg" alt="Kumo CLI home screen" width="100%">
</p>

### Step 2 — Choose what to run

| Input | Runs |
|---|---|
| `1 4 12` | just those modules |
| `a` | all 27 |
| `f` | fast scan — skips the slow modules |
| `w` | the web dashboard |
| `q` | quit |

Then enter the domain when prompted. Or skip the menu entirely:

```bash
python3 kumo.py example.com -m dns ssl nuclei
```

### Step 3 — Watch the spider work

Modules run in parallel, so results do not arrive in order. A spider crawls the
strand while they run, spinning silk behind it as each one lands, with the
modules still in flight trailing the counter.

<p align="center">
  <img src="docs/cli-scan.jpg" alt="Kumo scanning" width="100%">
</p>

### Step 4 — Export

```bash
python3 kumo.py example.com -o report.json
```

---

## 🖥️ The terminal

The terminal is not a fallback — every module renders in full, with its own
layout, tables and severity colouring.

| | |
|---|---|
| Home screen | all modules numbered, grouped, sized to the terminal |
| Selection | by number, or `a` / `f` / `w` |
| Progress | spider crawl with live counter and in-flight module names |
| Themes | four palettes in 24-bit colour, `--theme` or `KUMO_THEME` |
| Piping | `--no-color` strips every escape sequence |

The module menu is generated from the module registry itself, so anything
registered always appears — a new module cannot silently go missing from the
list.

---

## 🌐 The dashboard

```bash
python3 kumo.py --web             # → http://127.0.0.1:8888
python3 kumo.py --web -p 9000     # custom port
```

The dashboard streams over SSE. Each module gets a card that appears
immediately, shows a rotating edge while it is still running, then fills and
takes on the colour of what it found — red for critical, amber for warnings,
green for clean.

| | |
|---|---|
| Streaming | cards arrive as modules finish, no waiting for the slowest |
| Severity glow | card colour is derived from the badges it renders |
| Module pills | click to enable or disable before scanning |
| Export | JSON, or a standalone HTML report |
| Themes | four, switchable live, remembered across reloads |

---

## 🎨 Themes

Four palettes, in both the dashboard and the terminal. Click a dot in the
header, or press <kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>T</kbd> to cycle. The
choice is saved and survives a reload.

<p align="center">
  <img src="docs/themes.jpg" alt="Kumo themes" width="100%">
</p>

| Theme | Character |
|---|---|
| **Void** *(default)* | deepest navy, cyan bloom, flat surfaces |
| **Void Glass** | lit card edges, under-glow, larger radius |
| **Web 蜘蛛** | violet accent, strongest glow |
| **Carbon** | neutral surfaces, restrained glow — best for client screenshots |

In the terminal:

```bash
python3 kumo.py --theme carbon example.com
export KUMO_THEME=web
```

Adding a fifth theme is one palette block plus one dot — every renderer reads
its colours through the same token set.

---

## 🔓 Vulnerability scanner

**358 checks**, no external tool and no template directory to sync. The engine
mirrors nuclei's matcher model — `status`, `word`, `regex`, `size` and a small
`dsl`, combined with `matchers_condition`.

<p align="center">
  <img src="docs/vuln-card.jpg" alt="Kumo vulnerability scanner card" width="82%">
</p>

| | |
|---|---|
| Hand-written rules | 30 |
| Ported from nuclei-templates | 328 |
| Severity split | 30 critical · 142 high · 130 medium · 56 low |
| Concurrency | 25 workers — 358 checks cost about four seconds at 250 ms RTT |

### Why it does not cry wolf

A rule is never allowed to fire on a status code alone. Every rule pairs
**product identification** with **vulnerability evidence** under
`matchers_condition: and`, and on top of that the engine suppresses:

- catch-all servers and WAF baselines
- soft-404 pages that answer 200 for anything
- pages that merely echo the requested path back in the title
- the site's own brand appearing in an unrelated page
- cloud buckets returning 403 — only a 200 counts as public

Every rule is validated against a decoy suite before shipping. Any rule that
fires on a soft-404, a WAF block page, a marketing homepage, an empty 200, a
JSON error or a generic login form is discarded rather than shipped.

### Staying current

```bash
git clone --filter=blob:none https://github.com/projectdiscovery/nuclei-templates
python3 mine_unauth.py --nuclei ./nuclei-templates --since 2025-01-01
python3 validate_rules.py
```

`mine_unauth.py` pulls recently-added unauthenticated-access templates, skips
anything already covered, keeps only those with real matcher evidence, and runs
the survivors through the decoy suite.

---

## 🧩 Modules

**27 modules**, all running in parallel. Pick them by number on the home screen, or by name with `-m`.

### Network & Infrastructure

| # | Module | Name | What it does |
|---|---|---|---|
| 1 | DNS & Email Security | `dns` | DNS Records + Email Security |
| 2 | IP Geolocation & ASN | `geo` | IP Geolocation & ASN |
| 3 | WHOIS / RDAP | `whois` | WHOIS / RDAP Registration |
| 4 | SSL/TLS Certificate | `ssl` | SSL/TLS Certificate |
| 5 | Port Scan & Banners | `ports` | Port Scan (70+ ports + banners) |
| 6 | Subdomain Discovery | `subdomains` | Subdomain Discovery |
| 7 | Subdomain Brute Force | `brute` | Subdomain Brute Force |
| 8 | Favicon Fingerprint | `favicon` | Favicon Hash Fingerprinting |

### Web Application Analysis

| # | Module | Name | What it does |
|---|---|---|---|
| 9 | Website Screenshot | `screenshot` | Website Screenshot |
| 10 | Tech Stack Detection | `whatweb` | WhatWeb Deep Tech Detection |
| 11 | Robots & Sitemap | `robots` | Robots/Security/Sitemap |
| 12 | Wayback Archives | `wayback` | Wayback Machine Archives |
| 13 | Content Intel | `content_intel` | Content Intel (JS/HTML URL & info extractor) |
| 14 | HTTP Inspector | `http_inspect` | HTTP Inspector (request/response headers) |
| 15 | API Endpoint Fuzzer | `api_fuzzer` | API Endpoint Fuzzer |
| 16 | JS Secret Scanner | `js_secrets` | JS Secret Scanner |
| 17 | Sensitive Endpoints | `endpoints` | Sensitive Endpoints (80+ paths) |

### Security & Threat Intelligence

| # | Module | Name | What it does |
|---|---|---|---|
| 18 | HTTP Security Headers | `headers` | HTTP Security Headers |
| 19 | WAF Detection | `wafw00f` | WAF Detection |
| 20 | Vulnerability Scanner | `nuclei` | Vulnerability Scanner (358 checks) |
| 21 | Shodan InternetDB | `shodan` | Shodan InternetDB + CVEs |
| 22 | Censys Hosts & Certs | `censys` | Censys Hosts + Certificates |
| 23 | Breach Intelligence | `breachintel` | Breach & Credential Intelligence |
| 24 | Email Harvester | `email_harvest` | Email Harvester (open-source, no key) |
| 25 | Cloud Bucket Finder | `cloud_buckets` | Cloud Bucket Finder (S3/Azure/GCP) |
| 26 | Google Dorks | `dorks` | Google Dorks (61) |
| 27 | OSINT Platform URLs | `osint` | OSINT Platform URLs (26) |

Each module is documented in full below, with real output.

---

### 🖼️ Screenshot — Website overview

Takes a live screenshot of the target and runs it against the **ransomware.live** feed. Pulls the page title, meta description, favicon, CMS fingerprint, and checks whether the domain appears in any ransomware gang's leak posts.

```
  URL         https://corp.com
  Title       Corp — Enterprise Solutions
  CMS         WordPress 6.4
  Favicon     ✓ found

  ☠ RANSOMWARE FEED
  ✓ No mentions found on ransomware.live
```

---

### 📡 DNS — Records + email security

Full DNS enumeration with a security grade on email protection. Detects missing DMARC, weak SPF policies, absent DKIM, and open zone transfers.

<p align="center"><img src="docs/mod-dns.jpg" alt="dns" width="88%"></p>
```
  A         203.0.113.10
  MX        mail.corp.com  (priority 10)
  NS        ns1.corp.com · ns2.corp.com
  TXT       v=spf1 include:_spf.google.com ~all

  EMAIL SECURITY
  DMARC     ✗ Missing — anyone can spoof @corp.com
  SPF       ⚠ Soft fail (~all) — not enforced
  DKIM      ✗ No selector found
```

---

### 📍 Geolocation — IP + ASN

Resolves the domain to IPv4/IPv6, geolocates each IP, and pulls ASN, ISP, and organization data.

<p align="center"><img src="docs/mod-geo.jpg" alt="geo" width="88%"></p>
```
  IP         203.0.113.10
  Country    🇺🇸 United States
  City       Ashburn, Virginia
  ASN        AS14618 — Amazon.com Inc.
  ISP        Amazon Web Services
```

---

### 🌐 WHOIS / RDAP — Registration data

Full registrar record including creation date, expiry, registrant info, and nameservers. Detects domains expiring soon and privacy-protected registrations.

<p align="center"><img src="docs/mod-whois.jpg" alt="whois" width="88%"></p>
```
  Registrar    GoDaddy LLC
  Created      2010-03-14
  Expires      2026-03-14  ← 337 days left
  Updated      2024-11-01
  Status       clientTransferProhibited
  Name servers ns1.corp.com · ns2.corp.com
```

---

### 🔒 SSL/TLS — Certificate analysis

Inspects the full certificate chain — issuer, expiry, Subject Alternative Names, cipher suite, and protocol version. Flags expired, self-signed, or misconfigured certificates.

<p align="center"><img src="docs/mod-ssl.jpg" alt="ssl" width="88%"></p>
```
  Subject     corp.com
  Issuer      Let's Encrypt — R11
  Valid from  2025-01-10
  Expires     2025-04-10  ← 89 days left
  SANs        corp.com · www.corp.com · api.corp.com · mail.corp.com
  Protocol    TLSv1.3  ✓
  Cipher      TLS_AES_256_GCM_SHA384  ✓
```

---

### 🛡️ HTTP Headers — Security grade

Checks every security-relevant response header and grades the configuration. Flags missing headers that leave the site open to XSS, clickjacking, MIME sniffing, and information disclosure.

<p align="center"><img src="docs/mod-headers.jpg" alt="headers" width="88%"></p>
```
  Grade   C

  ✗ Content-Security-Policy    missing — XSS risk
  ✗ X-Frame-Options            missing — clickjacking risk
  ✓ X-Content-Type-Options     nosniff
  ✗ Strict-Transport-Security  missing — HSTS not enforced
  ✗ Permissions-Policy         missing
  ✓ Referrer-Policy            no-referrer-when-downgrade
  ℹ Server                     nginx/1.24.0  ← version exposed
  ℹ X-Powered-By               PHP/8.1.2    ← stack disclosed
```

---

### 🧱 WAF Detection

Fingerprints the WAF or CDN sitting in front of the target using 40+ signatures — headers, cookies, server banners, and active probe responses. If nothing is detected, it says so clearly.

<p align="center"><img src="docs/mod-wafw00f.jpg" alt="wafw00f" width="88%"></p>
```
  Source   Python fingerprinter (40+ signatures)

  ✓ Probably no WAF/CDN detected
  Based on header, cookie and active probe analysis.
  Note: absence of WAF signatures does not guarantee no protection.
```

Or when detected:

```
  [HIGH]   Cloudflare
           cf-ray header · __cfduid cookie · CF-Cache-Status

  [LOW]    Akamai
           X-Check-Cacheable header
```

---

### 🚪 Port Scan — 70+ ports + banners

Scans 70+ common ports and grabs service banners for each open one. **False-positive hardened**: the host is first probed on random unused ports — if it answers those too (tarpit, transparent proxy, or firewall that accepts everything), only ports with real application-layer evidence (a service banner, a TLS handshake, or a valid HTTP reply) are reported. Every open port is also re-verified before being listed. Enriched with data from Shodan and Censys when available.

<p align="center"><img src="docs/mod-ports.jpg" alt="ports" width="88%"></p>
```
  PORT     STATE    SERVICE     BANNER
  22/tcp   open     SSH         OpenSSH 8.9p1 Ubuntu
  80/tcp   open     HTTP        nginx/1.24.0
  443/tcp  open     HTTPS       nginx/1.24.0
  3306/tcp open     MySQL       5.7.42-log ← exposed to internet
  6379/tcp open     Redis       PONG       ← no auth required
  8080/tcp open     HTTP        Apache Tomcat/9.0.80
```

---

### 🕵️ WhatWeb — Technology fingerprinting

Identifies the full tech stack — CMS, frameworks, JavaScript libraries, analytics, CDN, server, and more. Runs 80+ signature checks without sending a single intrusive request.

<p align="center"><img src="docs/mod-whatweb.jpg" alt="whatweb" width="88%"></p>
```
  CMS           WordPress 6.4.3
  Server        nginx 1.24.0
  PHP           8.1.2
  Framework     jQuery 3.6.0
  Analytics     Google Analytics · Hotjar
  CDN           Cloudflare
  Fonts         Google Fonts
  SSL           Let's Encrypt
```

---

### 🤖 Robots / Security — Crawl rules + disclosure

Parses `robots.txt` for disallowed and allowed paths, highlights sensitive ones, and checks for a `security.txt` vulnerability disclosure contact. Also discovers sitemaps.

<p align="center"><img src="docs/mod-robots.jpg" alt="robots" width="88%"></p>
```
  ✓ robots.txt found (23 rules)

  ⚠ SENSITIVE DISALLOWED PATHS
  /admin/
  /wp-admin/
  /config/
  /backup/
  /.git/

  ✓ ALLOWED PATHS
  /api/public/
  /sitemap.xml
  /Darklord

  ✗ No security.txt — no vulnerability disclosure contact
```

---

### 🔓 Sensitive Endpoint Discovery — 80+ known paths

Probes 80+ paths that are commonly left exposed: admin panels, backup files, config files, debug interfaces, API docs, source control, and infrastructure files. Every hit is severity-graded. A `403 Forbidden` response still confirms the path exists and is automatically downgraded one severity level.

<p align="center"><img src="docs/mod-endpoints.jpg" alt="endpoints" width="88%"></p>
```
  12 found / 80 probed   CRITICAL: 2  HIGH: 4  MEDIUM: 5  LOW: 1

  CRITICAL  /.env                      200  ← credentials exposed
  CRITICAL  /WEB-INF/web.xml           200  ← Java config leak
  HIGH      /wp-admin/                 200
  HIGH      /phpmyadmin/               200
  HIGH      /docker-compose.yml        200
  HIGH      /.git/HEAD                 200
  MEDIUM    /api/swagger.json          200
  MEDIUM    /actuator/env              200
  MEDIUM    /.git/config [403]         403  ← exists, access denied
  LOW       /.htaccess [403]           403
```

---

### 🔓 Vulnerability Scanner — 358 built-in checks

Pure Python, zero external tools. A **nuclei-style rule playbook of 358 rules** with real `matchers` / `matchers-condition: and`, each pairing *product identification* with *vulnerability evidence* — never a bare status code. 30 rules are hand-written; **328 are ported directly from the official [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) repository**, covering Drupal, Joomla, Magento, TYPO3, Sitecore, Umbraco, OpenCart, Confluence, SharePoint, Jira, Airflow, Jupyter, etcd, Consul, Keycloak, Rancher, Portainer, Artifactory, Zabbix, Nagios, Spring, Symfony, Django, Laravel, Tomcat, Redis, Elasticsearch, Kubernetes and Docker. Every ported rule is replayed against eight decoy responses (soft-404, WAF 403, marketing homepage, SPA shell, empty 200, JSON error, redirect, generic login) and discarded if it fires on any of them. Plus 150+ HTTP-based checks inspired by real Nuclei templates — covering known CVEs, CMS vulnerabilities, exposed admin panels, cloud metadata endpoints, CI/CD dashboards, CORS misconfigurations, and more. Every check is **catch-all / WAF aware**: a baseline is fingerprinted first, so the generic 403/404 page a host returns for every path is never reported as a finding. Raw-file checks (`.git`, `.env`, backups) require the *actual* file content, and 403 responses are downgraded — never reported as "exposed". **Soft-404 aware**: sites that answer unknown paths with HTTP 200 and a friendly "page not found" page (very common on e-commerce and SPAs) are detected and discarded, and the requested path is scrubbed from the response before product matching — so a URL echoed back in an error page or redirect can never be mistaken for the product itself.

<p align="center"><img src="docs/mod-nuclei.jpg" alt="nuclei" width="88%"></p>
```
  CRITICAL: 2   HIGH: 5   MEDIUM: 7

  CRITICAL  Log4Shell RCE (CVE-2021-44228)          200 — Confirmed
  CRITICAL  Laravel .env Exposed                    200 — Plaintext secrets
  HIGH      Git Repository Accessible               200
  HIGH      phpMyAdmin Public Access                200
  HIGH      Jenkins Dashboard (Unauthenticated)     200
  HIGH      AWS Keys in HTTP Response               200
  MEDIUM    Spring Boot Actuator /env               200
  MEDIUM    Grafana Default Credentials             200
```

Checks include: **Log4Shell · Spring4Shell · Drupalgeddon2 · Confluence OGNL · Oracle WebLogic · 15 WordPress plugin CVEs · CORS misconfiguration · Host header injection · Clickjacking** and many more.

**Recent CVE detection (2024–2026)** — a dedicated set of *detection-only* templates fingerprints exposure/version for the newest, actively-exploited CVEs (no exploitation, just correlation):

```
  RECENT CVE  cPanel / WHM Login Panel Exposed     CVE-2026-41940
  RECENT CVE  Next.js Middleware Auth Bypass       CVE-2025-29927
  RECENT CVE  SharePoint "ToolShell" RCE           CVE-2025-53770
  RECENT CVE  SAP NetWeaver Visual Composer        CVE-2025-31324
  RECENT CVE  Ivanti EPMM / Connect Secure         CVE-2025-4427
  RECENT CVE  CrushFTP Auth Bypass                 CVE-2025-31161
  ... 15 more (Fortinet · Palo Alto · Oracle EBS · Craft CMS · Vite · Langflow · Wazuh)
```

---

### 🔌 API Endpoint Fuzzer

Smart API discovery. Probes a random baseline first to detect catch-all servers, confirms a base API path actually exists before fuzzing, then discovers live endpoints and checks for **GraphQL introspection**. Every hit shows its HTTP status and response **byte size**.

<p align="center"><img src="docs/mod-api_fuzzer.jpg" alt="api_fuzzer" width="88%"></p>
```
  Base found   /api/v1
  GraphQL      /graphql — introspection enabled   [200]  1.2 KB

  API ENDPOINTS
  HIGH      /api/v1/users            200   8.9 KB
  HIGH      /api/v1/admin            401   512 B
  MEDIUM    /api/v1/config           200   2.1 KB
  MEDIUM    /api/swagger.json        200   14 KB
```

---

### 🔑 JS Secret Scanner

Pulls and scans first-party JavaScript for hardcoded secrets — API keys, tokens, cloud credentials, and private keys — with clear-text output and the exact source line for each hit.

<p align="center"><img src="docs/mod-js_secrets.jpg" alt="js_secrets" width="88%"></p>
```
  ⚠ Secrets Detected (clear text)

  CRITICAL  AWS Access Key      AKIA................   app.min.js
  HIGH      Google API Key      AIza................   main.js
  HIGH      Stripe Live Key     sk_live_.............  checkout.js
  MEDIUM    JWT Token           eyJhbGciOiJ.........   auth.js
```

---

### 🔎 HTTP Inspector — request/response headers

Your browser's DevTools *Network* tab, headless. Shows exactly what Kumo sent and exactly what came back — the full request headers, every response header verbatim, the complete redirect chain, cookie security flags, allowed HTTP methods, CORS behaviour, and any non-standard or leaky headers worth a second look.

<p align="center"><img src="docs/mod-http_inspect.jpg" alt="http_inspect" width="88%"></p>
```
Final URL   https://corp.com/
Status      200 OK          561 KB · 89 ms

↪ REDIRECT CHAIN (2 hops)
  1. [301] http://corp.com/        → https://corp.com/
  2. [200] https://corp.com/

▶ REQUEST HEADERS SENT (6)
  ▶ User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0
  ▶ Accept: text/html,application/xhtml+xml,...

◀ RESPONSE HEADERS RECEIVED (19)
  ◀ server: nginx/1.24.0
  ◀ strict-transport-security: max-age=31536000
  ◀ set-cookie: session=abc123; Path=/

⚠ NOTABLE HEADERS (3)
  [Backend stack disclosed]      x-powered-by: PHP/8.1.2
  [Internal backend leaked]      x-backend-server: web03.internal
  [Symfony profiler exposed]     x-debug-token-link: /_profiler/a1b2c3

🍪 COOKIES (2)
  NAME       SECURE  HTTPONLY  SAMESITE  ISSUES
  session    yes     yes       Lax       -
  tracking   NO      NO        -         no Secure, no HttpOnly, no SameSite

Allowed methods: GET POST OPTIONS PUT DELETE   ← PUT/DELETE risky
CORS Allow-Origin: *   ← Wildcard origin allowed
```

---

### 🧠 Content Intelligence — JS/HTML extraction

Scrapes the homepage HTML, inline scripts, and every first-party JS file, then extracts the **valuable** signal — not just secrets. Endpoints, internal/external URLs, API routes, **database connection URIs**, cloud storage (S3 / GCS / Azure / Firebase), emails, internal hosts, JWTs, private keys, source maps, and risky code comments. Static assets (`.css`, `.js`, images, fonts) and documentation domains (MDN, W3C) are filtered out; external URLs are collapsed to unique third-party hosts.

<p align="center"><img src="docs/mod-content_intel.jpg" alt="content_intel" width="88%"></p>
```
  166 items extracted   ·   14 JS files   ·   3 inline

  🗄️ DATABASE URIS
     mongodb+srv://svc:****@cluster0.abcd.mongodb.net/prod
  ☁️ CLOUD STORAGE
     [AWS S3]  assets-prod.s3.amazonaws.com
  🔌 API ENDPOINTS (12)
     /api/v1/users   ·   /api/internal/config   ·   /graphql
  🔐 SENSITIVE INFO (21)
     [Credential-like assignment]  api_key = 7f3c9a12de...
     [JWT token]                   eyJhbGciOiJIUzI1NiIs...
     [Risky code comment]          // TODO: remove hardcoded admin creds
  🌐 EXTERNAL SOURCES (19 unique hosts)
     cdn.thirdparty.com · api.stripe.com · fonts.googleapis.com ...
```

---

### 🎯 Favicon Hash — tech fingerprint

Fetches the favicon (HTML-declared first, then common paths in parallel — bounded so it never hangs), computes the **MMH3 hash** used by Shodan/Censys, and maps known hashes to technologies. Handy for fingerprinting the stack and pivoting to other hosts running the same favicon.

<p align="center"><img src="docs/mod-favicon.jpg" alt="favicon" width="88%"></p>
```
  Favicon     https://corp.com/favicon.ico   (33.2 KB)
  MMH3 hash   -1319625119
  Shodan      http.favicon.hash:-1319625119
  Match       GitLab
```

---

### ☁️ Cloud Storage Buckets

Enumerates likely **AWS S3 / GCP / Azure** bucket names derived from the domain and checks for public exposure. Only a confirmed **HTTP 200 (publicly readable)** is reported — unreliable 403 responses are never flagged as findings.

<p align="center"><img src="docs/mod-cloud_buckets.jpg" alt="cloud_buckets" width="88%"></p>
```
  Checked   42 candidate buckets

  PUBLIC   corp-backups.s3.amazonaws.com          200  ← readable
  PUBLIC   corp-assets.storage.googleapis.com     200
```

---

### 🔭 Shodan — InternetDB + CVE enrichment

Queries Shodan InternetDB (free, no key) for open ports, CPEs, hostnames, and CVEs. Every CVE is enriched with CVSS score, severity, KEV flag, and description via Shodan's free CVEDB API.

<p align="center"><img src="docs/mod-shodan.jpg" alt="shodan" width="88%"></p>
```
  Source   InternetDB (free, no key)
  Ports    22, 80, 443, 3306, 6379, 8080
  CVEs     4

  CVE-2021-44228   CVSS 10.0   CRITICAL   [KEV]   EPSS 0.9741
  Remote code execution via JNDI lookup in Log4j 2.x

  CVE-2022-26134   CVSS 9.8    CRITICAL   [KEV]   EPSS 0.9689
  Confluence Server OGNL injection — unauthenticated RCE

  CVE-2021-26084   CVSS 9.8    CRITICAL   [KEV]
  Confluence Server pre-auth remote code execution
```

---

### 🔬 Censys — Hosts + certificates

Pulls host data and certificate intelligence from Censys. Enriched with optional API key for full results.

<p align="center"><img src="docs/mod-censys.jpg" alt="censys" width="88%"></p>
```
  IPs      203.0.113.10 · 203.0.113.11
  Certs    14 certificates found in CT logs

  CERT     corp.com  (valid)      → Let's Encrypt  exp. 2025-04-10
  CERT     dev.corp.com  (valid)  → Let's Encrypt  exp. 2025-03-22
  CERT     old.corp.com  (expired)→ DigiCert       exp. 2022-08-01 ⚠
```

---

### 🗺️ Subdomain Discovery — 4 passive sources + CT logs

Queries **crt.sh**, **HackerTarget**, **RapidDNS**, and **AlienVault OTX** simultaneously, cross-references with Certificate Transparency logs, resolves every result, checks if it's alive, and flags anything that looks sensitive.

<p align="center"><img src="docs/mod-subdomains.jpg" alt="subdomains" width="88%"></p>
```
  Total found   52    Alive   34    ⚠ Sensitive   8

  SUBDOMAIN               IP                FLAG
  admin.corp.com          203.0.113.10      ⚠ SENSITIVE
  dev.corp.com            203.0.113.24      ⚠ SENSITIVE
  staging.corp.com        203.0.113.31      ⚠ SENSITIVE
  intranet.corp.com       203.0.113.45      ⚠ SENSITIVE
  vpn.corp.com            203.0.113.88      ⚠ SENSITIVE
  api.corp.com            203.0.113.55
  mail.corp.com           203.0.113.12
  shop.corp.com           203.0.113.78
  cdn.corp.com            203.0.113.92
  ...
```

---

### 🔨 Subdomain Brute Force

Tests thousands of common subdomain names via DNS with wildcard detection — eliminates false positives automatically. Finds subdomains that passive sources miss entirely.

<p align="center"><img src="docs/mod-brute.jpg" alt="brute" width="88%"></p>
```
  Wordlist     5000 names
  Threads      50
  Wildcard     ✓ detected and filtered

  NEW (not in passive)
  backup.corp.com         203.0.113.101   ⚠ SENSITIVE
  jenkins.corp.com        203.0.113.102   ⚠ SENSITIVE
  vault.corp.com          203.0.113.103   ⚠ SENSITIVE
```

---

### 📚 Wayback Machine — Archive mining

Queries the Wayback Machine for archived snapshots of the target — mining old endpoints, forgotten login pages, exposed config files, and paths that no longer exist on the live site but reveal the attack surface history.

<p align="center"><img src="docs/mod-wayback.jpg" alt="wayback" width="88%"></p>
```
  Snapshots    2,847
  Date range   2011-03-14 → 2025-01-09

  INTERESTING ARCHIVED PATHS
  /admin/old-login.php           (2019-08-22)
  /config/database.yml           (2021-03-10)
  /api/v1/debug/                 (2022-06-18)
  /backup/db_export_2020.sql     (2020-11-05)  ← backup exposed
  /.env.backup                   (2023-01-14)  ← secrets
```

---

### 💀 Breach & Credential Intelligence — 5 sources

Aggregates from **5 free sources** and runs an automatic per-email stealer check against Hudson Rock's database — showing which employee machines were infected, what malware ran, what passwords were stolen, and which services were compromised.

<p align="center"><img src="docs/mod-breachintel.jpg" alt="breachintel" width="88%"></p>
```
  ┌────────────────┬──────────────┬──────────────┬─────────────┐
  │     8024       │      12      │     183      │      6      │
  │  INFOSTEALER   │  EMPLOYEES   │   CLIENTS    │   EMAILS    │
  └────────────────┴──────────────┴──────────────┴─────────────┘

⚠ CRITICAL FINDINGS
  [hudsonrock] employees_infected_infostealer
               3 employee machines infected — last: 2025-03-14
  [hudsonrock] stealer_family_identified
               Primary malware: RedLine (3100 infections)
  [chiasmodon] employee_plaintext_password
               john@corp.com — pass: S3cr*** (2024-08-11)
  [proxynova]  comb_credentials_found
               183 unique emails with plaintext passwords

HUDSON ROCK CAVALIER
  Employees 3 · Clients 8017 · 3rd Parties 21 · Records 8041
  Malware: RedLine: 3100 · Lumma: 1540 · Raccoon: 892 · StealC: 401
  Last employee hit: 2025-03-14

CHIASMODON (pages 1+2)
  EMAIL                PASSWORD     DATE
  john@corp.com        S3c•••••    2024-08-11
  admin@corp.com       adm•••••    2024-11-02
  dev@corp.com         d3v•••••    2024-07-28

PROXYNOVA COMB (3.2B credentials)
  Records 247 · Emails 38
  billing@corp.com    bil*****   (len 11)
  info@corp.com       inf****    (len 8)

HAVEIBEENPWNED
  ✓ No domain breaches found (972 indexed)

☠ STEALER CHECK  (per-email · 9 infected / 20 checked)
  john@corp.com                                  ☠ INFECTED
  📅 2025-01-12   💻 JOHN-PC   🖥 Windows 10 Pro x64
  🦠 C:\Users\john\AppData\Roaming\update\svc.exe
  🔑 Passwords: S3cr***0 · c0rp***y · J0hn***!
  🏢 4 corp services stolen · 👤 89 personal
```

---

### 📧 Email Harvester

Discovers `@domain` employee email addresses across multiple open sources, then merges in every confirmed email found during the breach intelligence scan.

<p align="center"><img src="docs/mod-email_harvest.jpg" alt="email_harvest" width="88%"></p>
```
  Confirmed   7    Patterns   20
  Sources: crt.sh · web scraping · whois · DNS SOA · wayback

  📧 CONFIRMED EMAILS
  john@corp.com
  admin@corp.com
  dev@corp.com
  support@corp.com
  billing@corp.com

  💡 COMMON PATTERNS (may exist)
  info@corp.com  contact@corp.com  security@corp.com  hr@corp.com ...
```

Sources: **Hunter.io** · **crt.sh** certificate logs · web page scraping (contact / about / team) · **DNS SOA** record · **WHOIS** contact · **Wayback Machine** archive · common business prefixes.

---

### 🔍 Google Dorks — 61 queries

Generates 61 targeted Google dork queries pre-built for the domain — one click opens them in Google. Covers exposed files, login pages, sensitive directories, subdomains, cached pages, code repositories, and more.

```
  FILE EXPOSURE
  site:corp.com filetype:pdf
  site:corp.com filetype:xlsx OR filetype:csv
  site:corp.com filetype:sql OR filetype:bak
  site:corp.com ext:env OR ext:config OR ext:yaml

  LOGIN & ADMIN
  site:corp.com inurl:login OR inurl:admin OR inurl:dashboard
  site:corp.com inurl:wp-admin

  SENSITIVE CONTENT
  site:corp.com intext:"password" OR intext:"api_key"
  site:corp.com intext:"BEGIN RSA PRIVATE KEY"

  SUBDOMAINS & INFRA
  site:*.corp.com -www
  site:corp.com inurl:dev OR inurl:staging OR inurl:test

  ... 51 more queries across 8 categories
```

---

### 🔗 OSINT Platform Links — 26 sources

Pre-generates 26 investigation links for the target across the most useful OSINT platforms — one click and you're there.

```
  THREAT INTEL
  VirusTotal          https://virustotal.com/gui/domain/corp.com
  URLhaus             https://urlhaus.abuse.ch/browse/?search=corp.com
  Shodan              https://shodan.io/search?query=hostname:corp.com

  BREACH & LEAKS
  HaveIBeenPwned      https://haveibeenpwned.com/DomainSearch
  ProxyNova COMB      https://proxynova.com/tools/comb?query=@corp.com
  IntelX              https://intelx.io/?s=corp.com
  DeHashed            https://dehashed.com/search?query=corp.com
  LeakRadar           https://leakradar.io/search?q=corp.com
  HudsonRock          https://cavalier.hudsonrock.com/...

  RECON & MAPPING
  Shodan Maps         https://maps.shodan.io/#corp.com
  Censys              https://search.censys.io/search?q=corp.com
  Fofa                https://en.fofa.info/result?qbase64=...
  ZoomEye             https://zoomeye.org/searchResult?q=corp.com

  ... 13 more across threat intel, archive, and code search
```

---

---

## ⚙️ Optional API keys

Everything above works with no key at all. These only unlock richer data:

| Variable | Unlocks |
|---|---|
| `SHODAN_API_KEY` | full Shodan host data — banners, services, history |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | full Censys host & certificate search |
| `HIBP_API_KEY` | per-email HaveIBeenPwned lookup |
| `CHIASMODON_API_KEY` | Chiasmodon pro tier — more results |
| `RANSOMWARE_LIVE_API_KEY` | Ransomware.live pro feed |
| `GOOGLE_CSE_KEY` + `GOOGLE_CSE_ID` | execute the generated dorks live |

```bash
export SHODAN_API_KEY="your_key_here"
# read at run time — never written to disk
```

---

## 📟 CLI reference

```
python3 kumo.py                               home screen — pick modules by number
python3 kumo.py example.com                   full scan
python3 kumo.py example.com --fast            skip the slow modules
python3 kumo.py example.com -m dns ssl ports  specific modules only
python3 kumo.py example.com -o report.json    export to JSON
python3 kumo.py --web                         web dashboard (port 8888)
python3 kumo.py --web -p 9000                 custom port
python3 kumo.py --list-modules                every module, grouped
python3 kumo.py --theme carbon example.com    void · glass · web · carbon
python3 kumo.py example.com --no-spider       disable the crawl animation
python3 kumo.py example.com --no-color        pipe-friendly output
```

| Flag | Default |
|---|---|
| `--theme` | `void`, or `$KUMO_THEME` |
| `-p` / `--port` | `8888` |
| `--host` | `0.0.0.0` |

Fast mode skips: `wayback` · `brute` · `subdomains` · `screenshot` ·
`email_harvest` · `nuclei` · `cloud_buckets`

---

## 🧪 Tests

```bash
python3 test_rules.py      # every rule fires on its fixture and on no decoy
python3 test_modules.py    # every module returns cleanly inside its budget
python3 test_live.py       # end-to-end against a real domain
```

`test_rules.py` is the one that matters. It runs each vulnerability rule
against a vulnerable fixture *and* against seven decoys, and fails if a rule
either misses its target or fires on something harmless.

---

## 🙏 Credits

Kumo collects and correlates — the data belongs to the sources below, and they
deserve the star far more than this repo does:

| Source | Used for |
|---|---|
| [crt.sh](https://crt.sh) | certificate transparency logs, subdomain discovery |
| [Shodan InternetDB](https://internetdb.shodan.io) | open ports, CVEs, host tags — free, keyless |
| [Hudson Rock](https://hudsonrock.com) | infostealer infection intelligence |
| [ProjectDiscovery](https://github.com/projectdiscovery/nuclei-templates) | the templates behind most vulnerability rules |
| [Wayback Machine](https://web.archive.org) | archived URLs and historical surface |
| [RDAP](https://rdap.org) / regional registries | registration and ASN data |
| [HaveIBeenPwned](https://haveibeenpwned.com) | breach corpus |

Respect each source's own terms of use and rate limits.

---

## 🌐 Ecosystem

| | Tool | Domain |
|---|---|---|
| ☁️ | **Kumo** 蜘蛛 | domain OSINT & reconnaissance |
| 🌑 | [**Kage** 影](https://github.com/karim852/Kage-DFIR-toolkit) | DFIR host triage |

---

> ⚠️ **For authorized security testing only.**
> Only scan domains you own or have explicit written permission to test.
> Free to use, modify and share for educational and personal purposes — please
> credit the work. Commercial use requires explicit permission from the author.

<p align="center"><sub>Built for those who move fast. 蜘蛛</sub></p>
