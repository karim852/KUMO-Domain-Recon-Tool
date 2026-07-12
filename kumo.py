#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Kumo v2.0 — Domain OSINT & Reconnaissance Framework
Usage:
    python3 kumo.py example.com              CLI full scan
    python3 kumo.py example.com --fast        CLI fast scan
    python3 kumo.py example.com -m dns ssl    CLI specific modules
    python3 kumo.py --web                     Launch web UI
    python3 kumo.py --web -p 9000             Web UI on custom port
"""

import sys
import os
import json
import argparse
import textwrap
import time
from datetime import datetime, timezone

from engine import clean_domain, ALL_MODULES, FAST_SKIP, run_scan

# ═══════════════════════════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════════════════════════

class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"; M="\033[95m"
    CY="\033[96m"; W="\033[97m"; GR="\033[90m"; BD="\033[1m"; DM="\033[2m"
    UL="\033[4m"; RS="\033[0m"; BG_R="\033[41m"

    @classmethod
    def off(cls):
        for a in list(vars(cls)):
            if a.isupper() and not a.startswith("_"):
                setattr(cls, a, "")


# ═══════════════════════════════════════════════════════════════
# CLI DISPLAY
# ═══════════════════════════════════════════════════════════════

def banner():
    import platform
    os_name = platform.system() or "Unknown"
    print(f"""{C.B}{C.BD}
██╗  ██╗██╗   ██╗███╗   ███╗ ██████╗
██║ ██╔╝██║   ██║████╗ ████║██╔═══██╗
█████╔╝ ██║   ██║██╔████╔██║██║   ██║
██╔═██╗ ██║   ██║██║╚██╔╝██║██║   ██║
██║  ██╗╚██████╔╝██║ ╚═╝ ██║╚██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝{C.RS}
  {C.CY}{C.BD}Powered by Kumo Recon Engine{C.RS}        {C.GR}v2.0{C.RS}
  {C.M}{C.BD}蜘蛛{C.RS}  {C.GR}web recon · osint · breach intel{C.RS}
  {C.Y}OS:{C.RS} {C.W}{os_name}{C.RS}    {C.Y}Modules:{C.RS} {C.W}{len(ALL_MODULES)}{C.RS}    {C.Y}API Key:{C.RS} {C.G}not required{C.RS}
  {C.CY}🌐 github.com/karim852/KUMO{C.RS}   {C.GR}·  authorized security testing only{C.RS}
""")


def section(title, icon="►"):
    print(f"\n  {C.CY}{C.BD}{icon}  {title.upper()}{C.RS}")
    print(f"  {C.GR}{'─' * 60}{C.RS}")


def _box(title, rows, color=None):
    """Draw a clean framed box with a title and label/value rows."""
    color = color or C.CY
    width = 54
    inner = width - 2            # printable columns between the │ borders
    label_w = 10
    top = f"  {color}╭─ {C.BD}{title}{C.RS}{color} " + "─" * (inner - len(title) - 3) + "╮" + C.RS
    print(top)
    for label, value in rows:
        val = _strip_ansi(str(value))
        # content = 1 leading space + label field + value + pad  == inner
        pad = inner - 1 - label_w - len(val)
        if pad < 1:
            val = val[: inner - 1 - label_w - 1]
            pad = 1
        print(f"  {color}│{C.RS} {C.Y}{label:<{label_w}}{C.RS}{C.W}{val}{C.RS}{' ' * pad}{color}│{C.RS}")
    print(f"  {color}╰" + "─" * inner + f"╯{C.RS}")


def _strip_ansi(s):
    import re as _re
    return _re.sub(r'\033\[[0-9;]*m', '', str(s))


def _dwidth(s):
    """Approximate terminal display width (emoji/CJK count as 2 cells)."""
    w = 0
    for ch in _strip_ansi(s):
        o = ord(ch)
        w += 2 if (o >= 0x1100 and (o >= 0x2600 or 0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF
                   or 0xAC00 <= o <= 0xD7A3 or 0xF900 <= o <= 0xFAFF or 0xFE30 <= o <= 0xFE4F
                   or 0xFF00 <= o <= 0xFF60 or 0x1F000 <= o <= 0x1FAFF)) else 1
    return w


def _textbox(title, text, color=None, width=60):
    """Draw a bordered box with a title and wrapped body text (HeroMap-style)."""
    import textwrap as _tw
    color = color or C.CY
    inner = width - 2
    tw = _dwidth(title)
    print(f"  {color}╭─ {C.BD}{title}{C.RS}{color} " + "─" * max(1, inner - tw - 3) + "╮" + C.RS)
    for ln in _tw.wrap(text, inner - 2) or [""]:
        pad = inner - 1 - len(ln)
        print(f"  {color}│{C.RS} {C.W}{ln}{C.RS}{' ' * max(0, pad)}{color}│{C.RS}")
    print(f"  {color}╰" + "─" * inner + f"╯{C.RS}")


def _bar(pct, width=12, color=None):
    color = color or C.G
    filled = int(round(pct / 100 * width))
    return f"{color}{'█' * filled}{C.GR}{'░' * (width - filled)}{C.RS}"


TIPS = [
    "A 403 on /.git/config means the path is blocked, not exposed — Kumo won't flag it.",
    "Run --fast to skip the slow modules (vuln scan, subdomains, brute, cloud buckets).",
    "Content Intel pulls DB connection strings and API routes straight out of JS files.",
    "Favicon MMH3 hashes let you pivot to other hosts running the same stack on Shodan.",
    "Kumo never sends exploit payloads — recent-CVE checks only fingerprint exposure.",
    "Use -o report.json to save the full machine-readable results for later.",
    "The web UI (--web) streams all modules live and builds a shareable HTML report.",
    "Breach intel runs a per-email infostealer check against Hudson Rock automatically.",
    "External URLs in Content Intel are collapsed to unique hosts — your third-party map.",
    "Pass -m to run only what you need, e.g. -m dns ssl headers ports.",
]


def print_tip():
    import random
    _textbox("💡 RECON TIP", random.choice(TIPS), C.Y)


def _human_bytes_cli(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    if n < 1024:
        return f"{int(n)} B"
    if n < 1048576:
        return f"{n/1024:.1f} KB"
    return f"{n/1048576:.2f} MB"


def info(label, value, indent=4):
    print(f"{' '*indent}{C.Y}{label:<24}{C.RS}{C.W}{value}{C.RS}")


def ok(msg, indent=4):
    print(f"{' '*indent}{C.G}[✓]{C.RS} {msg}")


def warn(msg, indent=4):
    print(f"{' '*indent}{C.Y}[!]{C.RS} {msg}")


def fail(msg, indent=4):
    print(f"{' '*indent}{C.R}[✗]{C.RS} {msg}")


def status(msg, indent=4):
    print(f"{' '*indent}{C.B}[*]{C.RS} {msg}")


def dimprint(msg, indent=4):
    print(f"{' '*indent}{C.GR}{msg}{C.RS}")


def table_header(cols, widths):
    row = "    "
    for col, w in zip(cols, widths):
        row += f"{C.CY}{C.BD}{col:<{w}}{C.RS}"
    print(row)
    print(f"    {C.GR}{'─' * sum(widths)}{C.RS}")


def table_row(vals, widths, colors=None):
    row = "    "
    for i, (v, w) in enumerate(zip(vals, widths)):
        c = colors[i] if colors and i < len(colors) else C.W
        row += f"{c}{str(v):<{w}}{C.RS}"
    print(row)


# ═══════════════════════════════════════════════════════════════
# CLI RENDERERS — print scan results to terminal
# ═══════════════════════════════════════════════════════════════

def render_dns(data):
    section("DNS RECORDS", "📡")
    if data.get("ips"):
        for label, key in [("A (IPv4)", "v4"), ("AAAA (IPv6)", "v6")]:
            ips = data["ips"].get(key, [])
            if ips:
                for ip in ips:
                    info(label, ip)
    for rtype, vals in data.get("records", {}).items():
        print(f"\n    {C.M}{rtype}:{C.RS}")
        for v in vals:
            dimprint(v[:85], 6)
    es = data.get("email_security", {})
    print(f"\n    {C.M}Email Security:{C.RS}")
    spf = es.get("spf", {})
    (ok if spf.get("found") else fail)(f"SPF: {'Found '+spf.get('policy','') if spf.get('found') else 'Not found'}", 6)
    dmarc = es.get("dmarc", {})
    (ok if dmarc.get("found") else fail)(f"DMARC: {'Found '+dmarc.get('policy','') if dmarc.get('found') else 'Not found'}", 6)
    dkim = es.get("dkim", {})
    (ok if dkim.get("found") else warn)(f"DKIM: {'Found sel='+dkim.get('selector','') if dkim.get('found') else 'Not found'}", 6)


def render_whois(data):
    section("WHOIS / RDAP", "🌐")
    if data.get("error"):
        fail(data["error"]); return
    for key in ["domain", "registration", "expiration", "last_changed"]:
        if data.get(key):
            label = key.replace("_", " ").title()
            val = data[key]
            if key == "expiration" and data.get("days_until_expiry") is not None:
                val += f" ({data['days_until_expiry']} days)"
            info(label, val)
    if data.get("status"):
        info("Status", ", ".join(data["status"]))
    if data.get("nameservers"):
        info("Nameservers", ", ".join(data["nameservers"]))
    for e in data.get("entities", []):
        info(e["role"].title(), e["name"])


def render_ssl(data):
    section("SSL/TLS CERTIFICATE", "🔒")
    if data.get("error"):
        fail(data["error"]); return
    for key, label in [("common_name","CN"), ("issuer","Issuer"), ("valid_from","From"), ("valid_until","Until"), ("protocol","Protocol"), ("cipher","Cipher"), ("serial","Serial")]:
        if data.get(key):
            val = str(data[key])
            if key == "cipher" and data.get("cipher_bits"):
                val += f" ({data['cipher_bits']}-bit)"
            info(label, val)
    if data.get("days_left") is not None:
        d = data["days_left"]
        (fail if d < 0 else ok)(f"{'EXPIRED ' + str(abs(d)) + 'd ago' if d<0 else str(d)+' days remaining'}")
    if data.get("sans"):
        info("SANs", f"{len(data['sans'])} entries")
        for s in data["sans"]:
            dimprint(s, 6)


def render_crtsh(data):
    section("CERTIFICATE TRANSPARENCY", "📜")
    if data.get("error"):
        warn(data["error"]); return
    ok(f"{data.get('total',0)} unique subdomains")
    if data.get("sensitive"):
        print(f"\n    {C.M}Sensitive Subdomains:{C.RS}")
        for s in data["sensitive"]:
            warn(s, 6)
    if data.get("resolved"):
        print()
        table_header(["SUBDOMAIN", "IP", "STATUS"], [42, 18, 10])
        for r in data["resolved"]:
            table_row([r["subdomain"], r["ip"], "LIVE" if r["alive"] else "DEAD"], [42, 18, 10],
                      [C.W if r["alive"] else C.GR, C.GR, C.G if r["alive"] else C.R])


def render_headers(data):
    section("HTTP SECURITY HEADERS", "🛡️")
    if data.get("error"):
        fail(data["error"]); return
    info("Status", data.get("status_code"))
    info("Server", data.get("server"))
    info("Grade", f"{data.get('grade')} ({data.get('score',0):.0f}%)")
    print()
    for h in data.get("headers", []):
        sym = f"{C.G}✓ PASS{C.RS}" if h["present"] else f"{C.R}✗ FAIL{C.RS}"
        print(f"    {sym}  {C.W}{h['header']}{C.RS}")
        if h["present"]:
            dimprint(str(h["value"])[:70], 11)
        else:
            dimprint(h["description"], 11)
    if data.get("disclosure"):
        print(f"\n    {C.M}Info Disclosure:{C.RS}")
        for d in data["disclosure"]:
            warn(f"{d['header']}: {d['value']}", 6)


def render_ports(data):
    section("PORT SCAN", "🚪")
    open_ports = data.get("open", [])
    if not open_ports:
        warn("No open ports"); return
    print()
    table_header(["PORT", "SERVICE", "RISK"], [10, 16, 12])
    for p in open_ports:
        risk_color = {"critical": C.R, "high": C.Y, "medium": C.Y, "low": C.G}.get(p["risk"], C.W)
        table_row([p["port"], p["service"], p["risk"].upper()], [10, 16, 12], [C.W, C.CY, risk_color])
    risky = [p for p in open_ports if p["risk"] in ("critical", "high")]
    if risky:
        print(f"\n    {C.M}Alerts:{C.RS}")
        for p in risky:
            fail(f"Port {p['port']} ({p['service']}) — risk: {p['risk']}", 6)


def render_tech(data):
    section("TECHNOLOGY DETECTION", "⚙️")
    if data.get("error"):
        fail(data["error"]); return
    for cat, items in data.items():
        if isinstance(items, list):
            print(f"\n    {C.M}{cat}:{C.RS}")
            for item in items:
                info("•", item, 6)


def render_geo(data):
    section("IP GEOLOCATION & ASN", "📍")
    if data.get("error"):
        fail(data["error"]); return
    for key, label in [("ip","IP"),("hostname","Hostname"),("country","Country"),("region","Region"),
                        ("city","City"),("timezone","Timezone"),("isp","ISP"),("org","Organization"),("asn","ASN")]:
        if data.get(key):
            info(label, data[key])
    info("Type", "Hosting/DC" if data.get("is_hosting") else "ISP/Business")


def render_robots(data):
    section("ROBOTS.TXT / SECURITY.TXT", "🤖")
    if data.get("robots"):
        ok(f"robots.txt found ({data['robots']['count']} rules)")
        sensitive = [d for d in data["robots"].get("disallowed", []) if d.get("sensitive")]
        if sensitive:
            print(f"\n    {C.M}Interesting Paths:{C.RS}")
            for d in sensitive:
                warn(d["path"], 6)
    else:
        warn("No robots.txt")
    if data.get("security_txt"):
        ok(f"security.txt found at {data['security_txt']['path']}")
    else:
        warn("No security.txt")


def render_wayback(data):
    section("WAYBACK MACHINE", "📚")
    if data.get("snapshot"):
        info("Snapshot", data["snapshot"]["timestamp"])
    info("Range", data.get("range", "N/A"))
    info("URLs", data.get("total", 0))
    if data.get("interesting"):
        print(f"\n    {C.M}Interesting Paths:{C.RS}")
        for u in data["interesting"]:
            warn(u[:80], 6)


def render_brute(data):
    section("SUBDOMAIN BRUTE FORCE", "🔨")
    found = data.get("found", [])
    if not found:
        warn("No subdomains found"); return
    ok(f"{len(found)} subdomains discovered")
    print()
    table_header(["SUBDOMAIN", "IP"], [44, 18])
    for r in found:
        table_row([r["subdomain"], r["ip"]], [44, 18], [C.CY, C.W])


def render_subdomains(data):
    section("SUBDOMAIN SCANNER (4 SOURCES)", "🌐")
    sources_used = data.get("sources_used", [])
    sources_failed = data.get("sources_failed", [])
    ok(f"Sources used: {', '.join(sources_used) if sources_used else 'none'}")
    if sources_failed:
        warn(f"Sources failed: {', '.join(sources_failed)}")
    ok(f"{data.get('total', 0)} unique subdomains discovered")
    ok(f"{data.get('alive_count', 0)} alive")
    sensitive = data.get("sensitive", [])
    if sensitive:
        print(f"\n    {C.M}Sensitive Subdomains:{C.RS}")
        for s in sensitive:
            fail(f"{s['subdomain']}  ({s['ip']})", 6)
    resolved = data.get("resolved", [])
    alive = [r for r in resolved if r["alive"]]
    if alive:
        print()
        table_header(["SUBDOMAIN", "IP", "FLAG"], [44, 18, 12])
        for r in alive:
            flag = "⚠ SENSITIVE" if r.get("sensitive") else ""
            table_row([r["subdomain"], r["ip"], flag], [44, 18, 12],
                      [C.CY, C.W, C.Y if flag else C.GR])



def render_whatweb(data):
    section("WHATWEB TECH DETECTION", "🕵️")
    if data.get("error"):
        fail(data["error"]); return
    source = data.get("source", "")
    info("Source", "whatweb binary" if source == "whatweb_binary" else "Python fingerprinter")
    if data.get("url"):
        info("URL", data["url"])
    if data.get("status_code"):
        info("Status", data["status_code"])
    if source == "whatweb_binary":
        dimprint(data.get("raw", "")[:500], 4)
        detected = data.get("detected", [])
        if detected:
            print(f"\n    {C.M}Detected:{C.RS}")
            for item in detected[:40]:
                dimprint(f"• {item}", 6)
    else:
        detected = data.get("detected", {})
        total = data.get("total_detected", 0)
        info("Total detected", total)
        for cat, items in detected.items():
            print(f"\n    {C.M}{cat}:{C.RS}")
            for item in items:
                info("•", item, 6)


def render_nuclei(data):
    section("NUCLEI VULNERABILITY SCAN", "☢️")
    if not data.get("nuclei_installed"):
        warn("Nuclei not installed — showing manual exposure checks")
        hint = data.get("install_hint", "")
        if hint:
            dimprint(hint[:100], 6)
            dimprint(hint[100:] if len(hint) > 100 else "", 6)
    if data.get("error"):
        fail(data["error"]); return
    counts = data.get("severity_counts", {})
    if counts:
        parts = []
        for sev, color in [("critical", C.R), ("high", C.Y), ("medium", C.Y), ("low", C.G), ("info", C.B)]:
            if counts.get(sev):
                parts.append(f"{color}{sev.upper()}: {counts[sev]}{C.RS}")
        print(f"\n    {' | '.join(parts)}")
    findings = data.get("findings", [])
    if not findings:
        ok("No findings detected"); return
    print()
    sev_color = {"critical": C.R, "high": C.Y, "medium": C.Y, "low": C.G, "info": C.B}
    for f in findings:
        sc = sev_color.get(f.get("severity", ""), C.W)
        name = f.get("name") or f.get("path", "")
        sev = f.get("severity", "").upper()
        url = f.get("url") or f.get("matched_at", "")
        status = f.get("status", "")
        size = f.get("size", "")
        print(f"    {sc}[{sev}]{C.RS} {C.W}{name}{C.RS}")
        if url:
            meta = ""
            if status:
                meta += f"  [{status}]"
            if size != "" and size is not None:
                meta += f"  {_human_bytes(size)}"
            dimprint(f"  → {url}{meta}", 6)
        desc = f.get("description", "")
        if desc:
            dimprint(f"  {desc[:80]}", 6)


def render_shodan(data):
    section("SHODAN INTERNETDB + CVEs", "🔭")
    if data.get("error"):
        fail(data["error"]); return
    api_used = data.get("api_key_used", False)
    info("API Key", "Full API (SHODAN_API_KEY)" if api_used else "InternetDB (free, no key)")
    s = data.get("summary", {})
    info("Total Ports", s.get("total_ports", 0))
    info("Total CVEs", s.get("total_cves", 0))
    crit = s.get("critical_cves", [])
    if crit:
        print(f"\n    {C.R}{C.BD}Critical CVEs (CVSS ≥ 9.0):{C.RS}")
        for c in crit:
            fail(f"{c['cve']}  CVSS {c['cvss']}  on {c['ip']}", 6)
    for ip, ip_data in data.get("ips", {}).items():
        print(f"\n    {C.M}IP: {C.CY}{ip}{C.RS}")
        if ip_data.get("ports"):
            info("Open Ports", ", ".join(str(p) for p in ip_data["ports"]), 6)
        if ip_data.get("cpes"):
            info("CPEs", ", ".join(ip_data["cpes"][:4]), 6)
        if ip_data.get("tags"):
            info("Tags", ", ".join(ip_data["tags"]), 6)
        if ip_data.get("os"):
            info("OS", ip_data["os"], 6)
        if ip_data.get("isp"):
            info("ISP", ip_data["isp"], 6)
        cves = ip_data.get("cves", [])
        if cves:
            print(f"      {C.Y}CVEs ({len(cves)}):{C.RS}")
            if isinstance(cves[0], dict):
                for cv in cves:
                    cvss = cv.get("cvss", "?")
                    col = C.R if float(cvss or 0) >= 7 else C.Y
                    print(f"        {col}{cv['id']}{C.RS}  CVSS {cvss}")
                    if cv.get("summary"):
                        dimprint(cv["summary"][:80], 10)
            else:
                for cv in cves:
                    warn(cv, 6)
        svcs = (ip_data.get("api_data") or {}).get("services", [])
        if svcs:
            print(f"      {C.M}Services:{C.RS}")
            table_header(["PORT", "PRODUCT", "VERSION", "BANNER"], [8, 18, 14, 28])
            for svc in svcs:
                table_row([svc["port"], svc.get("product","")[:16],
                           svc.get("version","")[:12], svc.get("banner","")[:26]],
                          [8, 18, 14, 28], [C.W, C.CY, C.G, C.GR])


def render_censys(data):
    section("CENSYS HOSTS + CERTIFICATES", "🔬")
    if data.get("error"):
        fail(data["error"]); return
    api_used = data.get("api_used", False)
    info("API", "Full API (CENSYS_API_ID/SECRET)" if api_used else "Free (deep links + crt.sh certs)")
    info("IPs Found", len(data.get("ips", [])))
    info("Certs Found", data.get("summary", {}).get("certs_found", 0))

    links = data.get("links", {})
    if links:
        print(f"\n    {C.M}Search Links:{C.RS}")
        for label, url in [
            ("Platform Search",  links.get("search_platform", "")),
            ("Hosts by Domain",  links.get("hosts_by_domain", "")),
            ("Certificates",     links.get("certificates", "")),
        ]:
            print(f"    {C.GR}  {label:<20}{C.RS}{C.UL}{C.CY}{url}{C.RS}")
        for ip_url in links.get("hosts_by_ip", []):
            print(f"    {C.GR}  Host Detail         {C.RS}{C.UL}{C.CY}{ip_url}{C.RS}")

    for ip, ip_data in data.get("ip_data", {}).items():
        print(f"\n    {C.M}IP: {C.CY}{ip}{C.RS}")
        if ip_data.get("source") == "censys_api":
            if ip_data.get("os"):      info("OS",      ip_data["os"], 6)
            if ip_data.get("country"): info("Country", ip_data["country"], 6)
            if ip_data.get("asn_name"):info("ASN",     f"{ip_data.get('asn','')} {ip_data['asn_name']}", 6)
            svcs = ip_data.get("services", [])
            if svcs:
                table_header(["PORT", "PROTOCOL", "SERVICE", "PRODUCT"], [8, 10, 18, 22])
                for svc in svcs:
                    table_row([svc.get("port",""), svc.get("transport_protocol",""),
                               svc.get("service_name","")[:16], svc.get("product","")[:20]],
                              [8, 10, 18, 22], [C.W, C.GR, C.CY, C.G])
        else:
            if ip_data.get("ports"):
                info("Ports", ", ".join(str(p) for p in ip_data["ports"]), 6)
            if ip_data.get("cves"):
                warn(f"{len(ip_data['cves'])} CVEs — see Shodan module or Censys link", 6)

    certs = data.get("certificates", [])
    if certs:
        print(f"\n    {C.M}Certificates ({len(certs)}):{C.RS}")
        table_header(["COMMON NAME", "ISSUER", "NOT AFTER"], [36, 30, 12])
        for c in certs:
            issuer = c.get("issuer","")
            if "," in issuer:
                issuer = issuer.split(",")[0].replace("O=","").replace("CN=","")
            table_row([c.get("common_name","")[:34], issuer[:28], c.get("not_after","")],
                      [36, 30, 12], [C.CY, C.GR, C.W])


def render_wafw00f(data):
    section("WAF DETECTION (WAFW00F)", "🧱")
    if data.get("error"):
        fail(data["error"]); return
    source = data.get("source", "")
    info("Source", "wafw00f binary" if source == "wafw00f_binary" else "Python fingerprinter")
    if data.get("normal_status"):
        info("HTTP Status", data["normal_status"])
    if data.get("probe_status"):
        blocked = data.get("probe_blocked", False)
        probe_col = C.R if blocked else C.G
        print(f"    {C.Y}Probe Status        {C.RS}{probe_col}{data['probe_status']}"
              f"{'  ← BLOCKED' if blocked else '  ← passed through'}{C.RS}")

    if source == "wafw00f_binary":
        dimprint(data.get("raw", "")[:600], 4)

    detected = data.get("detected", [])
    if not detected:
        ok("No WAF detected — site may be unprotected or using unknown WAF")
        return

    waf_found = data.get("waf_found", False)
    if waf_found:
        ok(f"{len(detected)} WAF signature(s) matched")
    print()
    conf_color = {"high": C.R, "medium": C.Y, "low": C.GR}
    for d in detected:
        cc = conf_color.get(d.get("confidence", "low"), C.W)
        print(f"    {cc}[{d['confidence'].upper()}]{C.RS}  {C.W}{C.BD}{d['waf']}{C.RS}  "
              f"{C.GR}(score: {d['score']}){C.RS}")
        for ev in d.get("evidence", []):
            dimprint(f"  → {ev}", 8)


def render_breachintel(data):
    section("BREACH & CREDENTIAL INTELLIGENCE", "💀")
    if data.get("error"):
        fail(data["error"]); return

    keys = data.get("api_keys_used", {})
    info("HIBP Key",       "✓ active" if keys.get("hibp") else "not set (set HIBP_API_KEY for per-email lookups)")
    info("LeakCheck Key",  "✓ active" if keys.get("leakcheck") else "not set (set LEAKCHECK_API_KEY for more results)")
    info("Chiasmodon Key", "✓ active" if keys.get("chiasmodon") else "free tier (set CHIASMODON_API_KEY for more)")

    s = data.get("summary", {})
    print(f"\n    {C.M}Summary:{C.RS}")
    info("Infostealer Hits",    s.get("total_infostealer_hits", 0))
    info("Employees Leaked",    s.get("total_employees_leaked", 0))
    info("Clients Leaked",      s.get("total_clients_leaked", 0))
    info("Emails Found",        s.get("total_emails_found", 0))
    if s.get("breach_names"):
        info("Known Breaches",  ", ".join(s["breach_names"]))

    crits = s.get("critical_findings", [])
    if crits:
        print(f"\n    {C.R}{C.BD}⚠ Critical Findings:{C.RS}")
        for c in crits:
            src_col = {"hudsonrock": C.M, "chiasmodon": C.Y}.get(c.get("source",""), C.R)
            fail(f"[{c.get('source','?').upper()}] {c.get('type','')}", 4)
            dimprint(c.get("detail",""), 8)

    # ── Hudson Rock ──
    hr = data.get("sources", {}).get("hudsonrock", {})
    print(f"\n    {C.CY}{C.BD}Hudson Rock Cavalier (Infostealer DB):{C.RS}")
    info("Status",   hr.get("status", "?"))
    info("Employees Infected", hr.get("total_employees", 0))
    info("Clients Infected",   hr.get("total_clients", 0))

    if hr.get("employees"):
        print(f"\n    {C.M}Infected Employee Machines:{C.RS}")
        table_header(["USERNAME", "COMPUTER", "DATE", "OS", "CREDS"], [24, 20, 12, 16, 6])
        for e in hr["employees"]:
            table_row([
                (e.get("username") or "")[:22],
                (e.get("computer_name") or "")[:18],
                (e.get("date_compromised") or "")[:10],
                (e.get("operating_system") or "")[:14],
                str(e.get("credential_count", 0)),
            ], [24, 20, 12, 16, 6], [C.R, C.Y, C.GR, C.GR, C.R if e.get("credential_count",0)>3 else C.Y])
            for cred in (e.get("credentials") or []):
                url_c = cred.get("url", "") if isinstance(cred, dict) else str(cred)
                user_c = cred.get("username", "") if isinstance(cred, dict) else ""
                dimprint(f"    → {url_c[:60]}" + (f"  user:{user_c[:20]}" if user_c else ""), 8)

    if hr.get("clients"):
        print(f"\n    {C.M}Infected Client Machines:{C.RS}")
        for c in hr["clients"]:
            warn(f"{c.get('username','?')}  [{c.get('date_compromised','?')}]  {c.get('credential_count',0)} creds", 6)

    if hr.get("urls"):
        print(f"\n    {C.M}Stolen URLs ({len(hr['urls'])}):{C.RS}")
        for u in hr["urls"]:
            dimprint(str(u)[:80], 6)

    # ── Chiasmodon ──
    chia = data.get("sources", {}).get("chiasmodon", {})
    print(f"\n    {C.CY}{C.BD}Chiasmodon (Credential DB):{C.RS}")

    emp_logins = chia.get("employee_logins", [])
    if emp_logins:
        ok(f"{len(emp_logins)} employee credential entries", 4)
        print()
        table_header(["URL/HOST", "USER/EMAIL", "PASSWORD"], [32, 28, 18])
        for login in emp_logins:
            url_v  = str(login.get("url") or login.get("host") or "")[:30]
            user_v = str(login.get("user") or login.get("username") or login.get("email") or "")[:26]
            pw_v   = str(login.get("password") or "")
            pw_display = pw_v[:3] + "*" * max(0, len(pw_v) - 3) if pw_v else ""
            table_row([url_v, user_v, pw_display], [32, 28, 18], [C.GR, C.CY, C.R if pw_v else C.GR])
    else:
        warn(f"Employee logins: {chia.get('employee_status', 'no results')}", 4)

    cli_logins = chia.get("client_logins", [])
    if cli_logins:
        ok(f"{len(cli_logins)} client credential entries", 4)
        for login in cli_logins:
            url_v  = str(login.get("url") or login.get("host") or "")[:40]
            user_v = str(login.get("user") or login.get("username") or login.get("email") or "")[:30]
            pw_v   = str(login.get("password") or "")
            pw_display = pw_v[:2] + "*"*max(0, len(pw_v)-2) if pw_v else ""
            dimprint(f"{url_v}  {user_v}  {pw_display}", 6)

    emails = chia.get("emails", [])
    if emails:
        print(f"\n    {C.M}Company Emails ({len(emails)}):{C.RS}")
        for e_item in emails:
            em = e_item if isinstance(e_item, str) else e_item.get("email", str(e_item))
            dimprint(em, 6)

    related = chia.get("related", [])
    if related:
        print(f"\n    {C.M}Related Domains:{C.RS}")
        for r_item in related:
            rel = r_item if isinstance(r_item, str) else r_item.get("domain", str(r_item))
            dimprint(rel, 6)

    # ── ProxyNova COMB ──
    pn = data.get("sources", {}).get("proxynova_comb", {})
    print(f"\n    {C.CY}{C.BD}ProxyNova COMB (3.2 Billion Credentials):{C.RS}")
    info("Status",         pn.get("status", "ok"))
    info("Total Records",  f"{pn.get('total_count', 0):,}")
    info("Unique Emails",  pn.get("unique_count", 0))
    info("Weak Passwords", pn.get("weak_password_count", 0))

    parsed = pn.get("parsed", [])
    if parsed:
        print()
        table_header(["EMAIL", "PASSWORD (PARTIAL)", "LEN"], [40, 22, 5])
        for entry in parsed:
            pw_col = C.R if entry.get("has_password") else C.GR
            table_row(
                [entry.get("email",""), entry.get("password",""), str(entry.get("pw_len",""))],
                [40, 22, 5],
                [C.CY, pw_col, C.GR]
            )

    else:
        warn("No COMB entries found for this domain", 4)

    if pn.get("sample_passwords"):
        print(f"\n    {C.M}Sample Password Patterns:{C.RS}")
        for pw in pn["sample_passwords"]:
            dimprint(f"  {pw}", 6)

    # ── HIBP ──
    hibp = data.get("sources", {}).get("hibp", {})
    print(f"\n    {C.CY}{C.BD}HaveIBeenPwned:{C.RS}")
    domain_breaches = hibp.get("domain_breaches", [])
    if domain_breaches:
        ok(f"{len(domain_breaches)} breach(es) matching this domain", 4)
        for b in domain_breaches:
            print(f"    {C.R}[BREACH]{C.RS} {C.W}{b['title'] or b['name']}{C.RS}  "
                  f"{C.GR}{b['breach_date']}{C.RS}  {C.Y}{b['pwn_count']:,} accounts{C.RS}")
            if b.get("data_classes"):
                dimprint("Data: " + ", ".join(b["data_classes"][:6]), 8)
    else:
        ok(f"No direct domain breaches in HIBP ({hibp.get('total_known_breaches',0)} total breaches indexed)", 4)
    if hibp.get("per_email_breaches"):
        print(f"\n    {C.M}Per-Email Breach Results:{C.RS}")
        for email, breaches in hibp["per_email_breaches"].items():
            warn(f"{email}: {', '.join(breaches)}", 6)

    # ── LeakCheck ──
    lc = data.get("sources", {}).get("leakcheck", {})
    print(f"\n    {C.CY}{C.BD}LeakCheck:{C.RS}")
    lc_results = lc.get("results", [])
    if lc_results:
        ok(f"{lc.get('found_count', len(lc_results))} entries found", 4)
        for item in lc_results:
            sources = ", ".join(item.get("sources", []))
            has_pw  = "  [HAS PASSWORD]" if item.get("has_password") else ""
            print(f"      {C.CY}{item.get('email','')}{C.RS}  {C.GR}{sources}{C.RS}{C.R}{has_pw}{C.RS}")
    else:
        warn(f"LeakCheck: {lc.get('status', 'no results')}", 4)

    # ── OSINT Links ──
    links = data.get("osint_links", {})
    if links:
        print(f"\n    {C.M}Useful Breach Investigation Links:{C.RS}")
        for label, url in links.items():
            print(f"    {C.GR}  {label:<24}{C.RS}{C.UL}{C.CY}{url}{C.RS}")


def render_dorks(data):
    section("GOOGLE DORK QUERIES", "🔍")
    dimprint("Ready to paste into Google.", 4)
    total = 0
    for cat, items in data.items():
        print(f"\n    {C.M}{C.BD}{cat}:{C.RS}")
        for label, dork in items:
            total += 1
            print(f"    {C.GR}[{total:02d}]{C.RS} {C.Y}{label:<28}{C.RS}{C.W}{dork}{C.RS}")
    print(f"\n    {C.G}{C.BD}Total: {total} dorks{C.RS}")


def render_osint(data):
    section("OSINT PLATFORM URLS", "🔗")
    total = 0
    for cat, items in data.items():
        print(f"\n    {C.M}{C.BD}{cat}:{C.RS}")
        for label, url in items:
            total += 1
            print(f"    {C.GR}[{total:02d}]{C.RS} {C.Y}{label:<22}{C.RS}{C.UL}{C.CY}{url}{C.RS}")
    print(f"\n    {C.G}{C.BD}Total: {total} URLs{C.RS}")


def _human_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    if n < 1024:
        return f"{int(n)} B"
    if n < 1048576:
        return f"{n/1024:.1f} KB"
    return f"{n/1048576:.2f} MB"


def render_endpoints(data):
    section("SENSITIVE ENDPOINTS", "📂")
    if data.get("error"):
        fail(data["error"]); return
    counts = data.get("severity_counts", {})
    if counts:
        parts = []
        for sev, color in [("critical", C.R), ("high", C.Y), ("medium", C.Y), ("low", C.GR), ("info", C.B)]:
            if counts.get(sev):
                parts.append(f"{color}{sev.upper()}: {counts[sev]}{C.RS}")
        print(f"\n    {' | '.join(parts)}")
    dimprint(f"{data.get('total_found', 0)} found / {data.get('total_probed', 0)} probed", 4)
    findings = data.get("findings", [])
    if not findings:
        ok("No sensitive endpoints found"); return
    print()
    sev_color = {"critical": C.R, "high": C.Y, "medium": C.Y, "low": C.GR, "info": C.B}
    for f in findings:
        sc = sev_color.get(f.get("severity", ""), C.W)
        print(f"    {sc}[{f.get('severity','').upper()}]{C.RS} {C.W}{f.get('name','')}{C.RS}  "
              f"{C.GR}[{f.get('status','')}]  {_human_bytes(f.get('size',''))}{C.RS}")
        url = f.get("url", "")
        if url:
            dimprint(f"  → {url}", 6)


def render_content_intel(data):
    section("CONTENT INTELLIGENCE (JS/HTML EXTRACTION)", "🧠")
    if data.get("error"):
        fail(data["error"]); return
    ss = data.get("sources_scanned", {})
    dimprint(f"Scanned: 1 HTML · {ss.get('inline_scripts',0)} inline · {ss.get('js_files',0)} JS files", 4)
    total = data.get("total", 0)
    if not total:
        ok("Nothing interesting extracted"); return
    print(f"    {C.CY}{C.BD}{total} items extracted{C.RS}")

    cats = data.get("categories", {})
    counts = data.get("counts", {})
    # (key, label, color, is_kinded)
    groups = [
        ("databases",      "Database URIs",      C.R,  True),
        ("cloud_storage",  "Cloud Storage",      C.Y,  True),
        ("api_endpoints",  "API Endpoints",      C.M,  False),
        ("sensitive",      "Sensitive Info",     C.R,  True),
        ("urls_external",  "External Sources",   C.Y,  False),
        ("urls_internal",  "Internal URLs",      C.CY, False),
        ("endpoints",      "Endpoints / Paths",  C.CY, False),
        ("internal_hosts", "Internal Hosts",     C.Y,  False),
        ("ip_addresses",   "IP Addresses",       C.W,  False),
        ("emails",         "Emails",             C.W,  False),
    ]
    sev_color = {"critical": C.R, "high": C.Y, "medium": C.Y, "low": C.GR}
    for key, label, color, kinded in groups:
        items = cats.get(key, [])
        if not items:
            continue
        extra = "+" if counts.get(key, 0) >= 200 else ""
        print(f"\n    {color}{C.BD}{label}{C.RS} {C.GR}({len(items)}{extra}){C.RS}")
        for it in items[:15]:
            if kinded and it.get("kind"):
                kc = sev_color.get(it.get("severity", ""), C.GR)
                print(f"      {kc}[{it['kind']}]{C.RS} {C.W}{it['value']}{C.RS}")
            else:
                print(f"      {C.GR}•{C.RS} {C.W}{it['value']}{C.RS}")
        if len(items) > 15:
            dimprint(f"  + {len(items)-15} more…", 6)


RENDERERS = {
    "dns": render_dns, "whois": render_whois, "ssl": render_ssl,
    "crtsh": render_crtsh, "headers": render_headers, "ports": render_ports,
    "tech": render_tech, "geo": render_geo, "robots": render_robots,
    "wayback": render_wayback, "brute": render_brute, "dorks": render_dorks,
    "osint": render_osint,
    "subdomains": render_subdomains,
    "whatweb": render_whatweb,
    "nuclei": render_nuclei,
    "endpoints": render_endpoints,
    "content_intel": render_content_intel,
    "shodan": render_shodan,
    "censys": render_censys,
    "wafw00f": render_wafw00f,
    "breachintel": render_breachintel,
}


# ═══════════════════════════════════════════════════════════════
# SUMMARY DASHBOARD
# ═══════════════════════════════════════════════════════════════

def print_summary(results, domain, elapsed, to_run):
    R = results or {}

    # ── aggregate severities across all finding-bearing modules ──
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    def add_sev(items, key="severity"):
        for it in (items or []):
            s = (it.get(key) or "").lower()
            if s in sev:
                sev[s] += 1
    add_sev((R.get("nuclei") or {}).get("findings"))
    add_sev((R.get("endpoints") or {}).get("findings"))
    add_sev((R.get("api_fuzzer") or {}).get("endpoints"))
    add_sev((R.get("content_intel") or {}).get("categories", {}).get("sensitive"))
    add_sev((R.get("js_secrets") or {}).get("secrets"))

    total_findings = sum(sev.values())

    print(f"\n  {C.CY}{C.BD}{'═' * 60}{C.RS}")
    print(f"  {C.G}{C.BD}  ✓  SCAN COMPLETE{C.RS}   {C.GR}{domain}{C.RS}")
    print(f"  {C.CY}{C.BD}{'═' * 60}{C.RS}\n")

    # ── module roadmap (numbered, with status bars — HeroMap style) ──
    print(f"  {C.W}{C.BD}Module roadmap{C.RS}")
    ok_count = 0
    for i, k in enumerate(to_run, 1):
        res = R.get(k, {})
        err = isinstance(res, dict) and res.get("error")
        name = ALL_MODULES.get(k, (k,))[0]
        name = name if len(name) <= 28 else name[:27] + "…"
        if err:
            timed = "timed out" in str(err).lower() or "timeout" in str(err).lower()
            col = C.Y if timed else C.R
            icon = "⏱" if timed else "✗"
            label = "timeout" if timed else "no data"
            bar = _bar(100, 10, col)
        else:
            ok_count += 1
            col, icon, label, bar = C.G, "✓", "done", _bar(100, 10, C.G)
        print(f"    {C.GR}[{i:>2}]{C.RS} {C.W}{name:<28}{C.RS} {bar} {col}{icon}{C.RS} {C.GR}{label}{C.RS}")
    overall = (ok_count / len(to_run) * 100) if to_run else 0
    print(f"\n    {C.CY}{C.BD}Overall{C.RS}  {_bar(overall, 24, C.CY)} {C.W}{overall:.0f}%{C.RS} "
          f"{C.GR}({ok_count}/{len(to_run)} ok){C.RS}\n")

    # ── severity bar ──
    sev_colors = {"critical": C.R, "high": C.M, "medium": C.Y, "low": C.GR}
    sev_icons  = {"critical": "☠", "high": "▲", "medium": "◆", "low": "•"}
    if total_findings:
        print(f"  {C.W}{C.BD}Findings by severity{C.RS}")
        maxv = max(sev.values()) or 1
        for s in ("critical", "high", "medium", "low"):
            n = sev[s]
            bar = "█" * int((n / maxv) * 28) if n else ""
            print(f"    {sev_colors[s]}{sev_icons[s]} {s.upper():<9}{C.RS} "
                  f"{sev_colors[s]}{bar}{C.RS} {C.W}{n}{C.RS}")
        print()

    # ── key recon stats ──
    def g(*path, default=0):
        cur = R
        for p in path:
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                return default
        return cur if cur is not None else default

    stats = []
    ports = g("ports", "open", default=[])
    if ports: stats.append(("Open ports", len(ports)))
    subs = g("subdomains", "total", default=0) or len(g("subdomains", "subdomains", default=[]) or [])
    if subs: stats.append(("Subdomains", subs))
    cves = g("shodan", "summary", "total_cves", default=0)
    if cves: stats.append(("CVEs (Shodan)", cves))
    bs = g("breachintel", "summary", default={}) or {}
    leaks = (bs.get("total_infostealer_hits", 0) or 0) + (bs.get("total_employees_leaked", 0) or 0)
    if leaks: stats.append(("Leaked creds", leaks))
    secrets = g("js_secrets", "total", default=0)
    if secrets: stats.append(("JS secrets", secrets))
    ci = g("content_intel", "total", default=0)
    if ci: stats.append(("Intel items", ci))
    emails = len(g("email_harvest", "emails", default=[]) or [])
    if emails: stats.append(("Emails", emails))
    grade = g("headers", "grade", default=None)
    if grade: stats.append(("Header grade", grade))

    if stats:
        print(f"  {C.W}{C.BD}Recon highlights{C.RS}")
        for i in range(0, len(stats), 2):
            left = stats[i]
            cell_l = f"{C.Y}{left[0]:<16}{C.RS}{C.CY}{C.BD}{left[1]}{C.RS}"
            if i + 1 < len(stats):
                right = stats[i + 1]
                cell_r = f"{C.Y}{right[0]:<16}{C.RS}{C.CY}{C.BD}{right[1]}{C.RS}"
                print(f"    {cell_l:<44}   {cell_r}")
            else:
                print(f"    {cell_l}")
        print()

    # ── top critical/high findings ──
    top = []
    for f in (R.get("nuclei") or {}).get("findings", []):
        if (f.get("severity") or "").lower() in ("critical", "high"):
            top.append((f.get("severity"), f.get("name") or f.get("path", ""), "vuln"))
    for f in (R.get("endpoints") or {}).get("findings", []):
        if (f.get("severity") or "").lower() in ("critical", "high"):
            top.append((f.get("severity"), f.get("name") or f.get("path", ""), "endpoint"))
    if top:
        print(f"  {C.W}{C.BD}Top findings{C.RS}")
        for s, name, kind in top[:8]:
            sc = sev_colors.get((s or "").lower(), C.W)
            print(f"    {sc}[{(s or '').upper():<8}]{C.RS} {C.W}{name[:48]}{C.RS} {C.GR}({kind}){C.RS}")
        if len(top) > 8:
            dimprint(f"  + {len(top)-8} more", 4)
        print()

    # ── quick commands (HeroMap-style bracketed menu) ──
    print(f"  {C.W}{C.BD}Commands{C.RS}")
    for key, label, cmd in [
        ("o", "Save JSON report", f"kumo.py {domain} -o report.json"),
        ("f", "Fast scan",        f"kumo.py {domain} --fast"),
        ("w", "Launch web UI",    "kumo.py --web"),
        ("m", "List all modules", "kumo.py --list-modules"),
    ]:
        print(f"    {C.M}[{key}]{C.RS} {C.W}{label:<18}{C.RS}{C.GR}{cmd}{C.RS}")
    print()

    _box("SCAN SUMMARY", [
        ("Target", domain),
        ("Modules", f"{len(to_run)} executed"),
        ("Findings", f"{total_findings} ({sev['critical']}C / {sev['high']}H / {sev['medium']}M / {sev['low']}L)"),
        ("Duration", f"{elapsed:.1f}s"),
    ], color=C.G)
    print()


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    mod_list = "\n".join(f"  {k:<14} {desc}" for k, (desc, _) in ALL_MODULES.items())

    parser = argparse.ArgumentParser(
        description="Kumo v2.0 — Domain OSINT & Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(f"""\
Examples:
  %(prog)s example.com                       CLI full scan
  %(prog)s example.com --fast                CLI fast scan
  %(prog)s example.com -m dns ssl ports      Specific modules
  %(prog)s example.com -m dorks osint        Dork + OSINT generator
  %(prog)s --web                             Launch web UI on :8888
  %(prog)s --web -p 9000                     Web UI on custom port
  %(prog)s example.com -o report.json        Save JSON report
  %(prog)s example.com --no-color            Pipe-friendly

Modules ({len(ALL_MODULES)}):
{mod_list}""")
    )

    parser.add_argument("domain", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("-m", "--modules", nargs="+", choices=list(ALL_MODULES.keys()),
                        help="Modules to run (default: all)")
    parser.add_argument("-o", "--output", help="Save JSON report")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--fast", action="store_true", help="Skip slow modules")
    parser.add_argument("--web", action="store_true", help="Launch web UI instead of CLI")
    parser.add_argument("-p", "--port", type=int, default=8888, help="Web UI port (default: 8888)")
    parser.add_argument("--host", default="0.0.0.0", help="Web UI host (default: 0.0.0.0)")
    parser.add_argument("--list-modules", action="store_true", help="List all modules")

    args = parser.parse_args()

    if args.no_color:
        C.off()

    # ──── Web mode ────
    if args.web:
        banner()
        try:
            from web import start_web
            start_web(host=args.host, port=args.port)
        except ImportError:
            print(f"{C.R}[✗] Flask required for web mode: pip install flask{C.RS}")
            sys.exit(1)
        return

    # ──── List modules ────
    if args.list_modules:
        banner()
        for k, (desc, _) in ALL_MODULES.items():
            print(f"  {C.Y}{k:<14}{C.RS} {desc}")
        sys.exit(0)

    # ──── CLI mode ────
    if not args.domain:
        banner()
        parser.print_help()
        sys.exit(1)

    domain = clean_domain(args.domain)
    if not domain:
        print(f"{C.R}[✗] Invalid domain: {args.domain}{C.RS}")
        sys.exit(1)

    banner()
    print_tip()

    if args.modules:
        to_run = args.modules
    elif args.fast:
        to_run = [k for k in ALL_MODULES if k not in FAST_SKIP]
    else:
        to_run = list(ALL_MODULES.keys())

    _box("SCAN CONFIG", [
        ("Target", domain),
        ("Date", datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
        ("Modules", f"{len(to_run)} / {len(ALL_MODULES)}"),
        ("Mode", "fast" if args.fast else ("custom" if args.modules else "full")),
    ])

    start = time.time()
    all_results = {}
    total_mods = len(to_run)
    counter = {"n": 0}

    def callback(key, desc, result):
        all_results[key] = result
        counter["n"] += 1
        el = time.time() - start
        print(f"\n  {C.GR}[{counter['n']:>2}/{total_mods}] · {el:5.1f}s{C.RS}", end="")
        renderer = RENDERERS.get(key)
        if renderer:
            try:
                renderer(result)
            except Exception as e:
                fail(f"Render error for {key}: {e}")
        else:
            section(desc.upper(), "📋")
            if isinstance(result, dict) and result.get("error"):
                fail(result["error"])
            else:
                dimprint(json.dumps(result, indent=2, default=str)[:500], 4)

    run_scan(domain, modules=to_run, fast=args.fast, callback=callback)

    elapsed = time.time() - start

    print_summary(all_results, domain, elapsed, to_run)

    if args.output:
        try:
            report = {
                "tool": "Kumo v2.0", "target": domain,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "modules": to_run, "duration": f"{elapsed:.1f}s",
                "results": all_results,
            }
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
            ok(f"Report saved to {C.BD}{args.output}{C.RS}")
        except Exception as e:
            fail(f"Could not save: {e}")


if __name__ == "__main__":
    main()
