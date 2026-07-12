#!/usr/bin/env python3
"""
Kumo v2.0 — Web Interface
Embedded web server with a hacker-aesthetic dashboard.
"""

import json
import threading
import time
from datetime import datetime

try:
    from flask import Flask, render_template_string, request, jsonify, Response
except ImportError:
    print("[!] Flask required for web mode: pip install flask")
    exit(1)

from engine import clean_domain, ALL_MODULES, FAST_SKIP, run_scan

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════════
# SCAN SESSION REGISTRY — enables the STOP button to cancel a scan
# ═══════════════════════════════════════════════════════════════
# Maps scan_id -> threading.Event(). When the event is set, the
# streaming generator stops waiting on stragglers and shuts down.
SCAN_STOP_EVENTS = {}
_SCAN_LOCK = threading.Lock()

# ── Per-module timeouts (seconds) — v2.0: generous, judged individually ──
# Every module runs against its OWN clock, so a slow scanner (nuclei) can take
# its time without other modules killing it, and fast modules are never held
# hostage waiting on a slow one.
MODULE_TIMEOUTS = {
    # fast / cheap
    'dns': 25, 'geo': 25, 'whois': 40, 'robots': 25, 'ssl': 35,
    'headers': 30, 'favicon': 50, 'dorks': 20, 'osint': 20,
    # medium (single API / moderate crawling)
    'shodan': 45, 'censys': 50, 'whatweb': 75, 'wafw00f': 75,
    'ports': 120, 'endpoints': 120, 'wayback': 120,
    'email_harvest': 120, 'screenshot': 90,
    # heavy (many parallel requests / brute / enumeration)
    'js_secrets': 120, 'api_fuzzer': 120, 'content_intel': 120, 'cloud_buckets': 180,
    'subdomains': 200, 'brute': 200, 'breachintel': 200,
    # vulnerability scanner — 145 checks + ~38 sequential exploit probes
    'nuclei': 360,
}
DEFAULT_TIMEOUT = 90    # anything unlisted
ABS_CAP = 420           # hard safety ceiling per module (7 min)


def _register_scan(scan_id):
    ev = threading.Event()
    with _SCAN_LOCK:
        SCAN_STOP_EVENTS[scan_id] = ev
    return ev


def _stop_scan(scan_id):
    with _SCAN_LOCK:
        ev = SCAN_STOP_EVENTS.get(scan_id)
    if ev:
        ev.set()
        return True
    return False


def _unregister_scan(scan_id):
    with _SCAN_LOCK:
        SCAN_STOP_EVENTS.pop(scan_id, None)

# ═══════════════════════════════════════════════════════════════
# HTML TEMPLATE — Full hacker terminal aesthetic
# ═══════════════════════════════════════════════════════════════

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kumo — OSINT Recon · Kumo v2.0</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#080b14;--bg2:#0d1117;--bg3:#161b27;--bg4:#1c2333;
  --border:#21293d;--border2:#2d3a52;--border3:#3d4f70;
  --text:#cdd5e0;--text2:#7d8fa8;--text3:#4a5568;
  --green:#3ddc84;--green2:#2aab68;--green-dim:rgba(61,220,132,.1);
  --red:#f85149;--red-dim:rgba(248,81,73,.1);
  --yellow:#e3b341;--yellow-dim:rgba(227,179,65,.1);
  --cyan:#58a6ff;--cyan-dim:rgba(88,166,255,.1);
  --purple:#bc8cff;--purple-dim:rgba(188,140,255,.1);
  --orange:#ffa657;--pink:#ff7b72;
  --card-r:12px;--input-r:8px;
}
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{background:var(--bg);color:var(--text);font-family:'Inter',system-ui,sans-serif;font-size:14px;min-height:100vh;overflow-x:hidden}
::selection{background:var(--cyan-dim);color:var(--cyan)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

/* ── HEADER ── */
.hdr{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 24px;height:auto;min-height:56px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:200}
.logo-skull{font-size:20px}
.logo-txt{font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;letter-spacing:2px;color:#fff}
.kumo-logo{font-family:'JetBrains Mono','Courier New',monospace;font-size:7.5px;line-height:1.35;color:#3b82f6;margin:0;padding:0;white-space:pre;font-weight:700;flex-shrink:0}
.logo-ver{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:1px;background:var(--green-dim);border:1px solid rgba(61,220,132,.25);color:var(--green);padding:2px 7px;border-radius:4px}
.hdr-right{margin-left:auto;font-size:11px;color:var(--text3);font-family:'JetBrains Mono',monospace}
.hdr-right span{color:var(--cyan)}

/* ── SEARCH BAR ── */
.search-bar{background:var(--bg2);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;gap:10px;align-items:center}
.search-hint{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--green);font-weight:700;flex-shrink:0}
.search-wrap{flex:1;display:flex;align-items:center;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--input-r);padding:0 14px;transition:border-color .2s,box-shadow .2s}
.search-wrap:focus-within{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(88,166,255,.1)}
#domInput{flex:1;background:transparent;border:none;outline:none;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;padding:12px 0;caret-color:var(--cyan)}
#domInput::placeholder{color:var(--text3)}
.btn{height:46px;padding:0 20px;border-radius:var(--input-r);font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;letter-spacing:1.5px;cursor:pointer;border:1px solid;transition:all .15s;display:flex;align-items:center;gap:6px;white-space:nowrap}
.btn-scan{background:var(--cyan);border-color:var(--cyan);color:#080b14}
.btn-scan:hover{background:#79c0ff;border-color:#79c0ff}
.btn-scan:disabled{opacity:.4;cursor:not-allowed}
.btn-scan.busy{animation:pulse 1.2s infinite}
.btn-fast{background:transparent;border-color:var(--border2);color:var(--yellow)}
.btn-fast:hover{border-color:var(--yellow);background:var(--yellow-dim)}

/* ── MODULE PILLS ── */
.pill-bar{background:var(--bg2);border-bottom:1px solid var(--border);padding:8px 24px;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.pill-lbl{font-size:9px;color:var(--text3);font-family:'JetBrains Mono',monospace;letter-spacing:1px;margin-right:4px}
.pill{padding:2px 9px;border-radius:20px;font-size:9px;font-family:'JetBrains Mono',monospace;border:1px solid var(--border);background:var(--bg3);color:var(--text3);cursor:pointer;transition:all .12s;user-select:none;letter-spacing:.5px}
.pill.on{border-color:var(--cyan);color:var(--cyan);background:var(--cyan-dim)}
.pill.done{border-color:var(--green);color:var(--green);background:var(--green-dim)}
.pill.done::after{content:" ✓";font-size:8px}
.pill.running{border-color:var(--yellow);color:var(--yellow);background:var(--yellow-dim);animation:pulse .8s infinite}

/* ── PROGRESS ── */
.prog{height:2px;background:var(--border);display:none}
.prog.on{display:block}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--green));transition:width .35s;width:0}

/* ── STATUS ── */
.status{padding:7px 24px;background:var(--bg);border-bottom:1px solid var(--border);display:none;align-items:center;gap:12px}
.status.on{display:flex}
.s-dot{width:6px;height:6px;border-radius:50%;background:var(--yellow);animation:pulse .8s infinite;flex-shrink:0}
.s-dot.done{background:var(--green);animation:none}
.s-txt{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text2)}
.s-txt b{color:var(--text)}
.s-counts{margin-left:auto;display:flex;gap:12px;font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text3)}
.s-counts span{color:var(--cyan)}

/* ── MAIN LAYOUT — left scan grid + right sticky panel ── */
.main-layout{display:flex;align-items:flex-start;min-height:calc(100vh - 170px)}

/* LEFT: scan result cards */
.scan-grid{
  flex:1;padding:20px 16px 20px 24px;
  columns:2;column-gap:14px;
  min-width:0;
}
@media(max-width:1400px){.scan-grid{columns:2}}
@media(max-width:900px){.scan-grid{columns:1;padding:16px}}

/* RIGHT: fixed dorks + osint panel */
.right-panel{
  width:400px;flex-shrink:0;
  position:sticky;top:56px;
  height:calc(100vh - 56px);
  overflow-y:auto;
  border-left:1px solid var(--border);
  background:var(--bg2);
  padding:16px;
  display:flex;flex-direction:column;gap:12px;
}
@media(max-width:900px){.right-panel{display:none}}

.right-section-title{
  font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:700;
  letter-spacing:1.5px;color:var(--text3);text-transform:uppercase;
  padding-bottom:8px;border-bottom:1px solid var(--border);margin-bottom:8px;
  display:flex;align-items:center;gap:8px
}

/* ── CARDS ── */
.card{break-inside:avoid;margin-bottom:14px;background:var(--bg2);border:1px solid var(--border);border-radius:var(--card-r);overflow:hidden;animation:slideUp .22s ease both;transition:border-color .2s}
.card:hover{border-color:var(--border2)}
@keyframes slideUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.c-head{display:flex;align-items:center;gap:8px;padding:11px 14px;cursor:pointer;user-select:none;border-bottom:1px solid var(--border);background:var(--bg3);transition:background .15s}
.c-head:hover{background:var(--bg4)}
.c-icon{font-size:15px;flex-shrink:0;width:20px;text-align:center}
.c-title{font-size:10px;font-weight:700;letter-spacing:.8px;color:var(--text);text-transform:uppercase;flex:1;font-family:'JetBrains Mono',monospace}
.c-badges{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.c-chev{color:var(--text3);font-size:9px;transition:transform .2s;flex-shrink:0}
.c-chev.open{transform:rotate(90deg)}
.c-body{padding:13px 14px;display:none}
.c-body.open{display:block}

/* badges */
.badge{font-size:9px;font-family:'JetBrains Mono',monospace;letter-spacing:.5px;padding:2px 6px;border-radius:4px;font-weight:700;white-space:nowrap}
.b-pass{background:var(--green-dim);color:var(--green);border:1px solid rgba(61,220,132,.25)}
.b-fail{background:var(--red-dim);color:var(--red);border:1px solid rgba(248,81,73,.25)}
.b-warn{background:var(--yellow-dim);color:var(--yellow);border:1px solid rgba(227,179,65,.25)}
.b-info{background:var(--cyan-dim);color:var(--cyan);border:1px solid rgba(88,166,255,.25)}
.b-purple{background:var(--purple-dim);color:var(--purple);border:1px solid rgba(188,140,255,.25)}

/* skeleton */
.sk{background:linear-gradient(90deg,var(--bg3) 25%,var(--bg4) 50%,var(--bg3) 75%);background-size:200% 100%;animation:shimmer 1.4s infinite;border-radius:4px;height:11px;margin:4px 0}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.sk-title{width:55%;height:10px}.sk-line{width:100%}.sk-short{width:38%}

/* kv */
.kv{display:flex;gap:8px;padding:4px 0;align-items:baseline;border-bottom:1px solid rgba(33,41,61,.5)}
.kv:last-child{border-bottom:none}
.kv-k{color:var(--text2);font-size:11px;width:140px;flex-shrink:0;font-family:'JetBrains Mono',monospace}
.kv-v{color:var(--text);font-size:12px;word-break:break-all;flex:1}

/* table */
.tbl{width:100%;border-collapse:collapse;font-size:11px;margin-top:6px}
.tbl th{text-align:left;color:var(--text3);font-size:9px;letter-spacing:1px;padding:4px 7px;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-weight:600;text-transform:uppercase}
.tbl td{padding:4px 7px;border-bottom:1px solid rgba(33,41,61,.4);vertical-align:middle}
.tbl tr:last-child td{border-bottom:none}
.tbl tr:hover td{background:rgba(88,166,255,.02)}

/* tag */
.tag{display:inline-block;background:var(--bg3);border:1px solid var(--border2);border-radius:4px;padding:2px 7px;margin:2px;font-size:10px;color:var(--purple);font-family:'JetBrains Mono',monospace}

/* section header */
.sec{font-size:9px;letter-spacing:1.5px;color:var(--text3);text-transform:uppercase;font-family:'JetBrains Mono',monospace;padding:9px 0 4px;border-bottom:1px solid var(--border);margin:7px 0 5px;font-weight:700}

/* dork */
.dork-item{padding:5px 0;border-bottom:1px solid rgba(33,41,61,.5)}
.dork-item:last-child{border-bottom:none}
.dork-lbl{color:var(--yellow);font-size:10px;font-family:'JetBrains Mono',monospace;margin-bottom:3px}

.dork-q{color:var(--text);font-size:10px;word-break:break-all;cursor:pointer;padding:3px 6px;background:var(--bg);border-radius:4px;border:1px solid var(--border);transition:all .12s;font-family:'JetBrains Mono',monospace;line-height:1.5}
.dork-q:hover{border-color:var(--cyan);color:var(--cyan);background:var(--cyan-dim)}

/* url */
.url-row{display:flex;align-items:baseline;gap:8px;padding:3px 0;border-bottom:1px solid rgba(33,41,61,.4)}
.url-row:last-child{border-bottom:none}
.url-lbl{color:var(--yellow);font-size:10px;width:140px;flex-shrink:0;font-family:'JetBrains Mono',monospace}
.url-row a{color:var(--cyan);font-size:10px;text-decoration:none;word-break:break-all}
.url-row a:hover{text-decoration:underline;color:var(--green)}

/* alert */
.alert{border-radius:5px;padding:8px 10px;margin-bottom:6px;font-size:11px;line-height:1.6}
.a-red{background:var(--red-dim);border:1px solid rgba(248,81,73,.25);color:var(--red)}
.a-yellow{background:var(--yellow-dim);border:1px solid rgba(227,179,65,.25);color:var(--yellow)}
.a-green{background:var(--green-dim);border:1px solid rgba(61,220,132,.25);color:var(--green)}
.a-info{background:var(--cyan-dim);border:1px solid rgba(88,166,255,.2);color:var(--cyan)}

/* stat grid */
.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(80px,1fr));gap:6px;margin-bottom:10px}
.stat-box{background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:9px;text-align:center}
.stat-n{font-size:20px;font-weight:700;font-family:'JetBrains Mono',monospace}
.stat-l{font-size:8px;color:var(--text3);margin-top:2px;letter-spacing:.5px;text-transform:uppercase}

/* screenshot */
.screenshot-img{width:100%;border-radius:6px;border:1px solid var(--border);display:block;margin-top:8px}
.screenshot-placeholder{background:var(--bg3);border:1px solid var(--border);border-radius:6px;height:200px;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:12px;margin-top:8px;flex-direction:column;gap:8px}

/* welcome */
.welcome{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 24px;text-align:center;gap:12px}
.welcome-icon{font-size:48px;opacity:.15}
.welcome-sub{font-size:12px;color:var(--text3);line-height:1.8;max-width:420px}
.welcome-sub code{color:var(--cyan);background:var(--bg3);padding:1px 4px;border-radius:3px;font-family:'JetBrains Mono',monospace}

/* misc */
@keyframes pulse{0%,100%{opacity:.4}50%{opacity:1}}
.mono{font-family:'JetBrains Mono',monospace}
.c-green{color:var(--green)}.c-red{color:var(--red)}.c-yellow{color:var(--yellow)}
.c-cyan{color:var(--cyan)}.c-purple{color:var(--purple)}.c-dim{color:var(--text2)}.c-dimmer{color:var(--text3)}
.pw{font-family:'JetBrains Mono',monospace;color:var(--red);font-weight:700}
.stolen{font-size:10px;color:var(--text3);padding:2px 0 2px 12px;font-family:'JetBrains Mono',monospace}
.stolen::before{content:"→ ";color:var(--border3)}
.grade-a{color:var(--green)}.grade-b{color:#79c0ff}.grade-c{color:var(--yellow)}.grade-d{color:var(--orange)}.grade-f{color:var(--red)}

/* email stealer card */
.email-stealer{background:var(--red-dim);border:1px solid rgba(248,81,73,.2);border-radius:6px;padding:8px 10px;margin-bottom:6px}
.email-stealer-header{display:flex;align-items:center;gap:8px;margin-bottom:4px}
.email-stealer .email-addr{color:var(--red);font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700}
.email-stealer-details{font-size:10px;color:var(--text2);line-height:1.7}

/* ══ UI v2 UPGRADES ══ */

/* stop button */
.btn-stop{background:var(--red);border-color:var(--red);color:#fff;display:none}
.btn-stop:hover{background:#ff6b64;border-color:#ff6b64}
.btn-stop.on{display:flex}
.btn-stop .stop-ico{width:9px;height:9px;background:#fff;border-radius:2px;display:inline-block}
.scanning .btn-scan,.scanning .btn-fast{display:none}

/* live elapsed timer chip in header */
.hdr-timer{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text2);display:none;align-items:center;gap:6px}
.hdr-timer.on{display:inline-flex}
.hdr-timer .t-dot{width:5px;height:5px;border-radius:50%;background:var(--yellow);animation:pulse .8s infinite}
.hdr-timer.done .t-dot{background:var(--green);animation:none}
.hdr-timer b{color:var(--cyan)}

/* pill toolbar controls */
.pill-ctrls{margin-left:auto;display:flex;gap:5px;align-items:center}
.pill-ctrl{font-family:'JetBrains Mono',monospace;font-size:9px;letter-spacing:.5px;color:var(--text3);background:transparent;border:1px solid var(--border);border-radius:6px;padding:3px 9px;cursor:pointer;transition:all .12s;text-transform:uppercase}
.pill-ctrl:hover{border-color:var(--border3);color:var(--text2)}
.pill-ctrl.danger:hover{border-color:var(--red);color:var(--red)}
.pill-count{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--text3);letter-spacing:.5px}
.pill-count b{color:var(--cyan)}
.pill.err{border-color:var(--red);color:var(--red);background:var(--red-dim)}
.pill.err::after{content:" ✗";font-size:8px}

/* status bar: elapsed + running/done/error segmented counts */
.s-elapsed{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3);margin-left:2px}
.s-elapsed b{color:var(--cyan)}
.s-counts .sc{display:inline-flex;align-items:center;gap:4px;padding:1px 7px;border-radius:20px;border:1px solid var(--border)}
.s-counts .sc-run{color:var(--yellow);border-color:rgba(227,179,65,.3)}
.s-counts .sc-done{color:var(--green);border-color:rgba(61,220,132,.3)}
.s-counts .sc-err{color:var(--red);border-color:rgba(248,81,73,.3)}
.s-cancel{margin-left:8px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--red);cursor:pointer;border:1px solid rgba(248,81,73,.3);border-radius:6px;padding:2px 9px;transition:all .12s;display:none}
.s-cancel.on{display:inline-block}
.s-cancel:hover{background:var(--red-dim)}
.s-export{margin-left:6px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--cyan);cursor:pointer;border:1px solid rgba(88,166,255,.3);border-radius:6px;padding:2px 9px;transition:all .12s;display:none}
.s-export.on{display:inline-block}
.s-export:hover{background:var(--cyan-dim)}

/* running pill spinner */
.pill.running::before{content:"";display:inline-block;width:6px;height:6px;margin-right:4px;border:1.4px solid var(--yellow);border-top-color:transparent;border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}

/* toast notifications */
.toast-wrap{position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none}
.toast{pointer-events:auto;min-width:240px;max-width:360px;background:var(--bg3);border:1px solid var(--border2);border-left:3px solid var(--cyan);border-radius:8px;padding:11px 14px;font-size:12px;color:var(--text);box-shadow:0 8px 28px rgba(0,0,0,.45);animation:toastIn .25s ease both;display:flex;align-items:flex-start;gap:9px;font-family:'JetBrains Mono',monospace}
.toast.out{animation:toastOut .25s ease both}
.toast.t-ok{border-left-color:var(--green)}
.toast.t-warn{border-left-color:var(--yellow)}
.toast.t-err{border-left-color:var(--red)}
.toast .t-ico{font-size:14px;line-height:1;flex-shrink:0}
.toast .t-body b{display:block;font-size:12px;margin-bottom:2px;letter-spacing:.3px}
.toast .t-body span{font-size:10px;color:var(--text2);line-height:1.4}
@keyframes toastIn{from{opacity:0;transform:translateX(24px)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{to{opacity:0;transform:translateX(24px)}}

/* completion summary strip */
.summary{display:none;gap:8px;flex-wrap:wrap;padding:10px 24px;background:var(--bg2);border-bottom:1px solid var(--border)}
.summary.on{display:flex}
.sum-chip{display:flex;align-items:center;gap:6px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text2);background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:5px 10px}
.sum-chip b{font-size:13px;color:var(--text)}
.sum-chip.crit{border-color:rgba(248,81,73,.3)}.sum-chip.crit b{color:var(--red)}
.sum-chip.warn{border-color:rgba(227,179,65,.3)}.sum-chip.warn b{color:var(--yellow)}
.sum-chip.ok{border-color:rgba(61,220,132,.3)}.sum-chip.ok b{color:var(--green)}
.sum-chip .sc-ico{font-size:13px}

/* focus/scan glow on the search wrap while running */
.scanning .search-wrap{border-color:var(--border2);opacity:.7}
#domInput:disabled{cursor:not-allowed}

/* completion modal */
.cmp-overlay{position:fixed;inset:0;background:rgba(3,6,15,.72);backdrop-filter:blur(4px);z-index:10000;display:none;align-items:center;justify-content:center;padding:20px}
.cmp-overlay.on{display:flex;animation:cmpFade .2s ease both}
@keyframes cmpFade{from{opacity:0}to{opacity:1}}
.cmp-modal{position:relative;width:100%;max-width:440px;background:linear-gradient(180deg,var(--bg2),var(--bg3));border:1px solid var(--border2);border-radius:16px;padding:28px 26px 22px;box-shadow:0 24px 70px rgba(0,0,0,.6);text-align:center;animation:cmpPop .25s cubic-bezier(.2,.9,.3,1.2) both}
@keyframes cmpPop{from{opacity:0;transform:translateY(14px) scale(.96)}to{opacity:1;transform:translateY(0) scale(1)}}
.cmp-x{position:absolute;top:12px;right:14px;background:none;border:none;color:var(--text3);font-size:22px;line-height:1;cursor:pointer;padding:2px 6px;border-radius:6px}
.cmp-x:hover{color:var(--text);background:var(--bg)}
.cmp-check{width:56px;height:56px;margin:2px auto 12px;border-radius:50%;background:rgba(61,220,132,.14);border:1.5px solid var(--green);color:var(--green);font-size:30px;display:flex;align-items:center;justify-content:center;animation:cmpCheck .4s ease both}
@keyframes cmpCheck{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}
.cmp-title{font-size:19px;font-weight:700;color:var(--text);letter-spacing:.3px}
.cmp-sub{font-size:12px;color:var(--text2);margin-top:5px;font-family:'JetBrains Mono',monospace}
.cmp-sub b{color:var(--cyan)}
.cmp-stats{display:flex;justify-content:center;gap:7px;flex-wrap:wrap;margin:16px 0 18px}
.cmp-stat{display:flex;flex-direction:column;align-items:center;min-width:56px;padding:8px 10px;background:var(--bg);border:1px solid var(--border);border-radius:9px}
.cmp-stat .n{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:700}
.cmp-stat .l{font-size:8.5px;letter-spacing:.6px;color:var(--text3);text-transform:uppercase;margin-top:2px}
.cmp-actions{display:flex;flex-direction:column;gap:8px}
.cmp-btn{width:100%;padding:11px;border-radius:9px;font-size:13px;font-weight:600;cursor:pointer;border:1px solid var(--border2);transition:all .13s;font-family:inherit}
.cmp-primary{background:linear-gradient(180deg,var(--cyan),#3d7dd8);border-color:var(--cyan);color:#04121f;box-shadow:0 4px 14px rgba(88,166,255,.3)}
.cmp-primary:hover{filter:brightness(1.08);transform:translateY(-1px)}
.cmp-ghost{background:var(--bg3);color:var(--text2)}
.cmp-ghost:hover{background:var(--bg);color:var(--text);border-color:var(--border3)}
</style>
</head>
<body>

<div class="hdr" style="align-items:center">
  <div style="display:flex;align-items:center;gap:18px;flex:1">
    <pre class="kumo-logo">██╗  ██╗██╗   ██╗███╗   ███╗ ██████╗
██║ ██╔╝██║   ██║████╗ ████║██╔═══██╗
█████╔╝ ██║   ██║██╔████╔██║██║   ██║
██╔═██╗ ██║   ██║██║╚██╔╝██║██║   ██║
██║  ██╗╚██████╔╝██║ ╚═╝ ██║╚██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝</pre>
    <div style="display:flex;flex-direction:column;gap:4px;border-left:1px solid var(--border);padding-left:18px">
      <div style="font-size:11px;color:var(--text2);font-family:var(--font-mono)">蜘蛛 · web recon · osint · breach intel</div>
      <div style="display:flex;gap:6px">
        <span class="logo-ver">v2.0</span>
        <span class="logo-ver" id="hdrModCount" style="background:transparent;border-color:var(--border)">modules</span>
        <span class="logo-ver" style="background:transparent;border-color:var(--border)">no key needed</span>
      </div>
    </div>
  </div>
  <div class="hdr-timer" id="hdrTimer"><span class="t-dot"></span><span>elapsed</span> <b id="hdrTimerVal">0.0s</b></div>
  <span class="hdr-right" id="hdrStat"></span>
</div>

<div class="search-bar">
  <span class="search-hint">❯</span>
  <div class="search-wrap">
    <input id="domInput" type="text" placeholder="Enter target domain — e.g. example.com" autocomplete="off" spellcheck="false">
  </div>
  <button class="btn btn-scan" id="scanBtn" onclick="startScan(false)"><span id="scanBtnTxt">SCAN</span></button>
  <button class="btn btn-fast" id="fastBtn" onclick="startScan(true)">⚡ FAST</button>
  <button class="btn btn-stop" id="stopBtn" onclick="stopScan()"><span class="stop-ico"></span> STOP</button>
</div>

<div class="pill-bar" id="pillBar">
  <span class="pill-lbl">MODULES</span>
  <span class="pill-ctrls">
    <span class="pill-count"><b id="activeCount">0</b>/<span id="totalModCount">0</span> active</span>
    <button class="pill-ctrl" id="ctrlAll" onclick="selectAllPills(true)">all</button>
    <button class="pill-ctrl" id="ctrlNone" onclick="selectAllPills(false)">none</button>
    <button class="pill-ctrl danger" id="ctrlReset" onclick="resetScan()">reset</button>
  </span>
</div>
<div class="prog" id="prog"><div class="prog-fill" id="progFill"></div></div>
<div class="status" id="statusBar">
  <div class="s-dot" id="sDot"></div>
  <span class="s-txt" id="sTxt">Ready</span>
  <span class="s-elapsed" id="sElapsed"></span>
  <div class="s-counts" id="sCounts"></div>
  <span class="s-cancel" id="sCancel" onclick="stopScan()">■ stop</span>
  <span class="s-export" id="sReport" onclick="generateReport()" style="color:var(--green);border-color:rgba(61,220,132,.35)">📄 report</span>
  <span class="s-export" id="sExport" onclick="exportResults()">↓ json</span>
</div>

<div class="summary" id="summaryBar"></div>

<div class="toast-wrap" id="toastWrap"></div>

<div class="cmp-overlay" id="cmpOverlay" onclick="if(event.target===this)closeCompletionModal()">
  <div class="cmp-modal" role="dialog" aria-modal="true">
    <button class="cmp-x" onclick="closeCompletionModal()" aria-label="Close">×</button>
    <div class="cmp-check">✓</div>
    <div class="cmp-title">Scan complete</div>
    <div class="cmp-sub" id="cmpSub"></div>
    <div class="cmp-stats" id="cmpStats"></div>
    <div class="cmp-actions">
      <button class="cmp-btn cmp-primary" onclick="generateReport(); closeCompletionModal();">📄 Generate report</button>
      <button class="cmp-btn cmp-ghost" onclick="exportResults();">↓ Export JSON</button>
      <button class="cmp-btn cmp-ghost" onclick="closeCompletionModal()">Dismiss</button>
    </div>
  </div>
</div>

<div class="main-layout">

  <!-- LEFT: scan cards in logical order -->
  <div class="scan-grid" id="scanGrid">
    <div class="welcome" id="welcome">
      <div class="welcome-icon">☠️</div>
      <div class="welcome-sub">Enter a domain to start reconnaissance.<br>Cards stream in as each module completes.<br>Try <code>example.com</code> or <code>target.org</code></div>
    </div>
  </div>

  <!-- RIGHT: sticky dorks + osint panel -->
  <div class="right-panel" id="rightPanel">
    <div>
      <div class="right-section-title">🔍 <span>Google Dorks</span> <span class="badge b-info" style="margin-left:auto">61 queries</span></div>
      <div style="color:var(--text3);font-size:10px;margin-bottom:10px;font-family:'JetBrains Mono',monospace">Click any query to search ·</div>
      <div id="dorksPanel"><div style="color:var(--text3);font-size:11px;text-align:center;padding:20px 0">Run a scan to generate dorks</div></div>
    </div>
    <div style="border-top:1px solid var(--border);padding-top:12px;margin-top:4px">
      <div class="right-section-title">🔗 <span>OSINT Platform Links</span> <span class="badge b-purple" style="margin-left:auto">26 tools</span></div>
      <div id="osintPanel"><div style="color:var(--text3);font-size:11px;text-align:center;padding:20px 0">Run a scan to generate links</div></div>
    </div>
  </div>

</div>

<script>
const MODULES = __MODULES_JSON__;
const PILL_LABELS = {
  'js_secrets':    'js secrets',
  'content_intel': 'content intel',
  'api_fuzzer':    'api fuzzer',
  'favicon':       'favicon',
  'cloud_buckets': 'cloud buckets',
  'nuclei':        'vuln scanner',
  'email_harvest': 'email harvest',
  'breachintel':   'breach intel',
  'wafw00f':       'waf',
  'subdomains':    'subdomains',
};

// ── Logical scan order ──
const SCAN_ORDER = [
  'screenshot',
  'dns','geo','whois',
  'ssl','headers','wafw00f','ports',
  'whatweb','robots','endpoints',
  'nuclei','shodan','censys',
  'subdomains','brute','wayback',
  'breachintel','email_harvest',
  'js_secrets','content_intel','api_fuzzer',
  'favicon','cloud_buckets',
  'dorks','osint'
];

const ICONS = {
  screenshot:'🏢',email_harvest:'📧',dns:'📡',whois:'🌐',ssl:'🔒',subdomains:'🗺️',
  headers:'🛡️',ports:'🚪',whatweb:'🕵️',wafw00f:'🧱',
  nuclei:'🔓',shodan:'🔭',censys:'🔬',breachintel:'💀',endpoints:'🔓',
  geo:'📍',robots:'🤖',wayback:'📚',brute:'🔨',dorks:'🔍',osint:'🔗'
};
const SLOW = new Set(['wayback','brute','subdomains','screenshot','email_harvest','nuclei','cloud_buckets']);

let activeModules = new Set(Object.keys(MODULES));
let scanning = false, completedCount = 0, totalCount = 0, errorCount = 0;
let currentDomain = '';
let scanAbort = null;      // AbortController for the active fetch
let scanId = null;         // unique id shared with the backend for STOP
let scanTimer = null;      // interval handle for the live elapsed clock
let scanStartTs = 0;
let runningSet = new Set(); // modules still in-flight

const pillBar   = document.getElementById('pillBar');
const pillCtrls = pillBar.querySelector('.pill-ctrls');
const scanGrid  = document.getElementById('scanGrid');
const prog      = document.getElementById('prog');
const progFill  = document.getElementById('progFill');
const statusBar = document.getElementById('statusBar');
const sDot      = document.getElementById('sDot');
const sTxt      = document.getElementById('sTxt');
const sCounts   = document.getElementById('sCounts');
const sElapsed  = document.getElementById('sElapsed');
const sCancel   = document.getElementById('sCancel');
const sExport   = document.getElementById('sExport');
const sReport   = document.getElementById('sReport');
const hdrTimer  = document.getElementById('hdrTimer');
const hdrTimerVal = document.getElementById('hdrTimerVal');
const summaryBar= document.getElementById('summaryBar');

// Build module pills in scan order (inserted BEFORE the control cluster)
[...SCAN_ORDER, ...Object.keys(MODULES).filter(m=>!SCAN_ORDER.includes(m))].forEach(id => {
  if (!MODULES[id]) return;
  const p = document.createElement('div');
  p.className = 'pill on'; p.textContent = PILL_LABELS[id]||id; p.dataset.id = id; p.title = MODULES[id];
  p.onclick = () => {
    if (scanning) return;
    activeModules.has(id) ? (activeModules.delete(id), p.classList.remove('on')) : (activeModules.add(id), p.classList.add('on'));
    updateActiveCount();
  };
  pillBar.insertBefore(p, pillCtrls);
});
document.getElementById('totalModCount').textContent = Object.keys(MODULES).length;
document.getElementById('hdrModCount').textContent = Object.keys(MODULES).length + ' modules';
updateActiveCount();

function updateActiveCount(){
  document.getElementById('activeCount').textContent = activeModules.size;
}

function selectAllPills(on){
  if (scanning) return;
  pillBar.querySelectorAll('.pill').forEach(p=>{
    const id=p.dataset.id;
    if(on){ activeModules.add(id); p.classList.add('on'); }
    else { activeModules.delete(id); p.classList.remove('on'); }
  });
  updateActiveCount();
}

function getPill(id){ return pillBar.querySelector(`[data-id="${id}"]`); }
function setPill(id, cls){ const p=getPill(id); if(p){p.classList.remove('on','running','done');p.classList.add(cls);} }
function escH(s){ return s?String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'):''; }
function fmtBytes(n){ if(n===''||n===undefined||n===null) return '—'; n=Number(n); if(isNaN(n)) return '—'; if(n<1024) return n+' B'; if(n<1048576) return (n/1024).toFixed(1)+' KB'; return (n/1048576).toFixed(2)+' MB'; }
function kv(k,v){ return `<div class="kv"><span class="kv-k">${k}</span><span class="kv-v">${v}</span></div>`; }

function getBadges(id, data) {
  if (data.error) return `<span class="badge b-fail">ERROR</span>`;
  const b = [];
  if (id==='headers'&&data.grade){const gc={A:'b-pass',B:'b-info',C:'b-warn',D:'b-warn',F:'b-fail'}[data.grade]||'b-fail';b.push(`<span class="badge ${gc}">${data.grade} · ${Math.round(data.score||0)}%</span>`);}
  if (id==='ports'&&data.open?.length) b.push(`<span class="badge b-info">${data.open.length} open</span>`);
  if (id==='subdomains'){b.push(`<span class="badge b-info">${data.total||0} found</span>`);if(data.alive_count)b.push(`<span class="badge b-pass">${data.alive_count} alive</span>`);if(data.ct_total)b.push(`<span class="badge b-purple">${data.ct_total} CT</span>`);}
  if (id==='brute'&&data.found?.length) b.push(`<span class="badge b-info">${data.found.length} found</span>`);
  if (id==='ssl'&&data.days_left!==undefined) b.push(`<span class="badge ${data.days_left<30?'b-fail':data.days_left<90?'b-warn':'b-pass'}">${data.days_left<0?'EXPIRED':data.days_left+'d left'}</span>`);
  if (id==='shodan'){const s=data.summary||{};if(s.total_cves)b.push(`<span class="badge b-fail">${s.total_cves} CVEs</span>`);if(s.total_ports)b.push(`<span class="badge b-info">${s.total_ports} ports</span>`);}
  if (id==='wafw00f'){const hi=(data.detected||[]).filter(d=>d.confidence==='high'||d.confidence==='medium');b.push(hi.length?`<span class="badge b-warn">${hi[0].waf}</span>`:data.waf_found===false?`<span class="badge b-pass">NO WAF</span>`:`<span class="badge b-info">${(data.detected||[]).length} hits</span>`);}
  if (id==='nuclei'){const c=data.severity_counts||{};if(c.critical)b.push(`<span class="badge b-fail">${c.critical} CRIT</span>`);if(c.high)b.push(`<span class="badge b-warn">${c.high} HIGH</span>`);if(!c.critical&&!c.high&&data.total===0)b.push(`<span class="badge b-pass">CLEAN</span>`);}
  if (id==='endpoints'){const c=data.severity_counts||{};if(c.critical)b.push(`<span class="badge b-fail">${c.critical} CRIT</span>`);if(c.high)b.push(`<span class="badge b-warn">${c.high} HIGH</span>`);if(data.total_found===0)b.push(`<span class="badge b-pass">NONE FOUND</span>`);}
  if (id==='whatweb'&&data.total_detected) b.push(`<span class="badge b-purple">${data.total_detected} techs</span>`);
  if (id==='censys'){const s=data.summary||{};b.push(`<span class="badge b-info">${s.ips_found||0} IPs</span>`);if(s.certs_found)b.push(`<span class="badge b-info">${s.certs_found} certs</span>`);}
  if (id==='geo'&&data.country) b.push(`<span class="badge b-info">${data.country_code||data.country}</span>`);
  if (id==='breachintel'){const s=data.summary||{};const hits=(s.total_infostealer_hits||0)+(s.total_employees_leaked||0);if(s.critical_findings?.length)b.push(`<span class="badge b-fail">${s.critical_findings.length} CRIT</span>`);b.push(hits>0?`<span class="badge b-warn">${hits} leaked</span>`:`<span class="badge b-pass">CLEAN</span>`);}
  if (id==='dns'&&data.email_security){const es=data.email_security;b.push(!es.dmarc?.found?`<span class="badge b-warn">NO DMARC</span>`:`<span class="badge b-pass">DMARC OK</span>`);}
  if (id==='screenshot'&&data.data) b.push(`<span class="badge b-pass">CAPTURED</span>`);
  return b.join('');
}

function renderSkeleton(){return`<div class="sk sk-title"></div><div class="sk sk-line" style="margin-top:8px"></div><div class="sk sk-short"></div>`;}

function renderContent(id, data) {
  if (data.error) return `<div class="alert a-red">⚠ ${escH(data.error)}</div>`;
  switch(id){
  case 'screenshot':{
    let h='';
    // Logo + title row
    if(data.logo_url||data.favicon_url){
      h+=`<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <img src="${escH(data.logo_url||data.favicon_url)}"
             onerror="this.src='${escH(data.favicon_url||'')}';this.onerror=null"
             style="width:48px;height:48px;border-radius:8px;object-fit:contain;background:var(--bg3);border:1px solid var(--border)">
        <div>
          <div style="font-weight:700;font-size:13px;color:var(--text)">${escH(data.title||data.url||'')}</div>
          ${data.description?`<div style="font-size:11px;color:var(--text2);margin-top:3px;line-height:1.5">${escH(data.description)}</div>`:''}
        </div>
      </div>`;
    } else if(data.title){
      h+=kv('Title', `<b>${escH(data.title)}</b>`);
    }
    if(data.description&&!data.logo_url&&!data.favicon_url) h+=kv('Description',`<span class="c-dim">${escH(data.description)}</span>`);
    h+=kv('URL',`<a href="${escH(data.url)}" target="_blank" class="c-cyan">${escH(data.url)}</a>`);
    if(data.cms) h+=kv('CMS',`<span class="badge b-purple">${escH(data.cms)}</span>`);

    // Screenshot
    if(data.data&&data.format==='base64_png'){
      h+=`<img class="screenshot-img" src="data:image/png;base64,${data.data}" alt="Screenshot" style="margin-top:10px">`;
    } else if(data.public_url){
      h+=`<div id="ss-loading" style="color:var(--text3);font-size:10px;font-family:monospace;padding:5px 0">⏳ Loading screenshot...</div>`;
      h+=`<img class="screenshot-img" id="ss-img" crossorigin="anonymous"
            src="${escH(data.public_url)}"
            onload="(function(img){try{var c=document.createElement('canvas');c.width=Math.min(img.naturalWidth,40);c.height=Math.min(img.naturalHeight,40);var ctx=c.getContext('2d');ctx.drawImage(img,0,0);var px=ctx.getImageData(0,0,1,1).data,pm=ctx.getImageData(Math.floor(c.width/2),Math.floor(c.height/2),1,1).data;if(px[0]>240&&px[1]>240&&px[2]>240&&pm[0]>240&&pm[1]>240&&pm[2]>240){img.style.display='none';var el=document.getElementById('ss-loading');if(el)el.textContent='⚠ Screenshot unavailable (site blocked capture)';}else{document.getElementById('ss-loading')?.remove();}}catch(e){document.getElementById('ss-loading')?.remove();}})(this)"
            onerror="document.getElementById('ss-loading').textContent='⚠ Screenshot unavailable'"
            style="margin-top:6px">`;
      // no external link — image shown inline or error message displayed;
    }

    // Ransomware feed
    const rw=data.ransomware||[];
    const rwStatus=data.ransomware_status||'';
    h+='<div class="sec" style="color:var(--red)">☠ Ransomware Feed (ransomware.live)</div>';
    if(rw.length){
      rw.forEach(r=>{
        h+=`<div class="alert a-red" style="margin-bottom:6px">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-weight:700;font-size:12px">${escH(r.group||'')}</span>
            ${r.country?`<span class="badge b-info" style="font-size:9px">${escH(r.country)}</span>`:''}
            <span class="c-dim" style="font-size:10px">${escH(r.date||'')}</span>
          </div>
          ${r.victim?`<div style="font-size:11px;margin-top:3px">Victim: <b>${escH(r.victim)}</b></div>`:''}
          ${r.description?`<div style="font-size:11px;margin-top:3px;color:var(--text2)">${escH(r.description)}</div>`:''}
          ${r.url?`<a href="${escH(r.url)}" target="_blank" style="font-size:10px;color:var(--yellow);margin-top:3px;display:block">View leak post ↗</a>`:''}
        </div>`;
      });
    } else {
      h+=`<div class="alert a-green">✓ No mentions found on ransomware.live</div>`;
    }

    // URLhaus threat feed
    const uh=data.threat_feeds?.urlhaus||null;
    if(uh){
      h+='<div class="sec" style="color:var(--orange)">⚠ URLhaus Threat Feed</div>';
      h+=kv('Status', `<span class="c-red">${escH(uh.status||'')}</span>`);
      if(uh.urls_count) h+=kv('Malicious URLs', `<span class="c-red">${uh.urls_count}</span>`);
    }

    return h;
  }
  case 'dns':{
    let h='';
    if(data.ips?.v4?.length) h+=kv('A (IPv4)',`<span class="c-cyan mono">${data.ips.v4.join(', ')}</span>`);
    if(data.ips?.v6?.length) h+=kv('AAAA (IPv6)',`<span class="mono c-dim" style="font-size:10px">${data.ips.v6[0]}</span>`);
    if(data.records) Object.entries(data.records).forEach(([t,vals])=>{h+=kv(t,`<span class="c-dim mono" style="font-size:10px">${escH(vals.map(v=>v.length>70?v.slice(0,67)+'…':v).join(' · '))}</span>`);});
    const es=data.email_security||{};
    h+='<div class="sec">Email Security</div>';
    const spf=es.spf||{};h+=kv('SPF',spf.found?`<span class="c-green">✓ ${escH(spf.policy)}</span>`:`<span class="c-red">✗ Not found</span>`);
    const dm=es.dmarc||{};h+=kv('DMARC',dm.found?`<span class="c-green">✓ ${escH(dm.policy)}</span>`:`<span class="c-red">✗ Missing — spoofing risk</span>`);
    const dk=es.dkim||{};h+=kv('DKIM',dk.found?`<span class="c-green">✓ selector=${escH(dk.selector)}</span>`:`<span class="c-yellow">⚠ Not found</span>`);
    return h;
  }
  case 'geo':{
    let h='';
    const flag=data.flag||'';
    h+=kv('IP',`<span class="c-cyan mono">${escH(data.ip)}</span>`);
    if(data.hostname) h+=kv('Hostname',`<span class="c-dim">${escH(data.hostname)}</span>`);
    h+=kv('Location',`${flag} ${escH(data.city||'')} ${escH(data.country||'')} ${data.country_code?'<span class="badge b-info" style="font-size:9px">'+data.country_code+'</span>':''}`);
    if(data.region) h+=kv('Region',escH(data.region));
    if(data.lat&&data.lon) h+=kv('Coordinates',`${data.lat}, ${data.lon}`);
    h+=kv('Timezone',escH(data.timezone||''));
    h+=kv('ISP',escH(data.isp||''));
    h+=kv('ASN',`<span class="mono c-dim">${escH(data.asn||'')}</span>`);
    h+=kv('Type',data.is_hosting?'<span class="c-yellow">Hosting / Datacenter</span>':'ISP / Business');
    return h;
  }
  case 'whois':{
    let h='';
    h+=kv('Domain',`<span class="c-cyan">${escH(data.domain)}</span>`);
    if(data.registration) h+=kv('Registered',escH(data.registration));
    if(data.expiration){const days=data.days_until_expiry;const col=days<30?'c-red':days<90?'c-yellow':'c-green';h+=kv('Expires',`<span class="${col}">${escH(data.expiration)} (${days}d)</span>`);}
    if(data.last_changed) h+=kv('Updated',escH(data.last_changed));
    if(data.status?.length) h+=kv('Status',`<span class="c-dim mono" style="font-size:10px">${escH(data.status.join(' · '))}</span>`);
    if(data.nameservers?.length) h+=kv('Nameservers',`<span class="c-dim">${escH(data.nameservers.slice(0,4).join(', '))}</span>`);
    if(data.entities?.length) data.entities.forEach(e=>h+=kv(e.role,escH(e.name)));
    return h;
  }
  case 'ssl':{
    let h='';
    h+=kv('Common Name',`<span class="c-cyan">${escH(data.common_name)}</span>`);
    h+=kv('Issuer',escH(data.issuer));
    h+=kv('Valid Until',escH(data.valid_until));
    if(data.days_left!==null){const d=data.days_left,col=d<0?'c-red':d<30?'c-red':d<90?'c-yellow':'c-green';h+=kv('Validity',`<span class="${col}">${d<0?`EXPIRED ${Math.abs(d)}d ago`:d+'d remaining'}</span>`);}
    h+=kv('Protocol',`<span class="${data.protocol==='TLSv1.3'?'c-green':'c-yellow'}">${escH(data.protocol)}</span>`);
    h+=kv('Cipher',`<span class="mono c-dim" style="font-size:10px">${escH(data.cipher)} (${data.cipher_bits}-bit)</span>`);
    if(data.sans?.length){h+='<div class="sec">Subject Alt Names</div>';h+=data.sans.slice(0,12).map(s=>`<span class="tag">${escH(s)}</span>`).join('')+(data.sans.length>12?`<span class="tag">+${data.sans.length-12} more</span>`:'');}
    return h;
  }
  case 'headers':{
    const gc={A:'grade-a',B:'grade-b',C:'grade-c',D:'grade-d',F:'grade-f'}[data.grade]||'grade-f';
    let h=`<div style="margin-bottom:10px"><span class="mono ${gc}" style="font-size:18px;font-weight:700">${data.grade}</span> <span class="c-dim" style="font-size:11px">· ${Math.round(data.score||0)}% · HTTP ${data.status_code} · ${escH(data.server||'')}</span></div>`;
    h+='<table class="tbl"><thead><tr><th>Header</th><th>Value</th><th></th></tr></thead><tbody>';
    (data.headers||[]).forEach(hdr=>{h+=`<tr><td class="mono" style="font-size:10px;color:${hdr.present?'var(--text)':'var(--text3)'}">${escH(hdr.header)}</td><td style="font-size:10px;color:var(--text2)">${hdr.present?escH((hdr.value||'').slice(0,50)):escH(hdr.description)}</td><td><span class="badge ${hdr.present?'b-pass':'b-fail'}">${hdr.present?'PASS':'FAIL'}</span></td></tr>`;});
    h+='</tbody></table>';
    if(data.disclosure?.length){h+='<div class="sec" style="color:var(--yellow)">Info Disclosure</div>';data.disclosure.forEach(d=>h+=kv(d.header,`<span class="c-yellow">${escH(d.value)}</span>`));}
    return h;
  }
  case 'wafw00f':{
    let h='';
    if(data.normal_status) h+=kv('HTTP Status',data.normal_status);
    if(data.probe_status!==undefined) h+=kv('Probe',`<span class="${data.probe_blocked?'c-red':'c-green'}">${data.probe_status} ${data.probe_blocked?'← BLOCKED':'← passed'}</span>`);
    const det=data.detected||[];
    if(!det.length) return h+`<div class="alert a-green" style="margin-top:8px">✓ Probably no WAF/CDN detected<div style="font-size:10px;margin-top:4px;opacity:.75">Based on header, cookie and active probe analysis.</div></div>`;
    h+=`<div class="sec">Detected (${det.length})</div>`;
    det.forEach(d=>{h+=`<div style="border:1px solid var(--border2);border-radius:6px;padding:9px;margin-bottom:7px"><div style="display:flex;align-items:center;gap:8px;margin-bottom:4px"><span class="mono" style="color:var(--text);font-weight:700">${escH(d.waf)}</span><span class="badge ${{high:'b-fail',medium:'b-warn',low:'b-info'}[d.confidence]||'b-info'}">${d.confidence.toUpperCase()}</span><span class="c-dimmer" style="font-size:10px">score ${d.score}</span></div><div class="c-dimmer" style="font-size:10px">${(d.evidence||[]).map(e=>escH(e)).join(' · ')}</div></div>`;});
    return h;
  }
  case 'ports':{
    const open=data.open||[];
    if(!open.length) return '<div class="c-dim">No open ports detected</div>';
    const sc={critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--green)'};
    let h=`<div class="c-dim" style="margin-bottom:8px;font-size:11px">${open.length} open / ${data.total_scanned} scanned</div>`;
    h+='<table class="tbl"><thead><tr><th>Port</th><th>Service</th><th>Risk</th></tr></thead><tbody>';
    open.forEach(p=>{
      const src=p.source==='shodan_censys'?'<span class="badge b-purple" style="font-size:8px">SHODAN/CENSYS</span>':'';
      const ver=p.version?`<span class="c-yellow" style="font-size:9px;margin-left:4px">${escH(p.version)}</span>`:'';
      const banner=p.banner?`<div style="font-size:9px;color:var(--text3);font-family:monospace;margin-top:2px;padding:2px 4px;background:var(--bg);border-radius:3px">${escH(p.banner.slice(0,120))}</div>`:'';
      h+=`<tr>
        <td class="mono c-cyan">${p.port} ${src}</td>
        <td>${escH(p.service)}${ver}${banner}</td>
        <td style="color:${sc[p.risk]||'var(--text)'};font-weight:700;font-size:10px">${p.risk.toUpperCase()}</td>
      </tr>`;
    });
    h+='</tbody></table>';
    const crit=open.filter(p=>p.risk==='critical'||p.risk==='high');
    if(crit.length){h+='<div class="sec" style="color:var(--red)">Critical Alerts</div>';crit.forEach(p=>h+=`<div class="alert a-red" style="font-size:11px;padding:5px 8px;margin:3px 0">Port ${p.port} (${escH(p.service)}) — ${p.risk}</div>`);}
    return h;
  }

  case 'whatweb':{
    let h='';
    if(data.url) h+=kv('URL',`<span class="c-cyan" style="font-size:10px">${escH(data.url)}</span>`);
    if(data.total_detected) h+=kv('Signatures Hit',`<span class="c-cyan">${data.total_detected}</span>`);
    const det=data.detected||{};
    if(typeof det==='object'&&!Array.isArray(det)) Object.entries(det).forEach(([cat,items])=>{h+=`<div class="sec">${escH(cat)}</div>`;items.forEach(i=>h+=`<span class="tag">${escH(i)}</span>`);});
    return h||'<div class="c-dim">No technologies detected</div>';
  }
  case 'robots':{
    let h='';
    if(data.robots){h+=`<div class="alert a-green" style="margin-bottom:8px">✓ robots.txt (${data.robots.count} rules)</div>`;const s=data.robots.disallowed?.filter(d=>d.sensitive)||[];if(s.length){h+='<div class="sec" style="color:var(--yellow)">⚠ Sensitive Disallowed Paths</div>';s.forEach(d=>h+=`<div class="c-yellow" style="font-size:11px;padding:2px 0">⚠ ${escH(d.path)}</div>`);}const allowed=data.robots.allowed||[];if(allowed.length){h+='<div class="sec">✓ Allowed Paths</div>';allowed.slice(0,15).forEach(a=>h+=`<div style="font-size:11px;padding:2px 0;color:${a.interesting?'var(--yellow)':'var(--text2)'}">${a.interesting?'⚠ ':''} ${escH(a.path)}</div>`);}const n=data.robots.disallowed?.filter(d=>!d.sensitive)||[];if(n.length){h+='<div class="sec">Other Disallowed</div>';n.slice(0,12).forEach(d=>h+=`<div class="c-dim" style="font-size:11px;padding:1px 0">${escH(d.path)}</div>`);}}
    else h+=`<div class="c-dim">No robots.txt found</div>`;
    if(data.security_txt) h+=`<div class="alert a-green" style="margin-top:8px">✓ security.txt at ${escH(data.security_txt.path)}</div>`;
    else h+=`<div class="alert a-yellow" style="margin-top:8px">⚠ No security.txt — no vulnerability disclosure contact</div>`;
    if(data.sitemaps?.length){h+='<div class="sec">Sitemaps</div>';data.sitemaps.forEach(s=>h+=`<div class="c-cyan" style="font-size:11px;padding:2px 0">${escH(s)}</div>`);}
    return h;
  }
  case 'endpoints':{
    let h='';
    const c=data.severity_counts||{};
    const sc={critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--text2)',info:'var(--cyan)'};
    const parts=Object.entries(c).map(([s,n])=>`<span style="color:${sc[s]};font-weight:700;font-family:monospace">${s.toUpperCase()}: ${n}</span>`).join('  ');
    if(parts) h+=`<div style="margin-bottom:10px;font-size:11px">${parts}</div>`;
    h+=`<div class="c-dim" style="margin-bottom:8px;font-size:11px">${data.total_found||0} found / ${data.total_probed||0} probed</div>`;
    const findings=data.findings||[];
    if(!findings.length) return h+'<div class="alert a-green">✓ No sensitive endpoints found</div>';
    h+='<table class="tbl"><thead><tr><th>Severity</th><th>Endpoint</th><th>Status</th><th>Size</th></tr></thead><tbody>';
    findings.forEach(f=>{h+=`<tr><td style="color:${sc[f.severity]||'var(--text)'};font-weight:700;font-size:9px">${(f.severity||'').toUpperCase()}</td><td><div style="font-size:11px">${escH(f.name)}</div><div class="mono c-dim" style="font-size:9px">${escH(f.path)}</div></td><td>${(f.status===301||f.status===302)?`<span class="c-dim" style="font-size:10px">[${f.status}]</span>`:`<a href="${escH(f.url)}" target="_blank" class="c-cyan" style="font-size:10px">[${f.status}]</a>`}</td><td class="mono c-dim" style="font-size:9px;white-space:nowrap">${fmtBytes(f.size)}</td></tr>`;});
    h+='</tbody></table>';
    return h;
  }
  case 'nuclei':{
    let h='';
    // Built-in vulnerability scanner — no external tools needed
    const c=data.severity_counts||{};
    const sc={critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--green)',info:'var(--cyan)'};
    const parts=Object.entries(c).map(([s,n])=>`<span style="color:${sc[s]};font-weight:700;font-family:monospace">${s.toUpperCase()}: ${n}</span>`).join('  ');
    if(parts) h+=`<div style="margin-bottom:10px;font-size:11px">${parts}</div>`;
    const findings=data.findings||[];
    if(!findings.length) return h+'<div class="alert a-green">✓ No findings</div>';
    h+='<table class="tbl"><thead><tr><th>Sev</th><th>Finding</th><th>URL</th><th>Size</th></tr></thead><tbody>';
    findings.forEach(f=>{
      const cveLink=f.cve?`<a href="https://nvd.nist.gov/vuln/detail/${escH(f.cve)}" target="_blank" class="badge b-fail" style="font-size:8px;margin-left:4px">${escH(f.cve)}</a>`:'';
      const srcBadge=f.source==='exploit_template'?'<span class="badge b-warn" style="font-size:8px">EXPLOIT</span>':f.source==='version_detection'?'<span class="badge b-purple" style="font-size:8px">VERSION</span>':f.source==='recent_cve'?'<span class="badge b-fail" style="font-size:8px">RECENT CVE</span>':f.source==='wp_plugin_cve'?'<span class="badge b-info" style="font-size:8px">WP PLUGIN</span>':'';
      h+=`<tr>
        <td style="color:${sc[f.severity]||'var(--text)'};font-weight:700;font-size:9px">${(f.severity||'').toUpperCase()}</td>
        <td style="font-size:11px">
          ${escH(f.name||f.path||'')} ${cveLink} ${srcBadge}
          ${f.description?`<div style="font-size:9px;color:var(--text2);margin-top:2px">${escH(f.description)}</div>`:''}
        </td>
        <td class="mono" style="font-size:9px;color:var(--cyan)">
          ${(f.status===301||f.status===302)
            ? `<span class="c-dim">${escH((f.url||'').slice(0,40))}</span> <span style="font-size:9px">[${f.status}]</span>`
            : `<a href="${escH(f.url||f.matched_at||'#')}" target="_blank" style="color:var(--cyan)">${escH((f.url||'').slice(0,40))}</a> ${f.status?`[${f.status}]`:''}`}
        </td>
        <td class="mono c-dim" style="font-size:9px;white-space:nowrap">${fmtBytes(f.size)}</td>
      </tr>`;
    });;
    h+='</tbody></table>';
    return h;
  }
  case 'shodan':{
    let h='';
    h+=kv('Source',data.api_key_used?'<span class="c-green">Full API</span>':'InternetDB (free, no key)');
    const s=data.summary||{};
    h+=kv('Ports',`<span class="c-cyan">${s.total_ports||0}</span>`);
    h+=kv('CVEs',`<span class="${(s.total_cves||0)>0?'c-red':'c-green'}">${s.total_cves||0}</span>`);
    if(s.critical_cves?.length){h+='<div class="sec" style="color:var(--red)">Critical CVEs</div>';s.critical_cves.forEach(c=>h+=`<div class="alert a-red" style="font-size:10px;padding:5px 8px;margin:3px 0">⚠ ${escH(c.cve)} · CVSS ${c.cvss} · ${escH(c.ip)}</div>`);}
    Object.entries(data.ips||{}).forEach(([ip,ipd])=>{
      h+=`<div class="sec">IP: ${escH(ip)} <a href="https://www.shodan.io/host/${escH(ip)}" target="_blank" class="c-cyan" style="font-size:9px;margin-left:8px">View on Shodan ↗</a></div>`;
      if(ipd.ports?.length) h+=kv('Ports',`<span class="mono c-cyan" style="font-size:10px">${ipd.ports.join(', ')}</span>`);
      if(ipd.os) h+=kv('OS',escH(ipd.os));
      if(ipd.tags?.length) h+=kv('Tags',`<span class="c-dim">${ipd.tags.join(', ')}</span>`);
      const cves=ipd.cves||[];
      if(cves.length){h+=`<div class="sec">CVEs (${cves.length})</div><table class="tbl"><thead><tr><th>CVE</th><th>CVSS</th><th>Description</th></tr></thead><tbody>`;const list=typeof cves[0]==='object'?cves:cves.map(id=>({id,cvss:null,summary:''}));list.slice(0,12).forEach(cv=>{
  const cvss=cv.cvss||'';
  const col=parseFloat(cvss)>=9?'var(--red)':parseFloat(cvss)>=7?'var(--orange)':parseFloat(cvss)>=4?'var(--yellow)':'var(--text2)';
  const sev=cv.severity?`<span style='color:${col};font-size:9px;font-weight:700;margin-left:4px'>${cv.severity.toUpperCase()}</span>`:'';
  const kev=cv.kev?'<span class="badge b-fail" style="font-size:8px;margin-left:3px">KEV</span>':'';
  const epss=cv.epss?`<span style='color:var(--text3);font-size:8px;margin-left:4px'>EPSS:${cv.epss}</span>`:'';
  h+=`<tr>
    <td class="mono" style="font-size:10px"><a href="https://nvd.nist.gov/vuln/detail/${escH(cv.id||cv)}" target="_blank" style="color:var(--cyan)">${escH(cv.id||cv)}</a>${sev}${kev}</td>
    <td style="color:${col};font-size:10px;font-weight:700">${cvss}${epss}</td>
    <td style="font-size:10px;color:var(--text2)">${escH(cv.summary||'')}</td>
  </tr>`;
});h+='</tbody></table>';}
    });
    return h;
  }
  case 'censys':{
    let h='';
    h+=kv('API',data.api_used?'<span class="c-green">Full API</span>':'Free (links + certs)');
    h+=kv('IPs',`<span class="c-cyan">${(data.ips||[]).join(', ')||'none'}</span>`);
    const links=data.links||{};
    if(Object.keys(links).length){h+='<div class="sec">Search Links</div>';[['Platform',links.search_platform],['Hosts',links.hosts_by_domain],['Certs',links.certificates]].forEach(([l,u])=>{if(u)h+=`<div class="url-row"><span class="url-lbl">${l}</span><a href="${escH(u)}" target="_blank">${escH(u.length>45?u.slice(0,42)+'…':u)}</a></div>`;});(links.hosts_by_ip||[]).forEach(u=>h+=`<div class="url-row"><span class="url-lbl">Host</span><a href="${escH(u)}" target="_blank">${escH(u)}</a></div>`);}
    const certs=data.certificates||[];
    if(certs.length){h+=`<div class="sec">Certs (${certs.length})</div><table class="tbl"><thead><tr><th>CN</th><th>Issuer</th><th>Expires</th></tr></thead><tbody>`;certs.slice(0,8).forEach(c=>{let iss=c.issuer||'';if(iss.includes(','))iss=iss.split(',')[0].replace(/[OCN]=/g,'');h+=`<tr><td class="mono c-cyan" style="font-size:10px">${escH(c.common_name||'')}</td><td class="c-dim" style="font-size:10px">${escH(iss.slice(0,20))}</td><td class="mono c-dim" style="font-size:10px">${escH(c.not_after||'')}</td></tr>`;});h+='</tbody></table>';}
    return h||'<div class="c-dim">No data — check links above</div>';
  }

  case 'subdomains':{
    let h='';
    if(data.sources_failed?.length) h+=kv('Failed',`<span class="c-yellow">${escH(data.sources_failed.join(', '))}</span>`);
    h+=kv('Total Found',`<span class="c-cyan">${data.total||0}</span>`);
    h+=kv('Alive',`<span class="c-green">${data.alive_count||0}</span>`);
    if(data.sensitive?.length){h+='<div class="sec" style="color:var(--red)">⚠ Sensitive Subdomains</div>';data.sensitive.slice(0,10).forEach(s=>h+=`<div class="alert a-red" style="padding:4px 8px;margin:3px 0;font-size:11px">⚠ ${escH(s.subdomain)} <span class="c-dim">${escH(s.ip)}</span></div>`);}
    if(data.ct_sensitive?.length){h+='<div class="sec" style="color:var(--yellow)">⚠ Sensitive from CT Logs</div>';data.ct_sensitive.slice(0,10).forEach(s=>h+=`<div class="c-yellow" style="font-size:11px;padding:2px 0">⚠ ${escH(s)}</div>`);}
    if(data.ct_total) h+=kv('CT Log Total', `<span class="c-purple">${data.ct_total} unique subdomains in Certificate Transparency logs</span>`);
    const alive=(data.resolved||[]).filter(r=>r.alive);
    if(alive.length){h+='<div class="sec">Live Subdomains</div><table class="tbl"><thead><tr><th>Subdomain</th><th>IP</th><th></th></tr></thead><tbody>';alive.slice(0,30).forEach(r=>{h+=`<tr><td class="mono c-cyan" style="font-size:10px">${escH(r.subdomain)}</td><td class="mono c-dim" style="font-size:10px">${escH(r.ip)}</td><td>${r.sensitive?'<span class="badge b-warn">sensitive</span>':''}</td></tr>`;});if(alive.length>30)h+=`<tr><td colspan="3" class="c-dim" style="font-size:10px">… +${alive.length-30} more</td></tr>`;h+='</tbody></table>';}
    return h||'<div class="c-dim">No subdomains found</div>';
  }
  case 'brute':{
    const found=data.found||[];
    let h='';
    if(data.wildcard_detected){
      h+=`<div class="alert a-yellow" style="margin-bottom:8px">⚠ Wildcard DNS detected (${escH(data.wildcard_ip||'')}) — results filtered to exclude wildcard matches</div>`;
    }
    h+=`<div class="c-dim" style="margin-bottom:8px;font-size:11px">${found.length} real subdomains / ${data.total_checked} checked</div>`;
    if(!found.length) return h+'<div class="c-dim">No subdomains found</div>';
    h+='<table class="tbl"><thead><tr><th>Subdomain</th><th>IP</th></tr></thead><tbody>';
    found.forEach(r=>h+=`<tr><td class="mono c-cyan" style="font-size:10px">${escH(r.subdomain)}</td><td class="mono c-dim" style="font-size:10px">${escH(r.ip||'')}</td></tr>`);
    h+='</tbody></table>';
    return h;
  }
  case 'wayback':{
    let h='';
    if(data.snapshot) h+=kv('Latest',`<span class="c-green">${escH(data.snapshot.timestamp)}</span>`);
    h+=kv('Range',escH(data.range||'N/A'));
    h+=kv('URLs',`<span class="c-cyan">${data.total||0}</span>`);
    if(data.interesting?.length){h+='<div class="sec" style="color:var(--yellow)">Interesting Archived Paths</div>';data.interesting.forEach(u=>h+=`<div class="c-yellow" style="font-size:11px;padding:2px 0;word-break:break-all">⚠ ${escH(u)}</div>`);}
    return h;
  }
  case 'breachintel':{
    let h='';
    const s=data.summary||{};
    h+='<div class="stat-row">';
    [[s.total_infostealer_hits||0,'c-red','Infostealer'],[s.total_employees_leaked||0,'c-yellow','Employees'],[s.total_clients_leaked||0,'c-yellow','Clients'],[s.total_emails_found||0,'c-cyan','Emails']].forEach(([n,c,l])=>h+=`<div class="stat-box"><div class="stat-n ${c}">${n}</div><div class="stat-l">${l}</div></div>`);
    h+='</div>';
    if(s.critical_findings?.length){h+='<div class="sec" style="color:var(--red)">⚠ Critical Findings</div>';s.critical_findings.slice(0,8).forEach(c=>h+=`<div class="alert a-red" style="margin-bottom:5px"><div style="font-weight:700;font-size:10px">[${escH(c.source||'')}] ${escH(c.type||'')}</div><div style="margin-top:2px;font-size:11px">${escH(c.detail||'')}</div></div>`);}

    // Hudson Rock — only show if API returned data
    const hr=(data.sources||{}).hudsonrock||{};
    const hrHasData=(hr.total_employees||0)+(hr.total_clients||0)>0;
    if(hrHasData||(hr.status&&hr.status!=='ok'&&hr.status!=='no_data')){
      h+='<div class="sec">🕵 Hudson Rock Cavalier</div>';
      if(hr.status&&hr.status!=='ok'&&hr.status!=='no_data'){
        h+=`<div class="alert a-yellow" style="font-size:10px">⚠ ${escH(hr.status)}</div>`;
      }
      if(hrHasData){
        h+='<div class="stat-row" style="margin-bottom:10px">';
        h+=`<div class="stat-box"><div class="stat-n c-red">${hr.total_employees||0}</div><div class="stat-l">Employees</div></div>`;
        h+=`<div class="stat-box"><div class="stat-n c-yellow">${hr.total_clients||0}</div><div class="stat-l">Clients</div></div>`;
        h+=`<div class="stat-box"><div class="stat-n c-orange">${hr.third_parties||0}</div><div class="stat-l">3rd Parties</div></div>`;
        h+=`<div class="stat-box"><div class="stat-n c-dim" style="font-size:12px">${hr.total_records||0}</div><div class="stat-l">Records</div></div>`;
        h+='</div>';
        if(hr.last_employee_compromised) h+=kv('Last Employee Hit', `<span class="c-red">${escH(hr.last_employee_compromised)}</span>`);
        if(hr.last_user_compromised)     h+=kv('Last Client Hit',   `<span class="c-yellow">${escH(hr.last_user_compromised)}</span>`);
      }

    // Stealer families
    const sf=hr.stealer_families||{};
    if(Object.keys(sf).length){
      h+='<div class="sec">Malware Families</div>';
      h+='<div style="display:flex;gap:6px;flex-wrap:wrap">';
      Object.entries(sf).sort((a,b)=>b[1]-a[1]).forEach(([name,count])=>{
        h+=`<span class="badge b-fail" style="font-size:10px">${escH(name)}: ${count}</span>`;
      });
      h+='</div>';
    }

    // Antivirus coverage
    const av=hr.antiviruses||{};
    if(av.list?.length){
      h+='<div class="sec">Antivirus on Victim Machines</div>';
      h+=kv('Total Machines', av.total||0);
      h+=kv('Had AV (found%)', `${av.found_pct||0}% protected · ${av.free_pct||0}% free AV`);
      h+='<div style="margin-top:5px">';
      av.list.slice(0,6).forEach(a=>h+=`<span class="tag">${escH(a.name)} (${a.count})</span>`);
      h+='</div>';
    }

    // Password strength
    const ep=hr.employee_passwords||{};
    if(ep.total){
      h+='<div class="sec">Employee Password Strength</div>';
      h+=`<div style="display:flex;gap:6px;flex-wrap:wrap">
        <span class="badge b-fail">Too Weak: ${ep.too_weak||0}</span>
        <span class="badge b-warn">Weak: ${ep.weak||0}</span>
        <span class="badge b-info">Medium: ${ep.medium||0}</span>
        <span class="badge b-pass">Strong: ${ep.strong||0}</span>
      </div>`;
    }

    // Stolen URLs (employees)
    const empUrls=hr.employee_urls||[];
    if(empUrls.length){
      h+='<div class="sec">Stolen Employee URLs</div>';
      h+='<table class="tbl"><thead><tr><th>URL</th><th>Hits</th></tr></thead><tbody>';
      empUrls.slice(0,10).forEach(u=>{
        h+=`<tr><td class="mono c-cyan" style="font-size:10px">${escH((u.url||u).slice(0,60))}</td><td class="c-dim" style="font-size:10px">${u.occurrence||''}</td></tr>`;
      });
      h+='</tbody></table>';
    }

    // Client/user stolen URLs
    const cliUrls=hr.client_urls||[];
    if(cliUrls.length){
      h+='<div class="sec">Stolen Client URLs</div>';
      h+='<table class="tbl"><thead><tr><th>URL</th><th>Hits</th></tr></thead><tbody>';
      cliUrls.slice(0,6).forEach(u=>{
        h+=`<tr><td class="mono c-yellow" style="font-size:10px">${escH((u.url||u).slice(0,60))}</td><td class="c-dim" style="font-size:10px">${u.occurrence||''}</td></tr>`;
      });
      h+='</tbody></table>';
    }

    // Third-party domains
    const tpd=hr.third_party_domains||[];
    if(tpd.length){
      h+='<div class="sec">Third-Party Domains (also compromised)</div>';
      h+='<div style="display:flex;gap:4px;flex-wrap:wrap">';
      tpd.slice(0,12).forEach(d=>h+=`<span class="tag" style="font-size:9px">${escH(d.domain||d)} (${d.occurrence||''})</span>`);
      h+='</div>';
    }

    // Email stealer checks
    const emailChecks=hr.email_stealer_checks||[];
    if(emailChecks.length){
      h+='<div class="sec" style="color:var(--red)">Per-Email Stealer Check</div>';
      emailChecks.forEach(ec=>{
        if(ec.compromised){
          h+=`<div class="email-stealer">
            <div class="email-stealer-header">
              <span class="email-addr">${escH(ec.email)}</span>
              <span class="badge b-fail">COMPROMISED</span>
            </div>
            <div class="email-stealer-details">Corp services: <b>${ec.total_corporate_services}</b> · Personal: <b>${ec.total_user_services}</b></div>`;
          (ec.stealers||[]).slice(0,2).forEach(st=>{
            h+=`<div style="margin-top:5px;padding:5px;background:rgba(0,0,0,.2);border-radius:4px;font-size:10px;color:var(--text2)">
              <span class="c-yellow">${escH(st.computer_name||'')}</span> · ${escH(st.operating_system||'')} · <span class="c-red">${escH(st.date_compromised||'')}</span>
              ${st.ip?` · IP: <span class="c-cyan">${escH(st.ip)}</span>`:''}
              ${(st.antiviruses||[]).length?`<br>AV: ${st.antiviruses.map(a=>escH(a)).join(', ')}`:''}
              ${(st.top_passwords||[]).length?`<br>Passwords: ${st.top_passwords.map(p=>escH(p)).join(' · ')}`:''}
              ${(st.top_logins||[]).length?`<br>Logins: ${st.top_logins.map(l=>escH(l)).join(' · ')}`:''}
            </div>`;
          });
          h+='</div>';
        } else {
          h+=`<span class="mono c-dim" style="font-size:11px">${escH(ec.email)}</span> <span class="badge b-pass">CLEAN</span><br>`;
        }
      });
    }

    // Per-email stealer results (Hudson Rock — chiasmodon + proxynova emails)
    const hrPE=(data.sources||{}).hr_per_email||{};
    const hrPEEmails=Object.keys(hrPE);
    if(hrPEEmails.length){
      const infected=hrPEEmails.filter(e=>hrPE[e]?.compromised);
      h+=`<div class="sec" style="color:${infected.length?'var(--red)':'var(--green)'}">☠ Stealer Check — ${infected.length} infected / ${hrPEEmails.length} checked</div>`;
      [...hrPEEmails].sort((a,b)=>(hrPE[b].compromised?1:0)-(hrPE[a].compromised?1:0)).forEach(em=>{
        const st=hrPE[em]||{};
        const inf=st.compromised;
        if(!inf) return; // skip CLEAN — user only cares about infected
        h+=`<div class="alert a-red" style="margin-bottom:5px;padding:6px 10px">
          <div style="font-weight:700;font-size:11px;font-family:monospace">${escH(em)}
            <span class="badge ${inf?'b-fail':'b-pass'}" style="margin-left:6px">${inf?'☠ INFECTED':'✓ CLEAN'}</span>
          </div>
          ${inf?`<div style="font-size:10px;color:var(--text2);margin-top:5px;line-height:1.9">
            ${st.date_compromised?`📅 <b style="color:var(--yellow)">${escH(st.date_compromised)}</b>&nbsp; `:''}
            ${st.computer_name?`💻 <b>${escH(st.computer_name)}</b>&nbsp; `:''}
            ${st.operating_system?`🖥 ${escH((st.operating_system||'').slice(0,35))}`:''}
            ${st.malware_path?`<br>🦠 <span style="font-family:monospace;font-size:9px;color:var(--orange)">${escH(st.malware_path.slice(0,80))}</span>`:''}
            ${(st.antiviruses||[]).length?`<br>🛡 AV: <span style="color:var(--text3)">${st.antiviruses.map(a=>escH(a)).join(' · ')}</span>`:''}
            ${(st.top_passwords||[]).length?`<br>🔑 Passwords: ${st.top_passwords.map(p=>`<span style="color:var(--yellow);font-family:monospace">${escH(p)}</span>`).join(' · ')}`:''}
            ${st.total_corporate_services?`<br>🏢 <b>${st.total_corporate_services}</b> corp stolen · 👤 <b>${st.total_user_services||0}</b> personal`:''}</div>`:''}
        </div>`;
      });
    }

    // Chiasmodon
    const chia=(data.sources||{}).chiasmodon||{};
    h+='<div class="sec">🗄 Chiasmodon (chiasmodon.online)</div>';
    const emp=chia.employee_logins||[];
    if(emp.length){
      h+=`<div class="c-green" style="font-size:11px;margin-bottom:6px">✓ ${emp.length} employee credential entries</div>`;
      h+='<table class="tbl"><thead><tr><th>Email</th><th>Password</th><th>Date</th></tr></thead><tbody>';
      emp.slice(0,20).forEach(l=>{
        const email = String(l.email||l.username||l.user||'').slice(0,35);
        const pw    = String(l.password||'');
        const pd    = pw ? pw.slice(0,3)+'●'.repeat(Math.max(0,pw.length-3)) : '—';
        const dt    = String(l.date||l.date_compromised||'').slice(0,10);
        const country = l.country ? ` (${escH(l.country)})` : '';
        h+=`<tr>
          <td class="mono c-cyan" style="font-size:10px">${escH(email)}${country}</td>
          <td class="pw" style="font-size:10px">${escH(pd)}</td>
          <td class="c-dim" style="font-size:10px">${escH(dt)}</td>
        </tr>`;
      });
      if(emp.length>20) h+=`<tr><td colspan="3" class="c-dim" style="font-size:10px">… +${emp.length-20} more</td></tr>`;
      h+='</tbody></table>';
    } else {
      h+=`<div class="c-dim" style="font-size:11px">${escH(chia.employee_status||'No results')}</div>`;
    }

    // ProxyNova COMB
    const pn=(data.sources||{}).proxynova_comb||{};
    h+='<div class="sec">💥 ProxyNova COMB (3.2B credentials)</div>';
    h+=kv('Records',`<span class="c-red mono">${(pn.total_count||0).toLocaleString()}</span>`);
    h+=kv('Emails',`<span class="c-yellow">${pn.unique_count||0}</span>`);
    if(pn.weak_password_count) h+=kv('Weak Passwords',`<span class="c-red">${pn.weak_password_count}</span>`);
    const parsed=pn.parsed||[];
    if(parsed.length){h+=`<div class="c-green" style="font-size:11px;margin:5px 0">✓ ${parsed.length} entries</div><table class="tbl"><thead><tr><th>Email</th><th>Password (partial)</th><th>Len</th></tr></thead><tbody>`;parsed.slice(0,20).forEach(e=>h+=`<tr><td class="mono c-cyan" style="font-size:10px">${escH(e.email||'')}</td><td class="pw" style="font-size:10px">${escH(e.password||'—')}</td><td class="c-dim" style="font-size:10px">${e.pw_len||'—'}</td></tr>`);if(parsed.length>20)h+=`<tr><td colspan="3" class="c-dim" style="font-size:10px">… +${parsed.length-20} more</td></tr>`;h+='</tbody></table>';if(pn.sample_passwords?.length){h+='<div class="sec">Password Patterns</div>';h+=pn.sample_passwords.map(p=>`<span class="tag" style="font-family:monospace">${escH(p)}</span>`).join('');}}
    else h+=`<div class="c-dim" style="font-size:11px;margin-top:4px">No COMB entries found</div>`;

    // HIBP
    const hibp=(data.sources||{}).hibp||{};
    h+='<div class="sec">📧 HaveIBeenPwned</div>';
    const dbr=hibp.domain_breaches||[];
    if(dbr.length){h+='<table class="tbl"><thead><tr><th>Breach</th><th>Date</th><th>Accounts</th></tr></thead><tbody>';dbr.forEach(b=>h+=`<tr><td class="c-red" style="font-weight:700;font-size:11px">${escH(b.title||b.name)}</td><td class="c-dim" style="font-size:10px">${escH(b.breach_date||'')}</td><td class="c-yellow mono" style="font-size:10px">${(b.pwn_count||0).toLocaleString()}</td></tr>`);h+='</tbody></table>';}
    else h+=`<div class="c-green" style="font-size:11px">✓ No domain breaches (${hibp.total_known_breaches||0} indexed)</div>`;

    // Stealer data from email harvester (if available in global scan results)
    const ehData=window._scanResults&&window._scanResults['email_harvest'];
    if(ehData&&(ehData.compromised||0)>0){
      h+='<div class="sec" style="color:var(--red)">☠ Compromised Emails (from Email Harvester)</div>';
      (ehData.emails||[]).filter(e=>e.compromised).forEach(e=>{
        const st=e.stealer||{};
        h+=`<div class="email-stealer">
          <div class="email-stealer-header">
            <span class="email-addr">${escH(e.email)}</span>
            <span class="badge b-fail">INFECTED</span>
          </div>
          <div class="email-stealer-details">
            📅 ${escH(st.date_compromised||'')} &nbsp;
            💻 ${escH(st.computer_name||'?')} &nbsp;
            🖥 ${escH((st.operating_system||'').slice(0,20))}
            ${st.malware_path?`<br>🦠 <span style="font-family:monospace;font-size:9px">${escH(st.malware_path.slice(0,70))}</span>`:''}
            ${(st.top_passwords||[]).length?`<br>🔑 Passwords: <span class="c-red">${st.top_passwords.map(p=>escH(p)).join(' · ')}</span>`:''}
            ${st.total_corporate_services?`<br>🏢 <b>${st.total_corporate_services}</b> corp services · 👤 <b>${st.total_user_services||0}</b> personal`:''}
          </div>
        </div>`;
      });
    }

    // Investigation links
    const olinks=data.osint_links||{};
    if(Object.keys(olinks).length){h+='<div class="sec">🔗 Investigation Links</div>';Object.entries(olinks).forEach(([lbl,url])=>h+=`<div class="url-row"><span class="url-lbl">${escH(lbl)}</span><a href="${escH(url)}" target="_blank">${escH(url.length>50?url.slice(0,47)+'…':url)}</a></div>`);}
    }  // close if(hrHasData||status)
    return h||'<div class="c-dim">No breach data found</div>';
  }
  case 'email_harvest':{
    let h='';
    // Merge all email sources — ONLY @domain emails, never external addresses
    const allEmails=new Set();
    const scanDomain=(data.domain||currentDomain||'').toLowerCase();
    const isDomainEmail=e=>e&&e.endsWith('@'+scanDomain);
    // From email_harvest itself (already scoped to @domain)
    (data.emails||[]).forEach(em=>{const s=typeof em==='string'?em:(em.email||'');if(isDomainEmail(s.toLowerCase()))allEmails.add(s.toLowerCase());});
    // From breachintel of THIS scan only — filter strictly to @domain
    const bi=window._scanResults&&window._scanResults['breachintel'];
    if(bi){
      const chia=(bi.sources||{}).chiasmodon||{};
      // ONLY employee logins — not client logins (clients use external emails)
      (chia.employee_logins||[]).forEach(l=>{
        const e=(l.email||l.username||'').toLowerCase();
        if(isDomainEmail(e))allEmails.add(e);
      });
      (chia.emails||[]).forEach(e=>{const s=(typeof e==='string'?e:(e.email||'')).toLowerCase();if(isDomainEmail(s))allEmails.add(s);});
      ((bi.sources||{}).proxynova_comb||{}).unique_emails?.forEach(e=>{const s=(e||'').toLowerCase();if(isDomainEmail(s))allEmails.add(s);});
    }
    const emailList=[...allEmails].sort();
    h+=`<div class="stat-row" style="margin-bottom:10px"><div class="stat-box"><div class="stat-n c-cyan">${emailList.length}</div><div class="stat-l">Emails Found</div></div></div>`;
    if(data.sources_used?.length) h+=kv('Scraped from',`<span class="c-dim" style="font-size:10px">${escH(data.sources_used.join(' · '))}</span>`);
    if(!emailList.length) return h+'<div class="c-dim" style="margin-top:10px">No emails found</div>';
    h+='<div class="sec">📧 Discovered Emails</div>';
    h+='<div style="display:flex;flex-direction:column;gap:2px">';
    emailList.forEach(em=>{
      h+=`<div style="font-family:monospace;font-size:11px;padding:4px 6px;color:var(--cyan);border-bottom:1px solid var(--border)">📧 ${escH(em)}</div>`;
    });
    h+='</div>';
    return h;
  }
  case 'favicon':{
    let h='';
    if(data.error&&!data.favicon_found) return h+`<div class="alert a-yellow">${escH(data.error)}</div>`;
    if(!data.favicon_found) return h+'<div class="c-dim">No favicon found</div>';
    h+=`<div class="stat-row" style="margin-bottom:10px">
      <div class="stat-box"><div class="stat-n c-cyan" style="font-size:16px">🎯</div><div class="stat-l">Found</div></div>
      <div class="stat-box"><div class="stat-n c-dim" style="font-size:11px">${data.size_bytes||0}B</div><div class="stat-l">Size</div></div>
      ${data.technology?`<div class="stat-box"><div class="stat-n c-yellow" style="font-size:11px">${escH(data.technology)}</div><div class="stat-l">Tech</div></div>`:''}
    </div>`;
    if(data.favicon_url) h+=kv('URL',`<a href="${escH(data.favicon_url)}" target="_blank" class="c-cyan" style="font-size:10px">${escH(data.favicon_url)}</a>`);
    if(data.hash_shodan!==null&&data.hash_shodan!==undefined) h+=kv('Shodan hash',`<span class="mono c-yellow">${data.hash_shodan}</span>`);
    if(data.hash_md5) h+=kv('MD5 hash',`<span class="mono c-dim" style="font-size:10px">${data.hash_md5}</span>`);
    const links=data.search_links||{};
    if(Object.keys(links).length){
      h+='<div class="sec" style="margin-top:10px">🔍 Cross-Infrastructure Search</div>';
      h+='<div style="display:flex;flex-direction:column;gap:5px;margin-top:6px">';
      Object.entries(links).forEach(([name,url])=>{
        h+=`<a href="${escH(url)}" target="_blank" style="display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;text-decoration:none">
          <span style="color:var(--text2);font-size:10px;min-width:70px">${escH(name)}</span>
          <span style="color:var(--cyan);font-size:10px">Search servers with this favicon →</span>
        </a>`;
      });
      h+='</div>';
    }
    return h;
  }

  case 'cloud_buckets':{
    let h='';
    const exposed=data.exposed||[];
    const critical=exposed.filter(b=>b.severity==='critical');
    const medium=exposed.filter(b=>b.severity==='medium');
    h+=`<div class="stat-row" style="margin-bottom:10px">
      <div class="stat-box"><div class="stat-n ${critical.length?'c-red':'c-green'}">${critical.length}</div><div class="stat-l">Public</div></div>
      <div class="stat-box"><div class="stat-n ${medium.length?'c-yellow':'c-dim'}">${medium.length}</div><div class="stat-l">Exists (private)</div></div>
      <div class="stat-box"><div class="stat-n c-dim" style="font-size:11px">${data.checked||0}</div><div class="stat-l">Probed</div></div>
    </div>`;
    if(!exposed.length) return h+'<div class="alert a-green">✓ No exposed cloud buckets found</div>';
    if(critical.length){
      h+='<div class="sec" style="color:var(--red)">☠ Publicly Accessible Buckets</div>';
      critical.forEach(b=>{
        h+=`<div class="alert a-red" style="margin-bottom:6px;padding:8px 12px">
          <div style="font-weight:700;font-size:11px;font-family:monospace">${escH(b.bucket)}</div>
          <div style="font-size:10px;color:var(--text2);margin-top:4px">
            <span class="badge" style="background:rgba(248,81,73,.15);border:1px solid var(--red);font-size:9px;margin-right:6px">${escH(b.provider)}</span>
            ${escH(b.status)}
          </div>
          ${b.files_exposed?`<div style="font-size:10px;color:var(--orange);margin-top:3px">📂 ${b.files_exposed} objects visible</div>`:''}
          ${(b.sample_files||[]).length?`<div style="font-size:9px;font-family:monospace;color:var(--text3);margin-top:3px">${b.sample_files.map(f=>escH(f)).join(' · ')}</div>`:''}
          <a href="${escH(b.url)}" target="_blank" style="display:block;margin-top:5px;font-size:9px;color:var(--cyan);font-family:monospace">${escH(b.url)}</a>
        </div>`;
      });
    }
    if(medium.length){
      h+='<div class="sec" style="margin-top:8px">Bucket Names Confirmed (access denied)</div>';
      h+='<table class="tbl"><thead><tr><th>Bucket</th><th>Provider</th><th></th></tr></thead><tbody>';
      medium.forEach(b=>{
        h+=`<tr>
          <td class="mono" style="font-size:10px">${escH(b.bucket)}</td>
          <td style="font-size:10px;color:var(--text2)">${escH(b.provider)}</td>
          <td><a href="${escH(b.url)}" target="_blank" style="font-size:9px;color:var(--cyan)">→</a></td>
        </tr>`;
      });
      h+='</tbody></table>';
    }
    return h;
  }

  case 'js_secrets':{
    let h='';
    const secrets=data.secrets||[];
    const files=data.js_files||[];

    // Summary stats
    const bysev={critical:0,high:0,medium:0,low:0};
    secrets.forEach(s=>{if(bysev[s.severity]!==undefined)bysev[s.severity]++;});
    h+=`<div class="stat-row" style="margin-bottom:12px">
      <div class="stat-box"><div class="stat-n ${secrets.length?'c-red':'c-green'}" style="font-size:28px">${secrets.length}</div><div class="stat-l">Total Secrets</div></div>
      ${bysev.critical?`<div class="stat-box"><div class="stat-n c-red">${bysev.critical}</div><div class="stat-l">Critical</div></div>`:''}
      ${bysev.high?`<div class="stat-box"><div class="stat-n c-orange">${bysev.high}</div><div class="stat-l">High</div></div>`:''}
      ${bysev.medium?`<div class="stat-box"><div class="stat-n c-yellow">${bysev.medium}</div><div class="stat-l">Medium</div></div>`:''}
      <div class="stat-box"><div class="stat-n c-dim">${files.length}</div><div class="stat-l">JS Files</div></div>
    </div>`;

    if(data.error) return h+`<div class="alert a-yellow">${escH(data.error)}</div>`;
    if(!secrets.length) return h+'<div class="alert a-green">✓ No secrets found in JS files</div>';

    const sc={'critical':'var(--red)','high':'var(--orange)','medium':'var(--yellow)','low':'var(--text2)'};

    h+='<div class="sec" style="color:var(--red)">⚠ Secrets Detected (clear text)</div>';

    secrets.forEach(s=>{
      h+=`<div style="margin-bottom:10px;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-left:3px solid ${sc[s.severity]||'var(--border)'};border-radius:5px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <span style="font-size:9px;font-weight:700;color:${sc[s.severity]}">${(s.severity||'').toUpperCase()}</span>
          <span style="font-size:11px;color:var(--text);font-weight:600">${escH(s.type)}</span>
          <span class="mono" style="font-size:9px;color:var(--text2);margin-left:auto">${escH(s.file)}</span>
        </div>
        <div style="font-family:monospace;font-size:12px;color:var(--cyan);background:var(--bg);padding:6px 8px;border-radius:4px;word-break:break-all;margin-bottom:${s.line?'5':'0'}px">${escH(s.value)}</div>
        ${s.line?`<div style="font-family:monospace;font-size:9px;color:var(--text3);padding:4px 8px;background:rgba(0,0,0,.3);border-radius:3px;word-break:break-all;white-space:pre-wrap">${escH(s.line.slice(0,120))}</div>`:''}
      </div>`;
    });

    if(files.length){
      h+='<div class="sec" style="margin-top:10px">JS Files Scanned</div>';
      h+='<div style="display:flex;flex-direction:column;gap:2px">';
      files.slice(0,15).forEach(f=>{
        h+=`<div class="mono c-dim" style="font-size:9px;padding:2px 4px">${escH(f.split('?')[0].slice(-70))}</div>`;
      });
      h+='</div>';
    }
    return h;
  }

  case 'content_intel':{
    let h='';
    if(data.error) return `<div class="alert a-yellow">${escH(data.error)}</div>`;
    const cat=data.categories||{};
    const cnt=data.counts||{};
    const ss=data.sources_scanned||{};
    h+=`<div class="stat-row" style="margin-bottom:12px">
      <div class="stat-box"><div class="stat-n ${data.total?'c-cyan':'c-dim'}" style="font-size:28px">${data.total||0}</div><div class="stat-l">Items Extracted</div></div>
      <div class="stat-box"><div class="stat-n c-dim">${ss.js_files||0}</div><div class="stat-l">JS Files</div></div>
      <div class="stat-box"><div class="stat-n c-dim">${ss.inline_scripts||0}</div><div class="stat-l">Inline</div></div>
    </div>`;
    if(!data.total) return h+'<div class="alert a-green">✓ Nothing interesting extracted from HTML/JS</div>';

    // group config: key -> [label, color, icon, isSensitive]
    const groups=[
      ['databases','Database URIs','var(--red)','🗄️'],
      ['cloud_storage','Cloud Storage','var(--orange)','☁️'],
      ['api_endpoints','API Endpoints','var(--purple)','🔌'],
      ['sensitive','Sensitive Info','var(--red)','🔐'],
      ['urls_external','External Sources','var(--yellow)','🌐'],
      ['urls_internal','Internal URLs','var(--cyan)','🔗'],
      ['endpoints','Endpoints / Paths','var(--cyan)','📍'],
      ['internal_hosts','Internal Hosts','var(--orange)','🏠'],
      ['ip_addresses','IP Addresses','var(--text2)','🔢'],
      ['emails','Emails','var(--text2)','✉️'],
    ];
    const sevc={critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--text2)'};
    groups.forEach(([key,label,color,ico])=>{
      const items=cat[key]||[];
      if(!items.length) return;
      h+=`<div class="sec" style="color:${color};margin-top:10px">${ico} ${label} <span class="c-dim" style="font-weight:400">(${items.length}${cnt[key]>=200?'+':''})</span></div>`;
      h+='<div style="display:flex;flex-direction:column;gap:3px">';
      items.slice(0,40).forEach(it=>{
        const kindBadge=it.kind?`<span class="badge" style="font-size:8px;background:var(--bg3);border:1px solid var(--border);color:${sevc[it.severity]||'var(--text2)'}">${escH(it.kind)}</span>`:'';
        const src=it.source?`<span class="mono c-dim" style="font-size:8px;margin-left:auto;white-space:nowrap;flex-shrink:0">${escH(it.source)}</span>`:'';
        const topRow=(kindBadge||src)?`<div style="display:flex;align-items:center;gap:6px;margin-bottom:3px">${kindBadge}${src}</div>`:'';
        h+=`<div style="font-family:monospace;font-size:10px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:5px 8px">
          ${topRow}<div style="color:var(--text);overflow-wrap:anywhere;white-space:pre-wrap;line-height:1.45">${escH(it.value)}</div>
        </div>`;
      });
      if(items.length>40) h+=`<div class="c-dim" style="font-size:9px;padding:2px 4px">+ ${items.length-40} more…</div>`;
      h+='</div>';
    });
    return h;
  }

  case 'api_fuzzer':{
    let h='';
    const eps=data.endpoints||[];
    const gql=data.graphql;
    h+=`<div class="stat-row" style="margin-bottom:10px">
      <div class="stat-box"><div class="stat-n ${data.total?'c-red':'c-green'}">${data.total||0}</div><div class="stat-l">Endpoints Found</div></div>
      <div class="stat-box"><div class="stat-n c-dim">${data.base_found||'—'}</div><div class="stat-l">API Base</div></div>
    </div>`;
    if(data.error) return h+`<div class="alert a-yellow">${escH(data.error)}</div>`;
    if(gql){
      const gc=gql.severity==='high'?'var(--orange)':'var(--yellow)';
      h+=`<div class="alert" style="border:1px solid var(--border);margin-bottom:8px;padding:7px 10px">
        <div style="font-weight:700;font-size:11px;color:${gc}">⚡ GraphQL — ${escH(gql.path)} <span class="mono c-dim" style="font-size:9px;font-weight:400">${fmtBytes(gql.size)}</span></div>
        <div style="font-size:10px;color:var(--text2);margin-top:3px">${escH(gql.detail)}</div>
      </div>`;
    }
    if(!eps.length&&!gql) return h+'<div class="alert a-green">✓ No API endpoints found</div>';
    if(eps.length){
      const sc={'critical':'var(--red)','high':'var(--orange)','medium':'var(--yellow)','low':'var(--text2)'};
      h+='<div class="sec">API Endpoints</div>';
      h+='<table class="tbl"><thead><tr><th>SEV</th><th>Endpoint</th><th>Name</th><th>Status</th><th>Size</th></tr></thead><tbody>';
      eps.forEach(e=>{
        h+=`<tr>
          <td style="color:${sc[e.severity]||'var(--text)'};font-weight:700;font-size:9px">${(e.severity||'').toUpperCase()}</td>
          <td class="mono" style="font-size:10px;color:var(--cyan)">${escH(e.path)}</td>
          <td style="font-size:10px">${escH(e.name)}</td>
          <td><span class="badge" style="background:var(--bg3);border:1px solid var(--border);font-size:9px">[${e.status}]</span></td>
          <td class="mono c-dim" style="font-size:9px;white-space:nowrap">${fmtBytes(e.size)}</td>
        </tr>`;
      });
      h+='</tbody></table>';
    }
    return h;
  }

  default:
    return `<pre style="font-size:10px;white-space:pre-wrap;color:var(--text2)">${escH(JSON.stringify(data,null,2).slice(0,500))}</pre>`;
  }
}

// ── Dorks panel renderer (right sidebar) ──
function renderDorksPanel(data, domain) {
  if (!data || typeof data !== 'object') return;
  const panel = document.getElementById('dorksPanel');
  panel.innerHTML = '';
  let count = 0;
  Object.entries(data).forEach(([cat, items]) => {
    const catDiv = document.createElement('div');
    catDiv.innerHTML = `<div class="sec">${escH(cat)}</div>`;
    items.forEach(([label, query]) => {
      count++;
      const idx = count;
      const item = document.createElement('div');
      item.className = 'dork-item';
      item.innerHTML = `
        <div class="dork-lbl">[${String(idx).padStart(2,'0')}] ${escH(label)}</div>
        <div class="dork-q" onclick="window.open('https://www.google.com/search?q='+encodeURIComponent(this.textContent),'_blank')" title="Click to open in Google">${escH(query)}</div>`;
      catDiv.appendChild(item);
    });
    panel.appendChild(catDiv);
  });
}

// ── OSINT panel renderer (right sidebar) ──
function renderOsintPanel(data) {
  if (!data || typeof data !== 'object') return;
  const panel = document.getElementById('osintPanel');
  panel.innerHTML = '';
  Object.entries(data).forEach(([cat, items]) => {
    const catDiv = document.createElement('div');
    catDiv.innerHTML = `<div class="sec">${escH(cat)}</div>`;
    items.forEach(([label, url]) => {
      catDiv.innerHTML += `<div class="url-row"><span class="url-lbl">${escH(label)}</span><a href="${escH(url)}" target="_blank">${escH(url.length>50?url.slice(0,47)+'…':url)}</a></div>`;
    });
    panel.appendChild(catDiv);
  });
}

// ── Dork result count fetcher (client-side, opens Google) ──

// ── Screenshot fallback chain ──
function tryFallbackScreenshot(img, cardId, fallbacks, siteUrl) {
  if (!fallbacks || fallbacks.length === 0) {
    // All fallbacks exhausted — show error div
    img.style.display = 'none';
    const errDiv = document.getElementById(cardId+'-err');
    if (errDiv) errDiv.style.display = 'flex';
    return;
  }
  const next = fallbacks[0];
  const rest = fallbacks.slice(1);
  img.onerror = () => tryFallbackScreenshot(img, cardId, rest, siteUrl);
  img.src = next;
}

// ── Card creation ──
function createCard(id, desc) {
  const card = document.createElement('div');
  card.className = 'card';
  card.id = 'card-'+id;
  card.innerHTML = `
    <div class="c-head" onclick="toggleCard('${id}')">
      <span class="c-icon">${ICONS[id]||'📋'}</span>
      <span class="c-title">${escH(desc)}</span>
      <div class="c-badges" id="badges-${id}"></div>
      <span class="c-chev open" id="chev-${id}">▶</span>
    </div>
    <div class="c-body open" id="body-${id}">${renderSkeleton()}</div>`;
  return card;
}

function toggleCard(id) {
  document.getElementById('body-'+id)?.classList.toggle('open');
  document.getElementById('chev-'+id)?.classList.toggle('open');
}

function fillCard(id, data) {
  const body = document.getElementById('body-'+id);
  const badges = document.getElementById('badges-'+id);
  if (body) body.innerHTML = renderContent(id, data);
  if (badges) badges.innerHTML = getBadges(id, data);
}

// ── Scan ──
function newScanId(){ return (crypto.randomUUID?crypto.randomUUID():Date.now()+'-'+Math.random().toString(16).slice(2)); }

async function startScan(fast) {
  const domain = document.getElementById('domInput').value.trim();
  if (!domain || scanning) return;
  scanning = true; currentDomain = domain;
  window._scanResults = {};
  completedCount = 0; errorCount = 0;
  runningSet.clear();

  const myId = scanId = newScanId();
  scanAbort = new AbortController();

  // ── enter scanning UI mode ──
  document.body.classList.add('scanning');
  document.getElementById('stopBtn').classList.add('on');
  const scanBtn = document.getElementById('scanBtn');
  const scanBtnTxt = document.getElementById('scanBtnTxt');
  scanBtn.disabled = true; scanBtn.classList.add('busy');
  scanBtnTxt.textContent = 'SCANNING…';
  document.getElementById('domInput').blur();

  document.getElementById('welcome')?.remove();
  scanGrid.innerHTML = '';
  summaryBar.classList.remove('on'); summaryBar.innerHTML = '';
  document.getElementById('dorksPanel').innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:20px 0">Generating dorks…</div>';
  document.getElementById('osintPanel').innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:20px 0">Generating links…</div>';

  const mods = [...SCAN_ORDER.filter(m => activeModules.has(m)), ...Object.keys(MODULES).filter(m => activeModules.has(m) && !SCAN_ORDER.includes(m))];
  const toRun = fast ? mods.filter(m => !SLOW.has(m)) : mods;
  totalCount = toRun.length;
  toRun.forEach(m => runningSet.add(m));

  prog.classList.add('on'); progFill.style.width = '0%';
  statusBar.classList.add('on'); sDot.className = 's-dot';
  sCancel.classList.add('on'); sExport.classList.remove('on'); sReport.classList.remove('on');
  sTxt.innerHTML = `Scanning <b>${escH(domain)}</b> — ${toRun.length} modules in parallel`;
  startTimer();
  updateCounts();

  // Reset pills to running for active modules
  pillBar.querySelectorAll('.pill').forEach(p => { p.classList.remove('done','running','err','on'); if(activeModules.has(p.dataset.id)) p.classList.add('on'); });

  // Pre-create cards in logical order (skip dorks/osint — they go in right panel)
  toRun.filter(id => id !== 'dorks' && id !== 'osint').forEach(id => {
    scanGrid.appendChild(createCard(id, MODULES[id]));
    setPill(id, 'running');
  });
  if(toRun.includes('dorks')) setPill('dorks','running');
  if(toRun.includes('osint')) setPill('osint','running');

  try {
    const resp = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({domain, modules: toRun, fast, scan_id: myId}),
      signal: scanAbort.signal
    });
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      if (scanId !== myId) break;   // a new scan/reset superseded this one
      buffer += decoder.decode(value, {stream: true});
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;   // skip heartbeats/comments
        try {
          const msg = JSON.parse(line.slice(6));
          if (msg.type === 'done') {
            runningSet.delete(msg.module);
            completedCount++;
            const isErr = !!(msg.data && msg.data.error);
            if (isErr) errorCount++;
            setPill(msg.module, isErr ? 'err' : 'done');

            if(!window._scanResults) window._scanResults={};
            window._scanResults[msg.module]=msg.data;

            if (msg.module === 'dorks') {
              renderDorksPanel(msg.data, domain);
            } else if (msg.module === 'osint') {
              renderOsintPanel(msg.data);
            } else {
              fillCard(msg.module, msg.data);
            }
            if(msg.module==='email_harvest'&&window._scanResults&&window._scanResults['breachintel']){
              fillCard('breachintel', window._scanResults['breachintel']);
            }

            progFill.style.width = (completedCount/totalCount*100)+'%';
            const still = runningSet.size;
            sTxt.innerHTML = `Scanning <b>${escH(domain)}</b> — ${completedCount}/${totalCount} done${still?` · ${still} running`:''}`;
            updateCounts();
          } else if (msg.type === 'complete') {
            finalizeComplete(domain, msg.duration, msg.timed_out);
          } else if (msg.type === 'stopped') {
            // backend acknowledged a stop it initiated (rare) — just tidy up
            finalizeComplete(domain, msg.duration, false);
          }
        } catch(e){}
      }
    }
  } catch(e) {
    if (e.name === 'AbortError' || scanId !== myId) return;   // user stopped — handled elsewhere
    sTxt.innerHTML = `<span style="color:var(--red)">Scan failed: ${escH(e.message)}</span>`;
    toast('err','Scan failed', e.message);
  }

  // Stream ended. If it wasn't stopped/superseded and we never got 'complete',
  // finalize defensively so nothing is left showing "running".
  if (scanId === myId && scanning) {
    finalizeComplete(domain, hdrTimerVal.textContent, false);
  }
}

// ── Stop a running scan and reset everything ──
async function stopScan() {
  if (!scanning) return;
  const sid = scanId;
  scanId = null;              // invalidate the in-flight loop
  try { scanAbort?.abort(); } catch(e){}
  try {
    await fetch('/api/stop', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({scan_id: sid})
    });
  } catch(e){}
  resetScanUI();
  toast('warn','Scan stopped','Everything reset — ready for a new scan');
}

// ── Reset button: stop if running, then wipe back to a clean slate ──
function resetScan() {
  if (scanning) { stopScan(); return; }
  resetScanUI();
  toast('ok','Reset','Ready for a new scan');
}

// ── Teardown shared by stop + reset ──
function resetScanUI() {
  scanning = false;
  document.body.classList.remove('scanning');
  document.getElementById('cmpOverlay').classList.remove('on');
  document.getElementById('stopBtn').classList.remove('on');
  const scanBtn = document.getElementById('scanBtn');
  scanBtn.disabled = false; scanBtn.classList.remove('busy');
  document.getElementById('scanBtnTxt').textContent = 'SCAN';
  stopTimer();
  runningSet.clear();
  scanAbort = null; scanId = null;

  prog.classList.remove('on'); progFill.style.width = '0%';
  statusBar.classList.remove('on'); sDot.className = 's-dot';
  sCancel.classList.remove('on'); sExport.classList.remove('on'); sReport.classList.remove('on');
  sElapsed.textContent = ''; sCounts.innerHTML = '';
  summaryBar.classList.remove('on'); summaryBar.innerHTML = '';
  hdrTimer.classList.remove('on','done');
  document.getElementById('hdrStat').innerHTML = '';

  scanGrid.innerHTML = `<div class="welcome" id="welcome"><div class="welcome-icon">☠️</div><div class="welcome-sub">Enter a domain to start reconnaissance.<br>Cards stream in as each module completes.<br>Try <code>example.com</code> or <code>target.org</code></div></div>`;
  document.getElementById('dorksPanel').innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:20px 0">Run a scan to generate dorks</div>';
  document.getElementById('osintPanel').innerHTML = '<div style="color:var(--text3);font-size:11px;text-align:center;padding:20px 0">Run a scan to generate links</div>';
  window._scanResults = {};

  pillBar.querySelectorAll('.pill').forEach(p => { p.classList.remove('running','done','err','on'); if(activeModules.has(p.dataset.id)) p.classList.add('on'); });
}

// ── Natural completion finalize (keeps results on screen) ──
function finalizeComplete(domain, duration, timedOut) {
  scanning = false;
  document.body.classList.remove('scanning');
  document.getElementById('stopBtn').classList.remove('on');
  const scanBtn = document.getElementById('scanBtn');
  scanBtn.disabled = false; scanBtn.classList.remove('busy');
  document.getElementById('scanBtnTxt').textContent = 'SCAN';
  sCancel.classList.remove('on');
  stopTimer();
  scanAbort = null;

  progFill.style.width = '100%';
  sDot.className = 's-dot done';
  hdrTimer.classList.add('done');

  // Defensive: resolve any pill still visually "running".
  pillBar.querySelectorAll('.pill.running').forEach(p => { p.classList.remove('running'); p.classList.add('done'); });

  sTxt.innerHTML = `<b>${escH(domain)}</b> — scan ${timedOut?'finished (some modules timed out)':'complete'} in ${duration}`;
  document.getElementById('hdrStat').innerHTML = `<span>${escH(domain)}</span> · ${completedCount}/${totalCount} · ${duration}`;
  sExport.classList.add('on');
  sReport.classList.add('on');
  buildSummary();
  showCompletionModal(domain, duration, timedOut);
}

// ── Completion modal ("scan finished — generate a report?") ──
function showCompletionModal(domain, duration, timedOut) {
  const R = window._scanResults || {};
  // severity tally across findings-bearing modules
  const t = {critical:0, high:0, medium:0, low:0};
  const bump = arr => (arr||[]).forEach(f => { const s=(f.severity||'').toLowerCase(); if(s in t) t[s]++; });
  bump(R.nuclei?.findings); bump(R.endpoints?.findings); bump(R.api_fuzzer?.endpoints); bump(R.js_secrets?.secrets);
  const totalFindings = t.critical+t.high+t.medium+t.low;

  document.getElementById('cmpSub').innerHTML =
    `<b>${escH(domain)}</b> · ${completedCount}/${totalCount} modules · ${duration}` +
    (timedOut ? ' · some timed out' : '');

  const stat = (n, l, c) => `<div class="cmp-stat"><div class="n" style="color:${c}">${n}</div><div class="l">${l}</div></div>`;
  document.getElementById('cmpStats').innerHTML =
    stat(totalFindings, 'findings', 'var(--text)') +
    (t.critical ? stat(t.critical, 'critical', 'var(--red)') : '') +
    (t.high ? stat(t.high, 'high', 'var(--orange)') : '') +
    (errorCount ? stat(errorCount, 'errors', 'var(--yellow)') : '');

  document.getElementById('cmpOverlay').classList.add('on');
}

function closeCompletionModal() {
  document.getElementById('cmpOverlay').classList.remove('on');
}

// ── Live elapsed clock ──
function startTimer() {
  scanStartTs = Date.now();
  hdrTimer.classList.remove('done'); hdrTimer.classList.add('on');
  const tick = () => {
    const s = ((Date.now()-scanStartTs)/1000).toFixed(1)+'s';
    hdrTimerVal.textContent = s;
    sElapsed.innerHTML = `· <b>${s}</b>`;
  };
  tick();
  scanTimer = setInterval(tick, 100);
}
function stopTimer() { if (scanTimer) { clearInterval(scanTimer); scanTimer = null; } }

// ── Completion summary chips ──
function buildSummary() {
  const r = window._scanResults || {};
  const chips = [];
  const add = (cls, ico, val, lbl) => chips.push(`<div class="sum-chip ${cls}"><span class="sc-ico">${ico}</span><b>${val}</b> ${lbl}</div>`);
  add('', '📦', `${completedCount}/${totalCount}`, 'modules');
  let crit = 0, high = 0;
  const nc = r.nuclei?.severity_counts || {}; crit += nc.critical||0; high += nc.high||0;
  const ec = r.endpoints?.severity_counts || {}; crit += ec.critical||0; high += ec.high||0;
  const cves = r.shodan?.summary?.total_cves || 0;
  if (crit) add('crit', '☠', crit, 'critical');
  if (high) add('warn', '▲', high, 'high');
  if (cves) add('crit', '🐛', cves, 'CVEs');
  const ports = r.ports?.open?.length || 0; if (ports) add('warn', '🚪', ports, 'open ports');
  const subs = r.subdomains?.total || 0; if (subs) add('', '🗺️', subs, 'subdomains');
  const bs = r.breachintel?.summary || {}; const leaks = (bs.total_infostealer_hits||0)+(bs.total_employees_leaked||0);
  if (leaks) add('crit', '💀', leaks, 'leaked creds');
  const grade = r.headers?.grade; if (grade) add((grade==='A'||grade==='B')?'ok':'warn', '🛡️', grade, 'headers');
  if (errorCount) add('warn', '⚠', errorCount, errorCount===1?'error':'errors');
  summaryBar.innerHTML = chips.join('');
  summaryBar.classList.add('on');
}

// ── Export results as JSON ──
function exportResults() {
  const data = window._scanResults || {};
  if (!Object.keys(data).length) { toast('warn','Nothing to export','Run a scan first'); return; }
  const payload = { domain: currentDomain, generated: new Date().toISOString(), modules: data };
  const blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `kumo_${(currentDomain||'scan').replace(/[^a-z0-9.\-]/gi,'_')}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('ok','Exported', a.download);
}

// ── Generate a standalone HTML security report ──
function generateReport() {
  const R = window._scanResults || {};
  if (!Object.keys(R).length) { toast('warn','Nothing to report','Run a scan first'); return; }

  const esc = escH;
  const sevRank = {critical:0, high:1, medium:2, low:3, info:4};
  const sevColor = {critical:'#e5484d', high:'#f76808', medium:'#e3b341', low:'#8b949e', info:'#3b82f6'};
  const SKIP_KEYS = new Set(['html','raw','body','screenshot','logo_url','favicon','content','snapshot',
    'parsed','api_data','ip_data','json','sources_failed','q','per_page','page','normal_status','probe_status']);
  const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
  const pretty = k => esc(String(k).replace(/_/g,' ').replace(/\b\w/g, c => c.toUpperCase()));
  const pick = (o, ...keys) => { for (const k of keys){ if (o && o[k]!=null && o[k]!=='') return o[k]; } return null; };

  function fmtVal(v){
    if (v==null || v==='') return '<span class="muted">—</span>';
    if (typeof v==='boolean') return v ? '<span class="ok">✓ yes</span>' : '<span class="muted">✗ no</span>';
    if (typeof v==='number') return String(v);
    if (typeof v==='string'){ const s = v.length>400 ? v.slice(0,400)+'…' : v; return esc(s); }
    return esc(JSON.stringify(v).slice(0,200));
  }

  function tableFromArray(arr){
    if (!arr.length) return '';
    const objRows = arr.filter(isObj);
    if (!objRows.length){
      const shown = arr.slice(0,300);
      return '<div class="chips">' + shown.map(x=>`<span class="chip">${esc(String(x))}</span>`).join('') + '</div>' +
             (arr.length>300 ? `<div class="muted">+ ${arr.length-300} more</div>` : '');
    }
    const keys = [];
    objRows.slice(0,80).forEach(o => Object.keys(o).forEach(k => { if(!keys.includes(k) && !SKIP_KEYS.has(k)) keys.push(k); }));
    const cols = keys.slice(0,7);
    const rows = arr.slice(0,80);
    let h = '<table><thead><tr>' + cols.map(k=>`<th>${pretty(k)}</th>`).join('') + '</tr></thead><tbody>';
    rows.forEach(o=>{
      h += '<tr>' + cols.map(k=>{
        let v = isObj(o) ? o[k] : '';
        if (isObj(v) || Array.isArray(v)) v = JSON.stringify(v).slice(0,90);
        return `<td>${fmtVal(v)}</td>`;
      }).join('') + '</tr>';
    });
    h += '</tbody></table>';
    if (arr.length>80) h += `<div class="muted">+ ${arr.length-80} more rows</div>`;
    return h;
  }

  function kvFromObject(obj, depth){
    depth = depth || 0;
    const scalars = [], complex = [];
    Object.keys(obj).forEach(k=>{
      if (SKIP_KEYS.has(k)) return;
      const v = obj[k];
      if (v==null || v==='') return;
      if (Array.isArray(v)){ if (v.length) complex.push([k,v]); }
      else if (isObj(v)){ if (Object.keys(v).length) complex.push([k,v]); }
      else scalars.push([k,v]);
    });
    let h = '';
    if (scalars.length){
      h += '<div class="kv-grid">' + scalars.map(([k,v]) =>
        `<div class="kv"><div class="kv-k">${pretty(k)}</div><div class="kv-v">${fmtVal(v)}</div></div>`).join('') + '</div>';
    }
    if (depth < 2) complex.forEach(([k,v])=>{
      h += `<h4>${pretty(k)} <span class="muted">(${Array.isArray(v)?v.length:'obj'})</span></h4>`;
      h += Array.isArray(v) ? tableFromArray(v) : kvFromObject(v, depth+1);
    });
    return h || '<div class="muted">No data</div>';
  }

  function renderAny(data){
    if (data==null) return '<div class="muted">No data</div>';
    if (Array.isArray(data)) return tableFromArray(data);
    if (isObj(data)) return kvFromObject(data, 0);
    return `<div>${fmtVal(data)}</div>`;
  }

  // ── collect findings (vuln + endpoints + api) ──
  const rows = [];
  const push = (mod, f) => rows.push({
    mod, severity: (f.severity||'info').toLowerCase(),
    name: f.name || f.path || '—', url: f.url || f.matched_at || '',
    status: (f.status===''||f.status==null) ? '' : f.status, size: f.size,
    cve: f.cve || (/(CVE-\d{4}-\d+)/.exec(f.description||'')||[])[1] || '',
    desc: f.description || ''
  });
  (R.nuclei?.findings||[]).forEach(f => push('Vuln Scan', f));
  (R.endpoints?.findings||[]).forEach(f => push('Endpoints', f));
  (R.api_fuzzer?.endpoints||[]).forEach(f => push('API Fuzzer', f));
  if (R.api_fuzzer?.graphql) push('API Fuzzer', {severity:R.api_fuzzer.graphql.severity, name:'GraphQL — '+R.api_fuzzer.graphql.path, url:'', status:R.api_fuzzer.graphql.status, size:R.api_fuzzer.graphql.size, description:R.api_fuzzer.graphql.detail});
  rows.sort((a,b)=> (sevRank[a.severity]??9)-(sevRank[b.severity]??9));

  const tally = {critical:0,high:0,medium:0,low:0,info:0};
  rows.forEach(r => { tally[r.severity] = (tally[r.severity]||0)+1; });
  // include js_secrets + content_intel sensitive in tally
  (R.js_secrets?.secrets||[]).forEach(s=>{ const k=(s.severity||'info').toLowerCase(); if(k in tally) tally[k]++; });

  const findingRows = rows.map(r => {
    const sc = sevColor[r.severity]||'#8b949e';
    const cve = r.cve ? `<a href="https://nvd.nist.gov/vuln/detail/${esc(r.cve)}" style="color:#ff6b64;font-weight:600">${esc(r.cve)}</a>` : '';
    const urlCell = r.url ? `<a href="${esc(r.url)}" style="color:#58a6ff;word-break:break-all">${esc(r.url)}</a>` : '<span class="muted">—</span>';
    return `<tr>
      <td><span class="sev" style="background:${sc}1a;color:${sc};border:1px solid ${sc}55">${esc(r.severity.toUpperCase())}</span></td>
      <td class="nowrap muted small">${esc(r.mod)}</td>
      <td><div class="strong">${esc(r.name)} ${cve}</div>${r.desc?`<div class="muted small mt2">${esc(r.desc)}</div>`:''}</td>
      <td class="mono small">${urlCell}</td>
      <td class="center mono small">${r.status!==''?esc(String(r.status)):'—'}</td>
      <td class="right mono small nowrap">${fmtBytes(r.size)}</td>
    </tr>`;
  }).join('');

  // ── target overview (curated, defensive) ──
  const geo=R.geo||{}, who=R.whois||{}, ssl=R.ssl||{}, hdr=R.headers||{}, waf=R.wafw00f||{}, ww=R.whatweb||{}, dns=R.dns||{};
  const ov = [];
  const addOv = (label,val)=>{ if(val!=null && val!=='' ) ov.push([label, val]); };
  addOv('IP address', pick(geo,'ip'));
  const loc = [pick(geo,'city'), pick(geo,'region'), pick(geo,'country')].filter(Boolean).join(', ');
  addOv('Location', loc);
  addOv('ASN / Org', [pick(geo,'asn'), pick(geo,'org','asn_name','isp')].filter(Boolean).join(' · '));
  addOv('Registrar', pick(who,'registrar'));
  addOv('Registered', pick(who,'registration'));
  addOv('Expires', pick(who,'expiration'));
  addOv('SSL issuer', pick(ssl,'issuer','issuer_cn'));
  const sslexp = pick(ssl,'valid_until','not_after'); const ssldays = pick(ssl,'days_left');
  addOv('SSL expiry', sslexp ? (sslexp + (ssldays!=null?` (${ssldays}d)`:'')) : null);
  addOv('SSL grade', pick(ssl,'grade'));
  addOv('Headers grade', pick(hdr,'grade'));
  addOv('Server', pick(hdr,'server'));
  addOv('WAF', (pick(waf,'waf_found')||pick(waf,'detected')) ? (pick(waf,'waf')||'detected') : null);
  addOv('Tech / CMS', pick(ww,'cms') || (Array.isArray(pick(ww,'technology'))? ww.technology.slice(0,4).join(', ') : pick(ww,'technology')));
  const es = dns.email_security||{}; addOv('Email security', pick(es,'grade') ? `Grade ${es.grade}` : null);
  const overviewGrid = ov.length ? ('<div class="kv-grid">' + ov.map(([k,v])=>`<div class="kv"><div class="kv-k">${esc(k)}</div><div class="kv-v">${esc(String(v))}</div></div>`).join('') + '</div>') : '';

  // ── content intelligence section ──
  let ciSection = '';
  const CI = R.content_intel;
  if (CI && CI.categories && CI.total){
    const cc = CI.categories, cn = CI.counts||{};
    const chip = (label,color,n) => n ? `<span class="pill" style="background:${color}1a;color:${color};border:1px solid ${color}55">${esc(label)}: <b>${n}</b></span>` : '';
    const listBlock = (title, items, opts) => {
      opts = opts||{}; const lim = opts.limit||40;
      if (!items || !items.length) return '';
      const body = items.slice(0,lim).map(it=>{
        const k = opts.kind ? `<td class="nowrap muted small">${esc(it.kind||'')}</td>` : '';
        return `<tr>${k}<td class="mono small break">${esc(it.value)}</td><td class="muted mono tiny nowrap">${esc(it.source||'')}</td></tr>`;
      }).join('');
      const kh = opts.kind ? '<th>Type</th>' : '';
      return `<h4>${esc(title)} <span class="muted">(${items.length})</span></h4><table><thead><tr>${kh}<th>Value</th><th>Source</th></tr></thead><tbody>${body}</tbody></table>` +
             (items.length>lim ? `<div class="muted">+ ${items.length-lim} more</div>` : '');
    };
    ciSection = section('content-intel','Content Intelligence — JS/HTML Extraction',
      '<div class="pills">' + chip('Endpoints','#58a6ff',cn.endpoints)+chip('Internal URLs','#33b3c9',cn.urls_internal)+
        chip('External hosts','#e3b341',cn.urls_external)+chip('API endpoints','#8b5cf6',cn.api_endpoints)+
        chip('Databases','#e5484d',cn.databases)+chip('Cloud storage','#f76808',cn.cloud_storage)+
        chip('Sensitive','#e5484d',cn.sensitive)+chip('Emails','#6b7280',cn.emails)+
        chip('IPs','#6b7280',cn.ip_addresses)+chip('Internal hosts','#f76808',cn.internal_hosts) + '</div>' +
      listBlock('Database URIs', cc.databases, {kind:true}) +
      listBlock('Cloud Storage', cc.cloud_storage, {kind:true}) +
      listBlock('API Endpoints', cc.api_endpoints, {limit:30}) +
      listBlock('Sensitive Information', cc.sensitive, {kind:true}) +
      listBlock('External / Third-party Hosts', cc.urls_external, {limit:40}) +
      listBlock('Endpoints & Paths', cc.endpoints, {limit:30}));
  }

  // ── per-module adaptive detail ──
  const MODORDER = ['dns','geo','whois','ssl','headers','wafw00f','ports','whatweb','robots','security_txt',
    'shodan','censys','subdomains','brute','wayback','email_harvest','breachintel','favicon','cloud_buckets',
    'js_secrets','screenshot','dorks','osint'];
  const CURATED = new Set(['nuclei','endpoints','api_fuzzer','content_intel']);
  const modName = id => (typeof MODULES!=='undefined' && MODULES[id]) || id.replace(/_/g,' ');
  const modIcon = {dns:'📡',geo:'📍',whois:'🌐',ssl:'🔒',headers:'🛡️',wafw00f:'🧱',ports:'🚪',whatweb:'🕵️',
    robots:'🤖',shodan:'🔭',censys:'🔬',subdomains:'🗺️',brute:'🔨',wayback:'📚',email_harvest:'📧',
    breachintel:'💀',favicon:'🎯',cloud_buckets:'☁️',js_secrets:'🔑',screenshot:'🖼️',dorks:'🔍',osint:'🔗'};
  const seen = new Set();
  const order = MODORDER.filter(id => R[id] !== undefined);
  Object.keys(R).forEach(id => { if(!order.includes(id) && !CURATED.has(id)) order.push(id); });
  let moduleSections = '';
  order.forEach(id => {
    if (CURATED.has(id) || seen.has(id)) return; seen.add(id);
    const d = R[id];
    if (d==null) return;
    let inner;
    if (isObj(d) && d.error) inner = `<div class="warnbox">⚠ ${esc(d.error)}</div>`;
    else inner = renderAny(d);
    moduleSections += section('mod-'+id, (modIcon[id]?modIcon[id]+' ':'') + modName(id), inner);
  });

  // ── severity bar (SVG) ──
  const totFind = rows.length;
  const barTotal = (tally.critical+tally.high+tally.medium+tally.low+tally.info)||1;
  let x=0; const segs = ['critical','high','medium','low','info'].map(s=>{
    const w = (tally[s]/barTotal)*100; const seg = w>0 ? `<rect x="${x}%" y="0" width="${w}%" height="18" fill="${sevColor[s]}"><title>${s}: ${tally[s]}</title></rect>` : ''; x+=w; return seg;
  }).join('');
  const sevBar = `<svg viewBox="0 0 100 18" preserveAspectRatio="none" width="100%" height="18" style="border-radius:6px;overflow:hidden">${segs}</svg>`;

  const cards = ['critical','high','medium','low','info'].map(s =>
    `<div class="card"><div class="num" style="color:${sevColor[s]}">${tally[s]||0}</div><div class="lbl">${s.toUpperCase()}</div></div>`).join('');

  // ── recon highlight chips ──
  const stat = [];
  const spush=(l,v,c)=>{ if(v) stat.push(`<span class="pill" style="background:${c}14;color:${c};border:1px solid ${c}44">${esc(l)}: <b>${v}</b></span>`); };
  spush('Open ports', (R.ports?.open||[]).length, '#f76808');
  spush('Subdomains', R.subdomains?.total || (R.subdomains?.subdomains||[]).length, '#58a6ff');
  spush('CVEs', R.shodan?.summary?.total_cves, '#e5484d');
  const bs=R.breachintel?.summary||{}; spush('Leaked creds', (bs.total_infostealer_hits||0)+(bs.total_employees_leaked||0), '#e5484d');
  spush('JS secrets', R.js_secrets?.total, '#f76808');
  spush('Intel items', R.content_intel?.total, '#8b5cf6');
  spush('Emails', (R.email_harvest?.emails||[]).length, '#6b7280');

  // ── nav / toc ──
  const navItems = [['exec','Summary'],['overview','Overview'],['findings','Findings']];
  if (ciSection) navItems.push(['content-intel','Content Intel']);
  order.forEach(id=>{ if(!CURATED.has(id) && R[id]!=null) navItems.push(['mod-'+id, modName(id)]); });
  const nav = '<nav class="toc">' + navItems.map(([id,label])=>`<a href="#${id}">${esc(label)}</a>`).join('') + '</nav>';

  function section(id,title,inner){
    return `<section id="${id}"><h2>${title}</h2>${inner}</section>`;
  }

  const now = new Date();
  const domain = currentDomain || 'target';
  const dur = (document.getElementById('hdrStat').textContent||'').trim();

  const CSS = `*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#c9d1d9;background:#0a0e16;line-height:1.55}
  .wrap{max-width:1080px;margin:0 auto;background:#0d1117;box-shadow:0 0 0 1px #1c2330,0 18px 60px rgba(0,0,0,.6)}
  .hero{background:linear-gradient(135deg,#0d1117 0%,#141b2e 55%,#1b2545 100%);color:#fff;padding:38px 44px;position:relative;overflow:hidden;border-bottom:1px solid #1c2330}
  .hero:after{content:"蜘蛛";position:absolute;right:24px;top:2px;font-size:130px;color:rgba(76,141,255,.10);font-weight:700;line-height:1}
  .hero h1{margin:0;font-size:34px;letter-spacing:8px;color:#4c8dff;font-family:ui-monospace,Menlo,monospace;text-shadow:0 0 24px rgba(76,141,255,.4)}
  .hero .sub{color:#8b949e;font-size:12px;margin-top:6px;font-family:ui-monospace,monospace;letter-spacing:1px}
  .hero .tgt{font-size:22px;margin-top:18px;font-weight:700;color:#f0f6fc}
  .hero .meta{color:#8b98ad;font-size:12px;margin-top:4px}
  .warn{background:rgba(227,179,65,.08);color:#e3b341;padding:9px 44px;font-size:12px;border-bottom:1px solid rgba(227,179,65,.2)}
  .toc{position:sticky;top:0;z-index:5;display:flex;flex-wrap:wrap;gap:2px;background:#080b12;padding:8px 44px;border-bottom:1px solid #1c2330}
  .toc a{color:#8b98ad;font-size:11px;text-decoration:none;padding:4px 10px;border-radius:6px;white-space:nowrap}
  .toc a:hover{background:rgba(88,166,255,.12);color:#58a6ff}
  section{padding:22px 44px;border-bottom:1px solid #161c26}
  h2{font-size:15px;text-transform:uppercase;letter-spacing:1px;color:#e6edf3;border-bottom:2px solid #1c2330;padding-bottom:8px;margin:0 0 16px;scroll-margin-top:48px}
  h4{font-size:13px;margin:16px 0 6px;color:#adbac7}
  .cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
  .card{flex:1;min-width:84px;border:1px solid #1c2330;border-radius:10px;padding:14px;text-align:center;background:#11161f}
  .card .num{font-size:30px;font-weight:800;font-family:ui-monospace,monospace}.card .lbl{font-size:10px;color:#8b949e;letter-spacing:1px;margin-top:4px}
  .pills{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 14px}
  .pill{display:inline-block;font-size:11px;border-radius:20px;padding:3px 10px}
  table{width:100%;border-collapse:collapse;font-size:12.5px;margin:4px 0}
  th{text-align:left;background:#11161f;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;border-bottom:1px solid #1c2330}
  td{padding:8px 10px;border-bottom:1px solid #161c26;vertical-align:top;color:#c9d1d9}
  tr:hover td{background:#0f141d}
  .kv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:8px}
  .kv{border:1px solid #1c2330;border-radius:8px;padding:8px 11px;background:#11161f}
  .kv-k{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#7d8794}
  .kv-v{font-size:13px;color:#e6edf3;word-break:break-word;margin-top:1px}
  .sev{display:inline-block;font-size:10px;font-weight:700;padding:2px 8px;border-radius:20px;letter-spacing:.5px}
  .chips{display:flex;flex-wrap:wrap;gap:5px}.chip{font-size:11px;background:#161c26;border:1px solid #232b38;border-radius:6px;padding:2px 8px;font-family:ui-monospace,monospace;color:#adbac7}
  .mono{font-family:ui-monospace,Menlo,monospace}.small{font-size:11px}.tiny{font-size:10px}.muted{color:#7d8794}.strong{font-weight:600;color:#e6edf3}
  .center{text-align:center}.right{text-align:right}.nowrap{white-space:nowrap}.break{word-break:break-all}.mt2{margin-top:2px}.ok{color:#3fb950}
  a{color:#58a6ff}
  .warnbox{color:#e3b341;background:rgba(227,179,65,.08);border:1px solid rgba(227,179,65,.25);border-radius:8px;padding:9px 12px;font-size:12px}
  .empty{color:#3fb950;background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25);border-radius:8px;padding:12px;text-align:center;font-weight:600}
  footer{padding:20px 44px;color:#6e7781;font-size:11px}
  @media print{body,.wrap{background:#0d1117}.toc{display:none}section{page-break-inside:avoid}}`;

  const html =
'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
'<title>Kumo Report — ' + esc(domain) + '</title><style>' + CSS + '</style></head><body><div class="wrap">' +
'<div class="hero"><h1>KUMO</h1><div class="sub">蜘蛛 · web recon · osint · breach intel · v2.0</div>' +
'<div class="tgt">' + esc(domain) + '</div><div class="meta">Report generated ' + esc(now.toLocaleString()) + (dur?(' · ' + esc(dur)):'') + '</div></div>' +
'<div class="warn">⚠ For authorized security testing only. Findings are indicators that require manual verification — false positives are possible.</div>' +
nav +
section('exec','Executive Summary',
  '<div class="cards">' + cards +
  '<div class="card"><div class="num" style="color:#f0f6fc">' + Object.keys(R).length + '</div><div class="lbl">MODULES</div></div>' +
  '<div class="card"><div class="num" style="color:#f0f6fc">' + totFind + '</div><div class="lbl">FINDINGS</div></div></div>' +
  (totFind ? ('<div style="margin:6px 0 12px">' + sevBar + '</div>') : '') +
  (stat.length ? ('<div class="pills">' + stat.join('') + '</div>') : '')) +
(overviewGrid ? section('overview','Target Overview', overviewGrid) : '') +
section('findings','Vulnerabilities, Endpoints &amp; API Findings',
  (rows.length ? ('<table><thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>URL</th><th>Status</th><th>Size</th></tr></thead><tbody>' + findingRows + '</tbody></table>')
   : '<div class="empty">✓ No vulnerabilities or exposed endpoints detected</div>')) +
ciSection +
moduleSections +
'<footer>Generated by <b>Kumo v2.0</b> — Domain OSINT &amp; Reconnaissance Framework · ' + esc(now.toISOString()) + '<br>This report is provided as-is for authorized security assessment. Verify all findings manually before acting on them.</footer>' +
'</div></body></html>';

  const blob = new Blob([html], {type:'text/html'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'kumo_report_' + domain.replace(/[^a-z0-9.\-]/gi,'_') + '_' + now.toISOString().slice(0,10) + '.html';
  a.click();
  URL.revokeObjectURL(url);
  toast('ok','Report generated', a.download);
}

// ── Toasts ──
function toast(kind, title, body) {
  const ico = {ok:'✓', warn:'▲', err:'✕', info:'ℹ'}[kind] || 'ℹ';
  const cls = {ok:'t-ok', warn:'t-warn', err:'t-err', info:''}[kind] || '';
  const el = document.createElement('div');
  el.className = 'toast ' + cls;
  el.innerHTML = `<span class="t-ico">${ico}</span><div class="t-body"><b>${escH(title)}</b>${body?`<span>${escH(body)}</span>`:''}</div>`;
  document.getElementById('toastWrap').appendChild(el);
  setTimeout(() => { el.classList.add('out'); setTimeout(() => el.remove(), 260); }, 3600);
}

function updateCounts(){
  const done = completedCount, run = runningSet.size, err = errorCount;
  sCounts.innerHTML =
    `<span class="sc sc-run">◐ ${run} running</span>` +
    `<span class="sc sc-done">✓ ${done}/${totalCount}</span>` +
    (err>0 ? `<span class="sc sc-err">✕ ${err}</span>` : '');
}

document.getElementById('domInput').addEventListener('keydown', e => { if(e.key==='Enter') startScan(false); });
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (document.getElementById('cmpOverlay').classList.contains('on')) { closeCompletionModal(); return; }
  if (scanning) stopScan();
});
</script>
</body>
</html>

"""




# ═══════════════════════════════════════════════════════════════
# API ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route('/')
def index():
    modules_json = json.dumps({k: desc for k, (desc, _) in ALL_MODULES.items()})
    # Use simple string replacement instead of Jinja2 to avoid
    # conflicts with CSS/JS {{ }} and {% %} syntax
    html = HTML_TEMPLATE.replace('__MODULES_JSON__', modules_json)
    return html


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json
    domain = clean_domain(data.get('domain', ''))
    if not domain:
        return jsonify({"error": "Invalid domain"}), 400

    modules = data.get('modules', list(ALL_MODULES.keys()))
    fast = data.get('fast', False)

    scan_id = data.get('scan_id') or ''
    stop_event = _register_scan(scan_id) if scan_id else threading.Event()

    def generate():
        import concurrent.futures
        import queue as queue_mod

        start = time.time()
        to_run = {k: v for k, v in ALL_MODULES.items() if k in modules}
        if fast:
            to_run = {k: v for k, v in to_run.items() if k not in FAST_SKIP}

        total = len(to_run)
        # Track which modules are still outstanding so we NEVER declare the
        # scan complete while something is still running.
        pending_keys = set(to_run.keys())

        # Queue for streaming results back as they complete
        result_queue = queue_mod.Queue()

        def run_module(key, desc, func):
            # Bail early if the user already hit stop before this thread started.
            if stop_event.is_set():
                return
            try:
                result = func(domain)
            except Exception as e:
                result = {"error": str(e)}
            if not stop_event.is_set():
                result_queue.put((key, desc, result))

        # Fire all modules in parallel
        executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(total, 12) if total else 1)
        for key, (desc, func) in to_run.items():
            executor.submit(run_module, key, desc, func)

        # Signal start for all modules immediately
        for key, (desc, _) in to_run.items():
            yield f"data: {json.dumps({'type':'start','module':key,'description':desc})}\n\n"

        # ── Per-module deadlines ──
        # Modules run in parallel and are each timed on their own clock, so a
        # slow module (nuclei) is never killed by a deadline sized for another
        # module, and fast modules are never held hostage by a slow one.
        base = time.time()
        module_deadline = {
            k: base + min(MODULE_TIMEOUTS.get(k, DEFAULT_TIMEOUT), ABS_CAP)
            for k in to_run
        }

        stopped = False
        timed_out_count = 0

        # Stream results as each module finishes. We poll in short slices so we
        # can (a) react to STOP within ~1s, (b) send SSE heartbeats to keep the
        # stream warm, and (c) time out only the specific module that overran.
        while pending_keys:
            if stop_event.is_set():
                stopped = True
                break

            now = time.time()
            # Time out any module that blew past its individual budget.
            expired = [k for k in pending_keys if now >= module_deadline[k]]
            for k in expired:
                pending_keys.discard(k)
                timed_out_count += 1
                desc = to_run[k][0]
                budget = int(min(MODULE_TIMEOUTS.get(k, DEFAULT_TIMEOUT), ABS_CAP))
                err = {"error": f"Module timed out after {budget}s"}
                yield f"data: {json.dumps({'type':'done','module':k,'description':desc,'data':err})}\n\n"
            if not pending_keys:
                break

            # Wait only until the next upcoming deadline (max 1s for stop/heartbeat).
            next_dl = min(module_deadline[k] for k in pending_keys)
            wait = max(0.1, min(1.0, next_dl - now))
            try:
                key, desc, result = result_queue.get(timeout=wait)
            except queue_mod.Empty:
                yield ": keepalive\n\n"
                continue
            if key in pending_keys:
                pending_keys.discard(key)
                yield f"data: {json.dumps({'type':'done','module':key,'description':desc,'data':result}, default=str)}\n\n"

        executor.shutdown(wait=False)
        _unregister_scan(scan_id)

        elapsed = f"{time.time()-start:.1f}s"
        if stopped:
            yield f"data: {json.dumps({'type':'stopped','duration':elapsed,'remaining':sorted(pending_keys)})}\n\n"
        else:
            yield f"data: {json.dumps({'type':'complete','duration':elapsed,'timed_out':timed_out_count>0,'timed_out_count':timed_out_count})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache',
                             'Connection': 'keep-alive'})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    data = request.json or {}
    scan_id = data.get('scan_id', '')
    stopped = _stop_scan(scan_id)
    return jsonify({"stopped": stopped})


@app.route('/api/modules')
def api_modules():
    return jsonify({k: desc for k, (desc, _) in ALL_MODULES.items()})


def start_web(host='0.0.0.0', port=8888):
    """Start the web server."""
    print(f"\n  ☠️  Kumo Web UI running at http://127.0.0.1:{port}")
    print(f"     Press Ctrl+C to stop\n")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == '__main__':
    start_web()
