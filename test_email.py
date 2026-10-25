"""
Email-security parsing tests: SPF, DMARC, DKIM, MTA-STS.

These records are tag-value strings, and the tempting way to read them is a
substring search. That is wrong in ways that invert the finding — 'p=none' is a
substring of 'sp=none', so a domain publishing 'p=reject; sp=none' was reported
as not enforcing DMARC. Every case below is a shape that broke, or must keep
working.

    python3 test_email.py
"""
import warnings

warnings.filterwarnings("ignore")

import engine

G = "\033[92m"; R = "\033[91m"; D = "\033[90m"; B = "\033[1m"; X = "\033[0m"


def dmarc(record):
    """Parse one DMARC record the way scan_dns does."""
    tags = engine._parse_tags(record)
    p = (tags.get("p") or "").lower()
    return {"none": "none (not enforcing)", "quarantine": "quarantine",
            "reject": "reject (strict)"}.get(p, p or "missing p tag")


def spf_policy(record):
    tokens = record.split()
    allq = next((t for t in reversed(tokens) if t.lower().lstrip("+-~?") == "all"), None)
    redirect = next((t.split("=", 1)[1] for t in tokens
                     if t.lower().startswith("redirect=")), None)
    if allq:
        q = allq[0] if allq[0] in "+-~?" else "+"
        return {"+": "+all", "~": "~all", "-": "-all", "?": "?all"}[q]
    if redirect:
        return f"redirect={redirect}"
    return "no all mechanism"


DMARC_CASES = [
    # the bug that mattered: a strict policy with a permissive subdomain policy
    ("v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c", "reject (strict)"),
    ("v=DMARC1; p=quarantine; sp=none", "quarantine"),
    ("v=DMARC1; sp=none; p=reject", "reject (strict)"),
    # ordinary records
    ("v=DMARC1; p=none; rua=mailto:dmarc@example.com", "none (not enforcing)"),
    ("v=DMARC1; p=reject", "reject (strict)"),
    ("v=DMARC1; p=quarantine; pct=50", "quarantine"),
    # whitespace and case
    ("v=DMARC1;p=reject;sp=quarantine", "reject (strict)"),
    ("v=DMARC1 ;  P=Reject ; adkim=s", "reject (strict)"),
    # malformed: no p tag at all
    ("v=DMARC1; rua=mailto:a@b.c", "missing p tag"),
]

SPF_CASES = [
    # +all must not be matched inside an include hostname or a macro
    ("v=spf1 include:_spf.google.com -all", "-all"),
    ("v=spf1 include:plusall.example.com -all", "-all"),
    ("v=spf1 exists:%{i}.spf.example.com -all", "-all"),
    ("v=spf1 a mx ~all", "~all"),
    ("v=spf1 +all", "+all"),
    ("v=spf1 ip4:198.51.100.0/24 ?all", "?all"),
    ("v=spf1 ip4:198.51.100.1 all", "+all"),
    # a redirect carries the policy; "no policy" would be wrong
    ("v=spf1 redirect=_spf.example.net", "redirect=_spf.example.net"),
    ("v=spf1 a mx", "no all mechanism"),
]

# (selector record, expect key found, expect revoked)
DKIM_CASES = [
    ("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", True, False),
    ("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN", True, False),
    # empty p = the key is REVOKED (RFC 6376 3.6.1), not healthy
    ("v=DKIM1; k=rsa; p=", False, True),
    ("v=DKIM1; p=", False, True),
    # not a DKIM record at all
    ("some-verification-token-12345", False, False),
]


def dkim_classify(record):
    tags = engine._parse_tags(record)
    if "p" not in tags and "v" not in tags:
        return False, False
    key = (tags.get("p") or "").strip()
    if key:
        return True, False
    if "p" in tags:
        return False, True
    return False, False


def main():
    fails = []

    print(f"{B}DMARC policy parsing{X}  {D}(substring matching inverts these){X}")
    for rec, want in DMARC_CASES:
        got = dmarc(rec)
        ok = got == want
        fails += [] if ok else [("dmarc", rec, want, got)]
        print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} {rec[:50]:<52} -> {got}")

    print(f"\n{B}SPF mechanism parsing{X}")
    for rec, want in SPF_CASES:
        got = spf_policy(rec)
        ok = got == want
        fails += [] if ok else [("spf", rec, want, got)]
        print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} {rec[:50]:<52} -> {got}")

    print(f"\n{B}DKIM key state{X}")
    for rec, want_found, want_revoked in DKIM_CASES:
        found, revoked = dkim_classify(rec)
        ok = (found is want_found) and (revoked is want_revoked)
        fails += [] if ok else [("dkim", rec, f"found={want_found} revoked={want_revoked}",
                                 f"found={found} revoked={revoked}")]
        print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} {rec[:50]:<52} "
              f"-> found={found} revoked={revoked}")

    print(f"\n{B}Multi-chunk TXT joining{X}  {D}(long records arrive split){X}")
    chunked = [{"type": 16, "data": '"v=DKIM1; k=rsa; p=MIGfMA0GCS" "qGSIb3DQEBAQUAA4GN"'}]
    joined = engine._txt_values(chunked)
    want = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GN"
    ok = joined == [want]
    fails += [] if ok else [("txt", str(chunked), want, str(joined))]
    print(f"  {G+'ok  '+X if ok else R+'FAIL'+X} two chunks join with no separator")

    non_txt = engine._txt_values([{"type": 5, "data": "example.com."}])
    ok2 = non_txt == []
    fails += [] if ok2 else [("txt", "CNAME", "[]", str(non_txt))]
    print(f"  {G+'ok  '+X if ok2 else R+'FAIL'+X} non-TXT answers ignored")

    print(f"\n{B}Selector coverage{X}")
    n = len(engine.DKIM_SELECTORS)
    dupes = [s for s in set(engine.DKIM_SELECTORS)
             if engine.DKIM_SELECTORS.count(s) > 1]
    ok3 = n >= 60 and not dupes
    fails += [] if ok3 else [("dkim", "selectors", ">=60, no dupes",
                              f"{n}, dupes={dupes}")]
    print(f"  {G+'ok  '+X if ok3 else R+'FAIL'+X} {n} selectors, "
          f"{'no duplicates' if not dupes else 'DUPLICATES: ' + str(dupes)}")

    # ── end to end through scan_dns, with the resolver stubbed ──────────
    # The whole module is exercised here, not just the parsers: record
    # assembly, the grade, and above all the difference between "no record"
    # and "the lookup failed".
    print(f"\n{B}scan_dns end to end{X}  {D}(stubbed resolver){X}")

    def run_scan(zone, failing=(), target="example.com"):
        """zone: {(qname, qtype): [txt strings]}; failing: qnames whose lookup errors."""
        def fake_query_ex(qname, qtype):
            if qname in failing:
                return [], "error"
            vals = zone.get((qname, qtype))
            if not vals:
                return [], "ok"          # resolver answered: record absent
            return [{"type": 16, "data": '"%s"' % v} for v in vals], "ok"
        real_q, real_r = engine.dns_query_ex, engine.resolve
        engine.dns_query_ex = fake_query_ex
        engine.resolve = lambda d: {"v4": ["198.51.100.7"], "v6": []}
        try:
            return engine.scan_dns(target)["email_security"]
        finally:
            engine.dns_query_ex, engine.resolve = real_q, real_r

    # 1. a well-configured domain: strict SPF, reject DMARC, DKIM present
    es = run_scan({
        ("example.com", "TXT"): ["v=spf1 include:_spf.google.com -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com"],
        ("google._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"],
        ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20260101"],
    })
    checks = [
        ("strict SPF recognised", es["spf"]["policy"].startswith("-all")),
        ("DMARC reject recognised", es["dmarc"]["policy"].startswith("reject")),
        ("DKIM found via google selector", es["dkim"]["selector"] == "google"),
        ("MTA-STS found", es["mta_sts"]["found"]),
        ("grade A", es["grade"] == "A"),
    ]

    # 2. the sp=none trap: enforcing domain, unprotected subdomains
    es2 = run_scan({
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=none"],
    })
    checks += [
        ("p=reject not misread as none", es2["dmarc"]["policy"].startswith("reject")),
        ("sp=none surfaced as a note",
         any("sp=none" in n for n in es2["dmarc"]["notes"])),
    ]

    # 3. multiple records: SPF permerror, DMARC ignored by receivers
    es3 = run_scan({
        ("example.com", "TXT"): ["v=spf1 include:a.com ~all", "v=spf1 include:b.com -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
    })
    checks += [
        ("duplicate SPF flagged invalid", not es3["spf"]["valid"]),
        ("duplicate DMARC flagged invalid", not es3["dmarc"]["valid"]),
    ]

    # 4. lookup failure must NOT be reported as a missing record
    es4 = run_scan({}, failing={"_dmarc.example.com", "example.com"})
    checks += [
        ("failed DMARC lookup not called missing", es4["dmarc"]["lookup_failed"]),
        ("failed SPF lookup not called missing", es4["spf"]["lookup_failed"]),
    ]

    # 5. a genuinely bare domain: absence IS established here
    es5 = run_scan({})
    checks += [
        ("true absence still reported", not es5["dmarc"]["found"]
         and not es5["dmarc"]["lookup_failed"]),
        ("bare domain grades F", es5["grade"] == "F"),
    ]

    # 6. a non-DMARC TXT at _dmarc must not count as a policy
    es6 = run_scan({("_dmarc.example.com", "TXT"): ["google-site-verification=abc123"]})
    checks += [("verification token at _dmarc ignored", not es6["dmarc"]["found"])]

    # 7. revoked DKIM key is not a healthy key
    es7 = run_scan({("default._domainkey.example.com", "TXT"): ["v=DKIM1; k=rsa; p="]})
    checks += [
        ("revoked DKIM key not counted as found", not es7["dkim"]["found"]),
        ("revoked DKIM key reported", "default" in es7["dkim"]["revoked_selectors"]),
    ]

    # 8. +all is dangerous and must cost score
    es8 = run_scan({("example.com", "TXT"): ["v=spf1 +all"]})
    checks += [("+all flagged dangerous", "DANGEROUS" in es8["spf"]["policy"])]

    for label, good in checks:
        fails += [] if good else [("scan_dns", label, "True", "False")]
        print(f"  {G+'ok  '+X if good else R+'FAIL'+X} {label}")
    checks = []

    # ── DMARC organisational-domain fallback ────────────────────────────
    # The reported bug: a domain with DMARC enabled was reported as having it
    # off, because the policy is published at the organisational domain and
    # only the exact name was queried. RFC 7489 6.6.3 requires the fallback.
    print(f"\n{B}DMARC organisational-domain inheritance{X}  "
          f"{D}(RFC 7489 §6.6.3){X}")

    apex = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:d@example.com"]}

    e_apex = run_scan(apex, target="example.com")["dmarc"]
    e_www = run_scan(apex, target="www.example.com")["dmarc"]
    e_deep = run_scan(apex, target="mail.corp.example.com")["dmarc"]

    checks += [
        ("apex: found directly, not inherited",
         e_apex["found"] and not e_apex["inherited"] and e_apex["found_at"] == "example.com"),
        ("www: policy inherited rather than reported missing",
         e_www["found"] and e_www["inherited"] and e_www["found_at"] == "example.com"),
        ("www: inherited policy is the parent's reject",
         e_www["policy"].startswith("reject")),
        ("www: inheritance explained in a note",
         any("inherited" in n and "example.com" in n for n in e_www["notes"])),
        ("deep subdomain walks up to the org domain",
         e_deep["found"] and e_deep["found_at"] == "example.com"),
    ]

    # sp= governs what applies to a subdomain. A subdomain of a
    # "p=reject; sp=none" domain is genuinely unprotected, and saying "reject"
    # here would overstate it.
    sp_none = {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=none"]}
    e_sp = run_scan(sp_none, target="www.example.com")["dmarc"]
    e_sp_apex = run_scan(sp_none, target="example.com")["dmarc"]
    checks += [
        ("subdomain of sp=none reports not enforcing",
         e_sp["policy"].startswith("none")),
        ("apex of the same domain still reports reject",
         e_sp_apex["policy"].startswith("reject")),
    ]

    # multi-label public suffixes must not be walked into
    e_uk = run_scan({("_dmarc.example.co.uk", "TXT"): ["v=DMARC1; p=quarantine"]},
                    target="shop.example.co.uk")["dmarc"]
    checks += [("co.uk: inherits from example.co.uk",
                e_uk["found"] and e_uk["found_at"] == "example.co.uk")]

    e_tn = run_scan({("_dmarc.example.com.tn", "TXT"): ["v=DMARC1; p=reject"]},
                    target="mail.example.com.tn")["dmarc"]
    checks += [("com.tn: inherits from example.com.tn",
                e_tn["found"] and e_tn["found_at"] == "example.com.tn")]

    # and the fallback must not invent a policy where there is none
    e_none = run_scan({}, target="www.nodmarc.com")["dmarc"]
    checks += [
        ("genuinely absent DMARC still reported missing",
         not e_none["found"] and not e_none["lookup_failed"]),
    ]

    # a public suffix must never be queried as if it were a domain
    checks += [
        ("co.uk not treated as a domain", "co.uk" not in engine._parent_domains("example.co.uk")),
        ("apex has no parents", engine._parent_domains("example.com") == []),
        ("IP target has no parents", engine._parent_domains("127.0.0.1") == []),
    ]

    for label, good in checks:
        fails += [] if good else [("scan_dns", label, "True", "False")]
        print(f"  {G+'ok  '+X if good else R+'FAIL'+X} {label}")

    print()
    if fails:
        print(f"{R}{len(fails)} failure(s){X}")
        for where, inp, want, got in fails:
            print(f"  [{where}] {inp[:46]}  wanted {want}, got {got}")
        return 1
    print(f"{G}every record shape parsed correctly, and a failed lookup is "
          f"never reported as a missing record{X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
