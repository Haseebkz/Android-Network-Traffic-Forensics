#!/usr/bin/env python3
"""
netforensics.py  -  Cell-phone / web traffic forensics for pcap & pcapng
=========================================================================
1) Privacy leakage : tracker/ad domain count, categories, per-source tracker SCORE + comparison
2) Suspicious behaviour : DGA-like domains, DNS tunnelling, beaconing (C2-style periodicity),
   NXDOMAIN storms, cleartext PII/credentials, direct-IP connections, exfil-like uploads,
   Tor/DoH/DoT, odd ports/TLDs, canary-string leakage (cleartext only).

"Source" = one thing you want a score for (an app or a website). Three ways to define it:
  a) one pcap per app/site            ->  python netforensics.py bbc.pcapng fox.pcapng
  b) one pcap, several apps in turn   ->  --windows windows.csv   (app,start,end[,first_party])
  c) just one pcap                    ->  whole file = one source

Usage examples
  python netforensics.py new5.pcap
  python netforensics.py bbc.pcapng fox.pcapng cnn.pcapng -o out
  python netforensics.py new5.pcap --windows windows.csv --blocklist hosts.txt
  python update_trackers.py && python netforensics.py new5.pcap --tracker-db tracker_db.csv
  python netforensics.py new5.pcap --canary "haseeb.test@mail.com,356938035643809"

windows.csv (times = seconds from first packet, or mm:ss, or epoch):
  app,start,end,first_party
  chrome_bbc,0,120,bbc.co.uk;bbci.co.uk
  tiktok,130,300,tiktok;byteoversea

Install:  pip install scapy   (optional: tldextract matplotlib openpyxl geoip2)
"""
import urllib.request, datetime as _dt
import argparse, csv, hashlib, ipaddress, json, math, os, platform, re, sys
from collections import Counter, defaultdict
from functools import lru_cache
from datetime import datetime, timezone

import importlib.util
if importlib.util.find_spec("scapy") is None:
    sys.exit("scapy missing ->  pip install scapy")
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS
from scapy.layers.dns import DNSQR, DNSRR
from scapy.packet import NoPayload

# --------------------------------------------------------------------------- tracker DB
_T = {
    "advertising": """doubleclick.net googlesyndication.com googleadservices.com adservice.google.com admob.com
        adnxs.com adsrvr.org rubiconproject.com pubmatic.com openx.net criteo.com criteo.net taboola.com
        outbrain.com amazon-adsystem.com moatads.com casalemedia.com smartadserver.com 33across.com
        bidswitch.net adform.net advertising.com yieldmo.com teads.tv sharethrough.com indexww.com
        mathtag.com contextweb.com lijit.com sovrn.com media.net applovin.com ironsrc.com vungle.com
        chartboost.com inmobi.com mopub.com adcolony.com startapp.com tapjoy.com fyber.com smaato.net
        unityads.unity3d.com adsafeprotected.com doubleverify.com serving-sys.com everesttech.net
        bidr.io adition.com zedo.com revcontent.com mgid.com
        adtrafficquality.google the-ozone-project.com 2mdn.net fundingchoicesmessages.google.com dv.tech""".split(),
    "analytics": """google-analytics.com googletagmanager.com googletagservices.com scorecardresearch.com
        chartbeat.com chartbeat.net hotjar.com mixpanel.com segment.io segment.com amplitude.com
        quantserve.com nr-data.net optimizely.com crazyegg.com mouseflow.com parsely.com comscore.com
        demdex.net omtrdc.net 2o7.net app-measurement.com crashlytics.com flurry.com sentry.io
        bugsnag.com fullstory.com heap.io clarity.ms matomo.cloud statcounter.com
        mc.yandex.ru adobedtm.com tiqcdn.com
        analytics.google.com dotmetrics.net piano.io cxense.com speedcurve.com""".split(),
    "attribution": """branch.io adjust.com appsflyer.com kochava.com singular.net adjust.net.in
        onelink.me app.adjust.com""".split(),
    "social": """connect.facebook.net graph.facebook.com pixel.facebook.com ads-twitter.com analytics.twitter.com
        ads.linkedin.com px.ads.linkedin.com snap.licdn.com analytics.tiktok.com ads.tiktok.com
        business-api.tiktok.com log.byteoversea.com sc-static.net tr.snapchat.com ct.pinterest.com
        platform.twitter.com t.co""".split(),
    "data-broker/DMP": """bluekai.com krxd.net exelator.com rlcdn.com lotame.com tapad.com id5-sync.com
        adsymptotic.com eyeota.net permutive.com agkn.com liveramp.com crwdcntrl.net
        semasio.net turn.com tags.tiqcdn.com permutive.app id5-tech.io""".split(),
}
TRACKERS = {d: c for c, ds in _T.items() for d in ds}
BUILTIN = set(TRACKERS)                   # domains hard-coded in this script
LISTED = defaultdict(set)                  # domain -> public lists that contain it (filled by load_tracker_db)

# What each tracker/ad service typically collects (documented vendor behaviour).
# NOTE: traffic is encrypted, so this is a VENDOR PROFILE (inferred), not decrypted proof.
_ADREQ = "page URL & referrer, IP address, user-agent, device/screen/language, cookie or advertising ID, consent string"
TRACKER_INFO = {
    "doubleclick.net": ("Google Ad Manager / DoubleClick", _ADREQ + ", ad-slot info, impression/click events (cm.* hosts = cookie-ID matching)"),
    "googlesyndication.com": ("Google AdSense / ad serving", _ADREQ + ", ad impressions & clicks (safeframe.* = ad-creative sandbox)"),
    "googleadservices.com": ("Google Ads conversion tracking", "conversion events, click ID (gclid), page URL, cookie/ad ID, IP, user-agent"),
    "adtrafficquality.google": ("Google ad-traffic quality (invalid-traffic / bot detection)", "browser & device signals, interaction/timing signals, IP, user-agent"),
    "fundingchoicesmessages.google.com": ("Google Funding Choices (consent / ad-block messages)", "page URL, consent state, IP, user-agent, cookie"),
    "googletagmanager.com": ("Google Tag Manager", "mostly downloads tag scripts (container ID, IP, user-agent in request); the tags it loads then collect more"),
    "google-analytics.com": ("Google Analytics", "page URL/title, referrer, client ID (cookie), screen size, language, browser/OS, events, IP"),
    "analytics.google.com": ("Google Analytics 4", "page URL/title, referrer, client ID (cookie), screen size, language, browser/OS, events, IP"),
    "2mdn.net": ("Google DoubleClick Studio (ad creative CDN)", "ad creative delivery; IP, user-agent, referrer"),
    "doubleverify.com": ("DoubleVerify ad verification", "page URL & content category, viewability/attention metrics, ad-placement IDs, IP, user-agent"),
    "dv.tech": ("DoubleVerify ad verification", "page URL & content category, viewability/attention metrics, ad-placement IDs, IP, user-agent"),
    "adsafeprotected.com": ("Integral Ad Science (IAS) verification", "page URL, viewability, brand-safety/fraud signals, IP, user-agent"),
    "adform.net": ("Adform ad exchange / DSP", _ADREQ + ", bid requests, ad interactions"),
    "pubmatic.com": ("PubMatic SSP", "bid requests: " + _ADREQ),
    "amazon-adsystem.com": ("Amazon Publisher Services / ad exchange", "bid requests: " + _ADREQ + " (incl. Amazon IDs)"),
    "the-ozone-project.com": ("Ozone Project (publisher ad exchange / prebid)", "bid requests: " + _ADREQ + ", user IDs from ID providers (e.g. ID5)"),
    "id5-sync.com": ("ID5 identity graph", "pseudonymous ID5 ID, cookie sync with ad partners, IP, user-agent, consent string"),
    "id5-tech.io": ("ID5 identity graph", "pseudonymous ID5 ID, cookie sync with ad partners, IP, user-agent, consent string"),
    "permutive.com": ("Permutive audience platform (DMP)", "pageview & behaviour events, content categories read, user IDs, segment membership, IP, user-agent"),
    "permutive.app": ("Permutive audience platform (DMP)", "pageview & behaviour events, content categories read, user IDs, segment membership, IP, user-agent"),
    "semasio.net": ("Semasio contextual/behavioural targeting", "page content/keywords, cookie ID, IP, user-agent"),
    "scorecardresearch.com": ("Comscore audience measurement", "page URL, referrer, cookie ID, site/panel ID, IP, user-agent"),
    "chartbeat.net": ("Chartbeat live audience analytics", "page URL/title, engaged time, scroll depth, referrer, visitor ID, IP, user-agent"),
    "chartbeat.com": ("Chartbeat live audience analytics", "page URL/title, engaged time, scroll depth, referrer, visitor ID, IP, user-agent"),
    "cxense.com": ("Cxense / Piano audience analytics", "page URL, content/keywords, cookie/user ID, IP, user-agent"),
    "piano.io": ("Piano paywall & audience analytics", "page URL, user/session ID, login/subscription state, IP, user-agent"),
    "dotmetrics.net": ("DotMetrics audience measurement", "page URL, cookie ID, IP, user-agent"),
    "speedcurve.com": ("SpeedCurve real-user performance monitoring", "page-load timings, URL, device/browser, connection type"),
}
CAT_INFO = {
    "advertising": "ad request: " + _ADREQ,
    "analytics": "usage analytics: page URL, referrer, visitor/client ID, device & browser info, events",
    "attribution": "install/click attribution: device & advertising ID, IP, user-agent, campaign IDs",
    "social": "social pixel: page URL, cookie/user ID of a logged-in account, events",
    "data-broker/DMP": "identity/audience data: pseudonymous IDs, cookie sync, browsing categories, IP",
    "fingerprinting": "browser/device fingerprinting: canvas/font/screen/hardware signals combined into a device ID, IP, user-agent",
    "cryptomining": "runs mining script in the browser/app - CPU use; little personal data",
    "email-tracking": "email/web beacon: opens, clicks, IP, user-agent, recipient ID",
    "blocklist": "listed in a public ad/tracker blocklist - exact data not documented here",
}

COMPANY = {}      # domain -> company name (filled from --tracker-db)

def tracker_info(host, cat):
    """(vendor, typical data) - longest matching domain suffix first, else company from tracker-db, else category default."""
    p = host.split(".")
    for i in range(len(p) - 1):
        v = TRACKER_INFO.get(".".join(p[i:]))
        if v:
            return v
    for i in range(len(p) - 1):
        co = COMPANY.get(".".join(p[i:]))
        if co:
            return (co, CAT_INFO.get(cat, "unknown"))
    return ("", CAT_INFO.get(cat, "unknown"))

LIVE_DISCONNECT = "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json"
LIVE_STEVENBLACK = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
_CATMAP = {"Advertising": "advertising", "Analytics": "analytics", "Social": "social", "FingerprintingInvasive": "fingerprinting",
           "FingerprintingGeneral": "fingerprinting", "Cryptomining": "cryptomining", "Email": "email-tracking", "EmailAggressive": "email-tracking"}
_DOM_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_-]+\.)+[a-z]{2,}$")

def _http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "netforensics"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "ignore")

def live_update(cache_path):
    """Download the CURRENT Disconnect + StevenBlack lists and write them to cache_path. Returns (domains, status)."""
    db, errs = {}, []
    try:
        j = json.loads(_http_get(LIVE_DISCONNECT))
        for cat in ["Advertising", "Analytics", "Social", "FingerprintingInvasive", "FingerprintingGeneral", "Cryptomining", "Email", "EmailAggressive"]:
            for ent in j.get("categories", {}).get(cat, []):
                for company, sites in ent.items():
                    if isinstance(sites, dict):
                        for doms in sites.values():
                            if isinstance(doms, list):
                                for d in doms:
                                    d = str(d).lower().strip().strip(".")
                                    if _DOM_RE.match(d):
                                        db.setdefault(d, (_CATMAP[cat], company, "Disconnect"))
    except Exception as e:
        errs.append(f"Disconnect: {e}")
    try:
        for line in _http_get(LIVE_STEVENBLACK).splitlines():
            parts = line.split("#")[0].split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                d = parts[1].lower().strip(".")
                if _DOM_RE.match(d) and d not in ("broadcasthost", "local"):
                    db.setdefault(d, ("blocklist", "", "StevenBlack"))
    except Exception as e:
        errs.append(f"StevenBlack: {e}")
    if not db:
        return 0, "FAILED (" + "; ".join(errs) + ")"
    with open(cache_path, "w", newline="", encoding="utf-8") as f:
        f.write(f"# tracker_db built {_dt.datetime.now(_dt.timezone.utc):%Y-%m-%d %H:%M} UTC from Disconnect + StevenBlack\n")
        w = csv.writer(f)
        w.writerow(["domain", "category", "company", "source"])
        for d in sorted(db):
            w.writerow([d, *db[d]])
    return len(db), "LIVE download OK" + (" (partial: " + "; ".join(errs) + ")" if errs else "")

def listed_in(host):
    """Which lists contain this host (or a parent domain)? Shows WHY it was reported as a tracker."""
    p = host.split(".")
    src = set()
    for i in range(len(p) - 1):
        k = ".".join(p[i:])
        if k in BUILTIN:
            src.add("built-in")
        src |= LISTED.get(k, set())
    return ", ".join(sorted(src))

def load_tracker_db(path):
    """CSV from update_trackers.py: domain,category,company,source.
    Built-in categories win over the file, and a generic 'blocklist' entry never overrides a
    parent domain that already has a real category (e.g. securepubads.g.doubleclick.net stays 'advertising')."""
    rows = []
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(l for l in f if not l.startswith("#")):
            if len(row) < 2 or row[0] == "domain":
                continue
            d = row[0].strip().lower().strip(".")
            if "." in d and "/" not in d and not is_allowed(d):
                rows.append((d, row[1].strip() or "blocklist", row[2].strip() if len(row) > 2 else ""))
                LISTED[d].add(row[3].strip() if len(row) > 3 and row[3].strip() else "tracker-db")
    n = 0
    for generic in (False, True):                      # specific categories first, generic blocklist rows last
        for d, cat, co in rows:
            if (cat == "blocklist") != generic:
                continue
            if d not in TRACKERS:
                p = d.split(".")
                if generic and any(TRACKERS.get(".".join(p[i:]), "blocklist") != "blocklist" for i in range(1, len(p) - 1)):
                    pass                                # parent already classified -> keep parent's category
                else:
                    TRACKERS[d] = cat
                    n += 1
            if co:
                COMPANY.setdefault(d, co)
    return n

def fmt_ips(ips, cap=12):
    ips = list(ips)
    return "\n".join(ips[:cap]) + (f"\n+{len(ips) - cap} more" if len(ips) > cap else "")

def tracker_evidence(v):
    """What the capture itself shows for this tracker (no decryption)."""
    prot = "/".join(v["ports"]) if v["ports"] else "-"
    s = f"{v['up']:,} B up / {v['down']:,} B down, {v['flows']} flow(s) via {prot}. "
    if v["pii_seen"]:
        s += "CLEARTEXT identifiers seen: " + ", ".join(v["pii_seen"]) + "."
    elif v["flows"] == 0:
        s += "DNS lookup only - no connection seen."
    else:
        s += "Payload encrypted - actual content not visible."
    if v["flows"] and v["up"] > v["down"]:
        s += " Upload > download (mostly sends data out)."
    return s

# domains that look random but are legit CDN/infra -> skip DGA & tunnelling heuristics
SAFE_REG = set("""cloudfront.net akamaiedge.net akamai.net akadns.net edgekey.net edgesuite.net fastly.net
    fbcdn.net googleusercontent.com googlevideo.com gvt1.com gvt2.com amazonaws.com azureedge.net
    windows.net cloudflare.net ytimg.com ggpht.com gstatic.com twimg.com cdninstagram.com scdn.co
    appspot.com firebaseio.com apple.com icloud.com microsoft.com msedge.net akamaihd.net
    cloudflareinsights.com""".split())
BENIGN_PERIODIC = ("gstatic.com", "google.com", "googleapis.com", "android.com", "microsoft.com",
                   "msftconnecttest.com", "windowsupdate.com", "apple.com", "ntp.org", "pool.ntp.org")
ALLOW = set(SAFE_REG) | set("""cloudflare.com challenges.cloudflare.com cdnjs.cloudflare.com jsdelivr.net unpkg.com
    bootstrapcdn.com fontawesome.com githubusercontent.com github.io wikipedia.org wikimedia.org""".split())

def is_allowed(d):
    p = d.split(".")
    return any(".".join(p[i:]) in ALLOW for i in range(len(p) - 1))

def load_allow(path):
    n = 0
    with open(path, errors="ignore") as f:
        for line in f:
            d = line.split("#")[0].strip().lower().strip(".")
            if "." in d and "/" not in d:
                ALLOW.add(d); n += 1
    for k in [k for k in TRACKERS if is_allowed(k)]:      # also un-flag built-in entries the user allowed
        del TRACKERS[k]
    return n

SUSPECT_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "mov", "work", "icu",
                "buzz", "cyou", "monster", "rest", "quest", "cfd", "sbs"}
SUSPECT_PORTS = {4444: "Metasploit default", 1337: "common backdoor", 31337: "back-orifice/elite",
                 6667: "IRC (botnet C2)", 6666: "IRC alt", 12345: "NetBus", 9001: "Tor ORPort",
                 9030: "Tor DirPort", 2323: "telnet alt (Mirai)", 23: "telnet"}
DOH_HOSTS = ("dns.google", "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com", "dns.nextdns.io",
             "mozilla.cloudflare-dns.com", "dns.adguard.com")
PII_RE = re.compile(r"(?i)\b(imei|imsi|android[_-]?id|advertising[_-]?id|adid|gaid|aaid|idfa|device[_-]?id|"
                    r"mac(?:addr)?|serial|lat|lon|lng|latitude|longitude|email|e-mail|phone|msisdn|"
                    r"password|passwd|pwd|token|session[_-]?id)=([^&\s\"';]{3,})")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}")
TOOL_VERSION = "netforensics 1.7"
MARKER_RE = re.compile(r"^(start|stop)(?:-([a-z0-9_]+))?\.test$")
HTTP_M = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")

# --------------------------------------------------------------------------- helpers
try:
    import tldextract
    _ext = tldextract.TLDExtract(suffix_list_urls=())
    def reg_domain(h):
        e = _ext(h)
        return getattr(e, "top_domain_under_public_suffix", None) or e.registered_domain or h
except Exception:
    _2L = {"co", "com", "org", "net", "gov", "edu", "ac"}
    def reg_domain(h):
        p = h.strip(".").split(".")
        if len(p) <= 2:
            return ".".join(p)
        if len(p[-1]) == 2 and p[-2] in _2L:
            return ".".join(p[-3:])
        return ".".join(p[-2:])

def tld(h):
    return h.rsplit(".", 1)[-1] if "." in h else h

@lru_cache(maxsize=65536)
def is_global(a):
    """True only for real internet hosts (multicast/link-local/loopback/reserved are not 'remote servers')."""
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return False
    if (ip.is_multicast or ip.is_link_local or ip.is_loopback or ip.is_unspecified
            or ip.is_reserved):
        return False
    return ip.is_global

IP_OWNERS = (("142.250.", "Google"), ("142.251.", "Google"), ("172.217.", "Google"), ("216.58.", "Google"),
             ("74.125.", "Google"), ("64.233.", "Google"), ("108.177.", "Google"), ("157.240.", "Meta/Facebook"),
             ("31.13.", "Meta/Facebook"), ("179.60.", "Meta/Facebook"), ("185.60.", "Meta/Facebook"))

def ip_owner(ip):
    for pre, who in IP_OWNERS:
        if ip.startswith(pre):
            return who
    return None

def tracker_cat(host):
    p = host.split(".")
    for i in range(len(p) - 1):
        c = TRACKERS.get(".".join(p[i:]))
        if c:
            return c
    return None

def load_blocklist(path):
    n = 0
    with open(path, errors="ignore") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line or line.startswith("!"):
                continue
            if line.startswith("||"):
                d = line[2:].split("^")[0]
            else:
                parts = line.split()
                if len(parts) > 1 and parts[0] not in ("0.0.0.0", "127.0.0.1"):
                    continue
                d = parts[-1]
            d = d.lower().strip(".")
            if "." in d and "/" not in d and not is_allowed(d):
                TRACKERS.setdefault(d, "blocklist")
                n += 1
    return n

def shannon(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())

def dga_score(label):
    L = len(label)
    if L < 8:
        return 0
    ent = shannon(label)
    digits = sum(ch.isdigit() for ch in label) / L
    vowels = sum(ch in "aeiou" for ch in label) / L
    run = best = 0
    for ch in label:
        run = run + 1 if ch.isalpha() and ch not in "aeiou" else 0
        best = max(best, run)
    s = 0
    s += ent > 3.4
    s += ent > 3.8
    s += digits > 0.3
    s += vowels < 0.2
    s += best >= 5
    s += L >= 15
    return s

def rr_list(x):
    if x is None:
        return []
    if isinstance(x, (list, tuple)):
        return list(x)
    out, cur = [], x
    while cur is not None and not isinstance(cur, NoPayload):
        if isinstance(cur, (DNSRR, DNSQR)):
            out.append(cur)
        cur = cur.payload
    return out

def qname(q):
    if isinstance(q, bytes):
        q = q.decode("ascii", "ignore")
    return q.rstrip(".").lower()

def parse_sni(p):
    """SNI from a TLS ClientHello (first segment only)."""
    try:
        if len(p) < 50 or p[0] != 0x16 or p[5] != 0x01:
            return None
        pos = 43
        pos += 1 + p[pos]
        pos += 2 + int.from_bytes(p[pos:pos + 2], "big")
        pos += 1 + p[pos]
        end = pos + 2 + int.from_bytes(p[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= min(end, len(p)):
            et = int.from_bytes(p[pos:pos + 2], "big")
            el = int.from_bytes(p[pos + 2:pos + 4], "big")
            pos += 4
            if et == 0:
                nl = int.from_bytes(p[pos + 3:pos + 5], "big")
                return p[pos + 5:pos + 5 + nl].decode("ascii", "ignore").lower()
            pos += el
    except Exception:
        pass
    return None

def parse_http(p):
    try:
        txt = p[:6000].decode("latin-1")
        head, _, body = txt.partition("\r\n\r\n")
        lines = head.split("\r\n")
        method, path, _v = lines[0].split(" ", 2)
        hdr = {}
        for l in lines[1:]:
            k, _, v = l.partition(":")
            hdr[k.strip().lower()] = v.strip()
        blob = path + " " + body + " " + hdr.get("cookie", "")
        pii = [(m.group(1).lower(), m.group(2)[:3] + "***") for m in PII_RE.finditer(blob)]
        pii += [("email", m.group(0)[:3] + "***") for m in EMAIL_RE.finditer(blob)]
        if hdr.get("authorization", "").lower().startswith("basic"):
            pii.append(("basic-auth", "***"))
        return {"method": method, "host": hdr.get("host", "").lower().split(":")[0], "path": path[:120],
                "ua": hdr.get("user-agent", "")[:100], "pii": pii}
    except Exception:
        return None

def proto_label(proto, rport):
    if rport == 53: return "DNS"
    if rport == 853: return "DoT"
    if proto == "UDP" and rport == 443: return "QUIC"
    if proto == "TCP" and rport == 443: return "TLS"
    if proto == "TCP" and rport == 80: return "HTTP"
    return f"{proto}/{rport}"

# --------------------------------------------------------------------------- pass 1: parse
def parse_pcap(path, canaries, max_packets=0):
    R = dict(dns_q=[], dns_r=[], flows=[], http=[], sni=[], canary=[], ip_dns={}, ip_sni={},
             pkts=0, bytes=0, t0=None, t1=None, nonip=0, protos=Counter())
    flows = {}
    try:
        reader = PcapReader(path)
    except Exception as e:
        sys.exit(f"cannot open {path}: {e}")
    for pkt in reader:
        R["pkts"] += 1
        if max_packets and R["pkts"] > max_packets:
            break
        ts = float(pkt.time)
        R["t0"] = ts if R["t0"] is None else R["t0"]
        R["t1"] = ts
        size = len(pkt)
        R["bytes"] += size
        if pkt.haslayer(IP):   ip = pkt[IP]
        elif pkt.haslayer(IPv6): ip = pkt[IPv6]
        else:
            R["nonip"] += 1
            continue
        if pkt.haslayer(TCP):   l4, proto = pkt[TCP], "TCP"
        elif pkt.haslayer(UDP): l4, proto = pkt[UDP], "UDP"
        else:
            R["protos"]["other(ICMP/etc)"] += 1
            continue
        src, dst = ip.src, ip.dst

        # ---- DNS
        if proto == "UDP" and pkt.haslayer(DNS) and 53 in (l4.sport, l4.dport):
            d = pkt[DNS]
            qs = rr_list(d.qd)
            qn = qname(qs[0].qname) if qs else None
            if d.qr == 0:
                for q in qs:
                    R["dns_q"].append((ts, qname(q.qname), int(q.qtype)))
            else:
                ips = []
                for r in rr_list(d.an):
                    if getattr(r, "type", 0) in (1, 28):
                        a = str(r.rdata)
                        ips.append(a)
                        if qn:
                            R["ip_dns"][a] = qn
                R["dns_r"].append((ts, qn, int(d.rcode), ips))
            R["protos"]["DNS"] += 1
            continue

        a_g, b_g = is_global(src), is_global(dst)
        if a_g == b_g:                      # LAN<->LAN or public<->public: skip
            continue
        up = not a_g                        # local side is the non-global one
        local, remote = (src, dst) if up else (dst, src)
        lport, rport = (l4.sport, l4.dport) if up else (l4.dport, l4.sport)
        key = (proto, local, lport, remote, rport)
        f = flows.get(key)
        if f is None:
            f = flows[key] = dict(proto=proto, remote=remote, rport=rport, t0=ts, t1=ts,
                                  up=0, down=0, pk=0, sni=None, tl=Counter(), label=proto_label(proto, rport))
            R["protos"][f["label"]] += 1
        f["t1"] = ts
        f["pk"] += 1
        f["up" if up else "down"] += size
        f["tl"][int(ts)] += size

        payload = bytes(l4.payload)
        if not payload:
            continue
        if up and proto == "TCP":
            if f["sni"] is None and payload[0] == 0x16:
                s = parse_sni(payload)
                if s:
                    f["sni"] = s
                    R["ip_sni"][remote] = s
                    R["sni"].append((ts, remote, s))
            elif payload.startswith(HTTP_M):
                h = parse_http(payload)
                if h:
                    h.update(ts=ts, remote=remote)
                    R["http"].append(h)
        for c in canaries:
            if c in payload:
                R["canary"].append((ts, remote, rport, c.decode("latin-1"), proto_label(proto, rport)))
    R["flows"] = list(flows.values())
    return R

# --------------------------------------------------------------------------- pass 2: analyse a source
def flow_name(f, R):
    return f["sni"] or R["ip_sni"].get(f["remote"]) or R["ip_dns"].get(f["remote"])

def slice_res(R, lo, hi):
    inb = lambda t: lo <= t < hi
    S = {k: R[k] for k in ("ip_dns", "ip_sni")}
    S["dns_q"] = [x for x in R["dns_q"] if inb(x[0]) and not MARKER_RE.match(x[1])]
    S["dns_r"] = [x for x in R["dns_r"] if inb(x[0]) and not (x[1] and MARKER_RE.match(x[1]))]
    S["flows"] = [f for f in R["flows"] if inb(f["t0"])]
    S["http"] = [h for h in R["http"] if inb(h["ts"])]
    S["sni"] = [x for x in R["sni"] if inb(x[0])]
    S["canary"] = [x for x in R["canary"] if inb(x[0])]
    return S

def clean(h):
    return h and "." in h and not h.endswith((".local", ".lan", ".arpa", ".internal", ".home")) \
        and not re.fullmatch(r"[\d.]+", h)

def analyse(name, S, fp_keys, min_beacon, t0=0.0):
    names = defaultdict(lambda: dict(flows=0, up=0, down=0, dns=0, ports=set(), ips=set(), dns_ips=set()))
    for _, q, _t in S["dns_q"]:
        if clean(q): names[q]["dns"] += 1
    for _, _ip, s in S["sni"]:
        if clean(s): names[s]
    for _, qn_, _rc, ips_ in S["dns_r"]:                 # IPs the DNS server returned for each name
        if qn_ in names:
            names[qn_]["dns_ips"].update(ips_)
    for h in S["http"]:
        if clean(h["host"]): names[h["host"]]
    raw_ip = defaultdict(lambda: dict(flows=0, up=0, down=0, ports=set()))
    for f in S["flows"]:
        n = flow_name(f, S)
        if n and clean(n):
            d = names[n]
            d["ips"].add(f["remote"])
        elif f["rport"] in (53, 123):
            continue
        else:
            d = raw_ip[f["remote"]]
        d["flows"] += 1; d["up"] += f["up"]; d["down"] += f["down"]; d["ports"].add(f["label"])

    # ---------------- privacy / tracker score
    trk = {}
    for n, d in names.items():
        c = tracker_cat(n)
        if c:
            trk[n] = dict(cat=c, **{k: (sorted(v) if isinstance(v, set) else v) for k, v in d.items()})
    pii_by = defaultdict(set)                            # identifiers actually visible in cleartext HTTP
    for h in S["http"]:
        if h["pii"]:
            pii_by[h["host"]].update(k for k, _ in h["pii"])
    for n, v in trk.items():
        v["pii_seen"] = sorted(pii_by.get(n, ()))
        v["vendor"], v["data"] = tracker_info(n, v["cat"])
        v["basis"] = "OBSERVED (cleartext)" if v["pii_seen"] else "INFERRED (vendor profile)"
        v["evidence"] = tracker_evidence(v)
        v["listed_in"] = listed_in(n)
    total_d = len(names)
    third = [n for n in names if not any(k in reg_domain(n) for k in fp_keys)] if fp_keys else list(names)
    tr_flows = sum(v["flows"] for v in trk.values())
    all_flows = sum(v["flows"] for v in names.values()) + sum(v["flows"] for v in raw_ip.values())
    tr_bytes = sum(v["up"] + v["down"] for v in trk.values())
    all_bytes = sum(v["up"] + v["down"] for v in names.values()) + sum(v["up"] + v["down"] for v in raw_ip.values())
    cats = Counter(v["cat"] for v in trk.values())
    ratio_d = len(trk) / total_d if total_d else 0
    ratio_f = tr_flows / all_flows if all_flows else 0
    score = round(50 * min(1, len(trk) / 50) + 25 * min(1, ratio_d / 0.5)
                  + 15 * min(1, ratio_f / 0.5) + 10 * min(1, len(cats) / 5), 1)
    level = "LOW" if score < 25 else "MODERATE" if score < 50 else "HIGH" if score < 75 else "VERY HIGH"

    # ---------------- all websites in this capture (+ main one)
    sites = {}
    for n, d in names.items():
        rd = reg_domain(n)
        if tracker_cat(n) or tracker_cat(rd):
            continue
        fpm = bool(fp_keys) and any(k in rd for k in fp_keys)
        c = sites.setdefault(rd, dict(site=rd, fp=fpm, page=False, infra=(rd in SAFE_REG or rd.endswith(BENIGN_PERIODIC)) and not fpm,
                                      hosts=[], dns=0, flows=0, up=0, down=0))
        c["hosts"].append(n)
        c["page"] = c["page"] or n == rd or n.startswith(("www.", "m.", "amp."))
        c["dns"] += d["dns"]; c["flows"] += d["flows"]; c["up"] += d["up"]; c["down"] += d["down"]
    for c in sites.values():
        c["role"] = ("first-party" if c["fp"] else "website" if c["page"] and not c["infra"] else
                     "cdn/infra" if c["infra"] else "other")
        c["hosts"] = sorted(c["hosts"])
        del c["fp"], c["page"], c["infra"]
    rank = {"first-party": 0, "website": 1, "other": 2, "cdn/infra": 3}
    websites = sorted(sites.values(), key=lambda c: (rank[c["role"]], -(c["up"] + c["down"] + c["dns"])))
    shown = [c["site"] for c in websites if c["role"] in ("first-party", "website")] or [c["site"] for c in websites[:1]]
    main_site = shown[0] if shown else ""
    main_inferred = bool(websites) and websites[0]["role"] != "first-party"
    sites_text = ", ".join(shown[:6]) + (f" (+{len(shown) - 6} more)" if len(shown) > 6 else "")

    # ---------------- suspicious behaviour
    F = []
    add = lambda sev, typ, ind, det: F.append(dict(sev=sev, type=typ, indicator=ind, detail=det))

    # DGA / TLD / punycode
    regs = {}
    for n in names:
        regs.setdefault(reg_domain(n), []).append(n)
    for rd in regs:
        if rd in SAFE_REG or tracker_cat(rd):
            continue
        sld = rd.split(".")[0]
        sc = dga_score(sld)
        if sc >= 3:
            add("HIGH" if sc >= 4 else "MED", "DGA-like domain", rd,
                f"score={sc} entropy={shannon(sld):.2f} len={len(sld)}")
        if tld(rd) in SUSPECT_TLDS:
            add("LOW", "Suspicious TLD", rd, f".{tld(rd)} is heavily abused")
        if "xn--" in rd:
            add("LOW", "Punycode/IDN", rd, "possible homograph domain")
        if rd.endswith(".onion") or ".onion" in rd:
            add("HIGH", "Tor hidden service", rd, "onion address in traffic")

    # NXDOMAIN storm
    nx = {q for _, q, rc, _ in S["dns_r"]
          if rc == 3 and q and not q.rstrip(".").lower().endswith((".in-addr.arpa", ".ip6.arpa"))}  # PTR lookups are not DGA
    if len(nx) >= 10:
        add("MED" if len(nx) < 40 else "HIGH", "NXDOMAIN storm", f"{len(nx)} failing names",
            "e.g. " + ", ".join(sorted(nx)[:4]) + " (DGA scanning / dead C2 list)")

    # DNS tunnelling / exfil over DNS
    by_reg = defaultdict(list)
    for _, q, qt in S["dns_q"]:
        by_reg[reg_domain(q)].append((q, qt))
    for rd, lst in by_reg.items():
        if rd in SAFE_REG or tracker_cat(rd):
            continue
        subs = {q[:-(len(rd) + 1)] for q, _ in lst if q != rd}
        subs = {s for s in subs if s}
        avg = sum(len(s) for s in subs) / len(subs) if subs else 0
        mx = max((len(l) for s in subs for l in s.split(".")), default=0)
        txt = sum(1 for _, qt in lst if qt in (16, 10))
        if (len(subs) >= 25 and avg >= 18) or mx > 50 or txt >= 10:
            add("HIGH", "DNS tunnelling?", rd,
                f"{len(subs)} unique subdomains, avg len {avg:.0f}, max label {mx}, TXT/NULL q={txt}")

    # Beaconing
    ev = defaultdict(list)
    for f in S["flows"]:
        if f["rport"] in (53, 123):
            continue
        ev[f"{flow_name(f, S) or f['remote']}:{f['rport']}"].append(f["t0"])
    for _, q, _t in S["dns_q"]:
        ev["DNS " + q].append(_)
    for k, ts_ in ev.items():
        ts_.sort()
        if len(ts_) < min_beacon:
            continue
        iv = [b - a for a, b in zip(ts_, ts_[1:]) if b - a > 0.2]
        if len(iv) < min_beacon - 1:
            continue
        m = sum(iv) / len(iv)
        sd = math.sqrt(sum((x - m) ** 2 for x in iv) / len(iv))
        cv = sd / m if m else 9
        host = k.replace("DNS ", "").split(":")[0]
        if cv < 0.25 and 3 <= m <= 7200:
            benign = host.endswith(BENIGN_PERIODIC)
            trk_hb = tracker_cat(host)
            sev = "LOW" if (benign or trk_hb) else ("HIGH" if cv < 0.1 and len(iv) >= 15 else "MED")
            note = " (likely benign OS/Google periodic)" if benign else " (tracker heartbeat)" if trk_hb else ""
            add(sev, "Beaconing", k, f"{len(ts_)} events, every ~{m:.1f}s, jitter cv={cv:.2f}{note}")

    # Connections whose name is not visible (no DNS/SNI in this capture)
    big = [(ipx, d) for ipx, d in raw_ip.items() if d["up"] > 50_000]
    small = [(ipx, d) for ipx, d in raw_ip.items() if d["up"] <= 50_000]
    for ipx, d in big:
        add("MED", "Direct-IP upload (no DNS/SNI)", ipx,
            f"{ip_owner(ipx) or '?'}: {d['flows']} flows, up={d['up']}B down={d['down']}B ports={sorted(d['ports'])}")
    if small:
        top = sorted(small, key=lambda kv: -(kv[1]["up"] + kv[1]["down"]))[:6]
        add("LOW", "Connections without visible DNS/SNI", f"{len(small)} IPs",
            ", ".join(f"{ipx}({ip_owner(ipx) or '?'})" for ipx, _ in top)
            + "  -> capture started after DNS/TLS handshake, or QUIC/DoH hides the names")

    # suspicious ports / DoT / DoH
    seen = set()
    for f in S["flows"]:
        p = f["rport"]
        if p in SUSPECT_PORTS and (f["remote"], p) not in seen:
            seen.add((f["remote"], p))
            add("HIGH" if p in (4444, 31337, 1337, 6667, 9001, 9030) else "MED",
                "Suspicious port", f"{f['remote']}:{p}", SUSPECT_PORTS[p])
        if p == 853 and ("DoT", f["remote"]) not in seen:
            seen.add(("DoT", f["remote"]))
            add("LOW", "DNS-over-TLS", f["remote"], "bypasses local DNS monitoring")
    for n in names:
        if n.endswith(DOH_HOSTS):
            add("LOW", "DNS-over-HTTPS", n, "DNS hidden inside HTTPS")

    # Exfil-like uploads
    for n, d in names.items():
        if d["up"] >= 200_000 and d["up"] >= 5 * max(d["down"], 1):
            add("MED", "Upload-heavy flow", n, f"up={d['up']}B down={d['down']}B (possible exfiltration)")

    # Cleartext HTTP + PII
    if S["http"]:
        hosts = Counter(h["host"] or h["remote"] for h in S["http"])
        add("LOW", "Cleartext HTTP", f"{len(S['http'])} requests",
            "hosts: " + ", ".join(f"{h}({c})" for h, c in hosts.most_common(5)))
    for h in S["http"]:
        if h["pii"]:
            keys = sorted({k for k, _ in h["pii"]})
            sev = "HIGH" if any(k in ("password", "passwd", "pwd", "basic-auth", "token", "imei", "imsi") for k in keys) else "MED"
            add(sev, "PII/credential in cleartext", h["host"] or h["remote"],
                f"{h['method']} {h['path'][:60]} -> {', '.join(keys)}")
    for ts_, remote, port, c, lab in S["canary"]:
        add("HIGH", "CANARY leaked", f"{remote}:{port}", f"value '{c}' seen in cleartext over {lab} -> {flow_name({'sni':None,'remote':remote}, S) or ''}")

    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    F.sort(key=lambda x: (order[x["sev"]], x["type"]))
    sus = sum({"HIGH": 10, "MED": 4, "LOW": 1}[x["sev"]] for x in F)
    verdict = "CLEAN" if sus < 5 else "REVIEW" if sus < 20 else "SUSPICIOUS" if sus < 50 else "LIKELY MALICIOUS"

    # destinations (for GeoIP map / ASN view)
    dest = {}
    for f in S["flows"]:
        if f["rport"] == 53:
            continue
        d = dest.setdefault(f["remote"], dict(ip=f["remote"], name=None, up=0, down=0, flows=0))
        d["name"] = d["name"] or flow_name(f, S)
        d["up"] += f["up"]; d["down"] += f["down"]; d["flows"] += 1
    destinations = sorted(dest.values(), key=lambda x: -(x["up"] + x["down"]))[:300]
    for d in destinations:
        d["owner"] = ip_owner(d["ip"])
        d["tracker"] = bool(d["name"] and tracker_cat(d["name"]))

    # traffic timeline (bytes per bucket, tracker share)
    tot, tk = Counter(), Counter()
    for f in S["flows"]:
        n_ = flow_name(f, S)
        is_t = bool(n_ and tracker_cat(n_))
        for sec, b in f["tl"].items():
            tot[sec] += b
            if is_t:
                tk[sec] += b
    timeline, bucket = [], 1
    if tot:
        lo_s, hi_s = min(tot), max(tot)
        bucket = max(1, math.ceil((hi_s - lo_s + 1) / 300))
        agg_t, agg_k = Counter(), Counter()
        for sec, b in tot.items():
            k = (sec - lo_s) // bucket
            agg_t[k] += b; agg_k[k] += tk.get(sec, 0)
        timeline = [[int(lo_s - t0 + k * bucket), agg_t[k], agg_k[k]] for k in sorted(agg_t)]

    return dict(
        source=name, main_site=main_site, main_site_inferred=main_inferred, websites=websites, sites_text=sites_text, domains=total_d, third_party=len(third), tracker_domains=len(trk),
        tracker_ratio=round(ratio_d, 3), tracker_flow_ratio=round(ratio_f, 3),
        tracker_bytes=tr_bytes, total_bytes=all_bytes, categories=dict(cats),
        tracker_score=score, tracker_level=level, suspicion_points=sus, verdict=verdict,
        trackers=sorted(({"domain": n, **v} for n, v in trk.items()), key=lambda x: -(x["up"] + x["down"] + x["dns"])),
        findings=F, destinations=destinations, timeline=timeline, timeline_bucket=bucket)

# --------------------------------------------------------------------------- output
def file_evidence(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    st = os.stat(path)
    iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        import scapy
        sv = scapy.__version__
    except Exception:
        sv = "?"
    return dict(file=os.path.abspath(path), sha256=h.hexdigest(), size_bytes=st.st_size,
                file_modified=iso(st.st_mtime), analysed_at=iso(datetime.now(timezone.utc).timestamp()),
                tool=TOOL_VERSION, scapy=sv, python=platform.python_version(),
                os=platform.platform(), command=" ".join(sys.argv))

def geo_enrich(results, city_db, asn_db):
    try:
        import geoip2.database
    except ImportError:
        print("[!] geoip2 missing -> pip install geoip2   (GeoIP skipped)")
        return False
    try:
        city = geoip2.database.Reader(city_db)
        asn = geoip2.database.Reader(asn_db) if asn_db else None
    except Exception as e:
        print(f"[!] cannot open GeoIP database: {e}")
        return False
    cache = {}
    for r in results:
        for d in r["destinations"]:
            ip = d["ip"]
            if ip not in cache:
                g = dict(country="?", iso="", city="", lat=None, lon=None, asn="")
                try:
                    c = city.city(ip)
                    g.update(country=c.country.name or "?", iso=c.country.iso_code or "",
                             city=c.city.name or "", lat=c.location.latitude, lon=c.location.longitude)
                except Exception:
                    pass
                if asn:
                    try:
                        a_ = asn.asn(ip)
                        g["asn"] = f"AS{a_.autonomous_system_number} {a_.autonomous_system_organization}"
                    except Exception:
                        pass
                cache[ip] = g
            d.update(cache[ip])
    return True

GEO_HTML = r"""<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Destination map</title>
<link rel=stylesheet href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>html,body,#m{height:100%;margin:0}.info{background:#fff;padding:8px 12px;border-radius:6px;font:12px/1.5 system-ui,Segoe UI,sans-serif;box-shadow:0 1px 5px rgba(0,0,0,.4);color:#222}.info h4{margin:0 0 4px;font-size:13px}.leaflet-control-layers{font:12px system-ui,sans-serif}</style><div id=m></div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const P=__DATA__;
const e=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fb=n=>{const u=['B','KB','MB','GB'];let i=0;n=Number(n)||0;while(n>=1024&&i<3){n/=1024;i++;}return n.toFixed(i?1:0)+' '+u[i];};
const m=L.map('m',{worldCopyJump:true}).setView([20,0],2);
const street=L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}',{maxZoom:19,attribution:'Tiles &copy; Esri'});
const osm=L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'&copy; OpenStreetMap contributors'});
const gray=L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}',{maxZoom:16,attribution:'Tiles &copy; Esri'});
street.addTo(m);
L.control.scale().addTo(m);
const cols=['#2a81cb','#2aad27','#cb8427','#9c2bcb','#3d3d3d','#cb2b83','#00a3a3','#8a6d3b'];
const TRK='#d63e2a';
const srcs=[...new Set(P.map(p=>p.src))];
function pin(color,tracker){
 const ring=tracker?'#000':'#fff';
 return L.divIcon({className:'',iconSize:[26,36],iconAnchor:[13,36],popupAnchor:[0,-32],
  html:'<svg width="26" height="36" viewBox="0 0 26 36"><path d="M13 1C6.4 1 1 6.2 1 12.7 1 21.5 13 35 13 35s12-13.5 12-22.3C25 6.2 19.6 1 13 1z" fill="'+color+'" stroke="'+ring+'" stroke-width="'+(tracker?2.5:1.5)+'"/><circle cx="13" cy="12.5" r="4.5" fill="#fff"/></svg>'});
}
const groups={};srcs.forEach(s=>{groups[s]=L.layerGroup().addTo(m);});
const trkOnly=L.layerGroup();
const pts=[];let nTrk=0,bytes=0;
P.forEach(p=>{
 const col=cols[srcs.indexOf(p.src)%cols.length];
 const html='<div style="min-width:210px"><b>'+e(p.name||p.ip)+'</b>'+(p.tracker?' <span style="color:'+TRK+'">[tracker/ad]</span>':'')+
  '<br>IP: '+e(p.ip)+'<br>'+e([p.city,p.country].filter(Boolean).join(', '))+(p.asn?'<br>'+e(p.asn):'')+
  '<hr style="margin:5px 0">source: '+e(p.src)+'<br>upload '+fb(p.up)+' &middot; download '+fb(p.down)+'<br>flows: '+p.flows+'</div>';
 groups[p.src].addLayer(L.marker([p.lat,p.lon],{icon:pin(p.tracker?TRK:col,p.tracker),title:p.name||p.ip}).bindPopup(html));
 if(p.tracker){trkOnly.addLayer(L.marker([p.lat,p.lon],{icon:pin(TRK,true),title:p.name||p.ip}).bindPopup(html));nTrk++;}
 pts.push([p.lat,p.lon]);bytes+=p.up+p.down;});
const overlays={};
srcs.forEach((s,i)=>{overlays['<span style="color:'+cols[i%cols.length]+'">&#9679;</span> '+e(s)]=groups[s];});
overlays['<span style="color:'+TRK+'">&#9679;</span> tracker/ad destinations only']=trkOnly;
L.control.layers({'Street map (Esri)':street,'OpenStreetMap':osm,'Light gray':gray},overlays,{collapsed:false}).addTo(m);
if(pts.length){m.fitBounds(pts,{padding:[40,40],maxZoom:12});}
const lg=L.control({position:'bottomleft'});
lg.onAdd=()=>{const d=L.DomUtil.create('div','info');
 d.innerHTML='<h4>Destination servers</h4>'+pts.length+' IPs &middot; '+fb(bytes)+' total<br>'+nTrk+' tracker/ad (red pin, black outline)<br>pin colour = source &middot; click a pin for details';return d;};
lg.addTo(m);
</script>"""

def write_geo_html(results, path):
    pts = []
    for r in results:
        for d in r["destinations"]:
            if d.get("lat") is None:
                continue
            pts.append(dict(src=r["source"], ip=d["ip"], name=d.get("name") or "", country=d.get("country", ""),
                            city=d.get("city", ""), asn=d.get("asn") or d.get("owner") or "", lat=d["lat"], lon=d["lon"],
                            up=d["up"], down=d["down"], flows=d["flows"], tracker=d["tracker"]))
    if not pts:
        return False
    data = json.dumps(pts).replace("</", "<\\/")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(GEO_HTML.replace("__DATA__", data))
    return True

def save_charts(results, out, stamp):
    """PNG charts: per-source timeline, top trackers, destination countries + one cross-source comparison."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    from matplotlib.ticker import FuncFormatter
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True,
                         "grid.alpha": 0.25, "axes.axisbelow": True, "figure.facecolor": "white"})
    bfmt = FuncFormatter(lambda v, _: fmt_b(v))
    safe = lambda x: re.sub(r"[^A-Za-z0-9_.-]", "_", x)
    OTHER, TRK = "#4C78A8", "#E45756"
    made = []
    def save(fig, name):
        fig.tight_layout()
        fig.savefig(os.path.join(out, name), dpi=150)
        plt.close(fig)
        made.append(name)
    for r in results:
        sf = safe(r["source"])
        share = (r["tracker_bytes"] / r["total_bytes"] * 100) if r["total_bytes"] else 0
        tl = r["timeline"]
        if tl:
            b = r["timeline_bucket"]
            xs = [x[0] for x in tl]
            tot = [x[1] / 1024 for x in tl]
            trk = [x[2] / 1024 for x in tl]
            non = [t - k for t, k in zip(tot, trk)]
            fig, ax = plt.subplots(figsize=(11, 4))
            ax.bar(xs, non, width=b, align="edge", color=OTHER, label="other traffic")
            ax.bar(xs, trk, width=b, align="edge", bottom=non, color=TRK, label="tracker/ad traffic")
            pk = max(range(len(tl)), key=lambda i: tl[i][1])
            ax.annotate(f"peak {fmt_b(tl[pk][1])} / {b}s", (xs[pk] + b / 2, tot[pk]), textcoords="offset points",
                        xytext=(0, 8), ha="center", fontsize=9)
            ax.set_title(f"Traffic timeline: {r['source']}   (tracker/ad traffic {share:.0f}% of {fmt_b(r['total_bytes'])})",
                         loc="left", fontweight="bold")
            ax.set_ylim(0, (max(tot) or 1) * 1.28)          # headroom for the peak label and legend
            ax.set_xlabel("seconds from capture start"); ax.set_ylabel(f"KB per {b}s")
            ax.legend(frameon=False, loc="upper right", ncol=2)
            save(fig, f"timeline_{sf}_{stamp}.png")
        tl_ = sorted(r["trackers"], key=lambda t: -(t["up"] + t["down"]))[:15]
        if tl_:
            cats = sorted({t["cat"] for t in tl_})
            cmap = plt.get_cmap("tab10")
            col = {c: cmap(i % 10) for i, c in enumerate(cats)}
            fig, ax = plt.subplots(figsize=(10, 0.42 * len(tl_) + 1.8))
            vals = [t["up"] + t["down"] for t in tl_][::-1]
            ax.barh([t["domain"] for t in tl_][::-1], vals, color=[col[t["cat"]] for t in tl_][::-1])
            top = max(vals) or 1
            for i, v in enumerate(vals):
                ax.text(v, i, "  " + fmt_b(v), va="center", fontsize=8)
            ax.set_xlim(0, top * 1.18)
            ax.xaxis.set_major_formatter(bfmt)
            ax.set_xlabel("traffic (upload + download)")
            ax.set_title(f"Top tracker/ad domains by traffic: {r['source']}", loc="left", fontweight="bold")
            ax.legend(handles=[Patch(color=col[c], label=c) for c in cats], frameon=False, loc="lower right", title="category")
            save(fig, f"top_trackers_{sf}_{stamp}.png")
        by = defaultdict(lambda: [0, 0])
        for d in r["destinations"]:
            if d.get("country"):
                c = by[d["country"]]
                c[0] += d["up"] + d["down"]
                c[1] += (d["up"] + d["down"]) if d["tracker"] else 0
        if by:
            top10 = sorted(by.items(), key=lambda kv: -kv[1][0])[:10][::-1]
            fig, ax = plt.subplots(figsize=(10, 0.45 * len(top10) + 1.8))
            names = [k for k, _ in top10]
            trk_b = [v[1] for _, v in top10]
            oth_b = [v[0] - v[1] for _, v in top10]
            ax.barh(names, oth_b, color=OTHER, label="other traffic")
            ax.barh(names, trk_b, left=oth_b, color=TRK, label="tracker/ad traffic")
            mx = max((o + t) for o, t in zip(oth_b, trk_b)) or 1
            for i, (o, t) in enumerate(zip(oth_b, trk_b)):
                ax.text(o + t, i, "  " + fmt_b(o + t), va="center", fontsize=8)
            ax.set_xlim(0, mx * 1.18)
            ax.xaxis.set_major_formatter(bfmt)
            ax.set_xlabel("traffic to destination country")
            ax.set_title(f"Destination countries (top 10): {r['source']}", loc="left", fontweight="bold")
            ax.legend(frameon=False, loc="lower right")
            save(fig, f"countries_{sf}_{stamp}.png")
    rs = sorted(results, key=lambda x: -x["tracker_score"])
    cats = sorted({c for r in rs for c in r["categories"]})
    if cats:
        cmap = plt.get_cmap("tab10")
        fig, ax = plt.subplots(figsize=(max(6.5, len(rs) * 1.5), 5))
        bottom = [0] * len(rs)
        names = [r["source"] for r in rs]
        for i, c in enumerate(cats):
            vals = [r["categories"].get(c, 0) for r in rs]
            ax.bar(names, vals, bottom=bottom, label=c, color=cmap(i % 10))
            bottom = [x + y for x, y in zip(bottom, vals)]
        for i, r in enumerate(rs):
            ax.text(i, bottom[i], f"{bottom[i]} domains\nscore {r['tracker_score']}", ha="center", va="bottom", fontsize=9)
        ax.set_ylim(0, (max(bottom) or 1) * 1.22)
        ax.set_ylabel("unique tracker/ad domains")
        ax.set_title("Privacy leakage: tracker domains per source", loc="left", fontweight="bold")
        ax.legend(frameon=False, title="category")
        plt.xticks(rotation=30, ha="right")
        save(fig, f"tracker_comparison_{stamp}.png")
    return made

def table(rows, headers, maxw=70):
    rows = [[str(c)[:maxw] for c in r] for r in rows]
    w = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]
    line = lambda r: "  ".join(c.ljust(w[i]) for i, c in enumerate(r))
    return "\n".join([line(headers), "  ".join("-" * x for x in w)] + [line(r) for r in rows])

def fmt_b(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.0f}{u}" if u == "B" else f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}TB"

def marker_windows(R, gap=10.0):
    """start-<app>.test / stop[-<app>].test DNS lookups -> (app, lo, hi) windows."""
    ev, last = [], {}
    for ts, q, _t in sorted(R["dns_q"]):
        m = MARKER_RE.match(q)
        if not m:
            continue
        kind, app = m.group(1), m.group(2) or ""
        if q in last and ts - last[q] < gap:      # nslookup/OS retries
            continue
        last[q] = ts
        ev.append((ts, kind, app))
    out = []
    for i, (ts, kind, app) in enumerate(ev):
        if kind != "start":
            continue
        hi = next((t for t, _k, _a in ev[i + 1:]), R["t1"] + 1)
        out.append((app or f"segment{len(out)+1}", ts, hi))
    return out

def parse_fp_map(txt):
    m = {}
    for part in txt.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            m[k.strip().lower()] = [x for x in re.split(r"[;|]", v) if x]
    return m

def parse_t(s, t0):
    s = s.strip()
    v = 0.0
    for p in s.split(":"):
        v = v * 60 + float(p)
    return v if v > 1e9 else t0 + v


# --------------------------------------------------------------------------- report files
def csv_safe(v):
    """Neutralise spreadsheet formula injection (domains/hosts come from untrusted captures)."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v

def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:      # utf-8-sig: opens correctly in Excel
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow([csv_safe(c) for c in r])

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

REPORT_CSS = """
:root{--bg:#fff;--fg:#1d2330;--mut:#667085;--line:#e4e7ec;--card:#f8fafc;--hi:#b42318;--hib:#fee4e2;--md:#b54708;--mdb:#fef0c7;--lo:#175cd3;--lob:#d1e9ff;--ok:#067647;--okb:#d1fadf}
@media (prefers-color-scheme:dark){:root{--bg:#10141c;--fg:#e6e9ef;--mut:#98a2b3;--line:#2a3140;--card:#171c27;--hi:#fda29b;--hib:#55160c;--md:#fec84b;--mdb:#4e2a05;--lo:#84caff;--lob:#0b2a52;--ok:#6ce9a6;--okb:#053321}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 20px 60px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:15px;margin:22px 0 8px}.sub{color:var(--mut);margin:0 0 18px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.card b{display:block;font-size:20px}.card span{color:var(--mut);font-size:12px}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{background:var(--card);position:sticky;top:0;white-space:nowrap}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.b{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}.HIGH,.VERYHIGH,.LIKELYMALICIOUS,.SUSPICIOUS{background:var(--hib);color:var(--hi)}
.MED,.MODERATE,.REVIEW{background:var(--mdb);color:var(--md)}.LOW{background:var(--lob);color:var(--lo)}.CLEAN{background:var(--okb);color:var(--ok)}
.note{background:var(--card);border-left:4px solid var(--md);padding:10px 14px;border-radius:4px;color:var(--mut)}footer{margin-top:40px;color:var(--mut);font-size:12px}
@media print{body{background:#fff;color:#000}.tw{overflow:visible}th{position:static}}
"""

def write_html_report(results, evidence, meta, path, files):
    from html import escape as E
    def badge(x):
        x = str(x)
        return f'<span class="b {re.sub(r"[^A-Za-z]", "", x)}">{E(x)}</span>'
    def tab(headers, rows, num=()):
        h = "".join(f'<th class="{"n" if i in num else ""}">{E(c)}</th>' for i, c in enumerate(headers))
        body = ""
        for r in rows:
            body += "<tr>" + "".join(
                f'<td class="{"n" if i in num else ""}">{c if isinstance(c, Raw) else E(str(c))}</td>' for i, c in enumerate(r)) + "</tr>"
        return f'<div class="tw"><table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table></div>'
    class Raw(str):
        pass
    rs = sorted(results, key=lambda x: -x["tracker_score"])
    o = [f'<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
         f'<title>Network forensics report</title><style>{REPORT_CSS}</style><main>',
         "<h1>Network forensics report</h1>",
         f'<p class="sub">Generated {E(meta["generated_utc"])} &middot; {E(meta["tool"])} &middot; {len(results)} source(s) from {len(evidence)} capture file(s)</p>',
         "<h2>1. Summary</h2>"]
    worst = max(results, key=lambda x: x["suspicion_points"])
    o.append('<div class="cards">'
             f'<div class="card"><b>{len(results)}</b><span>sources analysed</span></div>'
             f'<div class="card"><b>{max(r["tracker_score"] for r in results)}</b><span>highest tracker score</span></div>'
             f'<div class="card"><b>{sum(r["tracker_domains"] for r in results)}</b><span>tracker/ad domains (total)</span></div>'
             f'<div class="card"><b>{sum(len(r["findings"]) for r in results)}</b><span>forensic findings</span></div>'
             f'<div class="card"><b>{E(worst["verdict"])}</b><span>worst verdict ({E(worst["source"])})</span></div></div>')
    o.append(tab(["Source", "Websites visited", "Score", "Level", "Domains", "Third-party", "Trackers", "Trk %", "Tracker bytes", "Total bytes", "Susp. pts", "Verdict"],
                 [[r["source"], r["sites_text"], r["tracker_score"], Raw(badge(r["tracker_level"])), r["domains"], r["third_party"], r["tracker_domains"],
                   f'{r["tracker_ratio"]*100:.0f}%', fmt_b(r["tracker_bytes"]), fmt_b(r["total_bytes"]), r["suspicion_points"], Raw(badge(r["verdict"]))]
                  for r in rs], num=(2, 4, 5, 6, 7, 8, 9, 10)))
    o.append('<p class="note"><b>How to read this.</b> The tracker score (0-100) combines how many tracker/ad domains were contacted, their share of all domains and of traffic, '
             'and how many categories they span. Findings are heuristics: they say &ldquo;worth checking&rdquo;, not &ldquo;proven malicious&rdquo;. '
             'Traffic is never decrypted; only DNS, TLS SNI, cleartext HTTP, flow sizes and timing are examined.</p>')
    for n, r in enumerate(rs, 1):
        o.append(f'<h2>2.{n} Source: {E(r["source"])}</h2>')
        o.append('<div class="cards">'
                 f'<div class="card"><b>{r["tracker_score"]}/100</b><span>tracker score &middot; {E(r["tracker_level"])}</span></div>'
                 f'<div class="card"><b>{r["domains"]}</b><span>domains contacted</span></div>'
                 f'<div class="card"><b>{r["tracker_domains"]}</b><span>tracker/ad domains ({r["tracker_ratio"]*100:.0f}%)</span></div>'
                 f'<div class="card"><b>{fmt_b(r["tracker_bytes"])}</b><span>tracker traffic of {fmt_b(r["total_bytes"])}</span></div>'
                 f'<div class="card"><b>{E(r["verdict"])}</b><span>{r["suspicion_points"]} suspicion points</span></div></div>')
        if r["websites"]:
            o.append(f"<h3>Websites in this capture ({len(r['websites'])})</h3>" + tab(["Website", "Role", "Hosts", "DNS", "Flows", "Traffic"],
                     [[Raw(f'<code>{E(w["site"])}</code>'), w["role"], ", ".join(w["hosts"][:5]), w["dns"], w["flows"], fmt_b(w["up"] + w["down"])] for w in r["websites"]], num=(3, 4)))
        if r["categories"]:
            o.append("<h3>Tracker categories</h3>" + tab(["Category", "Unique domains"], [[k, v] for k, v in sorted(r["categories"].items(), key=lambda kv: -kv[1])], num=(1,)))
        o.append("<h3>Forensic findings</h3>")
        if r["findings"]:
            sev_order = {"HIGH": 0, "MED": 1, "LOW": 2}
            fs = sorted(r["findings"], key=lambda x: sev_order.get(x["sev"], 3))
            o.append(tab(["Severity", "Type", "Indicator", "Detail"], [[Raw(badge(x["sev"])), x["type"], Raw(f'<code>{E(str(x["indicator"]))}</code>'), x["detail"]] for x in fs]))
        else:
            o.append("<p>No suspicious indicators.</p>")
        o.append("<h3>Tracker / ad domains (all, by traffic)</h3>")
        o.append(tab(["Domain", "Category", "DNS", "Flows", "Upload", "Download", "Server IPs", "Vendor / data typically collected", "Basis"],
                     [[Raw(f'<code>{E(t["domain"])}</code>'), t["cat"], t["dns"], t["flows"], fmt_b(t["up"]), fmt_b(t["down"]),
                       Raw("<br>".join(f"<code>{E(i)}</code>" for i in (t["ips"] or t["dns_ips"])[:6])),
                       f'{t["vendor"]}: {t["data"]}' if t["vendor"] else t["data"], t["basis"]] for t in r["trackers"]], num=(2, 3, 4, 5))
                 if r["trackers"] else "<p>None found.</p>")
        dests = r["destinations"]
        if dests and any("country" in d for d in dests):
            by = defaultdict(lambda: [set(), 0, 0])
            for d in dests:
                c = by[d.get("country", "?") or "?"]
                c[0].add(d["ip"]); c[1] += d["up"] + d["down"]; c[2] += (d["up"] + d["down"]) if d["tracker"] else 0
            o.append("<h3>Destination countries</h3>" + tab(["Country", "IPs", "Bytes", "Tracker bytes"],
                     [[k, len(v[0]), fmt_b(v[1]), fmt_b(v[2])] for k, v in sorted(by.items(), key=lambda kv: -kv[1][1])], num=(1, 2, 3)))
        if dests:
            o.append(f"<h3>Top destinations (up to {min(len(dests), 50)} of {len(dests)})</h3>" + tab(
                ["IP", "Name", "Owner / ASN", "Country", "City", "Upload", "Download", "Flows", "Tracker"],
                [[Raw(f'<code>{E(d["ip"])}</code>'), d.get("name") or "", d.get("asn") or d.get("owner") or "", d.get("country", ""), d.get("city", ""),
                  fmt_b(d["up"]), fmt_b(d["down"]), d["flows"], "yes" if d["tracker"] else ""] for d in dests[:50]], num=(5, 6, 7)))
    o.append("<h2>3. Evidence / chain of custody</h2>")
    o.append(tab(["File", "SHA-256", "Size", "Packets", "Capture start", "Capture end"],
                 [[Raw(f'<code>{E(str(e.get("file", "")))}</code>'), Raw(f'<code>{E(str(e.get("sha256", "")))}</code>'), fmt_b(e.get("size_bytes", 0)),
                   e.get("packets", ""), e.get("capture_start", ""), e.get("capture_end", "")] for e in evidence], num=(2, 3)))
    o.append("<h2>4. Run details</h2>")
    o.append(tab(["Item", "Value"], [[k, Raw(f'<code>{E(str(v))}</code>')] for k, v in meta.items()]))
    o.append("<h2>5. Files produced by this run</h2><ul>" + "".join(f"<li><code>{E(f)}</code></li>" for f in files) + "</ul>")
    o.append(f'<footer>Verify integrity of every file in this folder with MANIFEST_sha256.txt. Report generated by {E(meta["tool"])}.</footer></main></html>')
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(o))

XL_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

def write_xlsx(results, evidence, meta, path):
    """Formatted Excel workbook (needs openpyxl). Returns False when openpyxl is not installed."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        from openpyxl.utils import get_column_letter
        from openpyxl.chart import BarChart, Reference
        from openpyxl.formatting.rule import DataBarRule
    except ImportError:
        return False
    rs = sorted(results, key=lambda x: -x["tracker_score"])
    thin = Side(style="thin", color="D0D5DD")
    BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)
    HDR_FILL, HDR_FONT = PatternFill("solid", fgColor="1F3864"), Font(bold=True, color="FFFFFF")
    SEV = {"HIGH": ("F4B6B0", "7A0C00"), "MED": ("FFE1A8", "7A4A00"), "LOW": ("CFE2FF", "0B3D91")}
    LEVEL = {"VERY HIGH": ("F4B6B0", "7A0C00"), "HIGH": ("F9CBA7", "7A3000"), "MODERATE": ("FFE1A8", "7A4A00"), "LOW": ("C6EFCE", "0B5A1E")}
    VERDICT = {"CLEAN": ("C6EFCE", "0B5A1E"), "REVIEW": ("FFE1A8", "7A4A00"), "SUSPICIOUS": ("F9CBA7", "7A3000"), "LIKELY MALICIOUS": ("F4B6B0", "7A0C00")}
    INT, DEC1, PCT, GEO = "#,##0", "0.0", "0%", "0.0000"
    widths = {}

    def setc(ws, row, col, v):
        if isinstance(v, str):
            v = XL_ILLEGAL.sub("", v)
        c = ws.cell(row=row, column=col, value=v)
        if isinstance(v, str) and v[:1] == "=":
            c.data_type = "s"                       # never let capture data become an Excel formula
        return c

    def put_table(ws, r0, headers, rows, fmts=None, wrap=(), colors=None, mono=(), max_w=60):
        fmts, colors = fmts or {}, colors or {}
        for j, h in enumerate(headers):
            c = setc(ws, r0, j + 1, h)
            c.fill, c.font, c.border = HDR_FILL, HDR_FONT, BORDER
            c.alignment = Alignment(vertical="center", wrap_text=True)
            widths[(ws.title, j)] = max(widths.get((ws.title, j), 0), len(str(h)))
        for i, row in enumerate(rows, r0 + 1):
            for j, v in enumerate(row):
                c = setc(ws, i, j + 1, v)
                c.border = BORDER
                c.alignment = Alignment(vertical="top", wrap_text=j in wrap)
                if j in mono:
                    c.font = Font(name="Consolas", size=10)
                if j in fmts and isinstance(v, (int, float)):
                    c.number_format = fmts[j]
                if j in colors and isinstance(v, str) and v in colors[j]:
                    bg, fg = colors[j][v]
                    c.fill, c.font = PatternFill("solid", fgColor=bg), Font(bold=True, color=fg)
                ln = len(f"{v:,}") if isinstance(v, int) else len(str(v)) if v is not None else 0
                widths[(ws.title, j)] = max(widths.get((ws.title, j), 0), min(ln, max_w))
        ws.row_dimensions[r0].height = 30
        return r0 + len(rows)

    def finish(ws, ncols, last, freeze="A2", filt=True):
        for j in range(ncols):
            ws.column_dimensions[get_column_letter(j + 1)].width = min(max(widths.get((ws.title, j), 8) + 2, 9), 62)
        if freeze:
            ws.freeze_panes = freeze
        if filt:
            ws.auto_filter.ref = f"A{int(freeze[1:]) - 1}:{get_column_letter(ncols)}{max(last, int(freeze[1:]) - 1)}"

    wb = Workbook()
    # ---------------- Summary
    ws = wb.active
    ws.title = "Summary"
    ws["A1"] = "Network forensics report"
    ws["A1"].font = Font(size=16, bold=True, color="1F3864")
    ws["A2"] = f'Generated {meta["generated_utc"]}  |  {meta["tool"]}  |  {len(results)} source(s)  |  {len(evidence)} capture file(s)'
    ws["A2"].font = Font(italic=True, color="667085")
    hdr = ["Source", "Tracker score (0-100)", "Level", "Domains", "Third-party domains", "Tracker/ad domains", "Tracker % of domains",
           "Tracker bytes", "Total bytes", "Tracker % of bytes", "Suspicion points", "Verdict", "Websites visited"]
    rows = [[r["source"], r["tracker_score"], r["tracker_level"], r["domains"], r["third_party"], r["tracker_domains"], r["tracker_ratio"],
             r["tracker_bytes"], r["total_bytes"], (r["tracker_bytes"] / r["total_bytes"]) if r["total_bytes"] else 0,
             r["suspicion_points"], r["verdict"], r["sites_text"]] for r in rs]
    last = put_table(ws, 4, hdr, rows, fmts={1: DEC1, 3: INT, 4: INT, 5: INT, 6: PCT, 7: INT, 8: INT, 9: PCT, 10: INT},
                     colors={2: LEVEL, 11: VERDICT})
    note_r = last + 2
    ws.merge_cells(start_row=note_r, start_column=1, end_row=note_r, end_column=12)
    ws.cell(note_r, 1, "How to read: the tracker score (0-100) combines the number of tracker/ad domains contacted, their share of all domains and of traffic, "
            "and how many tracker categories are involved. Findings are heuristics (\"worth checking\"), not proof of malicious activity. "
            "Traffic is never decrypted: only DNS, TLS SNI, cleartext HTTP, flow sizes and timing are examined.").alignment = Alignment(wrap_text=True, vertical="top")
    ws.row_dimensions[note_r].height = 48
    ch = BarChart()
    ch.type, ch.title, ch.style = "col", "Tracker/ad domains per source", 10
    ch.y_axis.title, ch.x_axis.title = "unique domains", "source"
    ch.y_axis.delete = ch.x_axis.delete = False
    ch.add_data(Reference(ws, min_col=6, min_row=4, max_row=last), titles_from_data=True)
    ch.set_categories(Reference(ws, min_col=1, min_row=5, max_row=last))
    ch.legend = None
    ch.width, ch.height = 22, 9
    ws.add_chart(ch, f"A{note_r + 2}")
    finish(ws, len(hdr), last, freeze="A5", filt=True)
    ws.column_dimensions["A"].width = max(ws.column_dimensions["A"].width, 24)

    # ---------------- Websites
    ws = wb.create_sheet("Websites")
    h = ["Source", "Website (domain)", "Role", "Hosts", "DNS queries", "Flows", "Upload (bytes)", "Download (bytes)"]
    rows = [[r["source"], w["site"], w["role"], ", ".join(w["hosts"][:8]), w["dns"], w["flows"], w["up"], w["down"]] for r in rs for w in r["websites"]]
    last = put_table(ws, 1, h, rows or [["-", "none found", "", "", 0, 0, 0, 0]], fmts={4: INT, 5: INT, 6: INT, 7: INT}, wrap=(3,), mono=(1,), max_w=70)
    finish(ws, len(h), last)

    # ---------------- Findings
    ws = wb.create_sheet("Findings")
    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    rows = [[r["source"], x["sev"], x["type"], x["indicator"], x["detail"]]
            for r in rs for x in sorted(r["findings"], key=lambda f: order.get(f["sev"], 3))]
    h = ["Source", "Severity", "Type", "Indicator", "Detail"]
    last = put_table(ws, 1, h, rows or [["-", "", "No suspicious indicators", "", ""]], wrap=(3, 4), colors={1: SEV}, max_w=70)
    finish(ws, len(h), last)

    # ---------------- Trackers
    ws = wb.create_sheet("Trackers")
    h = ["Source", "Domain", "Category", "DNS queries", "Flows", "Upload (bytes)", "Download (bytes)", "Total (bytes)",
         "Server IPs (connected)", "IPs from DNS answer", "Protocol", "Vendor / service", "Data typically collected", "Basis", "Evidence in capture", "Verified in list(s)"]
    rows = [[r["source"], t["domain"], t["cat"], t["dns"], t["flows"], t["up"], t["down"], t["up"] + t["down"],
             fmt_ips(t["ips"]), fmt_ips(t["dns_ips"]), "/".join(t["ports"]), t["vendor"], t["data"], t["basis"], t["evidence"], t["listed_in"]]
            for r in rs for t in r["trackers"]]
    last = put_table(ws, 1, h, rows or [["-", "none found", "", 0, 0, 0, 0, 0, "", "", "", "", "", "", "", ""]],
                     fmts={3: INT, 4: INT, 5: INT, 6: INT, 7: INT}, wrap=(8, 9, 11, 12, 14), mono=(8, 9))
    if last >= 2:
        ws.conditional_formatting.add(f"H2:H{last}", DataBarRule(start_type="min", end_type="max", color="5B9BD5"))
        for rr in range(2, last + 1):                    # mark OBSERVED rows
            c = ws.cell(rr, 14)
            if isinstance(c.value, str) and c.value.startswith("OBSERVED"):
                c.fill, c.font = PatternFill("solid", fgColor="F4B6B0"), Font(bold=True, color="7A0C00")
    finish(ws, len(h), last)
    for col, w in (("I", 18), ("J", 22), ("K", 10), ("L", 30), ("M", 60), ("N", 24), ("O", 55), ("P", 26)):
        ws.column_dimensions[col].width = w

    # ---------------- Destinations
    ws = wb.create_sheet("Destinations")
    h = ["Source", "IP", "Name", "Owner", "ASN", "Country", "City", "Latitude", "Longitude", "Upload (bytes)", "Download (bytes)", "Total (bytes)", "Flows", "Tracker/ad"]
    rows = [[r["source"], d["ip"], d.get("name") or "", d.get("owner") or "", d.get("asn", ""), d.get("country", ""), d.get("city", ""),
             d.get("lat") if d.get("lat") is not None else "", d.get("lon") if d.get("lon") is not None else "",
             d["up"], d["down"], d["up"] + d["down"], d["flows"], "yes" if d["tracker"] else "no"] for r in rs for d in r["destinations"]]
    last = put_table(ws, 1, h, rows or [["-"] + [""] * 13], fmts={7: GEO, 8: GEO, 9: INT, 10: INT, 11: INT, 12: INT}, mono=(1,))
    if last >= 2:
        ws.conditional_formatting.add(f"L2:L{last}", DataBarRule(start_type="min", end_type="max", color="5B9BD5"))
    finish(ws, len(h), last)

    # ---------------- Countries
    ws = wb.create_sheet("Countries")
    rows = []
    for r in rs:
        by = defaultdict(lambda: [set(), 0, 0])
        for d in r["destinations"]:
            c = by[d.get("country") or "unknown"]
            c[0].add(d["ip"]); c[1] += d["up"] + d["down"]; c[2] += (d["up"] + d["down"]) if d["tracker"] else 0
        for k, v in sorted(by.items(), key=lambda kv: -kv[1][1]):
            rows.append([r["source"], k, len(v[0]), v[1], v[2], (v[2] / v[1]) if v[1] else 0])
    h = ["Source", "Country", "IPs", "Total (bytes)", "Tracker/ad (bytes)", "Tracker % of bytes"]
    last = put_table(ws, 1, h, rows or [["-", "(no GeoIP data)", 0, 0, 0, 0]], fmts={2: INT, 3: INT, 4: INT, 5: PCT})
    if last >= 2:
        ws.conditional_formatting.add(f"D2:D{last}", DataBarRule(start_type="min", end_type="max", color="5B9BD5"))
    finish(ws, len(h), last)

    # ---------------- Evidence
    ws = wb.create_sheet("Evidence")
    h = ["#", "File", "SHA-256", "Size (bytes)", "Packets", "Capture start", "Capture end"]
    rows = [[i, e.get("file", ""), e.get("sha256", ""), e.get("size_bytes", 0), e.get("packets", ""), e.get("capture_start", ""), e.get("capture_end", "")]
            for i, e in enumerate(evidence, 1)]
    last = put_table(ws, 1, h, rows, fmts={0: "0", 3: INT, 4: INT}, mono=(2,), max_w=70)
    finish(ws, len(h), last)

    # ---------------- About
    ws = wb.create_sheet("About")
    last = put_table(ws, 1, ["Item", "Value"], [[k, str(v)] for k, v in meta.items()], wrap=(1,), max_w=80)
    legend = [
        ("Tracker score", "50 x min(1, tracker domains / 50) + 25 x min(1, tracker domain share / 0.5) + 15 x min(1, tracker flow share / 0.5) + 10 x min(1, categories / 5)"),
        ("Tracker level", "LOW < 25, MODERATE < 50, HIGH < 75, VERY HIGH >= 75"),
        ("Suspicion points", "HIGH finding = 10, MED = 4, LOW = 1"),
        ("Verdict", "CLEAN < 5, REVIEW < 20, SUSPICIOUS < 50, LIKELY MALICIOUS >= 50"),
        ("Severity", "HIGH = strong indicator, MED = needs a look, LOW = informational"),
        ("Trackers: Server IPs", "IPs actually connected to (from flows). 'IPs from DNS answer' = every IP the DNS reply listed for that name (may include IPs never used)."),
        ("Trackers: Data typically collected", "Documented behaviour of that vendor/category (page URL, IP, user-agent, device info, cookie/ad IDs ...). Traffic is encrypted, so this is a vendor profile, NOT decrypted proof."),
        ("Trackers: Basis", "OBSERVED = identifier seen in cleartext HTTP to that tracker. INFERRED = vendor profile + traffic size/direction only."),
        ("Limits", "Heuristics only. No decryption. QUIC/ECH/DoH can hide names. Multicast/link-local traffic is ignored."),
    ]
    last = put_table(ws, last + 3, ["Term", "Meaning"], [list(x) for x in legend], wrap=(1,), max_w=80)
    for j in range(2):
        ws.column_dimensions[get_column_letter(j + 1)].width = [24, 90][j]
    wb.save(path)
    return True

def write_run_files(results, evidence, meta, run_dir, stamp, geo_ok):
    """Writes every output of a run into run_dir and returns the list of file names."""
    rs = sorted(results, key=lambda x: -x["tracker_score"])
    j = lambda n: os.path.join(run_dir, n)
    # chain of custody (text)
    with open(j(f"evidence_{stamp}.txt"), "w", encoding="utf-8") as fh:
        fh.write("EVIDENCE / CHAIN-OF-CUSTODY RECORD\n" + "=" * 60 + "\n")
        for k, v in meta.items():
            fh.write(f"{k:16}: {v}\n")
        fh.write("=" * 60 + "\n")
        for i, ev in enumerate(evidence, 1):
            fh.write(f"[capture {i}]\n")
            for k, v in ev.items():
                fh.write(f"  {k:16}: {v}\n")
            fh.write("-" * 60 + "\n")
    # JSON: self-describing, full detail
    summary = [{k: r[k] for k in ("source", "main_site", "sites_text", "tracker_score", "tracker_level", "domains", "third_party", "tracker_domains", "tracker_ratio",
                                  "tracker_bytes", "total_bytes", "suspicion_points", "verdict")} for r in rs]
    with open(j(f"report_{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump(dict(schema_version="1.4", meta=meta, summary=summary, evidence=evidence, results=results),
                  f, indent=2, ensure_ascii=False, default=str)
    # Excel (CSV fallback if openpyxl is missing)
    if not write_xlsx(results, evidence, meta, j(f"report_{stamp}.xlsx")):
        print("[!] openpyxl not installed -> writing CSV files instead (pip install openpyxl for the formatted Excel workbook)")
        write_csv(j(f"tracker_scores_{stamp}.csv"), list(summary[0].keys()), [list(x.values()) for x in summary])
        write_csv(j(f"findings_{stamp}.csv"), ["source", "severity", "type", "indicator", "detail"],
                  [[r["source"], x["sev"], x["type"], x["indicator"], x["detail"]] for r in results for x in r["findings"]])
        write_csv(j(f"trackers_{stamp}.csv"), ["source", "domain", "category", "dns_queries", "flows", "upload_bytes", "download_bytes",
                                                "server_ips", "dns_ips", "protocol", "vendor", "data_typically_collected", "basis", "evidence"],
                  [[r["source"], t["domain"], t["cat"], t["dns"], t["flows"], t["up"], t["down"], " ".join(t["ips"]), " ".join(t["dns_ips"]),
                    "/".join(t["ports"]), t["vendor"], t["data"], t["basis"], t["evidence"]] for r in results for t in r["trackers"]])
        write_csv(j(f"destinations_{stamp}.csv"),
                  ["source", "ip", "name", "owner", "asn", "country", "city", "latitude", "longitude", "upload_bytes", "download_bytes", "flows", "tracker"],
                  [[r["source"], d["ip"], d.get("name") or "", d.get("owner") or "", d.get("asn", ""), d.get("country", ""), d.get("city", ""),
                    d.get("lat", ""), d.get("lon", ""), d["up"], d["down"], d["flows"], "yes" if d["tracker"] else "no"]
                   for r in results for d in r["destinations"]])
    # charts
    try:
        save_charts(results, run_dir, stamp)
    except ImportError:
        print("[!] matplotlib not installed -> PNG charts skipped (pip install matplotlib)")
    except Exception as e:
        print(f"[!] charts skipped: {e}")
    if geo_ok:
        write_geo_html(results, j(f"geo_map_{stamp}.html"))
    # HTML report last (it lists the files), then a manifest of everything
    names = sorted(set(os.listdir(run_dir)) | {f"report_{stamp}.html", "MANIFEST_sha256.txt"})
    write_html_report(results, evidence, meta, j(f"report_{stamp}.html"), names)
    names = sorted(n for n in os.listdir(run_dir) if n != "MANIFEST_sha256.txt")
    with open(j("MANIFEST_sha256.txt"), "w", encoding="utf-8", newline="\n") as fh:     # sha256sum -c compatible
        for n in names:
            fh.write(f"{sha256_file(j(n))}  {n}\n")
    return sorted(names + ["MANIFEST_sha256.txt"])

def main():
    ap = argparse.ArgumentParser(description="pcap/pcapng privacy-leakage + suspicious-behaviour forensics")
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("-o", "--out", default="forensics_out")
    ap.add_argument("--first-party", default="", help="comma keywords treated as first-party (e.g. bbc,bbci)")
    ap.add_argument("--windows", help="CSV app,start,end[,first_party] to split one pcap per app")
    ap.add_argument("--offline", action="store_true", help="do NOT download tracker lists (use cached tracker_db.csv if present)")
    ap.add_argument("--allow", action="append", default=[], help="allow.txt: domains that must NEVER be reported as trackers (one per line)")
    ap.add_argument("--tracker-db", action="append", default=[], help="tracker_db.csv built by update_trackers.py (live Disconnect + StevenBlack lists)")
    ap.add_argument("--blocklist", action="append", default=[], help="hosts/domain list (StevenBlack, EasyPrivacy-domains)")
    ap.add_argument("--markers", action="store_true",
                    help="auto-split by DNS marker lookups: nslookup start-bbc.test ... nslookup stop.test")
    ap.add_argument("--fp", default="", help='first-party map, e.g. "bbc=bbc.co.uk;bbci.co.uk,fox=foxnews.com"')
    ap.add_argument("--geoip", help="GeoLite2-City.mmdb (MaxMind, free) for destination country/map")
    ap.add_argument("--asn", help="GeoLite2-ASN.mmdb (optional) for company/ASN names")
    ap.add_argument("--canary", default="", help="comma list of fake values to hunt for in cleartext")
    ap.add_argument("--min-beacon", type=int, default=8)
    ap.add_argument("--max-packets", type=int, default=0)
    a = ap.parse_args()

    files = []
    for x in a.pcaps:
        if os.path.isdir(x):
            files += sorted(os.path.join(x, n) for n in os.listdir(x) if n.lower().endswith((".pcap", ".pcapng")))
        else:
            files.append(x)
    if not files:
        sys.exit("no .pcap/.pcapng files found in the given path")
    a.pcaps = files

    for b in a.allow:
        print(f"[+] allowlist {b}: {load_allow(b)} domains")
    cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tracker_db.csv")
    if a.offline:
        db_status = "offline (cached file)"
    else:
        print("[*] downloading current ad/tracker lists (Disconnect + StevenBlack) ...")
        n_live, db_status = live_update(cache)
        print(f"    {db_status}: {n_live} domains")
        if n_live == 0 and os.path.exists(cache):
            db_status += " -> using OLD cached tracker_db.csv"
            print("    [!] no internet / download failed -> falling back to old cached tracker_db.csv")
    db_files = a.tracker_db or ([cache] if os.path.exists(cache) else [])
    db_hash = ""
    for b in db_files:
        print(f"[+] tracker-db {b}: {load_tracker_db(b)} domains added")
        db_hash = sha256_file(b)
    if not db_files:
        print("[!] no tracker_db available -> using only the built-in list (run once with internet)")
    for b in a.blocklist:
        print(f"[+] blocklist {b}: {load_blocklist(b)} domains")
    canaries = [c.strip().encode() for c in a.canary.split(",") if c.strip()]
    os.makedirs(a.out, exist_ok=True)
    results = []
    evidence = []

    for path in a.pcaps:
        stem = os.path.splitext(os.path.basename(path))[0]
        print(f"\n[*] parsing {path} ...")
        R = parse_pcap(path, canaries, a.max_packets)
        ev = file_evidence(path)
        iso = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if t else "?"
        ev.update(capture_start=iso(R["t0"]), capture_end=iso(R["t1"]), packets=R["pkts"])
        evidence.append(ev)
        print(f"    SHA-256: {ev['sha256']}")
        dur = (R["t1"] or 0) - (R["t0"] or 0)
        print(f"    {R['pkts']} pkts, {fmt_b(R['bytes'])}, {dur:.0f}s, {len(R['flows'])} flows, "
              f"{len(R['dns_q'])} DNS queries, {len(R['sni'])} TLS SNI, {len(R['http'])} HTTP requests")
        print("    protocols: " + ", ".join(f"{k}={v}" for k, v in R["protos"].most_common(8)))
        if R["t0"] is None:
            continue
        jobs = []
        fpmap = parse_fp_map(a.fp)
        if a.markers:
            mw = marker_windows(R)
            if not mw:
                print("    [!] no start-*.test markers found in this pcap, analysing whole file")
            for app, lo, hi in mw:
                jobs.append((app, lo, hi, fpmap.get(app.lower()) or re.findall(r"[a-z0-9]{3,}", app.lower())))
                print(f"    marker window: {app}  {lo - R['t0']:.0f}s -> {hi - R['t0']:.0f}s")
        if jobs:
            pass
        elif a.windows:
            with open(a.windows, newline="") as f:
                for row in csv.DictReader(f):
                    fp = [k for k in re.split(r"[;,|]", row.get("first_party", "") or "") if k]
                    jobs.append((row["app"], parse_t(row["start"], R["t0"]), parse_t(row["end"], R["t0"]),
                                 fp or re.findall(r"[a-z0-9]{3,}", row["app"].lower())))
        else:
            fp = [k for k in a.first_party.lower().split(",") if k] or re.findall(r"[a-z0-9]{3,}", stem.lower())
            jobs.append((stem, 0, float("inf"), fp))
        for name, lo, hi, fp in jobs:
            res = analyse(name, slice_res(R, lo, hi), fp, a.min_beacon, t0=R["t0"])
            res["evidence"] = dict(ev, window_start_s=round(max(lo, R["t0"]) - R["t0"], 1),
                                   window_end_s=round(min(hi, R["t1"]) - R["t0"], 1))
            results.append(res)

    if not results:
        sys.exit("no results")

    # ---- per-source detail
    for r in results:
        print("\n" + "=" * 90)
        print(f"SOURCE: {r['source']}   |  tracker score {r['tracker_score']}/100 ({r['tracker_level']})  |  verdict: {r['verdict']}")
        print("=" * 90)
        print(f"main website: {r['main_site'] or '?'}" + ("  (inferred - use --first-party to pin it)" if r["main_site_inferred"] else ""))
        if r["websites"]:
            print(f"\nWebsites in this capture ({len(r['websites'])}):")
            print(table([[w["site"], w["role"], len(w["hosts"]), w["dns"], w["flows"], fmt_b(w["up"] + w["down"])]
                         for w in r["websites"][:40]], ["website", "role", "hosts", "dns", "flows", "traffic"]))
            print()
        print(f"domains={r['domains']}  third-party={r['third_party']}  tracker/ad domains={r['tracker_domains']} "
              f"({r['tracker_ratio']*100:.0f}%)  tracker traffic={fmt_b(r['tracker_bytes'])}/{fmt_b(r['total_bytes'])}")
        if r["categories"]:
            print("categories: " + ", ".join(f"{k}={v}" for k, v in r["categories"].items()))
        if r["trackers"]:
            print("\nTop tracker/ad domains:")
            print(table([[t["domain"], t["cat"], t["dns"], t["flows"], fmt_b(t["up"]), fmt_b(t["down"])]
                         for t in r["trackers"][:15]], ["domain", "category", "dns", "flows", "up", "down"]))
        if r["findings"]:
            print("\nSuspicious / forensic findings:")
            print(table([[x["sev"], x["type"], x["indicator"], x["detail"]] for x in r["findings"][:30]],
                        ["sev", "type", "indicator", "detail"], 80))
        else:
            print("\nNo suspicious indicators.")

    # ---- comparison
    print("\n" + "#" * 90 + "\nCOMPARISON (sorted by tracker score)\n" + "#" * 90)
    rs = sorted(results, key=lambda x: -x["tracker_score"])
    print(table([[r["source"], r["sites_text"], r["tracker_score"], r["tracker_level"], r["domains"], r["tracker_domains"],
                  f"{r['tracker_ratio']*100:.0f}%", fmt_b(r["tracker_bytes"]), r["suspicion_points"], r["verdict"]]
                 for r in rs], ["source", "websites", "score", "level", "domains", "trackers", "trk%", "trk bytes", "sus.pts", "verdict"]))

    # ---- GeoIP
    geo_ok = bool(a.geoip) and geo_enrich(results, a.geoip, a.asn)
    if geo_ok:
        for r in results:
            by = defaultdict(lambda: [set(), 0, 0])
            for d in r["destinations"]:
                c = by[d.get("country", "?")]
                c[0].add(d["ip"]); c[1] += d["up"] + d["down"]; c[2] += (d["up"] + d["down"]) if d["tracker"] else 0
            print(f"\nDestination countries: {r['source']}")
            print(table([[k, len(v[0]), fmt_b(v[1]), fmt_b(v[2])] for k, v in sorted(by.items(), key=lambda kv: -kv[1][1])[:12]],
                        ["country", "IPs", "bytes", "tracker bytes"]))

    # ---- files (everything for one run goes into its own folder)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(a.out, f"run_{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    meta = {
        "tool": TOOL_VERSION,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "command_line": " ".join(sys.argv),
        "capture_files": len(a.pcaps),
        "geoip_database": os.path.basename(a.geoip) if a.geoip else "not used",
        "asn_database": os.path.basename(a.asn) if a.asn else "not used",
        "min_beacon_events": a.min_beacon,
        "tracker_lists": f"{db_status}; files: {', '.join(os.path.basename(x) for x in db_files) or 'built-in only'}",
        "tracker_db_sha256": db_hash or "n/a",
    }
    files = write_run_files(results, evidence, meta, run_dir, stamp, geo_ok)
    print(f"\n[+] saved {len(files)} files in {run_dir}")
    print(f"[+] start with: {os.path.join(run_dir, f'report_{stamp}.html')}")
    if geo_ok:
        print(f"[+] map: {os.path.join(run_dir, f'geo_map_{stamp}.html')}  (needs internet for map tiles)")

if __name__ == "__main__":
    main()
