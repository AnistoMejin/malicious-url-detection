"""Lexical and host-based feature extraction for URL classification.

Every feature is computed from the URL STRING ONLY - this module never opens a
network connection, resolves DNS or fetches page content. That is deliberate:
visiting a possibly malicious URL to inspect it would be unsafe and is out of
scope for this project.

Public interface:
    FEATURE_NAMES              ordered, stable list of feature column names
    extract_features(url)      dict keyed exactly by FEATURE_NAMES
    featurize(urls)            np.ndarray of shape (len(urls), len(FEATURE_NAMES))
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse

import numpy as np

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "count_dot",
    "count_hyphen",
    "count_underscore",
    "count_slash",
    "count_question",
    "count_equal",
    "count_at",
    "count_ampersand",
    "count_percent",
    "count_digits",
    "count_letters",
    "count_special",
    "num_subdomains",
    "tld_length",
    "is_ip_host",
    # NOTE: "uses_https" was removed deliberately. The scheme is stripped during
    # normalisation (see extract_features), so the feature carried no information
    # and its only effect was to leak the dataset's collection artifact.
    "has_port",
    "has_at_symbol",
    "has_double_slash_redirect",
    "url_entropy",
    "hostname_entropy",
    "digit_letter_ratio",
    "longest_token_length",
    "suspicious_keyword_count",
    "is_shortened",
    "hostname_has_digit",
    "hostname_hyphen_count",
]

SUSPICIOUS_KEYWORDS = (
    "login",
    "secure",
    "account",
    "update",
    "verify",
    "bank",
    "paypal",
    "signin",
    "confirm",
    "webscr",
    "free",
    "bonus",
)

SHORTENER_DOMAINS = (
    "bit.ly",
    "goo.gl",
    "tinyurl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
)

_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")

_ZERO_ROW = [0.0] * len(FEATURE_NAMES)


def _shannon_entropy(text):
    """Shannon entropy (base 2) of the characters of `text`."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    total = 0.0
    for c in counts.values():
        p = c / n
        total -= p * math.log2(p)
    return total


def _is_ipv4(host):
    m = _IPV4_RE.match(host)
    if not m:
        return False
    for part in m.groups():
        if len(part) > 1 and part[0] == "0":
            return False
        if int(part) > 255:
            return False
    return True


def extract_features(url):
    """Return a dict of lexical/host features for a single URL string.

    Never raises: any input that is not a usable string yields an all-zero
    feature dict.
    """
    if not isinstance(url, str):
        url = "" if url is None else str(url)
    raw = url.strip()
    if not raw:
        return dict(zip(FEATURE_NAMES, _ZERO_ROW))

    # ------------------------------------------------------------------
    # Normalise away the scheme before doing anything else.
    #
    # In malicious_phish.csv the scheme is a COLLECTION ARTIFACT, not a
    # security signal: only 8.3% of benign URLs carry "http(s)://" but 100%
    # of defacement and 96.3% of malware do. A model allowed to see it simply
    # learns "has a scheme -> malicious", which scores ~96% on this dataset
    # while classifying https://www.google.com as malicious. Stripping the
    # scheme forces the model to rely on real lexical structure instead.
    # ------------------------------------------------------------------
    raw = _SCHEME_RE.sub("", raw, count=1)
    if not raw:
        return dict(zip(FEATURE_NAMES, _ZERO_ROW))

    lower = raw.lower()
    to_parse = "http://" + raw
    had_scheme = False

    try:
        parsed = urlparse(to_parse)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = parsed.netloc or ""
    except Exception:
        hostname = ""
        path = raw
        query = ""
        scheme = ""
        port = None
        netloc = ""

    hostname = hostname.lower()

    n_digits = 0
    n_letters = 0
    for ch in raw:
        if ch.isdigit():
            n_digits += 1
        elif ch.isalpha():
            n_letters += 1
    n_special = len(raw) - n_digits - n_letters

    is_ip = _is_ipv4(hostname)

    if is_ip or not hostname:
        labels = []
        tld_len = 0
    else:
        labels = [p for p in hostname.split(".") if p]
        tld_len = len(labels[-1]) if len(labels) > 1 else 0

    # host.tld counts as zero subdomains; www.host.tld counts as one.
    num_subdomains = max(0, len(labels) - 2) if not is_ip else 0

    has_port = 1.0 if (port is not None or re.search(r":\d+$", netloc)) else 0.0

    tokens = _TOKEN_RE.findall(raw)
    longest_token = max((len(t) for t in tokens), default=0)

    keyword_count = 0
    for kw in SUSPICIOUS_KEYWORDS:
        keyword_count += lower.count(kw)

    shortened = 0.0
    for dom in SHORTENER_DOMAINS:
        if dom in hostname or (not hostname and dom in lower):
            shortened = 1.0
            break

    # "//" appearing after the scheme's own separator suggests a redirect.
    tail = path + (("?" + query) if query else "")
    double_slash_redirect = 1.0 if "//" in tail else 0.0

    values = [
        float(len(raw)),
        float(len(hostname)),
        float(len(path)),
        float(len(query)),
        float(raw.count(".")),
        float(raw.count("-")),
        float(raw.count("_")),
        float(raw.count("/")),
        float(raw.count("?")),
        float(raw.count("=")),
        float(raw.count("@")),
        float(raw.count("&")),
        float(raw.count("%")),
        float(n_digits),
        float(n_letters),
        float(n_special),
        float(num_subdomains),
        float(tld_len),
        1.0 if is_ip else 0.0,
        has_port,
        1.0 if "@" in raw else 0.0,
        double_slash_redirect,
        _shannon_entropy(raw),
        _shannon_entropy(hostname),
        float(n_digits) / float(n_letters) if n_letters else float(n_digits),
        float(longest_token),
        float(keyword_count),
        shortened,
        1.0 if any(c.isdigit() for c in hostname) else 0.0,
        float(hostname.count("-")),
    ]

    return dict(zip(FEATURE_NAMES, values))


def featurize(urls):
    """Build a (n_urls, n_features) float array, preserving row order."""
    rows = []
    append = rows.append
    for u in urls:
        feats = extract_features(u)
        append([feats[name] for name in FEATURE_NAMES])
    if not rows:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
    return np.array(rows, dtype=np.float64)


if __name__ == "__main__":
    examples = [
        "https://www.google.com/search?q=machine+learning",
        "br-icloud.com.br",
        "http://192.168.1.15:8080/secure/login/update-account.php?verify=1",
    ]
    for example in examples:
        print(example)
        feats = extract_features(example)
        for name in FEATURE_NAMES:
            print("  {:<28} {}".format(name, round(feats[name], 4)))
        print()
    print("matrix shape:", featurize(examples).shape)
