"""Extract the same numeric URL features used by the URL-Phish CSV."""
from __future__ import annotations

import ipaddress
import math
from collections import Counter
from urllib.parse import urlsplit

import tldextract

# Disable network fetching of the public suffix list; use tldextract's bundled snapshot.
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

FEATURE_NAMES = [
    "url_len", "dom_len", "is_ip", "tld_len", "subdom_cnt",
    "letter_cnt", "digit_cnt", "special_cnt", "eq_cnt", "qm_cnt",
    "amp_cnt", "dot_cnt", "dash_cnt", "under_cnt", "letter_ratio",
    "digit_ratio", "spec_ratio", "is_https", "slash_cnt", "entropy",
    "path_len", "query_len",
]


def normalize_url(raw_url: str) -> str:
    """Trim input and add http:// when the user enters only a hostname/path."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("Please enter a URL.")
    url = raw_url.strip()
    if len(url) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    parsed = urlsplit(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    try:
        hostname = parsed.hostname or ""
    except ValueError as exc:
        raise ValueError("Invalid URL hostname.") from exc
    if not hostname:
        raise ValueError("Enter a valid URL with a hostname, such as example.com.")
    return url


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(raw_url: str) -> dict[str, int | float]:
    """Return URL numeric features with the exact names expected by the model."""
    url = normalize_url(raw_url)
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()

    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    if is_ip:
        domain = hostname
        suffix = ""
        subdomain_count = 0
    else:
        extracted = _TLD_EXTRACT(hostname)
        suffix = extracted.suffix or ""
        domain = (
            f"{extracted.domain}.{suffix}"
            if extracted.domain and suffix
            else (extracted.domain or hostname)
        )
        subdomain_count = len([part for part in extracted.subdomain.split(".") if part])

    url_length = len(url)
    letter_count = sum(char.isalpha() for char in url)
    digit_count = sum(char.isdigit() for char in url)
    special_count = url_length - letter_count - digit_count

    return {
        "url_len": url_length,
        "dom_len": len(domain),
        "is_ip": is_ip,
        "tld_len": len(suffix),
        "subdom_cnt": subdomain_count,
        "letter_cnt": letter_count,
        "digit_cnt": digit_count,
        "special_cnt": special_count,
        "eq_cnt": url.count("="),
        "qm_cnt": url.count("?"),
        "amp_cnt": url.count("&"),
        "dot_cnt": url.count("."),
        "dash_cnt": url.count("-"),
        "under_cnt": url.count("_"),
        "letter_ratio": letter_count / url_length if url_length else 0.0,
        "digit_ratio": digit_count / url_length if url_length else 0.0,
        "spec_ratio": special_count / url_length if url_length else 0.0,
        "is_https": int(parsed.scheme.lower() == "https"),
        "slash_cnt": url.count("/"),
        "entropy": _entropy(url),
        "path_len": len(parsed.path or ""),
        "query_len": len(parsed.query or ""),
    }
