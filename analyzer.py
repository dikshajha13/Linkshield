"""
analyzer.py - rule-based URL analysis engine for LinkShield.

IMPORTANT: this module only looks at the URL *text*. It never opens the URL,
resolves DNS or makes any network request (this avoids SSRF risks).

How scoring works
-----------------
Every rule has a fixed weight (see WEIGHTS). Each rule that matches adds its
weight to the score. The total is capped at 100.
    0-24  -> Low risk      25-59 -> Medium risk      60-100 -> High risk
The score is a heuristic. It is NOT a probability that the site is an attack.
"""
import ipaddress
import re
from urllib.parse import unquote, urlsplit

MAX_URL_LENGTH = 2048
MEDIUM_THRESHOLD = 25
HIGH_THRESHOLD = 60

DISCLAIMER = ("LinkShield only inspects the text of a URL. A low score does not guarantee "
              "a website is safe, and a high score does not prove it is malicious.")

# ---- Rule weights (points added when a rule matches) ----------------------
WEIGHTS = {
    "no_https": 10, "ip_host": 25, "obfuscated_ip": 30,
    "subdomains_many": 20, "subdomains_some": 10,
    "long_url": 8, "very_long_url": 15, "shortener": 25,
    "userinfo_at": 30, "at_in_path": 5, "punycode": 25,
    "brand_impersonation": 25, "lookalike": 25, "many_hyphens": 8,
    "sensitive_words": 6, "risky_tld": 8, "long_label": 5,
    "unusual_port": 12, "encoding_double": 15, "encoding_dangerous": 15,
    "encoding_heavy": 8, "redirect_param": 8,
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "bl.ink"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "country"}
BRANDS = {"paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
          "netflix", "whatsapp", "paytm", "hdfc", "icici", "sbi"}
# Real domains that legitimately contain a brand name (small demo allow-list).
SAFE_BRAND_DOMAINS = {"amazonaws.com", "googleapis.com", "googleusercontent.com",
                      "microsoftonline.com", "windows.net", "azure.com", "live.com"}
SENSITIVE_WORDS = {"login", "signin", "verify", "secure", "account", "update", "password",
                   "wallet", "confirm", "banking"}
# Two-part suffixes so "bbc.co.uk" is treated as domain "bbc" under "co.uk".
TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.in", "net.in",
                      "org.in", "ac.in", "gov.in", "co.jp", "com.br", "co.nz", "com.cn"}

_OBFUSCATED_IP = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TLD = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_LEET_O = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})
_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "5": "s", "$": "s"})


class ValidationError(ValueError):
    """Raised when the submitted text is not a usable http(s) URL."""


# ---- Documentation of the rules (shown on the "How It Works" section) -----
RULES = [
    ("No HTTPS", f"+{WEIGHTS['no_https']}", "Plain HTTP traffic is not encrypted. Common on old sites, so only a small penalty."),
    ("IP address as host", f"+{WEIGHTS['ip_host']}", "Legitimate public sites almost always use a domain name."),
    ("Obfuscated IP (decimal/hex)", f"+{WEIGHTS['obfuscated_ip']}", "Hosts like 3232235777 or 0x7f.0.0.1 hide an IP address."),
    ("Many subdomains", f"+{WEIGHTS['subdomains_some']} (3) / +{WEIGHTS['subdomains_many']} (4+)", "Long chains can bury the real domain."),
    ("Long URL", f"+{WEIGHTS['long_url']} (100+) / +{WEIGHTS['very_long_url']} (200+)", "Very long URLs can hide the real destination."),
    ("URL shortener", f"+{WEIGHTS['shortener']}", "The final destination is hidden behind a redirect."),
    ("'@' before the host", f"+{WEIGHTS['userinfo_at']}", "In http://a.com@b.com the browser goes to b.com, not a.com."),
    ("'@' in path/query", f"+{WEIGHTS['at_in_path']}", "Unusual but often harmless, so a small penalty."),
    ("Punycode (xn--)", f"+{WEIGHTS['punycode']}", "Can be used for look-alike international characters."),
    ("Brand name in wrong place", f"+{WEIGHTS['brand_impersonation']}", "e.g. paypal.example.com - brand appears but is not the real domain."),
    ("Look-alike spelling", f"+{WEIGHTS['lookalike']}", "e.g. paypa1 or rnicrosoft imitate a real brand."),
    ("Many hyphens", f"+{WEIGHTS['many_hyphens']}", "Hosts like secure-login-update-now.com are a common pattern."),
    ("Several sensitive words in host", f"+{WEIGHTS['sensitive_words']}", "login/verify/secure/account stacked in a hostname."),
    ("Frequently abused TLD", f"+{WEIGHTS['risky_tld']}", "Some cheap TLDs are over-represented in abuse reports."),
    ("Very long hostname label", f"+{WEIGHTS['long_label']}", "A single label over 30 characters is unusual."),
    ("Unusual port", f"+{WEIGHTS['unusual_port']}", "Anything other than 80 / 443."),
    ("Double encoding (%25xx)", f"+{WEIGHTS['encoding_double']}", "Used to slip patterns past filters."),
    ("Dangerous encoded pattern", f"+{WEIGHTS['encoding_dangerous']}", "Decodes to <script>, javascript:, ../ or control characters."),
    ("Heavy percent-encoding", f"+{WEIGHTS['encoding_heavy']}", "Many encoded characters make a URL hard to read."),
    ("Redirect-style parameter", f"+{WEIGHTS['redirect_param']}", "?next=http://... can send you to another site."),
]


def validate_url(raw_url):
    """Check the text is a well-formed http(s) URL. Returns (url, parts, host, port, kind).

    kind is 'domain', 'ip' or 'obfuscated_ip'. Raises ValidationError otherwise.
    """
    if not isinstance(raw_url, str):
        raise ValidationError("The URL must be sent as text.")
    url = raw_url.strip()
    if not url:
        raise ValidationError("Please enter a URL to scan.")
    if len(url) > MAX_URL_LENGTH:
        raise ValidationError(f"The URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if re.search(r"[\s\x00-\x1f\x7f]", url):
        raise ValidationError("The URL must not contain spaces or control characters.")
    if not re.match(r"^https?://", url, re.I):
        raise ValidationError("The URL must start with http:// or https://")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise ValidationError("This URL is malformed (check the port number and brackets).")
    if not host:
        raise ValidationError("The URL has no hostname, e.g. https://example.com")

    try:
        ipaddress.ip_address(host)
        kind = "ip"
    except ValueError:
        if _OBFUSCATED_IP.match(host):
            kind = "obfuscated_ip"
        else:
            kind = "domain"
            try:  # converts international names to xn-- form; also rejects empty labels
                host = host.encode("idna").decode("ascii").lower()
            except UnicodeError:
                raise ValidationError("The hostname contains invalid characters or empty parts.")
            labels = host.split(".")
            if len(labels) < 2:
                raise ValidationError("The hostname needs a domain and extension, e.g. example.com")
            if len(host) > 253 or not all(_LABEL.match(label) for label in labels):
                raise ValidationError("The hostname contains invalid characters.")
            if not _TLD.match(labels[-1]):
                raise ValidationError("The domain extension (like .com) is not valid.")
    return url, parts, host, port, kind


def _split_host(host):
    """Return (registered_domain, [subdomain labels]) using a simple suffix rule."""
    labels = host.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES else 2
    return ".".join(labels[-n:]), labels[:-n]


def _lookalike_variants(token):
    return {token.translate(_LEET_O), token.translate(_LEET_I),
            token.replace("rn", "m"), token.replace("vv", "w")}


def _level(score):
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def analyze_url(raw_url):
    """Analyze one URL string and return a result dictionary (JSON-serialisable)."""
    url, parts, host, port, kind = validate_url(raw_url)
    indicators, positives = [], []

    def add(rule_id, title, explanation):
        points = WEIGHTS[rule_id]
        severity = "high" if points >= 25 else "medium" if points >= 12 else "low"
        indicators.append({"id": rule_id, "title": title, "points": points,
                           "severity": severity, "explanation": explanation})

    # 1. Protocol
    if parts.scheme.lower() == "http":
        add("no_https", "Connection is not encrypted (HTTP)",
            "The address uses http://, so data between you and the site is not encrypted. "
            "Many harmless old sites still use HTTP, so this alone is a minor signal.")
    else:
        positives.append("Uses HTTPS, so the connection is encrypted (this does not prove the site is trustworthy).")

    # 2. Host type
    if kind == "ip":
        add("ip_host", "Website address is an IP address",
            f"The host is the IP address {host} rather than a domain name. Real public services "
            "rarely ask you to log in through a bare IP address.")
    elif kind == "obfuscated_ip":
        add("obfuscated_ip", "Host looks like a disguised IP address",
            f"'{host}' is written as a decimal, hexadecimal or shortened number. "
            "Browsers may convert it to an IP address, which can hide the real destination.")
    else:
        positives.append("Uses a normal domain name instead of an IP address.")

    registered, subs = _split_host(host) if kind == "domain" else (host, [])

    # 3. Domain-based checks
    if kind == "domain":
        labels = host.split(".")
        reg_label = registered.split(".")[0]
        tokens = re.split(r"[.\-]", host)

        if len(subs) >= 4:
            add("subdomains_many", f"Too many subdomains ({len(subs)})",
                f"The host has {len(subs)} parts before the main domain '{registered}'. "
                "Attackers stack subdomains so a trusted word appears first.")
        elif len(subs) == 3:
            add("subdomains_some", "Several subdomains (3)",
                f"Three parts come before '{registered}'. Some large sites do this legitimately, "
                "so check that the main domain is the one you expect.")
        else:
            positives.append("Has a simple hostname structure (few subdomains).")

        if host in SHORTENERS or registered in SHORTENERS:
            add("shortener", "URL-shortening service",
                f"{registered} is a link shortener, so the real destination is hidden until you click.")

        if any(label.startswith("xn--") for label in labels):
            readable = "contains non-English characters" if not parts.hostname.isascii() else "is written in Punycode"
            add("punycode", "Internationalised (Punycode) domain",
                f"The hostname {readable}. Look-alike characters from other alphabets can imitate "
                "a well-known name (e.g. a Cyrillic 'a' that looks like a Latin 'a').")
        else:
            positives.append("No Punycode (xn--) look-alike characters in the hostname.")

        brand_hit = next((b for b in BRANDS if b in tokens), None)
        if brand_hit and reg_label != brand_hit and registered not in SAFE_BRAND_DOMAINS:
            add("brand_impersonation", f"Brand name '{brand_hit}' used in a different domain",
                f"The host contains '{brand_hit}' but the real domain is '{registered}'. "
                "Scammers add a famous name to their own domain to look genuine.")
        for tok in reg_label.split("-"):
            fake = next((b for b in BRANDS if b != tok and b in _lookalike_variants(tok)), None)
            if fake:
                add("lookalike", f"Look-alike spelling of '{fake}'",
                    f"'{tok}' resembles '{fake}' with swapped characters (such as 1 for l or rn for m).")
                break

        non_puny = [label for label in labels if not label.startswith("xn--")]
        if sum(label.count("-") for label in non_puny) >= 3:
            add("many_hyphens", "Many hyphens in the hostname",
                "Hostnames with several hyphens (like secure-login-update-now) are a common phishing style.")
        if sum(1 for t in tokens if t in SENSITIVE_WORDS) >= 2 or \
                any(t in SENSITIVE_WORDS for t in reg_label.split("-")):
            add("sensitive_words", "Sensitive words inside the hostname",
                "Words like login, verify, secure or account in the hostname are used to create false trust.")
        if labels[-1] in RISKY_TLDS:
            add("risky_tld", f"Frequently abused extension (.{labels[-1]})",
                "This extension is cheap or free and often appears in abuse reports. "
                "Many legitimate sites use it too, so it is only a weak signal.")
        if any(len(label) > 30 for label in non_puny):
            add("long_label", "Unusually long hostname part",
                "One part of the hostname is over 30 characters, which is uncommon for real sites.")

    # 4. Credentials-style '@' trick
    full_path = parts.path + ("?" + parts.query if parts.query else "") + \
        ("#" + parts.fragment if parts.fragment else "")
    if "@" in parts.netloc:
        add("userinfo_at", "'@' symbol before the real host",
            f"Everything before '@' is ignored as a username. The browser actually connects to '{host}'. "
            "This trick makes a link look like it belongs to another site.")
    elif "@" in full_path:
        add("at_in_path", "'@' symbol in the path or query",
            "An '@' after the host is usually harmless, but it can be used to confuse readers.")
    else:
        positives.append("No '@' trick found in the address.")

    # 5. Port
    if port is not None and port not in (80, 443):
        add("unusual_port", f"Unusual port ({port})",
            "Normal websites use ports 80 or 443. A custom port is common for test servers and unusual for public login pages.")
    else:
        positives.append("Uses the default web port.")

    # 6. Length
    if len(url) >= 200:
        add("very_long_url", f"Very long URL ({len(url)} characters)",
            "Extremely long URLs can hide the true destination or carry large hidden parameters.")
    elif len(url) >= 100:
        add("long_url", f"Long URL ({len(url)} characters)",
            "A long URL is not harmful by itself (tracking parameters are common), but read it carefully.")
    else:
        positives.append("URL length is reasonable.")

    # 7. Percent-encoding
    encoded = re.findall(r"%[0-9a-fA-F]{2}", full_path)
    decoded = unquote(full_path)
    if re.search(r"%25[0-9a-fA-F]{2}", full_path):
        add("encoding_double", "Double URL-encoding",
            "Sequences like %252e are an encoded '%'. This is used to slip patterns past security filters.")
    if re.search(r"<\s*script|javascript:|\.\./|[\x00\r\n<]", unquote(decoded), re.I):
        add("encoding_dangerous", "Encoded characters decode to a risky pattern",
            "After decoding, the path or query contains script tags, 'javascript:', '../' or control characters.")
    if len(encoded) >= 10:
        add("encoding_heavy", f"Heavy percent-encoding ({len(encoded)} encoded characters)",
            "Lots of %XX sequences make the URL hard to read and can hide its meaning.")
    if re.search(r"[?&][^=&]{0,20}=(https?(:|%3a)(//|%2f%2f))", "?" + parts.query, re.I):
        add("redirect_param", "Redirect-style parameter containing another URL",
            "A parameter holds a full web address. If the site redirects to it blindly, it could send you elsewhere.")
    if not encoded:
        positives.append("No percent-encoded characters to inspect.")

    score = min(100, sum(i["points"] for i in indicators))
    level = _level(score)
    advice = {
        "low": ["Nothing alarming in the URL text, but still check the address matches the site you expect.",
                "Never enter passwords or payment details unless you trust the site.",
                "Type important addresses (like your bank) yourself instead of following links."],
        "medium": ["Be careful: some parts of this URL are unusual. Check the main domain carefully.",
                   "Avoid entering passwords or personal data until you are sure of the source.",
                   "If it came in a message, confirm with the sender through another channel."],
        "high": ["Do not open this link or enter any information unless you can verify it independently.",
                 "If it arrived by email or SMS, report it as phishing and delete it.",
                 "If you already clicked, change passwords for any account you used and enable two-factor authentication."],
    }[level]

    return {"url": url, "host": host, "score": score, "level": level,
            "label": {"low": "Low risk", "medium": "Medium risk", "high": "High risk"}[level],
            "indicators": sorted(indicators, key=lambda i: -i["points"]),
            "positives": positives, "advice": advice, "disclaimer": DISCLAIMER}
