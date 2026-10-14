import re
from typing import Dict, List, Set

SUSPICIOUS_TLDS: Set[str] = {
    "xyz", "top", "work", "tk", "ml", "ga", "cf", "gq", "buzz", "fit",
    "icu", "cam", "vip", "click", "rest", "country", "stream", "gdn",
    "mom", "lol", "monster", "cfd", "sbs", "quest", "cyou", "beauty",
    "hair", "skin", "uno", "casa", "surf", "fun", "pw", "cc", "ws", "link"
}

KNOWN_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "v.gd",
    "soo.gd", "trib.al", "bl.ink", "lnkd.in", "qr.ae", "adf.ly"
}

TARGET_BRANDS: Dict[str, List[str]] = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "facebook": ["facebook.com", "fb.com", "meta.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank": ["citi.com", "citibank.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "metamask": ["metamask.io"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com", "discord.gg"],
    "telegram": ["telegram.org", "t.me"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "usps": ["usps.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "twitter": ["twitter.com", "x.com"]
}

SUSPICIOUS_KEYWORDS: Set[str] = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "authenticate", "authentication",
    "wallet", "recover", "recovery", "suspended", "unusual-activity",
    "confirm", "credential", "webscr", "ebayisapi", "auth", "validation",
    "passcode", "identity", "billing", "invoice", "refund", "support-desk",
    "portal", "session", "resolution", "notice"
}

COMMON_MULTI_PART_TLDS: Set[str] = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "net.za", "gov.za",
    "com.sg", "net.sg", "org.sg", "gov.sg",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.tr", "org.tr", "edu.tr", "gov.tr",
    "com.ar", "org.ar", "gov.ar"
}

IPV4_PATTERN: re.Pattern = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

IPV6_PATTERN: re.Pattern = re.compile(
    r"^(?:\[)?[0-9a-fA-F:]+(?:\])?$"
)

HEX_OCTAL_IP_PATTERN: re.Pattern = re.compile(
    r"^(?:(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)\.){3}(?:0x[0-9a-fA-F]+|0[0-7]+|\d+)$"
)

PERCENT_ENCODED_PATTERN: re.Pattern = re.compile(
    r"%[0-9a-fA-F]{2}"
)

PUNYCODE_PREFIX: str = "xn--"
