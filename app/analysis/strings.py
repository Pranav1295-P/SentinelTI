"""String extraction and IOC recovery from raw bytes (no execution)."""

import ipaddress
import re
from pathlib import Path

MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_STRINGS = 40_000
MAX_STRING_LENGTH = 1024
MAX_PER_IOC_TYPE = 50

_ASCII = re.compile(rb"[\x20-\x7e]{5,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

_URL = re.compile(r"\b(?:https?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}", re.I)
_IP_ONLY = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|ru|cn|su|top|xyz|io|cc|tk|pw|onion|club|site|online|shop|me)\b",
    re.I,
)
_REGISTRY = re.compile(
    r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE|SYSTEM)\\[A-Za-z0-9_ .\\{}-]{3,}", re.I
)
_WIN_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

# Certificate object ids look exactly like IP addresses (2.5.4.3 is "common name").
_OID_PREFIXES = ("1.2.", "1.3.", "2.5.", "2.16.")

# Infrastructure every signed or installer binary references. Kept as IOCs, not scored.
BENIGN_DOMAINS = (
    "microsoft.com", "windows.com", "digicert.com", "verisign.com", "symantec.com", "symcb.com",
    "symcd.com", "thawte.com", "globalsign.com", "sectigo.com", "comodoca.com", "usertrust.com",
    "w3.org", "xmlsoap.org", "openssl.org", "python.org", "gnu.org", "apache.org", "mozilla.org",
    "letsencrypt.org", "entrust.net", "godaddy.com", "amazontrust.com", "adobe.com", "github.com",
)


def extract_strings(path: Path) -> list[str]:
    with path.open("rb") as handle:
        raw = handle.read(MAX_SCAN_BYTES)

    found: dict[str, None] = {}
    for match in _ASCII.finditer(raw):
        found.setdefault(match.group().decode("ascii")[:MAX_STRING_LENGTH])
        if len(found) >= MAX_STRINGS:
            return list(found)
    for match in _UTF16.finditer(raw):
        found.setdefault(match.group().decode("utf-16-le", "ignore")[:MAX_STRING_LENGTH])
        if len(found) >= MAX_STRINGS:
            break
    return list(found)


def _public_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text.split(":")[0])
    except ValueError:
        return False
    return ip.is_global


def _looks_like_version(text: str) -> bool:
    """Assembly versions (1.0.0.0) and certificate ids look like addresses when standing alone."""
    return text.startswith(_OID_PREFIXES) or text.split(":")[0].endswith(".0")


def is_benign_host(host: str) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in BENIGN_DOMAINS)


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    iocs: dict[str, dict[str, None]] = {
        k: {} for k in ("urls", "ips", "domains", "emails", "registry_keys", "file_paths", "crypto_wallets")
    }

    def add(kind: str, value: str) -> None:
        if len(iocs[kind]) < MAX_PER_IOC_TYPE:
            iocs[kind].setdefault(value)

    for text in strings:
        for url in _URL.findall(text):
            add("urls", url.rstrip(".,;'\")"))
            host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0].split("@")[-1]
            if _public_ip(host):
                add("ips", host)
            elif _DOMAIN.fullmatch(host.split(":")[0]):
                add("domains", host.split(":")[0].lower())
        # Standalone only: dotted numbers inside longer text are usually versions or OIDs.
        stripped = text.strip()
        if _IP_ONLY.match(stripped) and _public_ip(stripped) and not _looks_like_version(stripped):
            add("ips", stripped)
        for email in _EMAIL.findall(text):
            add("emails", email)
        for domain in (m.group() for m in _DOMAIN.finditer(text)):
            # Random bytes often spell "v4.cc"; a real registered name is rarely under 3 characters.
            if len(domain.split(".")[-2]) >= 3:
                add("domains", domain.lower())
        for key in _REGISTRY.findall(text):
            add("registry_keys", key)
        for win_path in _WIN_PATH.findall(text):
            add("file_paths", win_path)
        if len(text) <= 64:
            for wallet in _BTC.findall(text):
                if any(c.isdigit() for c in wallet) and any(c.isupper() for c in wallet):
                    add("crypto_wallets", wallet)

    return {kind: list(values) for kind, values in iocs.items()}


def literal_in_bytes(raw: bytes, literal: str) -> bool:
    """True when the text is physically present in the file, as ASCII or UTF-16LE."""
    try:
        return literal.encode("ascii") in raw or literal.encode("utf-16-le") in raw
    except UnicodeEncodeError:
        return literal.encode("utf-16-le") in raw
