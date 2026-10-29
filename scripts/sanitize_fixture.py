#!/usr/bin/env python3
"""Sanitize a raw OPNsense capture into a committable fixture. Stdlib only. See sanitize-fixture.sh."""
import argparse, hashlib, ipaddress, json, re, sys

# Whole key names only: pf counters such as in_pass_p must survive, so a bare "pass" is
# redacted only when it is the entire key; the other names match as _/./-/camelCase-split words.
SECRET_WORDS = {"password", "passwd", "secret", "token", "key", "apikey", "hash", "cert", "crt",
                "pem", "psk", "private", "username"}
SECRET_WHOLE_KEYS = {"pass"}
PEM = re.compile(r"-----BEGIN ")
CRYPT = re.compile(r"^\$(1|2[abxy]?|5|6|y)\$")
BLOB = re.compile(r"^[A-Za-z0-9+/=_-]{40,}$")
UUID36 = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
REF32 = re.compile(r"^[0-9a-f]{32}$")
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")
DOMAIN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:org|com|net|io|dev|lan|local|internal|home|localdomain|arpa|info|biz|cloud|edu|gov|eu|us|uk|de)\b", re.I)
KEEP_DOMAIN = re.compile(r"(^|\.)(example\.(org|com|net)|opnsense\.org)$", re.I)
DOC_V4 = ("192.0.2.", "198.51.100.", "203.0.113.")
SALT = "rustopnsmcp-fixture-v1"


def is_secret_key(key):
    """True when the key names a secret as a whole word (not as a substring of a counter name)."""
    lowered = key.lower()
    if lowered in SECRET_WHOLE_KEYS:
        return True
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return any(word in SECRET_WORDS for word in re.split(r"[^A-Za-z0-9]+", split.lower()))


def digest(kind, value):
    return hashlib.sha256(f"{SALT}:{kind}:{value}".encode()).digest()


def fake_v4(match):
    address = match.group(0)
    octets = [int(part) for part in address.split(".")]
    if any(octet > 255 for octet in octets):  # not an address (e.g. a long version string)
        return address
    normalized = ".".join(str(octet) for octet in octets)  # tolerates leading zeros
    if normalized == "0.0.0.0" or normalized.startswith(("255.", "127.") + DOC_V4):
        return address
    index = int.from_bytes(digest("v4", normalized)[:4], "big") % (len(DOC_V4) * 254)
    return f"{DOC_V4[index // 254]}{index % 254 + 1}"


def fake_v6(match):
    text = match.group(0)
    try:
        parsed = ipaddress.IPv6Address(text)
    except ValueError:
        return text
    if parsed in (ipaddress.IPv6Address("::"), ipaddress.IPv6Address("::1")) or str(parsed).startswith("2001:db8:"):
        return text
    return "2001:db8::%x" % (int.from_bytes(digest("v6", str(parsed))[:2], "big") or 1)


def fake_mac(match):
    if match.group(0).lower().startswith("02:00:00:00"):
        return match.group(0)
    raw = digest("mac", match.group(0).lower().replace("-", ":"))
    return "02:00:00:00:%02x:%02x" % (raw[0], raw[1])


def fake_domain(match):
    if KEEP_DOMAIN.search(match.group(0)):
        return match.group(0)
    return "host-%d.example.org" % (int.from_bytes(digest("dom", match.group(0).lower())[:2], "big") % 1000)


def fake_uuid(match):
    h = digest("uuid", match.group(0).lower()).hex()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def scrub_string(text, denied):
    if PEM.search(text) or CRYPT.match(text) or BLOB.match(text):
        return "REDACTED"
    if REF32.match(text):
        return digest("ref", text).hex()[:32]
    for name in denied:
        text = re.sub(re.escape(name), "redacted.example.org", text, flags=re.I)
    text = MAC.sub(fake_mac, text)
    text = UUID36.sub(fake_uuid, text)
    text = IPV4.sub(fake_v4, text)
    text = IPV6.sub(fake_v6, text)
    return DOMAIN.sub(fake_domain, text)


def walk(node, denied, secret=False):
    """`secret` is true beneath a secret-named key: every string leaf there is redacted."""
    if isinstance(node, dict):
        # Keys are scrubbed too: an alias's content map is keyed by its addresses.
        return {scrub_string(k, denied) if k else k: walk(v, denied, secret or is_secret_key(k))
                for k, v in node.items()}
    if isinstance(node, list):
        return [walk(v, denied, secret) for v in node]
    if isinstance(node, str) and node:
        return "REDACTED" if secret else scrub_string(node, denied)
    return node


def structural_leftovers(node, secret=False):
    """Counts of secret-shaped values that survive in a parsed document."""
    counts = {"secret-key value": 0, "crypt hash": 0, "blob": 0}
    def visit(item, under_secret):
        if isinstance(item, dict):
            for k, v in item.items():
                visit(k, False)
                visit(v, under_secret or is_secret_key(k))
        elif isinstance(item, list):
            for v in item:
                visit(v, under_secret)
        elif isinstance(item, str) and item:
            if under_secret and item != "REDACTED":
                counts["secret-key value"] += 1
            if CRYPT.match(item):
                counts["crypt hash"] += 1
            if BLOB.match(item):
                counts["blob"] += 1
    visit(node, secret)
    return counts


def leftovers(text, denied):
    """Categories still present in already-sanitized text, as {category: count}."""
    found = {}
    def note(category, count):
        if count:
            found[category] = count
    note("ipv4", sum(1 for m in IPV4.finditer(text) if fake_v4(m) != m.group(0)))
    note("ipv6", sum(1 for m in IPV6.finditer(text) if fake_v6(m) != m.group(0)))
    note("mac", sum(1 for m in MAC.finditer(text) if fake_mac(m) != m.group(0)))
    note("domain", sum(1 for m in DOMAIN.finditer(text) if fake_domain(m) != m.group(0)))
    note("pem", len(PEM.findall(text)))
    note("deny-file name", sum(1 for name in denied if name.lower() in text.lower()))
    try:
        document = json.loads(text)
    except ValueError:
        found["not json"] = 1
        return found
    for category, count in structural_leftovers(document).items():
        note(category, count)
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--deny-file")
    parser.add_argument("--max-rows", type=int)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    denied = [l.strip() for l in open(args.deny_file) if l.strip()] if args.deny_file else []
    if args.verify:
        found = leftovers(open(args.file).read(), denied)
        for category, count in found.items():
            print(f"leftover {category}: {count}", file=sys.stderr)
        sys.exit(2 if found else 0)
    document = json.load(open(args.file))
    if args.max_rows is not None and isinstance(document, dict) and isinstance(document.get("rows"), list):
        document["rows"] = document["rows"][: args.max_rows]
        for field in ("total", "rowCount"):
            if field in document:
                document[field] = len(document["rows"])
    clean = walk(document, denied)
    text = json.dumps(clean, indent=2, sort_keys=True) + "\n"
    found = leftovers(text, denied)
    if found:
        print("sanitizer left " + ", ".join(f"{k}: {v}" for k, v in found.items()), file=sys.stderr)
        sys.exit(2)
    sys.stdout.write(text)


main()
