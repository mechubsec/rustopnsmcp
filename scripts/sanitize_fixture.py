#!/usr/bin/env python3
"""Sanitize a raw OPNsense capture into a committable fixture. Stdlib only. See sanitize-fixture.sh.

Every scan runs over the decoded JSON strings and keys, never over the raw text.
Values of "name" keys are KEPT (tests need them): cover lab names with --deny-file, and
review every sanitized capture by eye before it is committed.
"""
import argparse, hashlib, ipaddress, json, re, sys

# Secret-named keys. Substrings are matched anywhere in the lowercased key; the words below
# match as whole _/./-/camelCase-split words; "pass" and "pwd" only as the entire key, so pf
# counters such as in_pass_p survive.
SECRET_SUBSTRINGS = ("password", "passwd", "passphrase", "secret", "token", "private", "psk", "hash",
                     "cert", "crt", "pem", "username", "community", "authorized")
SECRET_WORDS = {"key", "keys", "apikey", "apikeys", "authkey"}
SECRET_WHOLE_KEYS = {"pass", "pwd"}
# Free-text keys (normalised: lowercase, alphanumerics only) -> (template, already-mapped pattern).
FREE_TEXT = {
    "hostname": ("host-{n}", re.compile(r"host-\d+")),
    "fqdn": ("host-{n}.example.org", re.compile(r"host-\d+\.example\.org")),
    "email": ("user-{n}@example.org", re.compile(r"user-\d+@example\.org")),
    "fullname": ("user-{n}", re.compile(r"user-\d+")),
    "descr": ("desc-{n}", re.compile(r"desc-\d+")),
    "description": ("desc-{n}", re.compile(r"desc-\d+")),
    "summary": ("desc-{n}", re.compile(r"desc-\d+")),
}
FILE_EXTENSIONS = {"json", "txt", "conf", "cfg", "py", "sh", "rs", "toml", "yml", "yaml", "md", "xml", "pem",
                   "crt", "key", "log", "html", "js", "css", "php", "ini", "csv", "gz", "tar", "zip", "deb",
                   "pkg", "txz"}
PEM = re.compile(r"-----BEGIN .*", re.S)
CRYPT_WHOLE = re.compile(r"^\$(1|2[abxy]?|5|6|y)\$")
CRYPT = re.compile(r"\$(?:1|2[abxy]?|5|6|y)\$[^\s\"<]{8,}")
BLOB = re.compile(r"[A-Za-z0-9+/=_-]{40,}")
UUID36 = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
REF32 = re.compile(r"^[0-9a-fA-F]{32}$")
IPV4 = re.compile(r"(?<!\d)(?<!\d\.)\d{1,3}(?:\.\d{1,3}){3}(?!\d)(?!\.\d)")
IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
MAC = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_-])")
DOMAIN = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_-])")
KEEP_DOMAIN = re.compile(r"(^|\.)(example\.(org|com|net)|opnsense\.org)$", re.I)
DOC_V4 = ("192.0.2.", "198.51.100.", "203.0.113.")
SALT = "rustopnsmcp-fixture-v1"


def normalise_key(key):
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_secret_key(key):
    """True when the key names a secret (see SECRET_* above); pf counters like in_pass_p are not."""
    lowered = key.lower()
    if lowered in SECRET_WHOLE_KEYS or any(part in lowered for part in SECRET_SUBSTRINGS):
        return True
    split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return any(word in SECRET_WORDS for word in re.split(r"[^A-Za-z0-9]+", split.lower()))


def digest(kind, value):
    return hashlib.sha256(f"{SALT}:{kind}:{value}".encode()).digest()


def number(kind, value):
    return int.from_bytes(digest(kind, value)[:4], "big") % 1000000


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
    raw = digest("v6", str(parsed))
    return "2001:db8::%x:%x" % (int.from_bytes(raw[:2], "big"), int.from_bytes(raw[2:4], "big"))


def fake_mac(match):
    if match.group(0).lower().startswith("02:00:00:00"):
        return match.group(0)
    raw = digest("mac", match.group(0).lower().replace("-", ":"))
    return "02:00:00:00:%02x:%02x" % (raw[0], raw[1])


def fake_email(match):
    if FREE_TEXT["email"][1].fullmatch(match.group(0)):
        return match.group(0)
    return "user-%d@example.org" % number("email", match.group(0).lower())


def fake_domain(match):
    text = match.group(0)
    if KEEP_DOMAIN.search(text) or text.rsplit(".", 1)[1].lower() in FILE_EXTENSIONS:
        return text
    return "host-%d.example.org" % number("dom", text.lower())


def fake_uuid(match):
    h = digest("uuid", match.group(0).lower()).hex()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def scrub_string(text, denied):
    for name in denied:
        text = re.sub(re.escape(name), "redacted.example.org", text, flags=re.I)
    if CRYPT_WHOLE.match(text):
        return "REDACTED"
    text = PEM.sub("REDACTED", text)
    text = CRYPT.sub("REDACTED", text)
    text = BLOB.sub("REDACTED", text)
    if REF32.match(text):
        return digest("ref", text.lower()).hex()[:32]
    text = MAC.sub(fake_mac, text)
    text = UUID36.sub(fake_uuid, text)
    text = EMAIL.sub(fake_email, text)
    text = IPV4.sub(fake_v4, text)
    text = IPV6.sub(fake_v6, text)
    return DOMAIN.sub(fake_domain, text)


def free_text(kind, text):
    template, mapped = FREE_TEXT[kind]
    return text if mapped.fullmatch(text) else template.format(n=number(kind, text))


def is_number(node):
    return isinstance(node, (int, float)) and not isinstance(node, bool)


def walk(node, denied, stats, secret=False, kind=None):
    """`secret`: beneath a secret-named key every leaf and nested key is redacted. `kind`: free-text key."""
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if secret and key:
                new_key = "REDACTED-" + digest("key", key).hex()[:8]
            else:
                new_key = scrub_string(key, denied) if key else key
            if new_key in out:
                stats["key collisions"] = stats.get("key collisions", 0) + 1
            out[new_key] = walk(value, denied, stats, secret or is_secret_key(key), FREE_TEXT_KEY.get(normalise_key(key)))
        return out
    if isinstance(node, list):
        return [walk(v, denied, stats, secret, kind) for v in node]
    if (isinstance(node, str) and node) or (secret and is_number(node)):
        if secret:
            return "REDACTED"
        return free_text(kind, node) if kind else scrub_string(node, denied)
    return node


FREE_TEXT_KEY = {key: key for key in FREE_TEXT}


def string_leftovers(text, denied, found):
    """Add the categories still present in one decoded string to `found`."""
    def add(category, count):
        if count:
            found[category] = found.get(category, 0) + count
    add("ipv4", sum(1 for m in IPV4.finditer(text) if fake_v4(m) != m.group(0)))
    add("ipv6", sum(1 for m in IPV6.finditer(text) if fake_v6(m) != m.group(0)))
    add("mac", sum(1 for m in MAC.finditer(text) if fake_mac(m) != m.group(0)))
    add("email", sum(1 for m in EMAIL.finditer(text) if fake_email(m) != m.group(0)))
    add("domain", sum(1 for m in DOMAIN.finditer(text) if fake_domain(m) != m.group(0)))
    add("pem", len(PEM.findall(text)))
    add("crypt hash", len(CRYPT.findall(text)) + (1 if CRYPT_WHOLE.match(text) else 0))
    add("blob", len(BLOB.findall(text)))
    add("deny-file name", sum(1 for name in denied if name.lower() in text.lower()))


def leftovers(document, denied):
    """Categories still present in a (sanitized) document, as {category: count}."""
    found = {}
    def visit(node, secret=False, kind=None):
        if isinstance(node, dict):
            for key, value in node.items():
                string_leftovers(key, denied, found)
                if secret and key and not key.startswith("REDACTED"):
                    found["secret-key name"] = found.get("secret-key name", 0) + 1
                visit(value, secret or is_secret_key(key), FREE_TEXT_KEY.get(normalise_key(key)))
        elif isinstance(node, list):
            for value in node:
                visit(value, secret, kind)
        elif isinstance(node, str) and node:
            string_leftovers(node, denied, found)
            if secret and node != "REDACTED":
                found["secret-key value"] = found.get("secret-key value", 0) + 1
            elif kind and not FREE_TEXT[kind][1].fullmatch(node):
                found["free-text value"] = found.get("free-text value", 0) + 1
        elif secret and is_number(node):
            found["secret-key value"] = found.get("secret-key value", 0) + 1
    visit(document)
    return found


def load_json(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except ValueError:
        print("input is not valid JSON", file=sys.stderr)
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file")
    parser.add_argument("--deny-file", help="one lab-specific name per line; blank lines and # comments skipped")
    parser.add_argument("--max-rows", type=int)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    denied = []
    if args.deny_file:
        with open(args.deny_file) as handle:
            denied = [l.strip() for l in handle if l.strip() and not l.lstrip().startswith("#")]
    if args.verify:
        found = leftovers(load_json(args.file), denied)
        for category, count in found.items():
            print(f"leftover {category}: {count}", file=sys.stderr)
        sys.exit(2 if found else 0)
    document = load_json(args.file)
    if args.max_rows is not None and isinstance(document, dict) and isinstance(document.get("rows"), list):
        document["rows"] = document["rows"][: args.max_rows]
        for field in ("total", "rowCount"):
            if field in document:
                document[field] = len(document["rows"])
    stats = {}
    clean = walk(document, denied, stats)
    found = {**leftovers(clean, denied), **stats}
    if found:
        print("sanitizer left " + ", ".join(f"{k}: {v}" for k, v in found.items()), file=sys.stderr)
        sys.exit(2)
    sys.stdout.write(json.dumps(clean, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
