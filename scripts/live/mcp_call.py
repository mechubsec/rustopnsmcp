#!/usr/bin/env python3
"""Call tools on a rustopnsmcp server; print one PASS/FAIL line per call, shapes only.

  mcp_call.py CALLS.json --stdio -- /path/to/rustopnsmcp [server flags]
  mcp_call.py CALLS.json --url http://127.0.0.1:PORT/mcp --token-env VAR
  add  --vars FILE  to preload saved variables and  --save-vars FILE  to keep them for the next run

Never prints values, only key names, types and counts, so output can be pasted
into a gate comment. Exit 0 when every call met its expectation, else 1.
"""
import argparse, html, http.client, json, os, re, subprocess, sys, urllib.parse

# mecmcp_redact::Untrusted::render_tagged: open tag, one preamble line, entity-escaped body, close tag
# carrying the same id. Pinned at mecmcp v0.28.1.
TAG = re.compile(
    r'(?s)\s*<untrusted-device-content id="([0-9a-f]+)"[^>]*>\n[^\n]*\n(.*)\n</untrusted-device-content id="\1">\s*$'
)
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def payload_of(result):
    """Parse a tool result: structuredContent if present, else the unwrapped, unescaped text."""
    if isinstance(result.get("structuredContent"), (dict, list)):
        return result["structuredContent"]
    text = "".join(block.get("text", "") for block in result.get("content", []))
    match = TAG.match(text)
    try:
        # html.unescape is a superset of the three entities render_tagged emits (&amp; &lt; &gt;)
        return json.loads(html.unescape(match.group(2)) if match else text)
    except ValueError:
        return None


def unparsed_note(text):
    """A fixed class for a body that did not parse, plus only the text before any untrusted tag.

    That leading context line is this server's own words; everything from the tag on is device
    content and is never echoed.
    """
    context = IPV4.sub("x.x.x.x", text.split("<untrusted-device-content", 1)[0].strip())[:160]
    return ("non-json " + context).strip()


def shape(value, depth=0):
    if isinstance(value, dict):
        return "{...}" if depth >= 2 else {k: shape(v, depth + 1) for k, v in list(value.items())[:30]}
    if isinstance(value, list):
        return "list[%d]" % len(value)
    return type(value).__name__


class Stdio:
    def __init__(self, argv, stderr_path):
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     stderr=open(stderr_path or os.devnull, "a"))  # server audit lines stay out of the output

    def rpc(self, message, want_reply=True):
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        while want_reply:
            line = self.proc.stdout.readline()
            if not line:
                raise SystemExit("server closed stdout")
            try:
                reply = json.loads(line)
            except ValueError:
                continue
            if reply.get("id") == message["id"]:
                return reply

    def close(self):
        self.proc.kill()


class Http:
    def __init__(self, url, token):
        self.url, self.token, self.session = urllib.parse.urlparse(url), token, None

    def rpc(self, message, want_reply=True):
        conn = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=120)
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + self.token}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        conn.request("POST", self.url.path or "/", json.dumps(message), headers)
        response = conn.getresponse()
        self.session = response.getheader("Mcp-Session-Id") or self.session
        raw = response.read().decode()
        if not want_reply:
            return None
        if response.status >= 300:
            raise SystemExit("HTTP %d from server" % response.status)
        for chunk in raw.splitlines() if "data:" in raw else [raw]:
            chunk = chunk[5:].strip() if chunk.startswith("data:") else chunk.strip()
            try:
                reply = json.loads(chunk)
            except ValueError:
                continue
            if reply.get("id") == message["id"]:
                return reply
        raise SystemExit("no reply with id %s" % message["id"])

    def close(self):
        pass


def substitute(value, saved):
    if isinstance(value, str) and value.startswith("$") and value[1:] in saved:
        return saved[value[1:]]
    if isinstance(value, dict):
        return {k: substitute(v, saved) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, saved) for v in value]
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("calls")
    parser.add_argument("--stdio", action="store_true")
    parser.add_argument("--url")
    parser.add_argument("--token-env")
    parser.add_argument("--stderr", help="file for the server's stderr (stdio only); default discards it")
    parser.add_argument("--vars")
    parser.add_argument("--save-vars")
    parser.add_argument("server", nargs="*")
    args = parser.parse_args()
    client = Stdio(args.server, args.stderr) if args.stdio else Http(args.url, os.environ[args.token_env])
    client.rpc({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp_call", "version": "0"}}})
    client.rpc({"jsonrpc": "2.0", "method": "notifications/initialized"}, want_reply=False)
    saved = json.load(open(args.vars)) if args.vars else {}
    failures = 0
    for index, call in enumerate(json.load(open(args.calls)), start=1):
        reply = client.rpc({"jsonrpc": "2.0", "id": index, "method": "tools/call", "params": {
            "name": call["tool"], "arguments": substitute(call.get("arguments", {}), saved)}})
        result = reply.get("result") or {}
        text = "".join(block.get("text", "") for block in result.get("content", []))
        is_error = bool(result.get("isError")) or "error" in reply
        payload = payload_of(result)
        problems = []
        if is_error != (call.get("expect", "ok") == "error"):
            problems.append("expected %s" % call.get("expect", "ok"))
        for key in call.get("keys", []):
            if not isinstance(payload, dict) or key not in payload:
                problems.append("missing key " + key)
        for pointer, pattern in call.get("pointers", {}).items():
            node = payload
            for part in [p for p in pointer.split("/") if p]:
                node = node[int(part)] if isinstance(node, list) and part.isdigit() and int(part) < len(node) else (
                    node.get(part) if isinstance(node, dict) else None)
            shown_pattern = pattern  # never echo a saved value: it may come from the device
            if pattern.startswith("$"):  # "$name": must equal a saved variable exactly
                pattern = "^" + re.escape(str(saved.get(pattern[1:]))) + "$"
            if not re.search(pattern, str(node)):
                problems.append("pointer %s does not match %s" % (pointer, shown_pattern))
        if "error_contains" in call and call["error_contains"] not in text:
            problems.append("error text lacks %r" % call["error_contains"])
        for variable, pointer in call.get("save", {}).items():
            node = payload
            for part in [p for p in pointer.split("/") if p]:
                node = node.get(part) if isinstance(node, dict) else None
            saved[variable] = node
        failures += bool(problems)
        shown = {name: saved.get(name) for name in call.get("show", [])}  # only for non-secret ids and fingerprints
        detail = json.dumps(shape(payload)) if payload is not None else unparsed_note(text)
        print("%s %-34s %s%s" % ("FAIL" if problems else "PASS", call["name"],
                                 "[error] " if is_error else "", detail), *("<- " + p for p in problems),
              *(["shown " + json.dumps(shown)] if shown else []))
    if args.save_vars:
        fd = os.open(args.save_vars, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(saved, handle)
    client.close()
    sys.exit(1 if failures else 0)


main()
