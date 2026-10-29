#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
san=scripts/sanitize-fixture.sh
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
fail() { echo "FAIL: $*"; exit 1; }
# Secret-shaped input is assembled at run time so this file holds no secret-shaped literal.
python3 -I - "$work/in.json" <<'PY'
import json, sys
secret_key = "pass" + "word"; blob = "A" * 44
json.dump({"rows": [
  {"uuid": "6f1c2a3e-1111-4222-8333-444455556666", "name": "web", secret_key: "hunter" + "2",
   "content": "10.20.30.40\n10.20.30.41/24", "gw": "fe80::1:2:3:4", "mac": "00:11:22:33:44:55",
   "fqdn": "gateway.corp.net", "pem": "-----BEGIN " + "CERTIFICATE-----", "blob": blob,
   "legacy_ref": "0123456789abcdef0123456789abcdef", "crypt": "$6$" + "salt$hash", "version": "26.7.5", "ok": "config.xml",
   "in_pass_p": "1234", "in_pass_b": 5678, "out_pass_p": "9012", "pass": "tiny" + "pw",
   "nested": {"apiKey": "plain" + "value"}, "list_of_pw": {"user_" + secret_key: ["a" + "b"]},
   "old_ip": "010.020.030.040", "mac2": "AA-BB-CC-DD-EE-FF"},
  {"uuid": "6f1c2a3e-1111-4222-8333-444455556666", "name": "second"}], "total": 2, "rowCount": 2}, open(sys.argv[1], "w"))
PY
"$san" "$work/in.json" > "$work/out1.json"
"$san" "$work/in.json" > "$work/out2.json"
cmp "$work/out1.json" "$work/out2.json"                                  # deterministic
"$san" --verify "$work/out1.json"                                        # its own output is clean
# shellcheck disable=SC2016  # the pattern is a regex, not an expansion
for leaked in 10.20.30 010.020 fe80 00:11:22 AA-BB corp.net hunter2 BEGIN 0123456789abcdef '\$6\$' AAAAAAAA tinypw plainvalue; do
  if grep -qE "$leaked" "$work/out1.json"; then fail "leaked: $leaked"; fi
done
grep -q '26.7.5' "$work/out1.json" || fail "version dropped"
grep -q 'config.xml' "$work/out1.json" || fail "benign value dropped"
jq -e '.rows[0].uuid == .rows[1].uuid' "$work/out1.json" >/dev/null || fail "uuid not deterministic"
jq -e '.rows[0].password == "REDACTED" and .rows[0].pass == "REDACTED"' "$work/out1.json" >/dev/null || fail "secret key not redacted"
# pf counters whose names merely contain "pass" must survive with their values.
jq -e '.rows[0].in_pass_p == "1234" and .rows[0].in_pass_b == 5678 and .rows[0].out_pass_p == "9012"' "$work/out1.json" >/dev/null \
  || fail "pass counters were redacted"
"$san" --max-rows 1 "$work/in.json" | jq -e '.total == 1 and .rowCount == 1 and (.rows|length) == 1' >/dev/null || fail "max-rows"
if "$san" --verify "$work/in.json" 2>"$work/err"; then fail "verify passed dirty input"; fi
grep -q 'leftover ipv4' "$work/err" || fail "verify did not name a category"
if grep -qE '10\.20\.30|corp\.net|hunter' "$work/err"; then fail "verify message carries a value"; fi
# --verify flags an unredacted secret value even when no address rule fires.
python3 -I -c 'import json,sys; json.dump({"pass"+"word": "x"+"y"}, open(sys.argv[1], "w"))' "$work/s.json"
if "$san" --verify "$work/s.json" 2>/dev/null; then fail "verify passed an unredacted secret key"; fi
# The deny-file term is one no built-in rule flags, so only the deny-file can catch it.
printf 'zanzibar-widget\n' > "$work/deny"
echo '{"x":"see zanzibar-widget now"}' > "$work/d.json"
"$san" --verify "$work/d.json" || fail "term flagged without a deny-file"
if "$san" --verify --deny-file "$work/deny" "$work/d.json" 2>/dev/null; then fail "deny-file ignored by verify"; fi
"$san" --deny-file "$work/deny" "$work/d.json" > "$work/d.out" || fail "sanitize with deny-file failed"
if grep -q zanzibar "$work/d.out"; then fail "deny-file ignored by sanitize"; fi
grep -q 'redacted.example.org' "$work/d.out" || fail "deny term not replaced"

# --- fix round 1: each block below fails when its rule is sabotaged ---
python3 -I - "$work" <<'PY'
import importlib.util, json, sys
work = sys.argv[1]
spec = importlib.util.spec_from_file_location("sf", "scripts/sanitize_fixture.py")
sf = importlib.util.module_from_spec(spec); spec.loader.exec_module(sf)
def dump(name, doc): json.dump(doc, open(f"{work}/{name}.json", "w"))
secret = "pass" + "word"
# 1: dirty address on the second/third line of an escaped-newline string
dump("nl", {"c": "192.0.2.1\n10.9.8.7\n00:11:22:33:44:55"})
# 2: secret-named keys the whole-word rule missed; numbers and nested keys beneath them
dump("keys", {"private" + "key": "v1", "pass" + "phrase": "v2", "authorized_" + "keys": "v3", "api" + "keys": "v4",
              "community": "v5", "secret" + "key": "v6", "api" + "secret": "v7", "auth" + "key": "v8",
              "pwd": "v9", "cert": {"inner_name": 123456, "flag": True}, "in_pass_p": 7})
# 3: secret-shaped substrings inside larger strings
dump("embedded", {"xml": "<p>$6$" + "saltsalt$hashhash</p>", "auth": "Authorization: Bearer " + "B" * 44 + " ok",
                  "ssh": "ssh-rsa " + "C" * 50 + " me", "url": "https://h/?k=" + "D" * 42 + "&x=1"})
# 4: underscore-adjacent addresses and hostnames
dump("under", {"a": "gw_10.1.2.3", "b": "my_host.corp.net", "c": "mac_00:11:22:33:44:55"})
# 5: any TLD is a domain; file extensions and documentation domains are not
dump("tld", {"d": ["a.b.co", "x.ca", "y.app", "z.xyz", "q.lab", "t.test", "h.tail1234.ts.net", "e.fr"],
             "keep": ["config.xml", "notes.md", "host.example.org", "pkg.opnsense.org", "a.example.com"]})
# 6: two addresses that map to the same fake, used as dict keys
class M:  # minimal match stand-in
    def __init__(self, text): self.text = text
    def group(self, _): return self.text
seen = {}
for last in range(1, 255):
    ip = f"10.0.0.{last}"
    fake = sf.fake_v4(M(ip))
    if fake in seen:
        dump("collide", {seen[fake]: 1, ip: 2}); break
    seen[fake] = ip
# 7: free-text keys and emails
dump("free", {"hostname": "fw-real", "fqdn": "fw-real.lan.example.net", "email": "a.b@gmail.com",
              "full_name": "Jane Q Public", "descr": "rack 4 uplink", "description": "owner jane",
              "name": "keepme", "note": "mail jane.q@corp.org now", "ref": "0123456789ABCDEF0123456789ABCDEF"})
dump("deninput", {"x": "see zanzibar-widget", "y": "z\u00fcrich-widget", "z": "# zanzibar-widget"})
PY
"$san" "$work/keys.json" > "$work/keys.out" || fail "keys sanitize failed"
for leaked in v1 v2 v3 v4 v5 v6 v7 v8 v9 123456 inner_name; do
  if grep -q "$leaked" "$work/keys.out"; then fail "secret-named key leaked: $leaked"; fi
done
jq -e '.in_pass_p == 7' "$work/keys.out" >/dev/null || fail "counter lost beside secret keys"
if "$san" --verify "$work/nl.json" 2>"$work/err"; then fail "verify missed escaped-newline lines"; fi
for category in ipv4 mac; do
  grep -q "leftover $category" "$work/err" || fail "verify did not name $category after a newline"
done
"$san" "$work/nl.json" > "$work/nl.out" || fail "sanitize nl"
if grep -qE '10\.9\.8|00:11:22' "$work/nl.out"; then fail "address after newline survived"; fi
"$san" "$work/embedded.json" > "$work/emb.out" || fail "sanitize embedded"
if grep -qE 'saltsalt|BBBB|CCCC|DDDD' "$work/emb.out"; then fail "embedded secret survived"; fi
grep -q 'Authorization: Bearer REDACTED ok' "$work/emb.out" || fail "surrounding text lost"
if "$san" --verify "$work/embedded.json" 2>"$work/err"; then fail "verify passed embedded secrets"; fi
for category in 'crypt hash' blob; do
  grep -q "leftover $category" "$work/err" || fail "verify did not name $category"
done
"$san" "$work/under.json" > "$work/under.out" || fail "sanitize under"
if grep -qE '10\.1\.2|my_host|corp|00:11:22' "$work/under.out"; then fail "underscore-adjacent value survived"; fi
"$san" "$work/tld.json" > "$work/tld.out" || fail "sanitize tld"
if grep -qE 'a\.b\.co|x\.ca|y\.app|xyz|q\.lab|t\.test|tail1234|e\.fr' "$work/tld.out"; then fail "domain with an uncommon TLD survived"; fi
for kept in config.xml notes.md host.example.org pkg.opnsense.org a.example.com; do
  grep -q "$kept" "$work/tld.out" || fail "kept name rewritten: $kept"
done
if [ -f "$work/collide.json" ]; then
  if "$san" "$work/collide.json" >"$work/c.out" 2>"$work/err"; then fail "key collision not detected"; fi
  grep -q 'key collisions: 1' "$work/err" || fail "collision message"
  if grep -q '10\.0\.0' "$work/err"; then fail "collision message carries a value"; fi
  [ ! -s "$work/c.out" ] || fail "collision still wrote output"
else fail "no collision pair found for the test"; fi
"$san" "$work/free.json" > "$work/free.out" || fail "sanitize free"
for leaked in fw-real Jane rack owner gmail jane.q corp.org; do
  if grep -q "$leaked" "$work/free.out"; then fail "free text leaked: $leaked"; fi
done
jq -e '.name == "keepme" and (.hostname|test("^host-[0-9]+$")) and (.email|test("^user-[0-9]+@example.org$"))
       and (.descr|test("^desc-[0-9]+$")) and (.ref|test("^[0-9a-f]{32}$")) and .ref != "0123456789abcdef0123456789abcdef"' \
  "$work/free.out" >/dev/null || fail "free-text keys not mapped as specified"
"$san" --verify "$work/free.out" || fail "free-text output not clean"
echo '{"hostname":"fw-real"}' > "$work/h.json"
if "$san" --verify "$work/h.json" 2>/dev/null; then fail "verify passed a raw hostname value"; fi
# deny-file: comments and blanks ignored; verify compares decoded strings (the file holds a non-ASCII term)
printf '# zanzibar-widget\n\n  \n' > "$work/deny2"
"$san" --verify --deny-file "$work/deny2" "$work/deninput.json" || fail "comment/blank deny lines were applied"
printf 'z\xc3\xbcrich-widget\n' > "$work/deny3"
if "$san" --verify --deny-file "$work/deny3" "$work/deninput.json" 2>/dev/null; then fail "verify missed an escaped non-ASCII deny term"; fi
echo OK
