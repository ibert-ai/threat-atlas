#!/usr/bin/env bash
# Offline test of scripts/get-latest.sh against the shared fixtures (no network, nothing installed).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
feed="$here/fixtures/update-feed-sample.json"
fail=0
n=0
cases="$(python3 - "$here/fixtures/update-feed-cases.json" <<'PY'
import json, sys
for c in json.load(open(sys.argv[1]))["cases"]:
    print("\t".join([c["product"], c["channel"], c["platform"], c["version"], c["asset"]]))
PY
)"
[ -n "$cases" ] || { echo "FAIL: no cases were generated"; exit 1; }
while IFS=$'\t' read -r product channel platform version asset; do
  n=$((n + 1))
  line="$(bash "$here/get-latest.sh" --product "$product" --channel "$channel" --platform "$platform" \
          --feed-file "$feed" --resolve-only --allow-unsigned-feed 2>/dev/null)" || { echo "FAIL $product $channel $platform: no result"; fail=$((fail + 1)); continue; }
  IFS=$'\t' read -r gv _ _ _ _ gn <<<"$line"
  if [ "$gv" != "$version" ] || [ "$gn" != "$asset" ]; then echo "FAIL $product $channel $platform: got $gv $gn, want $version $asset"; fail=$((fail + 1)); fi
done <<<"$cases"
[ "$n" -ge 15 ] || { echo "FAIL: only $n resolution cases ran"; exit 1; }
if bash "$here/get-latest.sh" --feed-file "$feed" --resolve-only >/dev/null 2>&1; then echo "FAIL: ran without --allow-unsigned-feed"; fail=$((fail + 1)); fi
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
python3 - "$feed" "$tmp" <<'PY'
import json, sys
f = json.load(open(sys.argv[1]))
for a in f["products"]["atlassoc"]["releases"][0]["assets"]:
    a["url"] = "https://evil.example/x"
json.dump(f, open(sys.argv[2], "w"))
PY
if bash "$here/get-latest.sh" --channel beta --platform windows-x64 --feed-file "$tmp" --resolve-only --allow-unsigned-feed >/dev/null 2>&1; then echo "FAIL: accepted a foreign URL"; fail=$((fail + 1)); fi
python3 - "$feed" "$tmp" <<'PY'
import json, sys
f = json.load(open(sys.argv[1]))
rel = f["products"]["atlassoc"]["releases"][0]
for a in rel["assets"]:
    a["url"] = "https://github.com/Ibert-Iam/threat-atlas/releases/download/../../../evil/x/" + rel["tag"] + "/" + a["name"]
json.dump(f, open(sys.argv[2], "w"))
PY
if bash "$here/get-latest.sh" --channel beta --platform windows-x64 --feed-file "$tmp" --resolve-only --allow-unsigned-feed >/dev/null 2>&1; then echo "FAIL: accepted a dot-dot URL"; fail=$((fail + 1)); fi
[ "$fail" -eq 0 ] || { echo "$fail get-latest.sh test(s) failed"; exit 1; }
echo "get-latest.sh: $n resolution cases and 3 refusal cases passed."
