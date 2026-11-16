#!/usr/bin/env python3
"""Build, validate and resolve the Threat Atlas update feed (see docs/UPDATE-CHANNELS.md).

Standard library only. The feed is a pointer list: it never authorises an installation by itself.
Apps and scripts must still verify the SHA-256 and the operating-system signature.

  update_feed.py from-github --out feed.json [--releases-json FILE] [--keep-from OLD.json]
  update_feed.py validate feed.json
  update_feed.py resolve feed.json --product atlassoc --channel beta [--platform windows-x64]
  update_feed.py check-online feed.json [--hash]
"""
import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request

REPO = "Ibert-Iam/threat-atlas"
DOWNLOAD_PREFIX = f"https://github.com/{REPO}/releases/download/"
SCHEMA = 1
CHANNELS = ("stable", "rc", "beta")
# Channel -> channels it may be offered from, newest version wins (docs/UPDATE-CHANNELS.md section 3).
ALLOWED = {"stable": ("stable",), "rc": ("stable", "rc"), "beta": ("stable", "rc", "beta")}
MAX_FEED_BYTES = 1_000_000
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(beta|rc)\.(\d+))?$")
TAGS = {  # product -> (tag regex with the version in group 1, linux-side tag suffix)
    "atlassoc": re.compile(r"^atlassoc-v(\d+\.\d+\.\d+(?:-(?:beta|rc)\.\d+)?)(-linux)?$"),
    "screensaver": re.compile(r"^v(\d+\.\d+\.\d+(?:-(?:beta|rc)\.\d+)?)$"),
}
ASSET_RULES = (  # (regex on asset name, platform, kind)
    (re.compile(r"Setup-.*\.exe$"), "windows-x64", "installer"),
    (re.compile(r"\.msi$"), "windows-x64", "installer"),
    (re.compile(r"Windows.*\.zip$"), "windows-x64", "portable"),
    (re.compile(r"macOS.*\.zip$"), "macos-universal", "portable"),
    (re.compile(r"Linux.*\.tar\.gz$"), "linux-x64", "portable"),
    (re.compile(r"SHA256.*\.txt$|SHA256SUMS"), "any", "checksums"),
)


def download_url_ok(url, tags, name):
    """True only for https://github.com/Ibert-Iam/threat-atlas/releases/download/<tag>/<name>.

    A string-prefix test is not enough: '..' segments, percent-encoding, user-info, ports, queries and
    fragments all let a URL that starts with the right text point somewhere else once a client
    normalises it. Compare the parsed components exactly instead.
    """
    if not isinstance(url, str) or any(c in url for c in "\\%?#@ \t\r\n"):
        return False
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or p.netloc != "github.com" or p.query or p.fragment:
        return False
    parts = p.path.split("/")
    if len(parts) != 7 or parts[0] != "":
        return False
    owner, repo, releases, download, tag, filename = parts[1:]
    safe = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
    return ((owner, repo, releases, download) == ("Ibert-Iam", "threat-atlas", "releases", "download")
            and tag in tags and filename == name
            and safe.fullmatch(tag) is not None and safe.fullmatch(filename) is not None
            and ".." not in tag and ".." not in filename)


def parse_version(text):
    """Returns a sortable key; a pre-release sorts below its release (beta < rc < final)."""
    m = VERSION_RE.match(text)
    if not m:
        raise ValueError(f"bad version: {text!r}")
    major, minor, patch, kind, num = m.groups()
    rank = {"beta": 0, "rc": 1, None: 2}[kind]
    return (int(major), int(minor), int(patch), rank, int(num or 0))


def channel_of(version):
    kind = VERSION_RE.match(version).group(4)
    return "stable" if kind is None else kind


def classify_asset(name):
    for rule, platform, kind in ASSET_RULES:
        if rule.search(name):
            return platform, kind
    return None


def build_product(product, releases, withdrawn=()):
    """releases: GitHub release objects. Returns the feed block for one product."""
    tag_re = TAGS[product]
    by_version = {}
    for rel in releases:
        if rel.get("draft"):
            continue
        m = tag_re.match(rel["tag_name"])
        if not m:
            continue
        version = m.group(1)
        entry = by_version.setdefault(version, {
            "version": version, "build": None, "tag": None, "channel": channel_of(version),
            "published_at": rel.get("published_at"), "assets": [], "_tags": []})
        is_linux_side = product == "atlassoc" and m.group(2) == "-linux"
        if not is_linux_side:
            entry["tag"] = rel["tag_name"]
            entry["published_at"] = rel.get("published_at")
            entry["notes_url"] = f"https://github.com/{REPO}/releases/tag/{rel['tag_name']}"
        entry["_tags"].append(rel["tag_name"])
        for asset in rel.get("assets", []):
            cls = classify_asset(asset["name"])
            digest = (asset.get("digest") or "")
            if not cls or not digest.startswith("sha256:"):
                continue
            build = re.search(r"build(\d+)", asset["name"])
            if build and entry["build"] is None:
                entry["build"] = int(build.group(1))
            entry["assets"].append({
                "platform": cls[0], "kind": cls[1], "name": asset["name"],
                "url": f"{DOWNLOAD_PREFIX}{rel['tag_name']}/{asset['name']}",
                "sha256": digest.split(":", 1)[1], "size": asset["size"]})
    out = []
    for version in sorted(by_version, key=parse_version, reverse=True):
        entry = by_version[version]
        if entry["tag"] is None:  # only a linux-side release exists: use it as the tag
            entry["tag"] = entry["_tags"][0]
            entry["notes_url"] = f"https://github.com/{REPO}/releases/tag/{entry['tag']}"
        del entry["_tags"]
        entry["assets"].sort(key=lambda a: (a["platform"], a["kind"], a["name"]))
        out.append(entry)
    block = {"channels": {}, "releases": out, "withdrawn": sorted(withdrawn, key=parse_version)}
    for ch in CHANNELS:
        best = next((r for r in out if r["channel"] == ch and r["version"] not in withdrawn), None)
        block["channels"][ch] = None if best is None else {"version": best["version"], "tag": best["tag"]}
    return block


def resolve(block, channel, platform=None):
    """Highest non-withdrawn release the channel may offer; None if there is none."""
    if channel not in ALLOWED:
        raise ValueError(f"unknown channel: {channel}")
    best = None
    for rel in block["releases"]:
        if rel["version"] in block.get("withdrawn", []) or rel["channel"] not in ALLOWED[channel]:
            continue
        if platform and not any(a["platform"] == platform and a["kind"] != "checksums" for a in rel["assets"]):
            continue
        if best is None or parse_version(rel["version"]) > parse_version(best["version"]):
            best = rel
    return best


def validate(feed):
    """Returns a list of problems (empty when the feed is valid)."""
    errors = []
    if feed.get("schema_version") != SCHEMA:
        errors.append(f"schema_version must be {SCHEMA}")
    products = feed.get("products")
    if not isinstance(products, dict) or not products:
        return errors + ["products missing"]
    for pname, block in products.items():
        if pname not in TAGS:
            errors.append(f"{pname}: unknown product")
            continue
        seen = set()
        withdrawn = block.get("withdrawn", [])
        for v in withdrawn:
            if not VERSION_RE.match(str(v)):
                errors.append(f"{pname}: withdrawn has bad version {v!r}")
        for rel in block.get("releases", []):
            v = rel.get("version", "")
            if not VERSION_RE.match(v):
                errors.append(f"{pname}: bad version {v!r}")
                continue
            if v in seen:
                errors.append(f"{pname}: duplicate version {v}")
            seen.add(v)
            if rel.get("channel") != channel_of(v):
                errors.append(f"{pname} {v}: channel {rel.get('channel')!r} does not match the version")
            tags = {rel.get("tag"), f"{rel.get('tag')}-linux"}
            if not TAGS[pname].match(str(rel.get("tag"))):
                errors.append(f"{pname} {v}: tag {rel.get('tag')!r} is not a {pname} tag")
            names = set()
            for a in rel.get("assets", []):
                if not re.fullmatch(r"[0-9a-f]{64}", str(a.get("sha256", ""))):
                    errors.append(f"{pname} {v} {a.get('name')}: sha256 must be 64 lowercase hex digits")
                if not isinstance(a.get("size"), int) or a["size"] <= 0:
                    errors.append(f"{pname} {v} {a.get('name')}: size must be a positive integer")
                if not download_url_ok(a.get("url"), tags, a.get("name")):
                    errors.append(f"{pname} {v} {a.get('name')}: url must be a {REPO} release download of this tag and file")
                if a.get("name") in names:
                    errors.append(f"{pname} {v}: duplicate asset {a.get('name')}")
                names.add(a.get("name"))
                if a.get("platform") not in ("windows-x64", "macos-universal", "linux-x64", "any"):
                    errors.append(f"{pname} {v} {a.get('name')}: unknown platform {a.get('platform')!r}")
        channels = block.get("channels", {})
        for ch in CHANNELS:
            ptr = channels.get(ch)
            if ptr is None:
                continue
            rel = next((r for r in block.get("releases", []) if r.get("version") == ptr.get("version")), None)
            if rel is None:
                errors.append(f"{pname}: {ch} points to unknown version {ptr.get('version')}")
            elif rel["channel"] != ch:
                errors.append(f"{pname}: {ch} points to a {rel['channel']} version")
            elif ptr.get("version") in withdrawn:
                errors.append(f"{pname}: {ch} points to withdrawn version {ptr.get('version')}")
            elif ptr.get("tag") != rel.get("tag"):
                errors.append(f"{pname}: {ch} tag differs from the release entry")
        for ch in CHANNELS:  # pointer must be the newest non-withdrawn release of its channel
            newest = next((r for r in block.get("releases", [])
                           if r.get("channel") == ch and r.get("version") not in withdrawn), None)
            ptr = channels.get(ch)
            if (newest["version"] if newest else None) != (ptr["version"] if ptr else None):
                errors.append(f"{pname}: {ch} pointer is not the newest non-withdrawn {ch} release")
    return errors


def load_releases(path):
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    raw = subprocess.run(["gh", "api", f"repos/{REPO}/releases", "--paginate", "--slurp"],
                         check=True, capture_output=True, text=True).stdout
    return [rel for page in json.loads(raw) for rel in page]


def build_feed(releases, old=None, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    feed = {"schema_version": SCHEMA, "generated_at": now, "products": {}}
    for product in TAGS:
        kept = (old or {}).get("products", {}).get(product, {}).get("withdrawn", [])
        feed["products"][product] = build_product(product, releases, kept)
    return feed


def check_online(feed, with_hash):
    problems = []
    for pname, block in feed["products"].items():
        for rel in block["releases"]:
            for a in rel["assets"]:
                try:
                    req = urllib.request.Request(a["url"], headers={"User-Agent": "threat-atlas-feed-check"})
                    with urllib.request.urlopen(req, timeout=60) as resp:
                        if with_hash:
                            h = hashlib.sha256()
                            for chunk in iter(lambda: resp.read(1 << 20), b""):
                                h.update(chunk)
                            if h.hexdigest() != a["sha256"]:
                                problems.append(f"{a['url']}: sha256 mismatch")
                        elif resp.status != 200:
                            problems.append(f"{a['url']}: HTTP {resp.status}")
                except Exception as exc:  # noqa: BLE001 - report every failure, keep going
                    problems.append(f"{a['url']}: {exc}")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("from-github")
    g.add_argument("--out", required=True)
    g.add_argument("--releases-json")
    g.add_argument("--keep-from", help="previous feed; its withdrawn lists are kept")
    v = sub.add_parser("validate")
    v.add_argument("feed")
    r = sub.add_parser("resolve")
    r.add_argument("feed")
    r.add_argument("--product", required=True, choices=sorted(TAGS))
    r.add_argument("--channel", required=True, choices=CHANNELS)
    r.add_argument("--platform")
    c = sub.add_parser("check-online")
    c.add_argument("feed")
    c.add_argument("--hash", action="store_true", help="download every file and compare SHA-256")
    args = ap.parse_args(argv)

    if args.cmd == "from-github":
        old = None
        if args.keep_from:
            with open(args.keep_from, encoding="utf-8") as f:
                old = json.load(f)
        feed = build_feed(load_releases(args.releases_json), old)
        problems = validate(feed)
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 1
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(feed, f, indent=2, ensure_ascii=False)
            f.write("\n")
        return 0
    with open(args.feed, "rb") as f:
        raw = f.read()
    if len(raw) > MAX_FEED_BYTES:
        print("feed too large", file=sys.stderr)
        return 1
    feed = json.loads(raw)
    if args.cmd == "validate":
        problems = validate(feed)
        print("\n".join(problems) if problems else "feed valid")
        return 1 if problems else 0
    problems = validate(feed)
    if problems:
        print("invalid feed:\n" + "\n".join(problems), file=sys.stderr)
        return 1
    if args.cmd == "resolve":
        rel = resolve(feed["products"][args.product], args.channel, args.platform)
        if rel is None:
            print("no release available", file=sys.stderr)
            return 2
        print(json.dumps(rel, indent=2))
        return 0
    problems = check_online(feed, args.hash)
    print("\n".join(problems) if problems else "all feed links verified")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
