"""Build status/atlas-status.json for https://ibert.se/Project/status/ without any agent in the loop.

Every agent writes its own small file status/<agent>.json in the private
Ibert-Iam/project-status-dashboard repository (format: status/README.md there). This script, run by
a scheduled workflow with no AI, reads those files plus the public GitHub releases and publishes one
public file. Until an agent has a status file, its old handovers/<agent>.json health and credits
fields are used instead (source "handover").

Only reviewed fields go public: agent id, name, role, last-seen time, state word and credits class.
Task text, blockers, credit numbers, hosts and tokens stay private.

Environment: HANDOVER_TOKEN (read-only contents on the private repo), GH_TOKEN (write contents on
this public repo), optionally DRY_RUN=1 to print instead of publishing.
"""
import base64
import datetime as dt
import json
import os
import re
import sys
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # -I drops the script directory
from agent_health import (FUTURE_SKEW, PRIVATE_REPO, PUBLIC_BRANCH, PUBLIC_REPO, api, iso,  # noqa: E402
                          read_json, stamp)

AGENTS = {  # id: (public name, role)
    "cl": ("Jean-Claude Van Damme", "CBO, Chief Bot Officer (Claude)"),
    "mac": ("MacGyver", "Crew (Codex)"),
    "noris": ("Seek Norris", "CMO, Chief Marketing Officer (DeepSeek)"),
    "billy": ("Billy Badass", "Crew (DeepSeek)"),
}
PRODUCTS = [  # id, name, tag pattern
    ("screensaver", "Threat Atlas screensaver", re.compile(r"^v\d")),
    ("desktop", "AtlasSOC Desktop", re.compile(r"^atlassoc-v\d")),
]
STATES = {"working", "idle", "blocked", "off"}
CREDITS = {"ok", "low", "empty", "unknown"}
LEGACY_CREDITS = {"available": "ok", "low": "low", "exhausted": "empty", "unknown": "unknown"}
LOW_WEEKLY_PERCENT = 15   # Claude and Codex plans: below this share of the weekly limit is low
LOW_BALANCE_USD = 1.0     # DeepSeek: below this balance is low
STALL_MINUTES = 180       # shown on the page; the private alert job uses the same value
ALERT_HOURS = [7, 22]     # Europe/Stockholm, alerts only inside this window
CREDITS_MAX_AGE = 24 * 3600  # an older credit reading is shown as unknown
HEARTBEAT = 3600            # republish at least hourly so generated_at proves the builder runs
PUBLIC_PATH = "status/atlas-status.json"
RELEASE_PREFIX = f"https://github.com/{PUBLIC_REPO}/releases/"
MAX_ASSETS = 12


def iso_s(seconds):
    return iso(int(seconds))


def past(value, now):
    """Parsed time if valid and not in the future, else None."""
    try:
        t = stamp(value)
    except (ValueError, TypeError):
        return None
    return t if t <= now + FUTURE_SKEW else None


def number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def credit_class(credits):
    """Credits class from the private numbers; falls back to the class the agent declared."""
    if not isinstance(credits, dict):
        return "unknown"
    weekly = number(credits.get("weekly_percent_remaining"))
    balance = number(credits.get("balance_usd"))
    if balance is None and credits.get("currency") == "USD":
        balance = number(credits.get("remaining"))
    if weekly is not None:
        return "empty" if weekly <= 0 else "low" if weekly < LOW_WEEKLY_PERCENT else "ok"
    if balance is not None:
        return "empty" if balance <= 0 else "low" if balance < LOW_BALANCE_USD else "ok"
    declared = credits.get("status")
    return declared if declared in CREDITS else LEGACY_CREDITS.get(declared, "unknown")


def from_status(raw, now):
    seen = past(raw.get("updated_at"), now)
    if seen is None:
        return None
    credits = raw.get("credits") if isinstance(raw.get("credits"), dict) else {}
    checked = past(credits.get("checked_at"), now)
    if checked and now - checked > CREDITS_MAX_AGE:
        checked = None
    return {"last_seen_at": iso_s(seen), "state": raw.get("state") if raw.get("state") in STATES else "unknown",
            "credits": credit_class(credits) if checked else "unknown",
            "credits_checked_at": iso_s(checked) if checked else None, "source": "status"}


def from_handover(raw, now):
    health = raw.get("health") if isinstance(raw.get("health"), dict) else {}
    times = [t for t in (past(raw.get("updated_at"), now), past(health.get("reported_at"), now)) if t]
    if not times:
        return None
    # Newest of the two credit records some agents keep (credits, capacity).
    best = None
    for key, at in (("credits", "reported_at"), ("capacity", "observed_at")):
        record = raw.get(key)
        t = past(record.get(at), now) if isinstance(record, dict) else None
        if t and now - t <= CREDITS_MAX_AGE and (best is None or t > best[0]):
            best = (t, record)
    return {"last_seen_at": iso_s(max(times)), "state": "unknown",
            "credits": credit_class(best[1]) if best else "unknown",
            "credits_checked_at": iso_s(best[0]) if best else None, "source": "handover"}


def agent_rows(status_files, handover_files, previous, now):
    """status_files / handover_files: {id: parsed JSON or None}. A broken or missing input keeps the
    previous public row, so one bad file never blanks the page."""
    old = {a.get("id"): a for a in (previous or {}).get("agents", []) if isinstance(a, dict)}
    rows = []
    for ident, (name, role) in AGENTS.items():
        row = None
        if isinstance(status_files.get(ident), dict):
            row = from_status(status_files[ident], now)
        if row is None and isinstance(handover_files.get(ident), dict):
            row = from_handover(handover_files[ident], now)
        if row is None and ident in old:
            row = {k: old[ident].get(k) for k in ("last_seen_at", "state", "credits", "credits_checked_at", "source")}
        if row is None:
            row = {"last_seen_at": None, "state": "unknown", "credits": "unknown", "credits_checked_at": None,
                   "source": "none"}
        rows.append({"id": ident, "name": name, "role": role, **row})
    return rows


def release_view(release):
    assets = []
    for asset in release.get("assets", [])[:MAX_ASSETS]:
        url = asset.get("browser_download_url", "")
        digest = asset.get("digest") or ""
        if not url.startswith(RELEASE_PREFIX):
            continue
        sha = digest[7:] if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) else None
        assets.append({"name": str(asset.get("name", ""))[:120], "url": url, "sha256": sha})
    url = release.get("html_url", "")
    return {"tag": release["tag_name"], "name": str(release.get("name") or release["tag_name"])[:160],
            "published_at": release.get("published_at"),
            "url": url if url.startswith(RELEASE_PREFIX) else RELEASE_PREFIX, "assets": assets}


def products(releases):
    out = []
    published = [r for r in releases if not r.get("draft") and r.get("published_at") and r.get("tag_name")]
    published.sort(key=lambda r: r["published_at"], reverse=True)
    for ident, name, pattern in PRODUCTS:
        mine = [r for r in published if pattern.match(r["tag_name"])]
        stable = next((r for r in mine if not r.get("prerelease")), None)
        preview = next((r for r in mine if r.get("prerelease")), None)
        if preview and stable and preview["published_at"] <= stable["published_at"]:
            preview = None
        out.append({"id": ident, "name": name, "stable": release_view(stable) if stable else None,
                    "preview": release_view(preview) if preview else None})
    return out


def build(status_files, handover_files, releases, previous, now):
    return {"schema_version": 1, "generated_at": iso_s(now),
            "project": {"name": "Threat Atlas", "repository_url": f"https://github.com/{PUBLIC_REPO}"},
            "products": products(releases) if releases is not None else (previous or {}).get("products", []),
            "rules": {"stall_after_minutes": STALL_MINUTES, "alert_hours_stockholm": ALERT_HOURS,
                      "low_weekly_percent": LOW_WEEKLY_PERCENT, "low_balance_usd": LOW_BALANCE_USD},
            "agents": agent_rows(status_files, handover_files, previous, now)}


def same_content(a, b):
    strip = lambda d: {k: v for k, v in (d or {}).items() if k != "generated_at"}
    return strip(a) == strip(b)


def needs_publish(previous, public, now):
    """Publish on any change, and at least every HEARTBEAT seconds so a quiet night still shows
    that the builder runs (the alert job watches generated_at)."""
    try:
        last = stamp((previous or {}).get("generated_at"))
    except (ValueError, TypeError):
        return True
    return not same_content(previous, public) or now - last >= HEARTBEAT


def try_read(repo, path, token, label):
    try:
        return read_json(repo, path, token)[0]
    except urllib.error.HTTPError as error:
        if error.code != 404:
            print(f"{label}: unreadable (HTTP {error.code}), using fallback")
    except (urllib.error.URLError, ValueError, KeyError) as error:
        print(f"{label}: unreadable ({type(error).__name__}), using fallback")
    return None


def main():
    handover_token, publish_token = os.environ.get("HANDOVER_TOKEN"), os.environ.get("GH_TOKEN")
    if not handover_token or not publish_token:
        print("::warning::AGENT_HEALTH_READ_TOKEN secret is not set; status not published")
        return
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    status_files, handover_files = {}, {}
    for ident in AGENTS:
        status_files[ident] = try_read(PRIVATE_REPO, f"status/{ident}.json", handover_token, f"status/{ident}")
        if status_files[ident] is None:
            handover_files[ident] = try_read(PRIVATE_REPO, f"handovers/{ident}.json", handover_token,
                                             f"handovers/{ident}")
    try:
        releases = api(f"repos/{PUBLIC_REPO}/releases?per_page=50", publish_token)
    except (urllib.error.URLError, ValueError) as error:
        print(f"releases: unreadable ({type(error).__name__}), keeping previous products")
        releases = None
    try:
        previous, sha = read_json(PUBLIC_REPO, PUBLIC_PATH, publish_token, PUBLIC_BRANCH)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        previous, sha = None, None
    public = build(status_files, handover_files, releases, previous, now)
    summary = ", ".join(f"{a['id']} {a['source']} {a['last_seen_at']} credits {a['credits']}" for a in public["agents"])
    if not needs_publish(previous, public, now):
        print("No change: " + summary)
        return
    if os.environ.get("DRY_RUN"):
        print(json.dumps(public, indent=2))
        return
    body = {"message": "Refresh public Atlas status", "branch": PUBLIC_BRANCH,
            "content": base64.b64encode((json.dumps(public, indent=2) + "\n").encode()).decode()}
    if sha:
        body["sha"] = sha
    api(f"repos/{PUBLIC_REPO}/contents/{PUBLIC_PATH}", publish_token, "PUT", body)
    print("Published: " + summary)


if __name__ == "__main__":
    main()
