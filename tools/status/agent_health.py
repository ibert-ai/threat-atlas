"""Publish the public agent-health projection for https://ibert.se/Project/status/ straight from
the private Git handovers, without any agent's computer in the loop (owner request, 9 Nov 2026,
ATLAS-STATUS-GIT-DIRECT-001).

Reads handovers/<agent>.json from the private ibert-ai/project-status-dashboard repository with
a read-only token, merges them into the existing public file and publishes only the reviewed
fields: fixed agent ids and names, latest report and heartbeat times, and the capacity class with
its time. No handover content, task text, sources, hosts, tokens or credit numbers are exported.
Times only move forward; future-dated reports are refused; an unreadable agent file keeps the
previous public values. The browser ages the times to yellow/red by itself.

Environment: HANDOVER_TOKEN (read-only contents on the private repo), GH_TOKEN (write contents on
this public repo), optionally DRY_RUN=1 to print instead of publishing.
"""
import base64
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.request

AGENTS = {"mac": "MacGyver (Crew)", "cl": "Jean-Claude Van Damme (CBO – Chief Bot Officer)", "billy": "BillyBadass (Crew)",
          "noris": "Seek Norris (CMO – Chief Marketing Officer)"}
CAPACITY = {"available", "low", "exhausted", "unknown"}
PRIVATE_REPO = "ibert-ai/project-status-dashboard"
PUBLIC_REPO = "ibert-ai/threat-atlas"
PUBLIC_BRANCH = "codex/release-status"
PUBLIC_PATH = "status/agent-health.json"
FUTURE_SKEW = 120


def stamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp required")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timezone required")
    return parsed.timestamp()


def iso(seconds):
    return dt.datetime.fromtimestamp(seconds, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def empty_row():
    return {"last_reported_at": None, "last_heartbeat_at": None, "capacity": "unknown",
            "capacity_reported_at": None}


def merge(previous, inputs, now):
    """previous: the current public projection (or None). inputs: {agent_id: parsed handover file}.
    Returns the new public projection. Invalid fields in one agent file are ignored for that field
    only; a broken file never erases earlier values."""
    rows = {}
    for agent in (previous or {}).get("agents", []):
        if agent.get("id") in AGENTS:
            rows[agent["id"]] = {k: agent.get(k) for k in empty_row()}
    started = (previous or {}).get("monitoring_started_at") or iso(now)
    for ident in AGENTS:
        row = rows.setdefault(ident, empty_row())
        raw = inputs.get(ident)
        if not isinstance(raw, dict):
            continue
        health = raw.get("health") if isinstance(raw.get("health"), dict) else {}
        for key, value in (("last_reported_at", raw.get("updated_at")),
                           ("last_heartbeat_at", health.get("reported_at"))):
            try:
                t = stamp(value)
            except (ValueError, TypeError):
                continue
            if t > now + FUTURE_SKEW:
                continue
            if row[key] is None or t > stamp(row[key]):
                row[key] = iso(t)
        if row["last_heartbeat_at"] and (not row["last_reported_at"]
                                         or stamp(row["last_heartbeat_at"]) > stamp(row["last_reported_at"])):
            row["last_reported_at"] = row["last_heartbeat_at"]
        credits = raw.get("credits") if isinstance(raw.get("credits"), dict) else {}
        status = credits.get("status")
        try:
            t = stamp(credits.get("reported_at"))
        except (ValueError, TypeError):
            t = None
        if status in CAPACITY and t is not None and t <= now + FUTURE_SKEW:
            if row["capacity_reported_at"] is None or t > stamp(row["capacity_reported_at"]):
                row["capacity"], row["capacity_reported_at"] = status, iso(t)
    return {"schema_version": 1, "updated_at": iso(now), "monitoring_started_at": started,
            "agents": [dict(id=k, name=v, **rows[k]) for k, v in AGENTS.items()]}


def same_observations(a, b):
    """True when nothing but updated_at differs (no commit needed)."""
    strip = lambda d: {k: v for k, v in (d or {}).items() if k != "updated_at"}
    return strip(a) == strip(b)


def api(path, token, method="GET", body=None):
    request = urllib.request.Request(
        "https://api.github.com/" + path, method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "atlas-agent-health"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def read_json(repo, path, token, ref=None):
    query = f"?ref={ref}" if ref else ""
    meta = api(f"repos/{repo}/contents/{path}{query}", token)
    return json.loads(base64.b64decode(meta["content"])), meta["sha"]


def main():
    handover_token, publish_token = os.environ.get("HANDOVER_TOKEN"), os.environ.get("GH_TOKEN")
    if not handover_token or not publish_token:
        # Not configured yet: warn and skip instead of failing every 5 minutes.
        print("::warning::AGENT_HEALTH_READ_TOKEN secret is not set; agent health not published")
        return
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    inputs = {}
    for ident in AGENTS:
        try:
            inputs[ident] = read_json(PRIVATE_REPO, f"handovers/{ident}.json", handover_token)[0]
        except (urllib.error.URLError, ValueError, KeyError) as error:
            detail = " ".join(str(x) for x in (type(error).__name__, getattr(error, "code", "")) if x)
            print(f"{ident}: unreadable, keeping previous values ({detail})")
    previous, sha = read_json(PUBLIC_REPO, PUBLIC_PATH, publish_token, PUBLIC_BRANCH)
    public = merge(previous, inputs, now)
    summary = ", ".join(f"{a['id']} heartbeat {a['last_heartbeat_at']}" for a in public["agents"])
    if same_observations(previous, public):
        print("No change: " + summary)
        return
    if os.environ.get("DRY_RUN"):
        print(json.dumps(public, indent=2))
        return
    content = base64.b64encode((json.dumps(public, indent=2) + "\n").encode()).decode()
    api(f"repos/{PUBLIC_REPO}/contents/{PUBLIC_PATH}", publish_token, "PUT",
        {"message": "Refresh public agent health from private handovers", "content": content,
         "sha": sha, "branch": PUBLIC_BRANCH})
    print("Published: " + summary)


if __name__ == "__main__":
    main()
