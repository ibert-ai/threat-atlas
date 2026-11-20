"""Tests for build_status.py (no network). Run: python3 -I tools/status/test_build_status.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_status as b  # noqa: E402

NOW = b.stamp("2026-11-20T15:00:00Z")
URL = "https://github.com/Ibert-Iam/threat-atlas/releases/"


def release(tag, at, pre=False, draft=False):
    return {"tag_name": tag, "name": tag, "published_at": at, "prerelease": pre, "draft": draft,
            "html_url": URL + "tag/" + tag,
            "assets": [{"name": "a.zip", "browser_download_url": URL + f"download/{tag}/a.zip",
                        "digest": "sha256:" + "a" * 64},
                       {"name": "evil", "browser_download_url": "https://evil.example/x", "digest": ""}]}


class Credits(unittest.TestCase):
    def test_weekly_percent(self):
        self.assertEqual(b.credit_class({"weekly_percent_remaining": 3}), "low")
        self.assertEqual(b.credit_class({"weekly_percent_remaining": 40}), "ok")
        self.assertEqual(b.credit_class({"weekly_percent_remaining": 0}), "empty")

    def test_balance(self):
        self.assertEqual(b.credit_class({"balance_usd": 0.5}), "low")
        self.assertEqual(b.credit_class({"currency": "USD", "remaining": 1.18}), "ok")
        self.assertEqual(b.credit_class({"balance_usd": 0}), "empty")

    def test_declared_and_legacy(self):
        self.assertEqual(b.credit_class({"status": "low"}), "low")
        self.assertEqual(b.credit_class({"status": "available"}), "ok")
        self.assertEqual(b.credit_class({"status": "<script>"}), "unknown")
        self.assertEqual(b.credit_class(None), "unknown")


class Agents(unittest.TestCase):
    def test_status_file_wins_and_hides_private_text(self):
        status = {"cl": {"updated_at": "2026-11-20T14:30:00Z", "state": "working", "current_work": "secret task",
                         "blockers": ["x"], "credits": {"weekly_percent_remaining": 50,
                                                        "checked_at": "2026-11-20T14:00:00Z"}}}
        row = b.agent_rows(status, {}, None, NOW)[0]
        self.assertEqual((row["source"], row["state"], row["credits"]), ("status", "working", "ok"))
        self.assertNotIn("secret", repr(row))
        self.assertNotIn("blockers", row)

    def test_future_or_bad_time_falls_back(self):
        status = {"cl": {"updated_at": "2030-01-01T00:00:00Z", "state": "working"}}
        handover = {"cl": {"updated_at": "2026-11-20T10:00:00Z", "health": {"reported_at": "2026-11-20T14:00:00Z"},
                           "credits": {"status": "low", "reported_at": "2026-11-20T11:00:00Z"}}}
        row = b.agent_rows(status, handover, None, NOW)[0]
        self.assertEqual((row["source"], row["last_seen_at"], row["credits"]),
                         ("handover", "2026-11-20T14:00:00Z", "low"))

    def test_bad_state_word(self):
        status = {"cl": {"updated_at": "2026-11-20T14:30:00Z", "state": "<b>hi</b>"}}
        self.assertEqual(b.agent_rows(status, {}, None, NOW)[0]["state"], "unknown")

    def test_missing_input_keeps_previous_row(self):
        previous = {"agents": [{"id": "mac", "last_seen_at": "2026-11-20T09:00:00Z", "state": "idle",
                                "credits": "ok", "credits_checked_at": None, "source": "status"}]}
        rows = {r["id"]: r for r in b.agent_rows({}, {}, previous, NOW)}
        self.assertEqual(rows["mac"]["last_seen_at"], "2026-11-20T09:00:00Z")
        self.assertEqual(rows["billy"]["source"], "none")

    def test_newest_billy_capacity_record(self):
        handover = {"billy": {"updated_at": "2026-11-20T14:00:00Z",
                              "credits": {"status": "available", "reported_at": "2026-11-10T10:00:00Z"},
                              "capacity": {"status": "low", "observed_at": "2026-11-20T14:05:00Z"}}}
        row = {r["id"]: r for r in b.agent_rows({}, handover, None, NOW)}["billy"]
        self.assertEqual((row["credits"], row["credits_checked_at"]), ("low", "2026-11-20T14:05:00Z"))


class Products(unittest.TestCase):
    def test_split_and_preview(self):
        out = b.products([release("v0.4.8", "2026-11-11T00:00:00Z"),
                          release("v0.4.7-rc.1", "2026-11-10T00:00:00Z", pre=True),
                          release("atlassoc-v0.7.0", "2026-11-11T00:00:00Z"),
                          release("atlassoc-v0.8.0-rc.1", "2026-11-15T00:00:00Z", pre=True),
                          release("atlassoc-v0.9.0", "2026-11-16T00:00:00Z", draft=True)])
        saver, desktop = out
        self.assertEqual((saver["stable"]["tag"], saver["preview"]), ("v0.4.8", None))
        self.assertEqual((desktop["stable"]["tag"], desktop["preview"]["tag"]),
                         ("atlassoc-v0.7.0", "atlassoc-v0.8.0-rc.1"))
        self.assertEqual([a["name"] for a in saver["stable"]["assets"]], ["a.zip"])
        self.assertEqual(saver["stable"]["assets"][0]["sha256"], "a" * 64)

    def test_releases_unreadable_keeps_previous(self):
        previous = {"products": [{"id": "screensaver"}]}
        self.assertEqual(b.build({}, {}, None, previous, NOW)["products"], [{"id": "screensaver"}])

    def test_old_credit_reading_is_unknown(self):
        status = {"cl": {"updated_at": "2026-11-20T14:30:00Z", "state": "idle",
                         "credits": {"weekly_percent_remaining": 3, "checked_at": "2026-11-18T10:00:00Z"}}}
        self.assertEqual(b.agent_rows(status, {}, None, NOW)[0]["credits"], "unknown")

    def test_hourly_heartbeat_publish(self):
        a = b.build({}, {}, [], None, NOW)
        self.assertFalse(b.needs_publish(a, b.build({}, {}, [], None, NOW + 600), NOW + 600))
        self.assertTrue(b.needs_publish(a, b.build({}, {}, [], None, NOW + 3600), NOW + 3600))
        self.assertTrue(b.needs_publish(None, a, NOW))

    def test_no_change_detection(self):
        a = b.build({}, {}, [], None, NOW)
        c = b.build({}, {}, [], None, NOW + 60)
        self.assertTrue(b.same_content(a, c))


if __name__ == "__main__":
    unittest.main(verbosity=1)
