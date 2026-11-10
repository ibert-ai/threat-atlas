"""Offline tests for the public agent-health projection. Synthetic data only; no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from agent_health import iso, merge, same_observations, stamp  # noqa: E402

NOW = stamp("2026-11-10T03:00:00Z")
PREVIOUS = {
    "schema_version": 1, "updated_at": "2026-11-07T15:22:46Z", "monitoring_started_at": "2026-11-04T23:16:11Z",
    "agents": [
        {"id": "mac", "name": "MacGyver", "last_reported_at": "2026-11-07T15:20:49Z",
         "last_heartbeat_at": "2026-11-07T07:31:11Z", "capacity": "low", "capacity_reported_at": "2026-11-07T14:15:11Z"},
        {"id": "cl", "name": "Jean-Claude Van Damme", "last_reported_at": "2026-11-07T15:18:31Z",
         "last_heartbeat_at": "2026-11-07T15:18:31Z", "capacity": "available", "capacity_reported_at": "2026-11-07T15:18:31Z"},
        {"id": "billy", "name": "BillyBadass", "last_reported_at": "2026-11-06T19:01:06Z",
         "last_heartbeat_at": "2026-11-06T19:01:06Z", "capacity": "low", "capacity_reported_at": "2026-11-06T19:00:53Z"},
    ],
}
SECRET_TASK = "private task text that must never be published"


class AgentHealthTests(unittest.TestCase):
    def test_new_heartbeats_and_capacity_are_published(self):
        inputs = {
            "cl": {"updated_at": "2026-11-10T02:40:00Z", "health": {"reported_at": "2026-11-10T02:48:00Z"},
                   "handovers": [{"task": SECRET_TASK}]},
            "mac": {"updated_at": "2026-11-10T02:27:55.626875+00:00",
                    "health": {"reported_at": "2026-11-10T02:27:55.626875+00:00", "note": SECRET_TASK},
                    "credits": {"status": "available", "reported_at": "2026-11-10T02:27:55Z", "balance": 1234}},
        }
        public = merge(PREVIOUS, inputs, NOW)
        rows = {a["id"]: a for a in public["agents"]}
        self.assertEqual(rows["cl"]["last_heartbeat_at"], "2026-11-10T02:48:00Z")
        self.assertEqual(rows["cl"]["last_reported_at"], "2026-11-10T02:48:00Z")
        self.assertEqual(rows["mac"]["last_heartbeat_at"], "2026-11-10T02:27:55.626875Z")
        self.assertEqual((rows["mac"]["capacity"], rows["mac"]["capacity_reported_at"]), ("available", "2026-11-10T02:27:55Z"))
        self.assertEqual(rows["billy"], {**PREVIOUS["agents"][2]}, "missing agent file keeps previous values")
        self.assertEqual(public["monitoring_started_at"], PREVIOUS["monitoring_started_at"])
        text = json.dumps(public)
        self.assertNotIn(SECRET_TASK, text)
        self.assertNotIn("1234", text, "credit numbers stay private")
        self.assertEqual(set(rows["mac"]), {"id", "name", "last_reported_at", "last_heartbeat_at", "capacity", "capacity_reported_at"})

    def test_times_never_move_back_and_future_or_broken_values_are_ignored(self):
        inputs = {
            "cl": {"updated_at": "2026-11-01T00:00:00Z", "health": {"reported_at": "2026-11-01T00:00:00Z"}},
            "mac": {"updated_at": "2026-11-11T00:00:00Z", "health": {"reported_at": "2026-11-11T00:00:00Z"},
                    "credits": {"status": "available", "reported_at": "2026-11-11T00:00:00Z"}},
            "billy": {"updated_at": "not a time", "health": "broken", "credits": {"status": "rich", "reported_at": "2026-11-10T00:00:00Z"}},
        }
        public = merge(PREVIOUS, inputs, NOW)
        self.assertEqual([{k: a[k] for k in a if k != "name"} for a in public["agents"][:3]],
                         [{k: a[k] for k in a if k != "name"} for a in PREVIOUS["agents"]])
        self.assertEqual(public["agents"][3]["id"], "noris")

    def test_nothing_new_means_no_commit(self):
        public = merge(PREVIOUS, {}, NOW)
        self.assertFalse(same_observations(PREVIOUS, public), "new agent row is a change")
        self.assertTrue(same_observations(public, merge(public, {"cl": {"health": {"reported_at": "2026-11-01T00:00:00Z"}}}, NOW + 60)))

    def test_first_run_without_previous_file(self):
        public = merge(None, {"cl": {"health": {"reported_at": "2026-11-10T02:59:00Z"}}}, NOW)
        self.assertEqual(public["monitoring_started_at"], iso(NOW))
        self.assertEqual([a["id"] for a in public["agents"]], ["mac", "cl", "billy", "noris"])
        self.assertEqual(public["agents"][0]["last_heartbeat_at"], None)
        self.assertEqual(public["agents"][1]["capacity"], "unknown")

    def test_naive_timestamps_are_refused(self):
        with self.assertRaises(ValueError):
            stamp("2026-11-10T02:00:00")


if __name__ == "__main__":
    unittest.main()
