"""Frozen v1 thresholds and additive accounting contracts."""
import dataclasses
import importlib
import unittest

MiB = 1024 ** 2
GiB = 1024 ** 3
DEFAULTS = {
    "repositories": 32, "root_groups": 32, "selected_root_commits": 64,
    "commits": 50_000, "git_objects": 250_000,
    "gitlink_occurrences": 100_000, "commit_path_visits": 5_000_000,
    "repository_depth": 16, "path_depth": 64, "bundle_seed_refs": 8_192,
    "git_object_bytes": 256 * MiB, "lfs_payload_bytes": 512 * MiB,
    "source_git_bytes": 2 * GiB, "unique_lfs_bytes": 2 * GiB,
    "scratch_bytes": 8 * GiB, "packet_bytes": 4 * GiB,
    "restore_bytes": 4 * GiB, "combined_bytes": 12 * GiB,
    "spec_bytes": 16 * MiB, "manifest_bytes": 16 * MiB,
    "config_bytes": MiB, "gitmodules_bytes": MiB,
    "gitattributes_bytes": 256 * 1024, "pointer_bytes": 1024,
    "path_bytes": 1024, "component_bytes": 255,
    "command_wall_seconds": 300, "command_cpu_seconds": 180,
    "command_file_bytes": 4 * GiB, "job_wall_seconds": 1800,
    "observed_rss_bytes": GiB, "native_commands": 1,
    "command_descriptors": 256, "captured_bytes": 16 * MiB,
    "diagnostics": 1000, "observation_entries": 4096,
}


class LimitsTests(unittest.TestCase):
    def setUp(self):
        try:
            self.module = importlib.import_module("historycrate.limits")
            self.errors = importlib.import_module("historycrate.errors")
        except ModuleNotFoundError as exc:
            self.fail(f"Limits foundation is not implemented: {exc.name}")

    def test_default_thresholds_match_v1_exactly(self):
        limits = self.module.Limits()
        self.assertEqual(dataclasses.asdict(limits), DEFAULTS)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            limits.repositories = 33

    def test_limits_cannot_increase(self):
        defaults = self.module.Limits()
        for name, amount in DEFAULTS.items():
            with self.subTest(name=name):
                with self.assertRaises(self.errors.CrateError) as caught:
                    defaults.lower({name: amount + 1})
                self.assertEqual(caught.exception.exit_code, 2)
        lower = defaults.lower({"repositories": 3})
        self.assertEqual(lower.repositories, 3)
        self.assertEqual(defaults.repositories, 32)
        with self.assertRaises(self.errors.CrateError):
            lower.lower({"repositories": 4})

    def test_limit_construction_cannot_bypass_profile_caps(self):
        with self.assertRaises(self.errors.CrateError):
            self.module.Limits(repositories=33)
        with self.assertRaises(self.errors.CrateError):
            self.module.Limits(command_wall_seconds=True)
        self.assertEqual(self.module.Limits(repositories=1).repositories, 1)

    def test_limits_require_known_nonnegative_integers(self):
        limits = self.module.Limits()
        for overrides in [{"unknown": 1}, {"repositories": -1}, {"repositories": True}, {"repositories": 1.5}, {"repositories": "1"}, [], None]:
            with self.subTest(overrides=overrides):
                with self.assertRaises(self.errors.CrateError) as caught:
                    limits.lower(overrides)
                self.assertEqual(caught.exception.exit_code, 2)
        self.assertEqual(limits.lower({"repositories": 0}).repositories, 0)
        self.assertEqual(limits.lower({}), limits)

    def test_budget_boundary(self):
        limits = self.module.Limits().lower({name: min(amount, 3) for name, amount in DEFAULTS.items()})
        for name in DEFAULTS:
            budget = self.module.Budget(limits)
            amount = getattr(limits, name)
            with self.subTest(resource=name):
                budget.charge(name, amount)
                self.assertEqual(budget.used[name], amount)
                with self.assertRaises(self.errors.CrateError) as caught:
                    budget.charge(name, 1)
                self.assertEqual(caught.exception.exit_code, 5)
                self.assertEqual(caught.exception.code, "BUDGET_EXCEEDED")
                self.assertEqual(caught.exception.context["resource"], name)
                self.assertEqual(budget.used[name], amount)

    def test_budget_accumulates_without_clamping(self):
        budget = self.module.Budget(self.module.Limits().lower({"commits": 5}))
        budget.charge("commits", 2)
        budget.charge("commits", 3)
        self.assertEqual(budget.used["commits"], 5)
        with self.assertRaises(self.errors.CrateError):
            budget.charge("commits", 1)
        self.assertEqual(budget.used["commits"], 5)
        with self.assertRaises(TypeError):
            budget.used["commits"] = 0

    def test_budget_rejects_unknown_and_invalid_charges_as_invariants(self):
        budget = self.module.Budget(self.module.Limits())
        for resource, amount in [("not_a_limit", 1), ("commits", -1), ("commits", True), ("commits", 0.1), ("commits", "1")]:
            with self.assertRaises(self.errors.CrateError) as caught:
                budget.charge(resource, amount)
            self.assertEqual(caught.exception.exit_code, 6)
        budget.charge("commits", 0)
        self.assertEqual(budget.used["commits"], 0)

    def test_limit_report_distinguishes_observation_and_enforcement(self):
        report = self.module.Limits().as_dict()
        self.assertEqual(set(report), set(DEFAULTS))
        for name, threshold in DEFAULTS.items():
            self.assertEqual(report[name]["threshold"], threshold)
            self.assertIsInstance(report[name]["kind"], str)
        self.assertIn("observed", report["scratch_bytes"]["kind"])
        self.assertIn("sampled", report["observed_rss_bytes"]["kind"])
        self.assertIn("per-process", report["command_cpu_seconds"]["kind"])
        self.assertNotIn("hard", report["combined_bytes"]["kind"])


if __name__ == "__main__":
    unittest.main()
