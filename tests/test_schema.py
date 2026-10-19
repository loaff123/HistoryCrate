"""Strict syntactic input tests; filesystem admission belongs to paths tests."""
import copy
import dataclasses
import importlib
import json
from pathlib import Path
import unittest


OID = "a" * 40


def valid_spec():
    return {
        "version": 1,
        "repositories": [
            {"id": "main", "git_dir": "/declared/missing/main.git"},
            {"id": "child", "git_dir": "/declared/missing/child.git"},
        ],
        "roots": [{"id": "release", "repository": "main", "commits": [OID]}],
        "bindings": [{"parent_repository": "main", "path": "data", "url": "../data.git", "child_repository": "child"}],
    }


class SchemaTests(unittest.TestCase):
    def setUp(self):
        try:
            self.schema = importlib.import_module("historycrate.schema")
            self.errors = importlib.import_module("historycrate.errors")
        except ModuleNotFoundError as exc:
            self.fail(f"Schema foundation is not implemented: {exc.name}")

    def load(self, value):
        return self.schema.load_spec(json.dumps(value).encode("utf-8"))

    def assert_invalid(self, data, exit_code=2):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode("utf-8")
        with self.assertRaises(self.errors.CrateError) as caught:
            self.schema.load_spec(data)
        self.assertEqual(caught.exception.exit_code, exit_code)
        return caught.exception

    def test_valid_typed_immutable_spec_and_exact_default_cache(self):
        spec = self.load(valid_spec())
        self.assertEqual(spec.version, 1)
        self.assertEqual(spec.repositories[0].git_dir, Path("/declared/missing/main.git"))
        self.assertEqual(spec.repositories[0].lfs_objects_dir, Path("/declared/missing/main.git/lfs/objects"))
        self.assertEqual(spec.roots[0].commits, (OID,))
        self.assertEqual(spec.bindings[0].url, "../data.git")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            spec.version = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            spec.repositories[0].id = "changed"

    def test_explicit_cache_preserved_without_filesystem_discovery(self):
        value = valid_spec()
        value["repositories"][0]["lfs_objects_dir"] = "/custom/nonexistent/cache"
        self.assertEqual(str(self.load(value).repositories[0].lfs_objects_dir), "/custom/nonexistent/cache")

    def test_duplicate_keys_and_unknown_fields_fail(self):
        raw = json.dumps(valid_spec()).encode()
        self.assert_invalid(raw.replace(b'"version": 1', b'"version": 1, "version": 1'))
        self.assert_invalid(raw.replace(b'"id": "release"', b'"id": "release", "id": "release"'))
        for route in [(), ("repositories", 0), ("roots", 0), ("bindings", 0)]:
            value = valid_spec()
            target = value
            for part in route:
                target = target[part]
            target["misspelled"] = 1
            with self.subTest(route=route):
                self.assert_invalid(value)

    def test_required_fields_and_exact_container_types(self):
        for field in ["version", "repositories", "roots", "bindings"]:
            value = valid_spec()
            del value[field]
            self.assert_invalid(value)
        for value in [None, [], "string", 1]:
            self.assert_invalid(value)
        for field in ["repositories", "roots", "bindings"]:
            for replacement in [{}, None, "text", [True]]:
                value = valid_spec()
                value[field] = replacement
                self.assert_invalid(value)

    def test_oid_must_be_exact_commit_shape(self):
        for oid in ["HEAD", "v1.0", "a" * 40 + "^", "A" * 40, "a" * 39, "a" * 41, "g" * 40, "a" * 39 + "\n", None, 1]:
            value = valid_spec()
            value["roots"][0]["commits"] = [oid]
            with self.subTest(oid=oid):
                self.assert_invalid(value)
        value = valid_spec()
        value["roots"][0]["commits"] = []
        self.assert_invalid(value)
        value["roots"][0]["commits"] = OID
        self.assert_invalid(value)

    def test_id_shape_and_unknown_references(self):
        for identity in ["Main", "1main", "a" * 33, "", "main\n", "é", None]:
            value = valid_spec()
            value["repositories"][0]["id"] = identity
            self.assert_invalid(value)
        for route, field in [("roots", "repository"), ("bindings", "parent_repository"), ("bindings", "child_repository")]:
            value = valid_spec()
            value[route][0][field] = "absent"
            self.assert_invalid(value)

    def test_duplicate_identities_are_rejected(self):
        for array in ["repositories", "roots", "bindings"]:
            value = valid_spec()
            value[array].append(copy.deepcopy(value[array][0]))
            self.assert_invalid(value)
        value = valid_spec()
        value["roots"][0]["commits"].append(OID)
        self.assert_invalid(value)
        value = valid_spec()
        value["repositories"][1]["git_dir"] = value["repositories"][0]["git_dir"]
        self.assert_invalid(value)
        value = valid_spec()
        value["bindings"].append(dict(value["bindings"][0], child_repository="main"))
        self.assert_invalid(value)

    def test_distinct_historical_bindings_and_shared_child_are_preserved(self):
        value = valid_spec()
        value["bindings"].extend([
            dict(value["bindings"][0], url="../renamed.git"),
            dict(value["bindings"][0], path="other"),
        ])
        spec = self.load(value)
        self.assertEqual(len(spec.bindings), 3)
        self.assertEqual({binding.child_repository for binding in spec.bindings}, {"child"})

    def test_absolute_paths_are_syntactic_and_explicit(self):
        for path in ["relative/.git", "", "~/repo", "/repo/../other", "/repo/./objects", "//ambiguous/repo", "/repo//objects", "/bad\x00repo", "/bad\nrepo", "/bad\\repo"]:
            value = valid_spec()
            value["repositories"][0]["git_dir"] = path
            self.assert_invalid(value)
        value = valid_spec()
        value["repositories"][0]["git_dir"] = "/home/user/project/.git/modules/data"
        self.assertEqual(str(self.load(value).repositories[0].git_dir), value["repositories"][0]["git_dir"])

    def test_relative_path_refusals(self):
        for path in ["", "/absolute", "a//b", "a/./b", "a/../b", "a/", ".git", "a/.GiT/file", "a\\b", "a\x00b", "a\nb", "e\u0301", "a" * 256, "/".join(["a"] * 65), "/".join(["a" * 255] * 5)]:
            value = valid_spec()
            value["bindings"][0]["path"] = path
            with self.subTest(path=path):
                self.assert_invalid(value)

    def test_safe_posix_punctuation_and_nfc_unicode_paths(self):
        for path in [":wq", "a b/'quoted'", "-leading-dash", "é", "é" * 127]:
            value = valid_spec()
            value["bindings"][0]["path"] = path
            self.assertEqual(self.load(value).bindings[0].path, path)

    def test_byte_limits_apply_to_utf8_paths(self):
        value = valid_spec()
        value["bindings"][0]["path"] = "é" * 128
        self.assert_invalid(value)
        value = valid_spec()
        value["limits"] = {"path_bytes": 3}
        value["bindings"][0]["path"] = "éé"
        self.assert_invalid(value)

    def test_bad_utf8_bom_lone_surrogates_and_noninteger_numbers_fail(self):
        raw = json.dumps(valid_spec()).encode()
        for data in [b"\xef\xbb\xbf" + raw, b"\xff", raw + b"\xff", raw.replace(b'"version": 1', b'"version": 1.0'), raw.replace(b'"version": 1', b'"version": true'), raw.replace(b'"version": 1', b'"version": NaN'), raw.replace(b'"version": 1', b'"version": Infinity'), raw.replace(b'"data"', b'"\\ud800"')]:
            self.assert_invalid(data)
        for version in [0, 2, "1", None]:
            value = valid_spec()
            value["version"] = version
            self.assert_invalid(value)

    def test_json_depth_and_input_size_are_bounded(self):
        self.assert_invalid(b"[" * 1000 + b"0" + b"]" * 1000)
        self.assert_invalid(b" " * (16 * 1024 * 1024 + 1), exit_code=5)
        value = valid_spec()
        value["limits"] = {"spec_bytes": 1}
        self.assert_invalid(value, exit_code=5)

    def test_lowered_admission_limits_apply(self):
        for limits in [{"root_groups": 0}, {"selected_root_commits": 0}, {"repositories": 0}]:
            value = valid_spec()
            value["limits"] = limits
            self.assert_invalid(value, exit_code=5)

    def test_empty_selections_and_unused_declarations_are_syntactically_valid(self):
        value = {"version": 1, "repositories": [], "roots": [], "bindings": []}
        self.assertEqual(self.load(value).roots, ())
        value = valid_spec()
        value["limits"] = {"repositories": 1}
        self.assertEqual(len(self.load(value).repositories), 2)

    def test_invalid_limit_override_is_schema_error(self):
        for overrides in [{"repositories": 33}, {"lfs_payload_bytes": 513 * 1024 * 1024}, {"unknown": 1}, {"repositories": True}, {"repositories": -1}, [], None]:
            value = valid_spec()
            value["limits"] = overrides
            self.assert_invalid(value)

    def test_encode_canonical_is_sorted_utf8_and_rejects_non_json_values(self):
        self.assertEqual(self.schema.encode_canonical({"z": [1, True, None], "a": "é"}), '{"a":"é","z":[1,true,null]}'.encode())
        for value in [{"a": 1.0}, {"a": float("nan")}, {"a": float("inf")}, {1: "not-a-string-key"}, {"a": (1, 2)}, {"a": "\ud800"}, {"a": Path("/private/runtime")}, {"a": object()}]:
            with self.subTest(value=repr(value)):
                with self.assertRaises(self.errors.CrateError):
                    self.schema.encode_canonical(value)

    def test_encode_canonical_rejects_cycles_and_excessive_depth(self):
        value = []
        value.append(value)
        with self.assertRaises(self.errors.CrateError):
            self.schema.encode_canonical(value)
        value = 0
        for _ in range(1000):
            value = [value]
        with self.assertRaises(self.errors.CrateError):
            self.schema.encode_canonical(value)

    def test_diagnostics_escape_controls_and_hide_url_credentials(self):
        exc = self.errors.CrateError("INPUT_INVALID", 4, {
            "path": "bad\x1b[31m\nname",
            "url": "https://alice:secret-token@example.test/repo?token=private-token",
            "config": "[credential]\nhelper = secret-helper",
        })
        rendered = json.dumps(exc.to_dict(), ensure_ascii=True) + str(exc)
        for secret in ["secret-token", "private-token", "secret-helper", "\x1b"]:
            self.assertNotIn(secret, rendered)
        self.assertEqual(exc.code, "INPUT_INVALID")
        self.assertEqual(exc.exit_code, 4)
        self.assertIn("\\u001b", rendered)
        self.assertNotIn("https://", rendered)


    def test_diagnostics_preserve_safe_lowercase_codes_and_finite_observations(self):
        exc = self.errors.CrateError("process_io_failed", 5, {"elapsed_seconds": 1.25, "sample_gap_seconds": 0.125, "observations": [0.25] * 101})
        diagnostic = exc.to_dict()
        self.assertEqual(diagnostic["code"], "process_io_failed")
        self.assertEqual(diagnostic["exit_code"], 5)
        self.assertEqual(diagnostic["context"]["elapsed_seconds"], 1.25)
        self.assertEqual(diagnostic["context"]["sample_gap_seconds"], 0.125)
        self.assertEqual(diagnostic["context"]["observations"][:100], [0.25] * 100)
        self.assertEqual(diagnostic["context"]["observations"][100], {"context_truncated": True, "omitted": 1})
        for value in [float("nan"), float("inf"), -float("inf")]:
            safe = self.errors.CrateError("ERROR", 6, {"value": value}).to_dict()
            json.dumps(safe, allow_nan=False)

    def test_url_digest_survives_repeated_serialization(self):
        import hashlib
        url = "https://alice:token@example.test/repo"
        expected = "<url-sha256:" + hashlib.sha256(url.encode()).hexdigest() + ">"
        exc = self.errors.CrateError("INVALID_INPUT", 4, {"url": url})
        self.assertEqual(exc.context["url"], expected)
        self.assertEqual(exc.to_dict()["context"]["url"], expected)
        self.assertEqual(exc.to_dict(), exc.to_dict())
        self.assertEqual(json.loads(str(exc))["context"]["url"], expected)


if __name__ == "__main__":
    unittest.main()
