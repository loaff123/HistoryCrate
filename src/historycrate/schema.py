"""Strict, bounded UTF-8 JSON decoding and syntactic selection admission.

No filesystem path is resolved or opened here. Ownership, concrete directory
identity, symlink refusal, overlaps and commit-object kinds belong to later
filesystem/native boundaries. A syntactically valid Spec is not readiness.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import unicodedata

from .errors import CrateError
from .limits import Budget, Limits
from .model import Binding, RepoSpec, RootSpec, Spec

MAX_JSON_DEPTH = 64
_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_OID = re.compile(r"[0-9a-f]{40}\Z")


def _invalid(reason: str) -> CrateError:
    return CrateError("INVALID_SPEC", 2, {"reason": reason})


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _invalid("duplicate JSON key")
        result[key] = value
    return result


def _noninteger(value: str) -> object:
    raise _invalid("noninteger JSON number")


def _check_text_depth(text: str) -> None:
    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise _invalid("excessive JSON nesting")
        elif char in "]}":
            depth -= 1


def _check_json_value(value: object, depth: int = 0, active: set[int] | None = None) -> None:
    if depth > MAX_JSON_DEPTH:
        raise _invalid("excessive JSON nesting")
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise _invalid("invalid Unicode scalar value") from None
        return
    if type(value) not in (list, dict):
        raise _invalid("unsupported JSON value type")
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise _invalid("cyclic JSON value")
    active.add(identity)
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _invalid("JSON object key must be a string")
            _check_json_value(key, depth + 1, active)
            _check_json_value(item, depth + 1, active)
    else:
        for item in value:
            _check_json_value(item, depth + 1, active)
    active.remove(identity)


def encode_canonical(value: object) -> bytes:
    """UTF-8 JSON with sorted keys, compact separators and integer numbers.

    Only JSON types are accepted; runtime Path objects and typed records must
    never silently leak into semantic JSON through a generic str() fallback.
    """
    try:
        _check_json_value(value)
        return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (ValueError, OverflowError, RecursionError, UnicodeError):
        raise _invalid("cannot encode canonical JSON") from None


def _object(value: object, required: set[str], optional: set[str] | None = None) -> dict[str, object]:
    if type(value) is not dict:
        raise _invalid("expected JSON object")
    allowed = required | (optional or set())
    if set(value) - allowed or required - set(value):
        raise _invalid("missing or unknown field")
    return value


def _array(value: object) -> list[object]:
    if type(value) is not list:
        raise _invalid("expected JSON array")
    return value


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise _invalid("expected nonempty string")
    if any(unicodedata.category(char) == "Cc" for char in value):
        raise _invalid("control character in identity or path")
    return value


def _id(value: object) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise _invalid("invalid identifier")
    return value


def _absolute_path(value: object) -> Path:
    value = _string(value)
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        raise _invalid("source path must be explicit absolute POSIX path")
    if value != "/" and any(component in ("", ".", "..") for component in value[1:].split("/")):
        raise _invalid("nonconcrete source path component")
    return Path(value)


def _relative_path(value: object, limits: Limits) -> str:
    value = _string(value)
    if value.startswith("/") or "\\" in value or unicodedata.normalize("NFC", value) != value:
        raise _invalid("unsupported repository-relative path")
    parts = value.split("/")
    if len(parts) > limits.path_depth or len(value.encode("utf-8")) > limits.path_bytes:
        raise _invalid("repository-relative path exceeds limit")
    for component in parts:
        if component in ("", ".", "..") or component.casefold() == ".git":
            raise _invalid("unsafe repository-relative component")
        if len(component.encode("utf-8")) > limits.component_bytes:
            raise _invalid("repository-relative component exceeds limit")
    return value


def load_spec(data: bytes) -> Spec:
    if type(data) is not bytes:
        raise _invalid("spec input must be bytes")
    Budget().charge("spec_bytes", len(data))
    if data.startswith(b"\xef\xbb\xbf"):
        raise _invalid("UTF-8 BOM is not allowed")
    try:
        text = data.decode("utf-8", errors="strict")
        _check_text_depth(text)
        value = json.loads(text, object_pairs_hook=_unique_object, parse_float=_noninteger, parse_constant=_noninteger)
        _check_json_value(value)
    except (UnicodeError, ValueError, RecursionError):
        raise _invalid("invalid UTF-8 JSON") from None
    value = _object(value, {"version", "repositories", "roots", "bindings"}, {"limits"})
    if type(value["version"]) is not int or value["version"] != 1:
        raise _invalid("unsupported spec version")
    limits = Limits().lower(value.get("limits", {}))
    budget = Budget(limits)
    budget.charge("spec_bytes", len(data))

    repositories = []
    repository_ids = set()
    repository_paths = set()
    for item in _array(value["repositories"]):
        item = _object(item, {"id", "git_dir"}, {"lfs_objects_dir"})
        identity = _id(item["id"])
        git_dir = _absolute_path(item["git_dir"])
        cache = _absolute_path(item["lfs_objects_dir"]) if "lfs_objects_dir" in item else git_dir / "lfs" / "objects"
        if identity in repository_ids or git_dir in repository_paths:
            raise _invalid("duplicate repository identity")
        repository_ids.add(identity)
        repository_paths.add(git_dir)
        repositories.append(RepoSpec(identity, git_dir, cache))

    roots = []
    root_ids = set()
    active_root_repositories = set()
    for item in _array(value["roots"]):
        item = _object(item, {"id", "repository", "commits"})
        identity, repository = _id(item["id"]), _id(item["repository"])
        if identity in root_ids or repository not in repository_ids:
            raise _invalid("duplicate root or unknown repository")
        raw_commits = _array(item["commits"])
        if not raw_commits:
            raise _invalid("root commits must be nonempty")
        commits = []
        seen_commits = set()
        for commit in raw_commits:
            if not isinstance(commit, str) or _OID.fullmatch(commit) is None:
                raise _invalid("commit must be an exact lowercase SHA-1 OID")
            if commit in seen_commits:
                raise _invalid("duplicate selected commit")
            seen_commits.add(commit)
            commits.append(commit)
        root_ids.add(identity)
        active_root_repositories.add(repository)
        budget.charge("root_groups", 1)
        budget.charge("selected_root_commits", len(commits))
        roots.append(RootSpec(identity, repository, tuple(commits)))
    # Unused repository declarations are permitted and are not acquired. The
    # closure walker must account for each newly demanded dependency later.
    budget.charge("repositories", len(active_root_repositories))

    bindings = []
    binding_keys = set()
    for item in _array(value["bindings"]):
        item = _object(item, {"parent_repository", "path", "url", "child_repository"})
        parent, child = _id(item["parent_repository"]), _id(item["child_repository"])
        if parent not in repository_ids or child not in repository_ids:
            raise _invalid("binding references unknown repository")
        path, url = _relative_path(item["path"], limits), _string(item["url"])
        key = (parent, path, url)
        if key in binding_keys:
            raise _invalid("duplicate or ambiguous binding identity")
        binding_keys.add(key)
        bindings.append(Binding(parent, path, url, child))
    return Spec(1, tuple(repositories), tuple(roots), tuple(bindings), limits)
