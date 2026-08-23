"""
Simple content-hash based cache, so that scanning the same unchanged
files (or the same unchanged requirements.txt) twice doesn't re-run
the underlying tools. This matters most in CI/CD (GitHub Actions):
if a PR only touches one file out of a hundred, there's no reason to
re-run bandit/detect-secrets on the other ninety-nine, or re-hit
osv.dev for dependencies that didn't change.

Cache is stored as a single JSON file on disk. Structure:
{
    "files": {
        "<file_path>": {
            "hash": "<sha256 of file content>",
            "bandit": [...findings...],
            "secrets": [...findings...]
        }
    },
    "dependencies": {
        "<sha256 of requirements.txt content>": [...findings...]
    }
}
"""
from __future__ import annotations

import hashlib
import json
import os


DEFAULT_CACHE_PATH = ".audit_cache.json"


def compute_file_hash(path: str) -> str:
    """Returns the sha256 hash of a file's raw bytes."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def compute_text_hash(text: str) -> str:
    """Returns the sha256 hash of a string (used for requirements.txt content)."""
    return hashlib.sha256(text.encode()).hexdigest()


def load_cache(cache_path: str = DEFAULT_CACHE_PATH) -> dict:
    if os.path.isfile(cache_path):
        try:
            with open(cache_path) as f:
                return json.load(f)
        except json.JSONDecodeError:
            # corrupted cache file - start fresh rather than crashing
            pass
    return {"files": {}, "dependencies": {}}


def save_cache(data: dict, cache_path: str = DEFAULT_CACHE_PATH) -> None:
    with open(cache_path, "w") as f:
        json.dump(data, f, indent=2)


def get_cached_file_findings(cache: dict, file_path: str, current_hash: str) -> dict | None:
    """
    Returns the cached {"bandit": [...], "secrets": [...]} for a file
    only if its hash matches the cached one (i.e. content unchanged).
    Returns None if there's no valid cache entry (new or changed file).
    """
    entry = cache["files"].get(file_path)
    if entry is not None and entry.get("hash") == current_hash:
        return {"bandit": entry.get("bandit", []), "secrets": entry.get("secrets", [])}
    return None


def set_cached_file_findings(
    cache: dict, file_path: str, current_hash: str, bandit_findings: list, secrets_findings: list
) -> None:
    cache["files"][file_path] = {
        "hash": current_hash,
        "bandit": bandit_findings,
        "secrets": secrets_findings,
    }


def get_cached_dependency_findings(cache: dict, requirements_hash: str) -> list | None:
    return cache["dependencies"].get(requirements_hash)


def set_cached_dependency_findings(cache: dict, requirements_hash: str, findings: list) -> None:
    cache["dependencies"][requirements_hash] = findings