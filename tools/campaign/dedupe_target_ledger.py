#!/usr/bin/env python3
"""Deterministically normalize and dedupe target_ledger.json."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


GITHUB_REPO_RE = re.compile(r"github\.com/([^/\s]+)/([^/\s]+)")


def canonical_repo_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [segment for segment in parsed.path.split("/") if segment]
    if len(parts) < 2:
        return None
    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"{owner}/{repo}"


def canonical_repo_from_text(text: str) -> str | None:
    match = GITHUB_REPO_RE.search(text)
    if not match:
        return None
    owner, repo = match.groups()
    repo = repo.rstrip("/").removesuffix(".git")
    return f"{owner}/{repo}"


def canonical_github_url(url: str) -> str:
    repo = canonical_repo_from_url(url)
    if repo is None:
        return url
    return f"https://github.com/{repo}"


def ordered_unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def entry_key(entry: dict) -> tuple[str, str]:
    urls = entry.get("urls", [])
    repos = ordered_unique(
        [repo for repo in (canonical_repo_from_url(url) for url in urls) if repo]
    )
    if len(repos) == 1:
        return ("github_repo", repos[0])
    text_repo = canonical_repo_from_text(entry.get("target", ""))
    if text_repo and len(repos) <= 1:
        return ("github_repo", text_repo)
    return (
        "verbatim",
        json.dumps(
            {
                "engagement": entry.get("engagement"),
                "source_file": entry.get("source_file"),
                "line_number": entry.get("line_number"),
                "target": entry.get("target"),
                "urls": [canonical_github_url(url) for url in urls],
            },
            sort_keys=True,
        ),
    )


def merge_entries(primary: dict, duplicate: dict) -> dict:
    primary["urls"] = ordered_unique(
        [canonical_github_url(url) for url in primary.get("urls", [])]
        + [canonical_github_url(url) for url in duplicate.get("urls", [])]
    )
    for field in ("language_tags", "matched_attack_keywords"):
        primary[field] = ordered_unique(primary.get(field, []) + duplicate.get(field, []))
    primary["priority_score"] = max(
        int(primary.get("priority_score", 0)),
        int(duplicate.get("priority_score", 0)),
    )

    primary_hunted = bool(primary.get("hunted", False))
    duplicate_hunted = bool(duplicate.get("hunted", False))
    if primary_hunted or duplicate_hunted:
        primary["hunted"] = True
        if not primary.get("hunt_result") and duplicate.get("hunt_result"):
            primary["hunt_result"] = duplicate["hunt_result"]
    return primary


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tools/campaign/target_ledger.json")
    document = json.loads(path.read_text(encoding="utf-8"))
    targets = document.get("targets", [])

    repo_hunt_state: dict[str, str] = {}
    hunted_repos: set[str] = set()
    for entry in targets:
        repos = ordered_unique(
            [repo for repo in (canonical_repo_from_url(url) for url in entry.get("urls", [])) if repo]
        )
        if not entry.get("hunted", False):
            continue
        for repo in repos:
            hunted_repos.add(repo)
            if entry.get("hunt_result") and repo not in repo_hunt_state:
                repo_hunt_state[repo] = entry["hunt_result"]

    deduped: list[dict] = []
    index: dict[tuple[str, str], int] = {}
    for entry in targets:
        normalized = dict(entry)
        normalized["urls"] = [canonical_github_url(url) for url in entry.get("urls", [])]
        repos = ordered_unique(
            [repo for repo in (canonical_repo_from_url(url) for url in normalized.get("urls", [])) if repo]
        )
        if repos and all(repo in hunted_repos for repo in repos):
            normalized["hunted"] = True
            if not normalized.get("hunt_result"):
                for repo in repos:
                    if repo in repo_hunt_state:
                        normalized["hunt_result"] = repo_hunt_state[repo]
                        break
        key = entry_key(normalized)
        existing = index.get(key)
        if existing is None:
            index[key] = len(deduped)
            deduped.append(normalized)
            continue
        deduped[existing] = merge_entries(deduped[existing], normalized)

    document["targets"] = deduped
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
