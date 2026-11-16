"""Build and publish a bounded public runtime report using only stdlib.

Release and orphan-tag ownership is proven by ``OWNER_MARKER``. Generated refs
point to annotated tag objects whose fixed message also includes the exact tag
name, allowing retention to reclaim owned orphans without touching unrelated
runtime-like tags.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener


API_BASE = "https://api.github.com"
UPLOAD_BASE = "https://uploads.github.com"
OWNER_MARKER = "<!-- litefupzl-runtime-report:v1 -->"
KEEP_GROUPS = 15
MAX_SOURCE_BYTES = 1_048_576
MAX_TIMELINE_BYTES = 2_097_152
MAX_TIMELINE_EVENTS = 5_000
MAX_LINE_BYTES = 16_384
MAX_API_BYTES = 2_097_152
MAX_API_PAGES = 20
REQUEST_TIMEOUT_SECONDS = 10

TAG_RE = re.compile(
    r"^runtime-(?P<timestamp>\d{8}T\d{6}Z)-(?P<run_id>\d{1,20})-(?P<attempt>\d{1,6})$"
)
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
SLOT_RE = re.compile(r"^slot-(\d{1,4})$")

RUN_OUTCOMES = {"success", "failure", "cancelled", "skipped"}
RUN_STATUSES = {"success", "cf_blocked", "auth_failed", "runtime_error"}
SLOT_STATUSES = set("success warning cf_blocked cookie_invalid account_blocked runtime_error".split())
COOKIE_STATES = {"ok", "unchanged", "warning", "skipped"}
WARNING_CODES = set(
    "CF_BLOCKED READ_FAILED USER_INFO_UNAVAILABLE TOPIC_FETCH_FAILED "
    "NEW_TOPIC_POOL_EXHAUSTED NEW_TOPIC_TARGET_UNMET COOKIE_REFRESH_FAILED "
    "LOGIN_DEVICE_PROOF_INCONCLUSIVE MUTUAL_LIKE_WARNING MUTUAL_LIKE_RATE_LIMITED "
    "BROWSER_DRIVER_CRASH BROWSER_DRIVER_HANG COOKIE_STATE_UNCERTAIN RUNTIME_WARNING".split()
)
WATCHDOG_PHASES = set(
    "startup driver_retry driver_crashed_cleanup login_prewarm login_prewarmed "
    "cookie_injection_started cookie_injected auth_navigation auth_navigated "
    "authenticated_unsynced authenticated_synced slot_complete".split()
)
WATCHDOG_TIMEOUTS = set(
    "BROWSER_DRIVER_HANG_PRE_AUTH BROWSER_DRIVER_HANG_POST_AUTH "
    "COOKIE_STATE_UNCERTAIN_DRIVER_HANG".split()
)


class ReportError(RuntimeError):
    def __init__(self, safe_code: str):
        super().__init__(safe_code)
        self.safe_code = safe_code


@dataclass(frozen=True)
class RuntimeIdentity:
    repository: str
    sha: str
    run_id: int
    run_attempt: int


@dataclass(frozen=True)
class ReportPaths:
    json_path: Path
    markdown_path: Path


@dataclass(frozen=True)
class OwnedRelease:
    release_id: int
    tag: str
    draft: bool


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


_CANONICAL_OPENER = build_opener(_NoRedirect()).open


def _integer(value: Any, minimum: int = 0, maximum: int = 1_000_000) -> int | None:
    return value if type(value) is int and minimum <= value <= maximum else None


def _boolean(value: Any) -> bool | None:
    return value if type(value) is bool else None


def _choice(value: Any, allowed: set[str], default: str = "unknown") -> str:
    return value if isinstance(value, str) and value in allowed else default


def _repository(value: str) -> bool:
    return bool(
        REPOSITORY_RE.fullmatch(value)
        and all(part not in {".", ".."} for part in value.split("/"))
    )


def _env_int(value: str | None, maximum: int) -> int | None:
    if value is None or not value.isascii() or not value.isdigit():
        return None
    parsed = int(value)
    return parsed if 1 <= parsed <= maximum else None


def _slot_index(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    match = SLOT_RE.fullmatch(value)
    return _integer(int(match.group(1)), 1, 1_000) if match else None


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str]:
    try:
        if path.is_symlink() or not path.is_file():
            return None, "missing"
        if path.stat().st_size > MAX_SOURCE_BYTES:
            return None, "too_large"
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, "malformed"
    return (value, "available") if isinstance(value, dict) else (None, "malformed")


def _read_timeline(path: Path) -> tuple[dict[int, dict[str, Any]], str]:
    facts: dict[int, dict[str, Any]] = {}
    try:
        if path.is_symlink() or not path.is_file():
            return facts, "missing"
        if path.stat().st_size > MAX_TIMELINE_BYTES:
            return facts, "too_large"
        with path.open("rb") as handle:
            for count, raw_line in enumerate(handle):
                if count >= MAX_TIMELINE_EVENTS:
                    return facts, "truncated"
                if not raw_line.strip():
                    continue
                if len(raw_line) > MAX_LINE_BYTES:
                    return {}, "malformed"
                event = json.loads(raw_line.decode("utf-8"))
                if not isinstance(event, dict):
                    return {}, "malformed"
                index = _slot_index(event.get("slot"))
                if index is None:
                    continue
                fact = facts.setdefault(index, {"cookie_state": "unknown", "warning_count": 0})
                status = event.get("status")
                level = event.get("level")
                if event.get("step") == "cookie-refresh" and isinstance(status, str) and status in COOKIE_STATES:
                    fact["cookie_state"] = status
                if (
                    isinstance(level, str)
                    and level in {"warning", "error"}
                    or isinstance(status, str)
                    and status in {"warning", "failed", "crashed", "unconfirmed"}
                ):
                    fact["warning_count"] = min(10_000, fact["warning_count"] + 1)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, "malformed"
    return facts, "available"


def _safe_slot(raw: Mapping[str, Any], timeline: Mapping[str, Any]) -> dict[str, Any] | None:
    index = _integer(raw.get("slot_index"), 1, 1_000) or _slot_index(raw.get("slot_alias"))
    if index is None:
        return None
    cookie_state = _choice(timeline.get("cookie_state"), COOKIE_STATES)
    if cookie_state == "unknown" and raw.get("cookie_refresh_ok") is True:
        cookie_state = "ok"
    warnings = raw.get("warning_codes")
    summary_warning_count = (
        len({item for item in warnings if isinstance(item, str) and item in WARNING_CODES})
        if isinstance(warnings, list)
        else 0
    )
    result = {
        "slot_index": index,
        "status": _choice(raw.get("status"), SLOT_STATUSES),
        "login_ok": _boolean(raw.get("login_ok")) or False,
        "read_ok": _boolean(raw.get("read_ok")) or False,
        "device_proof_ok": _boolean(raw.get("security_current_device_ok")) or False,
        "topics": {
            "target": _integer(raw.get("new_topic_target"), 0, 10_000) or 0,
            "confirmed": _integer(raw.get("new_topics_confirmed"), 0, 10_000) or 0,
            "target_met": _boolean(raw.get("new_topic_target_met")) or False,
        },
        "cookie_refresh_state": cookie_state,
        "warning_count": min(
            10_000,
            summary_warning_count + int(timeline.get("warning_count", 0)),
        ),
    }
    return result


def _safe_watchdog(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    result: dict[str, Any] = {"phase": _choice(raw.get("phase"), WATCHDOG_PHASES)}
    for key in (
        "timed_out",
        "child_terminated",
        "cookie_injection_started",
        "cookie_checkpoint_complete",
    ):
        value = _boolean(raw.get(key))
        if value is not None:
            result[key] = value
    exit_code = _integer(raw.get("exit_code"), 0, 255)
    if exit_code is not None:
        result["exit_code"] = exit_code
    timeout = raw.get("timeout_code")
    if isinstance(timeout, str) and timeout in WATCHDOG_TIMEOUTS:
        result["timeout_code"] = timeout
    index = _slot_index(raw.get("slot"))
    if index is not None:
        result["slot_index"] = index
    return result


def _availability(statuses: Mapping[str, str]) -> tuple[str, str]:
    values = list(statuses.values())
    if not any(value in {"available", "truncated"} for value in values):
        return "unavailable", "Runtime artifacts were unavailable or malformed; workflow metadata is still reported."
    if any(value != "available" for value in values):
        return "partial", "Some fixed runtime artifacts were unavailable or could not be fully read."
    return "available", "All fixed runtime artifacts were read within resource limits."


def _run_metadata(env: Mapping[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "step_outcome": _choice(env.get("REPORT_STEP_OUTCOME"), RUN_OUTCOMES)
    }
    repository = env.get("GITHUB_REPOSITORY", "")
    sha = env.get("GITHUB_SHA", "")
    run_id = _env_int(env.get("GITHUB_RUN_ID"), 10**20 - 1)
    attempt = _env_int(env.get("GITHUB_RUN_ATTEMPT"), 999_999)
    if _repository(repository):
        result["repository"] = repository
    if SHA_RE.fullmatch(sha):
        result["sha"] = sha.lower()
    if run_id is not None:
        result["run_id"] = run_id
    if attempt is not None:
        result["run_attempt"] = attempt
    if env.get("GITHUB_SERVER_URL") == "https://github.com" and _repository(repository) and run_id:
        result["run_url"] = f"https://github.com/{repository}/actions/runs/{run_id}"
    return result


def build_report(
    input_dir: Path,
    report_dir: Path,
    env: Mapping[str, str],
    *,
    now: datetime | None = None,
) -> tuple[dict[str, Any], ReportPaths]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    summary, summary_status = _read_json(input_dir / "oneshot_summary.json")
    timeline, timeline_status = _read_timeline(input_dir / "oneshot_timeline.jsonl")
    watchdog_raw, watchdog_status = _read_json(input_dir / "watchdog_state.json")
    sources = {
        "oneshot_summary.json": summary_status,
        "oneshot_timeline.jsonl": timeline_status,
        "watchdog_state.json": watchdog_status,
    }
    slots = []
    if summary and isinstance(summary.get("slots"), list):
        for raw in summary["slots"][:1_000]:
            if not isinstance(raw, dict):
                continue
            index = _integer(raw.get("slot_index"), 1, 1_000) or _slot_index(raw.get("slot_alias"))
            slot = _safe_slot(raw, timeline.get(index or -1, {}))
            if slot:
                slots.append(slot)
    slots.sort(key=lambda item: item["slot_index"])

    safe_summary: dict[str, Any] = {
        "final_status": _choice(summary.get("final_status") if summary else None, RUN_STATUSES),
        "slot_count": len(slots),
        "login_ok_count": sum(slot["login_ok"] for slot in slots),
        "read_ok_count": sum(slot["read_ok"] for slot in slots),
        "topics_confirmed": sum(slot["topics"]["confirmed"] for slot in slots),
        "device_proof_ok_count": sum(slot["device_proof_ok"] for slot in slots),
        "warning_count": sum(slot["warning_count"] for slot in slots),
    }
    availability, note = _availability(sources)
    report: dict[str, Any] = {
        "schema": "litefupzl-runtime-report/v1",
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "availability": availability,
        "note": note,
        "sources": sources,
        "run": _run_metadata(env),
        "summary": safe_summary,
        "slots": slots,
    }
    watchdog = _safe_watchdog(watchdog_raw)
    if watchdog is not None:
        report["watchdog"] = watchdog
        if watchdog.get("timed_out") is True and isinstance(watchdog.get("slot_index"), int):
            for slot in slots:
                if slot["slot_index"] != watchdog["slot_index"]:
                    continue
                slot["warning_count"] = min(10_000, slot["warning_count"] + 1)
                safe_summary["warning_count"] = min(10_000, safe_summary["warning_count"] + 1)
                if watchdog.get("timeout_code") == "COOKIE_STATE_UNCERTAIN_DRIVER_HANG":
                    slot["cookie_refresh_state"] = "warning"
                break

    report_dir.mkdir(parents=True, exist_ok=True)
    paths = ReportPaths(report_dir / "report.json", report_dir / "report.md")
    _write(paths.json_path, json.dumps(report, ensure_ascii=True, indent=2) + "\n")
    _write(paths.markdown_path, render_markdown(report))
    return report, paths


def render_markdown(report: Mapping[str, Any]) -> str:
    run, summary = report["run"], report["summary"]
    lines = [
        "# litefupzl runtime report",
        "",
        f"- Availability: `{report['availability']}`",
        f"- Runtime step outcome: `{run['step_outcome']}`",
        f"- Generated at: `{report['generated_at']}`",
        f"- Slots/login/read: `{summary['slot_count']}/{summary['login_ok_count']}/{summary['read_ok_count']}`",
        f"- Topics/device proof/warnings: `{summary['topics_confirmed']}/{summary['device_proof_ok_count']}/{summary['warning_count']}`",
    ]
    if "repository" in run:
        lines.append(f"- Repository: `{run['repository']}`")
    if "sha" in run:
        lines.append(f"- Commit: `{run['sha']}`")
    if "run_id" in run and "run_attempt" in run:
        lines.append(f"- Run: `{run['run_id']}` attempt `{run['run_attempt']}`")
    lines += ["", report["note"], "", "## Slots", ""]
    for slot in report["slots"]:
        lines.append(
            f"- Slot {slot['slot_index']}: {slot['status']}; login={slot['login_ok']}; "
            f"read={slot['read_ok']}; topics={slot['topics']['confirmed']}/{slot['topics']['target']}; "
            f"device_proof={slot['device_proof_ok']}; cookie={slot['cookie_refresh_state']}; "
            f"warnings={slot['warning_count']}"
        )
    if not report["slots"]:
        lines.append("No bounded slot summary was available.")
    return "\n".join(lines) + "\n"


def _write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _identity(env: Mapping[str, str]) -> RuntimeIdentity:
    repository = env.get("GITHUB_REPOSITORY", "")
    sha = env.get("GITHUB_SHA", "")
    run_id = _env_int(env.get("GITHUB_RUN_ID"), 10**20 - 1)
    attempt = _env_int(env.get("GITHUB_RUN_ATTEMPT"), 999_999)
    if not _repository(repository):
        raise ReportError("invalid_repository")
    if not SHA_RE.fullmatch(sha):
        raise ReportError("invalid_commit_sha")
    if run_id is None or attempt is None:
        raise ReportError("invalid_run_identity")
    return RuntimeIdentity(repository, sha.lower(), run_id, attempt)


class GitHubClient:
    def __init__(self, token: str, repository: str, *, opener=_CANONICAL_OPENER):
        if not token:
            raise ReportError("missing_runtime_report_token")
        if not _repository(repository):
            raise ReportError("invalid_repository")
        self.repository = repository
        self._token = token
        self._opener = opener

    def request_json(self, method, path, payload=None, *, expected=(200,)):
        if not path.startswith("/") or "//" in path:
            raise ReportError("invalid_api_path")
        data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        request = Request(
            API_BASE + path,
            data=data,
            method=method,
            headers=self._headers("application/vnd.github+json"),
        )
        return self._request(request, expected)

    def upload_asset(self, release_id: int, name: str, path: Path):
        if name not in {"report.json", "report.md"}:
            raise ReportError("invalid_asset_name")
        data = path.read_bytes()
        if len(data) > MAX_SOURCE_BYTES:
            raise ReportError("report_asset_too_large")
        content_type = "application/json" if name.endswith(".json") else "text/markdown; charset=utf-8"
        request = Request(
            f"{UPLOAD_BASE}/repos/{self.repository}/releases/{release_id}/assets?name={quote(name)}",
            data=data,
            method="POST",
            headers=self._headers(content_type),
        )
        return self._request(request, (201,))

    def _headers(self, content_type: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "Content-Type": content_type,
            "User-Agent": "litefupzl-runtime-report/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, request: Request, expected: tuple[int, ...]):
        try:
            with self._opener(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                status = int(response.status)
                raw = response.read(MAX_API_BYTES + 1)
        except HTTPError as exc:
            raise ReportError(f"github_api_http_{int(exc.code)}") from None
        except (URLError, OSError, TimeoutError):
            raise ReportError("github_api_unavailable") from None
        if status not in expected:
            raise ReportError(f"github_api_http_{status}")
        if len(raw) > MAX_API_BYTES:
            raise ReportError("github_api_response_too_large")
        if not raw:
            return None
        try:
            return json.loads(raw.decode())
        except (UnicodeError, json.JSONDecodeError):
            raise ReportError("github_api_invalid_response") from None


def _paged(client: Any, path: str) -> list[Any]:
    separator = "&" if "?" in path else "?"
    result = []
    for page in range(1, MAX_API_PAGES + 1):
        items = client.request_json(
            "GET",
            f"{path}{separator}per_page=100&page={page}",
            expected=(200,),
        )
        if not isinstance(items, list):
            raise ReportError("github_api_invalid_response")
        result.extend(items)
        if len(items) < 100:
            return result
    raise ReportError("github_api_pagination_limit")


def _tag_message(tag: str) -> str:
    return f"{OWNER_MARKER}\n{tag}"


def discover_releases_and_tags(client: Any) -> tuple[list[OwnedRelease], dict[str, str | None]]:
    releases = []
    unowned_release_tags = set()
    for raw in _paged(client, f"/repos/{client.repository}/releases"):
        if not isinstance(raw, dict):
            continue
        release_id = _integer(raw.get("id"), 1, 10**18)
        tag, body, draft = raw.get("tag_name"), raw.get("body"), _boolean(raw.get("draft"))
        if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
            continue
        if (
            release_id is not None
            and isinstance(body, str)
            and OWNER_MARKER in body
            and draft is not None
        ):
            releases.append(OwnedRelease(release_id, tag, draft))
        else:
            unowned_release_tags.add(tag)

    refs: dict[str, str | None] = {}
    for raw in _paged(client, f"/repos/{client.repository}/git/matching-refs/tags/runtime-"):
        if not isinstance(raw, dict) or not isinstance(raw.get("object"), dict):
            continue
        ref, obj = raw.get("ref"), raw["object"]
        tag = ref.removeprefix("refs/tags/") if isinstance(ref, str) else ""
        if not TAG_RE.fullmatch(tag):
            continue
        refs[tag] = None
        object_sha = obj.get("sha")
        if obj.get("type") != "tag" or not isinstance(object_sha, str) or not SHA_RE.fullmatch(object_sha):
            continue
        tag_object = client.request_json(
            "GET",
            f"/repos/{client.repository}/git/tags/{object_sha}",
            expected=(200,),
        )
        if not isinstance(tag_object, dict) or not isinstance(tag_object.get("object"), dict):
            continue
        target = tag_object["object"]
        target_sha = target.get("sha")
        if (
            tag_object.get("tag") == tag
            and tag_object.get("message") == _tag_message(tag)
            and target.get("type") == "commit"
            and isinstance(target_sha, str)
            and SHA_RE.fullmatch(target_sha)
        ):
            refs[tag] = target_sha.lower()
    for tag in unowned_release_tags:
        if tag in refs:
            refs[tag] = None
    return releases, refs


def build_tag(now: datetime, run_id: int, run_attempt: int) -> str:
    stamp = now.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y%m%dT%H%M%SZ")
    return f"runtime-{stamp}-{run_id}-{run_attempt}"


def _tag_key(tag: str) -> tuple[str, int, int]:
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise ReportError("invalid_runtime_tag")
    return match.group("timestamp"), int(match.group("run_id")), int(match.group("attempt"))


def _same_attempt(tag: str, identity: RuntimeIdentity) -> bool:
    match = TAG_RE.fullmatch(tag)
    return bool(
        match
        and int(match.group("run_id")) == identity.run_id
        and int(match.group("attempt")) == identity.run_attempt
    )


def _assets(client: Any, release_id: int) -> set[str]:
    return {
        raw.get("name")
        for raw in _paged(client, f"/repos/{client.repository}/releases/{release_id}/assets")
        if isinstance(raw, dict)
        and raw.get("name") in {"report.json", "report.md"}
        and raw.get("state") in {None, "uploaded"}
    }


def _ensure_tag(client: Any, tag: str, sha: str, refs: Mapping[str, str | None]) -> None:
    if tag in refs:
        if refs[tag] != sha:
            raise ReportError("runtime_tag_conflict")
        return
    tag_object = client.request_json(
        "POST",
        f"/repos/{client.repository}/git/tags",
        {"tag": tag, "message": _tag_message(tag), "object": sha, "type": "commit"},
        expected=(201,),
    )
    object_sha = tag_object.get("sha") if isinstance(tag_object, dict) else None
    if not isinstance(object_sha, str) or not SHA_RE.fullmatch(object_sha):
        raise ReportError("github_api_invalid_response")
    client.request_json(
        "POST",
        f"/repos/{client.repository}/git/refs",
        {"ref": f"refs/tags/{tag}", "sha": object_sha},
        expected=(201,),
    )


def _create_release(client: Any, tag: str, sha: str) -> OwnedRelease:
    raw = client.request_json(
        "POST",
        f"/repos/{client.repository}/releases",
        {
            "tag_name": tag,
            "target_commitish": sha,
            "name": tag,
            "body": f"{OWNER_MARKER}\n\nBounded litefupzl runtime report.",
            "draft": True,
            "prerelease": False,
            "make_latest": "false",
        },
        expected=(201,),
    )
    release_id = _integer(raw.get("id"), 1, 10**18) if isinstance(raw, dict) else None
    if release_id is None:
        raise ReportError("github_api_invalid_response")
    return OwnedRelease(release_id, tag, True)


def publish_report(
    client: Any,
    identity: RuntimeIdentity,
    paths: ReportPaths,
    *,
    now: datetime | None = None,
) -> str:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    releases, refs = discover_releases_and_tags(client)
    same = [item for item in releases if _same_attempt(item.tag, identity)]
    if same:
        release = max(same, key=lambda item: _tag_key(item.tag))
        _ensure_tag(client, release.tag, identity.sha, refs)
    else:
        orphans = [tag for tag, sha in refs.items() if sha == identity.sha and _same_attempt(tag, identity)]
        if orphans:
            tag = max(orphans, key=_tag_key)
        else:
            candidates = [build_tag(now + timedelta(seconds=i), identity.run_id, identity.run_attempt) for i in range(61)]
            tag = next((item for item in candidates if item not in refs), None)
            if tag is None:
                raise ReportError("runtime_tag_collision_limit")
        _ensure_tag(client, tag, identity.sha, refs)
        release = _create_release(client, tag, identity.sha)

    present = _assets(client, release.release_id)
    for name, path in (("report.json", paths.json_path), ("report.md", paths.markdown_path)):
        if name not in present:
            client.upload_asset(release.release_id, name, path)
    if release.draft:
        client.request_json(
            "PATCH",
            f"/repos/{client.repository}/releases/{release.release_id}",
            {"draft": False, "make_latest": "false"},
            expected=(200,),
        )
    cleanup_retention(client, current_tag=release.tag)
    return release.tag


def cleanup_retention(client: Any, *, current_tag: str, keep: int = KEEP_GROUPS) -> list[str]:
    releases, refs = discover_releases_and_tags(client)
    published = {release.tag: release for release in releases if not release.draft}
    ordered = sorted(published, key=_tag_key, reverse=True)
    kept = {current_tag}
    for tag in ordered:
        if tag != current_tag and len(kept) < keep:
            kept.add(tag)
    deleted = []
    stale_releases = [release for release in releases if release.draft and release.tag != current_tag]
    stale_releases += [published[tag] for tag in ordered if tag not in kept]
    for release in stale_releases:
        tag = release.tag
        client.request_json(
            "DELETE",
            f"/repos/{client.repository}/releases/{release.release_id}",
            expected=(204,),
        )
        if refs.get(tag) is not None:
            client.request_json(
                "DELETE",
                f"/repos/{client.repository}/git/refs/tags/{tag}",
                expected=(204,),
            )
        deleted.append(tag)
    release_tags = {release.tag for release in releases}
    for tag, commit_sha in refs.items():
        if commit_sha is None or tag == current_tag or tag in release_tags:
            continue
        client.request_json(
            "DELETE",
            f"/repos/{client.repository}/git/refs/tags/{tag}",
            expected=(204,),
        )
        deleted.append(tag)
    return deleted


def _append_summary(path_value: str | None, markdown: str) -> None:
    if not path_value:
        return
    try:
        path = Path(path_value)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(markdown)
    except OSError:
        pass


def main(env: Mapping[str, str] | None = None, *, now: datetime | None = None, client: Any = None) -> int:
    env = os.environ if env is None else env
    input_dir = Path(env.get("LITEFUPZL_OUTPUT_DIR") or "output/litefupzl")
    try:
        _, paths = build_report(input_dir, input_dir.parent / "runtime-report", env, now=now)
        markdown = paths.markdown_path.read_text(encoding="utf-8")
    except Exception:
        print("litefupzl runtime report failed: report_build_failed", file=sys.stderr)
        return 1
    _append_summary(env.get("GITHUB_STEP_SUMMARY"), markdown)
    try:
        identity = _identity(env)
        active_client = client or GitHubClient(env.get("RUNTIME_REPORT_TOKEN", ""), identity.repository)
        publish_report(active_client, identity, paths, now=now)
    except ReportError as exc:
        print(f"litefupzl runtime report failed: {exc.safe_code}", file=sys.stderr)
        return 1
    except Exception:
        print("litefupzl runtime report failed: unexpected_error", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
