from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit

import pytest

from apps.litefupzl import runtime_report as report


NOW = datetime(2026, 11, 14, 12, 34, 56, tzinfo=timezone.utc)
SHA = "a" * 40


def _env(tmp_path: Path, **overrides: str) -> dict[str, str]:
    values = {
        "LITEFUPZL_OUTPUT_DIR": str(tmp_path / "output" / "litefupzl"),
        "REPORT_STEP_OUTCOME": "success",
        "GITHUB_REPOSITORY": "owner/repository",
        "GITHUB_SHA": SHA,
        "GITHUB_RUN_ID": "12345",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_SERVER_URL": "https://github.com",
        "RUNTIME_REPORT_TOKEN": "test-token",
    }
    values.update(overrides)
    return values


def _write_inputs(tmp_path: Path, summary: dict, timeline: list[dict], watchdog: dict) -> Path:
    input_dir = tmp_path / "output" / "litefupzl"
    input_dir.mkdir(parents=True)
    (input_dir / "oneshot_summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (input_dir / "oneshot_timeline.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in timeline),
        encoding="utf-8",
    )
    (input_dir / "watchdog_state.json").write_text(json.dumps(watchdog), encoding="utf-8")
    return input_dir


def _tag(at: datetime, run_id: int, attempt: int = 1) -> str:
    return report.build_tag(at, run_id, attempt)


class FakeGitHubClient:
    repository = "owner/repository"

    def __init__(self, *, releases=None, refs=None, assets=None, unowned_refs=None):
        self.releases = list(releases or [])
        self.refs = dict(refs or {})
        self.unowned_refs = set(unowned_refs or [])
        self.tag_object_shas = {}
        self.tag_objects = {}
        for index, (tag, commit_sha) in enumerate(self.refs.items(), start=1):
            if tag in self.unowned_refs:
                continue
            object_sha = f"{index:040x}"
            self.tag_object_shas[tag] = object_sha
            self.tag_objects[object_sha] = {
                "tag": tag,
                "message": report._tag_message(tag),
                "object": {"type": "commit", "sha": commit_sha},
            }
        self.assets = {key: set(value) for key, value in (assets or {}).items()}
        self.calls: list[tuple] = []
        self.uploads: list[tuple[int, str, bytes]] = []
        self.fail_upload_number: int | None = None
        self.fail_create_release = False
        self.fail_delete_release: int | None = None
        self.fail_delete_tag_once: str | None = None
        self.next_release_id = max([item.get("id", 0) for item in self.releases] + [1000]) + 1
        self.next_tag_object = len(self.tag_objects) + 10_000

    @staticmethod
    def _page(path: str) -> tuple[str, int, int]:
        parsed = urlsplit(path)
        query = parse_qs(parsed.query)
        return parsed.path, int(query.get("page", [1])[0]), int(query.get("per_page", [100])[0])

    @staticmethod
    def _paginate(items: list, page: int, per_page: int) -> list:
        start = (page - 1) * per_page
        return items[start : start + per_page]

    def request_json(self, method, path, payload=None, *, expected=(200,)):
        self.calls.append((method, path, payload, expected))
        clean_path, page, per_page = self._page(path)

        if method == "GET" and clean_path.endswith("/releases"):
            return self._paginate(self.releases, page, per_page)
        if method == "GET" and clean_path.endswith("/git/matching-refs/tags/runtime-"):
            values = [
                {
                    "ref": f"refs/tags/{tag}",
                    "object": {
                        "type": "commit" if tag in self.unowned_refs else "tag",
                        "sha": sha if tag in self.unowned_refs else self.tag_object_shas[tag],
                    },
                }
                for tag, sha in self.refs.items()
            ]
            return self._paginate(values, page, per_page)
        if method == "GET" and "/git/tags/" in clean_path:
            return self.tag_objects[clean_path.rsplit("/", 1)[1]]
        if method == "GET" and "/releases/" in clean_path and clean_path.endswith("/assets"):
            release_id = int(clean_path.split("/releases/")[1].split("/")[0])
            values = [
                {"name": name, "state": "uploaded"}
                for name in sorted(self.assets.get(release_id, set()))
            ]
            return self._paginate(values, page, per_page)
        if method == "POST" and clean_path.endswith("/git/tags"):
            object_sha = f"{self.next_tag_object:040x}"
            self.next_tag_object += 1
            self.tag_objects[object_sha] = {
                "tag": payload["tag"],
                "message": payload["message"],
                "object": {"type": payload["type"], "sha": payload["object"]},
            }
            return {"sha": object_sha}
        if method == "POST" and clean_path.endswith("/git/refs"):
            tag = payload["ref"].removeprefix("refs/tags/")
            tag_object = self.tag_objects[payload["sha"]]
            self.refs[tag] = tag_object["object"]["sha"]
            self.tag_object_shas[tag] = payload["sha"]
            return {"ref": payload["ref"], "object": {"type": "tag", "sha": payload["sha"]}}
        if method == "POST" and clean_path.endswith("/releases"):
            if self.fail_create_release:
                raise report.ReportError("github_api_http_500")
            release = {
                "id": self.next_release_id,
                "tag_name": payload["tag_name"],
                "body": payload["body"],
                "draft": True,
            }
            self.next_release_id += 1
            self.releases.append(release)
            return release
        if method == "PATCH" and "/releases/" in clean_path:
            release_id = int(clean_path.rsplit("/", 1)[1])
            for release in self.releases:
                if release["id"] == release_id:
                    release["draft"] = False
                    return release
            raise AssertionError("release not found")
        if method == "DELETE" and "/releases/" in clean_path:
            release_id = int(clean_path.rsplit("/", 1)[1])
            if release_id == self.fail_delete_release:
                raise report.ReportError("github_api_http_500")
            self.releases = [item for item in self.releases if item["id"] != release_id]
            self.assets.pop(release_id, None)
            return None
        if method == "DELETE" and "/git/refs/tags/" in clean_path:
            tag = clean_path.split("/git/refs/tags/", 1)[1]
            if tag == self.fail_delete_tag_once:
                self.fail_delete_tag_once = None
                raise report.ReportError("github_api_http_500")
            self.refs.pop(tag, None)
            self.unowned_refs.discard(tag)
            self.tag_object_shas.pop(tag, None)
            return None
        raise AssertionError(f"unexpected request: {method} {path}")

    def upload_asset(self, release_id: int, name: str, path: Path):
        self.calls.append(("UPLOAD", release_id, name))
        self.uploads.append((release_id, name, path.read_bytes()))
        if self.fail_upload_number == len(self.uploads):
            raise report.ReportError("github_api_http_500")
        self.assets.setdefault(release_id, set()).add(name)
        return {"name": name, "state": "uploaded"}


def _owned_release(release_id: int, tag: str, *, draft: bool = False) -> dict:
    return {
        "id": release_id,
        "tag_name": tag,
        "body": report.OWNER_MARKER,
        "draft": draft,
    }


def _report_paths(tmp_path: Path) -> report.ReportPaths:
    output = tmp_path / "runtime-report"
    output.mkdir()
    json_path = output / "report.json"
    markdown_path = output / "report.md"
    json_path.write_text("{}\n", encoding="utf-8")
    markdown_path.write_text("# report\n", encoding="utf-8")
    return report.ReportPaths(json_path, markdown_path)


def test_build_report_drops_malicious_and_identity_fields(tmp_path):
    malicious = "</script>STEAL_TOKEN name=alice ip=203.0.113.1"
    input_dir = _write_inputs(
        tmp_path,
        {
            "started_at": "2026-11-14T12:00:00+00:00",
            "finished_at": "2026-11-14T12:30:00+00:00",
            "final_status": malicious,
            "slots": [
                {
                    "slot_index": 1,
                    "slot_alias": malicious,
                    "status": malicious,
                    "login_ok": True,
                    "same_context_login_proof_ok": True,
                    "read_ok": True,
                    "read_same_context_ok": True,
                    "security_current_device_ok": True,
                    "cookie_refresh_ok": False,
                    "new_topic_target": 3,
                    "new_topics_confirmed": 2,
                    "new_topic_target_met": False,
                    "warning_codes": ["NEW_TOPIC_TARGET_UNMET", malicious],
                    "platform": malicious,
                    "user_agent": malicious,
                    "topic_id": malicious,
                    "location": malicious,
                }
            ],
        },
        [
            {
                "ts": "2026-11-14T12:20:00+00:00",
                "slot": "slot-001",
                "level": "info",
                "step": "cookie-refresh",
                "status": "unchanged",
                "code": malicious,
                "name": malicious,
            },
            {
                "slot": "slot-001",
                "level": "warning",
                "step": malicious,
                "status": "warning",
                "code": malicious,
            },
        ],
        {
            "started_at": "2026-11-14T12:00:00+00:00",
            "finished_at": "2026-11-14T12:30:00+00:00",
            "phase": malicious,
            "slot": malicious,
            "exit_code": 0,
            "timed_out": False,
            "timeout_code": malicious,
            "child_terminated": False,
            "cookie_injection_started": True,
            "cookie_checkpoint_complete": True,
        },
    )

    built, paths = report.build_report(
        input_dir,
        tmp_path / "output" / "runtime-report",
        _env(tmp_path),
        now=NOW,
    )

    serialized = paths.json_path.read_text(encoding="utf-8") + paths.markdown_path.read_text(encoding="utf-8")
    assert malicious not in serialized
    assert "user_agent" not in serialized
    assert "topic_id" not in serialized
    assert built["slots"][0]["cookie_refresh_state"] == "unchanged"
    assert built["slots"][0]["warning_count"] == 2
    assert built["slots"][0]["device_proof_ok"] is True
    assert built["slots"][0]["status"] == "unknown"
    assert built["summary"]["final_status"] == "unknown"
    assert built["watchdog"]["phase"] == "unknown"


def test_missing_sources_still_build_unavailable_reports(tmp_path):
    env = _env(tmp_path, REPORT_STEP_OUTCOME="failure")
    input_dir = Path(env["LITEFUPZL_OUTPUT_DIR"])

    built, paths = report.build_report(
        input_dir,
        input_dir.parent / "runtime-report",
        env,
        now=NOW,
    )

    assert built["availability"] == "unavailable"
    assert built["run"]["step_outcome"] == "failure"
    assert set(built["sources"].values()) == {"missing"}
    assert paths.json_path.is_file()
    assert paths.markdown_path.is_file()
    assert paths.json_path.parent != input_dir


def test_nested_json_values_never_prevent_safe_report_generation(tmp_path):
    input_dir = _write_inputs(
        tmp_path,
        {
            "final_status": [],
            "slots": [
                {
                    "slot_index": 1,
                    "status": {},
                    "login_ok": [],
                    "read_ok": {},
                    "security_current_device_ok": [],
                    "new_topic_target": {},
                    "new_topics_confirmed": [],
                    "new_topic_target_met": {},
                    "warning_codes": [[], {}],
                }
            ],
        },
        [
            {"slot": "slot-001", "step": "cookie-refresh", "status": [], "level": {}},
            {"slot": "slot-001", "step": {}, "status": {}, "level": []},
        ],
        {
            "phase": [],
            "slot": {},
            "exit_code": [],
            "timed_out": {},
            "timeout_code": {},
        },
    )

    built, paths = report.build_report(
        input_dir,
        tmp_path / "output" / "runtime-report",
        _env(tmp_path),
        now=NOW,
    )

    assert set(built["sources"].values()) == {"available"}
    assert built["summary"]["final_status"] == "unknown"
    assert built["slots"][0]["status"] == "unknown"
    assert built["slots"][0]["cookie_refresh_state"] == "unknown"
    assert built["slots"][0]["warning_count"] == 0
    assert built["watchdog"] == {"phase": "unknown"}
    assert paths.json_path.is_file()
    assert paths.markdown_path.is_file()


def test_same_attempt_rerun_reuses_existing_release_and_timestamp_collision_is_bounded(tmp_path):
    existing_tag = _tag(NOW - timedelta(minutes=5), 12345, 2)
    client = FakeGitHubClient(
        releases=[_owned_release(42, existing_tag)],
        refs={existing_tag: SHA},
        assets={42: {"report.json", "report.md"}},
    )
    identity = report.RuntimeIdentity(client.repository, SHA, 12345, 2)

    published_tag = report.publish_report(client, identity, _report_paths(tmp_path), now=NOW)

    assert published_tag == existing_tag
    assert report.build_tag(NOW, 12345, 2) != report.build_tag(NOW, 12346, 2)
    assert not any(call[0] in {"POST", "UPLOAD", "PATCH", "DELETE"} for call in client.calls)


def test_discovery_paginates_past_one_hundred_items():
    releases = []
    refs = {}
    for index in range(101):
        tag = _tag(NOW + timedelta(seconds=index), 10_000 + index)
        releases.append(_owned_release(index + 1, tag))
        refs[tag] = SHA
    client = FakeGitHubClient(releases=releases, refs=refs)

    owned, discovered_refs = report.discover_releases_and_tags(client)

    assert len(owned) == 101
    assert len(discovered_refs) == 101
    assert any("/releases?per_page=100&page=2" in call[1] for call in client.calls)
    assert any("matching-refs/tags/runtime-?per_page=100&page=2" in call[1] for call in client.calls)


def test_retention_keeps_current_and_newest_fifteen_excluding_unowned_items():
    releases = []
    refs = {}
    owned_tags = []
    for index in range(20):
        tag = _tag(NOW + timedelta(minutes=index), 20_000 + index)
        owned_tags.append(tag)
        releases.append(_owned_release(index + 1, tag, draft=index == 3))
        refs[tag] = SHA

    unrelated_draft_tag = _tag(NOW - timedelta(days=10), 999_001)
    releases.extend(
        [
            {
                "id": 100,
                "tag_name": unrelated_draft_tag,
                "body": "user-created draft",
                "draft": True,
            },
            {"id": 101, "tag_name": "v1.0.0", "body": report.OWNER_MARKER, "draft": False},
        ]
    )
    unrelated_orphan = _tag(NOW - timedelta(days=20), 999_002)
    refs[unrelated_draft_tag] = SHA
    refs[unrelated_orphan] = SHA
    client = FakeGitHubClient(
        releases=releases,
        refs=refs,
        unowned_refs={unrelated_draft_tag, unrelated_orphan},
    )

    current_tag = owned_tags[0]
    deleted = report.cleanup_retention(client, current_tag=current_tag)

    assert len(deleted) == 5
    assert current_tag in client.refs
    assert unrelated_draft_tag in client.refs
    assert unrelated_orphan in client.refs
    assert any(item["id"] == 100 for item in client.releases)
    assert any(item["tag_name"] == "v1.0.0" for item in client.releases)
    assert owned_tags[3] not in client.refs
    assert all(tag not in client.refs for tag in deleted)


def test_unowned_release_protects_otherwise_owned_annotated_tag():
    tag = _tag(NOW - timedelta(days=30), 999_100)
    client = FakeGitHubClient(
        releases=[{"id": 501, "tag_name": tag, "body": "user release", "draft": False}],
        refs={tag: SHA},
    )

    owned, refs = report.discover_releases_and_tags(client)
    deleted = report.cleanup_retention(client, current_tag=_tag(NOW, 12345, 2))

    assert owned == []
    assert refs[tag] is None
    assert deleted == []
    assert tag in client.refs


def test_release_delete_failure_preserves_matching_tag():
    releases = []
    refs = {}
    tags = []
    for index in range(16):
        tag = _tag(NOW + timedelta(minutes=index), 30_000 + index)
        tags.append(tag)
        releases.append(_owned_release(index + 1, tag))
        refs[tag] = SHA
    stale_tag = tags[0]
    client = FakeGitHubClient(releases=releases, refs=refs)
    client.fail_delete_release = 1

    with pytest.raises(report.ReportError, match="github_api_http_500"):
        report.cleanup_retention(client, current_tag=tags[-1])

    assert stale_tag in client.refs
    release_delete_index = next(
        index
        for index, call in enumerate(client.calls)
        if call[0] == "DELETE" and call[1].endswith("/releases/1")
    )
    assert not any(
        call[0] == "DELETE" and "/git/refs/tags/" in call[1]
        for call in client.calls[release_delete_index + 1 :]
    )


def test_partial_upload_failure_does_not_publish_or_delete_old_groups(tmp_path):
    old_releases = []
    refs = {}
    for index in range(16):
        tag = _tag(NOW - timedelta(days=index + 1), 40_000 + index)
        old_releases.append(_owned_release(index + 1, tag))
        refs[tag] = SHA
    client = FakeGitHubClient(releases=old_releases, refs=refs)
    client.fail_upload_number = 2
    identity = report.RuntimeIdentity(client.repository, SHA, 12345, 2)

    with pytest.raises(report.ReportError, match="github_api_http_500"):
        report.publish_report(client, identity, _report_paths(tmp_path), now=NOW)

    assert len(client.uploads) == 2
    assert not any(call[0] == "PATCH" for call in client.calls)
    assert not any(call[0] == "DELETE" for call in client.calls)
    assert len([item for item in client.releases if report.OWNER_MARKER in item["body"]]) == 17


def test_release_create_failure_leaves_owned_tag_reused_by_retry(tmp_path):
    client = FakeGitHubClient()
    client.fail_create_release = True
    identity = report.RuntimeIdentity(client.repository, SHA, 12345, 2)
    paths = _report_paths(tmp_path)

    with pytest.raises(report.ReportError, match="github_api_http_500"):
        report.publish_report(client, identity, paths, now=NOW)

    tag = report.build_tag(NOW, identity.run_id, identity.run_attempt)
    assert client.refs[tag] == SHA
    assert not client.releases
    assert not any(call[0] == "DELETE" for call in client.calls)

    client.fail_create_release = False
    assert report.publish_report(client, identity, paths, now=NOW) == tag
    assert sum(call[0:2] == ("POST", f"/repos/{client.repository}/git/tags") for call in client.calls) == 1
    assert sum(call[0:2] == ("POST", f"/repos/{client.repository}/git/refs") for call in client.calls) == 1
    assert len(client.releases) == 1
    assert client.releases[0]["draft"] is False


def test_tag_delete_failure_is_reclaimed_after_next_successful_publish(tmp_path):
    releases = []
    refs = {}
    assets = {}
    tags = []
    for index in range(16):
        tag = _tag(NOW + timedelta(minutes=index), 50_000 + index)
        tags.append(tag)
        releases.append(_owned_release(index + 1, tag))
        refs[tag] = SHA
        assets[index + 1] = {"report.json", "report.md"}
    stale_tag, current_tag = tags[0], tags[-1]
    client = FakeGitHubClient(releases=releases, refs=refs, assets=assets)
    client.fail_delete_tag_once = stale_tag
    identity = report.RuntimeIdentity(client.repository, SHA, 50_015, 1)
    paths = _report_paths(tmp_path)

    with pytest.raises(report.ReportError, match="github_api_http_500"):
        report.publish_report(client, identity, paths, now=NOW)

    assert stale_tag in client.refs
    assert not any(item["tag_name"] == stale_tag for item in client.releases)

    assert report.publish_report(client, identity, paths, now=NOW) == current_tag
    assert stale_tag not in client.refs


def test_main_builds_reports_before_missing_token_failure(tmp_path, capsys):
    env = _env(tmp_path, RUNTIME_REPORT_TOKEN="")

    exit_code = report.main(env, now=NOW)

    assert exit_code == 1
    assert (tmp_path / "output" / "runtime-report" / "report.json").is_file()
    assert (tmp_path / "output" / "runtime-report" / "report.md").is_file()
    assert "missing_runtime_report_token" in capsys.readouterr().err


def test_github_client_uses_canonical_api_and_hides_transport_details():
    requests = []

    def failing_opener(request, timeout):
        requests.append((request, timeout))
        raise URLError("https://attacker.invalid/token=test-token")

    client = report.GitHubClient("test-token", "owner/repository", opener=failing_opener)

    with pytest.raises(report.ReportError) as exc_info:
        client.request_json("GET", "/repos/owner/repository/releases")

    assert exc_info.value.safe_code == "github_api_unavailable"
    assert str(exc_info.value) == "github_api_unavailable"
    assert requests[0][0].full_url == "https://api.github.com/repos/owner/repository/releases"
    assert requests[0][1] == report.REQUEST_TIMEOUT_SECONDS
