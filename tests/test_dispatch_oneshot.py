from contextlib import contextmanager
import json
import urllib.error

import pytest

from apps.litefupzl import dispatch_oneshot as scheduler


@contextmanager
def _response(status=204):
    class Response:
        pass
    response = Response()
    response.status = status
    yield response


def test_dispatch_targets_current_fork_ref_and_repository_cookie_policy():
    calls = []

    def opener(request, timeout):
        calls.append((request, timeout))
        return _response()

    scheduler.dispatch_oneshot(
        repository="someone/my-fork", ref="custom-default", token="fake-pat", opener=opener
    )
    request, timeout = calls[0]
    assert request.full_url == "https://api.github.com/repos/someone/my-fork/actions/workflows/oneshot.yml/dispatches"
    assert request.method == "POST"
    assert json.loads(request.data) == {
        "ref": "custom-default", "inputs": {"cookie_refresh_enabled": "configured"}
    }
    assert request.get_header("Authorization") == "Bearer fake-pat"
    assert timeout == 30


def test_scheduler_reports_only_http_status_and_does_not_retry(monkeypatch, capsys):
    calls = []
    monkeypatch.setenv("SCHEDULER_TOKEN", "sensitive-pat")
    monkeypatch.setenv("GITHUB_REPOSITORY", "someone/fork")
    monkeypatch.setenv("ONESHOT_REF", "main")

    def fail(request, **kwargs):
        calls.append(request)
        raise urllib.error.HTTPError(request.full_url, 403, "sensitive-pat", {}, None)

    monkeypatch.setattr(scheduler, "_open_request", fail)
    assert scheduler.main() == 1
    assert len(calls) == 1
    assert "sensitive-pat" not in capsys.readouterr().out
    assert "SCHEDULER_TOKEN" not in scheduler.os.environ


def test_scheduler_missing_pat_fails_without_api_call(monkeypatch):
    monkeypatch.delenv("SCHEDULER_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", "someone/fork")
    monkeypatch.setenv("ONESHOT_REF", "main")
    monkeypatch.setattr(scheduler, "_open_request", lambda *a, **k: pytest.fail("API called"))
    assert scheduler.main() == 1


def test_dispatch_rejects_http_redirect_instead_of_forwarding_pat():
    handler = scheduler._RejectRedirect()
    assert handler.redirect_request(None, None, 302, "", {}, "https://untrusted.invalid") is None
