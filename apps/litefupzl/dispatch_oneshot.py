"""Dispatch the fork's oneshot without exposing the existing administration PAT."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the administration PAT to a redirected endpoint.
        return None


def _open_request(request, *, timeout):
    return urllib.request.build_opener(_RejectRedirect()).open(request, timeout=timeout)


def dispatch_oneshot(*, repository: str, ref: str, token: str, opener=None) -> None:
    """Submit once; an ambiguous network failure must not duplicate an auth session."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid_repository")
    if not ref or len(ref) > 255 or any(ord(char) < 32 for char in ref):
        raise ValueError("invalid_ref")
    if not token or any(char.isspace() for char in token):
        raise ValueError("missing_or_invalid_token")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/actions/workflows/oneshot.yml/dispatches",
        data=json.dumps({
            "ref": ref,
            "inputs": {"cookie_refresh_enabled": "configured"},
        }).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "litefupzl-scheduler",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    open_request = opener or _open_request
    with open_request(request, timeout=30) as response:
        if response.status != 204:
            raise ValueError("unexpected_dispatch_status")


def main() -> int:
    token = os.environ.pop("SCHEDULER_TOKEN", "").strip()
    try:
        dispatch_oneshot(
            repository=os.environ.get("GITHUB_REPOSITORY", ""),
            ref=os.environ.get("ONESHOT_REF", ""),
            token=token,
        )
    except urllib.error.HTTPError as exc:
        print(f"::error::oneshot_dispatch_failed=HTTP_{exc.code}")
        return 1
    except Exception:
        # Neither exception messages nor response bodies are public-safe.
        print("::error::oneshot_dispatch_failed=CONFIG_OR_TRANSPORT_ERROR")
        return 1
    print("oneshot_dispatch=accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
