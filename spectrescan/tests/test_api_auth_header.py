"""
Unit tests for API auth header parsing
by BitSpectreLabs

Focuses on spectrescan.api.main.get_api_key_header and scope guards.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from spectrescan.api.auth import APIKey, TokenPayload


@pytest.mark.asyncio
async def test_get_api_key_header_accepts_bearer_token(monkeypatch) -> None:
    from spectrescan.api import main as api_main

    payload = TokenPayload(
        sub="user1",
        scopes=["scan:read"],
        exp=int(time.time()) + 3600,
        iat=int(time.time()),
        jti="jti",
    )

    monkeypatch.setattr(api_main, "get_current_user", lambda token: payload)

    got = await api_main.get_api_key_header(x_api_key=None, authorization="Bearer abc")
    assert got.sub == "user1"


@pytest.mark.asyncio
async def test_get_api_key_header_rejects_invalid_bearer(monkeypatch) -> None:
    from spectrescan.api import main as api_main

    monkeypatch.setattr(api_main, "get_current_user", lambda token: None)

    with pytest.raises(Exception) as excinfo:
        await api_main.get_api_key_header(x_api_key=None, authorization="Bearer bad")

    # fastapi.HTTPException derives from Exception; keep assertion simple
    assert "Invalid" in str(excinfo.value) or "expired" in str(excinfo.value)


@pytest.mark.asyncio
async def test_get_api_key_header_accepts_api_key(monkeypatch) -> None:
    from spectrescan.api import main as api_main

    api_key = APIKey(
        key_id="key1",
        key_hash="hash",
        name="n",
        scopes=["scan:read", "scan:write"],
    )

    monkeypatch.setattr(api_main, "verify_api_key", lambda key: api_key)

    got = await api_main.get_api_key_header(x_api_key="ss_x", authorization=None)
    assert got.sub == "key1"
    assert "scan:read" in got.scopes


@pytest.mark.asyncio
async def test_get_api_key_header_rejects_missing_auth(monkeypatch) -> None:
    from spectrescan.api import main as api_main

    # Ensure API key verification doesn't accidentally pass
    monkeypatch.setattr(api_main, "verify_api_key", lambda key: None)

    with pytest.raises(Exception) as excinfo:
        await api_main.get_api_key_header(x_api_key=None, authorization=None)

    assert "Missing authentication" in str(excinfo.value)


def test_require_scope_helpers(monkeypatch) -> None:
    from spectrescan.api import main as api_main

    payload = TokenPayload(sub="s", scopes=["scan:read"], exp=9999999999, iat=0, jti="j")

    # Force require_scope behavior for these guards
    monkeypatch.setattr(api_main, "require_scope", lambda p, scope: scope == "scan:read")

    assert api_main.require_scan_read(payload) is payload

    with pytest.raises(Exception):
        api_main.require_scan_write(payload)
