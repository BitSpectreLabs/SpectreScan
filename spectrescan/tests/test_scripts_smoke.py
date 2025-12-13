"""
Smoke tests for bundled scripts
by BitSpectreLabs

These tests avoid real network calls by mocking asyncio.open_connection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from spectrescan.scripts.ftp_anon import FtpAnon
from spectrescan.scripts.http_headers import HttpHeaders
from spectrescan.scripts.http_methods import HttpMethods
from spectrescan.scripts.http_title import HttpTitle
from spectrescan.scripts.mysql_info import MysqlInfo
from spectrescan.scripts.redis_info import RedisInfo
from spectrescan.scripts.smtp_commands import SmtpCommands
from spectrescan.scripts.ssh_hostkey import SshHostkey


@dataclass
class _ConnPlan:
    reads: List[bytes]


def _make_connection(plan: _ConnPlan) -> tuple[AsyncMock, MagicMock]:
    reader = AsyncMock()
    reader.read = AsyncMock(side_effect=plan.reads)

    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    return reader, writer


@pytest.mark.asyncio
async def test_http_title_non_http_service_short_circuit() -> None:
    script = HttpTitle()
    result = await script.run("example.com", port=80, service="ssh")
    assert result.success is False
    assert "Not an HTTP" in (result.output or "")


@pytest.mark.asyncio
async def test_http_title_extracts_title() -> None:
    script = HttpTitle()

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><head><title>  Hello   World </title></head></html>"
    )
    reader, writer = _make_connection(_ConnPlan(reads=[response]))

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=80, service="http")

    assert result.success is True
    assert result.data["title"] == "Hello World"
    assert "Title:" in result.output


@pytest.mark.asyncio
async def test_http_headers_parses_headers() -> None:
    script = HttpHeaders()

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx\r\n"
        b"X-Test: value\r\n\r\n"
    )
    reader, writer = _make_connection(_ConnPlan(reads=[response]))

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=80, service="http")

    assert result.success is True
    assert result.data["headers"]["Server"] == "nginx"
    assert result.data["headers"]["X-Test"] == "value"


@pytest.mark.asyncio
async def test_http_methods_detects_dangerous_methods() -> None:
    script = HttpMethods()

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Allow: GET, POST, PUT, DELETE\r\n\r\n"
    )
    reader, writer = _make_connection(_ConnPlan(reads=[response]))

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=80)

    assert result.success is True
    assert "PUT" in result.data["methods"]
    assert set(result.data["dangerous"]) >= {"PUT", "DELETE"}


@pytest.mark.asyncio
async def test_ftp_anon_allowed() -> None:
    script = FtpAnon()

    reader, writer = _make_connection(
        _ConnPlan(
            reads=[
                b"220 Welcome\r\n",
                b"331 Password required\r\n",
                b"230 Login successful\r\n",
            ]
        )
    )

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=21, service="ftp")

    assert result.success is True
    assert result.data["anonymous_allowed"] is True


@pytest.mark.asyncio
async def test_ssh_hostkey_parses_banner() -> None:
    script = SshHostkey()

    reader, writer = _make_connection(_ConnPlan(reads=[b"SSH-2.0-OpenSSH_8.9\r\n"]))

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=22, service="ssh")

    assert result.success is True
    assert result.data["protocol"] == "2.0"
    assert "OpenSSH" in result.data["software"]


@pytest.mark.asyncio
async def test_mysql_info_parses_greeting() -> None:
    script = MysqlInfo()

    # greeting[4] is protocol version, then a null-terminated version string starting at [5]
    greeting = b"\x00\x00\x00\x00" + bytes([10]) + b"8.0.33\x00extra"
    reader, writer = _make_connection(_ConnPlan(reads=[greeting]))

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=3306, service="mysql")

    assert result.success is True
    assert result.data["protocol"] == 10
    assert result.data["version"] == "8.0.33"
    assert result.data["type"] == "MySQL"


@pytest.mark.asyncio
async def test_redis_info_parses_info_and_warns_on_no_auth() -> None:
    script = RedisInfo()

    info = (
        b"# Server\r\n"
        b"redis_version:7.2.0\r\n"
        b"os:Linux\r\n"
        b"tcp_port:6379\r\n"
        b"uptime_in_days:1\r\n"
        b"requirepass:\r\n"
    )
    reader, writer = _make_connection(_ConnPlan(reads=[info]))

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=6379, service="redis")

    assert result.success is True
    assert any("No authentication" in w for w in result.data["warnings"])


@pytest.mark.asyncio
async def test_smtp_commands_parses_ehlo_and_flags_dangerous() -> None:
    script = SmtpCommands()

    reader, writer = _make_connection(
        _ConnPlan(
            reads=[
                b"220 smtp.example.com ESMTP\r\n",
                b"250-PIPELINING\r\n250-VRFY\r\n250 HELP\r\n",
                b"214-Commands supported\r\n214 End\r\n",
            ]
        )
    )

    with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(reader, writer)):
        result = await script.run("example.com", port=25, service="smtp")

    assert result.success is True
    assert any("VRFY" in cmd.upper() for cmd in result.data["commands"])
    assert result.data["dangerous"]
