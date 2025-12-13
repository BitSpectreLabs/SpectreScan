"""
Tests for SpectreScan module entrypoints
by BitSpectreLabs
"""

from __future__ import annotations

import runpy


def test_python_m_spectrescan_invokes_cli_app(monkeypatch) -> None:
    import spectrescan.cli.main as cli_main

    called = {"count": 0}

    def _fake_app(*_args, **_kwargs):
        called["count"] += 1

    monkeypatch.setattr(cli_main, "app", _fake_app)

    runpy.run_module("spectrescan", run_name="__main__")

    assert called["count"] == 1
