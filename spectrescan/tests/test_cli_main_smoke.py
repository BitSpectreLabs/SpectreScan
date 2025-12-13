"""
Tests for CLI main module smoke coverage
by BitSpectreLabs
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest
from typer.testing import CliRunner

import spectrescan.cli.main as cli
from spectrescan.core.utils import ScanResult


class _FakePortScanner:
    """Deterministic fake PortScanner for CLI tests."""

    def __init__(
        self,
        config,
        proxy=None,
        proxy_pool=None,
        evasion=None,
    ) -> None:
        self.config = config
        self.proxy = proxy
        self.proxy_pool = proxy_pool
        self.evasion = evasion
        self.host_info = {}

        self._open_results = [
            ScanResult(
                host="127.0.0.1",
                port=80,
                state="open",
                service="http",
                banner="hello",
                protocol="tcp",
            )
        ]

    def scan(self, target: str, callback=None):
        if callback is not None:
            for result in self._open_results:
                callback(result)
        return list(self._open_results)

    def get_scan_summary(self) -> dict:
        return {
            "total_ports": len(getattr(self.config, "ports", [])),
            "open_ports": len(self._open_results),
            "closed_ports": 0,
            "filtered_ports": 0,
            "scan_duration": "0.0s",
        }

    def get_open_ports(self, host: Optional[str] = None):
        return list(self._open_results)


@pytest.fixture()
def runner() -> CliRunner:
    """Typer test runner."""

    return CliRunner()


def _result_output(result) -> str:
    """Get output from a Typer/CliRunner result across Click versions."""

    return getattr(result, "stdout", None) or getattr(result, "output", "")


@pytest.fixture()
def fake_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch CLI module to use fake PortScanner."""

    monkeypatch.setattr(cli, "PortScanner", _FakePortScanner)


class TestCLIMainSmoke:
    """CLI smoke tests for coverage."""

    def test_version_command(self, runner: CliRunner) -> None:
        """Version command prints without error."""

        result = runner.invoke(cli.app, ["version"])
        assert result.exit_code == 0
        assert "SpectreScan" in _result_output(result)

    def test_presets_command(self, runner: CliRunner) -> None:
        """Presets command prints without error."""

        result = runner.invoke(cli.app, ["presets"])
        assert result.exit_code == 0

    def test_completion_bash_outputs_script(self, runner: CliRunner) -> None:
        """Completion command can generate a script."""

        result = runner.invoke(cli.app, ["completion", "bash"])
        assert result.exit_code == 0
        out = _result_output(result)
        assert "_spectrescan" in out or "spectrescan" in out

    def test_scan_missing_target_errors(self, runner: CliRunner, fake_scanner: None) -> None:
        """Scan requires either target or --target-file."""

        result = runner.invoke(cli.app, ["scan"])
        assert result.exit_code != 0
        assert "Either target" in _result_output(result)

    def test_scan_target_and_target_file_errors(
        self, runner: CliRunner, fake_scanner: None, tmp_path: Path
    ) -> None:
        """Scan rejects specifying both target and --target-file."""

        target_file = tmp_path / "targets.txt"
        target_file.write_text("127.0.0.1\n", encoding="utf-8")

        result = runner.invoke(
            cli.app,
            ["scan", "127.0.0.1", "--target-file", str(target_file), "--quick"],
        )
        assert result.exit_code != 0
        assert "Cannot specify both" in _result_output(result)

    def test_scan_invalid_ports_errors(self, runner: CliRunner, fake_scanner: None) -> None:
        """Invalid port specs produce a friendly error."""

        result = runner.invoke(cli.app, ["scan", "127.0.0.1", "--ports", "nope"])
        assert result.exit_code != 0

    def test_scan_with_target_file_quiet(self, runner: CliRunner, fake_scanner: None, tmp_path: Path) -> None:
        """Scan accepts --target-file and can run in quiet mode."""

        target_file = tmp_path / "targets.txt"
        target_file.write_text("127.0.0.1\n", encoding="utf-8")

        result = runner.invoke(cli.app, ["scan", "--target-file", str(target_file), "--quick", "--quiet"])
        assert result.exit_code == 0

    def test_scan_with_reports_written(
        self, runner: CliRunner, fake_scanner: None, tmp_path: Path
    ) -> None:
        """Scan can write multiple report formats."""

        json_out = tmp_path / "out.json"
        csv_out = tmp_path / "out.csv"
        xml_out = tmp_path / "out.xml"

        result = runner.invoke(
            cli.app,
            [
                "scan",
                "127.0.0.1",
                "--quick",
                "--tcp",
                "--timeout",
                "0.1",
                "--json",
                str(json_out),
                "--csv",
                str(csv_out),
                "--xml",
                str(xml_out),
            ],
        )
        assert result.exit_code == 0
        assert json_out.exists()
        assert csv_out.exists()
        assert xml_out.exists()

    def test_main_injects_scan_for_target_like_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """main() injects the scan command for target-like args."""

        called = {"argv": None}

        def _fake_app() -> None:
            called["argv"] = list(cli.sys.argv)

        monkeypatch.setattr(cli, "app", _fake_app)
        monkeypatch.setattr(cli.sys, "argv", ["spectrescan", "127.0.0.1", "--quick"])

        cli.main()

        assert called["argv"] is not None
        assert called["argv"][1] == "scan"
