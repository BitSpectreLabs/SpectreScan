"""
Additional CLI smoke tests for subcommand modules
by BitSpectreLabs

These tests call command functions directly with monkeypatched backends to
avoid filesystem and network access.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import pytest
import click


class _FakeVulnDB:
    def __init__(self) -> None:
        self._vulns: List[object] = []
        self.db_path = Path("C:/fake/vulndb.sqlite")

    def get_all_vulnerabilities(self):
        return list(self._vulns)

    def search_vulnerabilities(self, query: str):
        return []

    def add_vulnerability(self, vuln):
        self._vulns.append(vuln)
        return True

    def import_from_json(self, path: Path) -> int:
        return 2

    def import_from_csv(self, path: Path) -> int:
        return 3

    def export_to_json(self, path: Path) -> bool:
        return True

    def delete_vulnerability(self, vuln_id: str) -> bool:
        return False


@dataclass
class _FakeTemplateMetadata:
    name: str = "t.html"
    version: str = "1.0.0"
    author: str = "Unknown"
    description: str = "No description"
    category: str = "general"
    tags: List[str] = None
    format: str = "html"
    license: str = "MIT"


class _FakeTemplateManager:
    def __init__(self) -> None:
        self.templates_dir = Path("C:/fake/templates")
        self._templates: List[str] = []

    def list_templates(self) -> List[str]:
        return list(self._templates)

    def search_templates(self, category=None, tags=None):
        if category == "security":
            return [("sec.html", _FakeTemplateMetadata(category="security"))]
        return []

    def get_template_path(self, name: str) -> Optional[Path]:
        return None

    def get_metadata(self, name: str):
        return None

    def validate_template(self, name: str):
        return False, "missing", []

    def create_template(self, name: str, content: str, overwrite: bool = False):
        self._templates.append(name)
        return self.templates_dir / name

    def set_metadata(self, name: str, metadata):
        return None

    def delete_template(self, name: str) -> bool:
        return False

    def export_template(self, name: str, output: Path):
        raise FileNotFoundError("not found")

    def import_template(self, file: Path) -> str:
        raise ValueError("bad zip")

    def list_categories(self):
        return ["general", "security"]


def test_vulndb_list_empty(monkeypatch) -> None:
    from spectrescan.cli import vulndb_commands

    monkeypatch.setattr(vulndb_commands, "get_db", lambda: _FakeVulnDB())

    # Should not raise when database is empty
    vulndb_commands.list_vulns(limit=10, show_all=False)


def test_vulndb_import_unsupported(monkeypatch, tmp_path: Path) -> None:
    from spectrescan.cli import vulndb_commands

    monkeypatch.setattr(vulndb_commands, "get_db", lambda: _FakeVulnDB())

    p = tmp_path / "vulns.txt"
    p.write_text("nope", encoding="utf-8")

    vulndb_commands.import_vulns(file=p)


def test_vulndb_add_and_delete(monkeypatch) -> None:
    from spectrescan.cli import vulndb_commands

    db = _FakeVulnDB()
    monkeypatch.setattr(vulndb_commands, "get_db", lambda: db)

    vulndb_commands.add_vuln(
        id="CVE-2025-0001",
        title="Example",
        description="Desc",
        severity="High",
        cvss=7.5,
        product="Apache.*",
        version="< 2.4.50",
        remediation="Update",
        refs="https://example.com",
    )
    assert db.get_all_vulnerabilities()

    vulndb_commands.delete_vuln("CVE-2025-0001")


def test_template_list_no_templates(monkeypatch) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    template_commands.list_templates(category=None, tags=None)


def test_template_list_with_filters(monkeypatch) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    template_commands.list_templates(category="security", tags=None)


def test_template_create_requires_content_or_file(monkeypatch) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    with pytest.raises(click.exceptions.Exit):
        template_commands.create_template(
            name="x.html",
            file=None,
            content=None,
            version="1.0.0",
            author="",
            description="",
            category="general",
            tags="",
            format="html",
        )


def test_template_create_happy_path(monkeypatch) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()

    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)
    monkeypatch.setattr(template_commands.TemplateValidator, "validate_syntax", lambda _: (True, None))
    monkeypatch.setattr(template_commands, "TemplateMetadata", _FakeTemplateMetadata)

    template_commands.create_template(
        name="x.html",
        file=None,
        content="Hello {{ tool }}",
        version="1.2.3",
        author="Me",
        description="D",
        category="security",
        tags="a,b",
        format="html",
    )

    assert "x.html" in manager.list_templates()


def test_template_info_missing_template(monkeypatch) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    with pytest.raises(click.exceptions.Exit):
        template_commands.template_info("missing")


def test_template_validate_invalid(monkeypatch) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    with pytest.raises(click.exceptions.Exit):
        template_commands.validate_template("bad")


def test_template_export_missing(monkeypatch, tmp_path: Path) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    with pytest.raises(click.exceptions.Exit):
        template_commands.export_template("missing", tmp_path / "out.zip")


def test_template_import_failure(monkeypatch, tmp_path: Path) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    f = tmp_path / "t.zip"
    f.write_bytes(b"not a zip")

    with pytest.raises(click.exceptions.Exit):
        template_commands.import_template(f)


def test_template_categories(monkeypatch) -> None:
    from spectrescan.cli import template_commands

    manager = _FakeTemplateManager()
    monkeypatch.setattr(template_commands, "get_manager", lambda: manager)

    template_commands.list_categories()


def test_perf_profile_and_gc(monkeypatch) -> None:
    from spectrescan.cli import perf_commands

    class _FakeProfiler:
        @staticmethod
        def reset() -> None:
            return None

        @staticmethod
        def get_results():
            return []

    class _FakeGCOptimizer:
        @staticmethod
        def collect() -> int:
            return 123

        @staticmethod
        def tune_for_throughput() -> None:
            return None

        @staticmethod
        def tune_for_latency() -> None:
            return None

        @staticmethod
        def get_stats():
            return {
                "enabled": True,
                "threshold": (700, 10, 10),
                "counts": (1, 2, 3),
                "objects_tracked": 42,
            }

    monkeypatch.setattr("spectrescan.core.performance.Profiler", _FakeProfiler)
    monkeypatch.setattr("spectrescan.core.performance.GCOptimizer", _FakeGCOptimizer)

    perf_commands.show_profile(reset=True, top=10)
    perf_commands.show_profile(reset=False, top=10)

    # Exercise unknown tune branch and stats output
    perf_commands.gc_command(collect=True, tune="unknown", stats=False)


def test_perf_memory_stats(monkeypatch) -> None:
    from spectrescan.cli import perf_commands

    @dataclass
    class _MemStats:
        rss_mb: float = 1.0
        vms_mb: float = 2.0
        percent: float = 3.0
        available_mb: float = 4.0

    class _FakeMemoryMonitor:
        def get_memory_usage(self):
            return _MemStats()

        def get_memory_summary(self):
            return "ok"

    monkeypatch.setattr("spectrescan.core.memory_optimizer.MemoryMonitor", _FakeMemoryMonitor)

    perf_commands.memory_stats()
