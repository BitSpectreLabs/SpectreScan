"""
Tests for Enhanced Reporting Features (Templates, Interactive HTML)
by BitSpectreLabs
"""

import pytest
from pathlib import Path
from datetime import datetime
from spectrescan.core.utils import ScanResult
from spectrescan.reports.templates import (
    TemplateManager,
    generate_custom_report,
    create_default_templates,
    JINJA2_AVAILABLE
)
from spectrescan.reports.interactive_html import generate_interactive_html_report


# Test fixtures
@pytest.fixture
def sample_results():
    """Create sample scan results."""
    return [
        ScanResult(
            host="192.168.1.1",
            port=22,
            state="open",
            service="ssh",
            banner="OpenSSH 8.0",
            protocol="tcp",
            timestamp=datetime.now()
        ),
        ScanResult(
            host="192.168.1.1",
            port=80,
            state="open",
            service="http",
            banner="Apache/2.4.41",
            protocol="tcp",
            timestamp=datetime.now()
        ),
        ScanResult(
            host="192.168.1.1",
            port=443,
            state="open",
            service="https",
            banner=None,
            protocol="tcp",
            timestamp=datetime.now()
        ),
        ScanResult(
            host="192.168.1.1",
            port=3389,
            state="filtered",
            service="rdp",
            banner=None,
            protocol="tcp",
            timestamp=datetime.now()
        ),
    ]


@pytest.fixture
def temp_templates_dir(tmp_path):
    """Create temporary templates directory."""
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    return templates_dir


# Template Manager Tests
class TestTemplateManager:
    """Test template management functionality."""
    
    def test_template_manager_init(self, temp_templates_dir):
        """Test template manager initialization."""
        manager = TemplateManager(temp_templates_dir)
        assert manager.templates_dir == temp_templates_dir
        assert temp_templates_dir.exists()
    
    @pytest.mark.skipif(not JINJA2_AVAILABLE, reason="Jinja2 not installed")
    def test_create_template(self, temp_templates_dir):
        """Test template creation."""
        manager = TemplateManager(temp_templates_dir)
        content = "Test template: {{ variable }}"
        
        path = manager.create_template("test.txt", content)
        
        assert path.exists()
        assert path.read_text() == content
    
    @pytest.mark.skipif(not JINJA2_AVAILABLE, reason="Jinja2 not installed")
    def test_create_template_overwrite(self, temp_templates_dir):
        """Test template overwrite prevention."""
        manager = TemplateManager(temp_templates_dir)
        
        manager.create_template("test.txt", "Original")
        
        with pytest.raises(FileExistsError):
            manager.create_template("test.txt", "New", overwrite=False)
        
        # But overwrite=True should work
        manager.create_template("test.txt", "New", overwrite=True)
        assert (temp_templates_dir / "test.txt").read_text() == "New"
    
    def test_list_templates(self, temp_templates_dir):
        """Test listing templates."""
        manager = TemplateManager(temp_templates_dir)
        
        (temp_templates_dir / "template1.html").write_text("test")
        (temp_templates_dir / "template2.txt").write_text("test")
        (temp_templates_dir / "template3.md").write_text("test")
        (temp_templates_dir / "ignore.jpg").write_text("test")  # Should be ignored
        
        templates = manager.list_templates()
        
        assert len(templates) == 3
        assert "template1.html" in templates
        assert "template2.txt" in templates
        assert "template3.md" in templates
        assert "ignore.jpg" not in templates
    
    def test_delete_template(self, temp_templates_dir):
        """Test template deletion."""
        manager = TemplateManager(temp_templates_dir)
        
        template_path = temp_templates_dir / "test.txt"
        template_path.write_text("test")
        
        assert manager.delete_template("test.txt")
        assert not template_path.exists()
        assert not manager.delete_template("nonexistent.txt")
    
    def test_get_template_path(self, temp_templates_dir):
        """Test getting template path."""
        manager = TemplateManager(temp_templates_dir)
        
        template_path = temp_templates_dir / "test.txt"
        template_path.write_text("test")
        
        path = manager.get_template_path("test.txt")
        assert path == template_path
        
        assert manager.get_template_path("nonexistent.txt") is None
    
    @pytest.mark.skipif(not JINJA2_AVAILABLE, reason="Jinja2 not installed")
    def test_render_template(self, temp_templates_dir):
        """Test template rendering."""
        manager = TemplateManager(temp_templates_dir)
        
        template_content = "Hello {{ name }}! Count: {{ count }}"
        manager.create_template("greeting.txt", template_content)
        
        result = manager.render_template("greeting.txt", {"name": "Alice", "count": 5})
        
        assert result == "Hello Alice! Count: 5"
    
    @pytest.mark.skipif(not JINJA2_AVAILABLE, reason="Jinja2 not installed")
    def test_render_from_string(self, temp_templates_dir):
        """Test rendering from string."""
        manager = TemplateManager(temp_templates_dir)
        
        template = "Result: {{ value * 2 }}"
        result = manager.render_from_string(template, {"value": 10})
        
        assert result == "Result: 20"
    
    def test_render_without_jinja2(self, temp_templates_dir, monkeypatch):
        """Test graceful handling when Jinja2 not available."""
        manager = TemplateManager(temp_templates_dir)
        
        # Temporarily make JINJA2 unavailable
        import spectrescan.reports.templates as templates_module
        original_value = templates_module.JINJA2_AVAILABLE
        templates_module.JINJA2_AVAILABLE = False
        manager.env = None
        
        with pytest.raises(ImportError, match="Jinja2 is required"):
            manager.render_from_string("test", {})
        
        # Restore
        templates_module.JINJA2_AVAILABLE = original_value


class TestCustomReportGeneration:
    """Test custom report generation."""
    
    @pytest.mark.skipif(not JINJA2_AVAILABLE, reason="Jinja2 not installed")
    def test_generate_custom_report(self, sample_results, temp_templates_dir, tmp_path):
        """Test generating custom report from template."""
        manager = TemplateManager(temp_templates_dir)
        
        template = """Scan Report
Total: {{ results|length }}
Open: {{ open_ports|length }}
"""
        manager.create_template("report.txt", template)
        
        output = tmp_path / "output.txt"
        generate_custom_report(
            sample_results,
            "report.txt",
            output,
            templates_dir=temp_templates_dir
        )
        
        assert output.exists()
        content = output.read_text()
        assert "Total: 4" in content
        assert "Open: 3" in content
    
    def test_create_default_templates(self, temp_templates_dir):
        """Test creating default template examples."""
        create_default_templates(temp_templates_dir)
        
        manager = TemplateManager(temp_templates_dir)
        templates = manager.list_templates()
        
        assert "simple_text.txt" in templates
        assert "markdown_report.md" in templates
        assert "custom_xml.xml" in templates


# Interactive HTML Tests
class TestInteractiveHTML:
    """Test interactive HTML report generation."""
    
    def test_generate_interactive_html(self, sample_results, tmp_path):
        """Test generating interactive HTML report."""
        output = tmp_path / "report.html"
        
        generate_interactive_html_report(
            sample_results,
            output,
            summary={"total_scanned": 100, "scan_time": "5.2"}
        )
        
        assert output.exists()
        content = output.read_text(encoding='utf-8')
        
        # Check for key features
        assert "SpectreScan Interactive Report" in content
        assert "searchBox" in content  # Search functionality
        assert "filter-btn" in content  # Filter buttons
        assert "themeToggle" in content  # Dark mode toggle
        assert "192.168.1.1" in content  # Host
        assert "port=22" in content or "22</td>" in content  # Port
        assert "OpenSSH" in content  # Banner
    
    def test_interactive_html_features(self, sample_results, tmp_path):
        """Test that interactive features are present."""
        output = tmp_path / "report.html"
        
        generate_interactive_html_report(sample_results, output)
        
        content = output.read_text(encoding='utf-8')
        
        # Check JavaScript functions
        assert "function filterResults()" in content
        assert "function toggleDetails(" in content
        assert "function copyToClipboard(" in content
        
        # Check sorting
        assert "data-sort=" in content
        
        # Check state badges
        assert "state-open" in content
        assert "state-filtered" in content
        
        # Check stats display
        assert "Open: (3)" in content or "Open (3)" in content
    
    def test_interactive_html_with_empty_results(self, tmp_path):
        """Test generating report with no results."""
        output = tmp_path / "report.html"
        
        generate_interactive_html_report([], output)
        
        assert output.exists()
        content = output.read_text(encoding='utf-8')
        
        assert "SpectreScan Interactive Report" in content
        assert "All (0)" in content
