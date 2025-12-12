"""
Tests for Report Templating Engine
by BitSpectreLabs
"""

import pytest
from pathlib import Path
from spectrescan.reports.templates import (
    TemplateManager,
    TemplateMetadata,
    CompanyBranding,
    TemplateValidator,
    format_bytes,
    format_duration,
    severity_color,
    port_category,
    JINJA2_AVAILABLE
)
from spectrescan.core.utils import ScanResult

# Skip all tests if Jinja2 is not available
pytestmark = pytest.mark.skipif(not JINJA2_AVAILABLE, reason="Jinja2 not installed")

@pytest.fixture
def temp_templates_dir(tmp_path):
    """Create temporary templates directory."""
    return tmp_path / "templates"

@pytest.fixture
def manager(temp_templates_dir):
    """Create TemplateManager with temp directory."""
    return TemplateManager(temp_templates_dir)

@pytest.fixture
def sample_template_content():
    """Sample template content."""
    return """# Scan Report

**Tool:** {{ tool }}
**Vendor:** {{ vendor }}

## Summary
Total Ports: {{ results|length }}
Open Ports: {{ open_ports|length }}

## Results
{% for result in open_ports %}
- {{ result.port }}/{{ result.protocol }}: {{ result.service }}
{% endfor %}
"""

@pytest.fixture
def sample_results():
    """Sample scan results."""
    return [
        ScanResult(host="192.168.1.1", port=22, state="open", service="ssh", protocol="tcp"),
        ScanResult(host="192.168.1.1", port=80, state="open", service="http", protocol="tcp"),
        ScanResult(host="192.168.1.1", port=443, state="closed", service="https", protocol="tcp"),
    ]

class TestCustomFilters:
    """Test custom Jinja2 filters."""
    
    def test_format_bytes(self):
        """Test bytes formatting."""
        assert format_bytes(500) == "500.0 B"
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1024 * 1024) == "1.0 MB"
        assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"
    
    def test_format_duration(self):
        """Test duration formatting."""
        assert format_duration(30) == "30.0s"
        assert format_duration(90) == "1m 30s"
        assert format_duration(3661) == "1h 1m"
    
    def test_severity_color(self):
        """Test severity color mapping."""
        assert severity_color("critical") == "#dc2626"
        assert severity_color("high") == "#ea580c"
        assert severity_color("medium") == "#eab308"
        assert severity_color("low") == "#16a34a"
        assert severity_color("unknown") == "#6b7280"
    
    def test_port_category(self):
        """Test port categorization."""
        assert port_category(80) == "well-known"
        assert port_category(8080) == "registered"
        assert port_category(50000) == "dynamic"

class TestTemplateMetadata:
    """Test TemplateMetadata class."""
    
    def test_creation(self):
        """Test metadata creation."""
        metadata = TemplateMetadata(
            name="test.html",
            version="1.0.0",
            author="Test Author",
            description="Test template",
            category="security",
            tags=["scan", "report"],
            format="html"
        )
        
        assert metadata.name == "test.html"
        assert metadata.version == "1.0.0"
        assert metadata.author == "Test Author"
        assert "scan" in metadata.tags
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        metadata = TemplateMetadata(
            name="test.html",
            version="1.0.0",
            author="Test",
            description="Desc",
            category="general",
            tags=["tag1"],
            format="html"
        )
        
        data = metadata.to_dict()
        assert data['name'] == "test.html"
        assert data['version'] == "1.0.0"
        assert 'created_at' in data
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            'name': 'test.html',
            'version': '1.0.0',
            'author': 'Author',
            'description': 'Desc',
            'category': 'security',
            'tags': ['tag1', 'tag2'],
            'format': 'html',
            'license': 'MIT'
        }
        
        metadata = TemplateMetadata.from_dict(data)
        assert metadata.name == 'test.html'
        assert len(metadata.tags) == 2

class TestCompanyBranding:
    """Test CompanyBranding class."""
    
    def test_creation(self):
        """Test branding creation."""
        branding = CompanyBranding(
            company_name="Test Corp",
            logo_path="/path/to/logo.png",
            contact_email="test@example.com"
        )
        
        assert branding.company_name == "Test Corp"
        assert branding.contact_email == "test@example.com"
        assert 'primary' in branding.colors
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        branding = CompanyBranding("Test Corp")
        data = branding.to_dict()
        
        assert data['company_name'] == "Test Corp"
        assert 'colors' in data
        assert 'footer_text' in data

class TestTemplateValidator:
    """Test TemplateValidator class."""
    
    def test_validate_valid_syntax(self):
        """Test validation of valid template."""
        template = "Hello {{ name }}!"
        is_valid, error = TemplateValidator.validate_syntax(template)
        
        assert is_valid is True
        assert error is None
    
    def test_validate_invalid_syntax(self):
        """Test validation of invalid template."""
        template = "Hello {{ name }!"  # Missing closing brace
        is_valid, error = TemplateValidator.validate_syntax(template)
        
        assert is_valid is False
        assert error is not None
    
    def test_extract_variables(self):
        """Test variable extraction."""
        template = """
        {{ name }}
        {{ age }}
        {{ results|length }}
        {{ name }}
        """
        
        variables = TemplateValidator.extract_variables(template)
        
        assert 'name' in variables
        assert 'age' in variables
        assert 'results' in variables
        assert len(variables) == 3  # name should appear only once
    
    def test_check_required_variables(self):
        """Test required variable checking."""
        template = "Hello {{ name }} and {{ age }}"
        
        all_present, missing = TemplateValidator.check_required_variables(
            template, ['name', 'age', 'city']
        )
        
        assert all_present is False
        assert 'city' in missing
        assert 'name' not in missing

class TestTemplateManager:
    """Test TemplateManager class."""
    
    def test_init(self, temp_templates_dir):
        """Test manager initialization."""
        manager = TemplateManager(temp_templates_dir)
        
        assert manager.templates_dir.exists()
        assert manager.marketplace_dir.exists()
    
    def test_create_template(self, manager, sample_template_content):
        """Test template creation."""
        path = manager.create_template("test.md", sample_template_content)
        
        assert path.exists()
        assert path.name == "test.md"
        assert "test.md" in manager.list_templates()
    
    def test_create_duplicate_template(self, manager, sample_template_content):
        """Test creating duplicate template."""
        manager.create_template("test.md", sample_template_content)
        
        with pytest.raises(FileExistsError):
            manager.create_template("test.md", sample_template_content, overwrite=False)
    
    def test_delete_template(self, manager, sample_template_content):
        """Test template deletion."""
        manager.create_template("test.md", sample_template_content)
        assert manager.delete_template("test.md") is True
        assert "test.md" not in manager.list_templates()
    
    def test_render_template(self, manager, sample_template_content, sample_results):
        """Test template rendering."""
        manager.create_template("test.md", sample_template_content)
        
        context = {
            'tool': 'SpectreScan',
            'vendor': 'BitSpectreLabs',
            'results': sample_results,
            'open_ports': [r for r in sample_results if r.state == 'open']
        }
        
        rendered = manager.render_template("test.md", context)
        
        assert 'SpectreScan' in rendered
        assert 'BitSpectreLabs' in rendered
        assert '22/tcp' in rendered
        assert '80/tcp' in rendered
    
    def test_validate_template(self, manager, sample_template_content):
        """Test template validation."""
        manager.create_template("test.md", sample_template_content)
        
        is_valid, error, variables = manager.validate_template("test.md")
        
        assert is_valid is True
        assert error is None
        assert 'tool' in variables
        assert 'vendor' in variables
    
    def test_metadata_operations(self, manager, sample_template_content):
        """Test metadata set and get."""
        manager.create_template("test.md", sample_template_content)
        
        metadata = TemplateMetadata(
            name="test.md",
            version="1.0.0",
            author="Test Author",
            description="Test template",
            category="security",
            tags=["scan"],
            format="markdown"
        )
        
        manager.set_metadata("test.md", metadata)
        retrieved = manager.get_metadata("test.md")
        
        assert retrieved is not None
        assert retrieved.author == "Test Author"
        assert retrieved.category == "security"
    
    def test_search_templates(self, manager, sample_template_content):
        """Test template search."""
        manager.create_template("security_report.md", sample_template_content)
        
        metadata = TemplateMetadata(
            name="security_report.md",
            version="1.0.0",
            author="Author",
            description="Security scan report",
            category="security",
            tags=["scan", "security"],
            format="markdown"
        )
        manager.set_metadata("security_report.md", metadata)
        
        # Search by query
        results = manager.search_templates(query="security")
        assert len(results) > 0
        
        # Search by category
        results = manager.search_templates(category="security")
        assert len(results) > 0
        
        # Search by tags
        results = manager.search_templates(tags=["security"])
        assert len(results) > 0
    
    def test_list_categories(self, manager, sample_template_content):
        """Test listing categories."""
        manager.create_template("test.md", sample_template_content)
        
        metadata = TemplateMetadata(
            name="test.md",
            version="1.0.0",
            author="Author",
            description="Test",
            category="security",
            tags=[],
            format="markdown"
        )
        manager.set_metadata("test.md", metadata)
        
        categories = manager.list_categories()
        assert 'security' in categories
    
    def test_add_custom_filter(self, manager):
        """Test adding custom filter."""
        def my_filter(value):
            return value.upper()
        
        manager.add_custom_filter('uppercase', my_filter)
        
        template_content = "{{ name|uppercase }}"
        manager.create_template("test.txt", template_content)
        
        context = {'name': 'hello'}
        rendered = manager.render_template("test.txt", context)
        
        assert rendered.strip() == 'HELLO'
    
    def test_export_import_template(self, manager, sample_template_content, tmp_path):
        """Test template export and import."""
        # Create template with metadata
        manager.create_template("export_test.md", sample_template_content)
        
        metadata = TemplateMetadata(
            name="export_test.md",
            version="1.0.0",
            author="Test",
            description="Export test",
            category="test",
            tags=["export"],
            format="markdown"
        )
        manager.set_metadata("export_test.md", metadata)
        
        # Export
        export_path = tmp_path / "export.zip"
        manager.export_template("export_test.md", export_path)
        assert export_path.exists()
        
        # Delete original
        manager.delete_template("export_test.md")
        assert "export_test.md" not in manager.list_templates()
        
        # Import
        imported_name = manager.import_template(export_path)
        assert imported_name == "export_test.md"
        assert "export_test.md" in manager.list_templates()
        
        # Check metadata was imported
        imported_metadata = manager.get_metadata("export_test.md")
        assert imported_metadata is not None
        assert imported_metadata.author == "Test"
