"""
Custom Report Templates for SpectreScan
by BitSpectreLabs

Enhanced templating engine with company branding, custom filters,
template validation, and marketplace support.
"""

from typing import List, Dict, Optional, Any, Callable
from pathlib import Path
from datetime import datetime
import re
import hashlib
import json
from spectrescan.core.utils import ScanResult, HostInfo

try:
    from jinja2 import Environment, FileSystemLoader, Template, TemplateNotFound, TemplateSyntaxError
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


# Custom Jinja2 filters
def format_bytes(value: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format seconds to human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def severity_color(severity: str) -> str:
    """Get color code for severity level."""
    colors = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#eab308',
        'low': '#16a34a',
        'info': '#0284c7'
    }
    return colors.get(severity.lower(), '#6b7280')


def port_category(port: int) -> str:
    """Categorize port by range."""
    if port < 1024:
        return 'well-known'
    elif port < 49152:
        return 'registered'
    else:
        return 'dynamic'


class TemplateMetadata:
    """Metadata for template marketplace."""
    
    def __init__(
        self,
        name: str,
        version: str,
        author: str,
        description: str,
        category: str,
        tags: List[str],
        format: str,
        license: str = "MIT"
    ):
        self.name = name
        self.version = version
        self.author = author
        self.description = description
        self.category = category
        self.tags = tags
        self.format = format
        self.license = license
        self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'version': self.version,
            'author': self.author,
            'description': self.description,
            'category': self.category,
            'tags': self.tags,
            'format': self.format,
            'license': self.license,
            'created_at': self.created_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TemplateMetadata':
        """Create from dictionary."""
        return cls(
            name=data['name'],
            version=data['version'],
            author=data['author'],
            description=data['description'],
            category=data['category'],
            tags=data['tags'],
            format=data['format'],
            license=data.get('license', 'MIT')
        )


class CompanyBranding:
    """Company branding configuration."""
    
    def __init__(
        self,
        company_name: str,
        logo_path: Optional[str] = None,
        colors: Optional[Dict[str, str]] = None,
        footer_text: Optional[str] = None,
        contact_email: Optional[str] = None,
        website: Optional[str] = None
    ):
        self.company_name = company_name
        self.logo_path = logo_path
        self.colors = colors or {
            'primary': '#3b82f6',
            'secondary': '#8b5cf6',
            'accent': '#06b6d4'
        }
        self.footer_text = footer_text or f"© {datetime.now().year} {company_name}"
        self.contact_email = contact_email
        self.website = website
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for template context."""
        return {
            'company_name': self.company_name,
            'logo_path': self.logo_path,
            'colors': self.colors,
            'footer_text': self.footer_text,
            'contact_email': self.contact_email,
            'website': self.website
        }


class TemplateValidator:
    """Validate template syntax and required variables."""
    
    @staticmethod
    def validate_syntax(template_string: str) -> tuple[bool, Optional[str]]:
        """
        Validate Jinja2 template syntax.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not JINJA2_AVAILABLE:
            return False, "Jinja2 is not installed"
        
        try:
            Template(template_string)
            return True, None
        except TemplateSyntaxError as e:
            return False, f"Syntax error at line {e.lineno}: {e.message}"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def extract_variables(template_string: str) -> List[str]:
        """Extract all variables used in template."""
        # Simple regex to find {{ variable }} patterns
        pattern = r'\{\{\s*(\w+(?:\.\w+)*)\s*(?:\|[^}]*)?\}\}'
        matches = re.findall(pattern, template_string)
        # Remove duplicates and sort
        return sorted(set(matches))
    
    @staticmethod
    def check_required_variables(
        template_string: str,
        required_vars: List[str]
    ) -> tuple[bool, List[str]]:
        """
        Check if template contains required variables.
        
        Returns:
            Tuple of (all_present, missing_variables)
        """
        used_vars = set(TemplateValidator.extract_variables(template_string))
        missing = [var for var in required_vars if var not in used_vars]
        return len(missing) == 0, missing


class TemplateManager:
    """Manage custom report templates with enhanced features."""
    
    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        branding: Optional[CompanyBranding] = None
    ):
        """
        Initialize template manager.
        
        Args:
            templates_dir: Directory containing custom templates
            branding: Company branding configuration
        """
        if templates_dir is None:
            templates_dir = Path.home() / ".spectrescan" / "templates"
        
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # Marketplace directory
        self.marketplace_dir = self.templates_dir / "marketplace"
        self.marketplace_dir.mkdir(exist_ok=True)
        
        # Metadata file
        self.metadata_file = self.templates_dir / "metadata.json"
        
        self.branding = branding or CompanyBranding("BitSpectreLabs")
        
        if JINJA2_AVAILABLE:
            self.env = Environment(
                loader=FileSystemLoader(str(self.templates_dir)),
                autoescape=True
            )
            # Register custom filters
            self.env.filters['format_bytes'] = format_bytes
            self.env.filters['format_duration'] = format_duration
            self.env.filters['severity_color'] = severity_color
            self.env.filters['port_category'] = port_category
        else:
            self.env = None
    
    def add_custom_filter(self, name: str, func: Callable) -> None:
        """
        Add custom Jinja2 filter.
        
        Args:
            name: Filter name
            func: Filter function
        """
        if JINJA2_AVAILABLE and self.env:
            self.env.filters[name] = func
    
    def render_template(
        self,
        template_name: str,
        context: Dict[str, Any],
        validate: bool = False
    ) -> str:
        """
        Render a template with given context.
        
        Args:
            template_name: Name of template file
            context: Dictionary of template variables
            validate: Whether to validate template before rendering
            
        Returns:
            Rendered template as string
            
        Raises:
            ImportError: If Jinja2 is not installed
            TemplateNotFound: If template doesn't exist
            ValueError: If validation fails
        """
        if not JINJA2_AVAILABLE:
            raise ImportError(
                "Jinja2 is required for custom templates. "
                "Install it with: pip install jinja2"
            )
        
        # Add branding to context
        context['branding'] = self.branding.to_dict()
        
        # Validate if requested
        if validate:
            template_path = self.templates_dir / template_name
            if template_path.exists():
                content = template_path.read_text(encoding='utf-8')
                is_valid, error = TemplateValidator.validate_syntax(content)
                if not is_valid:
                    raise ValueError(f"Template validation failed: {error}")
        
        template = self.env.get_template(template_name)
        return template.render(**context)
    
    def render_from_string(
        self,
        template_string: str,
        context: Dict[str, Any]
    ) -> str:
        """
        Render a template from string.
        
        Args:
            template_string: Template content as string
            context: Dictionary of template variables
            
        Returns:
            Rendered template as string
        """
        if not JINJA2_AVAILABLE:
            raise ImportError(
                "Jinja2 is required for custom templates. "
                "Install it with: pip install jinja2"
            )
        
        template = Template(template_string)
        return template.render(**context)
    
    def list_templates(self) -> List[str]:
        """
        List all available templates.
        
        Returns:
            List of template filenames
        """
        if not self.templates_dir.exists():
            return []
        
        return [
            f.name for f in self.templates_dir.iterdir()
            if f.is_file() and (f.suffix in ['.html', '.txt', '.md', '.xml'])
        ]
    
    def create_template(
        self,
        name: str,
        content: str,
        overwrite: bool = False
    ) -> Path:
        """
        Create a new template file.
        
        Args:
            name: Template filename
            content: Template content
            overwrite: Whether to overwrite existing template
            
        Returns:
            Path to created template
            
        Raises:
            FileExistsError: If template exists and overwrite=False
        """
        template_path = self.templates_dir / name
        
        if template_path.exists() and not overwrite:
            raise FileExistsError(f"Template '{name}' already exists")
        
        template_path.write_text(content, encoding='utf-8')
        return template_path
    
    def delete_template(self, name: str) -> bool:
        """
        Delete a template file.
        
        Args:
            name: Template filename
            
        Returns:
            True if deleted, False if not found
        """
        template_path = self.templates_dir / name
        
        if template_path.exists():
            template_path.unlink()
            return True
        
        return False
    
    def get_template_path(self, name: str) -> Optional[Path]:
        """
        Get path to template file.
        
        Args:
            name: Template filename
            
        Returns:
            Path to template or None if not found
        """
        template_path = self.templates_dir / name
        return template_path if template_path.exists() else None
    
    def validate_template(self, name: str) -> tuple[bool, Optional[str], List[str]]:
        """
        Validate template syntax and extract variables.
        
        Args:
            name: Template filename
            
        Returns:
            Tuple of (is_valid, error_message, used_variables)
        """
        template_path = self.get_template_path(name)
        if not template_path:
            return False, f"Template '{name}' not found", []
        
        content = template_path.read_text(encoding='utf-8')
        is_valid, error = TemplateValidator.validate_syntax(content)
        variables = TemplateValidator.extract_variables(content) if is_valid else []
        
        return is_valid, error, variables
    
    def get_metadata(self, name: str) -> Optional[TemplateMetadata]:
        """
        Get template metadata.
        
        Args:
            name: Template filename
            
        Returns:
            Template metadata or None if not found
        """
        if not self.metadata_file.exists():
            return None
        
        try:
            metadata_dict = json.loads(self.metadata_file.read_text(encoding='utf-8'))
            if name in metadata_dict:
                return TemplateMetadata.from_dict(metadata_dict[name])
        except Exception:
            pass
        
        return None
    
    def set_metadata(self, name: str, metadata: TemplateMetadata) -> None:
        """
        Set template metadata.
        
        Args:
            name: Template filename
            metadata: Template metadata
        """
        metadata_dict = {}
        if self.metadata_file.exists():
            try:
                metadata_dict = json.loads(self.metadata_file.read_text(encoding='utf-8'))
            except Exception:
                pass
        
        metadata_dict[name] = metadata.to_dict()
        self.metadata_file.write_text(
            json.dumps(metadata_dict, indent=2),
            encoding='utf-8'
        )
    
    def list_categories(self) -> List[str]:
        """List all template categories."""
        categories = set()
        if self.metadata_file.exists():
            try:
                metadata_dict = json.loads(self.metadata_file.read_text(encoding='utf-8'))
                for data in metadata_dict.values():
                    categories.add(data.get('category', 'general'))
            except Exception:
                pass
        return sorted(categories)
    
    def search_templates(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> List[tuple[str, TemplateMetadata]]:
        """
        Search templates by query, category, or tags.
        
        Args:
            query: Search query for name/description
            category: Filter by category
            tags: Filter by tags
            
        Returns:
            List of (template_name, metadata) tuples
        """
        results = []
        
        if not self.metadata_file.exists():
            return results
        
        try:
            metadata_dict = json.loads(self.metadata_file.read_text(encoding='utf-8'))
            
            for name, data in metadata_dict.items():
                metadata = TemplateMetadata.from_dict(data)
                
                # Apply filters
                if category and metadata.category != category:
                    continue
                
                if tags:
                    if not any(tag in metadata.tags for tag in tags):
                        continue
                
                if query:
                    query_lower = query.lower()
                    if not (query_lower in name.lower() or 
                           query_lower in metadata.description.lower()):
                        continue
                
                results.append((name, metadata))
        
        except Exception:
            pass
        
        return results
    
    def export_template(self, name: str, export_path: Path) -> None:
        """
        Export template with metadata.
        
        Args:
            name: Template filename
            export_path: Export file path (.zip)
        """
        import zipfile
        
        template_path = self.get_template_path(name)
        if not template_path:
            raise FileNotFoundError(f"Template '{name}' not found")
        
        metadata = self.get_metadata(name)
        
        with zipfile.ZipFile(export_path, 'w') as zf:
            zf.write(template_path, template_path.name)
            if metadata:
                zf.writestr('metadata.json', json.dumps(metadata.to_dict(), indent=2))
    
    def import_template(self, import_path: Path) -> str:
        """
        Import template from export file.
        
        Args:
            import_path: Import file path (.zip)
            
        Returns:
            Imported template name
        """
        import zipfile
        
        with zipfile.ZipFile(import_path, 'r') as zf:
            names = zf.namelist()
            
            # Find template file
            template_name = None
            for name in names:
                if name != 'metadata.json':
                    template_name = name
                    break
            
            if not template_name:
                raise ValueError("No template file found in archive")
            
            # Extract template
            content = zf.read(template_name).decode('utf-8')
            self.create_template(template_name, content, overwrite=True)
            
            # Extract metadata if present
            if 'metadata.json' in names:
                metadata_json = zf.read('metadata.json').decode('utf-8')
                metadata_dict = json.loads(metadata_json)
                metadata = TemplateMetadata.from_dict(metadata_dict)
                self.set_metadata(template_name, metadata)
            
            return template_name


def generate_custom_report(
    results: List[ScanResult],
    template_name: str,
    output_path: Path,
    summary: Optional[Dict] = None,
    host_info: Optional[Dict[str, HostInfo]] = None,
    custom_vars: Optional[Dict[str, Any]] = None,
    templates_dir: Optional[Path] = None
) -> None:
    """
    Generate report using custom template.
    
    Args:
        results: List of scan results
        template_name: Name of template file
        output_path: Output file path
        summary: Optional scan summary
        host_info: Optional host information
        custom_vars: Optional custom template variables
        templates_dir: Optional custom templates directory
    """
    manager = TemplateManager(templates_dir)
    
    # Prepare context
    context = {
        'results': results,
        'summary': summary or {},
        'host_info': host_info or {},
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'tool': 'SpectreScan',
        'vendor': 'BitSpectreLabs',
        'open_ports': [r for r in results if r.state == 'open'],
        'closed_ports': [r for r in results if r.state == 'closed'],
        'filtered_ports': [r for r in results if r.state == 'filtered'],
    }
    
    # Add custom variables
    if custom_vars:
        context.update(custom_vars)
    
    # Render template
    rendered = manager.render_template(template_name, context)
    
    # Save output
    output_path.write_text(rendered, encoding='utf-8')


def create_default_templates(templates_dir: Optional[Path] = None) -> None:
    """
    Create default template examples.
    
    Args:
        templates_dir: Directory to create templates in
    """
    manager = TemplateManager(templates_dir)
    
    # Simple text template
    text_template = """SpectreScan Report - {{ tool }} by {{ vendor }}
Generated: {{ timestamp }}

=== SUMMARY ===
Total Ports Scanned: {{ summary.get('total_scanned', 0) }}
Open Ports: {{ open_ports|length }}
Closed Ports: {{ closed_ports|length }}
Filtered Ports: {{ filtered_ports|length }}

=== OPEN PORTS ===
{% for result in open_ports %}
{{ result.port }}/{{ result.protocol }} - {{ result.service or 'unknown' }}
{% if result.banner %}  Banner: {{ result.banner }}{% endif %}
{% endfor %}

=== HOST INFORMATION ===
{% for ip, info in host_info.items() %}
{{ ip }}
  Hostname: {{ info.hostname or 'N/A' }}
  OS: {{ info.os_guess or 'Unknown' }}
  Latency: {{ info.latency_ms or 'N/A' }} ms
{% endfor %}
"""
    
    # Markdown template
    markdown_template = """# SpectreScan Report

**Generated by:** {{ vendor }}  
**Timestamp:** {{ timestamp }}

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Ports Scanned | {{ summary.get('total_scanned', 0) }} |
| Open Ports | {{ open_ports|length }} |
| Closed Ports | {{ closed_ports|length }} |
| Filtered Ports | {{ filtered_ports|length }} |
| Scan Duration | {{ summary.get('scan_time', 0) }}s |

## Open Ports

{% for result in open_ports %}
### Port {{ result.port }}/{{ result.protocol }}

- **Service:** {{ result.service or 'unknown' }}
- **State:** {{ result.state }}
{% if result.banner %}
- **Banner:** `{{ result.banner }}`
{% endif %}

{% endfor %}

## Host Information

{% for ip, info in host_info.items() %}
### {{ ip }}

- **Hostname:** {{ info.hostname or 'N/A' }}
- **Operating System:** {{ info.os_guess or 'Unknown' }}
- **TTL:** {{ info.ttl or 'N/A' }}
- **Latency:** {{ info.latency_ms or 'N/A' }} ms

{% endfor %}

---
*Report generated by SpectreScan - Professional Network Security Tools*
"""
    
    # XML template
    xml_template = """<?xml version="1.0" encoding="UTF-8"?>
<spectrescan_report>
    <metadata>
        <tool>{{ tool }}</tool>
        <vendor>{{ vendor }}</vendor>
        <timestamp>{{ timestamp }}</timestamp>
    </metadata>
    <summary>
        <total_scanned>{{ summary.get('total_scanned', 0) }}</total_scanned>
        <open_ports>{{ open_ports|length }}</open_ports>
        <closed_ports>{{ closed_ports|length }}</closed_ports>
        <filtered_ports>{{ filtered_ports|length }}</filtered_ports>
    </summary>
    <results>
        {% for result in results %}
        <result>
            <host>{{ result.host }}</host>
            <port>{{ result.port }}</port>
            <protocol>{{ result.protocol }}</protocol>
            <state>{{ result.state }}</state>
            <service>{{ result.service or '' }}</service>
            <banner>{{ result.banner or '' }}</banner>
        </result>
        {% endfor %}
    </results>
    <hosts>
        {% for ip, info in host_info.items() %}
        <host>
            <ip>{{ ip }}</ip>
            <hostname>{{ info.hostname or '' }}</hostname>
            <os>{{ info.os_guess or '' }}</os>
            <ttl>{{ info.ttl or '' }}</ttl>
            <latency>{{ info.latency_ms or '' }}</latency>
        </host>
        {% endfor %}
    </hosts>
</spectrescan_report>
"""
    
    # Create templates
    try:
        manager.create_template('simple_text.txt', text_template, overwrite=True)
        manager.create_template('markdown_report.md', markdown_template, overwrite=True)
        manager.create_template('custom_xml.xml', xml_template, overwrite=True)
    except Exception:
        pass  # Ignore errors if templates already exist
