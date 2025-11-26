"""
Custom Report Templates for SpectreScan
by BitSpectreLabs
"""

from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime
from spectrescan.core.utils import ScanResult, HostInfo

try:
    from jinja2 import Environment, FileSystemLoader, Template, TemplateNotFound
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False


class TemplateManager:
    """Manage custom report templates."""
    
    def __init__(self, templates_dir: Optional[Path] = None):
        """
        Initialize template manager.
        
        Args:
            templates_dir: Directory containing custom templates
        """
        if templates_dir is None:
            templates_dir = Path.home() / ".spectrescan" / "templates"
        
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        if JINJA2_AVAILABLE:
            self.env = Environment(
                loader=FileSystemLoader(str(self.templates_dir)),
                autoescape=True
            )
        else:
            self.env = None
    
    def render_template(
        self,
        template_name: str,
        context: Dict[str, Any]
    ) -> str:
        """
        Render a template with given context.
        
        Args:
            template_name: Name of template file
            context: Dictionary of template variables
            
        Returns:
            Rendered template as string
            
        Raises:
            ImportError: If Jinja2 is not installed
            TemplateNotFound: If template doesn't exist
        """
        if not JINJA2_AVAILABLE:
            raise ImportError(
                "Jinja2 is required for custom templates. "
                "Install it with: pip install jinja2"
            )
        
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
