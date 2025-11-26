"""
Report generation modules for SpectreScan
by BitSpectreLabs
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
from pathlib import Path
from spectrescan.core.utils import ScanResult, get_timestamp

# Import enhanced reporting functions
from spectrescan.reports.pdf_report import generate_pdf_report
from spectrescan.reports.comparison_report import generate_comparison_report
from spectrescan.reports.executive_summary import (
    generate_executive_summary,
    calculate_risk_score,
    identify_critical_findings
)
from spectrescan.reports.charts import (
    create_port_distribution_chart,
    create_service_distribution_chart,
    generate_all_charts,
    get_ascii_chart
)
from spectrescan.reports.templates import (
    TemplateManager,
    generate_custom_report,
    create_default_templates
)
from spectrescan.reports.interactive_html import generate_interactive_html_report
from spectrescan.reports.markdown_report import (
    MarkdownReportGenerator,
    generate_markdown_report,
    generate_simple_markdown,
    generate_markdown_summary,
    results_to_markdown_table,
    TEMPLATE_MINIMAL,
    TEMPLATE_EXECUTIVE,
    TEMPLATE_TECHNICAL
)


def generate_json_report(results: List[ScanResult], output_path: Path, summary: Optional[Dict] = None) -> None:
    """
    Generate JSON report.
    
    Args:
        results: List of scan results
        output_path: Output file path
        summary: Optional scan summary
    """
    # Convert datetime objects in summary to strings
    if summary:
        summary_copy = {}
        for key, value in summary.items():
            if hasattr(value, 'isoformat'):  # datetime object
                summary_copy[key] = value.isoformat()
            else:
                summary_copy[key] = value
    else:
        summary_copy = {}
    
    report = {
        "scan_info": {
            "tool": "SpectreScan",
            "vendor": "BitSpectreLabs",
            "timestamp": get_timestamp(),
        },
        "summary": summary_copy,
        "results": []
    }
    
    for result in results:
        report["results"].append({
            "host": result.host,
            "port": result.port,
            "protocol": result.protocol,
            "state": result.state,
            "service": result.service,
            "banner": result.banner,
            "timestamp": result.timestamp.isoformat() if result.timestamp else None
        })
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def generate_csv_report(results: List[ScanResult], output_path: Path) -> None:
    """
    Generate CSV report.
    
    Args:
        results: List of scan results
        output_path: Output file path
    """
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Header
        writer.writerow(['Host', 'Port', 'Protocol', 'State', 'Service', 'Banner'])
        
        # Data
        for result in results:
            writer.writerow([
                result.host,
                result.port,
                result.protocol,
                result.state,
                result.service or '',
                result.banner or ''
            ])


def generate_xml_report(results: List[ScanResult], output_path: Path, summary: Optional[Dict] = None) -> None:
    """
    Generate XML report.
    
    Args:
        results: List of scan results
        output_path: Output file path
        summary: Optional scan summary
    """
    root = ET.Element("spectrescan_report")
    
    # Metadata
    metadata = ET.SubElement(root, "metadata")
    ET.SubElement(metadata, "tool").text = "SpectreScan"
    ET.SubElement(metadata, "vendor").text = "BitSpectreLabs"
    ET.SubElement(metadata, "timestamp").text = get_timestamp()
    
    # Summary
    if summary:
        summary_elem = ET.SubElement(root, "summary")
        for key, value in summary.items():
            ET.SubElement(summary_elem, key).text = str(value)
    
    # Results
    results_elem = ET.SubElement(root, "results")
    
    for result in results:
        result_elem = ET.SubElement(results_elem, "result")
        ET.SubElement(result_elem, "host").text = result.host
        ET.SubElement(result_elem, "port").text = str(result.port)
        ET.SubElement(result_elem, "protocol").text = result.protocol
        ET.SubElement(result_elem, "state").text = result.state
        ET.SubElement(result_elem, "service").text = result.service or ""
        ET.SubElement(result_elem, "banner").text = result.banner or ""
    
    # Write to file
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding='utf-8', xml_declaration=True)


__all__ = [
    "generate_json_report",
    "generate_csv_report", 
    "generate_xml_report",
    "generate_html_report",
    "generate_pdf_report",
    "generate_comparison_report",
    "generate_executive_summary",
    "calculate_risk_score",
    "identify_critical_findings",
    "create_port_distribution_chart",
    "create_service_distribution_chart",
    "generate_all_charts",
    "get_ascii_chart",
    "TemplateManager",
    "generate_custom_report",
    "create_default_templates",
    "generate_interactive_html_report",
    # Markdown reports
    "MarkdownReportGenerator",
    "generate_markdown_report",
    "generate_simple_markdown",
    "generate_markdown_summary",
    "results_to_markdown_table",
    "TEMPLATE_MINIMAL",
    "TEMPLATE_EXECUTIVE",
    "TEMPLATE_TECHNICAL",
]
