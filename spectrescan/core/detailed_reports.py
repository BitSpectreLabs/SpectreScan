"""
Detailed Service Reports
Generate comprehensive reports with technology stack and security findings.

Author: BitSpectreLabs
License: MIT
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """Security finding from scan."""
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    affected_service: str
    affected_port: int
    remediation: Optional[str] = None
    cve: Optional[List[str]] = None
    references: List[str] = field(default_factory=list)


@dataclass
class TechnologyReport:
    """Technology stack report."""
    host: str
    web_servers: List[str] = field(default_factory=list)
    app_frameworks: List[str] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    cms: List[str] = field(default_factory=list)
    waf: List[str] = field(default_factory=list)
    cdn: List[str] = field(default_factory=list)
    load_balancers: List[str] = field(default_factory=list)
    operating_system: Optional[str] = None
    additional: Dict[str, List[str]] = field(default_factory=dict)


class DetailedReportGenerator:
    """
    Generate detailed service reports with:
    - Technology stack summary
    - Security findings
    - Recommendations
    - Service details
    """
    
    def __init__(self):
        """Initialize report generator."""
        self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self):
        """Load patterns for identifying common vulnerabilities."""
        self.vulnerability_patterns = {
            # Outdated versions
            "apache": {
                "vulnerable_versions": ["2.4.0-2.4.48"],
                "finding": "Outdated Apache version may contain known vulnerabilities",
                "remediation": "Update to latest Apache version"
            },
            "openssh": {
                "vulnerable_versions": ["<7.0"],
                "finding": "Outdated OpenSSH version vulnerable to various attacks",
                "remediation": "Update to OpenSSH 8.0 or later"
            },
            
            # Insecure services
            "ftp": {
                "risk": "high",
                "finding": "FTP transmits credentials in clear text",
                "remediation": "Use SFTP or FTPS instead"
            },
            "telnet": {
                "risk": "critical",
                "finding": "Telnet is unencrypted and highly insecure",
                "remediation": "Use SSH instead of Telnet"
            },
            "http": {
                "risk": "medium",
                "finding": "HTTP transmits data without encryption",
                "remediation": "Use HTTPS (TLS/SSL) instead"
            },
            
            # Database exposure
            "mysql": {
                "risk": "high",
                "finding": "MySQL exposed to network may be vulnerable to attacks",
                "remediation": "Restrict MySQL access to trusted IPs, use firewalls"
            },
            "mongodb": {
                "risk": "high",
                "finding": "MongoDB exposed without authentication",
                "remediation": "Enable authentication, bind to localhost, use firewall"
            },
            "redis": {
                "risk": "high",
                "finding": "Redis exposed to network without authentication",
                "remediation": "Enable requirepass, bind to localhost, use firewall"
            },
        }
    
    def generate_report(
        self,
        results: List[Any],
        technology_stack: Optional[TechnologyReport] = None,
        script_results: Optional[List[Any]] = None,
        output_path: Optional[Path] = None
    ) -> str:
        """
        Generate detailed service report.
        
        Args:
            results: Scan results
            technology_stack: Detected technology stack
            script_results: Script execution results
            output_path: Output file path (optional)
        
        Returns:
            Report text
        """
        report_lines = []
        
        # Header
        report_lines.append("=" * 80)
        report_lines.append("SPECTRESCAN DETAILED SERVICE REPORT")
        report_lines.append("=" * 80)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Report by: BitSpectreLabs")
        report_lines.append("")
        
        # Executive Summary
        report_lines.extend(self._generate_executive_summary(results))
        
        # Technology Stack
        if technology_stack:
            report_lines.extend(self._generate_technology_section(technology_stack))
        
        # Service Details
        report_lines.extend(self._generate_service_details(results))
        
        # Security Findings
        findings = self._identify_security_findings(results)
        if findings:
            report_lines.extend(self._generate_security_section(findings))
        
        # Script Results
        if script_results:
            report_lines.extend(self._generate_script_section(script_results))
        
        # Recommendations
        report_lines.extend(self._generate_recommendations(results, findings))
        
        # Footer
        report_lines.append("")
        report_lines.append("=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)
        
        report_text = "\n".join(report_lines)
        
        # Write to file if path provided
        if output_path:
            output_path.write_text(report_text)
            logger.info(f"Detailed report written to {output_path}")
        
        return report_text
    
    def _generate_executive_summary(self, results: List[Any]) -> List[str]:
        """Generate executive summary section."""
        lines = []
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        
        # Count ports by state
        open_ports = sum(1 for r in results if getattr(r, 'state', '') == 'open')
        closed_ports = sum(1 for r in results if getattr(r, 'state', '') == 'closed')
        filtered_ports = sum(1 for r in results if getattr(r, 'state', '') == 'filtered')
        
        lines.append(f"Total ports scanned: {len(results)}")
        lines.append(f"  Open:     {open_ports}")
        lines.append(f"  Closed:   {closed_ports}")
        lines.append(f"  Filtered: {filtered_ports}")
        lines.append("")
        
        # Service summary
        services = {}
        for result in results:
            if getattr(result, 'state', '') == 'open':
                service = getattr(result, 'service', 'unknown')
                services[service] = services.get(service, 0) + 1
        
        if services:
            lines.append("Detected services:")
            for service, count in sorted(services.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"  - {service}: {count} port(s)")
        
        lines.append("")
        return lines
    
    def _generate_technology_section(self, tech: TechnologyReport) -> List[str]:
        """Generate technology stack section."""
        lines = []
        lines.append("TECHNOLOGY STACK")
        lines.append("-" * 80)
        
        if tech.operating_system:
            lines.append(f"Operating System: {tech.operating_system}")
            lines.append("")
        
        sections = [
            ("Web Servers", tech.web_servers),
            ("Application Frameworks", tech.app_frameworks),
            ("Databases", tech.databases),
            ("Programming Languages", tech.languages),
            ("CMS", tech.cms),
            ("Web Application Firewall", tech.waf),
            ("CDN", tech.cdn),
            ("Load Balancers", tech.load_balancers),
        ]
        
        for section_name, items in sections:
            if items:
                lines.append(f"{section_name}:")
                for item in items:
                    lines.append(f"  - {item}")
                lines.append("")
        
        return lines
    
    def _generate_service_details(self, results: List[Any]) -> List[str]:
        """Generate service details section."""
        lines = []
        lines.append("SERVICE DETAILS")
        lines.append("-" * 80)
        
        open_results = [r for r in results if getattr(r, 'state', '') == 'open']
        
        for result in open_results:
            port = getattr(result, 'port', 0)
            protocol = getattr(result, 'protocol', 'tcp')
            service = getattr(result, 'service', 'unknown')
            
            lines.append(f"Port {port}/{protocol} - {service}")
            
            product = getattr(result, 'product', None)
            version = getattr(result, 'version', None)
            if product or version:
                version_str = f"{product or ''} {version or ''}".strip()
                lines.append(f"  Version: {version_str}")
            
            banner = getattr(result, 'banner', None)
            if banner:
                # Show first 200 chars of banner
                banner_preview = banner[:200] + "..." if len(banner) > 200 else banner
                lines.append(f"  Banner: {banner_preview}")
            
            cpe = getattr(result, 'cpe', [])
            if cpe:
                lines.append(f"  CPE: {', '.join(cpe[:2])}")
            
            lines.append("")
        
        return lines
    
    def _identify_security_findings(self, results: List[Any]) -> List[SecurityFinding]:
        """Identify security findings from results."""
        findings = []
        
        for result in results:
            if getattr(result, 'state', '') != 'open':
                continue
            
            port = getattr(result, 'port', 0)
            service = getattr(result, 'service', '').lower()
            
            # Check for insecure services
            if service in self.vulnerability_patterns:
                pattern = self.vulnerability_patterns[service]
                
                if 'risk' in pattern:
                    severity = pattern['risk']
                    finding = SecurityFinding(
                        severity=severity,
                        title=f"Insecure protocol detected: {service.upper()}",
                        description=pattern['finding'],
                        affected_service=service,
                        affected_port=port,
                        remediation=pattern['remediation']
                    )
                    findings.append(finding)
        
        return findings
    
    def _generate_security_section(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate security findings section."""
        lines = []
        lines.append("SECURITY FINDINGS")
        lines.append("-" * 80)
        
        # Group by severity
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for finding in findings:
            by_severity[finding.severity].append(finding)
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            severity_findings = by_severity[severity]
            if not severity_findings:
                continue
            
            lines.append(f"\n{severity.upper()} Severity ({len(severity_findings)} findings):")
            lines.append("")
            
            for i, finding in enumerate(severity_findings, 1):
                lines.append(f"{i}. {finding.title}")
                lines.append(f"   Service: {finding.affected_service} (port {finding.affected_port})")
                lines.append(f"   Description: {finding.description}")
                if finding.remediation:
                    lines.append(f"   Remediation: {finding.remediation}")
                lines.append("")
        
        return lines
    
    def _generate_script_section(self, script_results: List[Any]) -> List[str]:
        """Generate script results section."""
        lines = []
        lines.append("SCRIPT RESULTS")
        lines.append("-" * 80)
        
        for result in script_results:
            if not getattr(result, 'success', False):
                continue
            
            script_name = getattr(result, 'script_name', 'unknown')
            output = getattr(result, 'output', '')
            
            lines.append(f"[{script_name}]")
            for line in output.split('\n'):
                lines.append(f"  {line}")
            lines.append("")
        
        return lines
    
    def _generate_recommendations(
        self,
        results: List[Any],
        findings: List[SecurityFinding]
    ) -> List[str]:
        """Generate recommendations section."""
        lines = []
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 80)
        
        # Priority recommendations based on findings
        if any(f.severity in ["critical", "high"] for f in findings):
            lines.append("IMMEDIATE ACTION REQUIRED:")
            lines.append("")
            for finding in findings:
                if finding.severity in ["critical", "high"] and finding.remediation:
                    lines.append(f"- {finding.remediation}")
            lines.append("")
        
        # General recommendations
        lines.append("General Security Recommendations:")
        lines.append("- Keep all services updated to latest stable versions")
        lines.append("- Disable unnecessary services and close unused ports")
        lines.append("- Use encryption for all network communications (TLS/SSL)")
        lines.append("- Implement strong authentication and access controls")
        lines.append("- Enable logging and monitoring for all services")
        lines.append("- Regular security audits and vulnerability assessments")
        lines.append("- Implement network segmentation and firewall rules")
        lines.append("")
        
        return lines
