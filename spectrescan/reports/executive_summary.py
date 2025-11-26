"""
Executive Summary Generator for SpectreScan
by BitSpectreLabs
"""

from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime
from collections import Counter
from spectrescan.core.utils import ScanResult, HostInfo


def generate_executive_summary(
    results: List[ScanResult],
    summary: Optional[Dict] = None,
    host_info: Optional[Dict[str, HostInfo]] = None,
    output_path: Optional[Path] = None
) -> str:
    """
    Generate executive summary with risk scoring.
    
    Args:
        results: List of scan results
        summary: Optional scan summary statistics
        host_info: Optional host information dictionary
        output_path: Optional file path to save summary
        
    Returns:
        Executive summary as string
    """
    # Calculate risk score
    risk_score, risk_level, risk_factors = calculate_risk_score(results)
    
    # Identify critical findings
    critical_findings = identify_critical_findings(results)
    
    # Service distribution
    service_dist = analyze_service_distribution(results)
    
    # Build summary text
    summary_text = _format_executive_summary(
        results=results,
        summary=summary,
        host_info=host_info,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        critical_findings=critical_findings,
        service_dist=service_dist
    )
    
    if output_path:
        output_path.write_text(summary_text, encoding='utf-8')
    
    return summary_text


def calculate_risk_score(results: List[ScanResult]) -> tuple[int, str, List[str]]:
    """
    Calculate risk score based on scan results.
    
    Returns:
        Tuple of (score, level, factors) where:
        - score: 0-100 risk score
        - level: Risk level (Critical/High/Medium/Low)
        - factors: List of contributing risk factors
    """
    score = 0
    factors = []
    
    # Open ports contribute to risk
    open_ports = [r for r in results if r.state == 'open']
    
    if len(open_ports) > 50:
        score += 30
        factors.append(f"Large attack surface: {len(open_ports)} open ports")
    elif len(open_ports) > 20:
        score += 20
        factors.append(f"Moderate attack surface: {len(open_ports)} open ports")
    elif len(open_ports) > 10:
        score += 10
        factors.append(f"Small attack surface: {len(open_ports)} open ports")
    
    # High-risk services
    high_risk_services = {
        'ftp': 15, 'telnet': 20, 'smb': 15, 'netbios': 10,
        'rpc': 10, 'mysql': 10, 'postgresql': 10, 'mongodb': 10,
        'redis': 12, 'elasticsearch': 12, 'vnc': 15
    }
    
    for result in open_ports:
        service = (result.service or '').lower()
        for risk_service, risk_points in high_risk_services.items():
            if risk_service in service:
                score += risk_points
                factors.append(f"High-risk service exposed: {result.service} on port {result.port}")
                break
    
    # Common vulnerable ports
    vulnerable_ports = {21, 23, 445, 3389, 5900, 6379, 9200, 27017}
    exposed_vulnerable = [r for r in open_ports if r.port in vulnerable_ports]
    
    if exposed_vulnerable:
        score += len(exposed_vulnerable) * 5
        ports_str = ', '.join(str(r.port) for r in exposed_vulnerable[:3])
        if len(exposed_vulnerable) > 3:
            ports_str += f" (+{len(exposed_vulnerable) - 3} more)"
        factors.append(f"Common vulnerable ports exposed: {ports_str}")
    
    # Administrative interfaces
    admin_ports = {22, 3389, 5900, 5901, 8080, 8443, 9090}
    admin_exposed = [r for r in open_ports if r.port in admin_ports]
    
    if admin_exposed:
        score += len(admin_exposed) * 8
        factors.append(f"Administrative interfaces exposed: {len(admin_exposed)}")
    
    # Database ports
    db_ports = {3306, 5432, 1433, 27017, 6379, 9200}
    db_exposed = [r for r in open_ports if r.port in db_ports]
    
    if db_exposed:
        score += len(db_exposed) * 12
        factors.append(f"Database services exposed: {len(db_exposed)}")
    
    # Cap at 100
    score = min(100, score)
    
    # Determine risk level
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return score, level, factors


def identify_critical_findings(results: List[ScanResult]) -> List[str]:
    """Identify critical security findings."""
    findings = []
    
    open_ports = [r for r in results if r.state == 'open']
    
    # Check for critical services
    critical_checks = [
        (21, "FTP", "Unencrypted file transfer protocol"),
        (23, "Telnet", "Unencrypted remote access"),
        (445, "SMB", "Windows file sharing - potential WannaCry vector"),
        (3389, "RDP", "Remote Desktop - common attack target"),
        (5900, "VNC", "Remote desktop - often poorly secured"),
        (6379, "Redis", "In-memory database - often misconfigured"),
        (9200, "Elasticsearch", "Search engine - frequently exposed"),
        (27017, "MongoDB", "NoSQL database - default no authentication"),
    ]
    
    for port, name, description in critical_checks:
        matching = [r for r in open_ports if r.port == port]
        if matching:
            findings.append(f"⚠️ {name} (port {port}): {description}")
    
    # Check for web admin interfaces
    web_admin_ports = {8080, 8443, 9090, 10000}
    web_admin = [r for r in open_ports if r.port in web_admin_ports]
    if web_admin:
        findings.append(f"⚠️ Web admin interfaces exposed on {len(web_admin)} port(s)")
    
    # Check for many open ports (potential misconfiguration)
    if len(open_ports) > 30:
        findings.append(f"⚠️ Excessive open ports ({len(open_ports)}) - review firewall rules")
    
    return findings


def analyze_service_distribution(results: List[ScanResult]) -> Dict[str, int]:
    """Analyze distribution of services."""
    open_results = [r for r in results if r.state == 'open']
    services = [r.service or 'unknown' for r in open_results]
    return dict(Counter(services).most_common(10))


def _format_executive_summary(
    results: List[ScanResult],
    summary: Optional[Dict],
    host_info: Optional[Dict[str, HostInfo]],
    risk_score: int,
    risk_level: str,
    risk_factors: List[str],
    critical_findings: List[str],
    service_dist: Dict[str, int]
) -> str:
    """Format the executive summary as text."""
    
    lines = []
    lines.append("=" * 80)
    lines.append("SPECTRESCAN EXECUTIVE SUMMARY")
    lines.append("Professional Network Security Assessment")
    lines.append("by BitSpectreLabs")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    
    # Overview
    lines.append("━" * 80)
    lines.append("SCAN OVERVIEW")
    lines.append("━" * 80)
    
    if summary:
        lines.append(f"Targets Scanned:    {summary.get('total_targets', 'N/A')}")
        lines.append(f"Ports Scanned:      {summary.get('total_scanned', 0):,}")
        lines.append(f"Open Ports Found:   {summary.get('open_count', 0)}")
        lines.append(f"Closed Ports:       {summary.get('closed_count', 0)}")
        lines.append(f"Filtered Ports:     {summary.get('filtered_count', 0)}")
        lines.append(f"Scan Duration:      {summary.get('scan_time', 0):.2f} seconds")
        lines.append(f"Scan Type:          {summary.get('scan_type', 'N/A')}")
    
    lines.append("")
    
    # Risk Assessment
    lines.append("━" * 80)
    lines.append("RISK ASSESSMENT")
    lines.append("━" * 80)
    
    # Color-coded risk level
    risk_indicators = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH": "🟠 HIGH",
        "MEDIUM": "🟡 MEDIUM",
        "LOW": "🟢 LOW"
    }
    
    lines.append(f"Risk Score: {risk_score}/100")
    lines.append(f"Risk Level: {risk_indicators.get(risk_level, risk_level)}")
    lines.append("")
    
    if risk_factors:
        lines.append("Risk Factors:")
        for factor in risk_factors[:10]:  # Top 10
            lines.append(f"  • {factor}")
        if len(risk_factors) > 10:
            lines.append(f"  ... and {len(risk_factors) - 10} more factors")
    else:
        lines.append("✅ No significant risk factors identified")
    
    lines.append("")
    
    # Critical Findings
    if critical_findings:
        lines.append("━" * 80)
        lines.append("CRITICAL FINDINGS")
        lines.append("━" * 80)
        
        for finding in critical_findings:
            lines.append(f"  {finding}")
        
        lines.append("")
    
    # Service Distribution
    if service_dist:
        lines.append("━" * 80)
        lines.append("TOP SERVICES DETECTED")
        lines.append("━" * 80)
        
        for service, count in service_dist.items():
            lines.append(f"  {service:<20} {count:>3} port(s)")
        
        lines.append("")
    
    # Host Summary
    if host_info:
        lines.append("━" * 80)
        lines.append("HOST INFORMATION")
        lines.append("━" * 80)
        
        for ip, info in host_info.items():
            lines.append(f"  {ip}")
            if info.hostname:
                lines.append(f"    Hostname: {info.hostname}")
            if info.os_guess:
                lines.append(f"    OS:       {info.os_guess}")
            if info.latency_ms:
                lines.append(f"    Latency:  {info.latency_ms:.2f} ms")
            lines.append("")
    
    # Recommendations
    lines.append("━" * 80)
    lines.append("RECOMMENDATIONS")
    lines.append("━" * 80)
    
    recommendations = generate_recommendations(risk_level, risk_factors, critical_findings)
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"  {i}. {rec}")
    
    lines.append("")
    lines.append("=" * 80)
    lines.append("End of Executive Summary")
    lines.append("© 2025 BitSpectreLabs. All rights reserved.")
    lines.append("=" * 80)
    
    return "\n".join(lines)


def generate_recommendations(
    risk_level: str,
    risk_factors: List[str],
    critical_findings: List[str]
) -> List[str]:
    """Generate security recommendations based on findings."""
    recommendations = []
    
    if risk_level in ["CRITICAL", "HIGH"]:
        recommendations.append(
            "URGENT: Conduct immediate security review and remediation"
        )
        recommendations.append(
            "Review and restrict access to all exposed services"
        )
    
    if any("High-risk service" in f for f in risk_factors):
        recommendations.append(
            "Disable or restrict access to high-risk services (FTP, Telnet, etc.)"
        )
    
    if any("Database" in f for f in risk_factors):
        recommendations.append(
            "Ensure database services are not publicly accessible"
        )
        recommendations.append(
            "Implement strong authentication for all database services"
        )
    
    if any("Administrative" in f for f in risk_factors):
        recommendations.append(
            "Restrict administrative interfaces to trusted networks only"
        )
        recommendations.append(
            "Implement multi-factor authentication for admin access"
        )
    
    if any("attack surface" in f for f in risk_factors):
        recommendations.append(
            "Review firewall rules to minimize unnecessary port exposure"
        )
        recommendations.append(
            "Implement network segmentation to isolate critical services"
        )
    
    recommendations.append(
        "Regularly update and patch all exposed services"
    )
    recommendations.append(
        "Implement intrusion detection/prevention systems (IDS/IPS)"
    )
    recommendations.append(
        "Conduct regular security assessments and penetration testing"
    )
    
    return recommendations
