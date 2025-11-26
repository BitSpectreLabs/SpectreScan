"""
Tests for Detailed Reports Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from pathlib import Path
from dataclasses import fields
from spectrescan.core.detailed_reports import (
    SecurityFinding,
    TechnologyReport,
    DetailedReportGenerator
)


class TestSecurityFinding:
    """Tests for SecurityFinding dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        finding = SecurityFinding(
            severity="high",
            title="Insecure Protocol",
            description="FTP transmits credentials in clear text",
            affected_service="ftp",
            affected_port=21
        )
        assert finding.severity == "high"
        assert finding.title == "Insecure Protocol"
        assert finding.affected_service == "ftp"
        assert finding.affected_port == 21
    
    def test_with_remediation(self):
        """Test finding with remediation."""
        finding = SecurityFinding(
            severity="critical",
            title="Telnet Exposed",
            description="Telnet is unencrypted",
            affected_service="telnet",
            affected_port=23,
            remediation="Use SSH instead of Telnet"
        )
        assert finding.remediation == "Use SSH instead of Telnet"
    
    def test_with_cve(self):
        """Test finding with CVE references."""
        finding = SecurityFinding(
            severity="high",
            title="Known Vulnerability",
            description="Service has known CVE",
            affected_service="apache",
            affected_port=80,
            cve=["CVE-2021-1234", "CVE-2021-5678"]
        )
        assert len(finding.cve) == 2
        assert "CVE-2021-1234" in finding.cve
    
    def test_with_references(self):
        """Test finding with references."""
        finding = SecurityFinding(
            severity="medium",
            title="Configuration Issue",
            description="Default configuration",
            affected_service="nginx",
            affected_port=80,
            references=["https://example.com/doc"]
        )
        assert len(finding.references) == 1
    
    def test_default_values(self):
        """Test default values."""
        finding = SecurityFinding(
            severity="info",
            title="Info",
            description="Information",
            affected_service="http",
            affected_port=80
        )
        assert finding.remediation is None
        assert finding.cve is None
        assert finding.references == []
    
    def test_all_severities(self):
        """Test all severity levels."""
        for severity in ["critical", "high", "medium", "low", "info"]:
            finding = SecurityFinding(
                severity=severity,
                title=f"{severity} finding",
                description=f"A {severity} finding",
                affected_service="test",
                affected_port=80
            )
            assert finding.severity == severity


class TestTechnologyReport:
    """Tests for TechnologyReport dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        report = TechnologyReport(host="192.168.1.1")
        assert report.host == "192.168.1.1"
    
    def test_default_empty_lists(self):
        """Test default empty lists."""
        report = TechnologyReport(host="localhost")
        assert report.web_servers == []
        assert report.app_frameworks == []
        assert report.databases == []
        assert report.languages == []
        assert report.cms == []
        assert report.waf == []
        assert report.cdn == []
        assert report.load_balancers == []
        assert report.additional == {}
    
    def test_with_web_servers(self):
        """Test with web servers."""
        report = TechnologyReport(
            host="192.168.1.1",
            web_servers=["nginx/1.18.0", "Apache/2.4.41"]
        )
        assert len(report.web_servers) == 2
        assert "nginx/1.18.0" in report.web_servers
    
    def test_with_databases(self):
        """Test with databases."""
        report = TechnologyReport(
            host="192.168.1.1",
            databases=["MySQL 8.0", "Redis 6.0", "MongoDB 4.4"]
        )
        assert len(report.databases) == 3
    
    def test_with_app_frameworks(self):
        """Test with app frameworks."""
        report = TechnologyReport(
            host="192.168.1.1",
            app_frameworks=["Django 3.2", "React 17.0"]
        )
        assert "Django 3.2" in report.app_frameworks
    
    def test_with_languages(self):
        """Test with programming languages."""
        report = TechnologyReport(
            host="192.168.1.1",
            languages=["Python 3.9", "PHP 8.0", "Node.js 16"]
        )
        assert len(report.languages) == 3
    
    def test_with_cms(self):
        """Test with CMS."""
        report = TechnologyReport(
            host="192.168.1.1",
            cms=["WordPress 5.8"]
        )
        assert "WordPress 5.8" in report.cms
    
    def test_with_waf(self):
        """Test with WAF."""
        report = TechnologyReport(
            host="192.168.1.1",
            waf=["Cloudflare", "ModSecurity"]
        )
        assert len(report.waf) == 2
    
    def test_with_operating_system(self):
        """Test with operating system."""
        report = TechnologyReport(
            host="192.168.1.1",
            operating_system="Ubuntu 20.04 LTS"
        )
        assert report.operating_system == "Ubuntu 20.04 LTS"
    
    def test_with_additional(self):
        """Test with additional technology categories."""
        report = TechnologyReport(
            host="192.168.1.1",
            additional={"container": ["Docker"], "ci_cd": ["Jenkins"]}
        )
        assert "container" in report.additional
        assert "Docker" in report.additional["container"]


class TestDetailedReportGenerator:
    """Tests for DetailedReportGenerator class."""
    
    def test_init(self):
        """Test initialization."""
        generator = DetailedReportGenerator()
        assert generator is not None
        assert hasattr(generator, 'vulnerability_patterns')
    
    def test_vulnerability_patterns_loaded(self):
        """Test vulnerability patterns are loaded."""
        generator = DetailedReportGenerator()
        patterns = generator.vulnerability_patterns
        
        assert "ftp" in patterns
        assert "telnet" in patterns
        assert "mysql" in patterns
        assert "mongodb" in patterns
        assert "redis" in patterns
    
    def test_ftp_pattern(self):
        """Test FTP vulnerability pattern."""
        generator = DetailedReportGenerator()
        ftp_pattern = generator.vulnerability_patterns["ftp"]
        
        assert ftp_pattern["risk"] == "high"
        assert "clear text" in ftp_pattern["finding"].lower()
        assert "sftp" in ftp_pattern["remediation"].lower()
    
    def test_telnet_pattern(self):
        """Test Telnet vulnerability pattern."""
        generator = DetailedReportGenerator()
        telnet_pattern = generator.vulnerability_patterns["telnet"]
        
        assert telnet_pattern["risk"] == "critical"
        assert "ssh" in telnet_pattern["remediation"].lower()


class MockScanResult:
    """Mock scan result for testing."""
    
    def __init__(self, host, port, state, service=None, protocol="tcp",
                 banner=None, product=None, version=None, cpe=None):
        self.host = host
        self.port = port
        self.state = state
        self.service = service or "unknown"
        self.protocol = protocol
        self.banner = banner
        self.product = product
        self.version = version
        self.cpe = cpe or []


class TestDetailedReportGeneration:
    """Tests for report generation."""
    
    def test_generate_empty_report(self):
        """Test generating report with no results."""
        generator = DetailedReportGenerator()
        report = generator.generate_report([])
        
        assert "SPECTRESCAN DETAILED SERVICE REPORT" in report
        assert "BitSpectreLabs" in report
        assert "END OF REPORT" in report
    
    def test_generate_report_with_results(self):
        """Test generating report with scan results."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 22, "open", "ssh"),
            MockScanResult("192.168.1.1", 80, "open", "http"),
            MockScanResult("192.168.1.1", 443, "open", "https"),
            MockScanResult("192.168.1.1", 3306, "closed", "mysql"),
        ]
        
        report = generator.generate_report(results)
        
        assert "EXECUTIVE SUMMARY" in report
        assert "SERVICE DETAILS" in report
        assert "RECOMMENDATIONS" in report
    
    def test_generate_report_with_technology_stack(self):
        """Test generating report with technology stack."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 80, "open", "http"),
        ]
        
        tech_stack = TechnologyReport(
            host="192.168.1.1",
            web_servers=["nginx/1.18.0"],
            databases=["MySQL 8.0"],
            operating_system="Ubuntu 20.04"
        )
        
        report = generator.generate_report(results, technology_stack=tech_stack)
        
        assert "TECHNOLOGY STACK" in report
        assert "nginx" in report
        assert "MySQL" in report
        assert "Ubuntu" in report
    
    def test_generate_report_with_insecure_services(self):
        """Test report identifies insecure services."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 21, "open", "ftp"),
            MockScanResult("192.168.1.1", 23, "open", "telnet"),
        ]
        
        report = generator.generate_report(results)
        
        assert "SECURITY FINDINGS" in report
    
    def test_generate_report_to_file(self, tmp_path):
        """Test generating report to file."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 80, "open", "http"),
        ]
        
        output_path = tmp_path / "report.txt"
        generator.generate_report(results, output_path=output_path)
        
        assert output_path.exists()
        content = output_path.read_text()
        assert "SPECTRESCAN" in content


class TestExecutiveSummary:
    """Tests for executive summary generation."""
    
    def test_port_counts(self):
        """Test port count statistics."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 22, "open", "ssh"),
            MockScanResult("192.168.1.1", 23, "closed", "telnet"),
            MockScanResult("192.168.1.1", 25, "filtered", "smtp"),
            MockScanResult("192.168.1.1", 80, "open", "http"),
            MockScanResult("192.168.1.1", 443, "open", "https"),
        ]
        
        report = generator.generate_report(results)
        
        # Should show correct counts
        assert "Open:" in report
        assert "Closed:" in report
        assert "Filtered:" in report
    
    def test_service_summary(self):
        """Test service summary in report."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 80, "open", "http"),
            MockScanResult("192.168.1.1", 8080, "open", "http"),
            MockScanResult("192.168.1.1", 443, "open", "https"),
        ]
        
        report = generator.generate_report(results)
        
        assert "Detected services" in report


class TestSecurityFindingsIdentification:
    """Tests for security findings identification."""
    
    def test_identify_ftp(self):
        """Test FTP is identified as insecure."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 21, "open", "ftp"),
        ]
        
        findings = generator._identify_security_findings(results)
        assert len(findings) >= 1
        assert any(f.affected_service == "ftp" for f in findings)
    
    def test_identify_telnet(self):
        """Test Telnet is identified as critical."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 23, "open", "telnet"),
        ]
        
        findings = generator._identify_security_findings(results)
        assert len(findings) >= 1
        
        telnet_finding = next(f for f in findings if f.affected_service == "telnet")
        assert telnet_finding.severity == "critical"
    
    def test_identify_exposed_database(self):
        """Test exposed database is identified."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 3306, "open", "mysql"),
        ]
        
        findings = generator._identify_security_findings(results)
        assert len(findings) >= 1
    
    def test_closed_ports_ignored(self):
        """Test closed ports don't generate findings."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 21, "closed", "ftp"),
            MockScanResult("192.168.1.1", 23, "closed", "telnet"),
        ]
        
        findings = generator._identify_security_findings(results)
        assert len(findings) == 0


class TestServiceDetails:
    """Tests for service details section."""
    
    def test_service_with_banner(self):
        """Test service with banner."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult(
                "192.168.1.1", 22, "open", "ssh",
                banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
            ),
        ]
        
        report = generator.generate_report(results)
        assert "Banner:" in report
        assert "OpenSSH" in report
    
    def test_service_with_version(self):
        """Test service with version info."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult(
                "192.168.1.1", 80, "open", "http",
                product="nginx", version="1.18.0"
            ),
        ]
        
        report = generator.generate_report(results)
        assert "nginx" in report
        assert "1.18.0" in report


class TestRecommendations:
    """Tests for recommendations section."""
    
    def test_general_recommendations(self):
        """Test general recommendations are included."""
        generator = DetailedReportGenerator()
        
        report = generator.generate_report([])
        
        assert "RECOMMENDATIONS" in report
        assert "updated" in report.lower()
        assert "encryption" in report.lower() or "tls" in report.lower()
    
    def test_immediate_action_for_critical(self):
        """Test immediate action for critical findings."""
        generator = DetailedReportGenerator()
        
        results = [
            MockScanResult("192.168.1.1", 23, "open", "telnet"),
        ]
        
        report = generator.generate_report(results)
        
        # Should have immediate action section
        assert "IMMEDIATE ACTION" in report or "Remediation" in report.lower()
