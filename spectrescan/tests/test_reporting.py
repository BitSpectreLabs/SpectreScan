"""
Tests for enhanced reporting features
"""

import pytest
from pathlib import Path
from datetime import datetime
from spectrescan.core.utils import ScanResult, HostInfo
from spectrescan.core.comparison import ScanComparison, PortDifference
from spectrescan.reports.comparison_report import (
    generate_comparison_report,
    _serialize_port_differences
)
from spectrescan.reports.executive_summary import (
    generate_executive_summary,
    calculate_risk_score,
    identify_critical_findings,
    analyze_service_distribution
)
from spectrescan.reports.charts import (
    get_ascii_chart,
    _ascii_port_distribution,
    _ascii_service_distribution
)


@pytest.fixture
def sample_results():
    """Sample scan results for testing."""
    return [
        ScanResult("192.168.1.1", 22, "open", "ssh", None, "tcp", datetime.now()),
        ScanResult("192.168.1.1", 80, "open", "http", "Apache/2.4", "tcp", datetime.now()),
        ScanResult("192.168.1.1", 443, "open", "https", None, "tcp", datetime.now()),
        ScanResult("192.168.1.1", 3306, "open", "mysql", "MySQL 8.0", "tcp", datetime.now()),
        ScanResult("192.168.1.1", 23, "closed", None, None, "tcp", datetime.now()),
        ScanResult("192.168.1.1", 445, "filtered", None, None, "tcp", datetime.now()),
    ]


@pytest.fixture
def sample_comparison():
    """Sample scan comparison for testing."""
    return ScanComparison(
        scan1_id="abc123",
        scan2_id="def456",
        scan1_target="192.168.1.1",
        scan2_target="192.168.1.1",
        scan1_timestamp="2025-01-01 10:00:00",
        scan2_timestamp="2025-01-02 10:00:00",
        newly_opened=[
            PortDifference(8080, "tcp", "closed", "open", None, "http-proxy")
        ],
        newly_closed=[
            PortDifference(21, "tcp", "open", "closed", "ftp", None)
        ],
        newly_filtered=[],
        service_changed=[
            PortDifference(80, "tcp", "open", "open", "apache", "nginx")
        ],
        total_changes=3,
        scan1_open_count=5,
        scan2_open_count=6,
        open_diff=1
    )


@pytest.fixture
def sample_host_info():
    """Sample host information."""
    return {
        "192.168.1.1": HostInfo(
            ip="192.168.1.1",
            hostname="server.example.com",
            os_guess="Linux 5.10",
            ttl=64,
            latency_ms=5.2,
            is_up=True
        )
    }


class TestComparisonReport:
    """Test comparison report generation."""
    
    def test_generate_text_comparison(self, sample_comparison, tmp_path):
        """Test text comparison report generation."""
        output_path = tmp_path / "comparison.txt"
        generate_comparison_report(sample_comparison, output_path, format='text')
        
        assert output_path.exists()
        content = output_path.read_text()
        assert "SCAN COMPARISON REPORT" in content
        assert "NEWLY OPENED PORTS" in content
        assert "8080/tcp" in content
    
    def test_generate_json_comparison(self, sample_comparison, tmp_path):
        """Test JSON comparison report generation."""
        import json
        
        output_path = tmp_path / "comparison.json"
        generate_comparison_report(sample_comparison, output_path, format='json')
        
        assert output_path.exists()
        data = json.loads(output_path.read_text())
        assert data['report_type'] == 'scan_comparison'
        assert data['comparison']['scan1']['id'] == 'abc123'
        assert len(data['comparison']['changes']['newly_opened']) == 1
    
    def test_generate_html_comparison(self, sample_comparison, tmp_path):
        """Test HTML comparison report generation."""
        output_path = tmp_path / "comparison.html"
        generate_comparison_report(sample_comparison, output_path, format='html')
        
        assert output_path.exists()
        content = output_path.read_text(encoding='utf-8')
        assert "<!DOCTYPE html>" in content
        assert "SpectreScan" in content
        assert "Newly Opened Ports" in content
    
    def test_invalid_format(self, sample_comparison, tmp_path):
        """Test invalid format raises error."""
        with pytest.raises(ValueError):
            generate_comparison_report(sample_comparison, tmp_path / "test.txt", format='invalid')
    
    def test_serialize_port_differences(self, sample_comparison):
        """Test port difference serialization."""
        serialized = _serialize_port_differences(sample_comparison.newly_opened)
        
        assert len(serialized) == 1
        assert serialized[0]['port'] == 8080
        assert serialized[0]['protocol'] == 'tcp'
        assert serialized[0]['new_state'] == 'open'


class TestExecutiveSummary:
    """Test executive summary generation."""
    
    def test_generate_summary_basic(self, sample_results, tmp_path):
        """Test basic executive summary generation."""
        output_path = tmp_path / "summary.txt"
        summary = generate_executive_summary(sample_results, output_path=output_path)
        
        assert output_path.exists()
        assert "SPECTRESCAN EXECUTIVE SUMMARY" in summary
        assert "RISK ASSESSMENT" in summary
        assert "RECOMMENDATIONS" in summary
    
    def test_calculate_risk_score_low(self):
        """Test low risk score calculation."""
        results = [
            ScanResult("192.168.1.1", 80, "open", "http", None, "tcp", datetime.now()),
            ScanResult("192.168.1.1", 443, "open", "https", None, "tcp", datetime.now()),
        ]
        
        score, level, factors = calculate_risk_score(results)
        
        assert score >= 0
        assert score < 100
        assert level == "LOW"
    
    def test_calculate_risk_score_high(self):
        """Test high risk score calculation."""
        results = []
        # Add many high-risk services
        high_risk_ports = [21, 23, 445, 3389, 5900, 6379, 9200, 27017, 3306, 5432]
        for port in high_risk_ports:
            results.append(
                ScanResult("192.168.1.1", port, "open", "service", None, "tcp", datetime.now())
            )
        
        score, level, factors = calculate_risk_score(results)
        
        assert score > 50
        assert level in ["HIGH", "CRITICAL"]
        assert len(factors) > 0
    
    def test_identify_critical_findings(self):
        """Test critical findings identification."""
        results = [
            ScanResult("192.168.1.1", 21, "open", "ftp", None, "tcp", datetime.now()),
            ScanResult("192.168.1.1", 23, "open", "telnet", None, "tcp", datetime.now()),
            ScanResult("192.168.1.1", 445, "open", "smb", None, "tcp", datetime.now()),
        ]
        
        findings = identify_critical_findings(results)
        
        assert len(findings) > 0
        assert any("FTP" in f for f in findings)
        assert any("Telnet" in f for f in findings)
    
    def test_analyze_service_distribution(self, sample_results):
        """Test service distribution analysis."""
        dist = analyze_service_distribution(sample_results)
        
        assert isinstance(dist, dict)
        assert "http" in dist
        assert "ssh" in dist
        assert dist["http"] == 1
    
    def test_summary_with_host_info(self, sample_results, sample_host_info):
        """Test summary generation with host info."""
        summary_dict = {
            'total_targets': 1,
            'total_scanned': 6,
            'open_count': 4,
            'closed_count': 1,
            'filtered_count': 1,
            'scan_time': 12.5,
            'scan_type': 'tcp'
        }
        
        summary = generate_executive_summary(
            sample_results,
            summary=summary_dict,
            host_info=sample_host_info
        )
        
        assert "192.168.1.1" in summary
        assert "server.example.com" in summary
        assert "Linux 5.10" in summary


class TestCharts:
    """Test chart generation."""
    
    def test_ascii_port_distribution(self, sample_results):
        """Test ASCII port distribution chart."""
        chart = get_ascii_chart(sample_results, 'port_distribution')
        
        assert "Port Status Distribution" in chart
        assert "open" in chart
        assert "closed" in chart
        assert "filtered" in chart
    
    def test_ascii_service_distribution(self, sample_results):
        """Test ASCII service distribution chart."""
        chart = get_ascii_chart(sample_results, 'service_distribution')
        
        assert "Top" in chart
        assert "Services" in chart
        assert "http" in chart or "ssh" in chart
    
    def test_ascii_port_dist_direct(self, sample_results):
        """Test direct ASCII port distribution."""
        chart = _ascii_port_distribution(sample_results)
        
        assert "open" in chart
        assert "4" in chart  # 4 open ports
    
    def test_ascii_service_dist_direct(self, sample_results):
        """Test direct ASCII service distribution."""
        chart = _ascii_service_distribution(sample_results)
        
        assert "http" in chart or "ssh" in chart
    
    def test_unsupported_chart_type(self, sample_results):
        """Test unsupported chart type."""
        chart = get_ascii_chart(sample_results, 'invalid_type')
        assert "Unsupported" in chart


class TestPDFReport:
    """Test PDF report generation (if reportlab available)."""
    
    def test_pdf_import(self):
        """Test PDF report module can be imported."""
        try:
            from spectrescan.reports.pdf_report import generate_pdf_report
            assert callable(generate_pdf_report)
        except ImportError:
            pytest.skip("ReportLab not installed")
    
    def test_pdf_generation_without_reportlab(self, sample_results, tmp_path):
        """Test PDF generation fails gracefully without reportlab."""
        try:
            from spectrescan.reports.pdf_report import REPORTLAB_AVAILABLE, generate_pdf_report
            
            if not REPORTLAB_AVAILABLE:
                with pytest.raises(ImportError):
                    generate_pdf_report(sample_results, tmp_path / "report.pdf")
            else:
                # If reportlab is available, test it works
                summary = {
                    'total_targets': 1,
                    'total_scanned': 6,
                    'open_count': 4,
                    'closed_count': 1,
                    'filtered_count': 1,
                    'scan_time': 12.5
                }
                output_path = tmp_path / "report.pdf"
                generate_pdf_report(sample_results, output_path, summary=summary)
                assert output_path.exists()
        except ImportError:
            pytest.skip("PDF report module not available")


class TestChartGeneration:
    """Test chart generation functions (if reportlab available)."""
    
    def test_chart_functions_import(self):
        """Test chart functions can be imported."""
        try:
            from spectrescan.reports.charts import (
                create_port_distribution_chart,
                create_service_distribution_chart,
                create_port_range_distribution_chart
            )
            assert callable(create_port_distribution_chart)
            assert callable(create_service_distribution_chart)
            assert callable(create_port_range_distribution_chart)
        except ImportError:
            pytest.skip("ReportLab not installed")
    
    def test_chart_creation(self, sample_results):
        """Test chart creation returns Drawing or None."""
        try:
            from spectrescan.reports.charts import (
                create_port_distribution_chart,
                create_service_distribution_chart,
                REPORTLAB_AVAILABLE
            )
            
            if REPORTLAB_AVAILABLE:
                chart1 = create_port_distribution_chart(sample_results)
                assert chart1 is not None
                
                chart2 = create_service_distribution_chart(sample_results)
                assert chart2 is not None
            else:
                chart = create_port_distribution_chart(sample_results)
                assert chart is None
        except ImportError:
            pytest.skip("Chart module not available")
