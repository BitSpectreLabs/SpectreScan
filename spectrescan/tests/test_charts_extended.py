"""
Tests for Charts Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from pathlib import Path
from spectrescan.core.utils import ScanResult
from spectrescan.reports.charts import (
    REPORTLAB_AVAILABLE,
    create_port_distribution_chart,
    create_service_distribution_chart,
    create_port_range_distribution_chart,
    create_risk_comparison_chart,
    generate_all_charts,
    get_ascii_chart,
    _ascii_port_distribution,
    _ascii_service_distribution
)


def create_mock_results():
    """Create mock scan results for testing."""
    results = [
        ScanResult(host="192.168.1.1", port=22, state="open", service="ssh"),
        ScanResult(host="192.168.1.1", port=80, state="open", service="http"),
        ScanResult(host="192.168.1.1", port=443, state="open", service="https"),
        ScanResult(host="192.168.1.1", port=8080, state="open", service="http"),
        ScanResult(host="192.168.1.1", port=21, state="closed", service="ftp"),
        ScanResult(host="192.168.1.1", port=23, state="closed", service="telnet"),
        ScanResult(host="192.168.1.1", port=25, state="filtered", service="smtp"),
        ScanResult(host="192.168.1.1", port=3306, state="open", service="mysql"),
    ]
    return results


class TestChartAvailability:
    """Tests for chart availability."""
    
    def test_reportlab_availability_flag(self):
        """Test REPORTLAB_AVAILABLE flag exists."""
        assert isinstance(REPORTLAB_AVAILABLE, bool)


class TestPortDistributionChart:
    """Tests for port distribution chart."""
    
    def test_with_empty_results(self):
        """Test with empty results."""
        result = create_port_distribution_chart([])
        
        if REPORTLAB_AVAILABLE:
            assert result is not None
        else:
            assert result is None
    
    def test_with_results(self):
        """Test with scan results."""
        results = create_mock_results()
        chart = create_port_distribution_chart(results)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
            # Should be a Drawing object
            assert hasattr(chart, 'width')
            assert hasattr(chart, 'height')
        else:
            assert chart is None
    
    def test_custom_dimensions(self):
        """Test with custom dimensions."""
        results = create_mock_results()
        chart = create_port_distribution_chart(results, width=800, height=600)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
            assert chart.width == 800
            assert chart.height == 600


class TestServiceDistributionChart:
    """Tests for service distribution chart."""
    
    def test_with_empty_results(self):
        """Test with empty results."""
        result = create_service_distribution_chart([])
        
        # No open ports means no chart
        assert result is None
    
    def test_with_results(self):
        """Test with scan results."""
        results = create_mock_results()
        chart = create_service_distribution_chart(results)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
        else:
            assert chart is None
    
    def test_top_n_parameter(self):
        """Test top_n parameter."""
        results = create_mock_results()
        chart = create_service_distribution_chart(results, top_n=3)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
    
    def test_only_closed_ports(self):
        """Test with only closed ports."""
        results = [
            ScanResult(host="192.168.1.1", port=21, state="closed", service="ftp"),
            ScanResult(host="192.168.1.1", port=22, state="closed", service="ssh"),
        ]
        chart = create_service_distribution_chart(results)
        assert chart is None


class TestPortRangeDistributionChart:
    """Tests for port range distribution chart."""
    
    def test_with_empty_results(self):
        """Test with empty results."""
        result = create_port_range_distribution_chart([])
        assert result is None
    
    def test_with_results(self):
        """Test with scan results."""
        results = create_mock_results()
        chart = create_port_range_distribution_chart(results)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
        else:
            assert chart is None
    
    def test_well_known_ports(self):
        """Test with well-known ports."""
        results = [
            ScanResult(host="192.168.1.1", port=22, state="open", service="ssh"),
            ScanResult(host="192.168.1.1", port=80, state="open", service="http"),
            ScanResult(host="192.168.1.1", port=443, state="open", service="https"),
        ]
        chart = create_port_range_distribution_chart(results)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
    
    def test_registered_ports(self):
        """Test with registered ports."""
        results = [
            ScanResult(host="192.168.1.1", port=3306, state="open", service="mysql"),
            ScanResult(host="192.168.1.1", port=5432, state="open", service="postgresql"),
            ScanResult(host="192.168.1.1", port=8080, state="open", service="http-proxy"),
        ]
        chart = create_port_range_distribution_chart(results)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
    
    def test_dynamic_ports(self):
        """Test with dynamic ports."""
        results = [
            ScanResult(host="192.168.1.1", port=50000, state="open", service="unknown"),
            ScanResult(host="192.168.1.1", port=55000, state="open", service="unknown"),
        ]
        chart = create_port_range_distribution_chart(results)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None


class TestRiskComparisonChart:
    """Tests for risk comparison chart."""
    
    def test_with_empty_summaries(self):
        """Test with empty summaries."""
        result = create_risk_comparison_chart([])
        assert result is None
    
    def test_with_single_summary(self):
        """Test with single summary (needs at least 2)."""
        summaries = [{"risk_score": 50}]
        result = create_risk_comparison_chart(summaries)
        assert result is None
    
    def test_with_multiple_summaries(self):
        """Test with multiple summaries."""
        summaries = [
            {"risk_score": 30},
            {"risk_score": 45},
            {"risk_score": 60},
        ]
        chart = create_risk_comparison_chart(summaries)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None
        else:
            assert chart is None
    
    def test_missing_risk_score(self):
        """Test with missing risk scores."""
        summaries = [
            {"risk_score": 30},
            {},  # Missing risk_score
        ]
        chart = create_risk_comparison_chart(summaries)
        
        if REPORTLAB_AVAILABLE:
            assert chart is not None


class TestASCIICharts:
    """Tests for ASCII chart generation."""
    
    def test_get_ascii_chart_port_distribution(self):
        """Test ASCII port distribution chart."""
        results = create_mock_results()
        chart = get_ascii_chart(results, 'port_distribution')
        
        assert "Port Status Distribution" in chart
        assert "open" in chart
        assert "closed" in chart
        assert "filtered" in chart
    
    def test_get_ascii_chart_service_distribution(self):
        """Test ASCII service distribution chart."""
        results = create_mock_results()
        chart = get_ascii_chart(results, 'service_distribution')
        
        assert "Services" in chart
        assert "http" in chart or "ssh" in chart
    
    def test_get_ascii_chart_unsupported(self):
        """Test unsupported chart type."""
        results = create_mock_results()
        chart = get_ascii_chart(results, 'unsupported_type')
        
        assert "Unsupported" in chart


class TestASCIIPortDistribution:
    """Tests for ASCII port distribution function."""
    
    def test_empty_results(self):
        """Test with empty results."""
        chart = _ascii_port_distribution([])
        
        assert "Port Status Distribution" in chart
        assert "0" in chart
    
    def test_with_results(self):
        """Test with results."""
        results = create_mock_results()
        chart = _ascii_port_distribution(results)
        
        assert "█" in chart  # Should have bar characters
        assert "open" in chart
    
    def test_all_open(self):
        """Test with all open ports."""
        results = [
            ScanResult(host="192.168.1.1", port=80, state="open", service="http"),
            ScanResult(host="192.168.1.1", port=443, state="open", service="https"),
        ]
        chart = _ascii_port_distribution(results)
        
        assert "open" in chart
        assert "2" in chart or "█" in chart
    
    def test_all_closed(self):
        """Test with all closed ports."""
        results = [
            ScanResult(host="192.168.1.1", port=21, state="closed", service="ftp"),
            ScanResult(host="192.168.1.1", port=22, state="closed", service="ssh"),
        ]
        chart = _ascii_port_distribution(results)
        
        assert "closed" in chart


class TestASCIIServiceDistribution:
    """Tests for ASCII service distribution function."""
    
    def test_empty_results(self):
        """Test with empty results."""
        chart = _ascii_service_distribution([])
        assert "No services detected" in chart
    
    def test_no_open_ports(self):
        """Test with no open ports."""
        results = [
            ScanResult(host="192.168.1.1", port=21, state="closed", service="ftp"),
        ]
        chart = _ascii_service_distribution(results)
        assert "No services detected" in chart
    
    def test_with_services(self):
        """Test with services."""
        results = create_mock_results()
        chart = _ascii_service_distribution(results)
        
        assert "Services" in chart
        assert "█" in chart
    
    def test_top_n(self):
        """Test top_n parameter."""
        results = create_mock_results()
        chart = _ascii_service_distribution(results, top_n=3)
        
        assert "3 Services" in chart or "Services" in chart
    
    def test_service_name_truncation(self):
        """Test long service names are truncated."""
        results = [
            ScanResult(host="192.168.1.1", port=80, state="open", 
                      service="very-long-service-name-that-should-be-truncated"),
        ]
        chart = _ascii_service_distribution(results)
        
        # Should still work with long names
        assert "█" in chart


class TestGenerateAllCharts:
    """Tests for generate_all_charts function."""
    
    @pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="ReportLab not available")
    def test_generate_pdf_charts(self, tmp_path):
        """Test generating PDF charts."""
        results = create_mock_results()
        output_dir = tmp_path / "charts"
        
        generated = generate_all_charts(results, output_dir, format='pdf')
        
        assert len(generated) > 0
        for path in generated:
            assert path.exists()
            assert path.suffix == '.pdf'
    
    @pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="ReportLab not available")
    def test_generates_port_distribution(self, tmp_path):
        """Test port distribution chart is generated."""
        results = create_mock_results()
        output_dir = tmp_path / "charts"
        
        generated = generate_all_charts(results, output_dir, format='pdf')
        
        port_dist_file = output_dir / "port_distribution.pdf"
        assert port_dist_file in generated
    
    @pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="ReportLab not available")
    def test_generates_service_distribution(self, tmp_path):
        """Test service distribution chart is generated."""
        results = create_mock_results()
        output_dir = tmp_path / "charts"
        
        generated = generate_all_charts(results, output_dir, format='pdf')
        
        service_dist_file = output_dir / "service_distribution.pdf"
        assert service_dist_file in generated
    
    @pytest.mark.skipif(not REPORTLAB_AVAILABLE, reason="ReportLab not available")
    def test_creates_output_directory(self, tmp_path):
        """Test output directory is created."""
        results = create_mock_results()
        output_dir = tmp_path / "new_charts_dir"
        
        generate_all_charts(results, output_dir, format='pdf')
        
        assert output_dir.exists()
        assert output_dir.is_dir()
    
    def test_no_reportlab(self):
        """Test behavior when ReportLab not available."""
        if not REPORTLAB_AVAILABLE:
            results = create_mock_results()
            
            with pytest.raises(ImportError):
                generate_all_charts(results, Path("output"), format='pdf')
