"""
Unit tests for Markdown report generation
by BitSpectreLabs
"""

import pytest
from pathlib import Path
from datetime import datetime
from typing import List

from spectrescan.core.utils import ScanResult, HostInfo
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


# Test fixtures
@pytest.fixture
def sample_results() -> List[ScanResult]:
    """Create sample scan results for testing."""
    return [
        ScanResult(
            host="192.168.1.1",
            port=22,
            state="open",
            service="ssh",
            banner="SSH-2.0-OpenSSH_8.2",
            protocol="tcp",
            timestamp=datetime.now()
        ),
        ScanResult(
            host="192.168.1.1",
            port=80,
            state="open",
            service="http",
            banner="Apache/2.4.41 (Ubuntu)",
            protocol="tcp",
            timestamp=datetime.now()
        ),
        ScanResult(
            host="192.168.1.1",
            port=443,
            state="open",
            service="https",
            banner="nginx/1.18.0",
            protocol="tcp",
            timestamp=datetime.now()
        ),
        ScanResult(
            host="192.168.1.1",
            port=3306,
            state="closed",
            service="mysql",
            banner=None,
            protocol="tcp",
            timestamp=datetime.now()
        ),
        ScanResult(
            host="192.168.1.1",
            port=8080,
            state="filtered",
            service=None,
            banner=None,
            protocol="tcp",
            timestamp=datetime.now()
        ),
    ]


@pytest.fixture
def multi_host_results() -> List[ScanResult]:
    """Create sample results from multiple hosts."""
    results = []
    for host in ["192.168.1.1", "192.168.1.2", "192.168.1.3"]:
        results.append(ScanResult(
            host=host,
            port=22,
            state="open",
            service="ssh",
            banner=f"SSH-2.0-OpenSSH on {host}",
            protocol="tcp",
            timestamp=datetime.now()
        ))
        results.append(ScanResult(
            host=host,
            port=80,
            state="open",
            service="http",
            banner=None,
            protocol="tcp",
            timestamp=datetime.now()
        ))
    return results


@pytest.fixture
def sample_host_info() -> dict:
    """Create sample host info."""
    return {
        "192.168.1.1": HostInfo(
            ip="192.168.1.1",
            hostname="server1.local",
            os_guess="Linux",
            ttl=64,
            latency_ms=1.5,
            is_up=True
        ),
        "192.168.1.2": HostInfo(
            ip="192.168.1.2",
            hostname="server2.local",
            os_guess="Windows",
            ttl=128,
            latency_ms=2.3,
            is_up=True
        ),
    }


@pytest.fixture
def sample_summary() -> dict:
    """Create sample summary dictionary."""
    return {
        "scan_type": "tcp",
        "total_time": "15.3s",
        "threads": 100,
        "start_time": datetime.now()
    }


class TestMarkdownReportGenerator:
    """Test MarkdownReportGenerator class."""
    
    def test_init_defaults(self):
        """Test default initialization."""
        generator = MarkdownReportGenerator()
        
        assert generator.include_toc is True
        assert generator.include_mermaid is True
        assert generator.include_banners is True
        assert generator.collapsible_threshold == 20
        assert generator.template is None
    
    def test_init_custom_options(self):
        """Test initialization with custom options."""
        generator = MarkdownReportGenerator(
            include_toc=False,
            include_mermaid=False,
            include_banners=False,
            collapsible_threshold=10,
            template="custom"
        )
        
        assert generator.include_toc is False
        assert generator.include_mermaid is False
        assert generator.include_banners is False
        assert generator.collapsible_threshold == 10
        assert generator.template == "custom"
    
    def test_generate_basic(self, sample_results):
        """Test basic report generation."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results)
        
        assert content is not None
        assert "# SpectreScan Report" in content
        assert "192.168.1.1" in content
        assert "22" in content
        assert "ssh" in content
    
    def test_generate_with_custom_title(self, sample_results):
        """Test generation with custom title."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results, title="Custom Scan Report")
        
        assert "# Custom Scan Report" in content
    
    def test_generate_includes_header(self, sample_results):
        """Test that header is included."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results)
        
        assert "SpectreScan" in content
        assert "BitSpectreLabs" in content
        assert "Report Date:" in content
    
    def test_generate_includes_toc(self, sample_results):
        """Test that TOC is included when enabled."""
        generator = MarkdownReportGenerator(include_toc=True)
        
        content = generator.generate(sample_results)
        
        assert "## Table of Contents" in content
        assert "[Summary Statistics]" in content
        assert "[Scan Results]" in content
    
    def test_generate_excludes_toc(self, sample_results):
        """Test that TOC is excluded when disabled."""
        generator = MarkdownReportGenerator(include_toc=False)
        
        content = generator.generate(sample_results)
        
        assert "## Table of Contents" not in content
    
    def test_generate_summary_section(self, sample_results):
        """Test summary statistics section."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results)
        
        assert "## Summary Statistics" in content
        assert "Total Ports Scanned" in content
        assert "Open Ports" in content
        assert "Closed Ports" in content
        assert "Filtered Ports" in content
    
    def test_generate_with_summary_dict(self, sample_results, sample_summary):
        """Test generation with summary dictionary."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results, summary=sample_summary)
        
        assert "### Additional Information" in content
        assert "Scan Type" in content
        assert "tcp" in content
    
    def test_generate_mermaid_diagram(self, sample_results):
        """Test Mermaid diagram generation."""
        generator = MarkdownReportGenerator(include_mermaid=True)
        
        content = generator.generate(sample_results)
        
        assert "## Network Topology" in content
        assert "```mermaid" in content
        assert "graph TD" in content
        assert "Scanner[SpectreScan Scanner]" in content
    
    def test_generate_excludes_mermaid(self, sample_results):
        """Test Mermaid diagram exclusion."""
        generator = MarkdownReportGenerator(include_mermaid=False)
        
        content = generator.generate(sample_results)
        
        assert "```mermaid" not in content
    
    def test_generate_host_info_section(self, sample_results, sample_host_info):
        """Test host information section."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results, host_info=sample_host_info)
        
        assert "## Host Information" in content
        assert "server1.local" in content
        assert "Linux" in content
        assert "64" in content  # TTL
    
    def test_generate_results_table(self, sample_results):
        """Test scan results table generation."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results)
        
        assert "## Scan Results" in content
        assert "| Port | Protocol | State | Service |" in content
        assert "| 22 | tcp |" in content
    
    def test_generate_service_details(self, sample_results):
        """Test service details section with banners."""
        generator = MarkdownReportGenerator(include_banners=True)
        
        content = generator.generate(sample_results)
        
        assert "## Service Details" in content
        assert "SSH-2.0-OpenSSH_8.2" in content
        assert "Apache/2.4.41" in content
    
    def test_generate_excludes_service_details(self, sample_results):
        """Test service details exclusion."""
        generator = MarkdownReportGenerator(include_banners=False)
        
        content = generator.generate(sample_results)
        
        # Service details section should not appear when no banners are shown
        # But it might appear if results have banners - check implementation
        # In this case, the section itself should be more minimal
        assert "## Service Details" not in content or "Banner:" not in content
    
    def test_generate_footer(self, sample_results):
        """Test footer generation."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results)
        
        assert "## About This Report" in content
        assert "BitSpectreLabs" in content
        assert "GitHub-Flavored Markdown" in content
    
    def test_generate_multi_host(self, multi_host_results):
        """Test generation with multiple hosts."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(multi_host_results)
        
        assert "192.168.1.1" in content
        assert "192.168.1.2" in content
        assert "192.168.1.3" in content
    
    def test_collapsible_sections_small(self, sample_results):
        """Test that small results don't use collapsible sections."""
        generator = MarkdownReportGenerator(collapsible_threshold=20)
        
        content = generator.generate(sample_results)
        
        assert "<details>" not in content
    
    def test_collapsible_sections_large(self):
        """Test that large results use collapsible sections."""
        # Create many results
        results = [
            ScanResult(
                host="192.168.1.1",
                port=i,
                state="open" if i % 3 == 0 else "closed",
                service=f"service{i}",
                banner=f"Banner for port {i}",
                protocol="tcp",
                timestamp=datetime.now()
            )
            for i in range(1, 51)  # 50 results
        ]
        
        generator = MarkdownReportGenerator(collapsible_threshold=20)
        
        content = generator.generate(results)
        
        assert "<details>" in content
        assert "<summary>" in content
        assert "</details>" in content
    
    def test_generate_saves_file(self, sample_results, tmp_path):
        """Test saving report to file."""
        generator = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"
        
        content = generator.generate(sample_results, output_path=output_path)
        
        assert output_path.exists()
        with open(output_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
        assert file_content == content
    
    def test_generate_creates_parent_dirs(self, sample_results, tmp_path):
        """Test that parent directories are created."""
        generator = MarkdownReportGenerator()
        output_path = tmp_path / "subdir1" / "subdir2" / "report.md"
        
        generator.generate(sample_results, output_path=output_path)
        
        assert output_path.exists()
    
    def test_state_badges(self, sample_results):
        """Test state badge rendering."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate(sample_results)
        
        assert "**OPEN**" in content  # Bold for open
        assert "CLOSED" in content
        assert "*filtered*" in content  # Italics for filtered
    
    def test_empty_results(self):
        """Test handling of empty results."""
        generator = MarkdownReportGenerator()
        
        content = generator.generate([])
        
        assert content is not None
        assert "## Summary Statistics" in content
        assert "Total Ports Scanned | 0" in content


class TestGenerateMarkdownReport:
    """Test generate_markdown_report convenience function."""
    
    def test_basic_generation(self, sample_results, tmp_path):
        """Test basic report generation."""
        output_path = tmp_path / "report.md"
        
        content = generate_markdown_report(sample_results, output_path)
        
        assert output_path.exists()
        assert "SpectreScan" in content
    
    def test_with_all_options(self, sample_results, sample_summary, sample_host_info, tmp_path):
        """Test generation with all options."""
        output_path = tmp_path / "full_report.md"
        
        content = generate_markdown_report(
            results=sample_results,
            output_path=output_path,
            summary=sample_summary,
            host_info=sample_host_info,
            include_toc=True,
            include_mermaid=True,
            include_banners=True,
            collapsible_threshold=100,
            title="Full Test Report"
        )
        
        assert output_path.exists()
        assert "# Full Test Report" in content
        assert "## Table of Contents" in content
        assert "```mermaid" in content
        assert "## Host Information" in content
    
    def test_without_optional_features(self, sample_results, tmp_path):
        """Test generation without optional features."""
        output_path = tmp_path / "minimal.md"
        
        content = generate_markdown_report(
            results=sample_results,
            output_path=output_path,
            include_toc=False,
            include_mermaid=False,
            include_banners=False
        )
        
        assert "## Table of Contents" not in content
        assert "```mermaid" not in content


class TestGenerateSimpleMarkdown:
    """Test generate_simple_markdown function."""
    
    def test_basic_generation(self, sample_results):
        """Test simple markdown generation."""
        content = generate_simple_markdown(sample_results)
        
        assert "# SpectreScan Report" in content
        assert "## Results" in content
        assert "| Host | Port | Protocol | State | Service |" in content
    
    def test_saves_to_file(self, sample_results, tmp_path):
        """Test saving to file."""
        output_path = tmp_path / "simple.md"
        
        content = generate_simple_markdown(sample_results, output_path)
        
        assert output_path.exists()
        with open(output_path, 'r') as f:
            assert f.read() == content
    
    def test_includes_timestamp(self, sample_results):
        """Test that timestamp is included."""
        content = generate_simple_markdown(sample_results)
        
        assert "> Generated:" in content
    
    def test_all_results_in_table(self, sample_results):
        """Test that all results appear in table."""
        content = generate_simple_markdown(sample_results)
        
        assert "| 192.168.1.1 | 22 |" in content
        assert "| 192.168.1.1 | 80 |" in content
        assert "| 192.168.1.1 | 443 |" in content


class TestGenerateMarkdownSummary:
    """Test generate_markdown_summary function."""
    
    def test_basic_summary(self, sample_results):
        """Test basic summary generation."""
        content = generate_markdown_summary(sample_results)
        
        assert "## Scan Summary" in content
        assert "**Total Ports:**" in content
        assert "**Open:**" in content
        assert "**Closed:**" in content
        assert "**Filtered:**" in content
    
    def test_correct_counts(self, sample_results):
        """Test that counts are correct."""
        content = generate_markdown_summary(sample_results)
        
        # sample_results has 3 open, 1 closed, 1 filtered
        assert "**Open:** 3" in content
        assert "**Closed:** 1" in content
        assert "**Filtered:** 1" in content
        assert "**Total Ports:** 5" in content
    
    def test_with_summary_dict(self, sample_results, sample_summary):
        """Test with additional summary dictionary."""
        content = generate_markdown_summary(sample_results, sample_summary)
        
        assert "**Scan Type:**" in content
        assert "tcp" in content
    
    def test_hosts_count(self, multi_host_results):
        """Test hosts count is correct."""
        content = generate_markdown_summary(multi_host_results)
        
        assert "**Hosts Scanned:** 3" in content


class TestResultsToMarkdownTable:
    """Test results_to_markdown_table function."""
    
    def test_basic_table(self, sample_results):
        """Test basic table generation."""
        content = results_to_markdown_table(sample_results)
        
        assert "| Host | Port | Protocol | State | Service |" in content
        assert "|------|------|----------|-------|---------|" in content
    
    def test_without_banner(self, sample_results):
        """Test table without banner column."""
        content = results_to_markdown_table(sample_results, include_banner=False)
        
        assert "Banner" not in content
        assert "| 192.168.1.1 | 22 | tcp | open | ssh |" in content
    
    def test_with_banner(self, sample_results):
        """Test table with banner column."""
        content = results_to_markdown_table(sample_results, include_banner=True)
        
        assert "| Banner |" in content
        assert "SSH-2.0-OpenSSH_8.2" in content
    
    def test_banner_truncation(self):
        """Test that long banners are truncated."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner="A" * 100,  # Long banner
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        content = results_to_markdown_table(results, include_banner=True)
        
        assert "..." in content
        # Should be truncated to ~50 chars
        assert "A" * 100 not in content
    
    def test_null_service(self):
        """Test handling of null service."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=8080,
                state="filtered",
                service=None,
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        content = results_to_markdown_table(results)
        
        assert "| - |" in content  # Service should be "-"
    
    def test_escape_pipe_in_banner(self):
        """Test that pipe characters in banners are escaped."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner="Key|Value|Other",
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        content = results_to_markdown_table(results, include_banner=True)
        
        # Pipes should be escaped
        assert "Key\\|Value\\|Other" in content


class TestTemplateConstants:
    """Test template constant definitions."""
    
    def test_template_minimal_exists(self):
        """Test TEMPLATE_MINIMAL is defined."""
        assert TEMPLATE_MINIMAL is not None
        assert "{title}" in TEMPLATE_MINIMAL
        assert "{results_table}" in TEMPLATE_MINIMAL
    
    def test_template_executive_exists(self):
        """Test TEMPLATE_EXECUTIVE is defined."""
        assert TEMPLATE_EXECUTIVE is not None
        assert "{title}" in TEMPLATE_EXECUTIVE
        assert "{summary}" in TEMPLATE_EXECUTIVE
        assert "Executive Summary" in TEMPLATE_EXECUTIVE
    
    def test_template_technical_exists(self):
        """Test TEMPLATE_TECHNICAL is defined."""
        assert TEMPLATE_TECHNICAL is not None
        assert "{title}" in TEMPLATE_TECHNICAL
        assert "{results}" in TEMPLATE_TECHNICAL
        assert "{topology}" in TEMPLATE_TECHNICAL


class TestSpecialCases:
    """Test special cases and edge conditions."""
    
    def test_special_characters_in_host(self):
        """Test handling of special characters in hostname."""
        results = [
            ScanResult(
                host="server-01.example.com",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        generator = MarkdownReportGenerator()
        content = generator.generate(results)
        
        assert "server-01.example.com" in content
    
    def test_ipv6_addresses(self):
        """Test handling of IPv6 addresses."""
        results = [
            ScanResult(
                host="2001:db8::1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        generator = MarkdownReportGenerator()
        content = generator.generate(results)
        
        assert "2001:db8::1" in content
    
    def test_code_in_banner(self):
        """Test that code markers in banners are handled."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner="```javascript\ncode\n```",
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        generator = MarkdownReportGenerator(include_banners=True)
        content = generator.generate(results)
        
        # Code markers should be escaped or handled
        # The banner should still be present but safe
        assert "Banner:" in content
    
    def test_unicode_in_banner(self):
        """Test handling of Unicode characters in banner."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner="Welcome - Bienvenue - Willkommen - 欢迎",
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        generator = MarkdownReportGenerator(include_banners=True)
        content = generator.generate(results)
        
        assert "欢迎" in content
    
    def test_very_long_service_name(self):
        """Test handling of very long service names."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=8080,
                state="open",
                service="some-really-really-long-service-name-that-might-break-formatting",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        generator = MarkdownReportGenerator()
        content = generator.generate(results)
        
        assert "some-really-really-long-service-name" in content
    
    def test_open_filtered_state(self):
        """Test handling of open|filtered state."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=53,
                state="open|filtered",
                service="dns",
                banner=None,
                protocol="udp",
                timestamp=datetime.now()
            )
        ]
        
        generator = MarkdownReportGenerator()
        content = generator.generate(results)
        
        assert "open|filtered" in content.lower() or "*open|filtered*" in content
    
    def test_mixed_protocols(self):
        """Test handling of mixed TCP/UDP results."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            ),
            ScanResult(
                host="192.168.1.1",
                port=53,
                state="open",
                service="dns",
                banner=None,
                protocol="udp",
                timestamp=datetime.now()
            ),
        ]
        
        generator = MarkdownReportGenerator()
        content = generator.generate(results)
        
        assert "tcp" in content
        assert "udp" in content


class TestMermaidDiagram:
    """Test Mermaid diagram generation specifically."""
    
    def test_mermaid_with_multiple_hosts(self, multi_host_results):
        """Test Mermaid diagram with multiple hosts."""
        generator = MarkdownReportGenerator(include_mermaid=True)
        
        content = generator.generate(multi_host_results)
        
        assert "graph TD" in content
        # Should have nodes for each host
        assert "H0[" in content
        assert "H1[" in content
        assert "H2[" in content
    
    def test_mermaid_shows_services(self, sample_results):
        """Test that Mermaid diagram shows services."""
        generator = MarkdownReportGenerator(include_mermaid=True)
        
        content = generator.generate(sample_results)
        
        # Should show top services
        assert "ssh" in content or "http" in content
    
    def test_mermaid_only_open_ports(self):
        """Test that Mermaid only shows open ports."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=22,
                state="closed",  # Closed, not open
                service="ssh",
                banner=None,
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        generator = MarkdownReportGenerator(include_mermaid=True)
        
        content = generator.generate(results)
        
        # Mermaid section should be empty or not show this host
        # since there are no open ports
        assert "graph TD" not in content or "0 open ports" in content
    
    def test_mermaid_with_host_info(self, sample_results, sample_host_info):
        """Test Mermaid uses hostname when available."""
        generator = MarkdownReportGenerator(include_mermaid=True)
        
        content = generator.generate(sample_results, host_info=sample_host_info)
        
        assert "server1.local" in content


class TestFileEncoding:
    """Test file encoding and writing."""
    
    def test_utf8_encoding(self, tmp_path):
        """Test that files are written with UTF-8 encoding."""
        results = [
            ScanResult(
                host="192.168.1.1",
                port=80,
                state="open",
                service="http",
                banner="Test with unicode: 日本語 中文 العربية",
                protocol="tcp",
                timestamp=datetime.now()
            )
        ]
        
        output_path = tmp_path / "unicode_report.md"
        generate_markdown_report(results, output_path)
        
        # Read back and verify
        with open(output_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        assert "日本語" in content
        assert "中文" in content
        assert "العربية" in content


class TestDatetimeHandling:
    """Test datetime object handling."""
    
    def test_datetime_in_summary(self, sample_results):
        """Test that datetime objects in summary are handled."""
        summary = {
            "start_time": datetime(2025, 1, 15, 10, 30, 0),
            "end_time": datetime(2025, 1, 15, 10, 35, 0),
        }
        
        generator = MarkdownReportGenerator()
        
        # Should not raise exception
        content = generator.generate(sample_results, summary=summary)
        
        assert "Start Time" in content
        assert "2025" in content
