"""
Tests for DNS Enumeration Module.

Tests comprehensive DNS enumeration functionality including forward/reverse
lookups, subdomain enumeration, zone transfer attempts, and wildcard detection.

by BitSpectreLabs
"""

import json
import socket
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest

# Import DNS classes for use in tests
from spectrescan.core.dns_enum import (
    DNSEnumerator,
    DNSRecord,
    DNSRecordType,
    DNSEnumerationResult,
    SubdomainResult,
    ZoneTransferResult,
    format_dns_report,
)


# ============================================================================
# Test Data Structures
# ============================================================================

class TestDNSRecordType:
    """Tests for DNSRecordType enum."""
    
    def test_record_type_values(self):
        """Test DNS record type values."""
        assert DNSRecordType.A.value == "A"
        assert DNSRecordType.AAAA.value == "AAAA"
        assert DNSRecordType.CNAME.value == "CNAME"
        assert DNSRecordType.MX.value == "MX"
        assert DNSRecordType.TXT.value == "TXT"
        assert DNSRecordType.NS.value == "NS"
        assert DNSRecordType.SOA.value == "SOA"
        assert DNSRecordType.PTR.value == "PTR"
        assert DNSRecordType.SRV.value == "SRV"
        assert DNSRecordType.CAA.value == "CAA"
    
    def test_record_type_string_enum(self):
        """Test that DNSRecordType is a string enum."""
        assert isinstance(DNSRecordType.A, str)
        assert DNSRecordType.A.value == "A"


class TestDNSRecord:
    """Tests for DNSRecord dataclass."""
    
    def test_dns_record_creation(self):
        """Test creating a DNS record."""
        record = DNSRecord(
            name="example.com",
            record_type="A",
            value="93.184.216.34",
            ttl=3600,
        )
        
        assert record.name == "example.com"
        assert record.record_type == "A"
        assert record.value == "93.184.216.34"
        assert record.ttl == 3600
        assert record.priority is None
        assert record.timestamp is not None
    
    def test_dns_record_with_priority(self):
        """Test MX record with priority."""
        record = DNSRecord(
            name="example.com",
            record_type="MX",
            value="mail.example.com",
            ttl=3600,
            priority=10,
        )
        
        assert record.priority == 10
    
    def test_dns_record_to_dict(self):
        """Test DNS record serialization."""
        record = DNSRecord(
            name="example.com",
            record_type="MX",
            value="mail.example.com",
            ttl=3600,
            priority=10,
        )
        
        data = record.to_dict()
        
        assert data["name"] == "example.com"
        assert data["record_type"] == "MX"
        assert data["value"] == "mail.example.com"
        assert data["ttl"] == 3600
        assert data["priority"] == 10
        assert "timestamp" in data


class TestSubdomainResult:
    """Tests for SubdomainResult dataclass."""
    
    def test_subdomain_result_creation(self):
        """Test creating subdomain result."""
        result = SubdomainResult(
            subdomain="www",
            full_domain="www.example.com",
            ip_addresses=["93.184.216.34"],
        )
        
        assert result.subdomain == "www"
        assert result.full_domain == "www.example.com"
        assert result.ip_addresses == ["93.184.216.34"]
        assert result.cname is None
        assert result.is_wildcard is False
    
    def test_subdomain_result_with_cname(self):
        """Test subdomain with CNAME."""
        result = SubdomainResult(
            subdomain="blog",
            full_domain="blog.example.com",
            ip_addresses=["1.2.3.4"],
            cname="blog.example.wordpress.com",
        )
        
        assert result.cname == "blog.example.wordpress.com"
    
    def test_subdomain_result_to_dict(self):
        """Test subdomain result serialization."""
        result = SubdomainResult(
            subdomain="api",
            full_domain="api.example.com",
            ip_addresses=["10.0.0.1", "10.0.0.2"],
        )
        
        data = result.to_dict()
        
        assert data["subdomain"] == "api"
        assert data["full_domain"] == "api.example.com"
        assert data["ip_addresses"] == ["10.0.0.1", "10.0.0.2"]


class TestZoneTransferResult:
    """Tests for ZoneTransferResult dataclass."""
    
    def test_zone_transfer_success(self):
        """Test successful zone transfer result."""
        records = [
            DNSRecord(name="example.com", record_type="A", value="93.184.216.34", ttl=3600),
            DNSRecord(name="www.example.com", record_type="A", value="93.184.216.34", ttl=3600),
        ]
        
        result = ZoneTransferResult(
            domain="example.com",
            nameserver="ns1.example.com",
            success=True,
            records=records,
        )
        
        assert result.success is True
        assert len(result.records) == 2
        assert result.error_message is None
    
    def test_zone_transfer_failure(self):
        """Test failed zone transfer result."""
        result = ZoneTransferResult(
            domain="example.com",
            nameserver="ns1.example.com",
            success=False,
            error_message="Zone transfer refused",
        )
        
        assert result.success is False
        assert result.error_message == "Zone transfer refused"
        assert len(result.records) == 0
    
    def test_zone_transfer_to_dict(self):
        """Test zone transfer result serialization."""
        result = ZoneTransferResult(
            domain="example.com",
            nameserver="ns1.example.com",
            success=False,
            error_message="Refused",
        )
        
        data = result.to_dict()
        
        assert data["domain"] == "example.com"
        assert data["nameserver"] == "ns1.example.com"
        assert data["success"] is False
        assert data["error_message"] == "Refused"


class TestDNSEnumerationResult:
    """Tests for DNSEnumerationResult dataclass."""
    
    def test_enumeration_result_creation(self):
        """Test creating enumeration result."""
        result = DNSEnumerationResult(domain="example.com")
        
        assert result.domain == "example.com"
        assert result.records == {}
        assert result.subdomains == []
        assert result.zone_transfers == []
        assert result.has_wildcard is False
        assert result.wildcard_ips == []
        assert result.nameservers == []
        assert result.mail_servers == []
        assert result.errors == []
    
    def test_enumeration_result_total_records(self):
        """Test total records property."""
        result = DNSEnumerationResult(domain="example.com")
        result.records = {
            "A": [
                DNSRecord(name="example.com", record_type="A", value="1.2.3.4", ttl=300),
                DNSRecord(name="www.example.com", record_type="A", value="1.2.3.4", ttl=300),
            ],
            "MX": [
                DNSRecord(name="example.com", record_type="MX", value="mail.example.com", ttl=300, priority=10),
            ],
        }
        
        assert result.total_records == 3
    
    def test_enumeration_result_unique_ips(self):
        """Test unique IPs property."""
        result = DNSEnumerationResult(domain="example.com")
        result.records = {
            "A": [
                DNSRecord(name="example.com", record_type="A", value="1.2.3.4", ttl=300),
                DNSRecord(name="www.example.com", record_type="A", value="1.2.3.5", ttl=300),
            ],
            "AAAA": [
                DNSRecord(name="example.com", record_type="AAAA", value="2001:db8::1", ttl=300),
            ],
        }
        result.subdomains = [
            SubdomainResult(subdomain="api", full_domain="api.example.com", ip_addresses=["1.2.3.6", "1.2.3.4"]),
        ]
        
        unique = result.unique_ips
        
        assert len(unique) == 4
        assert "1.2.3.4" in unique
        assert "1.2.3.5" in unique
        assert "1.2.3.6" in unique
        assert "2001:db8::1" in unique
    
    def test_enumeration_result_duration(self):
        """Test duration calculation."""
        result = DNSEnumerationResult(domain="example.com")
        result.start_time = datetime(2025, 1, 1, 12, 0, 0)
        result.end_time = datetime(2025, 1, 1, 12, 0, 15)
        
        assert result.duration == 15.0
    
    def test_enumeration_result_to_dict(self):
        """Test full serialization."""
        result = DNSEnumerationResult(domain="example.com")
        result.records = {
            "A": [DNSRecord(name="example.com", record_type="A", value="1.2.3.4", ttl=300)],
        }
        result.nameservers = ["ns1.example.com"]
        result.end_time = datetime.now()
        
        data = result.to_dict()
        
        assert data["domain"] == "example.com"
        assert "records" in data
        assert "statistics" in data
        assert data["statistics"]["total_records"] == 1


# ============================================================================
# Test DNSEnumerator Class
# ============================================================================

class TestDNSEnumeratorInit:
    """Tests for DNSEnumerator initialization."""
    
    def test_init_default_values(self):
        """Test default initialization values."""
        enumerator = DNSEnumerator()
        
        assert enumerator.timeout == 5.0
        assert enumerator.threads == 50
        assert enumerator.retries == 2
    
    def test_init_custom_values(self):
        """Test custom initialization values."""
        enumerator = DNSEnumerator(
            timeout=10.0,
            threads=100,
            retries=3,
        )
        
        assert enumerator.timeout == 10.0
        assert enumerator.threads == 100
        assert enumerator.retries == 3
    
    def test_init_custom_nameservers(self):
        """Test initialization with custom nameservers."""
        enumerator = DNSEnumerator(nameservers=["8.8.8.8", "8.8.4.4"])
        
        assert enumerator.resolver.nameservers == ["8.8.8.8", "8.8.4.4"]
    
    def test_stop_and_reset(self):
        """Test stop and reset functionality."""
        enumerator = DNSEnumerator()
        
        assert not enumerator._stop_event.is_set()
        
        enumerator.stop()
        assert enumerator._stop_event.is_set()
        
        enumerator.reset()
        assert not enumerator._stop_event.is_set()


class TestDNSEnumeratorLookups:
    """Tests for DNS lookup methods."""
    
    @patch('dns.resolver.Resolver.resolve')
    def test_lookup_a_record(self, mock_resolve):
        """Test A record lookup."""
        # Mock DNS response
        mock_rdata = Mock()
        mock_rdata.__str__ = lambda self: "93.184.216.34"
        
        mock_rrset = Mock()
        mock_rrset.ttl = 3600
        
        mock_answer = Mock()
        mock_answer.__iter__ = lambda self: iter([mock_rdata])
        mock_answer.rrset = mock_rrset
        mock_resolve.return_value = mock_answer
        
        enumerator = DNSEnumerator()
        records = enumerator._lookup("example.com", DNSRecordType.A)
        
        assert len(records) == 1
        assert records[0].name == "example.com"
        assert records[0].record_type == "A"
        assert records[0].value == "93.184.216.34"
        assert records[0].ttl == 3600
    
    @patch('dns.resolver.Resolver.resolve')
    def test_lookup_mx_record(self, mock_resolve):
        """Test MX record lookup with priority."""
        mock_rdata = Mock()
        mock_rdata.__str__ = lambda self: "10 mail.example.com."
        mock_rdata.preference = 10
        mock_rdata.exchange = Mock()
        mock_rdata.exchange.__str__ = lambda self: "mail.example.com."
        
        mock_rrset = Mock()
        mock_rrset.ttl = 3600
        
        mock_answer = Mock()
        mock_answer.__iter__ = lambda self: iter([mock_rdata])
        mock_answer.rrset = mock_rrset
        mock_resolve.return_value = mock_answer
        
        enumerator = DNSEnumerator()
        records = enumerator._lookup("example.com", DNSRecordType.MX)
        
        assert len(records) == 1
        assert records[0].record_type == "MX"
        assert records[0].priority == 10
        assert records[0].value == "mail.example.com"
    
    @patch('dns.resolver.Resolver.resolve')
    def test_lookup_nxdomain(self, mock_resolve):
        """Test lookup for non-existent domain."""
        import dns.resolver
        
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        
        enumerator = DNSEnumerator()
        records = enumerator._lookup("nonexistent.example.com", DNSRecordType.A)
        
        assert len(records) == 0
    
    @patch('dns.resolver.Resolver.resolve')
    def test_lookup_timeout(self, mock_resolve):
        """Test lookup timeout handling."""
        import dns.exception
        
        mock_resolve.side_effect = dns.exception.Timeout()
        
        enumerator = DNSEnumerator()
        records = enumerator._lookup("example.com", DNSRecordType.A)
        
        assert len(records) == 0
    
    @patch('dns.reversename.from_address')
    @patch('dns.resolver.Resolver.resolve')
    def test_reverse_lookup(self, mock_resolve, mock_from_address):
        """Test reverse DNS lookup."""
        mock_from_address.return_value = "34.216.184.93.in-addr.arpa."
        
        mock_rdata = Mock()
        mock_rdata.__str__ = lambda self: "example.com."
        
        mock_rrset = Mock()
        mock_rrset.ttl = 3600
        
        mock_answer = Mock()
        mock_answer.__iter__ = lambda self: iter([mock_rdata])
        mock_answer.rrset = mock_rrset
        mock_resolve.return_value = mock_answer
        
        enumerator = DNSEnumerator()
        records = enumerator._reverse_lookup("93.184.216.34")
        
        assert len(records) == 1
        assert records[0].record_type == "PTR"
        assert records[0].name == "93.184.216.34"
        assert records[0].value == "example.com"


class TestDNSEnumeratorZoneTransfer:
    """Tests for zone transfer functionality."""
    
    @patch('dns.zone.from_xfr')
    @patch('dns.query.xfr')
    @patch('dns.resolver.Resolver.resolve')
    def test_zone_transfer_success(self, mock_resolve, mock_xfr, mock_from_xfr):
        """Test successful zone transfer."""
        import dns.rdatatype
        
        # Mock nameserver resolution
        mock_ns_answer = Mock()
        mock_ns_answer.__getitem__ = lambda self, i: Mock(__str__=lambda s: "93.184.216.1")
        mock_resolve.return_value = mock_ns_answer
        
        # Mock zone data
        mock_node = Mock()
        mock_rdataset = Mock()
        mock_rdataset.rdtype = 1  # A record
        mock_rdataset.ttl = 3600
        mock_rdataset.__iter__ = lambda s: iter([Mock(__str__=lambda x: "93.184.216.34")])
        mock_node.rdatasets = [mock_rdataset]
        
        mock_zone = Mock()
        mock_zone.nodes.items.return_value = [("@", mock_node)]
        mock_from_xfr.return_value = mock_zone
        
        enumerator = DNSEnumerator()
        result = enumerator._zone_transfer("example.com", "ns1.example.com")
        
        assert result.success is True
        assert result.domain == "example.com"
        assert result.nameserver == "ns1.example.com"
    
    @patch('dns.query.xfr')
    def test_zone_transfer_refused(self, mock_xfr):
        """Test zone transfer refused."""
        import dns.exception
        
        mock_xfr.side_effect = dns.exception.FormError()
        
        enumerator = DNSEnumerator()
        result = enumerator._zone_transfer("example.com", "93.184.216.1")
        
        assert result.success is False
        assert "refused" in result.error_message.lower()
    
    @patch('dns.query.xfr')
    def test_zone_transfer_timeout(self, mock_xfr):
        """Test zone transfer timeout."""
        import dns.exception
        
        mock_xfr.side_effect = dns.exception.Timeout()
        
        enumerator = DNSEnumerator()
        result = enumerator._zone_transfer("example.com", "93.184.216.1")
        
        assert result.success is False
        assert "timed out" in result.error_message.lower() or "timeout" in result.error_message.lower()


class TestDNSEnumeratorWildcard:
    """Tests for wildcard detection."""
    
    @patch('dns.resolver.Resolver.resolve')
    def test_wildcard_detected(self, mock_resolve):
        """Test wildcard DNS detection."""
        # Mock wildcard response
        mock_rdata = Mock()
        mock_rdata.__str__ = lambda self: "10.0.0.1"
        
        mock_answer = Mock()
        mock_answer.__iter__ = lambda self: iter([mock_rdata])
        mock_resolve.return_value = mock_answer
        
        enumerator = DNSEnumerator()
        detected, ips = enumerator._detect_wildcard("example.com")
        
        assert detected is True
        assert "10.0.0.1" in ips
    
    @patch('dns.resolver.Resolver.resolve')
    def test_no_wildcard(self, mock_resolve):
        """Test no wildcard DNS."""
        import dns.resolver
        
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()
        
        enumerator = DNSEnumerator()
        detected, ips = enumerator._detect_wildcard("example.com")
        
        assert detected is False
        assert len(ips) == 0


class TestDNSEnumeratorWordlist:
    """Tests for wordlist handling."""
    
    def test_get_default_subdomains(self):
        """Test default subdomain list."""
        enumerator = DNSEnumerator()
        subdomains = enumerator._get_default_subdomains()
        
        assert len(subdomains) > 50
        assert "www" in subdomains
        assert "mail" in subdomains
        assert "api" in subdomains
        assert "admin" in subdomains
    
    def test_load_wordlist_custom(self, tmp_path):
        """Test loading custom wordlist."""
        # Create custom wordlist
        wordlist = tmp_path / "custom.txt"
        wordlist.write_text("custom1\ncustom2\n# comment\ncustom3")
        
        enumerator = DNSEnumerator()
        words = enumerator._load_wordlist(wordlist)
        
        assert len(words) == 3
        assert "custom1" in words
        assert "custom2" in words
        assert "custom3" in words
    
    def test_load_wordlist_fallback(self, tmp_path):
        """Test fallback to default subdomains."""
        enumerator = DNSEnumerator()
        # Non-existent wordlist
        words = enumerator._load_wordlist(tmp_path / "nonexistent.txt")
        
        # Should fall back to defaults
        assert len(words) > 50


class TestDNSEnumeratorSubdomains:
    """Tests for subdomain enumeration."""
    
    @patch('dns.resolver.Resolver.resolve')
    def test_enumerate_subdomains(self, mock_resolve):
        """Test subdomain enumeration."""
        import dns.resolver
        
        def resolve_side_effect(domain, rtype):
            if domain == "www.example.com" and rtype == "A":
                mock_rdata = Mock()
                mock_rdata.__str__ = lambda self: "93.184.216.34"
                mock_rrset = Mock()
                mock_rrset.ttl = 3600
                mock_answer = Mock()
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                mock_answer.rrset = mock_rrset
                return mock_answer
            elif domain == "mail.example.com" and rtype == "A":
                mock_rdata = Mock()
                mock_rdata.__str__ = lambda self: "93.184.216.35"
                mock_rrset = Mock()
                mock_rrset.ttl = 3600
                mock_answer = Mock()
                mock_answer.__iter__ = lambda self: iter([mock_rdata])
                mock_answer.rrset = mock_rrset
                return mock_answer
            else:
                raise dns.resolver.NXDOMAIN()
        
        mock_resolve.side_effect = resolve_side_effect
        
        enumerator = DNSEnumerator(threads=2)
        results = enumerator._enumerate_subdomains(
            domain="example.com",
            words=["www", "mail", "ftp", "api"],
            wildcard_ips=[],
        )
        
        assert len(results) == 2
        subdomains = [r.subdomain for r in results]
        assert "www" in subdomains
        assert "mail" in subdomains
    
    @patch('dns.resolver.Resolver.resolve')
    def test_enumerate_subdomains_wildcard_filter(self, mock_resolve):
        """Test subdomain enumeration filters wildcards."""
        # All responses return wildcard IP
        mock_rdata = Mock()
        mock_rdata.__str__ = lambda self: "10.0.0.1"
        mock_rrset = Mock()
        mock_rrset.ttl = 3600
        mock_answer = Mock()
        mock_answer.__iter__ = lambda self: iter([mock_rdata])
        mock_answer.rrset = mock_rrset
        mock_resolve.return_value = mock_answer
        
        enumerator = DNSEnumerator(threads=2)
        results = enumerator._enumerate_subdomains(
            domain="example.com",
            words=["www", "mail"],
            wildcard_ips=["10.0.0.1"],  # Filter out this IP
        )
        
        assert len(results) == 0


class TestDNSEnumeratorIntegration:
    """Integration tests for DNSEnumerator."""
    
    @patch.object(DNSEnumerator, '_lookup')
    @patch.object(DNSEnumerator, '_detect_wildcard')
    def test_enumerate_basic(self, mock_wildcard, mock_lookup):
        """Test basic enumeration flow."""
        # Mock methods
        mock_wildcard.return_value = (False, [])
        
        def lookup_side_effect(domain, rtype):
            if rtype == DNSRecordType.A:
                return [DNSRecord(name=domain, record_type="A", value="93.184.216.34", ttl=3600)]
            elif rtype == DNSRecordType.NS:
                return [DNSRecord(name=domain, record_type="NS", value="ns1.example.com", ttl=3600)]
            return []
        
        mock_lookup.side_effect = lookup_side_effect
        
        enumerator = DNSEnumerator()
        result = enumerator.enumerate("example.com")
        
        assert result.domain == "example.com"
        assert result.total_records > 0
        assert "ns1.example.com" in result.nameservers
    
    def test_enumerate_stop(self):
        """Test enumeration can be stopped."""
        enumerator = DNSEnumerator()
        enumerator.stop()
        
        result = enumerator.enumerate("example.com")
        
        # Should return early with minimal processing
        assert result.domain == "example.com"


class TestDNSEnumeratorHelpers:
    """Tests for helper methods."""
    
    def test_is_ip_ipv4(self):
        """Test IPv4 detection."""
        enumerator = DNSEnumerator()
        
        assert enumerator._is_ip("192.168.1.1") is True
        assert enumerator._is_ip("10.0.0.1") is True
        assert enumerator._is_ip("255.255.255.255") is True
    
    def test_is_ip_ipv6(self):
        """Test IPv6 detection."""
        enumerator = DNSEnumerator()
        
        assert enumerator._is_ip("2001:db8::1") is True
        assert enumerator._is_ip("::1") is True
        assert enumerator._is_ip("fe80::1") is True
    
    def test_is_ip_hostname(self):
        """Test hostname is not IP."""
        enumerator = DNSEnumerator()
        
        assert enumerator._is_ip("example.com") is False
        assert enumerator._is_ip("ns1.example.com") is False
    
    @patch('dns.resolver.Resolver.resolve')
    def test_lookup_all(self, mock_resolve):
        """Test lookup_all convenience method."""
        mock_rdata = Mock()
        mock_rdata.__str__ = lambda self: "93.184.216.34"
        mock_rrset = Mock()
        mock_rrset.ttl = 3600
        mock_answer = Mock()
        mock_answer.__iter__ = lambda self: iter([mock_rdata])
        mock_answer.rrset = mock_rrset
        mock_resolve.return_value = mock_answer
        
        enumerator = DNSEnumerator()
        results = enumerator.lookup_all("example.com")
        
        assert isinstance(results, dict)
    
    @patch.object(DNSEnumerator, '_reverse_lookup')
    def test_reverse_lookup_helper(self, mock_reverse):
        """Test reverse_lookup convenience method."""
        mock_reverse.return_value = [
            DNSRecord(name="93.184.216.34", record_type="PTR", value="example.com", ttl=3600)
        ]
        
        enumerator = DNSEnumerator()
        hostname = enumerator.reverse_lookup("93.184.216.34")
        
        assert hostname == "example.com"
    
    @patch.object(DNSEnumerator, '_lookup')
    def test_get_nameservers(self, mock_lookup):
        """Test get_nameservers convenience method."""
        mock_lookup.return_value = [
            DNSRecord(name="example.com", record_type="NS", value="ns1.example.com", ttl=3600),
            DNSRecord(name="example.com", record_type="NS", value="ns2.example.com", ttl=3600),
        ]
        
        enumerator = DNSEnumerator()
        nameservers = enumerator.get_nameservers("example.com")
        
        assert len(nameservers) == 2
        assert "ns1.example.com" in nameservers
        assert "ns2.example.com" in nameservers
    
    @patch.object(DNSEnumerator, '_lookup')
    def test_get_mail_servers(self, mock_lookup):
        """Test get_mail_servers convenience method."""
        mock_lookup.return_value = [
            DNSRecord(name="example.com", record_type="MX", value="mail1.example.com", ttl=3600, priority=10),
            DNSRecord(name="example.com", record_type="MX", value="mail2.example.com", ttl=3600, priority=20),
        ]
        
        enumerator = DNSEnumerator()
        mail_servers = enumerator.get_mail_servers("example.com")
        
        assert len(mail_servers) == 2
        assert (10, "mail1.example.com") in mail_servers
        assert (20, "mail2.example.com") in mail_servers


# ============================================================================
# Test Report Formatting
# ============================================================================

class TestFormatDNSReport:
    """Tests for DNS report formatting."""
    
    def test_format_basic_report(self):
        """Test basic report formatting."""
        result = DNSEnumerationResult(domain="example.com")
        result.records = {
            "A": [DNSRecord(name="example.com", record_type="A", value="93.184.216.34", ttl=3600)],
        }
        result.nameservers = ["ns1.example.com"]
        result.end_time = datetime.now()
        
        report = format_dns_report(result)
        
        assert "DNS ENUMERATION REPORT" in report
        assert "example.com" in report
        assert "93.184.216.34" in report
        assert "ns1.example.com" in report
        assert "BitSpectreLabs" in report
    
    def test_format_report_with_subdomains(self):
        """Test report with subdomains."""
        result = DNSEnumerationResult(domain="example.com")
        result.subdomains = [
            SubdomainResult(subdomain="www", full_domain="www.example.com", ip_addresses=["1.2.3.4"]),
            SubdomainResult(subdomain="api", full_domain="api.example.com", ip_addresses=["1.2.3.5"]),
        ]
        result.end_time = datetime.now()
        
        report = format_dns_report(result)
        
        assert "DISCOVERED SUBDOMAINS" in report
        assert "www.example.com" in report
        assert "api.example.com" in report
    
    def test_format_report_with_zone_transfers(self):
        """Test report with zone transfer results."""
        result = DNSEnumerationResult(domain="example.com")
        result.zone_transfers = [
            ZoneTransferResult(domain="example.com", nameserver="ns1.example.com", success=True),
            ZoneTransferResult(domain="example.com", nameserver="ns2.example.com", success=False, error_message="Refused"),
        ]
        result.end_time = datetime.now()
        
        report = format_dns_report(result)
        
        assert "ZONE TRANSFER" in report
        assert "SUCCESS" in report
        assert "FAILED" in report
    
    def test_format_report_with_wildcard(self):
        """Test report with wildcard detection."""
        result = DNSEnumerationResult(domain="example.com")
        result.has_wildcard = True
        result.wildcard_ips = ["10.0.0.1", "10.0.0.2"]
        result.end_time = datetime.now()
        
        report = format_dns_report(result)
        
        assert "Wildcard DNS: Yes" in report
        assert "10.0.0.1" in report
    
    def test_format_report_with_errors(self):
        """Test report with errors."""
        result = DNSEnumerationResult(domain="example.com")
        result.errors = ["Connection timeout", "DNS server unreachable"]
        result.end_time = datetime.now()
        
        report = format_dns_report(result)
        
        assert "ERRORS" in report
        assert "Connection timeout" in report


# ============================================================================
# Test Built-in Wordlists
# ============================================================================

class TestBuiltinWordlists:
    """Tests for built-in wordlist files."""
    
    def test_small_wordlist_exists(self):
        """Test small wordlist file exists."""
        wordlist = Path(__file__).parent.parent / "data" / "subdomains-small.txt"
        assert wordlist.exists()
    
    def test_small_wordlist_content(self):
        """Test small wordlist has content."""
        wordlist = Path(__file__).parent.parent / "data" / "subdomains-small.txt"
        content = wordlist.read_text()
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        
        assert len(lines) >= 50
        assert "www" in lines
        assert "mail" in lines
    
    def test_medium_wordlist_exists(self):
        """Test medium wordlist file exists."""
        wordlist = Path(__file__).parent.parent / "data" / "subdomains-medium.txt"
        assert wordlist.exists()
    
    def test_medium_wordlist_content(self):
        """Test medium wordlist has content."""
        wordlist = Path(__file__).parent.parent / "data" / "subdomains-medium.txt"
        content = wordlist.read_text()
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        
        assert len(lines) >= 200


# ============================================================================
# Test Module Availability
# ============================================================================

class TestModuleAvailability:
    """Tests for module availability checks."""
    
    def test_dnspython_available(self):
        """Test dnspython is available."""
        from spectrescan.core.dns_enum import DNSPYTHON_AVAILABLE
        
        assert DNSPYTHON_AVAILABLE is True
    
    def test_exports(self):
        """Test module exports."""
        # Classes already imported at module level
        assert DNSEnumerator is not None
        assert DNSRecord is not None
        assert DNSRecordType is not None


# ============================================================================
# Test CLI Integration
# ============================================================================

class TestDNSCLIIntegration:
    """Tests for DNS CLI command integration."""
    
    def test_cli_command_registered(self):
        """Test DNS command is registered in CLI."""
        from spectrescan.cli.main import app
        from typer.testing import CliRunner
        
        runner = CliRunner()
        result = runner.invoke(app, ["dns", "--help"])
        
        assert result.exit_code == 0
        assert "DNS enumeration" in result.output or "DNS" in result.output
    
    def test_cli_command_options(self):
        """Test DNS command has expected options."""
        from spectrescan.cli.main import app
        from typer.testing import CliRunner
        
        runner = CliRunner()
        result = runner.invoke(app, ["dns", "--help"])
        
        assert "--subdomains" in result.output
        assert "--wordlist" in result.output
        assert "--zone-transfer" in result.output
        assert "--reverse" in result.output
        assert "--timeout" in result.output
        assert "--threads" in result.output


# ============================================================================
# Test Core Module Exports
# ============================================================================

class TestCoreModuleExports:
    """Tests for core module DNS exports."""
    
    def test_dns_available_flag(self):
        """Test DNS_AVAILABLE flag in core module."""
        from spectrescan.core import DNS_AVAILABLE
        
        assert DNS_AVAILABLE is True
    
    def test_dns_enumerator_exported(self):
        """Test DNSEnumerator is exported from core."""
        from spectrescan.core import DNSEnumerator as CoreDNSEnumerator
        
        assert CoreDNSEnumerator is not None
    
    def test_dns_record_exported(self):
        """Test DNSRecord is exported from core."""
        from spectrescan.core import DNSRecord as CoreDNSRecord
        
        assert CoreDNSRecord is not None
    
    def test_format_dns_report_exported(self):
        """Test format_dns_report is exported from core."""
        from spectrescan.core import format_dns_report as core_format_dns_report
        
        assert core_format_dns_report is not None
