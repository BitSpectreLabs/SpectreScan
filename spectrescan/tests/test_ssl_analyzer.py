"""
Tests for SSL/TLS Analysis module
by BitSpectreLabs
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
import socket
import ssl

from spectrescan.core.ssl_analyzer import (
    SSLAnalyzer,
    SSLAnalysisResult,
    CertificateInfo,
    CipherInfo,
    VulnerabilityResult,
    TLSVersion,
    CipherStrength,
    VulnerabilityStatus,
    analyze_ssl,
    get_certificate_info,
    check_ssl_vulnerabilities,
)


class TestTLSVersion:
    """Test TLSVersion enum."""
    
    def test_all_versions_exist(self):
        """Test all expected TLS versions exist."""
        assert TLSVersion.SSLv2.value == "SSLv2"
        assert TLSVersion.SSLv3.value == "SSLv3"
        assert TLSVersion.TLSv1_0.value == "TLSv1.0"
        assert TLSVersion.TLSv1_1.value == "TLSv1.1"
        assert TLSVersion.TLSv1_2.value == "TLSv1.2"
        assert TLSVersion.TLSv1_3.value == "TLSv1.3"
        assert TLSVersion.UNKNOWN.value == "Unknown"


class TestCipherStrength:
    """Test CipherStrength enum."""
    
    def test_all_strengths_exist(self):
        """Test all cipher strength levels exist."""
        assert CipherStrength.STRONG.value == "Strong"
        assert CipherStrength.ACCEPTABLE.value == "Acceptable"
        assert CipherStrength.WEAK.value == "Weak"
        assert CipherStrength.INSECURE.value == "Insecure"


class TestVulnerabilityStatus:
    """Test VulnerabilityStatus enum."""
    
    def test_all_statuses_exist(self):
        """Test all vulnerability statuses exist."""
        assert VulnerabilityStatus.VULNERABLE.value == "Vulnerable"
        assert VulnerabilityStatus.NOT_VULNERABLE.value == "Not Vulnerable"
        assert VulnerabilityStatus.UNKNOWN.value == "Unknown"
        assert VulnerabilityStatus.NOT_APPLICABLE.value == "Not Applicable"


class TestCertificateInfo:
    """Test CertificateInfo dataclass."""
    
    def test_default_values(self):
        """Test default values are set correctly."""
        cert = CertificateInfo()
        assert cert.subject == {}
        assert cert.issuer == {}
        assert cert.serial_number == ""
        assert cert.version == 0
        assert cert.not_before is None
        assert cert.not_after is None
        assert cert.fingerprint_sha256 == ""
        assert cert.fingerprint_sha1 == ""
        assert cert.san == []
        assert cert.is_self_signed == False
        assert cert.is_expired == False
        assert cert.days_until_expiry == 0
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        cert = CertificateInfo(
            subject={"commonName": "example.com"},
            issuer={"organizationName": "Test CA"},
            serial_number="123456",
            version=3,
        )
        result = cert.to_dict()
        assert result["subject"] == {"commonName": "example.com"}
        assert result["issuer"] == {"organizationName": "Test CA"}
        assert result["serial_number"] == "123456"
        assert result["version"] == 3
    
    def test_expired_certificate(self):
        """Test expired certificate detection."""
        cert = CertificateInfo(
            is_expired=True,
            days_until_expiry=-10,
        )
        assert cert.is_expired == True
        assert cert.days_until_expiry == -10
    
    def test_self_signed_certificate(self):
        """Test self-signed certificate flag."""
        cert = CertificateInfo(
            subject={"commonName": "self-signed.local"},
            issuer={"commonName": "self-signed.local"},
            is_self_signed=True,
        )
        assert cert.is_self_signed == True


class TestCipherInfo:
    """Test CipherInfo dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        cipher = CipherInfo(name="AES256-GCM-SHA384", protocol="TLSv1.3")
        assert cipher.name == "AES256-GCM-SHA384"
        assert cipher.protocol == "TLSv1.3"
        assert cipher.bits == 0
        assert cipher.is_forward_secrecy == False
        assert cipher.is_authenticated == True
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        cipher = CipherInfo(
            name="ECDHE-RSA-AES256-GCM-SHA384",
            protocol="TLSv1.2",
            bits=256,
            strength=CipherStrength.STRONG,
            is_forward_secrecy=True,
        )
        result = cipher.to_dict()
        assert result["name"] == "ECDHE-RSA-AES256-GCM-SHA384"
        assert result["bits"] == 256
        assert result["strength"] == "Strong"
        assert result["is_forward_secrecy"] == True


class TestVulnerabilityResult:
    """Test VulnerabilityResult dataclass."""
    
    def test_vulnerable_result(self):
        """Test vulnerable result creation."""
        vuln = VulnerabilityResult(
            name="POODLE",
            cve="CVE-2014-3566",
            status=VulnerabilityStatus.VULNERABLE,
            description="SSLv3 is vulnerable",
            severity="High",
            recommendation="Disable SSLv3",
        )
        assert vuln.name == "POODLE"
        assert vuln.cve == "CVE-2014-3566"
        assert vuln.status == VulnerabilityStatus.VULNERABLE
        assert vuln.severity == "High"
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        vuln = VulnerabilityResult(
            name="Heartbleed",
            cve="CVE-2014-0160",
            status=VulnerabilityStatus.UNKNOWN,
        )
        result = vuln.to_dict()
        assert result["name"] == "Heartbleed"
        assert result["cve"] == "CVE-2014-0160"
        assert result["status"] == "Unknown"


class TestSSLAnalysisResult:
    """Test SSLAnalysisResult dataclass."""
    
    def test_default_values(self):
        """Test default values."""
        result = SSLAnalysisResult(host="example.com", port=443)
        assert result.host == "example.com"
        assert result.port == 443
        assert result.certificate is None
        assert result.certificate_chain == []
        assert result.supported_protocols == []
        assert result.cipher_suites == []
        assert result.vulnerabilities == []
        assert result.hsts_enabled == False
        assert result.error is None
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        result = SSLAnalysisResult(
            host="example.com",
            port=443,
            hsts_enabled=True,
            hsts_max_age=31536000,
        )
        d = result.to_dict()
        assert d["host"] == "example.com"
        assert d["port"] == 443
        assert d["hsts_enabled"] == True
        assert d["hsts_max_age"] == 31536000
    
    def test_risk_score_no_issues(self):
        """Test risk score with no issues."""
        result = SSLAnalysisResult(host="example.com", port=443)
        # No certificate, no protocols, no vulns - minimal risk from missing data
        assert result.get_risk_score() >= 0
    
    def test_risk_score_expired_cert(self):
        """Test risk score with expired certificate."""
        cert = CertificateInfo(is_expired=True)
        result = SSLAnalysisResult(
            host="example.com",
            port=443,
            certificate=cert,
        )
        score = result.get_risk_score()
        assert score >= 30  # Expired cert adds 30 points
    
    def test_risk_score_weak_key(self):
        """Test risk score with weak key size."""
        cert = CertificateInfo(public_key_bits=1024)
        result = SSLAnalysisResult(
            host="example.com",
            port=443,
            certificate=cert,
        )
        score = result.get_risk_score()
        assert score >= 20  # Weak key adds 20 points
    
    def test_risk_score_deprecated_protocols(self):
        """Test risk score with deprecated protocols."""
        result = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[TLSVersion.SSLv3, TLSVersion.TLSv1_0],
        )
        score = result.get_risk_score()
        assert score >= 20  # Each deprecated protocol adds 10 points
    
    def test_risk_score_vulnerabilities(self):
        """Test risk score with vulnerabilities."""
        vulns = [
            VulnerabilityResult(
                name="POODLE",
                status=VulnerabilityStatus.VULNERABLE,
                severity="High",
            ),
            VulnerabilityResult(
                name="DROWN",
                status=VulnerabilityStatus.VULNERABLE,
                severity="Critical",
            ),
        ]
        result = SSLAnalysisResult(
            host="example.com",
            port=443,
            vulnerabilities=vulns,
        )
        score = result.get_risk_score()
        assert score >= 40  # Critical=25, High=15
    
    def test_risk_score_capped_at_100(self):
        """Test risk score is capped at 100."""
        cert = CertificateInfo(is_expired=True, public_key_bits=512, is_self_signed=True)
        vulns = [
            VulnerabilityResult(name="V1", status=VulnerabilityStatus.VULNERABLE, severity="Critical"),
            VulnerabilityResult(name="V2", status=VulnerabilityStatus.VULNERABLE, severity="Critical"),
            VulnerabilityResult(name="V3", status=VulnerabilityStatus.VULNERABLE, severity="Critical"),
            VulnerabilityResult(name="V4", status=VulnerabilityStatus.VULNERABLE, severity="Critical"),
        ]
        result = SSLAnalysisResult(
            host="example.com",
            port=443,
            certificate=cert,
            supported_protocols=[TLSVersion.SSLv2, TLSVersion.SSLv3, TLSVersion.TLSv1_0],
            vulnerabilities=vulns,
        )
        score = result.get_risk_score()
        assert score == 100


class TestSSLAnalyzer:
    """Test SSLAnalyzer class."""
    
    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = SSLAnalyzer(timeout=10.0)
        assert analyzer.timeout == 10.0
    
    def test_default_timeout(self):
        """Test default timeout value."""
        analyzer = SSLAnalyzer()
        assert analyzer.timeout == 5.0
    
    @patch('spectrescan.core.ssl_analyzer.socket.socket')
    @patch('spectrescan.core.ssl_analyzer.ssl.create_default_context')
    def test_get_certificate_success(self, mock_context, mock_socket):
        """Test successful certificate retrieval."""
        # Setup mocks
        mock_ssl_sock = MagicMock()
        
        # Mock getpeercert to return correct values based on binary_form argument
        def getpeercert_side_effect(binary_form=False):
            if binary_form:
                return b"mock_certificate_der_data"
            return {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("organizationName", "Test CA"),),),
                "serialNumber": "123456",
                "version": 3,
                "notBefore": "Jan  1 00:00:00 2024 GMT",
                "notAfter": "Dec 31 23:59:59 2025 GMT",
            }
        mock_ssl_sock.getpeercert.side_effect = getpeercert_side_effect
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_context.return_value = mock_ctx
        
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        analyzer = SSLAnalyzer()
        cert = analyzer.get_certificate("example.com", 443)
        
        assert cert is not None
        assert cert.subject.get("commonName") == "example.com"
    
    @patch('spectrescan.core.ssl_analyzer.socket.socket')
    def test_get_certificate_connection_error(self, mock_socket):
        """Test certificate retrieval with connection error."""
        mock_socket.side_effect = socket.error("Connection refused")
        
        analyzer = SSLAnalyzer()
        cert = analyzer.get_certificate("example.com", 443)
        
        assert cert is None
    
    def test_parse_cipher_forward_secrecy(self):
        """Test cipher parsing with forward secrecy."""
        analyzer = SSLAnalyzer()
        
        # ECDHE cipher should have forward secrecy
        cipher = analyzer._parse_cipher("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
        assert cipher.is_forward_secrecy == True
        
        # DHE cipher should have forward secrecy
        cipher = analyzer._parse_cipher("DHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
        assert cipher.is_forward_secrecy == True
        
        # RSA cipher should not have forward secrecy
        cipher = analyzer._parse_cipher("AES256-GCM-SHA384", "TLSv1.2", 256)
        assert cipher.is_forward_secrecy == False
    
    def test_parse_cipher_authentication(self):
        """Test cipher parsing for authentication."""
        analyzer = SSLAnalyzer()
        
        # Normal cipher is authenticated
        cipher = analyzer._parse_cipher("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
        assert cipher.is_authenticated == True
        
        # Anonymous cipher is not authenticated
        cipher = analyzer._parse_cipher("ADH-AES256-SHA", "TLSv1.0", 256)
        assert cipher.is_authenticated == False
    
    def test_classify_cipher_strength_insecure(self):
        """Test insecure cipher classification."""
        analyzer = SSLAnalyzer()
        
        # NULL cipher
        strength = analyzer._classify_cipher_strength("NULL-SHA", 0)
        assert strength == CipherStrength.INSECURE
        
        # EXPORT cipher
        strength = analyzer._classify_cipher_strength("EXP-RC4-MD5", 40)
        assert strength == CipherStrength.INSECURE
        
        # ANON cipher (anonymous)
        strength = analyzer._classify_cipher_strength("ANON-DH-AES128", 128)
        assert strength == CipherStrength.INSECURE
        
        # ADH cipher (anonymous Diffie-Hellman)
        strength = analyzer._classify_cipher_strength("ADH-AES256-SHA", 256)
        assert strength == CipherStrength.INSECURE
        
        # Very low key bits
        strength = analyzer._classify_cipher_strength("SOME-CIPHER", 40)
        assert strength == CipherStrength.INSECURE
    
    def test_classify_cipher_strength_weak(self):
        """Test weak cipher classification."""
        analyzer = SSLAnalyzer()
        
        # DES cipher
        strength = analyzer._classify_cipher_strength("DES-CBC-SHA", 56)
        assert strength == CipherStrength.WEAK
        
        # RC4 cipher
        strength = analyzer._classify_cipher_strength("RC4-SHA", 128)
        assert strength == CipherStrength.WEAK
        
        # 3DES cipher
        strength = analyzer._classify_cipher_strength("DES-CBC3-SHA", 168)
        assert strength == CipherStrength.WEAK
    
    def test_classify_cipher_strength_acceptable(self):
        """Test acceptable cipher classification."""
        analyzer = SSLAnalyzer()
        
        # 128-bit AES
        strength = analyzer._classify_cipher_strength("AES128-GCM-SHA256", 128)
        assert strength == CipherStrength.ACCEPTABLE
    
    def test_classify_cipher_strength_strong(self):
        """Test strong cipher classification."""
        analyzer = SSLAnalyzer()
        
        # 256-bit AES
        strength = analyzer._classify_cipher_strength("AES256-GCM-SHA384", 256)
        assert strength == CipherStrength.STRONG


class TestVulnerabilityChecks:
    """Test vulnerability detection methods."""
    
    def test_check_poodle_vulnerable(self):
        """Test POODLE detection when SSLv3 is supported."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[TLSVersion.SSLv3, TLSVersion.TLSv1_2],
        )
        
        result = analyzer._check_poodle(analysis)
        assert result.status == VulnerabilityStatus.VULNERABLE
        assert result.cve == "CVE-2014-3566"
    
    def test_check_poodle_not_vulnerable(self):
        """Test POODLE detection when SSLv3 is not supported."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[TLSVersion.TLSv1_2, TLSVersion.TLSv1_3],
        )
        
        result = analyzer._check_poodle(analysis)
        assert result.status == VulnerabilityStatus.NOT_VULNERABLE
    
    def test_check_beast_vulnerable(self):
        """Test BEAST detection with TLS 1.0 and CBC."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[TLSVersion.TLSv1_0],
            cipher_suites=[CipherInfo(name="AES128-CBC-SHA", protocol="TLSv1.0", bits=128)],
        )
        
        result = analyzer._check_beast(analysis)
        assert result.status == VulnerabilityStatus.VULNERABLE
        assert result.cve == "CVE-2011-3389"
    
    def test_check_beast_not_vulnerable(self):
        """Test BEAST detection without TLS 1.0."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[TLSVersion.TLSv1_2],
        )
        
        result = analyzer._check_beast(analysis)
        assert result.status == VulnerabilityStatus.NOT_VULNERABLE
    
    def test_check_freak_vulnerable(self):
        """Test FREAK detection with export ciphers."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            cipher_suites=[
                CipherInfo(name="EXPORT-RC4-MD5", protocol="SSLv3", bits=40),
                CipherInfo(name="AES256-GCM-SHA384", protocol="TLSv1.2", bits=256),
            ],
        )
        
        result = analyzer._check_freak(analysis)
        assert result.status == VulnerabilityStatus.VULNERABLE
        assert result.cve == "CVE-2015-0204"
    
    def test_check_freak_not_vulnerable(self):
        """Test FREAK detection without export ciphers."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            cipher_suites=[
                CipherInfo(name="AES256-GCM-SHA384", protocol="TLSv1.2", bits=256),
            ],
        )
        
        result = analyzer._check_freak(analysis)
        assert result.status == VulnerabilityStatus.NOT_VULNERABLE
    
    def test_check_drown_vulnerable(self):
        """Test DROWN detection with SSLv2."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[TLSVersion.SSLv2],
        )
        
        result = analyzer._check_drown(analysis)
        assert result.status == VulnerabilityStatus.VULNERABLE
        assert result.cve == "CVE-2016-0800"
    
    def test_check_drown_not_vulnerable(self):
        """Test DROWN detection without SSLv2."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[TLSVersion.TLSv1_2],
        )
        
        result = analyzer._check_drown(analysis)
        assert result.status == VulnerabilityStatus.NOT_VULNERABLE
    
    def test_check_logjam_vulnerable(self):
        """Test Logjam detection with weak DH."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            cipher_suites=[
                CipherInfo(name="DHE-RSA-AES256-SHA", protocol="TLSv1.0", bits=512),
            ],
        )
        
        result = analyzer._check_logjam(analysis)
        assert result.status == VulnerabilityStatus.VULNERABLE
        assert result.cve == "CVE-2015-4000"
    
    def test_check_logjam_not_vulnerable(self):
        """Test Logjam detection with strong DH."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            cipher_suites=[
                CipherInfo(name="DHE-RSA-AES256-GCM-SHA384", protocol="TLSv1.2", bits=2048),
            ],
        )
        
        result = analyzer._check_logjam(analysis)
        assert result.status == VulnerabilityStatus.NOT_VULNERABLE
    
    def test_check_deprecated_protocols(self):
        """Test deprecated protocol detection."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            supported_protocols=[
                TLSVersion.SSLv3,
                TLSVersion.TLSv1_0,
                TLSVersion.TLSv1_1,
                TLSVersion.TLSv1_2,
            ],
        )
        
        results = analyzer._check_deprecated_protocols(analysis)
        
        # Should find SSLv3, TLS 1.0, and TLS 1.1 as deprecated
        assert len(results) == 3
        assert all(r.status == VulnerabilityStatus.VULNERABLE for r in results)
    
    def test_check_weak_certificate_expired(self):
        """Test weak certificate check for expired cert."""
        analyzer = SSLAnalyzer()
        cert = CertificateInfo(is_expired=True)
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            certificate=cert,
        )
        
        results = analyzer._check_weak_certificate(analysis)
        
        expired_vuln = [r for r in results if "Expired" in r.name]
        assert len(expired_vuln) == 1
        assert expired_vuln[0].severity == "Critical"
    
    def test_check_weak_certificate_expiring_soon(self):
        """Test weak certificate check for cert expiring soon."""
        analyzer = SSLAnalyzer()
        cert = CertificateInfo(days_until_expiry=15, is_expired=False)
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            certificate=cert,
        )
        
        results = analyzer._check_weak_certificate(analysis)
        
        expiring_vuln = [r for r in results if "Expiring" in r.name]
        assert len(expiring_vuln) == 1
        assert expiring_vuln[0].severity == "Medium"
    
    def test_check_weak_certificate_weak_key(self):
        """Test weak certificate check for weak key size."""
        analyzer = SSLAnalyzer()
        cert = CertificateInfo(public_key_bits=1024)
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            certificate=cert,
        )
        
        results = analyzer._check_weak_certificate(analysis)
        
        key_vuln = [r for r in results if "Key" in r.name]
        assert len(key_vuln) == 1
        assert key_vuln[0].severity == "High"
    
    def test_check_weak_ciphers(self):
        """Test weak cipher detection."""
        analyzer = SSLAnalyzer()
        analysis = SSLAnalysisResult(
            host="example.com",
            port=443,
            cipher_suites=[
                CipherInfo(name="NULL-SHA", protocol="SSLv3", bits=0, strength=CipherStrength.INSECURE),
                CipherInfo(name="RC4-SHA", protocol="TLSv1.0", bits=128, strength=CipherStrength.WEAK),
                CipherInfo(name="AES256-GCM-SHA384", protocol="TLSv1.2", bits=256, strength=CipherStrength.STRONG),
            ],
        )
        
        results = analyzer._check_weak_ciphers(analysis)
        
        # Should find NULL (insecure) and RC4 (weak)
        assert len(results) == 2


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    @patch.object(SSLAnalyzer, 'analyze')
    def test_analyze_ssl(self, mock_analyze):
        """Test analyze_ssl convenience function."""
        mock_result = SSLAnalysisResult(host="example.com", port=443)
        mock_analyze.return_value = mock_result
        
        result = analyze_ssl("example.com", 443, 5.0)
        
        assert result == mock_result
        mock_analyze.assert_called_once_with("example.com", 443)
    
    @patch.object(SSLAnalyzer, 'get_certificate')
    def test_get_certificate_info(self, mock_get_cert):
        """Test get_certificate_info convenience function."""
        mock_cert = CertificateInfo(subject={"commonName": "example.com"})
        mock_get_cert.return_value = mock_cert
        
        result = get_certificate_info("example.com", 443, 5.0)
        
        assert result == mock_cert
        mock_get_cert.assert_called_once_with("example.com", 443)
    
    @patch.object(SSLAnalyzer, 'analyze')
    def test_check_ssl_vulnerabilities(self, mock_analyze):
        """Test check_ssl_vulnerabilities convenience function."""
        vulns = [
            VulnerabilityResult(name="POODLE", status=VulnerabilityStatus.VULNERABLE),
        ]
        mock_result = SSLAnalysisResult(
            host="example.com",
            port=443,
            vulnerabilities=vulns,
        )
        mock_analyze.return_value = mock_result
        
        result = check_ssl_vulnerabilities("example.com", 443, 5.0)
        
        assert result == vulns


class TestIPv6Support:
    """Test IPv6 support in SSL analyzer."""
    
    @patch('spectrescan.core.ssl_analyzer.is_ipv6')
    @patch('spectrescan.core.ssl_analyzer.socket.socket')
    @patch('spectrescan.core.ssl_analyzer.ssl.create_default_context')
    def test_ipv6_address_handling(self, mock_context, mock_socket, mock_is_ipv6):
        """Test that IPv6 addresses use AF_INET6."""
        mock_is_ipv6.return_value = True
        
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = None
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_context.return_value = mock_ctx
        
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        analyzer = SSLAnalyzer()
        analyzer.get_certificate("2001:db8::1", 443)
        
        # Verify socket was created with AF_INET6
        mock_socket.assert_called_with(socket.AF_INET6, socket.SOCK_STREAM)
    
    @patch('spectrescan.core.ssl_analyzer.is_ipv6')
    @patch('spectrescan.core.ssl_analyzer.socket.socket')
    @patch('spectrescan.core.ssl_analyzer.ssl.create_default_context')
    def test_ipv4_address_handling(self, mock_context, mock_socket, mock_is_ipv6):
        """Test that IPv4 addresses use AF_INET."""
        mock_is_ipv6.return_value = False
        
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.getpeercert.return_value = None
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_context.return_value = mock_ctx
        
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        analyzer = SSLAnalyzer()
        analyzer.get_certificate("192.168.1.1", 443)
        
        # Verify socket was created with AF_INET
        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)


class TestCertificateDateParsing:
    """Test certificate date parsing."""
    
    def test_parse_cert_date_standard_format(self):
        """Test parsing standard certificate date format."""
        analyzer = SSLAnalyzer()
        
        date = analyzer._parse_cert_date("Jan  1 00:00:00 2024 GMT")
        assert date is not None
        assert date.year == 2024
        assert date.month == 1
        assert date.day == 1
    
    def test_parse_cert_date_compact_format(self):
        """Test parsing compact certificate date format."""
        analyzer = SSLAnalyzer()
        
        date = analyzer._parse_cert_date("Dec 31 23:59:59 2025 GMT")
        assert date is not None
        assert date.year == 2025
        assert date.month == 12
        assert date.day == 31
    
    def test_parse_cert_date_invalid(self):
        """Test parsing invalid date returns None."""
        analyzer = SSLAnalyzer()
        
        date = analyzer._parse_cert_date("invalid date format")
        assert date is None


class TestHSTSCheck:
    """Test HSTS header checking."""
    
    @patch('spectrescan.core.ssl_analyzer.socket.socket')
    @patch('spectrescan.core.ssl_analyzer.ssl.create_default_context')
    def test_hsts_enabled(self, mock_context, mock_socket):
        """Test HSTS detection when enabled."""
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\n\r\n"
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_context.return_value = mock_ctx
        
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        analyzer = SSLAnalyzer()
        enabled, max_age = analyzer.check_hsts("example.com", 443)
        
        assert enabled == True
        assert max_age == 31536000
    
    @patch('spectrescan.core.ssl_analyzer.socket.socket')
    @patch('spectrescan.core.ssl_analyzer.ssl.create_default_context')
    def test_hsts_not_enabled(self, mock_context, mock_socket):
        """Test HSTS detection when not enabled."""
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssl_sock
        mock_context.return_value = mock_ctx
        
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        analyzer = SSLAnalyzer()
        enabled, max_age = analyzer.check_hsts("example.com", 443)
        
        assert enabled == False
        assert max_age == 0
