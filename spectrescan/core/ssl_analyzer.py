"""
SSL/TLS Analysis module for comprehensive certificate and cipher analysis
by BitSpectreLabs

Provides certificate extraction, cipher enumeration, protocol detection,
and vulnerability scanning for TLS-enabled services.
"""

import socket
import ssl
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from spectrescan.core.utils import is_ipv6


class TLSVersion(Enum):
    """TLS/SSL protocol versions."""
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"
    UNKNOWN = "Unknown"


class CipherStrength(Enum):
    """Cipher strength classification."""
    STRONG = "Strong"
    ACCEPTABLE = "Acceptable"
    WEAK = "Weak"
    INSECURE = "Insecure"
    UNKNOWN = "Unknown"


class VulnerabilityStatus(Enum):
    """Vulnerability check status."""
    VULNERABLE = "Vulnerable"
    NOT_VULNERABLE = "Not Vulnerable"
    UNKNOWN = "Unknown"
    NOT_APPLICABLE = "Not Applicable"


@dataclass
class CertificateInfo:
    """Information about an SSL/TLS certificate."""
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    version: int = 0
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""
    signature_algorithm: str = ""
    public_key_type: str = ""
    public_key_bits: int = 0
    san: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    is_expired: bool = False
    days_until_expiry: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "version": self.version,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "fingerprint_sha256": self.fingerprint_sha256,
            "fingerprint_sha1": self.fingerprint_sha1,
            "signature_algorithm": self.signature_algorithm,
            "public_key_type": self.public_key_type,
            "public_key_bits": self.public_key_bits,
            "san": self.san,
            "is_self_signed": self.is_self_signed,
            "is_expired": self.is_expired,
            "days_until_expiry": self.days_until_expiry,
        }


@dataclass
class CipherInfo:
    """Information about a cipher suite."""
    name: str
    protocol: str
    bits: int = 0
    strength: CipherStrength = CipherStrength.UNKNOWN
    is_forward_secrecy: bool = False
    is_authenticated: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "protocol": self.protocol,
            "bits": self.bits,
            "strength": self.strength.value,
            "is_forward_secrecy": self.is_forward_secrecy,
            "is_authenticated": self.is_authenticated,
        }


@dataclass
class VulnerabilityResult:
    """Result of a vulnerability check."""
    name: str
    cve: Optional[str] = None
    status: VulnerabilityStatus = VulnerabilityStatus.UNKNOWN
    description: str = ""
    severity: str = "Unknown"
    recommendation: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "cve": self.cve,
            "status": self.status.value,
            "description": self.description,
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


@dataclass
class SSLAnalysisResult:
    """Complete SSL/TLS analysis result."""
    host: str
    port: int
    certificate: Optional[CertificateInfo] = None
    certificate_chain: List[CertificateInfo] = field(default_factory=list)
    supported_protocols: List[TLSVersion] = field(default_factory=list)
    cipher_suites: List[CipherInfo] = field(default_factory=list)
    preferred_cipher: Optional[CipherInfo] = None
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    ocsp_stapling: bool = False
    error: Optional[str] = None
    scan_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "host": self.host,
            "port": self.port,
            "certificate": self.certificate.to_dict() if self.certificate else None,
            "certificate_chain": [c.to_dict() for c in self.certificate_chain],
            "supported_protocols": [p.value for p in self.supported_protocols],
            "cipher_suites": [c.to_dict() for c in self.cipher_suites],
            "preferred_cipher": self.preferred_cipher.to_dict() if self.preferred_cipher else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "hsts_enabled": self.hsts_enabled,
            "hsts_max_age": self.hsts_max_age,
            "ocsp_stapling": self.ocsp_stapling,
            "error": self.error,
            "scan_timestamp": self.scan_timestamp.isoformat(),
        }
    
    def get_risk_score(self) -> int:
        """
        Calculate risk score based on analysis results.
        
        Returns:
            Risk score from 0 (no risk) to 100 (critical)
        """
        score = 0
        
        # Certificate issues
        if self.certificate:
            if self.certificate.is_expired:
                score += 30
            elif self.certificate.days_until_expiry < 30:
                score += 15
            elif self.certificate.days_until_expiry < 90:
                score += 5
            
            if self.certificate.is_self_signed:
                score += 10
            
            if self.certificate.public_key_bits < 2048:
                score += 20
        
        # Protocol issues
        deprecated_protocols = [TLSVersion.SSLv2, TLSVersion.SSLv3, 
                               TLSVersion.TLSv1_0, TLSVersion.TLSv1_1]
        for protocol in self.supported_protocols:
            if protocol in deprecated_protocols:
                score += 10
        
        # Vulnerability issues
        for vuln in self.vulnerabilities:
            if vuln.status == VulnerabilityStatus.VULNERABLE:
                if vuln.severity == "Critical":
                    score += 25
                elif vuln.severity == "High":
                    score += 15
                elif vuln.severity == "Medium":
                    score += 10
                else:
                    score += 5
        
        # Weak ciphers
        for cipher in self.cipher_suites:
            if cipher.strength == CipherStrength.INSECURE:
                score += 10
            elif cipher.strength == CipherStrength.WEAK:
                score += 5
        
        # Missing security features
        if not self.hsts_enabled:
            score += 5
        
        return min(score, 100)


# Weak cipher patterns
WEAK_CIPHERS = [
    "NULL", "EXPORT", "DES", "RC4", "RC2", "MD5", 
    "ANON", "ADH", "AECDH", "3DES", "IDEA", "SEED"
]

# Forward secrecy cipher prefixes
FS_CIPHERS = ["ECDHE", "DHE", "ECDH"]

# Protocol version mapping for ssl module
PROTOCOL_MAP = {
    TLSVersion.TLSv1_2: ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None,
    TLSVersion.TLSv1_3: ssl.PROTOCOL_TLS if hasattr(ssl, 'PROTOCOL_TLS') else None,
}


class SSLAnalyzer:
    """
    Comprehensive SSL/TLS analyzer for certificate and cipher analysis.
    
    Provides:
    - Certificate extraction and parsing
    - Certificate chain validation
    - Cipher suite enumeration
    - Protocol version detection
    - Vulnerability scanning
    - Security header analysis
    """
    
    def __init__(self, timeout: float = 5.0):
        """
        Initialize SSL analyzer.
        
        Args:
            timeout: Socket timeout in seconds
        """
        self.timeout = timeout
    
    def analyze(self, host: str, port: int = 443) -> SSLAnalysisResult:
        """
        Perform comprehensive SSL/TLS analysis on a host.
        
        Args:
            host: Target hostname or IP address
            port: Target port (default 443)
            
        Returns:
            SSLAnalysisResult with complete analysis data
        """
        result = SSLAnalysisResult(host=host, port=port)
        
        try:
            # Get certificate
            cert_info = self.get_certificate(host, port)
            if cert_info:
                result.certificate = cert_info
            
            # Get certificate chain
            chain = self.get_certificate_chain(host, port)
            result.certificate_chain = chain
            
            # Detect supported protocols
            protocols = self.detect_protocols(host, port)
            result.supported_protocols = protocols
            
            # Enumerate ciphers
            ciphers = self.enumerate_ciphers(host, port)
            result.cipher_suites = ciphers
            if ciphers:
                result.preferred_cipher = ciphers[0]
            
            # Check vulnerabilities
            vulns = self.check_vulnerabilities(host, port, result)
            result.vulnerabilities = vulns
            
            # Check security headers
            hsts_enabled, hsts_max_age = self.check_hsts(host, port)
            result.hsts_enabled = hsts_enabled
            result.hsts_max_age = hsts_max_age
            
            # Check OCSP stapling
            result.ocsp_stapling = self.check_ocsp_stapling(host, port)
            
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def get_certificate(self, host: str, port: int = 443) -> Optional[CertificateInfo]:
        """
        Extract and parse the server's certificate.
        
        Args:
            host: Target hostname or IP address
            port: Target port
            
        Returns:
            CertificateInfo or None if failed
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            # Get certificate in DER format
            cert_der = ssl_sock.getpeercert(binary_form=True)
            cert_dict = ssl_sock.getpeercert()
            
            ssl_sock.close()
            
            if not cert_dict:
                return None
            
            return self._parse_certificate(cert_dict, cert_der)
            
        except Exception:
            return None
    
    def _parse_certificate(self, cert_dict: Dict, cert_der: bytes) -> CertificateInfo:
        """
        Parse certificate dictionary into CertificateInfo.
        
        Args:
            cert_dict: Certificate dictionary from ssl module
            cert_der: Certificate in DER format
            
        Returns:
            CertificateInfo object
        """
        info = CertificateInfo()
        
        # Parse subject
        subject = cert_dict.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                info.subject[attr_type] = attr_value
        
        # Parse issuer
        issuer = cert_dict.get("issuer", ())
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                info.issuer[attr_type] = attr_value
        
        # Serial number
        info.serial_number = str(cert_dict.get("serialNumber", ""))
        
        # Version
        info.version = cert_dict.get("version", 0)
        
        # Validity dates
        not_before = cert_dict.get("notBefore")
        not_after = cert_dict.get("notAfter")
        
        if not_before:
            info.not_before = self._parse_cert_date(not_before)
        if not_after:
            info.not_after = self._parse_cert_date(not_after)
            # Calculate expiry
            if info.not_after:
                now = datetime.now(timezone.utc)
                delta = info.not_after - now
                info.days_until_expiry = delta.days
                info.is_expired = delta.days < 0
        
        # Fingerprints
        if cert_der:
            info.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest().upper()
            info.fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest().upper()
        
        # Subject Alternative Names
        san = cert_dict.get("subjectAltName", ())
        info.san = [value for name, value in san if name in ("DNS", "IP Address")]
        
        # Check if self-signed
        info.is_self_signed = info.subject == info.issuer
        
        return info
    
    def _parse_cert_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse certificate date string.
        
        Args:
            date_str: Date string from certificate
            
        Returns:
            datetime object or None
        """
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
            "%Y%m%d%H%M%SZ",
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        
        return None
    
    def get_certificate_chain(self, host: str, port: int = 443) -> List[CertificateInfo]:
        """
        Get the full certificate chain.
        
        Args:
            host: Target hostname or IP address
            port: Target port
            
        Returns:
            List of CertificateInfo for each certificate in chain
        """
        chain = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            # Get peer certificate chain if available
            # Note: Standard ssl module has limited chain access
            cert_dict = ssl_sock.getpeercert()
            cert_der = ssl_sock.getpeercert(binary_form=True)
            
            ssl_sock.close()
            
            if cert_dict:
                chain.append(self._parse_certificate(cert_dict, cert_der))
            
        except Exception:
            pass
        
        return chain
    
    def detect_protocols(self, host: str, port: int = 443) -> List[TLSVersion]:
        """
        Detect supported TLS/SSL protocol versions.
        
        Args:
            host: Target hostname or IP address
            port: Target port
            
        Returns:
            List of supported TLSVersion
        """
        supported = []
        
        # Test TLS 1.2
        if self._test_protocol(host, port, ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None):
            supported.append(TLSVersion.TLSv1_2)
        
        # Test TLS 1.3 (via PROTOCOL_TLS with options)
        if self._test_tls13(host, port):
            supported.append(TLSVersion.TLSv1_3)
        
        # Test deprecated protocols (optional, may not work on modern Python)
        if hasattr(ssl, 'PROTOCOL_TLSv1_1'):
            try:
                if self._test_protocol(host, port, ssl.PROTOCOL_TLSv1_1):
                    supported.append(TLSVersion.TLSv1_1)
            except Exception:
                pass
        
        if hasattr(ssl, 'PROTOCOL_TLSv1'):
            try:
                if self._test_protocol(host, port, ssl.PROTOCOL_TLSv1):
                    supported.append(TLSVersion.TLSv1_0)
            except Exception:
                pass
        
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            try:
                if self._test_protocol(host, port, ssl.PROTOCOL_SSLv3):
                    supported.append(TLSVersion.SSLv3)
            except Exception:
                pass
        
        return supported
    
    def _test_protocol(self, host: str, port: int, protocol) -> bool:
        """
        Test if a specific protocol is supported.
        
        Args:
            host: Target hostname
            port: Target port
            protocol: SSL protocol constant
            
        Returns:
            True if protocol is supported
        """
        if protocol is None:
            return False
        
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            ssl_sock.close()
            
            return True
            
        except Exception:
            return False
    
    def _test_tls13(self, host: str, port: int) -> bool:
        """
        Test TLS 1.3 support.
        
        Args:
            host: Target hostname
            port: Target port
            
        Returns:
            True if TLS 1.3 is supported
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            ssl_sock.close()
            
            return True
            
        except Exception:
            return False
    
    def enumerate_ciphers(self, host: str, port: int = 443) -> List[CipherInfo]:
        """
        Enumerate supported cipher suites.
        
        Args:
            host: Target hostname or IP address
            port: Target port
            
        Returns:
            List of supported CipherInfo
        """
        ciphers = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            # Get negotiated cipher
            cipher = ssl_sock.cipher()
            if cipher:
                name, protocol, bits = cipher
                ciphers.append(self._parse_cipher(name, protocol, bits))
            
            # Get shared ciphers (if available)
            if hasattr(ssl_sock, 'shared_ciphers'):
                shared = ssl_sock.shared_ciphers()
                if shared:
                    for name, protocol, bits in shared:
                        if not any(c.name == name for c in ciphers):
                            ciphers.append(self._parse_cipher(name, protocol, bits))
            
            ssl_sock.close()
            
        except Exception:
            pass
        
        return ciphers
    
    def _parse_cipher(self, name: str, protocol: str, bits: int) -> CipherInfo:
        """
        Parse cipher information.
        
        Args:
            name: Cipher suite name
            protocol: Protocol version string
            bits: Key bits
            
        Returns:
            CipherInfo object
        """
        info = CipherInfo(name=name, protocol=protocol, bits=bits)
        
        # Check for forward secrecy
        info.is_forward_secrecy = any(fs in name for fs in FS_CIPHERS)
        
        # Check for anonymous (unauthenticated)
        info.is_authenticated = "ANON" not in name and "ADH" not in name
        
        # Determine strength
        info.strength = self._classify_cipher_strength(name, bits)
        
        return info
    
    def _classify_cipher_strength(self, name: str, bits: int) -> CipherStrength:
        """
        Classify cipher strength.
        
        Args:
            name: Cipher suite name
            bits: Key bits
            
        Returns:
            CipherStrength classification
        """
        name_upper = name.upper()
        
        # Check for insecure ciphers
        insecure = ["NULL", "EXPORT", "EXP-", "ANON", "ADH", "AECDH"]
        if any(weak in name_upper for weak in insecure):
            return CipherStrength.INSECURE
        
        # Check for weak ciphers
        weak = ["DES", "RC4", "RC2", "MD5", "3DES", "IDEA", "SEED"]
        if any(w in name_upper for w in weak):
            return CipherStrength.WEAK
        
        # Check key size
        if bits < 128:
            return CipherStrength.INSECURE
        elif bits < 256:
            return CipherStrength.ACCEPTABLE
        else:
            return CipherStrength.STRONG
    
    def check_vulnerabilities(
        self, 
        host: str, 
        port: int, 
        analysis: SSLAnalysisResult
    ) -> List[VulnerabilityResult]:
        """
        Check for known SSL/TLS vulnerabilities.
        
        Args:
            host: Target hostname
            port: Target port
            analysis: Current analysis result
            
        Returns:
            List of VulnerabilityResult
        """
        vulns = []
        
        # Check for deprecated protocols
        vulns.extend(self._check_deprecated_protocols(analysis))
        
        # Check for weak ciphers
        vulns.extend(self._check_weak_ciphers(analysis))
        
        # Check for POODLE (SSLv3)
        vulns.append(self._check_poodle(analysis))
        
        # Check for BEAST (TLS 1.0 with CBC)
        vulns.append(self._check_beast(analysis))
        
        # Check for CRIME (compression)
        vulns.append(self._check_crime(host, port))
        
        # Check for Heartbleed (OpenSSL specific)
        vulns.append(self._check_heartbleed(host, port))
        
        # Check for FREAK (export ciphers)
        vulns.append(self._check_freak(analysis))
        
        # Check for Logjam (weak DH)
        vulns.append(self._check_logjam(analysis))
        
        # Check for DROWN (SSLv2)
        vulns.append(self._check_drown(analysis))
        
        # Check for weak certificate
        vulns.extend(self._check_weak_certificate(analysis))
        
        return [v for v in vulns if v is not None]
    
    def _check_deprecated_protocols(self, analysis: SSLAnalysisResult) -> List[VulnerabilityResult]:
        """Check for deprecated protocol support."""
        vulns = []
        
        deprecated = {
            TLSVersion.SSLv2: ("SSLv2 Supported", "CVE-2016-0800", "Critical"),
            TLSVersion.SSLv3: ("SSLv3 Supported", "CVE-2014-3566", "High"),
            TLSVersion.TLSv1_0: ("TLS 1.0 Supported", None, "Medium"),
            TLSVersion.TLSv1_1: ("TLS 1.1 Supported", None, "Low"),
        }
        
        for version in analysis.supported_protocols:
            if version in deprecated:
                name, cve, severity = deprecated[version]
                vulns.append(VulnerabilityResult(
                    name=name,
                    cve=cve,
                    status=VulnerabilityStatus.VULNERABLE,
                    description=f"{version.value} is deprecated and has known security issues.",
                    severity=severity,
                    recommendation=f"Disable {version.value} and use TLS 1.2 or higher.",
                ))
        
        return vulns
    
    def _check_weak_ciphers(self, analysis: SSLAnalysisResult) -> List[VulnerabilityResult]:
        """Check for weak cipher support."""
        vulns = []
        
        for cipher in analysis.cipher_suites:
            if cipher.strength == CipherStrength.INSECURE:
                vulns.append(VulnerabilityResult(
                    name=f"Insecure Cipher: {cipher.name}",
                    status=VulnerabilityStatus.VULNERABLE,
                    description=f"Cipher {cipher.name} is considered insecure.",
                    severity="High",
                    recommendation="Disable this cipher suite.",
                ))
            elif cipher.strength == CipherStrength.WEAK:
                vulns.append(VulnerabilityResult(
                    name=f"Weak Cipher: {cipher.name}",
                    status=VulnerabilityStatus.VULNERABLE,
                    description=f"Cipher {cipher.name} is considered weak.",
                    severity="Medium",
                    recommendation="Consider disabling this cipher suite.",
                ))
        
        return vulns
    
    def _check_poodle(self, analysis: SSLAnalysisResult) -> Optional[VulnerabilityResult]:
        """Check for POODLE vulnerability (SSLv3)."""
        if TLSVersion.SSLv3 in analysis.supported_protocols:
            return VulnerabilityResult(
                name="POODLE",
                cve="CVE-2014-3566",
                status=VulnerabilityStatus.VULNERABLE,
                description="SSLv3 is vulnerable to POODLE attack.",
                severity="High",
                recommendation="Disable SSLv3 completely.",
            )
        return VulnerabilityResult(
            name="POODLE",
            cve="CVE-2014-3566",
            status=VulnerabilityStatus.NOT_VULNERABLE,
            description="SSLv3 is not supported.",
            severity="None",
        )
    
    def _check_beast(self, analysis: SSLAnalysisResult) -> Optional[VulnerabilityResult]:
        """Check for BEAST vulnerability (TLS 1.0 with CBC)."""
        if TLSVersion.TLSv1_0 in analysis.supported_protocols:
            # Check for CBC ciphers
            has_cbc = any("CBC" in c.name for c in analysis.cipher_suites)
            if has_cbc:
                return VulnerabilityResult(
                    name="BEAST",
                    cve="CVE-2011-3389",
                    status=VulnerabilityStatus.VULNERABLE,
                    description="TLS 1.0 with CBC ciphers is vulnerable to BEAST.",
                    severity="Medium",
                    recommendation="Disable TLS 1.0 or use only non-CBC ciphers.",
                )
        return VulnerabilityResult(
            name="BEAST",
            cve="CVE-2011-3389",
            status=VulnerabilityStatus.NOT_VULNERABLE,
            description="TLS 1.0 with CBC is not in use.",
            severity="None",
        )
    
    def _check_crime(self, host: str, port: int) -> VulnerabilityResult:
        """Check for CRIME vulnerability (TLS compression)."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            # Check compression
            compression = ssl_sock.compression()
            ssl_sock.close()
            
            if compression:
                return VulnerabilityResult(
                    name="CRIME",
                    cve="CVE-2012-4929",
                    status=VulnerabilityStatus.VULNERABLE,
                    description="TLS compression is enabled, vulnerable to CRIME.",
                    severity="Medium",
                    recommendation="Disable TLS compression.",
                )
            
        except Exception:
            pass
        
        return VulnerabilityResult(
            name="CRIME",
            cve="CVE-2012-4929",
            status=VulnerabilityStatus.NOT_VULNERABLE,
            description="TLS compression is disabled.",
            severity="None",
        )
    
    def _check_heartbleed(self, host: str, port: int) -> VulnerabilityResult:
        """
        Check for Heartbleed vulnerability.
        
        Note: This is a simplified check. Full Heartbleed testing requires
        sending crafted heartbeat requests which may be intrusive.
        """
        # Simplified - we cannot safely test Heartbleed without sending
        # potentially harmful packets. Return unknown.
        return VulnerabilityResult(
            name="Heartbleed",
            cve="CVE-2014-0160",
            status=VulnerabilityStatus.UNKNOWN,
            description="Heartbleed check requires intrusive testing.",
            severity="Unknown",
            recommendation="Use dedicated tools like nmap --script ssl-heartbleed.",
        )
    
    def _check_freak(self, analysis: SSLAnalysisResult) -> VulnerabilityResult:
        """Check for FREAK vulnerability (export ciphers)."""
        export_ciphers = [c for c in analysis.cipher_suites if "EXPORT" in c.name.upper()]
        
        if export_ciphers:
            return VulnerabilityResult(
                name="FREAK",
                cve="CVE-2015-0204",
                status=VulnerabilityStatus.VULNERABLE,
                description="Export-grade ciphers are supported, vulnerable to FREAK.",
                severity="High",
                recommendation="Disable all export cipher suites.",
            )
        
        return VulnerabilityResult(
            name="FREAK",
            cve="CVE-2015-0204",
            status=VulnerabilityStatus.NOT_VULNERABLE,
            description="No export ciphers are supported.",
            severity="None",
        )
    
    def _check_logjam(self, analysis: SSLAnalysisResult) -> VulnerabilityResult:
        """Check for Logjam vulnerability (weak DH)."""
        # Check for DHE ciphers with small key sizes
        weak_dh = [c for c in analysis.cipher_suites 
                   if "DHE" in c.name and c.bits < 1024]
        
        if weak_dh:
            return VulnerabilityResult(
                name="Logjam",
                cve="CVE-2015-4000",
                status=VulnerabilityStatus.VULNERABLE,
                description="Weak DH parameters detected, vulnerable to Logjam.",
                severity="High",
                recommendation="Use DHE with at least 2048-bit parameters.",
            )
        
        return VulnerabilityResult(
            name="Logjam",
            cve="CVE-2015-4000",
            status=VulnerabilityStatus.NOT_VULNERABLE,
            description="DH parameters are adequate.",
            severity="None",
        )
    
    def _check_drown(self, analysis: SSLAnalysisResult) -> VulnerabilityResult:
        """Check for DROWN vulnerability (SSLv2)."""
        if TLSVersion.SSLv2 in analysis.supported_protocols:
            return VulnerabilityResult(
                name="DROWN",
                cve="CVE-2016-0800",
                status=VulnerabilityStatus.VULNERABLE,
                description="SSLv2 is supported, vulnerable to DROWN attack.",
                severity="Critical",
                recommendation="Disable SSLv2 immediately.",
            )
        
        return VulnerabilityResult(
            name="DROWN",
            cve="CVE-2016-0800",
            status=VulnerabilityStatus.NOT_VULNERABLE,
            description="SSLv2 is not supported.",
            severity="None",
        )
    
    def _check_weak_certificate(self, analysis: SSLAnalysisResult) -> List[VulnerabilityResult]:
        """Check for weak certificate issues."""
        vulns = []
        
        if not analysis.certificate:
            return vulns
        
        cert = analysis.certificate
        
        # Check key size
        if cert.public_key_bits > 0 and cert.public_key_bits < 2048:
            vulns.append(VulnerabilityResult(
                name="Weak Certificate Key",
                status=VulnerabilityStatus.VULNERABLE,
                description=f"Certificate uses {cert.public_key_bits}-bit key.",
                severity="High",
                recommendation="Use at least 2048-bit RSA or 256-bit ECDSA.",
            ))
        
        # Check expiration
        if cert.is_expired:
            vulns.append(VulnerabilityResult(
                name="Expired Certificate",
                status=VulnerabilityStatus.VULNERABLE,
                description="Certificate has expired.",
                severity="Critical",
                recommendation="Renew the certificate immediately.",
            ))
        elif cert.days_until_expiry < 30:
            vulns.append(VulnerabilityResult(
                name="Certificate Expiring Soon",
                status=VulnerabilityStatus.VULNERABLE,
                description=f"Certificate expires in {cert.days_until_expiry} days.",
                severity="Medium",
                recommendation="Renew the certificate before expiration.",
            ))
        
        # Check self-signed
        if cert.is_self_signed:
            vulns.append(VulnerabilityResult(
                name="Self-Signed Certificate",
                status=VulnerabilityStatus.VULNERABLE,
                description="Certificate is self-signed.",
                severity="Low",
                recommendation="Use a certificate from a trusted CA.",
            ))
        
        return vulns
    
    def check_hsts(self, host: str, port: int = 443) -> Tuple[bool, int]:
        """
        Check for HSTS (HTTP Strict Transport Security) header.
        
        Args:
            host: Target hostname
            port: Target port
            
        Returns:
            Tuple of (hsts_enabled, max_age)
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            # Send HTTP request
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            ssl_sock.send(request.encode())
            
            response = b""
            while True:
                try:
                    data = ssl_sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    break
            
            ssl_sock.close()
            
            # Parse headers
            response_str = response.decode("utf-8", errors="ignore")
            headers = response_str.split("\r\n\r\n")[0].lower()
            
            if "strict-transport-security" in headers:
                # Extract max-age
                import re
                match = re.search(r"max-age=(\d+)", headers)
                max_age = int(match.group(1)) if match else 0
                return True, max_age
            
        except Exception:
            pass
        
        return False, 0
    
    def check_ocsp_stapling(self, host: str, port: int = 443) -> bool:
        """
        Check if OCSP stapling is supported.
        
        Args:
            host: Target hostname
            port: Target port
            
        Returns:
            True if OCSP stapling is supported
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            addr_family = socket.AF_INET6 if is_ipv6(host) else socket.AF_INET
            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            # Check for OCSP response (limited in standard ssl module)
            # This is a simplified check
            ssl_sock.close()
            
        except Exception:
            pass
        
        return False  # Cannot reliably determine with standard ssl module


def analyze_ssl(host: str, port: int = 443, timeout: float = 5.0) -> SSLAnalysisResult:
    """
    Convenience function for SSL/TLS analysis.
    
    Args:
        host: Target hostname or IP address
        port: Target port (default 443)
        timeout: Socket timeout in seconds
        
    Returns:
        SSLAnalysisResult with complete analysis data
    """
    analyzer = SSLAnalyzer(timeout=timeout)
    return analyzer.analyze(host, port)


def get_certificate_info(host: str, port: int = 443, timeout: float = 5.0) -> Optional[CertificateInfo]:
    """
    Convenience function to get certificate information.
    
    Args:
        host: Target hostname or IP address
        port: Target port (default 443)
        timeout: Socket timeout in seconds
        
    Returns:
        CertificateInfo or None
    """
    analyzer = SSLAnalyzer(timeout=timeout)
    return analyzer.get_certificate(host, port)


def check_ssl_vulnerabilities(host: str, port: int = 443, timeout: float = 5.0) -> List[VulnerabilityResult]:
    """
    Convenience function to check SSL vulnerabilities.
    
    Args:
        host: Target hostname or IP address
        port: Target port (default 443)
        timeout: Socket timeout in seconds
        
    Returns:
        List of VulnerabilityResult
    """
    result = analyze_ssl(host, port, timeout)
    return result.vulnerabilities
