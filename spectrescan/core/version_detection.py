"""
Version Detection Engine

Extract and parse version information from service banners and responses.

File: spectrescan/core/version_detection.py
Author: BitSpectreLabs
"""

import re
from dataclasses import dataclass
from typing import Optional, Dict, List, Tuple
import logging

logger = logging.getLogger(__name__)


@dataclass
class VersionInfo:
    """Parsed version information."""
    
    product: Optional[str] = None
    version: Optional[str] = None
    update: Optional[str] = None
    edition: Optional[str] = None
    language: Optional[str] = None
    platform: Optional[str] = None
    patch: Optional[str] = None
    cpe: Optional[str] = None


class VersionExtractor:
    """Extract version information from banners and responses."""
    
    def __init__(self):
        # Common version patterns for various services
        self.patterns = {
            "http": [
                (re.compile(r'Server:\s*([^\r\n]+)', re.I), "server"),
                (re.compile(r'X-Powered-By:\s*([^\r\n]+)', re.I), "powered_by"),
                (re.compile(r'nginx/(\d+\.\d+\.\d+)', re.I), "nginx"),
                (re.compile(r'Apache/(\d+\.\d+\.\d+)', re.I), "apache"),
                (re.compile(r'Microsoft-IIS/(\d+\.\d+)', re.I), "iis"),
            ],
            "ssh": [
                (re.compile(r'SSH-(\d+\.\d+)-([^\r\n]+)', re.I), "ssh"),
                (re.compile(r'OpenSSH[_/](\d+\.\d+(?:p\d+)?)', re.I), "openssh"),
            ],
            "ftp": [
                (re.compile(r'220[- ].*?FTP.*?(\d+\.\d+\.\d+)', re.I), "version"),
                (re.compile(r'220[- ]([^\r\n(]+)', re.I), "banner"),
            ],
            "smtp": [
                (re.compile(r'220.*?ESMTP\s+([^\r\n]+)', re.I), "esmtp"),
                (re.compile(r'Postfix\)?(\d+\.\d+\.\d+)?', re.I), "postfix"),
                (re.compile(r'Exim\s+(\d+\.\d+)', re.I), "exim"),
            ],
            "mysql": [
                (re.compile(r'(\d+\.\d+\.\d+)-MariaDB', re.I), "mariadb"),
                (re.compile(r'(\d+\.\d+\.\d+)', re.I), "mysql"),
            ],
            "postgresql": [
                (re.compile(r'PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)', re.I), "postgresql"),
            ],
            "redis": [
                (re.compile(r'redis_version:(\d+\.\d+\.\d+)', re.I), "redis"),
            ],
            "mongodb": [
                (re.compile(r'version"?:\s*"?(\d+\.\d+\.\d+)', re.I), "mongodb"),
            ],
            "elasticsearch": [
                (re.compile(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', re.I), "elasticsearch"),
            ],
        }
    
    def extract_version(
        self,
        banner: str,
        service: str,
        port: int
    ) -> VersionInfo:
        """
        Extract version information from banner.
        
        Args:
            banner: Service banner
            service: Service name
            port: Port number
            
        Returns:
            VersionInfo object
        """
        version_info = VersionInfo()
        
        # Try service-specific patterns
        service_lower = service.lower()
        if service_lower in self.patterns:
            for pattern, pattern_type in self.patterns[service_lower]:
                match = pattern.search(banner)
                if match:
                    if match.groups():
                        version_info.version = match.group(1)
                        version_info.product = service
                        break
        
        # Try generic version patterns
        if not version_info.version:
            version_info = self._extract_generic_version(banner, service)
        
        # Generate CPE if we have enough info
        if version_info.product and version_info.version:
            version_info.cpe = self._generate_cpe(
                version_info.product,
                version_info.version
            )
        
        return version_info
    
    def _extract_generic_version(self, banner: str, service: str) -> VersionInfo:
        """Extract version using generic patterns."""
        version_info = VersionInfo(product=service)
        
        # Generic version patterns
        patterns = [
            # Standard version format: 1.2.3
            re.compile(r'(\d+\.\d+\.\d+)'),
            # Version with alpha/beta: 1.2.3-beta
            re.compile(r'(\d+\.\d+\.\d+-[a-z]+\d*)'),
            # Version with build: 1.2.3.4567
            re.compile(r'(\d+\.\d+\.\d+\.\d+)'),
            # Simple version: 1.2
            re.compile(r'(\d+\.\d+)(?![.\d])'),
        ]
        
        for pattern in patterns:
            match = pattern.search(banner)
            if match:
                version_info.version = match.group(1)
                break
        
        return version_info
    
    def extract_http_info(self, banner: str) -> Dict[str, str]:
        """
        Extract detailed HTTP information from banner.
        
        Args:
            banner: HTTP response banner
            
        Returns:
            Dictionary with HTTP info
        """
        info = {}
        
        # Server header
        server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.I)
        if server_match:
            info['server'] = server_match.group(1)
        
        # X-Powered-By header
        powered_match = re.search(r'X-Powered-By:\s*([^\r\n]+)', banner, re.I)
        if powered_match:
            info['powered_by'] = powered_match.group(1)
        
        # Content-Type
        content_match = re.search(r'Content-Type:\s*([^\r\n]+)', banner, re.I)
        if content_match:
            info['content_type'] = content_match.group(1)
        
        # Set-Cookie (framework detection)
        cookie_match = re.search(r'Set-Cookie:\s*([^\r\n]+)', banner, re.I)
        if cookie_match:
            cookie = cookie_match.group(1)
            info['cookie'] = cookie
            
            # Detect frameworks by cookie names
            if 'PHPSESSID' in cookie:
                info['framework'] = 'PHP'
            elif 'ASP.NET_SessionId' in cookie:
                info['framework'] = 'ASP.NET'
            elif 'JSESSIONID' in cookie:
                info['framework'] = 'Java/JSP'
            elif 'connect.sid' in cookie:
                info['framework'] = 'Express.js'
            elif 'sessionid' in cookie:
                info['framework'] = 'Django/Flask'
        
        return info
    
    def extract_ssh_info(self, banner: str) -> Dict[str, str]:
        """
        Extract SSH protocol and implementation info.
        
        Args:
            banner: SSH banner
            
        Returns:
            Dictionary with SSH info
        """
        info = {}
        
        # SSH protocol version
        protocol_match = re.search(r'SSH-(\d+\.\d+)-([^\r\n]+)', banner, re.I)
        if protocol_match:
            info['protocol_version'] = protocol_match.group(1)
            info['software'] = protocol_match.group(2)
            
            # Parse software for version
            software = protocol_match.group(2)
            
            # OpenSSH
            openssh_match = re.search(r'OpenSSH[_/](\d+\.\d+(?:p\d+)?)', software, re.I)
            if openssh_match:
                info['product'] = 'OpenSSH'
                info['version'] = openssh_match.group(1)
            
            # Dropbear
            dropbear_match = re.search(r'dropbear[_/](\d+\.\d+)', software, re.I)
            if dropbear_match:
                info['product'] = 'Dropbear'
                info['version'] = dropbear_match.group(1)
        
        return info
    
    def extract_database_info(self, banner: str, service: str) -> Dict[str, str]:
        """
        Extract database version information.
        
        Args:
            banner: Database banner
            service: Database service name
            
        Returns:
            Dictionary with database info
        """
        info = {'product': service}
        
        if 'mysql' in service.lower() or 'mariadb' in service.lower():
            # MariaDB
            mariadb_match = re.search(r'(\d+\.\d+\.\d+)-MariaDB', banner, re.I)
            if mariadb_match:
                info['product'] = 'MariaDB'
                info['version'] = mariadb_match.group(1)
            # MySQL
            elif re.search(r'mysql', banner, re.I):
                mysql_match = re.search(r'(\d+\.\d+\.\d+)', banner)
                if mysql_match:
                    info['product'] = 'MySQL'
                    info['version'] = mysql_match.group(1)
        
        elif 'postgres' in service.lower():
            postgres_match = re.search(r'PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)', banner, re.I)
            if postgres_match:
                info['version'] = postgres_match.group(1)
        
        elif 'redis' in service.lower():
            redis_match = re.search(r'redis_version:(\d+\.\d+\.\d+)', banner, re.I)
            if redis_match:
                info['version'] = redis_match.group(1)
        
        elif 'mongo' in service.lower():
            mongo_match = re.search(r'version"?:\s*"?(\d+\.\d+\.\d+)', banner, re.I)
            if mongo_match:
                info['version'] = mongo_match.group(1)
        
        return info
    
    def _generate_cpe(self, product: str, version: str) -> str:
        """
        Generate CPE (Common Platform Enumeration) string.
        
        Args:
            product: Product name
            version: Version string
            
        Returns:
            CPE string
        """
        # Normalize product name
        product_normalized = product.lower().replace(' ', '_')
        
        # Map common products to CPE vendor
        vendor_map = {
            'nginx': 'nginx',
            'apache': 'apache',
            'openssh': 'openbsd',
            'mysql': 'oracle',
            'mariadb': 'mariadb',
            'postgresql': 'postgresql',
            'redis': 'redis',
            'mongodb': 'mongodb',
            'elasticsearch': 'elastic',
        }
        
        vendor = vendor_map.get(product_normalized, product_normalized)
        
        return f"cpe:/a:{vendor}:{product_normalized}:{version}"
    
    def parse_json_version(self, json_str: str) -> Dict[str, str]:
        """
        Parse version info from JSON response.
        
        Args:
            json_str: JSON string
            
        Returns:
            Dictionary with version info
        """
        info = {}
        
        # Common JSON version fields
        version_fields = ['version', 'Version', 'ver', 'release']
        
        for field in version_fields:
            pattern = re.compile(f'"{field}"\\s*:\\s*"([^"]+)"', re.I)
            match = pattern.search(json_str)
            if match:
                info['version'] = match.group(1)
                break
        
        # Product name
        name_fields = ['name', 'product', 'software', 'app']
        for field in name_fields:
            pattern = re.compile(f'"{field}"\\s*:\\s*"([^"]+)"', re.I)
            match = pattern.search(json_str)
            if match:
                info['product'] = match.group(1)
                break
        
        return info
    
    def parse_xml_version(self, xml_str: str) -> Dict[str, str]:
        """
        Parse version info from XML response.
        
        Args:
            xml_str: XML string
            
        Returns:
            Dictionary with version info
        """
        info = {}
        
        # Version tag
        version_match = re.search(r'<version>([^<]+)</version>', xml_str, re.I)
        if version_match:
            info['version'] = version_match.group(1)
        
        # Product tag
        product_match = re.search(r'<(?:product|name)>([^<]+)</(?:product|name)>', xml_str, re.I)
        if product_match:
            info['product'] = product_match.group(1)
        
        return info


def extract_version_from_banner(
    banner: str,
    service: str,
    port: int
) -> VersionInfo:
    """
    Convenience function to extract version from banner.
    
    Args:
        banner: Service banner
        service: Service name
        port: Port number
        
    Returns:
        VersionInfo object
    """
    extractor = VersionExtractor()
    return extractor.extract_version(banner, service, port)
