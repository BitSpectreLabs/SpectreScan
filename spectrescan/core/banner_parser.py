"""
Enhanced Banner Parsing and Technology Detection

Parse banners to extract detailed service information and detect technologies,
frameworks, CMS, and security appliances.

File: spectrescan/core/banner_parser.py
Author: BitSpectreLabs
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import logging

logger = logging.getLogger(__name__)


@dataclass
class TechnologyStack:
    """Detected technology stack information."""
    
    web_server: Optional[str] = None
    app_framework: Optional[str] = None
    programming_language: Optional[str] = None
    database: Optional[str] = None
    cms: Optional[str] = None
    waf: Optional[str] = None
    load_balancer: Optional[str] = None
    cdn: Optional[str] = None
    operating_system: Optional[str] = None
    additional_tech: List[str] = field(default_factory=list)


@dataclass
class ParsedBanner:
    """Comprehensive banner parsing result."""
    
    raw_banner: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    technology: Optional[TechnologyStack] = None
    ssl_info: Optional[Dict[str, str]] = None
    metadata: Dict[str, str] = field(default_factory=dict)


class BannerParser:
    """Enhanced banner parser with technology detection."""
    
    def __init__(self):
        # Technology fingerprints
        self._init_fingerprints()
    
    def _init_fingerprints(self):
        """Initialize technology detection fingerprints."""
        
        # Web servers
        self.web_servers = {
            r'nginx/(\d+\.\d+\.\d+)': ('nginx', 1),
            r'Apache/(\d+\.\d+\.\d+)': ('Apache', 1),
            r'Microsoft-IIS/(\d+\.\d+)': ('IIS', 1),
            r'LiteSpeed': ('LiteSpeed', None),
            r'Caddy': ('Caddy', None),
            r'Tomcat/(\d+\.\d+)': ('Apache Tomcat', 1),
            r'Jetty\((\d+\.\d+)': ('Jetty', 1),
        }
        
        # Application frameworks
        self.frameworks = {
            r'X-Powered-By:.*?PHP/(\d+\.\d+\.\d+)': ('PHP', 1),
            r'X-Powered-By:.*?Express': ('Express.js', None),
            r'X-AspNet-Version: (\d+\.\d+)': ('ASP.NET', 1),
            r'X-AspNetMvc-Version: (\d+\.\d+)': ('ASP.NET MVC', 1),
            r'X-Powered-By:.*?Django': ('Django', None),
            r'X-Powered-By:.*?Flask': ('Flask', None),
            r'Server:.*?Kestrel': ('ASP.NET Core', None),
            r'X-Powered-By:.*?Next.js': ('Next.js', None),
            r'Server:.*?Uvicorn': ('Uvicorn/FastAPI', None),
            r'X-Powered-By:.*?Spring': ('Spring Framework', None),
            r'X-Powered-By:.*?Laravel': ('Laravel', None),
        }
        
        # CMS detection
        self.cms_patterns = {
            r'X-Powered-By:.*?WordPress': 'WordPress',
            r'wp-content/': 'WordPress',
            r'X-Drupal-': 'Drupal',
            r'Joomla!': 'Joomla',
            r'X-Magento-': 'Magento',
            r'X-Shopify-': 'Shopify',
            r'X-Ghost-': 'Ghost',
            r'/admin/content': 'Drupal',
        }
        
        # WAF detection
        self.waf_patterns = {
            r'cloudflare': 'Cloudflare',
            r'cf-ray': 'Cloudflare',
            r'X-Sucuri-': 'Sucuri',
            r'X-WAF-': 'Generic WAF',
            r'BarracudaWAF': 'Barracuda WAF',
            r'Imperva': 'Imperva',
            r'F5 BIG-IP': 'F5 BIG-IP ASM',
            r'AWS-WAF': 'AWS WAF',
            r'AzureWebApplication': 'Azure WAF',
        }
        
        # CDN detection
        self.cdn_patterns = {
            r'X-Cache:.*?cloudfront': 'Amazon CloudFront',
            r'X-CDN:.*?Fastly': 'Fastly',
            r'Server:.*?AkamaiGHost': 'Akamai',
            r'X-Edge-': 'Generic CDN',
            r'cf-ray': 'Cloudflare CDN',
        }
        
        # Load balancers
        self.lb_patterns = {
            r'X-Forwarded-For': 'Reverse Proxy/Load Balancer',
            r'X-LB-': 'Load Balancer',
            r'HAProxy': 'HAProxy',
            r'F5 BIG-IP': 'F5 BIG-IP',
        }
        
        # Programming languages
        self.languages = {
            r'PHP': 'PHP',
            r'Python': 'Python',
            r'Java': 'Java',
            r'\.NET': '.NET',
            r'Ruby': 'Ruby',
            r'Node\.js': 'Node.js',
            r'Perl': 'Perl',
            r'Go': 'Go',
        }
    
    def parse(self, banner: str, service: Optional[str] = None) -> ParsedBanner:
        """
        Parse banner and extract all available information.
        
        Args:
            banner: Raw banner text
            service: Known service name (optional)
            
        Returns:
            ParsedBanner object with parsed information
        """
        parsed = ParsedBanner(raw_banner=banner, service=service)
        
        # Parse based on service type
        if service:
            service_lower = service.lower()
            
            if 'http' in service_lower:
                self._parse_http(banner, parsed)
            elif 'ssh' in service_lower:
                self._parse_ssh(banner, parsed)
            elif 'ftp' in service_lower:
                self._parse_ftp(banner, parsed)
            elif 'smtp' in service_lower:
                self._parse_smtp(banner, parsed)
            elif 'mysql' in service_lower or 'mariadb' in service_lower:
                self._parse_mysql(banner, parsed)
            elif 'postgres' in service_lower:
                self._parse_postgresql(banner, parsed)
            elif 'redis' in service_lower:
                self._parse_redis(banner, parsed)
            elif 'mongo' in service_lower:
                self._parse_mongodb(banner, parsed)
        
        # Generic parsing
        self._parse_generic(banner, parsed)
        
        # Detect technology stack
        parsed.technology = self._detect_technology(banner, parsed)
        
        return parsed
    
    def _parse_http(self, banner: str, parsed: ParsedBanner):
        """Parse HTTP response banner."""
        # Set service to http
        parsed.service = "http"
        
        lines = banner.split('\r\n')
        
        # Parse status line
        if lines:
            status_match = re.match(r'HTTP/(\d\.\d) (\d{3}) (.+)', lines[0])
            if status_match:
                parsed.metadata['http_version'] = status_match.group(1)
                parsed.metadata['status_code'] = status_match.group(2)
                parsed.metadata['status_text'] = status_match.group(3)
        
        # Parse headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                parsed.headers[key.strip()] = value.strip()
        
        # Extract server info
        if 'Server' in parsed.headers:
            server = parsed.headers['Server']
            parsed.product = server.split('/')[0] if '/' in server else server
            
            # Extract version
            version_match = re.search(r'/(\d+\.\d+(?:\.\d+)?)', server)
            if version_match:
                parsed.version = version_match.group(1)
    
    def _parse_ssh(self, banner: str, parsed: ParsedBanner):
        """Parse SSH banner."""
        # Set service to ssh
        parsed.service = "ssh"
        
        # Format: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
        match = re.match(r'SSH-(\d+\.\d+)-(.+)', banner.strip())
        if match:
            parsed.metadata['protocol_version'] = match.group(1)
            software = match.group(2)
            
            # Parse software string
            parts = software.split()
            if parts:
                parsed.product = parts[0].split('_')[0]
                
                # Extract version
                version_match = re.search(r'(\d+\.\d+(?:p\d+)?)', software)
                if version_match:
                    parsed.version = version_match.group(1)
                
                # Extract OS info
                if len(parts) > 1:
                    parsed.os = ' '.join(parts[1:])
    
    def _parse_ftp(self, banner: str, parsed: ParsedBanner):
        """Parse FTP banner."""
        # Set service to ftp
        parsed.service = "ftp"
        
        # Format: 220 ProFTPD 1.3.5 Server ready
        match = re.match(r'220[- ](.+)', banner.strip())
        if match:
            banner_text = match.group(1)
            parsed.metadata['welcome'] = banner_text
            
            # Extract product and version
            product_match = re.search(r'(\w+)\s+(\d+\.\d+\.\d+)', banner_text)
            if product_match:
                parsed.product = product_match.group(1)
                parsed.version = product_match.group(2)
    
    def _parse_smtp(self, banner: str, parsed: ParsedBanner):
        """Parse SMTP banner."""
        # Set service to smtp
        parsed.service = "smtp"
        
        # Format: 220 mail.example.com ESMTP Postfix
        match = re.match(r'220[- ]([^\s]+)\s+ESMTP\s+(.+)', banner.strip())
        if match:
            parsed.hostname = match.group(1)
            parsed.product = match.group(2).strip()
            
            # Extract version
            version_match = re.search(r'(\d+\.\d+\.\d+)', parsed.product)
            if version_match:
                parsed.version = version_match.group(1)
    
    def _parse_mysql(self, banner: str, parsed: ParsedBanner):
        """Parse MySQL/MariaDB banner."""
        # Set service to mysql
        parsed.service = "mysql"
        
        # MariaDB detection
        if 'MariaDB' in banner:
            parsed.product = 'MariaDB'
            version_match = re.search(r'(\d+\.\d+\.\d+)-MariaDB', banner)
            if version_match:
                parsed.version = version_match.group(1)
        else:
            parsed.product = 'MySQL'
            version_match = re.search(r'(\d+\.\d+\.\d+)', banner)
            if version_match:
                parsed.version = version_match.group(1)
    
    def _parse_postgresql(self, banner: str, parsed: ParsedBanner):
        """Parse PostgreSQL banner."""
        parsed.service = "postgresql"
        parsed.product = 'PostgreSQL'
        version_match = re.search(r'PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)', banner, re.I)
        if version_match:
            parsed.version = version_match.group(1)
    
    def _parse_redis(self, banner: str, parsed: ParsedBanner):
        """Parse Redis banner."""
        parsed.service = "redis"
        parsed.product = 'Redis'
        version_match = re.search(r'redis_version:(\d+\.\d+\.\d+)', banner)
        if version_match:
            parsed.version = version_match.group(1)
    
    def _parse_mongodb(self, banner: str, parsed: ParsedBanner):
        """Parse MongoDB banner."""
        parsed.service = "mongodb"
        parsed.product = 'MongoDB'
        version_match = re.search(r'version"?:\s*"?(\d+\.\d+\.\d+)', banner)
        if version_match:
            parsed.version = version_match.group(1)
    
    def _parse_generic(self, banner: str, parsed: ParsedBanner):
        """Generic banner parsing for unknown services."""
        banner_lower = banner.lower()
        
        # Detect common modern services (order matters - check most specific first)
        if 'mongodb' in banner_lower or ('"version"' in banner and 'gitVersion' in banner and 'mongo' not in banner_lower):
            parsed.service = "mongodb"
            version_match = re.search(r'"version"\s*:\s*"(\d+\.\d+\.\d+)"', banner)
            if version_match:
                parsed.version = version_match.group(1)
        elif 'docker' in banner_lower and '"Version"' in banner:
            parsed.service = "docker"
            version_match = re.search(r'"Version":"(\d+\.\d+\.\d+)"', banner)
            if version_match:
                parsed.version = version_match.group(1)
        elif 'kubernetes' in banner_lower or 'gitVersion' in banner:
            parsed.service = "kubernetes"
            version_match = re.search(r'"gitVersion":"v(\d+\.\d+\.\d+)"', banner)
            if version_match:
                parsed.version = version_match.group(1)
        elif 'elasticsearch' in banner_lower or 'cluster_name' in banner_lower:
            parsed.service = "elasticsearch"
            version_match = re.search(r'"number"\s*:\s*"(\d+\.\d+\.\d+)"', banner)
            if version_match:
                parsed.version = version_match.group(1)
        
        # Look for version patterns
        if not parsed.version:
            version_patterns = [
                r'(\d+\.\d+\.\d+)',
                r'v(\d+\.\d+)',
            ]
            for pattern in version_patterns:
                match = re.search(pattern, banner)
                if match:
                    parsed.version = match.group(1)
                    break
    
    def _detect_technology(
        self,
        banner: str,
        parsed: ParsedBanner
    ) -> TechnologyStack:
        """
        Detect technology stack from banner.
        
        Args:
            banner: Raw banner
            parsed: Parsed banner object
            
        Returns:
            TechnologyStack object
        """
        tech = TechnologyStack()
        banner_lower = banner.lower()
        
        # Web server detection
        for pattern, (name, version_group) in self.web_servers.items():
            match = re.search(pattern, banner, re.I)
            if match:
                tech.web_server = name
                if version_group and match.groups():
                    tech.web_server += f" {match.group(version_group)}"
                break
        
        # Framework detection
        for pattern, (name, version_group) in self.frameworks.items():
            match = re.search(pattern, banner, re.I)
            if match:
                tech.app_framework = name
                if version_group and match.groups():
                    tech.app_framework += f" {match.group(version_group)}"
                break
        
        # CMS detection
        for pattern, name in self.cms_patterns.items():
            if re.search(pattern, banner, re.I):
                tech.cms = name
                break
        
        # WAF detection
        for pattern, name in self.waf_patterns.items():
            if re.search(pattern, banner, re.I):
                tech.waf = name
                break
        
        # CDN detection
        for pattern, name in self.cdn_patterns.items():
            if re.search(pattern, banner, re.I):
                tech.cdn = name
                break
        
        # Load balancer detection
        for pattern, name in self.lb_patterns.items():
            if re.search(pattern, banner, re.I):
                tech.load_balancer = name
                break
        
        # Programming language detection
        for pattern, name in self.languages.items():
            if re.search(pattern, banner, re.I):
                tech.programming_language = name
                break
        
        # OS detection from headers
        if 'ubuntu' in banner_lower:
            tech.operating_system = 'Ubuntu'
        elif 'debian' in banner_lower:
            tech.operating_system = 'Debian'
        elif 'centos' in banner_lower:
            tech.operating_system = 'CentOS'
        elif 'windows' in banner_lower or 'microsoft' in banner_lower:
            tech.operating_system = 'Windows'
        
        return tech
    
    def detect_vulnerabilities(self, parsed: ParsedBanner) -> List[str]:
        """
        Detect potential vulnerabilities based on banner info.
        
        Args:
            parsed: ParsedBanner object
            
        Returns:
            List of vulnerability indicators
        """
        vulns = []
        
        # Check for outdated/vulnerable services
        if parsed.product and parsed.version:
            product_lower = parsed.product.lower()
            
            # Known vulnerable versions (examples)
            if 'apache' in product_lower:
                if parsed.version < '2.4.50':
                    vulns.append('Apache < 2.4.50 (CVE-2021-42013 path traversal)')
            
            elif 'openssh' in product_lower:
                if parsed.version < '7.7':
                    vulns.append('OpenSSH < 7.7 (username enumeration)')
            
            elif 'nginx' in product_lower:
                if parsed.version < '1.20.0':
                    vulns.append('Nginx < 1.20.0 (potential vulnerabilities)')
        
        # Check for insecure protocols
        if parsed.service:
            service_lower = parsed.service.lower()
            if service_lower in ['ftp', 'telnet', 'http']:
                vulns.append(f'Insecure protocol: {service_lower} (unencrypted)')
        
        return vulns


def parse_banner(banner: str, service: Optional[str] = None) -> ParsedBanner:
    """
    Convenience function to parse a banner.
    
    Args:
        banner: Raw banner text
        service: Known service name (optional)
        
    Returns:
        ParsedBanner object
    """
    parser = BannerParser()
    return parser.parse(banner, service)
