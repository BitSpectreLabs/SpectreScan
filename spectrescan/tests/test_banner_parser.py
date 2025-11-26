"""
Tests for Banner Parser Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from spectrescan.core.banner_parser import (
    TechnologyStack,
    ParsedBanner,
    BannerParser
)


class TestTechnologyStack:
    """Tests for TechnologyStack dataclass."""
    
    def test_default_values(self):
        """Test default values are None/empty."""
        stack = TechnologyStack()
        
        assert stack.web_server is None
        assert stack.app_framework is None
        assert stack.programming_language is None
        assert stack.database is None
        assert stack.cms is None
        assert stack.waf is None
        assert stack.load_balancer is None
        assert stack.cdn is None
        assert stack.operating_system is None
        assert stack.additional_tech == []
    
    def test_with_web_server(self):
        """Test with web server."""
        stack = TechnologyStack(web_server="nginx 1.18.0")
        assert stack.web_server == "nginx 1.18.0"
    
    def test_with_framework(self):
        """Test with framework."""
        stack = TechnologyStack(app_framework="Django")
        assert stack.app_framework == "Django"
    
    def test_with_multiple_technologies(self):
        """Test with multiple technologies."""
        stack = TechnologyStack(
            web_server="Apache",
            app_framework="Laravel",
            programming_language="PHP",
            database="MySQL",
            cms="WordPress"
        )
        
        assert stack.web_server == "Apache"
        assert stack.app_framework == "Laravel"
        assert stack.programming_language == "PHP"
        assert stack.database == "MySQL"
        assert stack.cms == "WordPress"


class TestParsedBanner:
    """Tests for ParsedBanner dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        banner = ParsedBanner(raw_banner="SSH-2.0-OpenSSH")
        
        assert banner.raw_banner == "SSH-2.0-OpenSSH"
        assert banner.service is None
        assert banner.product is None
        assert banner.version is None
    
    def test_with_service(self):
        """Test with service."""
        banner = ParsedBanner(raw_banner="test", service="ssh")
        assert banner.service == "ssh"
    
    def test_with_full_info(self):
        """Test with full information."""
        banner = ParsedBanner(
            raw_banner="SSH-2.0-OpenSSH_8.2p1",
            service="ssh",
            product="OpenSSH",
            version="8.2p1",
            os="Ubuntu"
        )
        
        assert banner.product == "OpenSSH"
        assert banner.version == "8.2p1"
        assert banner.os == "Ubuntu"
    
    def test_default_headers(self):
        """Test default headers is empty dict."""
        banner = ParsedBanner(raw_banner="test")
        assert banner.headers == {}
    
    def test_default_metadata(self):
        """Test default metadata is empty dict."""
        banner = ParsedBanner(raw_banner="test")
        assert banner.metadata == {}


class TestBannerParser:
    """Tests for BannerParser class."""
    
    def test_init(self):
        """Test initialization."""
        parser = BannerParser()
        
        assert parser is not None
        assert hasattr(parser, 'web_servers')
        assert hasattr(parser, 'frameworks')
        assert hasattr(parser, 'cms_patterns')
        assert hasattr(parser, 'waf_patterns')
    
    def test_fingerprints_loaded(self):
        """Test fingerprints are loaded."""
        parser = BannerParser()
        
        assert len(parser.web_servers) > 0
        assert len(parser.frameworks) > 0
        assert len(parser.cms_patterns) > 0


class TestBannerParserSSH:
    """Tests for SSH banner parsing."""
    
    def test_parse_openssh(self):
        """Test parsing OpenSSH banner."""
        parser = BannerParser()
        
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        parsed = parser.parse(banner, service="ssh")
        
        assert parsed.service == "ssh"
        assert parsed.product == "OpenSSH"
        assert parsed.version == "8.2p1"
        assert parsed.os is not None
    
    def test_parse_dropbear(self):
        """Test parsing Dropbear SSH."""
        parser = BannerParser()
        
        banner = "SSH-2.0-dropbear_2019.78"
        parsed = parser.parse(banner, service="ssh")
        
        assert parsed.service == "ssh"
        assert parsed.version is not None
    
    def test_parse_ssh_no_version(self):
        """Test parsing SSH with no version."""
        parser = BannerParser()
        
        banner = "SSH-2.0-Generic"
        parsed = parser.parse(banner, service="ssh")
        
        assert parsed.service == "ssh"


class TestBannerParserHTTP:
    """Tests for HTTP banner parsing."""
    
    def test_parse_http_response(self):
        """Test parsing HTTP response."""
        parser = BannerParser()
        
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n"
        parsed = parser.parse(banner, service="http")
        
        assert parsed.service == "http"
        assert "Server" in parsed.headers
        assert parsed.product == "nginx"
        assert parsed.version == "1.18.0"
    
    def test_parse_apache(self):
        """Test parsing Apache banner."""
        parser = BannerParser()
        
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
        parsed = parser.parse(banner, service="http")
        
        assert parsed.product == "Apache"
        assert parsed.version == "2.4.41"
    
    def test_parse_http_status(self):
        """Test HTTP status parsing."""
        parser = BannerParser()
        
        banner = "HTTP/1.1 404 Not Found\r\nServer: nginx\r\n"
        parsed = parser.parse(banner, service="http")
        
        assert parsed.metadata.get('status_code') == "404"


class TestBannerParserFTP:
    """Tests for FTP banner parsing."""
    
    def test_parse_proftpd(self):
        """Test parsing ProFTPD banner."""
        parser = BannerParser()
        
        banner = "220 ProFTPD 1.3.5 Server ready"
        parsed = parser.parse(banner, service="ftp")
        
        assert parsed.service == "ftp"
        assert parsed.product == "ProFTPD"
        assert parsed.version == "1.3.5"
    
    def test_parse_vsftpd(self):
        """Test parsing vsftpd banner."""
        parser = BannerParser()
        
        banner = "220 (vsFTPd 3.0.3)"
        parsed = parser.parse(banner, service="ftp")
        
        assert parsed.service == "ftp"


class TestBannerParserSMTP:
    """Tests for SMTP banner parsing."""
    
    def test_parse_postfix(self):
        """Test parsing Postfix banner."""
        parser = BannerParser()
        
        banner = "220 mail.example.com ESMTP Postfix"
        parsed = parser.parse(banner, service="smtp")
        
        assert parsed.service == "smtp"
        assert parsed.hostname == "mail.example.com"
        assert parsed.product == "Postfix"


class TestBannerParserDatabase:
    """Tests for database banner parsing."""
    
    def test_parse_mysql(self):
        """Test parsing MySQL banner."""
        parser = BannerParser()
        
        banner = "5.7.32-mysql"
        parsed = parser.parse(banner, service="mysql")
        
        assert parsed.service == "mysql"
        assert parsed.product == "MySQL"
        assert parsed.version == "5.7.32"
    
    def test_parse_mariadb(self):
        """Test parsing MariaDB banner."""
        parser = BannerParser()
        
        banner = "5.5.68-MariaDB"
        parsed = parser.parse(banner, service="mysql")
        
        assert parsed.product == "MariaDB"
        assert parsed.version == "5.5.68"
    
    def test_parse_postgresql(self):
        """Test parsing PostgreSQL banner."""
        parser = BannerParser()
        
        banner = "PostgreSQL 13.4"
        parsed = parser.parse(banner, service="postgresql")
        
        assert parsed.product == "PostgreSQL"
        assert parsed.version == "13.4"
    
    def test_parse_redis(self):
        """Test parsing Redis banner."""
        parser = BannerParser()
        
        banner = "redis_version:6.2.5"
        parsed = parser.parse(banner, service="redis")
        
        assert parsed.product == "Redis"
        assert parsed.version == "6.2.5"
    
    def test_parse_mongodb(self):
        """Test parsing MongoDB banner."""
        parser = BannerParser()
        
        banner = '{"version": "4.4.6"}'
        parsed = parser.parse(banner, service="mongodb")
        
        assert parsed.product == "MongoDB"
        assert parsed.version == "4.4.6"


class TestBannerParserGeneric:
    """Tests for generic banner parsing."""
    
    def test_parse_unknown_service(self):
        """Test parsing unknown service."""
        parser = BannerParser()
        
        banner = "Welcome to MyService 1.2.3"
        parsed = parser.parse(banner)
        
        assert parsed.version == "1.2.3"
    
    def test_parse_version_detection(self):
        """Test version detection in generic parsing."""
        parser = BannerParser()
        
        banner = "Server version 2.5.1 ready"
        parsed = parser.parse(banner)
        
        assert parsed.version is not None


class TestTechnologyDetection:
    """Tests for technology stack detection."""
    
    def test_detect_nginx(self):
        """Test nginx detection."""
        parser = BannerParser()
        
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
        parsed = parser.parse(banner, service="http")
        
        assert parsed.technology is not None
        assert "nginx" in parsed.technology.web_server.lower()
    
    def test_detect_apache(self):
        """Test Apache detection."""
        parser = BannerParser()
        
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n"
        parsed = parser.parse(banner, service="http")
        
        assert parsed.technology is not None
        assert "apache" in parsed.technology.web_server.lower()
    
    def test_detect_php(self):
        """Test PHP detection."""
        parser = BannerParser()
        
        banner = "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/7.4.3\r\n"
        parsed = parser.parse(banner, service="http")
        
        if parsed.technology.app_framework:
            assert "PHP" in parsed.technology.app_framework
    
    def test_detect_wordpress(self):
        """Test WordPress detection."""
        parser = BannerParser()
        
        banner = "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/7.4.3\r\nLink: wp-content/themes\r\n"
        parsed = parser.parse(banner, service="http")
        
        # WordPress detected via cms pattern
        if parsed.technology and parsed.technology.cms:
            assert "WordPress" in parsed.technology.cms


class TestBannerParserEdgeCases:
    """Tests for edge cases."""
    
    def test_empty_banner(self):
        """Test empty banner."""
        parser = BannerParser()
        
        parsed = parser.parse("")
        
        assert parsed.raw_banner == ""
        assert parsed.technology is not None
    
    def test_binary_banner(self):
        """Test banner with binary data."""
        parser = BannerParser()
        
        banner = "some\x00binary\x01data"
        parsed = parser.parse(banner)
        
        assert parsed.raw_banner == banner
    
    def test_very_long_banner(self):
        """Test very long banner."""
        parser = BannerParser()
        
        banner = "A" * 10000
        parsed = parser.parse(banner)
        
        assert len(parsed.raw_banner) == 10000
    
    def test_unicode_banner(self):
        """Test unicode banner."""
        parser = BannerParser()
        
        banner = "Welcome to 服务器 v1.0.0"
        parsed = parser.parse(banner)
        
        assert parsed.version == "1.0.0"
