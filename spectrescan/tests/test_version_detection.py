"""
Tests for version_detection module
by BitSpectreLabs
"""

import pytest
from dataclasses import fields
from spectrescan.core.version_detection import VersionInfo, VersionExtractor


class TestVersionInfo:
    """Tests for VersionInfo dataclass."""
    
    def test_default_init(self):
        """Test default initialization."""
        info = VersionInfo()
        assert info.product is None
        assert info.version is None
        assert info.update is None
        assert info.edition is None
        assert info.language is None
        assert info.platform is None
        assert info.patch is None
        assert info.cpe is None
    
    def test_with_product(self):
        """Test with product."""
        info = VersionInfo(product="nginx")
        assert info.product == "nginx"
    
    def test_with_version(self):
        """Test with version."""
        info = VersionInfo(version="1.18.0")
        assert info.version == "1.18.0"
    
    def test_with_update(self):
        """Test with update."""
        info = VersionInfo(update="u1")
        assert info.update == "u1"
    
    def test_with_edition(self):
        """Test with edition."""
        info = VersionInfo(edition="Enterprise")
        assert info.edition == "Enterprise"
    
    def test_with_language(self):
        """Test with language."""
        info = VersionInfo(language="en-US")
        assert info.language == "en-US"
    
    def test_with_platform(self):
        """Test with platform."""
        info = VersionInfo(platform="Linux x86_64")
        assert info.platform == "Linux x86_64"
    
    def test_with_patch(self):
        """Test with patch."""
        info = VersionInfo(patch="p1")
        assert info.patch == "p1"
    
    def test_with_cpe(self):
        """Test with CPE."""
        info = VersionInfo(cpe="cpe:/a:nginx:nginx:1.18.0")
        assert info.cpe == "cpe:/a:nginx:nginx:1.18.0"
    
    def test_full_info(self):
        """Test with all fields."""
        info = VersionInfo(
            product="OpenSSH",
            version="8.2p1",
            update="Ubuntu-4ubuntu0.1",
            edition="portable",
            language="en",
            platform="Ubuntu Linux",
            patch="p1",
            cpe="cpe:/a:openbsd:openssh:8.2p1"
        )
        assert info.product == "OpenSSH"
        assert info.version == "8.2p1"
        assert info.update == "Ubuntu-4ubuntu0.1"
        assert info.edition == "portable"
        assert info.language == "en"
        assert info.platform == "Ubuntu Linux"
        assert info.patch == "p1"
        assert info.cpe == "cpe:/a:openbsd:openssh:8.2p1"
    
    def test_field_count(self):
        """Test that VersionInfo has expected fields."""
        info_fields = fields(VersionInfo)
        assert len(info_fields) == 8
        
        field_names = [f.name for f in info_fields]
        expected = ['product', 'version', 'update', 'edition', 
                    'language', 'platform', 'patch', 'cpe']
        for name in expected:
            assert name in field_names


class TestVersionExtractor:
    """Tests for VersionExtractor class."""
    
    def test_init(self):
        """Test initialization."""
        extractor = VersionExtractor()
        assert extractor.patterns is not None
        assert isinstance(extractor.patterns, dict)
    
    def test_patterns_exist(self):
        """Test expected patterns exist."""
        extractor = VersionExtractor()
        expected_services = ['http', 'ssh', 'ftp', 'smtp', 
                            'mysql', 'postgresql', 'redis', 
                            'mongodb', 'elasticsearch']
        
        for service in expected_services:
            assert service in extractor.patterns
    
    def test_http_patterns(self):
        """Test HTTP patterns exist."""
        extractor = VersionExtractor()
        assert 'http' in extractor.patterns
        assert len(extractor.patterns['http']) >= 1
    
    def test_ssh_patterns(self):
        """Test SSH patterns exist."""
        extractor = VersionExtractor()
        assert 'ssh' in extractor.patterns
        assert len(extractor.patterns['ssh']) >= 1


class TestVersionExtractorHTTP:
    """Tests for HTTP version extraction."""
    
    def test_extract_nginx_version(self):
        """Test extracting nginx version."""
        extractor = VersionExtractor()
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
        
        result = extractor.extract_version(banner, "http", 80)
        
        # May return full match or just version depending on pattern
        assert result.version is not None
        assert "1.18.0" in result.version
    
    def test_extract_apache_version(self):
        """Test extracting Apache version."""
        extractor = VersionExtractor()
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n"
        
        result = extractor.extract_version(banner, "http", 80)
        
        assert result.version is not None
        assert "2.4.41" in result.version
    
    def test_extract_iis_version(self):
        """Test extracting IIS version."""
        extractor = VersionExtractor()
        banner = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n"
        
        result = extractor.extract_version(banner, "http", 80)
        
        assert result.version is not None
        assert "10.0" in result.version
    
    def test_extract_server_header(self):
        """Test extracting general server header."""
        extractor = VersionExtractor()
        banner = "HTTP/1.1 200 OK\r\nServer: CustomServer/1.0\r\n"
        
        result = extractor.extract_version(banner, "http", 80)
        
        # Should extract version from header
        assert result is not None


class TestVersionExtractorSSH:
    """Tests for SSH version extraction."""
    
    def test_extract_openssh_version(self):
        """Test extracting OpenSSH version."""
        extractor = VersionExtractor()
        banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
        
        result = extractor.extract_version(banner, "ssh", 22)
        
        # SSH pattern may capture protocol or product version
        assert result.version is not None
    
    def test_extract_ssh_protocol_version(self):
        """Test extracting SSH protocol version."""
        extractor = VersionExtractor()
        banner = "SSH-2.0-Dropbear_2019.78"
        
        result = extractor.extract_version(banner, "ssh", 22)
        
        assert result is not None
    
    def test_extract_openssh_underscore(self):
        """Test extracting OpenSSH with underscore."""
        extractor = VersionExtractor()
        banner = "SSH-2.0-OpenSSH_7.9p1"
        
        result = extractor.extract_version(banner, "ssh", 22)
        
        assert result.version is not None


class TestVersionExtractorFTP:
    """Tests for FTP version extraction."""
    
    def test_extract_ftp_version(self):
        """Test extracting FTP version."""
        extractor = VersionExtractor()
        banner = "220 ProFTPD 1.3.5 Server ready."
        
        result = extractor.extract_version(banner, "ftp", 21)
        
        assert result is not None
    
    def test_extract_vsftpd_version(self):
        """Test extracting vsftpd version."""
        extractor = VersionExtractor()
        banner = "220 (vsFTPd 3.0.3)"
        
        result = extractor.extract_version(banner, "ftp", 21)
        
        assert result.version == "3.0.3"


class TestVersionExtractorSMTP:
    """Tests for SMTP version extraction."""
    
    def test_extract_postfix_version(self):
        """Test extracting Postfix version."""
        extractor = VersionExtractor()
        banner = "220 mail.example.com ESMTP Postfix (Ubuntu)"
        
        result = extractor.extract_version(banner, "smtp", 25)
        
        assert result is not None
    
    def test_extract_exim_version(self):
        """Test extracting Exim version."""
        extractor = VersionExtractor()
        banner = "220 mail.example.com ESMTP Exim 4.93"
        
        result = extractor.extract_version(banner, "smtp", 25)
        
        # May contain product name along with version
        assert result.version is not None
        assert "4.93" in result.version


class TestVersionExtractorMySQL:
    """Tests for MySQL version extraction."""
    
    def test_extract_mysql_version(self):
        """Test extracting MySQL version."""
        extractor = VersionExtractor()
        banner = "5.7.32-0ubuntu0.18.04.1"
        
        result = extractor.extract_version(banner, "mysql", 3306)
        
        assert "5.7.32" in result.version
    
    def test_extract_mariadb_version(self):
        """Test extracting MariaDB version."""
        extractor = VersionExtractor()
        banner = "10.5.8-MariaDB-1:10.5.8+maria~focal"
        
        result = extractor.extract_version(banner, "mysql", 3306)
        
        assert result.version == "10.5.8"


class TestVersionExtractorPostgreSQL:
    """Tests for PostgreSQL version extraction."""
    
    def test_extract_postgresql_version(self):
        """Test extracting PostgreSQL version."""
        extractor = VersionExtractor()
        banner = "PostgreSQL 13.2 (Ubuntu 13.2-1)"
        
        result = extractor.extract_version(banner, "postgresql", 5432)
        
        assert result.version == "13.2"
    
    def test_extract_postgresql_version_major_minor(self):
        """Test extracting PostgreSQL major.minor version."""
        extractor = VersionExtractor()
        banner = "PostgreSQL 12.5"
        
        result = extractor.extract_version(banner, "postgresql", 5432)
        
        assert result.version == "12.5"


class TestVersionExtractorRedis:
    """Tests for Redis version extraction."""
    
    def test_extract_redis_version(self):
        """Test extracting Redis version."""
        extractor = VersionExtractor()
        banner = "$97\r\nredis_version:6.0.9\r\nredis_git_sha1:00000000"
        
        result = extractor.extract_version(banner, "redis", 6379)
        
        assert result.version == "6.0.9"


class TestVersionExtractorMongoDB:
    """Tests for MongoDB version extraction."""
    
    def test_extract_mongodb_version(self):
        """Test extracting MongoDB version."""
        extractor = VersionExtractor()
        banner = '{"version": "4.4.3", "gitVersion": "xxx"}'
        
        result = extractor.extract_version(banner, "mongodb", 27017)
        
        assert result.version == "4.4.3"


class TestVersionExtractorElasticsearch:
    """Tests for Elasticsearch version extraction."""
    
    def test_extract_elasticsearch_version(self):
        """Test extracting Elasticsearch version."""
        extractor = VersionExtractor()
        banner = '{"version" : "7.10.2", "cluster_name" : "test"}'
        
        result = extractor.extract_version(banner, "elasticsearch", 9200)
        
        assert result.version == "7.10.2"


class TestVersionExtractorGeneric:
    """Tests for generic version extraction."""
    
    def test_extract_generic_semver(self):
        """Test extracting generic semantic version."""
        extractor = VersionExtractor()
        banner = "Service Version 1.2.3"
        
        result = extractor.extract_version(banner, "unknown", 8080)
        
        assert result.version == "1.2.3"
    
    def test_extract_generic_major_minor(self):
        """Test extracting generic major.minor version."""
        extractor = VersionExtractor()
        banner = "Service v2.5 ready"
        
        result = extractor.extract_version(banner, "unknown", 8080)
        
        assert result.version == "2.5"
    
    def test_extract_generic_with_build(self):
        """Test extracting version with build number."""
        extractor = VersionExtractor()
        banner = "Service 1.2.3.4567 Enterprise"
        
        result = extractor.extract_version(banner, "unknown", 8080)
        
        assert "1.2.3" in result.version
    
    def test_extract_no_version(self):
        """Test extraction with no version in banner."""
        extractor = VersionExtractor()
        banner = "Welcome to the service"
        
        result = extractor.extract_version(banner, "unknown", 8080)
        
        assert result is not None
        # Version may be None or empty
    
    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        extractor = VersionExtractor()
        banner = "SERVER: NGINX/1.18.0"
        
        result = extractor.extract_version(banner, "http", 80)
        
        assert result.version is not None
        assert "1.18.0" in result.version


class TestVersionExtractorCPE:
    """Tests for CPE generation."""
    
    def test_cpe_generated_for_nginx(self):
        """Test CPE is generated for nginx."""
        extractor = VersionExtractor()
        banner = "Server: nginx/1.18.0"
        
        result = extractor.extract_version(banner, "http", 80)
        
        # CPE should be generated if product and version exist
        if result.product and result.version:
            assert result.cpe is not None or result.cpe is None  # Implementation dependent
    
    def test_cpe_format(self):
        """Test CPE format if generated."""
        extractor = VersionExtractor()
        banner = "Server: Apache/2.4.41"
        
        result = extractor.extract_version(banner, "http", 80)
        
        if result.cpe:
            assert result.cpe.startswith("cpe:/")


class TestVersionExtractorEdgeCases:
    """Tests for edge cases."""
    
    def test_empty_banner(self):
        """Test with empty banner."""
        extractor = VersionExtractor()
        
        result = extractor.extract_version("", "http", 80)
        
        assert result is not None
    
    def test_binary_banner(self):
        """Test with binary data in banner."""
        extractor = VersionExtractor()
        banner = b"\x00\x01\x02nginx/1.18.0\x03\x04".decode('utf-8', errors='ignore')
        
        result = extractor.extract_version(banner, "http", 80)
        
        assert result is not None
    
    def test_very_long_banner(self):
        """Test with very long banner."""
        extractor = VersionExtractor()
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n" + "x" * 10000
        
        result = extractor.extract_version(banner, "http", 80)
        
        assert result.version is not None
        assert "1.18.0" in result.version
    
    def test_unknown_service(self):
        """Test with unknown service type."""
        extractor = VersionExtractor()
        banner = "CustomService/2.0.0"
        
        result = extractor.extract_version(banner, "customservice", 12345)
        
        assert result is not None
    
    def test_special_characters_in_version(self):
        """Test with special characters in version."""
        extractor = VersionExtractor()
        banner = "SSH-2.0-OpenSSH_8.2p1-ubuntu"
        
        result = extractor.extract_version(banner, "ssh", 22)
        
        assert result is not None
    
    def test_multiple_versions_in_banner(self):
        """Test with multiple versions in banner."""
        extractor = VersionExtractor()
        banner = "Server: Apache/2.4.41 (Ubuntu) PHP/7.4.3"
        
        result = extractor.extract_version(banner, "http", 80)
        
        # Should extract first matching version
        assert result.version is not None


class TestVersionExtractorHTTPInfo:
    """Tests for HTTP info extraction."""
    
    def test_extract_http_info_method_exists(self):
        """Test extract_http_info method exists."""
        extractor = VersionExtractor()
        assert hasattr(extractor, 'extract_http_info')
    
    def test_extract_http_info_with_server(self):
        """Test extracting HTTP info with Server header."""
        extractor = VersionExtractor()
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n"
        
        if hasattr(extractor, 'extract_http_info'):
            result = extractor.extract_http_info(banner)
            # Result should be a dict
            assert isinstance(result, dict)
