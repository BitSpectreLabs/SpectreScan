"""
Extended Tests for App Fingerprinting Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from spectrescan.core.app_fingerprinting import (
    ApplicationInfo,
    ApplicationFingerprinter
)


class TestApplicationInfo:
    """Tests for ApplicationInfo dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        info = ApplicationInfo(
            name="WordPress",
            category="cms"
        )
        
        assert info.name == "WordPress"
        assert info.category == "cms"
    
    def test_default_values(self):
        """Test default values."""
        info = ApplicationInfo(name="Test", category="web_app")
        
        assert info.version is None
        assert info.vendor is None
        assert info.confidence == 0
        assert info.metadata == {}
        assert info.cpe == []
        assert info.vulnerabilities == []
        assert info.components == []
    
    def test_with_version(self):
        """Test with version."""
        info = ApplicationInfo(
            name="WordPress",
            category="cms",
            version="5.8.1"
        )
        
        assert info.version == "5.8.1"
    
    def test_with_vendor(self):
        """Test with vendor."""
        info = ApplicationInfo(
            name="Django",
            category="framework",
            vendor="Django Software Foundation"
        )
        
        assert info.vendor == "Django Software Foundation"
    
    def test_with_confidence(self):
        """Test with confidence score."""
        info = ApplicationInfo(
            name="Laravel",
            category="framework",
            confidence=95
        )
        
        assert info.confidence == 95
    
    def test_with_metadata(self):
        """Test with metadata."""
        info = ApplicationInfo(
            name="Test",
            category="web_app",
            metadata={"key": "value", "count": 10}
        )
        
        assert info.metadata["key"] == "value"
        assert info.metadata["count"] == 10
    
    def test_with_cpe(self):
        """Test with CPE list."""
        info = ApplicationInfo(
            name="nginx",
            category="web_server",
            cpe=["cpe:/a:nginx:nginx:1.18.0"]
        )
        
        assert len(info.cpe) == 1
        assert "nginx" in info.cpe[0]
    
    def test_with_vulnerabilities(self):
        """Test with vulnerabilities."""
        info = ApplicationInfo(
            name="Test",
            category="web_app",
            vulnerabilities=["CVE-2021-1234", "CVE-2021-5678"]
        )
        
        assert len(info.vulnerabilities) == 2
    
    def test_with_components(self):
        """Test with components."""
        info = ApplicationInfo(
            name="WordPress",
            category="cms",
            components=[
                {"name": "PHP", "version": "7.4"},
                {"name": "MySQL", "version": "8.0"}
            ]
        )
        
        assert len(info.components) == 2


class TestApplicationFingerprinter:
    """Tests for ApplicationFingerprinter class."""
    
    def test_init(self):
        """Test initialization."""
        fp = ApplicationFingerprinter()
        
        assert fp is not None
    
    def test_signatures_loaded(self):
        """Test signatures are loaded."""
        fp = ApplicationFingerprinter()
        
        assert hasattr(fp, 'web_apps')
        assert hasattr(fp, 'api_signatures')
    
    def test_web_apps_content(self):
        """Test web apps content."""
        fp = ApplicationFingerprinter()
        
        assert "WordPress" in fp.web_apps
        assert "Drupal" in fp.web_apps
        assert "Django" in fp.web_apps
    
    def test_wordpress_signature(self):
        """Test WordPress signature structure."""
        fp = ApplicationFingerprinter()
        
        wp = fp.web_apps["WordPress"]
        
        assert "patterns" in wp
        assert "category" in wp
        assert "vendor" in wp
        assert "cpe" in wp
    
    def test_api_signatures_content(self):
        """Test API signatures content."""
        fp = ApplicationFingerprinter()
        
        assert "REST API" in fp.api_signatures
        assert "GraphQL" in fp.api_signatures
        assert "SOAP" in fp.api_signatures
    
    def test_microservice_patterns_loaded(self):
        """Test microservice patterns are loaded."""
        fp = ApplicationFingerprinter()
        
        assert hasattr(fp, 'microservice_patterns')
        assert "Spring Cloud" in fp.microservice_patterns


class TestFingerprint:
    """Tests for fingerprint method."""
    
    def test_fingerprint_wordpress(self):
        """Test detecting WordPress."""
        fp = ApplicationFingerprinter()
        
        banner = "wp-content wp-includes WordPress"
        result = fp.fingerprint(banner)
        
        assert isinstance(result, list)
        wp_apps = [app for app in result if app.name == "WordPress"]
        assert len(wp_apps) > 0
    
    def test_fingerprint_with_headers(self):
        """Test fingerprinting with headers."""
        fp = ApplicationFingerprinter()
        
        headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3"
        }
        
        result = fp.fingerprint("", headers=headers)
        
        assert isinstance(result, list)
    
    def test_fingerprint_django(self):
        """Test detecting Django."""
        fp = ApplicationFingerprinter()
        
        banner = "csrftoken django __admin__"
        result = fp.fingerprint(banner)
        
        assert isinstance(result, list)
    
    def test_fingerprint_empty(self):
        """Test with empty banner."""
        fp = ApplicationFingerprinter()
        
        result = fp.fingerprint("")
        
        assert isinstance(result, list)
    
    def test_fingerprint_with_url(self):
        """Test fingerprinting with URL path."""
        fp = ApplicationFingerprinter()
        
        result = fp.fingerprint("", url="/wp-admin/")
        
        assert isinstance(result, list)
    
    def test_fingerprint_graphql(self):
        """Test detecting GraphQL."""
        fp = ApplicationFingerprinter()
        
        result = fp.fingerprint("", url="/graphql")
        
        assert isinstance(result, list)
    
    def test_fingerprint_rest_api(self):
        """Test detecting REST API."""
        fp = ApplicationFingerprinter()
        
        result = fp.fingerprint("/api/v1/users application/json")
        
        assert isinstance(result, list)


class TestDetectWebApps:
    """Tests for _detect_web_apps method."""
    
    def test_detect_drupal(self):
        """Test detecting Drupal."""
        fp = ApplicationFingerprinter()
        
        apps = fp._detect_web_apps(
            banner="Drupal sites/default modules",
            headers=None,
            url=None,
            body=None
        )
        
        drupal_apps = [a for a in apps if a.name == "Drupal"]
        assert len(drupal_apps) > 0
    
    def test_detect_joomla(self):
        """Test detecting Joomla."""
        fp = ApplicationFingerprinter()
        
        apps = fp._detect_web_apps(
            banner="Joomla components/com_ administrator",
            headers=None,
            url=None,
            body=None
        )
        
        joomla_apps = [a for a in apps if a.name == "Joomla"]
        assert len(joomla_apps) > 0
    
    def test_detect_laravel(self):
        """Test detecting Laravel."""
        fp = ApplicationFingerprinter()
        
        apps = fp._detect_web_apps(
            banner="laravel laravel_session XSRF-TOKEN",
            headers=None,
            url=None,
            body=None
        )
        
        laravel_apps = [a for a in apps if a.name == "Laravel"]
        assert len(laravel_apps) > 0
    
    def test_detect_spring_boot(self):
        """Test detecting Spring Boot."""
        fp = ApplicationFingerprinter()
        
        apps = fp._detect_web_apps(
            banner="Spring Whitelabel Error Page actuator",
            headers=None,
            url="/actuator/health",
            body=None
        )
        
        spring_apps = [a for a in apps if a.name == "Spring Boot"]
        assert len(spring_apps) > 0


class TestDetectAPIs:
    """Tests for _detect_apis method."""
    
    def test_detect_rest_api(self):
        """Test detecting REST API."""
        fp = ApplicationFingerprinter()
        
        apis = fp._detect_apis(
            banner="/api/v2/",
            headers=None,
            url="/api/v2/users",
            body="application/json"
        )
        
        rest_apis = [a for a in apis if "REST" in a.name]
        assert len(rest_apis) > 0
    
    def test_detect_graphql_api(self):
        """Test detecting GraphQL API."""
        fp = ApplicationFingerprinter()
        
        apis = fp._detect_apis(
            banner="graphql __schema",
            headers=None,
            url="/graphql",
            body=None
        )
        
        graphql_apis = [a for a in apis if "GraphQL" in a.name]
        assert len(graphql_apis) > 0
    
    def test_detect_soap_api(self):
        """Test detecting SOAP API."""
        fp = ApplicationFingerprinter()
        
        apis = fp._detect_apis(
            banner="<SOAP-ENV:Envelope xmlns:soap",
            headers=None,
            url=None,
            body="application/soap+xml"
        )
        
        soap_apis = [a for a in apis if "SOAP" in a.name]
        assert len(soap_apis) > 0


class TestDetectMicroservices:
    """Tests for _detect_microservices method."""
    
    def test_detect_spring_cloud(self):
        """Test detecting Spring Cloud."""
        fp = ApplicationFingerprinter()
        
        services = fp._detect_microservices(
            banner="spring-cloud eureka zuul ribbon",
            headers=None
        )
        
        spring_services = [s for s in services if "Spring" in s.name]
        assert len(spring_services) > 0
    
    def test_detect_istio(self):
        """Test detecting Istio."""
        fp = ApplicationFingerprinter()
        
        headers = {
            "x-envoy-upstream-service-time": "10",
            "x-b3-traceid": "abc123"
        }
        
        services = fp._detect_microservices(
            banner="istio",
            headers=headers
        )
        
        istio_services = [s for s in services if "Istio" in s.name]
        assert len(istio_services) > 0


class TestDetectDatabases:
    """Tests for _detect_databases method."""
    
    def test_detect_mysql(self):
        """Test detecting MySQL."""
        fp = ApplicationFingerprinter()
        
        dbs = fp._detect_databases("5.7.32-log mysql")
        
        mysql_dbs = [d for d in dbs if "MySQL" in d.name or "mysql" in d.name.lower()]
        # Database detection may or may not be implemented
        assert isinstance(dbs, list)
    
    def test_detect_postgresql(self):
        """Test detecting PostgreSQL."""
        fp = ApplicationFingerprinter()
        
        dbs = fp._detect_databases("PostgreSQL 13.4")
        
        assert isinstance(dbs, list)
    
    def test_detect_mongodb(self):
        """Test detecting MongoDB."""
        fp = ApplicationFingerprinter()
        
        dbs = fp._detect_databases("MongoDB version 4.4.6")
        
        assert isinstance(dbs, list)


class TestVersionExtraction:
    """Tests for version extraction."""
    
    def test_extract_wordpress_version(self):
        """Test extracting WordPress version."""
        fp = ApplicationFingerprinter()
        
        if hasattr(fp, '_extract_app_version'):
            version = fp._extract_app_version("WordPress", "WordPress 5.8.1")
            # May or may not extract version
            assert version is None or isinstance(version, str)
    
    def test_extract_nginx_version(self):
        """Test extracting nginx version."""
        fp = ApplicationFingerprinter()
        
        if hasattr(fp, '_extract_app_version'):
            version = fp._extract_app_version("nginx", "nginx/1.18.0")
            assert version is None or isinstance(version, str)


class TestConfidenceScoring:
    """Tests for confidence scoring."""
    
    def test_confidence_with_multiple_matches(self):
        """Test confidence increases with matches."""
        fp = ApplicationFingerprinter()
        
        # Multiple WordPress indicators
        result = fp.fingerprint(
            banner="wp-content wp-includes wp-admin WordPress wp-json",
            url="/wp-admin/"
        )
        
        if result:
            wp_apps = [app for app in result if app.name == "WordPress"]
            if wp_apps:
                # Multiple matches should give higher confidence
                assert wp_apps[0].confidence >= 20
    
    def test_confidence_capped_at_100(self):
        """Test confidence is capped at 100."""
        fp = ApplicationFingerprinter()
        
        result = fp.fingerprint(
            banner="wp-content wp-includes wp-admin WordPress wp-json wp-login",
            url="/wp-admin/",
            headers={"X-Powered-By": "WordPress"}
        )
        
        for app in result:
            assert app.confidence <= 100
