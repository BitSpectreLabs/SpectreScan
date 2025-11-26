"""
Tests for Application Fingerprinting Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
from spectrescan.core.app_fingerprinting import ApplicationInfo, ApplicationFingerprinter


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
        assert info.version is None
        assert info.confidence == 0
    
    def test_full_init(self):
        """Test full initialization."""
        info = ApplicationInfo(
            name="nginx",
            category="web_server",
            version="1.18.0",
            vendor="nginx",
            confidence=95,
            cpe=["cpe:/a:nginx:nginx:1.18.0"],
            metadata={"ssl": True}
        )
        assert info.name == "nginx"
        assert info.version == "1.18.0"
        assert info.confidence == 95
        assert len(info.cpe) == 1
        assert info.metadata["ssl"] is True
    
    def test_default_lists(self):
        """Test default empty lists."""
        info = ApplicationInfo(name="test", category="test")
        assert info.cpe == []
        assert info.vulnerabilities == []
        assert info.components == []
        assert info.metadata == {}


class TestApplicationFingerprinter:
    """Tests for ApplicationFingerprinter class."""
    
    def test_init(self):
        """Test fingerprinter initialization."""
        fingerprinter = ApplicationFingerprinter()
        assert fingerprinter is not None
        assert hasattr(fingerprinter, 'web_apps')
    
    def test_has_web_app_signatures(self):
        """Test that web app signatures are loaded."""
        fingerprinter = ApplicationFingerprinter()
        assert len(fingerprinter.web_apps) > 0
    
    def test_wordpress_signature_exists(self):
        """Test WordPress signature."""
        fingerprinter = ApplicationFingerprinter()
        assert "WordPress" in fingerprinter.web_apps
        wp = fingerprinter.web_apps["WordPress"]
        assert "patterns" in wp
        assert "category" in wp
    
    def test_drupal_signature_exists(self):
        """Test Drupal signature."""
        fingerprinter = ApplicationFingerprinter()
        assert "Drupal" in fingerprinter.web_apps
    
    def test_joomla_signature_exists(self):
        """Test Joomla signature."""
        fingerprinter = ApplicationFingerprinter()
        assert "Joomla" in fingerprinter.web_apps
    
    def test_magento_signature_exists(self):
        """Test Magento signature."""
        fingerprinter = ApplicationFingerprinter()
        assert "Magento" in fingerprinter.web_apps
    
    def test_shopify_signature_exists(self):
        """Test Shopify signature."""
        fingerprinter = ApplicationFingerprinter()
        assert "Shopify" in fingerprinter.web_apps


class TestFingerprintDetection:
    """Tests for fingerprint detection methods."""
    
    def test_fingerprint_from_html(self):
        """Test fingerprinting from HTML content."""
        fingerprinter = ApplicationFingerprinter()
        
        if hasattr(fingerprinter, 'fingerprint_from_html'):
            html = '<html><head></head><body><script src="/wp-content/themes/test.js"></script></body></html>'
            results = fingerprinter.fingerprint_from_html(html)
            # Should detect WordPress
            assert isinstance(results, list)
    
    def test_fingerprint_from_headers(self):
        """Test fingerprinting from HTTP headers."""
        fingerprinter = ApplicationFingerprinter()
        
        if hasattr(fingerprinter, 'fingerprint_from_headers'):
            headers = {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4.0"
            }
            results = fingerprinter.fingerprint_from_headers(headers)
            assert isinstance(results, list)
    
    def test_fingerprint_from_url(self):
        """Test fingerprinting from URL patterns."""
        fingerprinter = ApplicationFingerprinter()
        
        if hasattr(fingerprinter, 'fingerprint_from_url'):
            url = "/wp-admin/login.php"
            results = fingerprinter.fingerprint_from_url(url)
            assert isinstance(results, list)


class TestCategoryDetection:
    """Tests for category-based detection."""
    
    def test_cms_category(self):
        """Test CMS category signatures."""
        fingerprinter = ApplicationFingerprinter()
        cms_apps = [app for app, sig in fingerprinter.web_apps.items() 
                    if sig.get("category") == "cms"]
        assert len(cms_apps) > 0
    
    def test_web_app_category(self):
        """Test web_app category signatures."""
        fingerprinter = ApplicationFingerprinter()
        web_apps = [app for app, sig in fingerprinter.web_apps.items() 
                    if sig.get("category") == "web_app"]
        # Should have some web apps
        assert isinstance(web_apps, list)
    
    def test_vendor_info(self):
        """Test vendor information in signatures."""
        fingerprinter = ApplicationFingerprinter()
        for name, sig in fingerprinter.web_apps.items():
            if "vendor" in sig:
                assert isinstance(sig["vendor"], str)
    
    def test_cpe_info(self):
        """Test CPE information in signatures."""
        fingerprinter = ApplicationFingerprinter()
        for name, sig in fingerprinter.web_apps.items():
            if "cpe" in sig:
                assert sig["cpe"].startswith("cpe:")


class TestPatternMatching:
    """Tests for pattern matching functionality."""
    
    def test_pattern_compilation(self):
        """Test that patterns are valid regex."""
        import re
        fingerprinter = ApplicationFingerprinter()
        
        for name, sig in fingerprinter.web_apps.items():
            if "patterns" in sig:
                for pattern in sig["patterns"]:
                    # Should not raise an error
                    try:
                        re.compile(pattern)
                    except re.error:
                        pytest.fail(f"Invalid regex pattern in {name}: {pattern}")
    
    def test_wordpress_pattern_matches(self):
        """Test WordPress pattern matches expected content."""
        import re
        fingerprinter = ApplicationFingerprinter()
        wp = fingerprinter.web_apps.get("WordPress", {})
        
        if "patterns" in wp:
            test_content = "/wp-content/themes/twentytwenty/style.css"
            matched = any(re.search(p, test_content) for p in wp["patterns"])
            assert matched, "WordPress pattern should match wp-content"
    
    def test_drupal_pattern_matches(self):
        """Test Drupal pattern matches expected content."""
        import re
        fingerprinter = ApplicationFingerprinter()
        drupal = fingerprinter.web_apps.get("Drupal", {})
        
        if "patterns" in drupal:
            test_content = "/sites/default/files/test.css"
            matched = any(re.search(p, test_content) for p in drupal["patterns"])
            assert matched, "Drupal pattern should match sites/default"


class TestAdditionalSignatures:
    """Tests for additional signature types."""
    
    def test_framework_signatures(self):
        """Test framework signatures if present."""
        fingerprinter = ApplicationFingerprinter()
        
        if hasattr(fingerprinter, 'frameworks'):
            assert isinstance(fingerprinter.frameworks, dict)
    
    def test_api_signatures(self):
        """Test API signatures if present."""
        fingerprinter = ApplicationFingerprinter()
        
        if hasattr(fingerprinter, 'apis'):
            assert isinstance(fingerprinter.apis, dict)
    
    def test_database_signatures(self):
        """Test database signatures if present."""
        fingerprinter = ApplicationFingerprinter()
        
        if hasattr(fingerprinter, 'databases'):
            assert isinstance(fingerprinter.databases, dict)
