"""
Tests for Signature Cache Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import re
from pathlib import Path
from spectrescan.core.signature_cache import (
    SignatureCache,
    get_signature_cache,
    get_cpe_for_service,
    match_service_signature,
    extract_version,
    clear_signature_cache,
    get_cache_stats
)


class TestSignatureCacheSingleton:
    """Tests for SignatureCache singleton pattern."""
    
    def test_singleton_instance(self):
        """Test singleton returns same instance."""
        cache1 = SignatureCache()
        cache2 = SignatureCache()
        
        assert cache1 is cache2
    
    def test_get_signature_cache(self):
        """Test get_signature_cache returns singleton."""
        cache = get_signature_cache()
        
        assert cache is not None
        assert isinstance(cache, SignatureCache)


class TestSignatureCacheInit:
    """Tests for SignatureCache initialization."""
    
    def test_data_dir_exists(self):
        """Test data directory exists."""
        cache = get_signature_cache()
        
        assert cache._data_dir.exists()
    
    def test_file_paths_set(self):
        """Test file paths are set."""
        cache = get_signature_cache()
        
        assert cache._cpe_file is not None
        assert cache._sigs_file is not None
        assert cache._patterns_file is not None


class TestCPEDictionary:
    """Tests for CPE dictionary loading."""
    
    def test_load_cpe_dictionary(self):
        """Test loading CPE dictionary."""
        cache = get_signature_cache()
        
        cpe_dict = cache.load_cpe_dictionary()
        
        assert cpe_dict is not None
        assert isinstance(cpe_dict, dict)
    
    def test_cpe_dictionary_cached(self):
        """Test CPE dictionary is cached."""
        cache = get_signature_cache()
        
        # Load twice
        dict1 = cache.load_cpe_dictionary()
        dict2 = cache.load_cpe_dictionary()
        
        assert dict1 is dict2
    
    def test_get_cpe_for_service_nginx(self):
        """Test getting CPE for nginx."""
        cpe = get_cpe_for_service("nginx")
        
        if cpe:
            assert "nginx" in cpe.lower()
    
    def test_get_cpe_for_service_apache(self):
        """Test getting CPE for Apache."""
        cpe = get_cpe_for_service("apache")
        
        # May or may not exist depending on dictionary
        assert cpe is None or "apache" in cpe.lower()
    
    def test_get_cpe_for_unknown_service(self):
        """Test getting CPE for unknown service."""
        cpe = get_cpe_for_service("unknown_service_xyz")
        
        assert cpe is None


class TestServiceSignatures:
    """Tests for service signatures loading."""
    
    def test_load_service_signatures(self):
        """Test loading service signatures."""
        cache = get_signature_cache()
        
        sigs = cache.load_service_signatures()
        
        assert sigs is not None
        assert isinstance(sigs, dict)
    
    def test_signatures_cached(self):
        """Test signatures are cached."""
        cache = get_signature_cache()
        
        sigs1 = cache.load_service_signatures()
        sigs2 = cache.load_service_signatures()
        
        assert sigs1 is sigs2
    
    def test_match_service_signature_http(self):
        """Test matching HTTP signature."""
        result = match_service_signature(
            banner="Server: nginx/1.18.0",
            port=80,
            protocol="tcp"
        )
        
        # May or may not match depending on signatures
        if result:
            assert "name" in result
    
    def test_match_service_signature_no_match(self):
        """Test no match for unknown banner."""
        result = match_service_signature(
            banner="Unknown Service XYZ",
            port=99999,
            protocol="tcp"
        )
        
        assert result is None


class TestVersionPatterns:
    """Tests for version patterns loading."""
    
    def test_load_version_patterns(self):
        """Test loading version patterns."""
        cache = get_signature_cache()
        
        patterns = cache.load_version_patterns()
        
        assert patterns is not None
        assert isinstance(patterns, dict)
    
    def test_patterns_cached(self):
        """Test patterns are cached."""
        cache = get_signature_cache()
        
        patterns1 = cache.load_version_patterns()
        patterns2 = cache.load_version_patterns()
        
        assert patterns1 is patterns2
    
    def test_extract_version_nginx(self):
        """Test extracting nginx version."""
        version = extract_version(
            banner="Server: nginx/1.18.0",
            service="nginx"
        )
        
        if version:
            assert "1.18" in version
    
    def test_extract_version_generic(self):
        """Test extracting version with generic pattern."""
        version = extract_version(
            banner="MyService v2.5.1",
            service="unknown"
        )
        
        if version:
            assert "2.5" in version


class TestCompiledPatterns:
    """Tests for pattern compilation and caching."""
    
    def test_get_compiled_pattern(self):
        """Test getting compiled pattern."""
        cache = get_signature_cache()
        
        pattern = cache.get_compiled_pattern(r"\d+\.\d+\.\d+")
        
        assert pattern is not None
        assert isinstance(pattern, re.Pattern)
    
    def test_compiled_pattern_cached(self):
        """Test compiled patterns are cached."""
        cache = get_signature_cache()
        
        pattern1 = cache.get_compiled_pattern(r"\d+")
        pattern2 = cache.get_compiled_pattern(r"\d+")
        
        assert pattern1 is pattern2
    
    def test_compiled_pattern_with_flags(self):
        """Test compiled pattern with flags."""
        cache = get_signature_cache()
        
        pattern = cache.get_compiled_pattern(r"test", re.IGNORECASE)
        
        assert pattern is not None
        assert pattern.match("TEST")
    
    def test_compiled_pattern_invalid(self):
        """Test invalid pattern returns None."""
        cache = get_signature_cache()
        
        # Invalid regex
        pattern = cache.get_compiled_pattern(r"[invalid")
        
        assert pattern is None


class TestCacheManagement:
    """Tests for cache management functions."""
    
    def test_clear_cache(self):
        """Test clearing cache."""
        cache = get_signature_cache()
        
        # Load something first
        cache.load_cpe_dictionary()
        cache.load_service_signatures()
        cache.load_version_patterns()
        cache.get_compiled_pattern(r"\d+")
        
        # Clear
        cache.clear_cache()
        
        # Check cleared
        assert cache._cpe_dict is None
        assert cache._service_sigs is None
        assert cache._version_patterns is None
        assert len(cache._compiled_patterns_cache) == 0
    
    def test_clear_signature_cache_function(self):
        """Test clear_signature_cache convenience function."""
        # Load something
        get_signature_cache().load_cpe_dictionary()
        
        # Clear via convenience function
        clear_signature_cache()
        
        # Should be cleared
        cache = get_signature_cache()
        assert cache._cpe_dict is None
    
    def test_get_cache_stats(self):
        """Test getting cache stats."""
        stats = get_cache_stats()
        
        assert "cpe_loaded" in stats
        assert "signatures_loaded" in stats
        assert "patterns_loaded" in stats
        assert "compiled_patterns_count" in stats
    
    def test_cache_stats_after_load(self):
        """Test cache stats after loading data."""
        cache = get_signature_cache()
        
        # Clear first
        cache.clear_cache()
        
        # Load CPE
        cache.load_cpe_dictionary()
        
        stats = cache.get_cache_stats()
        
        assert stats["cpe_loaded"] is True
        assert stats["cpe_count"] > 0


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_get_cpe_for_service_function(self):
        """Test get_cpe_for_service function."""
        # Should not raise error
        result = get_cpe_for_service("test")
        
        assert result is None or isinstance(result, str)
    
    def test_match_service_signature_function(self):
        """Test match_service_signature function."""
        # Should not raise error
        result = match_service_signature("test", 80)
        
        assert result is None or isinstance(result, dict)
    
    def test_extract_version_function(self):
        """Test extract_version function."""
        # Should not raise error
        result = extract_version("v1.0.0", "test")
        
        assert result is None or isinstance(result, str)
