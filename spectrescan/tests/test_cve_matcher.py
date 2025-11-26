"""
Unit tests for CVE Matcher module.

Tests online CVE lookup functionality with mocked API responses.

File: spectrescan/tests/test_cve_matcher.py
Author: BitSpectreLabs
"""

import json
import pytest
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

from spectrescan.core.cve_matcher import (
    CVESeverity,
    CVSSVersion,
    CVSSScore,
    CVEReference,
    CVEEntry,
    CVEMatchResult,
    CVECache,
    RateLimiter,
    CVEMatcher,
    format_cve_report,
    cve_result_to_dict,
)


# Sample NVD API response for testing
SAMPLE_NVD_RESPONSE = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:00.000Z",
                "lastModified": "2023-01-15T12:00:00.000Z",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 vulnerability allowing remote code execution."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 6.0
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-917"}]}
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
                                ]
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://logging.apache.org/log4j/2.x/security.html",
                        "source": "apache.org",
                        "tags": ["Vendor Advisory", "Patch"]
                    },
                    {
                        "url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
                        "source": "github.com",
                        "tags": ["Exploit"]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2021-45046",
                "published": "2021-12-14T10:15:00.000Z",
                "lastModified": "2023-01-15T12:00:00.000Z",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 incomplete fix for CVE-2021-44228."}
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.0,
                                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
                            },
                            "exploitabilityScore": 2.2,
                            "impactScore": 6.0
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"value": "CWE-917"}]}
                ],
                "configurations": [],
                "references": [
                    {
                        "url": "https://logging.apache.org/log4j/2.x/security.html",
                        "source": "apache.org",
                        "tags": ["Vendor Advisory"]
                    }
                ]
            }
        }
    ]
}

SAMPLE_SINGLE_CVE_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [SAMPLE_NVD_RESPONSE["vulnerabilities"][0]]
}

EMPTY_NVD_RESPONSE = {
    "totalResults": 0,
    "vulnerabilities": []
}


class TestCVESeverity:
    """Tests for CVESeverity enum."""
    
    def test_from_cvss_critical(self):
        assert CVESeverity.from_cvss(10.0) == CVESeverity.CRITICAL
        assert CVESeverity.from_cvss(9.0) == CVESeverity.CRITICAL
        assert CVESeverity.from_cvss(9.5) == CVESeverity.CRITICAL
    
    def test_from_cvss_high(self):
        assert CVESeverity.from_cvss(8.9) == CVESeverity.HIGH
        assert CVESeverity.from_cvss(7.0) == CVESeverity.HIGH
        assert CVESeverity.from_cvss(7.5) == CVESeverity.HIGH
    
    def test_from_cvss_medium(self):
        assert CVESeverity.from_cvss(6.9) == CVESeverity.MEDIUM
        assert CVESeverity.from_cvss(4.0) == CVESeverity.MEDIUM
        assert CVESeverity.from_cvss(5.0) == CVESeverity.MEDIUM
    
    def test_from_cvss_low(self):
        assert CVESeverity.from_cvss(3.9) == CVESeverity.LOW
        assert CVESeverity.from_cvss(0.1) == CVESeverity.LOW
        assert CVESeverity.from_cvss(2.0) == CVESeverity.LOW
    
    def test_from_cvss_none(self):
        assert CVESeverity.from_cvss(0.0) == CVESeverity.NONE
    
    def test_from_cvss_unknown(self):
        assert CVESeverity.from_cvss(None) == CVESeverity.UNKNOWN


class TestCVSSScore:
    """Tests for CVSSScore dataclass."""
    
    def test_cvss_score_creation(self):
        score = CVSSScore(
            version=CVSSVersion.V3_1,
            base_score=9.8,
            severity=CVESeverity.CRITICAL,
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        
        assert score.version == CVSSVersion.V3_1
        assert score.base_score == 9.8
        assert score.severity == CVESeverity.CRITICAL
        assert "AV:N" in score.vector_string
    
    def test_cvss_score_with_subscores(self):
        score = CVSSScore(
            version=CVSSVersion.V3_1,
            base_score=7.5,
            severity=CVESeverity.HIGH,
            exploitability_score=3.9,
            impact_score=3.6
        )
        
        assert score.exploitability_score == 3.9
        assert score.impact_score == 3.6


class TestCVEReference:
    """Tests for CVEReference dataclass."""
    
    def test_reference_creation(self):
        ref = CVEReference(
            url="https://example.com/advisory",
            source="example.com",
            tags=["Vendor Advisory", "Patch"]
        )
        
        assert ref.url == "https://example.com/advisory"
        assert ref.source == "example.com"
        assert "Patch" in ref.tags
    
    def test_reference_default_tags(self):
        ref = CVEReference(url="https://test.com", source="test")
        assert ref.tags == []


class TestCVEEntry:
    """Tests for CVEEntry dataclass."""
    
    def test_entry_creation(self):
        entry = CVEEntry(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            severity=CVESeverity.CRITICAL,
            cvss_v3=CVSSScore(
                version=CVSSVersion.V3_1,
                base_score=10.0,
                severity=CVESeverity.CRITICAL
            )
        )
        
        assert entry.cve_id == "CVE-2021-44228"
        assert entry.severity == CVESeverity.CRITICAL
        assert entry.highest_cvss_score == 10.0
    
    def test_highest_cvss_score_v4_priority(self):
        entry = CVEEntry(
            cve_id="CVE-2024-0001",
            description="Test CVE",
            cvss_v4=CVSSScore(version=CVSSVersion.V4, base_score=8.0, severity=CVESeverity.HIGH),
            cvss_v3=CVSSScore(version=CVSSVersion.V3_1, base_score=7.5, severity=CVESeverity.HIGH),
            cvss_v2=CVSSScore(version=CVSSVersion.V2, base_score=7.0, severity=CVESeverity.HIGH)
        )
        
        # V4 should be considered even if lower (it's the newest standard)
        assert entry.highest_cvss_score == 8.0
    
    def test_primary_cvss_fallback(self):
        entry = CVEEntry(
            cve_id="CVE-2020-0001",
            description="Old CVE",
            cvss_v2=CVSSScore(version=CVSSVersion.V2, base_score=6.8, severity=CVESeverity.MEDIUM)
        )
        
        assert entry.primary_cvss.version == CVSSVersion.V2
        assert entry.primary_cvss.base_score == 6.8
    
    def test_exploit_and_patch_flags(self):
        entry = CVEEntry(
            cve_id="CVE-2021-44228",
            description="Test",
            exploit_available=True,
            patch_available=True
        )
        
        assert entry.exploit_available is True
        assert entry.patch_available is True


class TestCVEMatchResult:
    """Tests for CVEMatchResult dataclass."""
    
    def test_result_creation(self):
        result = CVEMatchResult(
            product="nginx",
            version="1.19.0",
            total_found=5,
            critical_count=1,
            high_count=2,
            medium_count=2
        )
        
        assert result.product == "nginx"
        assert result.total_found == 5
        assert result.critical_count == 1
    
    def test_has_critical(self):
        result_critical = CVEMatchResult(critical_count=1)
        result_no_critical = CVEMatchResult(critical_count=0, high_count=5)
        
        assert result_critical.has_critical is True
        assert result_no_critical.has_critical is False
    
    def test_risk_level(self):
        assert CVEMatchResult(critical_count=1).risk_level == CVESeverity.CRITICAL
        assert CVEMatchResult(high_count=1).risk_level == CVESeverity.HIGH
        assert CVEMatchResult(medium_count=1).risk_level == CVESeverity.MEDIUM
        assert CVEMatchResult(low_count=1).risk_level == CVESeverity.LOW
        assert CVEMatchResult().risk_level == CVESeverity.NONE
    
    def test_cached_flag(self):
        result = CVEMatchResult(cached=True)
        assert result.cached is True


class TestCVECache:
    """Tests for CVECache class."""
    
    def test_cache_set_get(self):
        cache = CVECache(ttl_seconds=60)
        
        cache.set("test_key", {"data": "value"})
        result = cache.get("test_key")
        
        assert result == {"data": "value"}
    
    def test_cache_expiration(self):
        cache = CVECache(ttl_seconds=1)
        
        cache.set("test_key", "value")
        assert cache.get("test_key") == "value"
        
        # Wait for expiration
        time.sleep(1.1)
        assert cache.get("test_key") is None
    
    def test_cache_miss(self):
        cache = CVECache()
        assert cache.get("nonexistent") is None
        assert cache._misses == 1
    
    def test_cache_hit_rate(self):
        cache = CVECache()
        
        cache.set("key1", "value1")
        cache.get("key1")  # Hit
        cache.get("key1")  # Hit
        cache.get("key2")  # Miss
        
        assert cache._hits == 2
        assert cache._misses == 1
        assert cache.hit_rate == pytest.approx(2/3, rel=0.01)
    
    def test_cache_eviction(self):
        cache = CVECache(max_entries=3)
        
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.set("key3", "value3")
        cache.set("key4", "value4")  # Should trigger eviction
        
        assert len(cache._cache) <= 3
    
    def test_cache_clear(self):
        cache = CVECache()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        
        cache.clear()
        
        assert len(cache._cache) == 0
        assert cache._hits == 0
        assert cache._misses == 0
    
    def test_cache_stats(self):
        cache = CVECache(ttl_seconds=3600, max_entries=1000)
        cache.set("key1", "value1")
        cache.get("key1")
        
        stats = cache.stats
        
        assert stats["entries"] == 1
        assert stats["hits"] == 1
        assert stats["ttl_seconds"] == 3600


class TestRateLimiter:
    """Tests for RateLimiter class."""
    
    def test_rate_limiter_sync(self):
        limiter = RateLimiter(requests_per_second=10, burst_limit=5)
        
        # Should allow burst
        for _ in range(5):
            limiter.acquire_sync()
        
        # Check that it works (doesn't raise)
        assert limiter.tokens >= 0
    
    def test_rate_limiter_refill(self):
        limiter = RateLimiter(requests_per_second=10, burst_limit=1)
        
        limiter.acquire_sync()
        initial_tokens = limiter.tokens
        
        time.sleep(0.15)  # Wait for refill
        
        # Update tokens manually
        now = time.time()
        elapsed = now - limiter.last_update
        limiter.tokens = min(1, limiter.tokens + elapsed * 10)
        
        assert limiter.tokens > initial_tokens


class TestCVEMatcher:
    """Tests for CVEMatcher class."""
    
    def test_matcher_initialization(self):
        matcher = CVEMatcher(timeout=30.0)
        
        assert matcher.timeout == 30.0
        assert matcher.cache is not None
    
    def test_matcher_with_api_key(self):
        matcher = CVEMatcher(nvd_api_key="test_key")
        
        headers = matcher._get_headers()
        assert "apiKey" in headers
        assert headers["apiKey"] == "test_key"
    
    def test_build_cpe_string(self):
        matcher = CVEMatcher()
        
        cpe = matcher._build_cpe_string("nginx", "nginx", "1.19.0")
        assert cpe == "cpe:2.3:a:nginx:nginx:1.19.0:*:*:*:*:*:*:*"
        
        cpe_no_version = matcher._build_cpe_string("apache", "httpd")
        assert cpe_no_version == "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*"
    
    def test_normalize_product_name_known(self):
        matcher = CVEMatcher()
        
        vendor, product = matcher._normalize_product_name("nginx")
        assert vendor == "nginx"
        assert product == "nginx"
        
        vendor, product = matcher._normalize_product_name("openssh")
        assert vendor == "openbsd"
        assert product == "openssh"
        
        vendor, product = matcher._normalize_product_name("mysql")
        assert vendor == "oracle"
        assert product == "mysql"
    
    def test_normalize_product_name_unknown(self):
        matcher = CVEMatcher()
        
        vendor, product = matcher._normalize_product_name("unknown_product")
        assert vendor == "unknown_product"
        assert product == "unknown_product"
    
    def test_parse_nvd_response(self):
        matcher = CVEMatcher()
        
        cves = matcher._parse_nvd_response(SAMPLE_NVD_RESPONSE)
        
        assert len(cves) == 2
        assert cves[0].cve_id == "CVE-2021-44228"
        assert cves[0].severity == CVESeverity.CRITICAL
        assert cves[0].highest_cvss_score == 10.0
        assert cves[0].exploit_available is True
        assert cves[0].patch_available is True
    
    def test_parse_nvd_response_empty(self):
        matcher = CVEMatcher()
        
        cves = matcher._parse_nvd_response(EMPTY_NVD_RESPONSE)
        
        assert len(cves) == 0
    
    @patch.object(CVEMatcher, '_make_request_sync')
    def test_lookup_by_product_sync(self, mock_request):
        mock_request.return_value = (SAMPLE_NVD_RESPONSE, None)
        
        matcher = CVEMatcher()
        result = matcher.lookup_by_product_sync("log4j", version="2.14.1")
        
        assert result.total_found == 2
        assert result.critical_count >= 1
        assert len(result.cves) > 0
    
    @patch.object(CVEMatcher, '_make_request_sync')
    def test_lookup_by_product_sync_error(self, mock_request):
        mock_request.return_value = (None, "Connection timeout")
        
        matcher = CVEMatcher()
        result = matcher.lookup_by_product_sync("test_product")
        
        assert result.error == "Connection timeout"
        assert len(result.cves) == 0
    
    @patch.object(CVEMatcher, '_make_request_sync')
    def test_lookup_by_cpe_sync(self, mock_request):
        mock_request.return_value = (SAMPLE_NVD_RESPONSE, None)
        
        matcher = CVEMatcher()
        cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        result = matcher.lookup_by_cpe_sync(cpe)
        
        assert result.cpe == cpe
        assert result.total_found >= 1
    
    @patch.object(CVEMatcher, '_make_request_sync')
    def test_lookup_cve_id_sync(self, mock_request):
        mock_request.return_value = (SAMPLE_SINGLE_CVE_RESPONSE, None)
        
        matcher = CVEMatcher()
        cve = matcher.lookup_cve_id_sync("CVE-2021-44228")
        
        assert cve is not None
        assert cve.cve_id == "CVE-2021-44228"
        assert cve.severity == CVESeverity.CRITICAL
    
    def test_lookup_cve_id_invalid_format(self):
        matcher = CVEMatcher()
        
        cve = matcher.lookup_cve_id_sync("invalid-cve")
        assert cve is None
        
        cve = matcher.lookup_cve_id_sync("CVE-2021")
        assert cve is None
    
    @patch.object(CVEMatcher, '_make_request_sync')
    def test_lookup_with_severity_filter(self, mock_request):
        mock_request.return_value = (SAMPLE_NVD_RESPONSE, None)
        
        matcher = CVEMatcher()
        result = matcher.lookup_by_product_sync(
            "log4j",
            severity_filter=CVESeverity.CRITICAL
        )
        
        # All results should be critical severity
        for cve in result.cves:
            assert cve.severity in [CVESeverity.CRITICAL]
    
    def test_cache_integration(self):
        matcher = CVEMatcher()
        
        # Create a cached result
        result = CVEMatchResult(
            product="test",
            total_found=5,
            critical_count=1
        )
        cache_key = matcher.cache._generate_key("product", "test", "test", None, None)
        matcher.cache.set(cache_key, result)
        
        # Verify cache stats
        stats = matcher.cache_stats
        assert stats["entries"] == 1


class TestFormatCVEReport:
    """Tests for format_cve_report function."""
    
    def test_format_report_with_cves(self):
        cve = CVEEntry(
            cve_id="CVE-2021-44228",
            description="Test vulnerability description",
            severity=CVESeverity.CRITICAL,
            cvss_v3=CVSSScore(
                version=CVSSVersion.V3_1,
                base_score=10.0,
                severity=CVESeverity.CRITICAL
            ),
            exploit_available=True
        )
        
        result = CVEMatchResult(
            product="log4j",
            version="2.14.1",
            total_found=1,
            critical_count=1,
            cves=[cve]
        )
        
        report = format_cve_report(result)
        
        assert "CVE Report" in report
        assert "log4j" in report
        assert "2.14.1" in report
        assert "CVE-2021-44228" in report
        assert "CRITICAL" in report
        assert "EXPLOIT AVAILABLE" in report
    
    def test_format_report_error(self):
        result = CVEMatchResult(error="API rate limit exceeded")
        
        report = format_cve_report(result)
        
        assert "Error" in report
        assert "rate limit" in report
    
    def test_format_report_empty(self):
        result = CVEMatchResult(
            product="safe_product",
            total_found=0
        )
        
        report = format_cve_report(result)
        
        assert "Total CVEs Found: 0" in report
    
    def test_format_report_verbose(self):
        cve = CVEEntry(
            cve_id="CVE-2021-44228",
            description="Test vulnerability",
            severity=CVESeverity.CRITICAL,
            cwe_ids=["CWE-917"],
            references=[
                CVEReference(url="https://test.com", source="test", tags=["Patch"])
            ],
            published_date=datetime(2021, 12, 10)
        )
        
        result = CVEMatchResult(
            product="log4j",
            total_found=1,
            critical_count=1,
            cves=[cve]
        )
        
        report = format_cve_report(result, verbose=True)
        
        assert "CWE" in report
        assert "2021-12-10" in report
        assert "https://test.com" in report


class TestCVEResultToDict:
    """Tests for cve_result_to_dict function."""
    
    def test_result_to_dict(self):
        cve = CVEEntry(
            cve_id="CVE-2021-44228",
            description="Test CVE",
            severity=CVESeverity.CRITICAL,
            cvss_v3=CVSSScore(
                version=CVSSVersion.V3_1,
                base_score=10.0,
                severity=CVESeverity.CRITICAL,
                vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            ),
            published_date=datetime(2021, 12, 10),
            exploit_available=True,
            patch_available=True,
            cwe_ids=["CWE-917"],
            references=[
                CVEReference(url="https://test.com", source="test", tags=["Patch"])
            ]
        )
        
        result = CVEMatchResult(
            product="log4j",
            version="2.14.1",
            cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            total_found=1,
            critical_count=1,
            cves=[cve],
            query_time_ms=123.45
        )
        
        data = cve_result_to_dict(result)
        
        assert data["product"] == "log4j"
        assert data["version"] == "2.14.1"
        assert data["total_found"] == 1
        assert data["critical_count"] == 1
        assert data["risk_level"] == "critical"
        assert len(data["cves"]) == 1
        
        cve_data = data["cves"][0]
        assert cve_data["id"] == "CVE-2021-44228"
        assert cve_data["severity"] == "critical"
        assert cve_data["cvss_score"] == 10.0
        assert cve_data["exploit_available"] is True
    
    def test_result_to_dict_empty(self):
        result = CVEMatchResult(
            product="safe_product",
            total_found=0
        )
        
        data = cve_result_to_dict(result)
        
        assert data["total_found"] == 0
        assert data["cves"] == []
        assert data["risk_level"] == "none"


class TestCVEMatcherAsync:
    """Tests for async CVE matcher methods."""
    
    @pytest.mark.asyncio
    async def test_lookup_by_product_async(self):
        matcher = CVEMatcher()
        
        with patch.object(matcher, '_make_request_async', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = (SAMPLE_NVD_RESPONSE, None)
            
            result = await matcher.lookup_by_product("log4j", version="2.14.1")
            
            assert result.total_found == 2
            assert result.critical_count >= 1
    
    @pytest.mark.asyncio
    async def test_lookup_by_cpe_async(self):
        matcher = CVEMatcher()
        
        with patch.object(matcher, '_make_request_async', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = (SAMPLE_NVD_RESPONSE, None)
            
            cpe = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
            result = await matcher.lookup_by_cpe(cpe)
            
            assert result.cpe == cpe
            assert result.total_found >= 1
    
    @pytest.mark.asyncio
    async def test_lookup_cve_id_async(self):
        matcher = CVEMatcher()
        
        with patch.object(matcher, '_make_request_async', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = (SAMPLE_SINGLE_CVE_RESPONSE, None)
            
            cve = await matcher.lookup_cve_id("CVE-2021-44228")
            
            assert cve is not None
            assert cve.cve_id == "CVE-2021-44228"
    
    @pytest.mark.asyncio
    async def test_batch_lookup_async(self):
        matcher = CVEMatcher()
        
        with patch.object(matcher, '_make_request_async', new_callable=AsyncMock) as mock_request:
            mock_request.return_value = (SAMPLE_NVD_RESPONSE, None)
            
            products = [
                {"product": "nginx", "version": "1.19.0"},
                {"product": "apache", "version": "2.4.48"}
            ]
            
            results = await matcher.batch_lookup(products)
            
            assert len(results) == 2
            assert "nginx/1.19.0" in results
            assert "apache/2.4.48" in results


class TestCVEMatcherEdgeCases:
    """Tests for edge cases in CVE matcher."""
    
    def test_matcher_with_custom_cache_path(self, tmp_path):
        cache_path = tmp_path / "test_cve_cache.json"
        matcher = CVEMatcher(cache_path=cache_path)
        
        # Set some cache data
        matcher.cache.set("test_key", {"data": "value"})
        matcher.save_cache()
        
        # Verify cache file exists
        assert cache_path.exists()
    
    def test_parse_nvd_response_missing_fields(self):
        """Test parsing response with missing optional fields."""
        minimal_response = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2020-0001",
                        "descriptions": [
                            {"lang": "en", "value": "Minimal CVE"}
                        ]
                    }
                }
            ]
        }
        
        matcher = CVEMatcher()
        cves = matcher._parse_nvd_response(minimal_response)
        
        assert len(cves) == 1
        assert cves[0].cve_id == "CVE-2020-0001"
        assert cves[0].severity == CVESeverity.UNKNOWN
    
    def test_parse_nvd_response_cvss_v2_only(self):
        """Test parsing response with only CVSS v2 scores."""
        v2_response = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2010-0001",
                        "descriptions": [
                            {"lang": "en", "value": "Old CVE with CVSS v2"}
                        ],
                        "metrics": {
                            "cvssMetricV2": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        }
        
        matcher = CVEMatcher()
        cves = matcher._parse_nvd_response(v2_response)
        
        assert len(cves) == 1
        assert cves[0].cvss_v2 is not None
        assert cves[0].cvss_v2.base_score == 7.5
        assert cves[0].cvss_v3 is None
    
    @patch.object(CVEMatcher, '_make_request_sync')
    def test_lookup_with_max_results(self, mock_request):
        """Test that max_results limits the returned CVEs."""
        # Create a response with many CVEs
        many_cves = {
            "totalResults": 100,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": f"CVE-2021-{1000 + i}",
                        "descriptions": [{"lang": "en", "value": f"CVE {i}"}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 5.0}}
                            ]
                        }
                    }
                }
                for i in range(50)
            ]
        }
        mock_request.return_value = (many_cves, None)
        
        matcher = CVEMatcher()
        result = matcher.lookup_by_product_sync("test", max_results=10)
        
        assert len(result.cves) <= 10
    
    def test_normalize_product_name_with_spaces(self):
        """Test normalizing product names with spaces."""
        matcher = CVEMatcher()
        
        vendor, product = matcher._normalize_product_name("Apache Tomcat")
        assert vendor == "apache"
        assert "_" not in product or product == "tomcat"
    
    def test_build_cpe_string_with_special_chars(self):
        """Test building CPE with special characters."""
        matcher = CVEMatcher()
        
        cpe = matcher._build_cpe_string("my vendor", "my-product", "1.0.0")
        assert "my_vendor" in cpe
        assert "my_product" in cpe


class TestCVECachePeristence:
    """Tests for cache persistence functionality."""
    
    def test_cache_save_and_load(self, tmp_path):
        cache_path = tmp_path / "cache.json"
        
        # Create and populate cache
        cache1 = CVECache(persist_path=cache_path)
        cache1.set("key1", "value1")
        cache1.set("key2", {"nested": "data"})
        cache1.save_to_disk()
        
        # Create new cache and load
        cache2 = CVECache(persist_path=cache_path)
        
        # Verify data loaded
        assert cache2.get("key1") == "value1"
        assert cache2.get("key2") == {"nested": "data"}
    
    def test_cache_load_nonexistent_file(self, tmp_path):
        cache_path = tmp_path / "nonexistent.json"
        
        # Should not raise
        cache = CVECache(persist_path=cache_path)
        assert len(cache._cache) == 0


# Integration test (disabled by default - requires network)
class TestCVEMatcherIntegration:
    """Integration tests for CVE matcher (require network access)."""
    
    @pytest.mark.skip(reason="Requires network access and NVD API")
    def test_real_nvd_api_lookup(self):
        """Test real NVD API lookup."""
        matcher = CVEMatcher(timeout=30.0)
        
        result = matcher.lookup_by_product_sync("log4j", version="2.14.1")
        
        # Log4j should have known CVEs
        assert result.total_found > 0
        assert result.critical_count > 0
    
    @pytest.mark.skip(reason="Requires network access and NVD API")
    def test_real_cve_id_lookup(self):
        """Test real CVE ID lookup."""
        matcher = CVEMatcher(timeout=30.0)
        
        cve = matcher.lookup_cve_id_sync("CVE-2021-44228")
        
        assert cve is not None
        assert cve.cve_id == "CVE-2021-44228"
        assert cve.severity == CVESeverity.CRITICAL
