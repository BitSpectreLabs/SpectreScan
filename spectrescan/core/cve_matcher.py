"""
CVE Matcher - Online CVE Lookup and Vulnerability Matching

Provides real-time CVE vulnerability lookup using online APIs:
- NVD (National Vulnerability Database) API 2.0
- CVE.org API (fallback)

Features:
- CPE to CVE mapping
- Version-based vulnerability matching
- CVSS score retrieval
- Severity filtering
- Result caching
- Async API calls for performance
- Rate limiting to respect API quotas

File: spectrescan/core/cve_matcher.py
Author: BitSpectreLabs
"""

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, urlencode

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Fallback to urllib for basic sync requests
import urllib.request
import urllib.error
import ssl

logger = logging.getLogger(__name__)


class CVESeverity(Enum):
    """CVE severity levels based on CVSS scores."""
    CRITICAL = "critical"    # 9.0-10.0
    HIGH = "high"            # 7.0-8.9
    MEDIUM = "medium"        # 4.0-6.9
    LOW = "low"              # 0.1-3.9
    NONE = "none"            # 0.0
    UNKNOWN = "unknown"      # No CVSS score available
    
    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "CVESeverity":
        """Determine severity from CVSS score."""
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.NONE


class CVSSVersion(Enum):
    """CVSS version identifiers."""
    V2 = "2.0"
    V3 = "3.0"
    V3_1 = "3.1"
    V4 = "4.0"


@dataclass
class CVSSScore:
    """CVSS score details."""
    version: CVSSVersion
    base_score: float
    severity: CVESeverity
    vector_string: Optional[str] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None


@dataclass
class CVEReference:
    """CVE reference link."""
    url: str
    source: str
    tags: List[str] = field(default_factory=list)


@dataclass
class CVEEntry:
    """Complete CVE entry with all metadata."""
    cve_id: str
    description: str
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None
    cvss_v2: Optional[CVSSScore] = None
    cvss_v3: Optional[CVSSScore] = None
    cvss_v4: Optional[CVSSScore] = None
    severity: CVESeverity = CVESeverity.UNKNOWN
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    cpe_matches: List[str] = field(default_factory=list)
    references: List[CVEReference] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    
    @property
    def highest_cvss_score(self) -> Optional[float]:
        """Get the highest CVSS score available."""
        scores = []
        if self.cvss_v4:
            scores.append(self.cvss_v4.base_score)
        if self.cvss_v3:
            scores.append(self.cvss_v3.base_score)
        if self.cvss_v2:
            scores.append(self.cvss_v2.base_score)
        return max(scores) if scores else None
    
    @property
    def primary_cvss(self) -> Optional[CVSSScore]:
        """Get the primary (highest version) CVSS score."""
        if self.cvss_v4:
            return self.cvss_v4
        if self.cvss_v3:
            return self.cvss_v3
        return self.cvss_v2


@dataclass
class CVEMatchResult:
    """Result of CVE matching for a service/product."""
    cpe: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cves: List[CVEEntry] = field(default_factory=list)
    total_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    error: Optional[str] = None
    cached: bool = False
    query_time_ms: float = 0.0
    
    @property
    def has_critical(self) -> bool:
        """Check if there are critical vulnerabilities."""
        return self.critical_count > 0
    
    @property
    def risk_level(self) -> CVESeverity:
        """Get the highest risk level found."""
        if self.critical_count > 0:
            return CVESeverity.CRITICAL
        if self.high_count > 0:
            return CVESeverity.HIGH
        if self.medium_count > 0:
            return CVESeverity.MEDIUM
        if self.low_count > 0:
            return CVESeverity.LOW
        return CVESeverity.NONE


class CVECache:
    """In-memory cache for CVE lookup results with TTL."""
    
    def __init__(
        self,
        ttl_seconds: int = 3600,
        max_entries: int = 1000,
        persist_path: Optional[Path] = None
    ):
        """
        Initialize CVE cache.
        
        Args:
            ttl_seconds: Time-to-live for cache entries (default 1 hour)
            max_entries: Maximum number of cached entries
            persist_path: Optional path to persist cache to disk
        """
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.persist_path = persist_path
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._hits = 0
        self._misses = 0
        
        # Load persisted cache if available
        if persist_path and persist_path.exists():
            self._load_from_disk()
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate a cache key from arguments."""
        # Convert enum values to strings for JSON serialization
        def serialize(obj):
            if isinstance(obj, Enum):
                return obj.value
            return obj
        
        serializable_args = [serialize(a) for a in args]
        serializable_kwargs = {k: serialize(v) for k, v in kwargs.items()}
        key_data = json.dumps({"args": serializable_args, "kwargs": serializable_kwargs}, sort_keys=True)
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]
    
    def get(self, key: str) -> Optional[Any]:
        """Get a cached value if not expired."""
        if key in self._cache:
            timestamp, value = self._cache[key]
            if time.time() - timestamp < self.ttl_seconds:
                self._hits += 1
                return value
            else:
                # Expired, remove it
                del self._cache[key]
        self._misses += 1
        return None
    
    def set(self, key: str, value: Any) -> None:
        """Set a cache value with current timestamp."""
        # Evict oldest entries if cache is full
        if len(self._cache) >= self.max_entries:
            self._evict_oldest()
        
        self._cache[key] = (time.time(), value)
    
    def _evict_oldest(self) -> None:
        """Evict the oldest 10% of cache entries."""
        if not self._cache:
            return
        
        sorted_keys = sorted(
            self._cache.keys(),
            key=lambda k: self._cache[k][0]
        )
        evict_count = max(1, len(sorted_keys) // 10)
        for key in sorted_keys[:evict_count]:
            del self._cache[key]
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
    
    def _load_from_disk(self) -> None:
        """Load cache from disk."""
        try:
            if self.persist_path and self.persist_path.exists():
                with open(self.persist_path, 'r') as f:
                    data = json.load(f)
                    # Filter out expired entries
                    current_time = time.time()
                    for key, (timestamp, value) in data.items():
                        if current_time - timestamp < self.ttl_seconds:
                            self._cache[key] = (timestamp, value)
                logger.info(f"Loaded {len(self._cache)} cached CVE entries from disk")
        except Exception as e:
            logger.warning(f"Failed to load CVE cache from disk: {e}")
    
    def save_to_disk(self) -> None:
        """Save cache to disk."""
        try:
            if self.persist_path:
                self.persist_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.persist_path, 'w') as f:
                    # Convert cache entries to serializable format
                    serializable = {}
                    for key, (timestamp, value) in self._cache.items():
                        if isinstance(value, CVEMatchResult):
                            serializable[key] = (timestamp, self._serialize_result(value))
                        else:
                            serializable[key] = (timestamp, value)
                    json.dump(serializable, f)
                logger.info(f"Saved {len(self._cache)} CVE cache entries to disk")
        except Exception as e:
            logger.warning(f"Failed to save CVE cache to disk: {e}")
    
    def _serialize_result(self, result: CVEMatchResult) -> Dict:
        """Serialize CVEMatchResult to dict."""
        return {
            "cpe": result.cpe,
            "product": result.product,
            "version": result.version,
            "total_found": result.total_found,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "error": result.error,
            "cves": [self._serialize_cve(cve) for cve in result.cves]
        }
    
    def _serialize_cve(self, cve: CVEEntry) -> Dict:
        """Serialize CVEEntry to dict."""
        return {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "severity": cve.severity.value,
            "highest_cvss_score": cve.highest_cvss_score,
            "exploit_available": cve.exploit_available,
            "patch_available": cve.patch_available
        }
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0
    
    @property
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "entries": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{self.hit_rate:.1%}",
            "max_entries": self.max_entries,
            "ttl_seconds": self.ttl_seconds
        }


class RateLimiter:
    """Rate limiter for API calls."""
    
    def __init__(
        self,
        requests_per_second: float = 5.0,
        burst_limit: int = 10
    ):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum requests per second
            burst_limit: Maximum burst of requests allowed
        """
        self.requests_per_second = requests_per_second
        self.burst_limit = burst_limit
        self.tokens = float(burst_limit)
        self.last_update = time.time()
        self._lock = asyncio.Lock() if asyncio.get_event_loop().is_running() else None
    
    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        while True:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(
                self.burst_limit,
                self.tokens + elapsed * self.requests_per_second
            )
            self.last_update = now
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            
            # Wait for tokens to replenish
            wait_time = (1.0 - self.tokens) / self.requests_per_second
            await asyncio.sleep(wait_time)
    
    def acquire_sync(self) -> None:
        """Synchronous version of acquire."""
        while True:
            now = time.time()
            elapsed = now - self.last_update
            self.tokens = min(
                self.burst_limit,
                self.tokens + elapsed * self.requests_per_second
            )
            self.last_update = now
            
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return
            
            wait_time = (1.0 - self.tokens) / self.requests_per_second
            time.sleep(wait_time)


class CVEMatcher:
    """
    Online CVE vulnerability matcher using NVD and CVE.org APIs.
    
    Provides real-time CVE lookup for detected services based on
    CPE identifiers or product/version strings.
    """
    
    # NVD API 2.0 endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    
    # CVE.org API (fallback)
    CVE_ORG_API = "https://cveawg.mitre.org/api/cve"
    
    # Exploit-DB API (for exploit references)
    EXPLOIT_DB_API = "https://www.exploit-db.com/search"
    
    def __init__(
        self,
        nvd_api_key: Optional[str] = None,
        cache_ttl: int = 3600,
        cache_path: Optional[Path] = None,
        timeout: float = 30.0,
        max_results_per_query: int = 100,
        rate_limit: float = 5.0
    ):
        """
        Initialize CVE Matcher.
        
        Args:
            nvd_api_key: NVD API key (optional, increases rate limit)
            cache_ttl: Cache time-to-live in seconds
            cache_path: Path to persist cache
            timeout: API request timeout
            max_results_per_query: Maximum CVEs to return per query
            rate_limit: Requests per second limit
        """
        self.nvd_api_key = nvd_api_key
        self.timeout = timeout
        self.max_results = max_results_per_query
        
        # Initialize cache
        if cache_path is None:
            cache_path = Path.home() / ".spectrescan" / "cve_cache.json"
        self.cache = CVECache(
            ttl_seconds=cache_ttl,
            persist_path=cache_path
        )
        
        # Rate limiter - NVD allows 5 requests/30s without key, 50/30s with key
        rate = 50.0 / 30.0 if nvd_api_key else 5.0 / 30.0
        self.rate_limiter = RateLimiter(requests_per_second=rate)
        
        # Session management
        self._session: Optional[Any] = None
        self._http_client = self._get_http_client()
    
    def _get_http_client(self) -> str:
        """Determine which HTTP client to use."""
        if AIOHTTP_AVAILABLE:
            return "aiohttp"
        elif HTTPX_AVAILABLE:
            return "httpx"
        return "urllib"
    
    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for API requests."""
        headers = {
            "User-Agent": "SpectreScan/2.0 (CVE Matcher; +https://github.com/BitSpectreLabs/SpectreScan)",
            "Accept": "application/json"
        }
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        return headers
    
    async def _make_request_async(self, url: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Make an async HTTP request."""
        await self.rate_limiter.acquire()
        
        try:
            if self._http_client == "aiohttp" and AIOHTTP_AVAILABLE:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        headers=self._get_headers(),
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as response:
                        if response.status == 200:
                            return await response.json(), None
                        elif response.status == 403:
                            return None, "API rate limit exceeded"
                        elif response.status == 404:
                            return None, "No CVEs found"
                        else:
                            return None, f"API error: {response.status}"
            
            elif self._http_client == "httpx" and HTTPX_AVAILABLE:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        url,
                        headers=self._get_headers(),
                        timeout=self.timeout
                    )
                    if response.status_code == 200:
                        return response.json(), None
                    elif response.status_code == 403:
                        return None, "API rate limit exceeded"
                    elif response.status_code == 404:
                        return None, "No CVEs found"
                    else:
                        return None, f"API error: {response.status_code}"
            
            else:
                # Fallback to sync urllib in async context
                return await asyncio.get_event_loop().run_in_executor(
                    None, self._make_request_sync, url
                )
                
        except asyncio.TimeoutError:
            return None, "Request timed out"
        except Exception as e:
            logger.error(f"CVE API request failed: {e}")
            return None, str(e)
    
    def _make_request_sync(self, url: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Make a synchronous HTTP request using urllib."""
        self.rate_limiter.acquire_sync()
        
        try:
            # Create SSL context that doesn't verify (for testing)
            ctx = ssl.create_default_context()
            
            request = urllib.request.Request(url, headers=self._get_headers())
            
            with urllib.request.urlopen(request, timeout=self.timeout, context=ctx) as response:
                if response.status == 200:
                    return json.loads(response.read().decode()), None
                else:
                    return None, f"API error: {response.status}"
                    
        except urllib.error.HTTPError as e:
            if e.code == 403:
                return None, "API rate limit exceeded"
            elif e.code == 404:
                return None, "No CVEs found"
            return None, f"API error: {e.code}"
        except urllib.error.URLError as e:
            return None, f"Connection error: {e.reason}"
        except Exception as e:
            logger.error(f"CVE API request failed: {e}")
            return None, str(e)
    
    def _parse_nvd_response(self, data: Dict) -> List[CVEEntry]:
        """Parse NVD API 2.0 response into CVEEntry objects."""
        cves = []
        
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue
            
            # Get description (prefer English)
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Parse dates
            published = None
            modified = None
            try:
                pub_str = cve_data.get("published")
                if pub_str:
                    published = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
                mod_str = cve_data.get("lastModified")
                if mod_str:
                    modified = datetime.fromisoformat(mod_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
            
            # Parse CVSS scores
            cvss_v2 = None
            cvss_v3 = None
            cvss_v4 = None
            
            metrics = cve_data.get("metrics", {})
            
            # CVSS v3.1
            for v31_metric in metrics.get("cvssMetricV31", []):
                cvss_data = v31_metric.get("cvssData", {})
                cvss_v3 = CVSSScore(
                    version=CVSSVersion.V3_1,
                    base_score=cvss_data.get("baseScore", 0.0),
                    severity=CVESeverity.from_cvss(cvss_data.get("baseScore")),
                    vector_string=cvss_data.get("vectorString"),
                    exploitability_score=v31_metric.get("exploitabilityScore"),
                    impact_score=v31_metric.get("impactScore")
                )
                break
            
            # CVSS v3.0
            if not cvss_v3:
                for v30_metric in metrics.get("cvssMetricV30", []):
                    cvss_data = v30_metric.get("cvssData", {})
                    cvss_v3 = CVSSScore(
                        version=CVSSVersion.V3,
                        base_score=cvss_data.get("baseScore", 0.0),
                        severity=CVESeverity.from_cvss(cvss_data.get("baseScore")),
                        vector_string=cvss_data.get("vectorString"),
                        exploitability_score=v30_metric.get("exploitabilityScore"),
                        impact_score=v30_metric.get("impactScore")
                    )
                    break
            
            # CVSS v2
            for v2_metric in metrics.get("cvssMetricV2", []):
                cvss_data = v2_metric.get("cvssData", {})
                cvss_v2 = CVSSScore(
                    version=CVSSVersion.V2,
                    base_score=cvss_data.get("baseScore", 0.0),
                    severity=CVESeverity.from_cvss(cvss_data.get("baseScore")),
                    vector_string=cvss_data.get("vectorString"),
                    exploitability_score=v2_metric.get("exploitabilityScore"),
                    impact_score=v2_metric.get("impactScore")
                )
                break
            
            # Determine overall severity
            highest_score = None
            if cvss_v3:
                highest_score = cvss_v3.base_score
            elif cvss_v2:
                highest_score = cvss_v2.base_score
            severity = CVESeverity.from_cvss(highest_score)
            
            # Parse references
            references = []
            for ref in cve_data.get("references", []):
                references.append(CVEReference(
                    url=ref.get("url", ""),
                    source=ref.get("source", ""),
                    tags=ref.get("tags", [])
                ))
            
            # Check for exploits
            exploit_available = any(
                "Exploit" in ref.tags
                for ref in references
            )
            
            # Check for patches
            patch_available = any(
                "Patch" in ref.tags or "Vendor Advisory" in ref.tags
                for ref in references
            )
            
            # Parse CWE IDs
            cwe_ids = []
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwe_ids.append(cwe_value)
            
            # Parse CPE matches
            cpe_matches = []
            configurations = cve_data.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        criteria = cpe_match.get("criteria", "")
                        if criteria:
                            cpe_matches.append(criteria)
            
            cve_entry = CVEEntry(
                cve_id=cve_id,
                description=description,
                published_date=published,
                last_modified_date=modified,
                cvss_v2=cvss_v2,
                cvss_v3=cvss_v3,
                cvss_v4=cvss_v4,
                severity=severity,
                cpe_matches=cpe_matches,
                references=references,
                cwe_ids=cwe_ids,
                exploit_available=exploit_available,
                patch_available=patch_available
            )
            
            cves.append(cve_entry)
        
        return cves
    
    def _build_cpe_string(
        self,
        vendor: str,
        product: str,
        version: Optional[str] = None
    ) -> str:
        """
        Build a CPE 2.3 string from components.
        
        Args:
            vendor: Vendor name
            product: Product name
            version: Optional version string
            
        Returns:
            CPE 2.3 formatted string
        """
        # Normalize names (lowercase, replace spaces with underscores)
        vendor = vendor.lower().replace(" ", "_").replace("-", "_")
        product = product.lower().replace(" ", "_").replace("-", "_")
        
        if version:
            version = version.lower().replace(" ", "_")
            return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        else:
            return f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"
    
    def _normalize_product_name(self, name: str) -> Tuple[str, str]:
        """
        Normalize a product name and extract vendor.
        
        Returns:
            Tuple of (vendor, product)
        """
        # Common vendor mappings
        vendor_mappings = {
            "apache": ("apache", None),
            "nginx": ("nginx", "nginx"),
            "openssh": ("openbsd", "openssh"),
            "ssh": ("openbsd", "openssh"),
            "mysql": ("oracle", "mysql"),
            "mariadb": ("mariadb", "mariadb"),
            "postgresql": ("postgresql", "postgresql"),
            "postgres": ("postgresql", "postgresql"),
            "redis": ("redis", "redis"),
            "mongodb": ("mongodb", "mongodb"),
            "elasticsearch": ("elastic", "elasticsearch"),
            "tomcat": ("apache", "tomcat"),
            "iis": ("microsoft", "internet_information_services"),
            "microsoft-iis": ("microsoft", "internet_information_services"),
            "httpd": ("apache", "http_server"),
            "apache httpd": ("apache", "http_server"),
            "lighttpd": ("lighttpd", "lighttpd"),
            "caddy": ("caddyserver", "caddy"),
            "haproxy": ("haproxy", "haproxy"),
            "varnish": ("varnish", "varnish"),
            "squid": ("squid-cache", "squid"),
            "proftpd": ("proftpd", "proftpd"),
            "vsftpd": ("vsftpd_project", "vsftpd"),
            "pure-ftpd": ("pureftpd", "pure-ftpd"),
            "postfix": ("postfix", "postfix"),
            "sendmail": ("sendmail", "sendmail"),
            "exim": ("exim", "exim"),
            "dovecot": ("dovecot", "dovecot"),
            "wordpress": ("wordpress", "wordpress"),
            "drupal": ("drupal", "drupal"),
            "joomla": ("joomla", "joomla"),
            "php": ("php", "php"),
            "python": ("python", "python"),
            "node.js": ("nodejs", "node.js"),
            "nodejs": ("nodejs", "node.js"),
            "java": ("oracle", "java"),
            "docker": ("docker", "docker"),
            "kubernetes": ("kubernetes", "kubernetes"),
            "jenkins": ("jenkins", "jenkins"),
            "grafana": ("grafana", "grafana"),
            "prometheus": ("prometheus", "prometheus"),
            "rabbitmq": ("vmware", "rabbitmq"),
            "kafka": ("apache", "kafka"),
            "memcached": ("memcached", "memcached"),
            "bind": ("isc", "bind"),
            "openssl": ("openssl", "openssl"),
        }
        
        name_lower = name.lower().strip()
        
        # Check direct mappings
        if name_lower in vendor_mappings:
            vendor, product = vendor_mappings[name_lower]
            return (vendor, product if product else name_lower)
        
        # Try to extract vendor/product from "vendor product" format
        parts = name_lower.split()
        if len(parts) >= 2:
            potential_vendor = parts[0]
            if potential_vendor in vendor_mappings:
                vendor, _ = vendor_mappings[potential_vendor]
                product = "_".join(parts[1:])
                return (vendor, product)
        
        # Default: use name as both vendor and product
        normalized = name_lower.replace(" ", "_").replace("-", "_")
        return (normalized, normalized)
    
    async def lookup_by_cpe(
        self,
        cpe: str,
        severity_filter: Optional[CVESeverity] = None,
        max_results: Optional[int] = None
    ) -> CVEMatchResult:
        """
        Look up CVEs by CPE string.
        
        Args:
            cpe: CPE 2.3 string
            severity_filter: Optional minimum severity filter
            max_results: Maximum number of results
            
        Returns:
            CVEMatchResult with matching CVEs
        """
        start_time = time.time()
        max_results = max_results or self.max_results
        
        # Check cache
        cache_key = self.cache._generate_key("cpe", cpe, severity_filter)
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit for CPE: {cpe}")
            result = cached
            result.cached = True
            return result
        
        # Build NVD API URL
        params = {
            "cpeName": cpe,
            "resultsPerPage": min(max_results, 2000)
        }
        url = f"{self.NVD_API_BASE}?{urlencode(params)}"
        
        logger.info(f"Querying NVD API for CPE: {cpe}")
        
        data, error = await self._make_request_async(url)
        
        query_time = (time.time() - start_time) * 1000
        
        if error:
            result = CVEMatchResult(
                cpe=cpe,
                error=error,
                query_time_ms=query_time
            )
            return result
        
        # Parse CVEs
        cves = self._parse_nvd_response(data)
        
        # Apply severity filter
        if severity_filter:
            severity_order = [
                CVESeverity.CRITICAL,
                CVESeverity.HIGH,
                CVESeverity.MEDIUM,
                CVESeverity.LOW
            ]
            min_index = severity_order.index(severity_filter)
            cves = [
                cve for cve in cves
                if cve.severity in severity_order[:min_index + 1]
            ]
        
        # Sort by severity (critical first)
        cves.sort(
            key=lambda c: (
                0 if c.severity == CVESeverity.CRITICAL else
                1 if c.severity == CVESeverity.HIGH else
                2 if c.severity == CVESeverity.MEDIUM else
                3 if c.severity == CVESeverity.LOW else 4
            )
        )
        
        # Limit results
        cves = cves[:max_results]
        
        # Count by severity
        critical = sum(1 for c in cves if c.severity == CVESeverity.CRITICAL)
        high = sum(1 for c in cves if c.severity == CVESeverity.HIGH)
        medium = sum(1 for c in cves if c.severity == CVESeverity.MEDIUM)
        low = sum(1 for c in cves if c.severity == CVESeverity.LOW)
        
        result = CVEMatchResult(
            cpe=cpe,
            cves=cves,
            total_found=data.get("totalResults", len(cves)),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            query_time_ms=query_time
        )
        
        # Cache result
        self.cache.set(cache_key, result)
        
        return result
    
    async def lookup_by_product(
        self,
        product: str,
        version: Optional[str] = None,
        vendor: Optional[str] = None,
        severity_filter: Optional[CVESeverity] = None,
        max_results: Optional[int] = None
    ) -> CVEMatchResult:
        """
        Look up CVEs by product name and version.
        
        Args:
            product: Product name (e.g., "nginx", "openssh")
            version: Optional version string
            vendor: Optional vendor name
            severity_filter: Optional minimum severity filter
            max_results: Maximum number of results
            
        Returns:
            CVEMatchResult with matching CVEs
        """
        start_time = time.time()
        max_results = max_results or self.max_results
        
        # Normalize product name
        if vendor:
            normalized_vendor = vendor.lower().replace(" ", "_")
            normalized_product = product.lower().replace(" ", "_")
        else:
            normalized_vendor, normalized_product = self._normalize_product_name(product)
        
        # Check cache
        cache_key = self.cache._generate_key(
            "product", normalized_vendor, normalized_product, version, severity_filter
        )
        cached = self.cache.get(cache_key)
        if cached:
            logger.debug(f"Cache hit for product: {product}")
            cached.cached = True
            return cached
        
        # Build CPE string
        cpe = self._build_cpe_string(normalized_vendor, normalized_product, version)
        
        # Query NVD with keyword search as fallback
        params = {
            "keywordSearch": f"{normalized_product}" + (f" {version}" if version else ""),
            "resultsPerPage": min(max_results * 2, 2000)  # Get more for filtering
        }
        
        if version:
            # Try CPE match first
            params = {
                "cpeName": cpe,
                "resultsPerPage": min(max_results * 2, 2000)
            }
        
        url = f"{self.NVD_API_BASE}?{urlencode(params)}"
        
        logger.info(f"Querying NVD API for product: {product} (version: {version})")
        
        data, error = await self._make_request_async(url)
        
        # If CPE search returned nothing, try keyword search
        if (error == "No CVEs found" or (data and data.get("totalResults", 0) == 0)) and version:
            params = {
                "keywordSearch": f"{normalized_product} {version}",
                "resultsPerPage": min(max_results * 2, 2000)
            }
            url = f"{self.NVD_API_BASE}?{urlencode(params)}"
            data, error = await self._make_request_async(url)
        
        query_time = (time.time() - start_time) * 1000
        
        if error:
            result = CVEMatchResult(
                product=product,
                version=version,
                cpe=cpe,
                error=error,
                query_time_ms=query_time
            )
            return result
        
        # Parse CVEs
        cves = self._parse_nvd_response(data)
        
        # Filter by version if specified
        if version:
            version_pattern = re.escape(version)
            cves = [
                cve for cve in cves
                if any(version in cpe_match for cpe_match in cve.cpe_matches)
                or version in cve.description.lower()
            ]
        
        # Apply severity filter
        if severity_filter:
            severity_order = [
                CVESeverity.CRITICAL,
                CVESeverity.HIGH,
                CVESeverity.MEDIUM,
                CVESeverity.LOW
            ]
            min_index = severity_order.index(severity_filter)
            cves = [
                cve for cve in cves
                if cve.severity in severity_order[:min_index + 1]
            ]
        
        # Sort by severity
        cves.sort(
            key=lambda c: (
                0 if c.severity == CVESeverity.CRITICAL else
                1 if c.severity == CVESeverity.HIGH else
                2 if c.severity == CVESeverity.MEDIUM else
                3 if c.severity == CVESeverity.LOW else 4
            )
        )
        
        # Limit results
        cves = cves[:max_results]
        
        # Count by severity
        critical = sum(1 for c in cves if c.severity == CVESeverity.CRITICAL)
        high = sum(1 for c in cves if c.severity == CVESeverity.HIGH)
        medium = sum(1 for c in cves if c.severity == CVESeverity.MEDIUM)
        low = sum(1 for c in cves if c.severity == CVESeverity.LOW)
        
        result = CVEMatchResult(
            product=product,
            version=version,
            cpe=cpe,
            cves=cves,
            total_found=data.get("totalResults", len(cves)),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            query_time_ms=query_time
        )
        
        # Cache result
        self.cache.set(cache_key, result)
        
        return result
    
    async def lookup_cve_id(self, cve_id: str) -> Optional[CVEEntry]:
        """
        Look up a specific CVE by its ID.
        
        Args:
            cve_id: CVE ID (e.g., "CVE-2021-44228")
            
        Returns:
            CVEEntry if found, None otherwise
        """
        # Validate CVE ID format
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id.upper()):
            logger.warning(f"Invalid CVE ID format: {cve_id}")
            return None
        
        cve_id = cve_id.upper()
        
        # Check cache
        cache_key = self.cache._generate_key("cve_id", cve_id)
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        # Query NVD
        url = f"{self.NVD_API_BASE}?cveId={cve_id}"
        
        logger.info(f"Looking up CVE: {cve_id}")
        
        data, error = await self._make_request_async(url)
        
        if error or not data:
            logger.warning(f"Failed to fetch {cve_id}: {error}")
            return None
        
        cves = self._parse_nvd_response(data)
        
        if cves:
            cve = cves[0]
            self.cache.set(cache_key, cve)
            return cve
        
        return None
    
    async def batch_lookup(
        self,
        products: List[Dict[str, str]],
        severity_filter: Optional[CVESeverity] = None,
        callback: Optional[Callable[[str, CVEMatchResult], None]] = None
    ) -> Dict[str, CVEMatchResult]:
        """
        Look up CVEs for multiple products.
        
        Args:
            products: List of dicts with 'product', 'version', 'vendor' keys
            severity_filter: Optional minimum severity filter
            callback: Optional callback for progress updates
            
        Returns:
            Dict mapping product names to CVEMatchResult
        """
        results = {}
        
        for product_info in products:
            product = product_info.get("product", "")
            version = product_info.get("version")
            vendor = product_info.get("vendor")
            
            if not product:
                continue
            
            result = await self.lookup_by_product(
                product=product,
                version=version,
                vendor=vendor,
                severity_filter=severity_filter
            )
            
            key = f"{product}" + (f"/{version}" if version else "")
            results[key] = result
            
            if callback:
                callback(key, result)
        
        return results
    
    def lookup_by_cpe_sync(
        self,
        cpe: str,
        severity_filter: Optional[CVESeverity] = None,
        max_results: Optional[int] = None
    ) -> CVEMatchResult:
        """Synchronous version of lookup_by_cpe."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.lookup_by_cpe(cpe, severity_filter, max_results)
        )
    
    def lookup_by_product_sync(
        self,
        product: str,
        version: Optional[str] = None,
        vendor: Optional[str] = None,
        severity_filter: Optional[CVESeverity] = None,
        max_results: Optional[int] = None
    ) -> CVEMatchResult:
        """Synchronous version of lookup_by_product."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            self.lookup_by_product(product, version, vendor, severity_filter, max_results)
        )
    
    def lookup_cve_id_sync(self, cve_id: str) -> Optional[CVEEntry]:
        """Synchronous version of lookup_cve_id."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.lookup_cve_id(cve_id))
    
    def save_cache(self) -> None:
        """Persist cache to disk."""
        self.cache.save_to_disk()
    
    @property
    def cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.stats


def format_cve_report(result: CVEMatchResult, verbose: bool = False) -> str:
    """
    Format a CVE match result as a readable report.
    
    Args:
        result: CVEMatchResult to format
        verbose: Include detailed CVE information
        
    Returns:
        Formatted string report
    """
    lines = []
    
    # Header
    if result.product:
        header = f"CVE Report: {result.product}"
        if result.version:
            header += f" v{result.version}"
    elif result.cpe:
        header = f"CVE Report: {result.cpe}"
    else:
        header = "CVE Report"
    
    lines.append("=" * 70)
    lines.append(header)
    lines.append("=" * 70)
    lines.append("")
    
    # Error case
    if result.error:
        lines.append(f"Error: {result.error}")
        return "\n".join(lines)
    
    # Summary
    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Total CVEs Found: {result.total_found}")
    lines.append(f"  Critical: {result.critical_count}")
    lines.append(f"  High:     {result.high_count}")
    lines.append(f"  Medium:   {result.medium_count}")
    lines.append(f"  Low:      {result.low_count}")
    lines.append(f"Risk Level: {result.risk_level.value.upper()}")
    lines.append(f"Query Time: {result.query_time_ms:.1f}ms")
    if result.cached:
        lines.append("(Cached result)")
    lines.append("")
    
    # CVE details
    if result.cves:
        lines.append("VULNERABILITIES")
        lines.append("-" * 40)
        
        for cve in result.cves:
            # CVE header
            severity_icon = {
                CVESeverity.CRITICAL: "[CRITICAL]",
                CVESeverity.HIGH: "[HIGH]",
                CVESeverity.MEDIUM: "[MEDIUM]",
                CVESeverity.LOW: "[LOW]",
                CVESeverity.UNKNOWN: "[?]"
            }.get(cve.severity, "[?]")
            
            score = cve.highest_cvss_score
            score_str = f" (CVSS: {score:.1f})" if score else ""
            
            lines.append(f"\n{cve.cve_id} {severity_icon}{score_str}")
            
            if cve.exploit_available:
                lines.append("  ** EXPLOIT AVAILABLE **")
            
            if cve.patch_available:
                lines.append("  [Patch Available]")
            
            # Description (truncated)
            if cve.description:
                desc = cve.description
                if len(desc) > 200 and not verbose:
                    desc = desc[:200] + "..."
                lines.append(f"  {desc}")
            
            if verbose:
                # CWE IDs
                if cve.cwe_ids:
                    lines.append(f"  CWE: {', '.join(cve.cwe_ids)}")
                
                # Dates
                if cve.published_date:
                    lines.append(f"  Published: {cve.published_date.strftime('%Y-%m-%d')}")
                
                # References
                if cve.references:
                    lines.append("  References:")
                    for ref in cve.references[:3]:  # Limit to 3
                        lines.append(f"    - {ref.url}")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)


def cve_result_to_dict(result: CVEMatchResult) -> Dict[str, Any]:
    """
    Convert CVEMatchResult to a JSON-serializable dictionary.
    
    Args:
        result: CVEMatchResult to convert
        
    Returns:
        Dictionary representation
    """
    return {
        "product": result.product,
        "version": result.version,
        "cpe": result.cpe,
        "total_found": result.total_found,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "low_count": result.low_count,
        "risk_level": result.risk_level.value,
        "error": result.error,
        "cached": result.cached,
        "query_time_ms": result.query_time_ms,
        "cves": [
            {
                "id": cve.cve_id,
                "description": cve.description,
                "severity": cve.severity.value,
                "cvss_score": cve.highest_cvss_score,
                "cvss_vector": cve.primary_cvss.vector_string if cve.primary_cvss else None,
                "published": cve.published_date.isoformat() if cve.published_date else None,
                "exploit_available": cve.exploit_available,
                "patch_available": cve.patch_available,
                "cwe_ids": cve.cwe_ids,
                "references": [
                    {"url": ref.url, "source": ref.source, "tags": ref.tags}
                    for ref in cve.references
                ]
            }
            for cve in result.cves
        ]
    }
