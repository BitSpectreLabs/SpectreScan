"""
Signature Database Cache - Performance Optimization

Lazy loading and caching of signature databases (CPE, service signatures, version patterns).
Only loads databases when service detection is actually enabled, improving startup time.

File: spectrescan/core/signature_cache.py
Author: BitSpectreLabs
Version: 1.2.0
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)


class SignatureCache:
    """
    Singleton cache for signature databases with lazy loading.
    
    Provides fast access to CPE dictionary, service signatures, and version patterns
    without loading them until actually needed. Uses LRU caching for regex compilation.
    """
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize cache (only once)."""
        if not SignatureCache._initialized:
            self._cpe_dict: Optional[Dict[str, Any]] = None
            self._service_sigs: Optional[Dict[str, Any]] = None
            self._version_patterns: Optional[Dict[str, List[str]]] = None
            self._compiled_patterns_cache: Dict[str, re.Pattern] = {}
            
            # Paths to database files
            self._data_dir = Path(__file__).parent.parent / "data"
            self._cpe_file = self._data_dir / "cpe-dictionary.json"
            self._sigs_file = self._data_dir / "service-signatures.json"
            self._patterns_file = self._data_dir / "version-patterns.json"
            
            SignatureCache._initialized = True
            logger.debug("SignatureCache initialized (lazy loading enabled)")
    
    def load_cpe_dictionary(self) -> Dict[str, Any]:
        """
        Load CPE dictionary with lazy loading.
        
        Returns:
            CPE dictionary data
        """
        if self._cpe_dict is None:
            logger.info("Loading CPE dictionary...")
            with open(self._cpe_file, 'r', encoding='utf-8') as f:
                self._cpe_dict = json.load(f)
            logger.info(f"Loaded {len(self._cpe_dict.get('cpe_mappings', {}))} CPE mappings")
        return self._cpe_dict
    
    def load_service_signatures(self) -> Dict[str, Any]:
        """
        Load service signatures with lazy loading.
        
        Returns:
            Service signatures data
        """
        if self._service_sigs is None:
            logger.info("Loading service signatures...")
            with open(self._sigs_file, 'r', encoding='utf-8') as f:
                self._service_sigs = json.load(f)
            logger.info(f"Loaded {len(self._service_sigs.get('signatures', []))} service signatures")
        return self._service_sigs
    
    def load_version_patterns(self) -> Dict[str, List[str]]:
        """
        Load version patterns with lazy loading.
        
        Returns:
            Version patterns data
        """
        if self._version_patterns is None:
            logger.info("Loading version patterns...")
            with open(self._patterns_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self._version_patterns = data.get('patterns', {})
            logger.info(f"Loaded {len(self._version_patterns)} version pattern sets")
        return self._version_patterns
    
    def get_compiled_pattern(self, pattern: str, flags: int = 0) -> Optional[re.Pattern]:
        """
        Get compiled regex pattern with caching.
        
        Args:
            pattern: Regex pattern string
            flags: Regex flags
            
        Returns:
            Compiled pattern or None if compilation fails
        """
        cache_key = f"{pattern}:{flags}"
        
        if cache_key not in self._compiled_patterns_cache:
            try:
                self._compiled_patterns_cache[cache_key] = re.compile(pattern, flags)
            except re.error as e:
                logger.warning(f"Failed to compile pattern '{pattern[:50]}...': {e}")
                return None
        
        return self._compiled_patterns_cache.get(cache_key)
    
    def get_cpe_for_service(self, service_name: str) -> Optional[str]:
        """
        Get CPE identifier for a service name.
        
        Args:
            service_name: Service name (e.g., "nginx", "apache")
            
        Returns:
            CPE string or None
        """
        cpe_dict = self.load_cpe_dictionary()
        mappings = cpe_dict.get('cpe_mappings', {})
        
        service_lower = service_name.lower()
        if service_lower in mappings:
            return mappings[service_lower].get('cpe_base')
        
        return None
    
    def match_service_signature(
        self, 
        banner: str, 
        port: int, 
        protocol: str = "tcp"
    ) -> Optional[Dict[str, Any]]:
        """
        Match banner against service signatures.
        
        Args:
            banner: Service banner text
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            Matched signature dict or None
        """
        sigs = self.load_service_signatures()
        signatures = sigs.get('signatures', [])
        
        best_match = None
        best_confidence = 0
        
        for sig in signatures:
            # Check if port matches
            if port in sig.get('ports', []) and protocol == sig.get('protocol', 'tcp'):
                # Check patterns
                for pattern in sig.get('patterns', []):
                    compiled = self.get_compiled_pattern(pattern, re.IGNORECASE)
                    if compiled and compiled.search(banner):
                        confidence = sig.get('confidence', 50)
                        if confidence > best_confidence:
                            best_confidence = confidence
                            best_match = sig
        
        return best_match
    
    def extract_version(self, banner: str, service: str) -> Optional[str]:
        """
        Extract version from banner using version patterns.
        
        Args:
            banner: Service banner text
            service: Service name
            
        Returns:
            Version string or None
        """
        patterns = self.load_version_patterns()
        service_lower = service.lower()
        
        # Try service-specific patterns first
        if service_lower in patterns:
            for pattern in patterns[service_lower]:
                compiled = self.get_compiled_pattern(pattern)
                if compiled:
                    match = compiled.search(banner)
                    if match:
                        return match.group(1) if match.groups() else match.group(0)
        
        # Try generic patterns as fallback
        if 'generic_patterns' in patterns:
            for pattern in patterns['generic_patterns']:
                compiled = self.get_compiled_pattern(pattern)
                if compiled:
                    match = compiled.search(banner)
                    if match:
                        return match.group(1) if match.groups() else match.group(0)
        
        return None
    
    def clear_cache(self) -> None:
        """Clear all cached data (for memory management)."""
        self._cpe_dict = None
        self._service_sigs = None
        self._version_patterns = None
        self._compiled_patterns_cache.clear()
        logger.info("Signature cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dict with cache stats
        """
        return {
            "cpe_loaded": self._cpe_dict is not None,
            "signatures_loaded": self._service_sigs is not None,
            "patterns_loaded": self._version_patterns is not None,
            "compiled_patterns_count": len(self._compiled_patterns_cache),
            "cpe_count": len(self._cpe_dict.get('cpe_mappings', {})) if self._cpe_dict else 0,
            "signatures_count": len(self._service_sigs.get('signatures', [])) if self._service_sigs else 0,
            "patterns_count": len(self._version_patterns) if self._version_patterns else 0,
        }


# Global singleton instance
_cache = SignatureCache()


def get_signature_cache() -> SignatureCache:
    """Get global signature cache instance."""
    return _cache


# Convenience functions for common operations
def get_cpe_for_service(service_name: str) -> Optional[str]:
    """Get CPE identifier for service."""
    return _cache.get_cpe_for_service(service_name)


def match_service_signature(banner: str, port: int, protocol: str = "tcp") -> Optional[Dict[str, Any]]:
    """Match banner against signatures."""
    return _cache.match_service_signature(banner, port, protocol)


def extract_version(banner: str, service: str) -> Optional[str]:
    """Extract version from banner."""
    return _cache.extract_version(banner, service)


def clear_signature_cache() -> None:
    """Clear all signature caches."""
    _cache.clear_cache()


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics."""
    return _cache.get_cache_stats()
