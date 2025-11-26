"""
Application Fingerprinting
Detect web applications, databases, APIs, microservices with detailed metadata.

Author: BitSpectreLabs
License: MIT
"""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class ApplicationInfo:
    """Detailed application information."""
    name: str
    category: str  # "web_app", "api", "database", "microservice", "cms", "framework"
    version: Optional[str] = None
    vendor: Optional[str] = None
    confidence: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    cpe: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    components: List[Dict[str, str]] = field(default_factory=list)


class ApplicationFingerprinter:
    """
    Advanced application fingerprinting engine.
    Detects web apps, APIs, databases, and microservices.
    """
    
    def __init__(self):
        """Initialize fingerprinter with detection databases."""
        self._load_signatures()
    
    def _load_signatures(self):
        """Load application signatures."""
        # Web application signatures
        self.web_apps = {
            # CMS
            "WordPress": {
                "patterns": [
                    r"wp-content", r"wp-includes", r"wp-admin",
                    r"/wp-json/", r"wordpress", r"X-Powered-By: W3 Total Cache"
                ],
                "headers": ["X-Powered-By"],
                "paths": ["/wp-admin/", "/wp-login.php", "/wp-json/wp/v2"],
                "category": "cms",
                "vendor": "WordPress Foundation",
                "cpe": "cpe:/a:wordpress:wordpress"
            },
            "Drupal": {
                "patterns": [
                    r"Drupal", r"/sites/default/", r"/sites/all/",
                    r"X-Generator: Drupal", r"drupal\.js"
                ],
                "headers": ["X-Generator", "X-Drupal-Cache"],
                "paths": ["/user/login", "/node", "/admin"],
                "category": "cms",
                "vendor": "Drupal",
                "cpe": "cpe:/a:drupal:drupal"
            },
            "Joomla": {
                "patterns": [
                    r"Joomla", r"/components/com_", r"/administrator/",
                    r"joomla\.js", r"/media/jui/"
                ],
                "paths": ["/administrator/", "/components/", "/modules/"],
                "category": "cms",
                "vendor": "Joomla",
                "cpe": "cpe:/a:joomla:joomla"
            },
            
            # E-commerce
            "Magento": {
                "patterns": [
                    r"Magento", r"/static/frontend/", r"Mage\.Cookies",
                    r"/skin/frontend/"
                ],
                "paths": ["/admin/", "/customer/account/", "/checkout/cart/"],
                "category": "web_app",
                "vendor": "Adobe",
                "cpe": "cpe:/a:magento:magento"
            },
            "Shopify": {
                "patterns": [
                    r"Shopify", r"cdn\.shopify\.com", r"myshopify\.com",
                    r"X-ShopId"
                ],
                "headers": ["X-ShopId", "X-ShardId"],
                "category": "web_app",
                "vendor": "Shopify",
                "cpe": "cpe:/a:shopify:shopify"
            },
            "WooCommerce": {
                "patterns": [
                    r"WooCommerce", r"woocommerce", r"/wc-api/",
                    r"wc-ajax"
                ],
                "paths": ["/shop/", "/cart/", "/checkout/"],
                "category": "web_app",
                "vendor": "Automattic",
                "cpe": "cpe:/a:woocommerce:woocommerce"
            },
            
            # Admin panels
            "phpMyAdmin": {
                "patterns": [
                    r"phpMyAdmin", r"pma_", r"/phpmyadmin/",
                    r"PMA_VERSION"
                ],
                "paths": ["/phpmyadmin/", "/pma/", "/phpMyAdmin/"],
                "category": "web_app",
                "vendor": "phpMyAdmin",
                "cpe": "cpe:/a:phpmyadmin:phpmyadmin"
            },
            "Adminer": {
                "patterns": [
                    r"Adminer", r"adminer\.css", r"adminer\.php"
                ],
                "paths": ["/adminer.php", "/adminer/"],
                "category": "web_app",
                "vendor": "Adminer",
                "cpe": "cpe:/a:adminer:adminer"
            },
            
            # Frameworks
            "Laravel": {
                "patterns": [
                    r"laravel", r"laravel_session", r"XSRF-TOKEN",
                    r"X-CSRF-TOKEN"
                ],
                "headers": ["X-Powered-By"],
                "category": "framework",
                "vendor": "Laravel",
                "cpe": "cpe:/a:laravel:laravel"
            },
            "Django": {
                "patterns": [
                    r"django", r"csrftoken", r"__admin__",
                    r"X-Frame-Options: DENY"
                ],
                "paths": ["/admin/", "/static/admin/"],
                "category": "framework",
                "vendor": "Django Software Foundation",
                "cpe": "cpe:/a:djangoproject:django"
            },
            "Ruby on Rails": {
                "patterns": [
                    r"Rails", r"_rails_session", r"X-Runtime",
                    r"csrf-token", r"csrf-param"
                ],
                "headers": ["X-Runtime", "X-Request-Id"],
                "category": "framework",
                "vendor": "Rails Core Team",
                "cpe": "cpe:/a:rubyonrails:rails"
            },
            "Spring Boot": {
                "patterns": [
                    r"Spring", r"Whitelabel Error Page", r"/actuator/",
                    r"X-Application-Context"
                ],
                "paths": ["/actuator/health", "/actuator/info", "/actuator/metrics"],
                "category": "framework",
                "vendor": "Pivotal",
                "cpe": "cpe:/a:vmware:spring_boot"
            },
        }
        
        # API signatures
        self.api_signatures = {
            "REST API": {
                "patterns": [r"/api/v\d+/", r"application/json", r"REST"],
                "indicators": ["json", "xml", "hal"]
            },
            "GraphQL": {
                "patterns": [r"/graphql", r"__schema", r"query.*mutation"],
                "paths": ["/graphql", "/graphiql", "/api/graphql"]
            },
            "SOAP": {
                "patterns": [r"<SOAP-ENV:", r"xmlns:soap", r"application/soap\+xml"],
                "indicators": ["wsdl", "soap"]
            },
            "gRPC": {
                "patterns": [r"application/grpc", r"grpc-status", r"grpc-message"],
                "indicators": ["grpc", "protobuf"]
            },
            "OpenAPI": {
                "patterns": [r"swagger", r"openapi", r"/swagger-ui/", r"/api-docs"],
                "paths": ["/swagger-ui.html", "/v3/api-docs", "/swagger.json"]
            },
        }
        
        # Microservice patterns
        self.microservice_patterns = {
            "Spring Cloud": {
                "patterns": [r"spring-cloud", r"eureka", r"zuul", r"ribbon"],
                "endpoints": ["/eureka/", "/actuator/", "/hystrix"]
            },
            "Netflix OSS": {
                "patterns": [r"eureka", r"zuul", r"hystrix", r"ribbon"],
                "endpoints": ["/eureka/apps", "/actuator/"]
            },
            "Istio": {
                "patterns": [r"istio", r"x-envoy", r"x-b3-traceid"],
                "headers": ["x-envoy-upstream-service-time", "x-b3-traceid"]
            },
            "Linkerd": {
                "patterns": [r"linkerd", r"l5d-", r"x-l5d-"],
                "headers": ["l5d-dst-override", "l5d-ctx-trace"]
            },
        }
    
    def fingerprint(
        self,
        banner: str,
        headers: Optional[Dict[str, str]] = None,
        url: Optional[str] = None,
        response_body: Optional[str] = None
    ) -> List[ApplicationInfo]:
        """
        Fingerprint application from various sources.
        
        Args:
            banner: Service banner
            headers: HTTP headers (if available)
            url: URL path (if available)
            response_body: Response content (if available)
        
        Returns:
            List of detected applications
        """
        applications = []
        
        # Detect web applications
        web_apps = self._detect_web_apps(banner, headers, url, response_body)
        applications.extend(web_apps)
        
        # Detect APIs
        apis = self._detect_apis(banner, headers, url, response_body)
        applications.extend(apis)
        
        # Detect microservices
        microservices = self._detect_microservices(banner, headers)
        applications.extend(microservices)
        
        # Detect databases (from banner)
        databases = self._detect_databases(banner)
        applications.extend(databases)
        
        return applications
    
    def _detect_web_apps(
        self,
        banner: str,
        headers: Optional[Dict[str, str]],
        url: Optional[str],
        body: Optional[str]
    ) -> List[ApplicationInfo]:
        """Detect web applications."""
        detected = []
        
        search_text = banner
        if body:
            search_text += "\n" + body
        if headers:
            search_text += "\n" + str(headers)
        if url:
            search_text += "\n" + url
        
        for app_name, signature in self.web_apps.items():
            confidence = 0
            matches = []
            metadata = {}
            
            # Check patterns
            for pattern in signature.get("patterns", []):
                if re.search(pattern, search_text, re.IGNORECASE):
                    confidence += 20
                    matches.append(pattern)
            
            # Check headers
            if headers:
                for header_name in signature.get("headers", []):
                    if header_name in headers:
                        confidence += 30
                        metadata[f"header_{header_name}"] = headers[header_name]
            
            # Check paths
            if url:
                for path in signature.get("paths", []):
                    if path in url:
                        confidence += 25
            
            if confidence >= 20:
                # Extract version
                version = self._extract_app_version(app_name, search_text)
                
                app_info = ApplicationInfo(
                    name=app_name,
                    category=signature.get("category", "web_app"),
                    version=version,
                    vendor=signature.get("vendor"),
                    confidence=min(confidence, 100),
                    metadata=metadata,
                    cpe=[signature.get("cpe", "")]
                )
                detected.append(app_info)
        
        return detected
    
    def _detect_apis(
        self,
        banner: str,
        headers: Optional[Dict[str, str]],
        url: Optional[str],
        body: Optional[str]
    ) -> List[ApplicationInfo]:
        """Detect API types."""
        detected = []
        
        search_text = banner
        if body:
            search_text += "\n" + body
        if headers:
            search_text += "\n" + str(headers)
        if url:
            search_text += "\n" + url
        
        for api_type, signature in self.api_signatures.items():
            confidence = 0
            
            # Check patterns
            for pattern in signature.get("patterns", []):
                if re.search(pattern, search_text, re.IGNORECASE):
                    confidence += 30
            
            # Check paths
            if url:
                for path in signature.get("paths", []):
                    if path in url:
                        confidence += 40
            
            if confidence >= 30:
                api_info = ApplicationInfo(
                    name=api_type,
                    category="api",
                    confidence=min(confidence, 100),
                    metadata={"type": api_type}
                )
                detected.append(api_info)
        
        return detected
    
    def _detect_microservices(
        self,
        banner: str,
        headers: Optional[Dict[str, str]]
    ) -> List[ApplicationInfo]:
        """Detect microservice frameworks."""
        detected = []
        
        search_text = banner
        if headers:
            search_text += "\n" + str(headers)
        
        for framework, signature in self.microservice_patterns.items():
            confidence = 0
            
            # Check patterns
            for pattern in signature.get("patterns", []):
                if re.search(pattern, search_text, re.IGNORECASE):
                    confidence += 35
            
            # Check headers
            if headers:
                for header_name in signature.get("headers", []):
                    if any(header_name.lower() in h.lower() for h in headers.keys()):
                        confidence += 40
            
            if confidence >= 35:
                ms_info = ApplicationInfo(
                    name=framework,
                    category="microservice",
                    confidence=min(confidence, 100),
                    metadata={"type": "service_mesh" if "istio" in framework.lower() or "linkerd" in framework.lower() else "framework"}
                )
                detected.append(ms_info)
        
        return detected
    
    def _detect_databases(self, banner: str) -> List[ApplicationInfo]:
        """Detect database applications."""
        detected = []
        
        db_patterns = {
            "MySQL": r"mysql.*?(\d+\.\d+\.\d+)",
            "MariaDB": r"mariadb.*?(\d+\.\d+\.\d+)",
            "PostgreSQL": r"postgresql.*?(\d+\.\d+)",
            "MongoDB": r"mongodb.*?(\d+\.\d+\.\d+)",
            "Redis": r"redis.*?(\d+\.\d+\.\d+)",
            "Elasticsearch": r"elasticsearch.*?(\d+\.\d+\.\d+)",
            "Cassandra": r"cassandra.*?(\d+\.\d+\.\d+)",
            "CouchDB": r"couchdb.*?(\d+\.\d+\.\d+)",
        }
        
        for db_name, pattern in db_patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex >= 1 else None
                
                db_info = ApplicationInfo(
                    name=db_name,
                    category="database",
                    version=version,
                    confidence=90,
                    cpe=[f"cpe:/a:{db_name.lower()}:{db_name.lower()}:{version or ''}"]
                )
                detected.append(db_info)
        
        return detected
    
    def _extract_app_version(self, app_name: str, text: str) -> Optional[str]:
        """Extract application version from text."""
        # Version patterns for common applications
        patterns = {
            "WordPress": r"WordPress[/\s](\d+\.\d+(?:\.\d+)?)",
            "Drupal": r"Drupal[/\s](\d+\.\d+)",
            "Joomla": r"Joomla[/!\s](\d+\.\d+\.\d+)",
            "Magento": r"Magento[/\s](\d+\.\d+\.\d+)",
            "phpMyAdmin": r"phpMyAdmin[/\s](\d+\.\d+\.\d+)",
            "Laravel": r"Laravel[/\s](\d+\.\d+)",
            "Django": r"Django[/\s](\d+\.\d+)",
        }
        
        pattern = patterns.get(app_name, rf"{app_name}[/\s](\d+\.\d+(?:\.\d+)?)")
        match = re.search(pattern, text, re.IGNORECASE)
        
        return match.group(1) if match else None
    
    def analyze_components(
        self,
        headers: Dict[str, str],
        body: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """
        Analyze application components (libraries, frameworks, modules).
        
        Args:
            headers: HTTP response headers
            body: Response body
        
        Returns:
            List of detected components
        """
        components = []
        
        # JavaScript libraries from HTML
        if body:
            js_patterns = {
                "jQuery": r"jquery[.-](\d+\.\d+\.\d+)",
                "React": r"react[.-](\d+\.\d+\.\d+)",
                "Vue.js": r"vue[.-](\d+\.\d+\.\d+)",
                "Angular": r"angular[.-](\d+\.\d+\.\d+)",
                "Bootstrap": r"bootstrap[.-](\d+\.\d+\.\d+)",
            }
            
            for lib, pattern in js_patterns.items():
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    components.append({
                        "name": lib,
                        "version": match.group(1),
                        "type": "javascript_library"
                    })
        
        # Server components from headers
        if "Server" in headers:
            server = headers["Server"]
            # Parse server string (e.g., "nginx/1.18.0 OpenSSL/1.1.1")
            parts = server.split()
            for part in parts:
                if "/" in part:
                    name, version = part.split("/", 1)
                    components.append({
                        "name": name,
                        "version": version,
                        "type": "server_component"
                    })
        
        return components
