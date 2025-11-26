"""
DNS Enumeration Module for SpectreScan.

Provides comprehensive DNS enumeration capabilities including forward/reverse
lookups, subdomain enumeration, zone transfer attempts, and wildcard detection.

by BitSpectreLabs
"""

import asyncio
import hashlib
import random
import socket
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

# DNS library import with fallback
try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    import dns.query
    import dns.rdatatype
    import dns.exception
    import dns.name
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False


class DNSRecordType(str, Enum):
    """Supported DNS record types."""
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"
    CAA = "CAA"


@dataclass
class DNSRecord:
    """Represents a single DNS record."""
    name: str
    record_type: str
    value: str
    ttl: int = 0
    priority: Optional[int] = None  # For MX records
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "name": self.name,
            "record_type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
        if self.priority is not None:
            result["priority"] = self.priority
        return result


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    subdomain: str
    full_domain: str
    ip_addresses: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    is_wildcard: bool = False
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "subdomain": self.subdomain,
            "full_domain": self.full_domain,
            "ip_addresses": self.ip_addresses,
            "cname": self.cname,
            "is_wildcard": self.is_wildcard,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class ZoneTransferResult:
    """Result of DNS zone transfer attempt."""
    domain: str
    nameserver: str
    success: bool
    records: List[DNSRecord] = field(default_factory=list)
    error_message: Optional[str] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "nameserver": self.nameserver,
            "success": self.success,
            "records": [r.to_dict() for r in self.records],
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class DNSEnumerationResult:
    """Complete DNS enumeration result for a domain."""
    domain: str
    records: Dict[str, List[DNSRecord]] = field(default_factory=dict)
    subdomains: List[SubdomainResult] = field(default_factory=list)
    zone_transfers: List[ZoneTransferResult] = field(default_factory=list)
    has_wildcard: bool = False
    wildcard_ips: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    mail_servers: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()
    
    @property
    def duration(self) -> float:
        """Get enumeration duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def total_records(self) -> int:
        """Get total number of DNS records found."""
        return sum(len(records) for records in self.records.values())
    
    @property
    def unique_ips(self) -> Set[str]:
        """Get all unique IP addresses discovered."""
        ips = set()
        for records in self.records.values():
            for record in records:
                if record.record_type in ("A", "AAAA"):
                    ips.add(record.value)
        for subdomain in self.subdomains:
            ips.update(subdomain.ip_addresses)
        return ips
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "records": {
                rtype: [r.to_dict() for r in records]
                for rtype, records in self.records.items()
            },
            "subdomains": [s.to_dict() for s in self.subdomains],
            "zone_transfers": [z.to_dict() for z in self.zone_transfers],
            "has_wildcard": self.has_wildcard,
            "wildcard_ips": self.wildcard_ips,
            "nameservers": self.nameservers,
            "mail_servers": self.mail_servers,
            "errors": self.errors,
            "statistics": {
                "total_records": self.total_records,
                "total_subdomains": len(self.subdomains),
                "unique_ips": list(self.unique_ips),
                "duration_seconds": self.duration,
            },
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class DNSEnumerator:
    """
    DNS Enumeration engine for comprehensive domain reconnaissance.
    
    Features:
    - Forward DNS lookups (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA)
    - Reverse DNS lookups (PTR records)
    - Subdomain enumeration with wordlists
    - DNS zone transfer attempts (AXFR)
    - Wildcard detection
    - Threading for parallel enumeration
    
    Example:
        enumerator = DNSEnumerator(timeout=5.0, threads=50)
        result = enumerator.enumerate("example.com", subdomains=True)
        print(f"Found {len(result.subdomains)} subdomains")
    """
    
    # Default record types for forward lookups
    DEFAULT_RECORD_TYPES = [
        DNSRecordType.A,
        DNSRecordType.AAAA,
        DNSRecordType.CNAME,
        DNSRecordType.MX,
        DNSRecordType.TXT,
        DNSRecordType.NS,
        DNSRecordType.SOA,
    ]
    
    # Built-in wordlist path
    DATA_DIR = Path(__file__).parent.parent / "data"
    
    def __init__(
        self,
        timeout: float = 5.0,
        threads: int = 50,
        nameservers: Optional[List[str]] = None,
        retries: int = 2,
    ):
        """
        Initialize DNS Enumerator.
        
        Args:
            timeout: DNS query timeout in seconds
            threads: Number of threads for parallel subdomain enumeration
            nameservers: Custom nameservers to use (default: system resolvers)
            retries: Number of retries for failed queries
        """
        if not DNSPYTHON_AVAILABLE:
            raise ImportError(
                "dnspython is required for DNS enumeration. "
                "Install with: pip install dnspython"
            )
        
        self.timeout = timeout
        self.threads = threads
        self.retries = retries
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        # Configure resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        if nameservers:
            self.resolver.nameservers = nameservers
    
    def stop(self) -> None:
        """Signal the enumerator to stop."""
        self._stop_event.set()
    
    def reset(self) -> None:
        """Reset the stop event for new enumeration."""
        self._stop_event.clear()
    
    def enumerate(
        self,
        domain: str,
        record_types: Optional[List[DNSRecordType]] = None,
        subdomains: bool = False,
        wordlist: Optional[Path] = None,
        zone_transfer: bool = False,
        reverse_lookup: bool = False,
        callback: Optional[Callable[[str, Any], None]] = None,
    ) -> DNSEnumerationResult:
        """
        Perform comprehensive DNS enumeration on a domain.
        
        Args:
            domain: Target domain to enumerate
            record_types: DNS record types to query (default: common types)
            subdomains: Enable subdomain enumeration
            wordlist: Custom wordlist path for subdomain enumeration
            zone_transfer: Attempt DNS zone transfers
            reverse_lookup: Perform reverse lookups on discovered IPs
            callback: Optional callback for progress updates
        
        Returns:
            DNSEnumerationResult with all discovered information
        """
        self.reset()
        result = DNSEnumerationResult(domain=domain)
        
        if record_types is None:
            record_types = self.DEFAULT_RECORD_TYPES
        
        try:
            # Step 1: Forward DNS lookups
            if callback:
                callback("status", f"Performing forward DNS lookups for {domain}")
            
            for rtype in record_types:
                if self._stop_event.is_set():
                    break
                records = self._lookup(domain, rtype)
                if records:
                    result.records[rtype.value] = records
                    if callback:
                        callback("records", {"type": rtype.value, "count": len(records)})
            
            # Extract nameservers and mail servers
            if DNSRecordType.NS.value in result.records:
                result.nameservers = [r.value for r in result.records[DNSRecordType.NS.value]]
            if DNSRecordType.MX.value in result.records:
                result.mail_servers = [r.value for r in result.records[DNSRecordType.MX.value]]
            
            # Step 2: Zone transfer attempts
            if zone_transfer and result.nameservers:
                if callback:
                    callback("status", "Attempting zone transfers")
                for ns in result.nameservers:
                    if self._stop_event.is_set():
                        break
                    zt_result = self._zone_transfer(domain, ns)
                    result.zone_transfers.append(zt_result)
                    if callback:
                        callback("zone_transfer", zt_result.to_dict())
            
            # Step 3: Wildcard detection
            if subdomains:
                if callback:
                    callback("status", "Checking for wildcard DNS")
                wildcard_detected, wildcard_ips = self._detect_wildcard(domain)
                result.has_wildcard = wildcard_detected
                result.wildcard_ips = wildcard_ips
                if callback:
                    callback("wildcard", {"detected": wildcard_detected, "ips": wildcard_ips})
            
            # Step 4: Subdomain enumeration
            if subdomains:
                if callback:
                    callback("status", "Enumerating subdomains")
                
                # Load wordlist
                words = self._load_wordlist(wordlist)
                if callback:
                    callback("wordlist", {"count": len(words)})
                
                # Enumerate subdomains with threading
                found_subdomains = self._enumerate_subdomains(
                    domain, words, result.wildcard_ips, callback
                )
                result.subdomains = found_subdomains
            
            # Step 5: Reverse lookups
            if reverse_lookup:
                if callback:
                    callback("status", "Performing reverse DNS lookups")
                for ip in result.unique_ips:
                    if self._stop_event.is_set():
                        break
                    ptr_records = self._reverse_lookup(ip)
                    if ptr_records:
                        if DNSRecordType.PTR.value not in result.records:
                            result.records[DNSRecordType.PTR.value] = []
                        result.records[DNSRecordType.PTR.value].extend(ptr_records)
            
        except Exception as e:
            result.errors.append(str(e))
        
        result.end_time = datetime.now()
        return result
    
    def _lookup(self, domain: str, record_type: DNSRecordType) -> List[DNSRecord]:
        """
        Perform a forward DNS lookup.
        
        Args:
            domain: Domain to query
            record_type: DNS record type
        
        Returns:
            List of DNS records
        """
        records = []
        
        try:
            answers = self.resolver.resolve(domain, record_type.value)
            for rdata in answers:
                value = str(rdata)
                priority = None
                
                # Handle MX records with priority
                if record_type == DNSRecordType.MX:
                    priority = rdata.preference
                    value = str(rdata.exchange).rstrip(".")
                
                # Clean up values
                if record_type in (DNSRecordType.CNAME, DNSRecordType.NS):
                    value = value.rstrip(".")
                
                records.append(DNSRecord(
                    name=domain,
                    record_type=record_type.value,
                    value=value,
                    ttl=answers.rrset.ttl,
                    priority=priority,
                ))
        except dns.resolver.NXDOMAIN:
            pass  # Domain does not exist
        except dns.resolver.NoAnswer:
            pass  # No records of this type
        except dns.resolver.NoNameservers:
            pass  # No nameservers available
        except dns.exception.Timeout:
            pass  # Query timed out
        except Exception:
            pass  # Other errors
        
        return records
    
    def _reverse_lookup(self, ip: str) -> List[DNSRecord]:
        """
        Perform a reverse DNS lookup.
        
        Args:
            ip: IP address to look up
        
        Returns:
            List of PTR records
        """
        records = []
        
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                records.append(DNSRecord(
                    name=ip,
                    record_type="PTR",
                    value=str(rdata).rstrip("."),
                    ttl=answers.rrset.ttl,
                ))
        except Exception:
            pass
        
        return records
    
    def _zone_transfer(self, domain: str, nameserver: str) -> ZoneTransferResult:
        """
        Attempt a DNS zone transfer (AXFR).
        
        Args:
            domain: Domain to transfer
            nameserver: Nameserver to query
        
        Returns:
            ZoneTransferResult with transfer status and records
        """
        result = ZoneTransferResult(
            domain=domain,
            nameserver=nameserver,
            success=False,
        )
        
        try:
            # Resolve nameserver to IP if needed
            ns_ip = nameserver
            if not self._is_ip(nameserver):
                try:
                    ns_answers = self.resolver.resolve(nameserver.rstrip("."), "A")
                    ns_ip = str(ns_answers[0])
                except Exception:
                    result.error_message = f"Could not resolve nameserver {nameserver}"
                    return result
            
            # Attempt zone transfer
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, domain, timeout=self.timeout)
            )
            
            result.success = True
            
            # Extract records from zone
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        record_name = str(name)
                        if record_name == "@":
                            record_name = domain
                        elif not record_name.endswith(domain):
                            record_name = f"{record_name}.{domain}"
                        
                        result.records.append(DNSRecord(
                            name=record_name,
                            record_type=dns.rdatatype.to_text(rdataset.rdtype),
                            value=str(rdata),
                            ttl=rdataset.ttl,
                        ))
        
        except dns.exception.FormError:
            result.error_message = "Zone transfer refused (FORMERR)"
        except dns.query.TransferError as e:
            result.error_message = f"Zone transfer failed: {e}"
        except dns.exception.Timeout:
            result.error_message = "Zone transfer timed out"
        except ConnectionRefusedError:
            result.error_message = "Connection refused"
        except Exception as e:
            result.error_message = str(e)
        
        return result
    
    def _detect_wildcard(self, domain: str) -> Tuple[bool, List[str]]:
        """
        Detect if domain has wildcard DNS configured.
        
        Args:
            domain: Domain to check
        
        Returns:
            Tuple of (wildcard_detected, wildcard_ips)
        """
        # Generate random subdomain
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        test_domain = f"{random_sub}.{domain}"
        
        wildcard_ips = []
        
        try:
            answers = self.resolver.resolve(test_domain, "A")
            for rdata in answers:
                wildcard_ips.append(str(rdata))
            return True, wildcard_ips
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return False, []
        except Exception:
            return False, []
    
    def _load_wordlist(self, wordlist: Optional[Path] = None) -> List[str]:
        """
        Load subdomain wordlist.
        
        Args:
            wordlist: Custom wordlist path, or None for built-in
        
        Returns:
            List of subdomain words
        """
        if wordlist and wordlist.exists():
            try:
                with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith("#")]
            except Exception:
                pass
        
        # Try built-in wordlists
        for size in ["small", "medium", "large"]:
            builtin = self.DATA_DIR / f"subdomains-{size}.txt"
            if builtin.exists():
                try:
                    with open(builtin, "r", encoding="utf-8", errors="ignore") as f:
                        return [line.strip() for line in f if line.strip() and not line.startswith("#")]
                except Exception:
                    continue
        
        # Fallback: minimal built-in list
        return self._get_default_subdomains()
    
    def _get_default_subdomains(self) -> List[str]:
        """Get minimal built-in subdomain list."""
        return [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "ns3", "ns4", "imap", "mx", "mx1", "mx2", "blog", "dev", "www2", "admin",
            "portal", "api", "test", "staging", "stage", "app", "apps", "web", "mobile",
            "m", "beta", "alpha", "vpn", "remote", "secure", "shop", "store", "cdn",
            "static", "assets", "img", "images", "media", "download", "downloads",
            "support", "help", "docs", "wiki", "forum", "forums", "community", "news",
            "old", "new", "demo", "sandbox", "backup", "bak", "git", "svn", "hg",
            "jenkins", "ci", "build", "deploy", "prod", "production", "uat", "qa",
            "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb",
            "redis", "elastic", "elasticsearch", "kibana", "grafana", "prometheus",
            "status", "monitor", "monitoring", "stats", "analytics", "track", "tracking",
            "email", "mx", "exchange", "autodiscover", "autoconfig", "calendar", "cal",
            "cloud", "aws", "azure", "gcp", "office", "office365", "o365", "sharepoint",
            "teams", "zoom", "meet", "video", "voice", "sip", "pbx", "voip", "asterisk",
            "proxy", "gateway", "firewall", "router", "switch", "dns", "dhcp", "ldap",
            "ad", "dc", "dc1", "dc2", "domain", "internal", "intranet", "extranet",
            "partner", "partners", "vendor", "vendors", "client", "clients", "customer",
            "hr", "payroll", "finance", "accounting", "legal", "sales", "marketing",
            "crm", "erp", "sap", "oracle", "jira", "confluence", "bitbucket", "github",
            "gitlab", "slack", "teams", "chat", "im", "messaging", "message", "sms",
        ]
    
    def _enumerate_subdomains(
        self,
        domain: str,
        words: List[str],
        wildcard_ips: List[str],
        callback: Optional[Callable[[str, Any], None]] = None,
    ) -> List[SubdomainResult]:
        """
        Enumerate subdomains using threading.
        
        Args:
            domain: Target domain
            words: List of subdomain words to try
            wildcard_ips: IPs that indicate wildcard response
            callback: Progress callback
        
        Returns:
            List of discovered subdomains
        """
        found = []
        total = len(words)
        completed = 0
        
        def check_subdomain(word: str) -> Optional[SubdomainResult]:
            """Check if subdomain exists."""
            if self._stop_event.is_set():
                return None
            
            full_domain = f"{word}.{domain}"
            
            try:
                answers = self.resolver.resolve(full_domain, "A")
                ips = [str(rdata) for rdata in answers]
                
                # Check for wildcard
                if wildcard_ips and all(ip in wildcard_ips for ip in ips):
                    return None
                
                # Check for CNAME
                cname = None
                try:
                    cname_answers = self.resolver.resolve(full_domain, "CNAME")
                    cname = str(cname_answers[0]).rstrip(".")
                except Exception:
                    pass
                
                return SubdomainResult(
                    subdomain=word,
                    full_domain=full_domain,
                    ip_addresses=ips,
                    cname=cname,
                    is_wildcard=False,
                )
            
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                return None
            except Exception:
                return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_subdomain, word): word for word in words}
            
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    break
                
                completed += 1
                result = future.result()
                
                if result:
                    with self._lock:
                        found.append(result)
                    if callback:
                        callback("subdomain", result.to_dict())
                
                if callback and completed % 100 == 0:
                    callback("progress", {"completed": completed, "total": total, "found": len(found)})
        
        return found
    
    def _is_ip(self, address: str) -> bool:
        """Check if string is an IP address."""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            pass
        
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True
        except socket.error:
            return False
    
    def lookup_all(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """
        Perform forward lookups for all common record types.
        
        Args:
            domain: Domain to query
        
        Returns:
            Dictionary of record type to list of records
        """
        result = {}
        for rtype in self.DEFAULT_RECORD_TYPES:
            records = self._lookup(domain, rtype)
            if records:
                result[rtype.value] = records
        return result
    
    def reverse_lookup(self, ip: str) -> Optional[str]:
        """
        Simple reverse lookup returning hostname.
        
        Args:
            ip: IP address
        
        Returns:
            Hostname or None
        """
        records = self._reverse_lookup(ip)
        if records:
            return records[0].value
        return None
    
    def get_nameservers(self, domain: str) -> List[str]:
        """
        Get authoritative nameservers for domain.
        
        Args:
            domain: Domain to query
        
        Returns:
            List of nameserver hostnames
        """
        records = self._lookup(domain, DNSRecordType.NS)
        return [r.value for r in records]
    
    def get_mail_servers(self, domain: str) -> List[Tuple[int, str]]:
        """
        Get mail servers for domain with priorities.
        
        Args:
            domain: Domain to query
        
        Returns:
            List of (priority, hostname) tuples
        """
        records = self._lookup(domain, DNSRecordType.MX)
        return [(r.priority or 0, r.value) for r in records]
    
    def check_zone_transfer(self, domain: str) -> List[ZoneTransferResult]:
        """
        Attempt zone transfers on all nameservers.
        
        Args:
            domain: Domain to transfer
        
        Returns:
            List of zone transfer results
        """
        results = []
        nameservers = self.get_nameservers(domain)
        
        for ns in nameservers:
            result = self._zone_transfer(domain, ns)
            results.append(result)
        
        return results


def format_dns_report(result: DNSEnumerationResult) -> str:
    """
    Format DNS enumeration result as human-readable report.
    
    Args:
        result: DNS enumeration result
    
    Returns:
        Formatted text report
    """
    lines = []
    lines.append("=" * 70)
    lines.append("DNS ENUMERATION REPORT")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"Domain: {result.domain}")
    lines.append(f"Duration: {result.duration:.2f} seconds")
    lines.append(f"Total Records: {result.total_records}")
    lines.append(f"Total Subdomains: {len(result.subdomains)}")
    lines.append(f"Unique IPs: {len(result.unique_ips)}")
    lines.append(f"Wildcard DNS: {'Yes' if result.has_wildcard else 'No'}")
    
    if result.has_wildcard:
        lines.append(f"Wildcard IPs: {', '.join(result.wildcard_ips)}")
    
    # DNS Records
    if result.records:
        lines.append("")
        lines.append("-" * 70)
        lines.append("DNS RECORDS")
        lines.append("-" * 70)
        
        for rtype, records in sorted(result.records.items()):
            lines.append(f"\n{rtype} Records ({len(records)}):")
            for record in records:
                if record.priority is not None:
                    lines.append(f"  {record.name} -> {record.priority} {record.value} (TTL: {record.ttl})")
                else:
                    lines.append(f"  {record.name} -> {record.value} (TTL: {record.ttl})")
    
    # Nameservers
    if result.nameservers:
        lines.append("")
        lines.append("-" * 70)
        lines.append("NAMESERVERS")
        lines.append("-" * 70)
        for ns in result.nameservers:
            lines.append(f"  {ns}")
    
    # Mail Servers
    if result.mail_servers:
        lines.append("")
        lines.append("-" * 70)
        lines.append("MAIL SERVERS")
        lines.append("-" * 70)
        for mx in result.mail_servers:
            lines.append(f"  {mx}")
    
    # Zone Transfers
    if result.zone_transfers:
        lines.append("")
        lines.append("-" * 70)
        lines.append("ZONE TRANSFER ATTEMPTS")
        lines.append("-" * 70)
        for zt in result.zone_transfers:
            status = "SUCCESS" if zt.success else "FAILED"
            lines.append(f"  {zt.nameserver}: {status}")
            if zt.error_message:
                lines.append(f"    Error: {zt.error_message}")
            if zt.success:
                lines.append(f"    Records obtained: {len(zt.records)}")
    
    # Subdomains
    if result.subdomains:
        lines.append("")
        lines.append("-" * 70)
        lines.append(f"DISCOVERED SUBDOMAINS ({len(result.subdomains)})")
        lines.append("-" * 70)
        for sub in sorted(result.subdomains, key=lambda x: x.subdomain):
            ips = ", ".join(sub.ip_addresses) if sub.ip_addresses else "N/A"
            cname_info = f" -> {sub.cname}" if sub.cname else ""
            lines.append(f"  {sub.full_domain}: {ips}{cname_info}")
    
    # Errors
    if result.errors:
        lines.append("")
        lines.append("-" * 70)
        lines.append("ERRORS")
        lines.append("-" * 70)
        for error in result.errors:
            lines.append(f"  {error}")
    
    lines.append("")
    lines.append("=" * 70)
    lines.append("Generated by SpectreScan - BitSpectreLabs")
    lines.append("=" * 70)
    
    return "\n".join(lines)
