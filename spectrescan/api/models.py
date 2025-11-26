"""
Pydantic models for SpectreScan REST API.

Defines request and response models for all API endpoints.

by BitSpectreLabs
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field, field_validator


class ScanType(str, Enum):
    """Scan type enumeration."""
    
    TCP = "tcp"
    SYN = "syn"
    UDP = "udp"
    ASYNC = "async"


class ScanState(str, Enum):
    """Scan execution state."""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PortState(str, Enum):
    """Port state enumeration."""
    
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


# =============================================================================
# Request Models
# =============================================================================


class ScanRequest(BaseModel):
    """Request model for initiating a scan."""
    
    target: str = Field(
        ...,
        description="Target to scan (IP, hostname, CIDR, or range)",
        examples=["192.168.1.1", "scanme.nmap.org", "192.168.1.0/24"]
    )
    ports: Optional[str] = Field(
        default=None,
        description="Ports to scan (e.g., '1-1000', '22,80,443')",
        examples=["1-1000", "22,80,443,8080"]
    )
    scan_type: ScanType = Field(
        default=ScanType.TCP,
        description="Type of scan to perform"
    )
    threads: int = Field(
        default=100,
        ge=1,
        le=2000,
        description="Number of concurrent threads/connections"
    )
    timeout: float = Field(
        default=2.0,
        ge=0.1,
        le=30.0,
        description="Connection timeout in seconds"
    )
    service_detection: bool = Field(
        default=True,
        description="Enable service/version detection"
    )
    banner_grab: bool = Field(
        default=False,
        description="Enable banner grabbing"
    )
    os_detection: bool = Field(
        default=False,
        description="Enable OS detection"
    )
    ssl_check: bool = Field(
        default=False,
        description="Enable SSL/TLS analysis"
    )
    cve_check: bool = Field(
        default=False,
        description="Enable CVE vulnerability lookup"
    )
    randomize: bool = Field(
        default=False,
        description="Randomize scan order"
    )
    rate_limit: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000,
        description="Rate limit in packets per second"
    )
    timing_template: int = Field(
        default=3,
        ge=0,
        le=5,
        description="Timing template (0=paranoid, 5=insane)"
    )
    
    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        """Validate target is not empty."""
        if not v or not v.strip():
            raise ValueError("Target cannot be empty")
        return v.strip()
    
    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: Optional[str]) -> Optional[str]:
        """Validate ports specification."""
        if v is not None:
            v = v.strip()
            if not v:
                return None
        return v


class ProfileRequest(BaseModel):
    """Request model for creating/updating a profile."""
    
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Profile name"
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Profile description"
    )
    ports: List[int] = Field(
        default_factory=list,
        description="List of ports to scan"
    )
    scan_types: List[str] = Field(
        default_factory=lambda: ["tcp"],
        description="Scan types to use"
    )
    threads: int = Field(
        default=100,
        ge=1,
        le=2000,
        description="Number of threads"
    )
    timeout: float = Field(
        default=2.0,
        ge=0.1,
        le=30.0,
        description="Connection timeout"
    )
    rate_limit: Optional[int] = Field(
        default=None,
        description="Rate limit"
    )
    enable_service_detection: bool = Field(
        default=True,
        description="Enable service detection"
    )
    enable_os_detection: bool = Field(
        default=False,
        description="Enable OS detection"
    )
    enable_banner_grabbing: bool = Field(
        default=False,
        description="Enable banner grabbing"
    )
    randomize: bool = Field(
        default=False,
        description="Randomize scan order"
    )
    timing_template: int = Field(
        default=3,
        ge=0,
        le=5,
        description="Timing template"
    )


class APIKeyRequest(BaseModel):
    """Request model for API key operations."""
    
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="API key name/identifier"
    )
    scopes: List[str] = Field(
        default_factory=lambda: ["scan:read", "scan:write"],
        description="Permission scopes for the API key"
    )
    expires_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
        description="Days until expiration (None = no expiration)"
    )


class TokenRequest(BaseModel):
    """Request model for JWT token generation."""
    
    api_key: str = Field(
        ...,
        description="API key to exchange for JWT token"
    )


# =============================================================================
# Response Models
# =============================================================================


class PortResult(BaseModel):
    """Individual port scan result."""
    
    port: int = Field(..., description="Port number")
    protocol: str = Field(default="tcp", description="Protocol")
    state: PortState = Field(..., description="Port state")
    service: Optional[str] = Field(default=None, description="Service name")
    version: Optional[str] = Field(default=None, description="Service version")
    banner: Optional[str] = Field(default=None, description="Service banner")
    cpe: Optional[str] = Field(default=None, description="CPE identifier")


class HostResult(BaseModel):
    """Host scan result."""
    
    host: str = Field(..., description="Host IP or hostname")
    hostname: Optional[str] = Field(default=None, description="Resolved hostname")
    ip: Optional[str] = Field(default=None, description="Resolved IP address")
    os_guess: Optional[str] = Field(default=None, description="OS guess")
    ttl: Optional[int] = Field(default=None, description="TTL value")
    latency_ms: Optional[float] = Field(default=None, description="Latency in ms")
    ports: List[PortResult] = Field(default_factory=list, description="Port results")


class SSLInfo(BaseModel):
    """SSL/TLS analysis information."""
    
    protocol: Optional[str] = Field(default=None, description="SSL/TLS protocol")
    cipher: Optional[str] = Field(default=None, description="Cipher suite")
    certificate: Optional[Dict[str, Any]] = Field(
        default=None, description="Certificate details"
    )
    vulnerabilities: List[str] = Field(
        default_factory=list, description="SSL vulnerabilities"
    )


class CVEInfo(BaseModel):
    """CVE vulnerability information."""
    
    cve_id: str = Field(..., description="CVE identifier")
    description: Optional[str] = Field(default=None, description="CVE description")
    severity: Optional[str] = Field(default=None, description="Severity level")
    cvss_score: Optional[float] = Field(default=None, description="CVSS score")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class ScanStatus(BaseModel):
    """Scan status response."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    state: ScanState = Field(..., description="Current scan state")
    target: str = Field(..., description="Scan target")
    progress: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Progress percentage"
    )
    ports_scanned: int = Field(default=0, description="Number of ports scanned")
    ports_total: int = Field(default=0, description="Total ports to scan")
    open_ports: int = Field(default=0, description="Number of open ports found")
    started_at: Optional[datetime] = Field(
        default=None, description="Scan start time"
    )
    completed_at: Optional[datetime] = Field(
        default=None, description="Scan completion time"
    )
    error: Optional[str] = Field(default=None, description="Error message if failed")


class ScanResponse(BaseModel):
    """Response model for scan initiation."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Initial scan status")
    message: str = Field(
        default="Scan initiated successfully",
        description="Status message"
    )


class ScanResultResponse(BaseModel):
    """Complete scan results response."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Final scan status")
    hosts: List[HostResult] = Field(
        default_factory=list, description="Host scan results"
    )
    ssl_results: Optional[Dict[str, SSLInfo]] = Field(
        default=None, description="SSL analysis results per host:port"
    )
    cve_results: Optional[Dict[str, List[CVEInfo]]] = Field(
        default=None, description="CVE results per service"
    )
    summary: Dict[str, Any] = Field(
        default_factory=dict, description="Scan summary statistics"
    )


class ProfileResponse(BaseModel):
    """Profile response model."""
    
    name: str = Field(..., description="Profile name")
    description: Optional[str] = Field(default=None, description="Profile description")
    ports: List[int] = Field(default_factory=list, description="Port list")
    scan_types: List[str] = Field(default_factory=list, description="Scan types")
    threads: int = Field(default=100, description="Thread count")
    timeout: float = Field(default=2.0, description="Timeout")
    rate_limit: Optional[int] = Field(default=None, description="Rate limit")
    enable_service_detection: bool = Field(default=True)
    enable_os_detection: bool = Field(default=False)
    enable_banner_grabbing: bool = Field(default=False)
    randomize: bool = Field(default=False)
    timing_template: int = Field(default=3)
    created_at: Optional[str] = Field(default=None, description="Creation timestamp")
    modified_at: Optional[str] = Field(default=None, description="Modification timestamp")


class HistoryEntryResponse(BaseModel):
    """History entry response model."""
    
    id: str = Field(..., description="Scan history ID")
    target: str = Field(..., description="Scan target")
    ports: List[int] = Field(default_factory=list, description="Scanned ports")
    scan_type: str = Field(default="tcp", description="Scan type")
    timestamp: str = Field(..., description="Scan timestamp")
    duration: float = Field(default=0.0, description="Scan duration in seconds")
    open_ports: int = Field(default=0, description="Open ports found")
    closed_ports: int = Field(default=0, description="Closed ports found")
    filtered_ports: int = Field(default=0, description="Filtered ports found")
    total_ports: int = Field(default=0, description="Total ports scanned")


class HistoryResponse(BaseModel):
    """History list response model."""
    
    entries: List[HistoryEntryResponse] = Field(
        default_factory=list, description="History entries"
    )
    total: int = Field(default=0, description="Total number of entries")
    page: int = Field(default=1, description="Current page")
    page_size: int = Field(default=20, description="Page size")


class HistoryStatsResponse(BaseModel):
    """History statistics response model."""
    
    total_scans: int = Field(default=0, description="Total scans performed")
    total_ports_scanned: int = Field(default=0, description="Total ports scanned")
    total_open_ports: int = Field(default=0, description="Total open ports found")
    total_scan_time: float = Field(default=0.0, description="Total scan time")
    scan_type_distribution: Dict[str, int] = Field(
        default_factory=dict, description="Scans per type"
    )
    most_scanned_target: Optional[str] = Field(
        default=None, description="Most frequently scanned target"
    )


class TokenResponse(BaseModel):
    """JWT token response model."""
    
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")
    scopes: List[str] = Field(default_factory=list, description="Token scopes")


class APIKeyResponse(BaseModel):
    """API key response model."""
    
    key_id: str = Field(..., description="API key identifier")
    api_key: str = Field(..., description="API key (shown only once)")
    name: str = Field(..., description="API key name")
    scopes: List[str] = Field(default_factory=list, description="Permission scopes")
    created_at: str = Field(..., description="Creation timestamp")
    expires_at: Optional[str] = Field(default=None, description="Expiration timestamp")


class ErrorResponse(BaseModel):
    """Error response model."""
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    detail: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional error details"
    )
    request_id: Optional[str] = Field(
        default=None, description="Request ID for tracking"
    )


class HealthResponse(BaseModel):
    """Health check response model."""
    
    status: str = Field(default="healthy", description="Health status")
    version: str = Field(..., description="SpectreScan version")
    uptime_seconds: float = Field(..., description="Server uptime in seconds")
    active_scans: int = Field(default=0, description="Currently running scans")


class WebSocketMessage(BaseModel):
    """WebSocket message model."""
    
    type: str = Field(..., description="Message type")
    scan_id: str = Field(..., description="Scan identifier")
    data: Dict[str, Any] = Field(default_factory=dict, description="Message data")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Message timestamp"
    )
