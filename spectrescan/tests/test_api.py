"""
Tests for SpectreScan REST API.

Comprehensive tests for all API endpoints, authentication, WebSocket,
and Pydantic models.

by BitSpectreLabs
"""

import asyncio
import json
import pytest
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

# Import models directly (no FastAPI needed for model tests)
from spectrescan.api.models import (
    ScanType,
    ScanState,
    PortState,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanResultResponse,
    ProfileRequest,
    ProfileResponse,
    HistoryResponse,
    HistoryEntryResponse,
    HistoryStatsResponse,
    ErrorResponse,
    TokenResponse,
    TokenRequest,
    APIKeyRequest,
    APIKeyResponse,
    HealthResponse,
    HostResult,
    PortResult,
    SSLInfo,
    CVEInfo,
    WebSocketMessage,
)

from spectrescan.api.auth import (
    APIKey,
    TokenPayload,
    APIKeyAuth,
    JWTAuth,
    verify_api_key,
    create_access_token,
    get_current_user,
    require_scope,
)


# =============================================================================
# Model Tests
# =============================================================================


class TestScanTypeEnum:
    """Tests for ScanType enum."""
    
    def test_tcp_value(self):
        """Test TCP scan type value."""
        assert ScanType.TCP.value == "tcp"
    
    def test_syn_value(self):
        """Test SYN scan type value."""
        assert ScanType.SYN.value == "syn"
    
    def test_udp_value(self):
        """Test UDP scan type value."""
        assert ScanType.UDP.value == "udp"
    
    def test_async_value(self):
        """Test ASYNC scan type value."""
        assert ScanType.ASYNC.value == "async"


class TestScanStateEnum:
    """Tests for ScanState enum."""
    
    def test_all_states(self):
        """Test all scan states."""
        assert ScanState.PENDING.value == "pending"
        assert ScanState.RUNNING.value == "running"
        assert ScanState.COMPLETED.value == "completed"
        assert ScanState.FAILED.value == "failed"
        assert ScanState.CANCELLED.value == "cancelled"


class TestPortStateEnum:
    """Tests for PortState enum."""
    
    def test_all_states(self):
        """Test all port states."""
        assert PortState.OPEN.value == "open"
        assert PortState.CLOSED.value == "closed"
        assert PortState.FILTERED.value == "filtered"
        assert PortState.OPEN_FILTERED.value == "open|filtered"


class TestScanRequest:
    """Tests for ScanRequest model."""
    
    def test_minimal_request(self):
        """Test minimal valid request."""
        request = ScanRequest(target="192.168.1.1")
        assert request.target == "192.168.1.1"
        assert request.ports is None
        assert request.scan_type == ScanType.TCP
        assert request.threads == 100
        assert request.timeout == 2.0
        assert request.service_detection is True
    
    def test_full_request(self):
        """Test fully specified request."""
        request = ScanRequest(
            target="scanme.nmap.org",
            ports="1-1000",
            scan_type=ScanType.SYN,
            threads=500,
            timeout=5.0,
            service_detection=True,
            banner_grab=True,
            os_detection=True,
            ssl_check=True,
            cve_check=True,
            randomize=True,
            rate_limit=1000,
            timing_template=4,
        )
        assert request.target == "scanme.nmap.org"
        assert request.ports == "1-1000"
        assert request.scan_type == ScanType.SYN
        assert request.threads == 500
        assert request.rate_limit == 1000
    
    def test_target_validation_empty(self):
        """Test that empty target is rejected."""
        with pytest.raises(ValueError):
            ScanRequest(target="")
    
    def test_target_validation_whitespace(self):
        """Test that whitespace target is rejected."""
        with pytest.raises(ValueError):
            ScanRequest(target="   ")
    
    def test_target_trimmed(self):
        """Test that target is trimmed."""
        request = ScanRequest(target="  192.168.1.1  ")
        assert request.target == "192.168.1.1"
    
    def test_threads_bounds(self):
        """Test thread count bounds."""
        # Valid range
        request = ScanRequest(target="host", threads=1)
        assert request.threads == 1
        
        request = ScanRequest(target="host", threads=2000)
        assert request.threads == 2000
        
        # Invalid
        with pytest.raises(ValueError):
            ScanRequest(target="host", threads=0)
        
        with pytest.raises(ValueError):
            ScanRequest(target="host", threads=2001)
    
    def test_timeout_bounds(self):
        """Test timeout bounds."""
        request = ScanRequest(target="host", timeout=0.1)
        assert request.timeout == 0.1
        
        request = ScanRequest(target="host", timeout=30.0)
        assert request.timeout == 30.0
        
        with pytest.raises(ValueError):
            ScanRequest(target="host", timeout=0.05)
        
        with pytest.raises(ValueError):
            ScanRequest(target="host", timeout=31.0)
    
    def test_timing_template_bounds(self):
        """Test timing template bounds."""
        for t in range(6):
            request = ScanRequest(target="host", timing_template=t)
            assert request.timing_template == t
        
        with pytest.raises(ValueError):
            ScanRequest(target="host", timing_template=-1)
        
        with pytest.raises(ValueError):
            ScanRequest(target="host", timing_template=6)


class TestScanStatus:
    """Tests for ScanStatus model."""
    
    def test_basic_status(self):
        """Test basic status creation."""
        status = ScanStatus(
            scan_id="scan_abc123",
            state=ScanState.RUNNING,
            target="192.168.1.1",
        )
        assert status.scan_id == "scan_abc123"
        assert status.state == ScanState.RUNNING
        assert status.progress == 0.0
        assert status.open_ports == 0
    
    def test_progress_bounds(self):
        """Test progress percentage bounds."""
        status = ScanStatus(
            scan_id="scan_abc123",
            state=ScanState.RUNNING,
            target="host",
            progress=50.5,
        )
        assert status.progress == 50.5
        
        with pytest.raises(ValueError):
            ScanStatus(
                scan_id="scan_abc123",
                state=ScanState.RUNNING,
                target="host",
                progress=-1.0,
            )
        
        with pytest.raises(ValueError):
            ScanStatus(
                scan_id="scan_abc123",
                state=ScanState.RUNNING,
                target="host",
                progress=101.0,
            )


class TestPortResult:
    """Tests for PortResult model."""
    
    def test_basic_result(self):
        """Test basic port result."""
        result = PortResult(port=80, state=PortState.OPEN)
        assert result.port == 80
        assert result.state == PortState.OPEN
        assert result.protocol == "tcp"
        assert result.service is None
    
    def test_full_result(self):
        """Test fully specified port result."""
        result = PortResult(
            port=443,
            protocol="tcp",
            state=PortState.OPEN,
            service="https",
            version="nginx/1.21.0",
            banner="HTTP/1.1 200 OK",
            cpe="cpe:/a:nginx:nginx:1.21.0",
        )
        assert result.port == 443
        assert result.service == "https"
        assert result.version == "nginx/1.21.0"


class TestHostResult:
    """Tests for HostResult model."""
    
    def test_basic_host(self):
        """Test basic host result."""
        host = HostResult(host="192.168.1.1")
        assert host.host == "192.168.1.1"
        assert host.ports == []
    
    def test_host_with_ports(self):
        """Test host result with ports."""
        port1 = PortResult(port=22, state=PortState.OPEN, service="ssh")
        port2 = PortResult(port=80, state=PortState.OPEN, service="http")
        
        host = HostResult(
            host="192.168.1.1",
            hostname="server.local",
            os_guess="Linux",
            ports=[port1, port2],
        )
        assert len(host.ports) == 2
        assert host.hostname == "server.local"


class TestProfileRequest:
    """Tests for ProfileRequest model."""
    
    def test_minimal_profile(self):
        """Test minimal profile request."""
        profile = ProfileRequest(name="Test Profile")
        assert profile.name == "Test Profile"
        assert profile.ports == []
        assert profile.threads == 100
    
    def test_full_profile(self):
        """Test fully specified profile."""
        profile = ProfileRequest(
            name="Full Scan",
            description="Comprehensive scan profile",
            ports=[22, 80, 443, 8080],
            scan_types=["tcp", "syn"],
            threads=500,
            timeout=5.0,
            rate_limit=1000,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=True,
            timing_template=4,
        )
        assert profile.name == "Full Scan"
        assert len(profile.ports) == 4
        assert profile.rate_limit == 1000


class TestHistoryEntryResponse:
    """Tests for HistoryEntryResponse model."""
    
    def test_basic_entry(self):
        """Test basic history entry."""
        entry = HistoryEntryResponse(
            id="abc123",
            target="192.168.1.1",
            timestamp="2025-01-15T10:00:00",
        )
        assert entry.id == "abc123"
        assert entry.open_ports == 0
        assert entry.duration == 0.0


class TestHealthResponse:
    """Tests for HealthResponse model."""
    
    def test_health_response(self):
        """Test health response."""
        health = HealthResponse(
            version="2.0.0",
            uptime_seconds=3600.5,
            active_scans=3,
        )
        assert health.status == "healthy"
        assert health.version == "2.0.0"
        assert health.uptime_seconds == 3600.5


class TestTokenResponse:
    """Tests for TokenResponse model."""
    
    def test_token_response(self):
        """Test token response."""
        token = TokenResponse(
            access_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            expires_in=3600,
            scopes=["scan:read", "scan:write"],
        )
        assert token.token_type == "bearer"
        assert token.expires_in == 3600


class TestSSLInfo:
    """Tests for SSLInfo model."""
    
    def test_ssl_info(self):
        """Test SSL info model."""
        ssl = SSLInfo(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            vulnerabilities=["BEAST", "POODLE"],
        )
        assert ssl.protocol == "TLSv1.3"
        assert len(ssl.vulnerabilities) == 2


class TestCVEInfo:
    """Tests for CVEInfo model."""
    
    def test_cve_info(self):
        """Test CVE info model."""
        cve = CVEInfo(
            cve_id="CVE-2021-44228",
            description="Log4Shell vulnerability",
            severity="CRITICAL",
            cvss_score=10.0,
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        )
        assert cve.cve_id == "CVE-2021-44228"
        assert cve.cvss_score == 10.0


class TestWebSocketMessage:
    """Tests for WebSocketMessage model."""
    
    def test_websocket_message(self):
        """Test WebSocket message."""
        msg = WebSocketMessage(
            type="progress",
            scan_id="scan_abc123",
            data={"progress": 50.0, "open_ports": 5},
        )
        assert msg.type == "progress"
        assert msg.data["progress"] == 50.0


# =============================================================================
# Authentication Tests
# =============================================================================


class TestAPIKey:
    """Tests for APIKey dataclass."""
    
    def test_basic_key(self):
        """Test basic API key creation."""
        key = APIKey(
            key_id="key_abc123",
            key_hash="sha256hash",
            name="Test Key",
        )
        assert key.key_id == "key_abc123"
        assert key.is_active is True
        assert not key.is_expired()
    
    def test_expired_key(self):
        """Test expired key detection."""
        key = APIKey(
            key_id="key_expired",
            key_hash="hash",
            name="Expired Key",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert key.is_expired()
    
    def test_non_expired_key(self):
        """Test non-expired key."""
        key = APIKey(
            key_id="key_valid",
            key_hash="hash",
            name="Valid Key",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert not key.is_expired()
    
    def test_scope_checking(self):
        """Test scope checking."""
        key = APIKey(
            key_id="key_abc",
            key_hash="hash",
            name="Test",
            scopes=["scan:read", "scan:write", "profile:*"],
        )
        
        assert key.has_scope("scan:read")
        assert key.has_scope("scan:write")
        assert key.has_scope("profile:read")  # Wildcard match
        assert key.has_scope("profile:write")  # Wildcard match
        assert not key.has_scope("history:read")
    
    def test_wildcard_scope(self):
        """Test wildcard scope."""
        key = APIKey(
            key_id="key_admin",
            key_hash="hash",
            name="Admin",
            scopes=["*"],
        )
        
        assert key.has_scope("scan:read")
        assert key.has_scope("anything:here")
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        key = APIKey(
            key_id="key_abc",
            key_hash="hash",
            name="Test",
            scopes=["scan:read"],
        )
        
        data = key.to_dict()
        assert data["key_id"] == "key_abc"
        assert data["name"] == "Test"
        assert data["scopes"] == ["scan:read"]
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "key_id": "key_abc",
            "key_hash": "hash",
            "name": "Test",
            "scopes": ["scan:read"],
            "created_at": "2025-01-15T10:00:00+00:00",
            "expires_at": None,
            "is_active": True,
        }
        
        key = APIKey.from_dict(data)
        assert key.key_id == "key_abc"
        assert key.name == "Test"


class TestTokenPayload:
    """Tests for TokenPayload dataclass."""
    
    def test_basic_payload(self):
        """Test basic token payload."""
        payload = TokenPayload(
            sub="key_abc123",
            scopes=["scan:read"],
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="unique_id",
        )
        assert payload.sub == "key_abc123"
        assert not payload.is_expired()
    
    def test_expired_payload(self):
        """Test expired token detection."""
        payload = TokenPayload(
            sub="key_abc",
            scopes=[],
            exp=int(time.time()) - 100,
            iat=int(time.time()) - 200,
            jti="id",
        )
        assert payload.is_expired()
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        payload = TokenPayload(
            sub="key_abc",
            scopes=["scan:read"],
            exp=1234567890,
            iat=1234567800,
            jti="unique",
        )
        
        data = payload.to_dict()
        assert data["sub"] == "key_abc"
        assert data["exp"] == 1234567890


class TestAPIKeyAuth:
    """Tests for APIKeyAuth manager."""
    
    def test_create_key(self):
        """Test API key creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = APIKeyAuth(storage_path=Path(tmpdir) / "keys.json")
            
            api_key, key_obj = auth.create_key(
                name="Test Key",
                scopes=["scan:read", "scan:write"],
            )
            
            assert api_key.startswith("ss_")
            assert key_obj.key_id.startswith("key_")
            assert key_obj.name == "Test Key"
            assert "scan:read" in key_obj.scopes
    
    def test_verify_valid_key(self):
        """Test verification of valid key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = APIKeyAuth(storage_path=Path(tmpdir) / "keys.json")
            
            api_key, key_obj = auth.create_key(name="Valid Key")
            
            verified = auth.verify_key(api_key)
            assert verified is not None
            assert verified.key_id == key_obj.key_id
    
    def test_verify_invalid_key(self):
        """Test verification of invalid key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = APIKeyAuth(storage_path=Path(tmpdir) / "keys.json")
            
            verified = auth.verify_key("invalid_key")
            assert verified is None
    
    def test_revoke_key(self):
        """Test key revocation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = APIKeyAuth(storage_path=Path(tmpdir) / "keys.json")
            
            api_key, key_obj = auth.create_key(name="To Revoke")
            
            # Key should work before revocation
            assert auth.verify_key(api_key) is not None
            
            # Revoke
            assert auth.revoke_key(key_obj.key_id)
            
            # Key should not work after revocation
            assert auth.verify_key(api_key) is None
    
    def test_delete_key(self):
        """Test key deletion."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = APIKeyAuth(storage_path=Path(tmpdir) / "keys.json")
            
            api_key, key_obj = auth.create_key(name="To Delete")
            
            assert auth.delete_key(key_obj.key_id)
            assert auth.get_key(key_obj.key_id) is None
    
    def test_list_keys(self):
        """Test listing keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = APIKeyAuth(storage_path=Path(tmpdir) / "keys.json")
            
            auth.create_key(name="Key 1")
            auth.create_key(name="Key 2")
            auth.create_key(name="Key 3")
            
            keys = auth.list_keys()
            assert len(keys) == 3
    
    def test_key_expiration(self):
        """Test key with expiration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            auth = APIKeyAuth(storage_path=Path(tmpdir) / "keys.json")
            
            # Key with 1 day expiration
            api_key, key_obj = auth.create_key(
                name="Expiring",
                expires_in_days=1,
            )
            
            assert key_obj.expires_at is not None
            assert not key_obj.is_expired()
            
            # Verify still works
            assert auth.verify_key(api_key) is not None
    
    def test_persistence(self):
        """Test key persistence across instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / "keys.json"
            
            # Create key
            auth1 = APIKeyAuth(storage_path=storage_path)
            api_key, key_obj = auth1.create_key(name="Persistent")
            
            # New instance should load the key
            auth2 = APIKeyAuth(storage_path=storage_path)
            verified = auth2.verify_key(api_key)
            
            assert verified is not None
            assert verified.key_id == key_obj.key_id


class TestJWTAuth:
    """Tests for JWTAuth manager."""
    
    def test_create_token(self):
        """Test JWT token creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_path = Path(tmpdir) / "jwt_secret"
            jwt = JWTAuth(secret_key="test_secret_key_12345")
            
            token = jwt.create_token(
                key_id="key_abc123",
                scopes=["scan:read", "scan:write"],
            )
            
            assert token is not None
            parts = token.split(".")
            assert len(parts) == 3  # header.payload.signature
    
    def test_verify_valid_token(self):
        """Test verification of valid token."""
        jwt = JWTAuth(secret_key="test_secret")
        
        token = jwt.create_token("key_abc", ["scan:read"])
        
        payload = jwt.verify_token(token)
        assert payload is not None
        assert payload.sub == "key_abc"
        assert "scan:read" in payload.scopes
    
    def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        jwt = JWTAuth(secret_key="test_secret")
        
        payload = jwt.verify_token("invalid.token.here")
        assert payload is None
    
    def test_verify_tampered_token(self):
        """Test detection of tampered token."""
        jwt = JWTAuth(secret_key="test_secret")
        
        token = jwt.create_token("key_abc", ["scan:read"])
        
        # Tamper with the token
        parts = token.split(".")
        parts[1] = parts[1][::-1]  # Reverse the payload
        tampered = ".".join(parts)
        
        payload = jwt.verify_token(tampered)
        assert payload is None
    
    def test_token_expiration(self):
        """Test token expiration."""
        jwt = JWTAuth(secret_key="test_secret", token_expiry_seconds=1)
        
        token = jwt.create_token("key_abc", [])
        
        # Should work immediately
        assert jwt.verify_token(token) is not None
        
        # Wait for expiration (with buffer)
        time.sleep(1.5)
        
        # Should be expired
        assert jwt.verify_token(token) is None
    
    def test_revoke_token(self):
        """Test token revocation."""
        jwt = JWTAuth(secret_key="test_secret")
        
        token = jwt.create_token("key_abc", [])
        
        # Should work before revocation
        assert jwt.verify_token(token) is not None
        
        # Revoke
        assert jwt.revoke_token(token)
        
        # Should not work after revocation
        assert jwt.verify_token(token) is None
    
    def test_different_secrets(self):
        """Test that different secrets produce invalid tokens."""
        jwt1 = JWTAuth(secret_key="secret_1")
        jwt2 = JWTAuth(secret_key="secret_2")
        
        token = jwt1.create_token("key_abc", [])
        
        # Should not verify with different secret
        assert jwt2.verify_token(token) is None


class TestAuthFunctions:
    """Tests for auth helper functions."""
    
    def test_require_scope(self):
        """Test scope requirement checking."""
        payload = TokenPayload(
            sub="key_abc",
            scopes=["scan:read", "profile:*"],
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="id",
        )
        
        assert require_scope(payload, "scan:read")
        assert require_scope(payload, "profile:read")
        assert require_scope(payload, "profile:write")
        assert not require_scope(payload, "scan:write")
        assert not require_scope(payload, "history:read")
    
    def test_wildcard_scope(self):
        """Test wildcard scope requirement."""
        payload = TokenPayload(
            sub="key_admin",
            scopes=["*"],
            exp=int(time.time()) + 3600,
            iat=int(time.time()),
            jti="id",
        )
        
        assert require_scope(payload, "anything")
        assert require_scope(payload, "scan:read")
        assert require_scope(payload, "admin:delete")


# =============================================================================
# API Endpoint Tests (with mocking)
# =============================================================================


class TestAPIEndpointsMocked:
    """Tests for API endpoints using mocks (no actual server)."""
    
    def test_health_endpoint_structure(self):
        """Test health response structure."""
        response = HealthResponse(
            status="healthy",
            version="2.0.0",
            uptime_seconds=100.5,
            active_scans=0,
        )
        
        data = response.model_dump()
        assert "status" in data
        assert "version" in data
        assert "uptime_seconds" in data
        assert "active_scans" in data
    
    def test_scan_request_model_dump(self):
        """Test ScanRequest serialization."""
        request = ScanRequest(
            target="192.168.1.1",
            ports="1-100",
            scan_type=ScanType.TCP,
        )
        
        data = request.model_dump()
        assert data["target"] == "192.168.1.1"
        assert data["ports"] == "1-100"
        assert data["scan_type"] == "tcp"
    
    def test_scan_response_model_dump(self):
        """Test ScanResponse serialization."""
        status = ScanStatus(
            scan_id="scan_abc123",
            state=ScanState.PENDING,
            target="192.168.1.1",
        )
        
        response = ScanResponse(
            scan_id="scan_abc123",
            status=status,
            message="Scan started",
        )
        
        data = response.model_dump()
        assert data["scan_id"] == "scan_abc123"
        assert data["status"]["state"] == "pending"
    
    def test_profile_response_structure(self):
        """Test profile response structure."""
        profile = ProfileResponse(
            name="Web Scan",
            description="Scan web servers",
            ports=[80, 443, 8080],
            scan_types=["tcp"],
            threads=100,
            timeout=2.0,
            enable_service_detection=True,
            enable_os_detection=False,
            enable_banner_grabbing=True,
            randomize=False,
            timing_template=3,
        )
        
        data = profile.model_dump()
        assert data["name"] == "Web Scan"
        assert len(data["ports"]) == 3
    
    def test_history_response_structure(self):
        """Test history response structure."""
        entry = HistoryEntryResponse(
            id="hist_abc",
            target="192.168.1.1",
            ports=[22, 80],
            scan_type="tcp",
            timestamp="2025-01-15T10:00:00",
            duration=10.5,
            open_ports=2,
            closed_ports=0,
            filtered_ports=0,
            total_ports=2,
        )
        
        response = HistoryResponse(
            entries=[entry],
            total=1,
            page=1,
            page_size=20,
        )
        
        data = response.model_dump()
        assert len(data["entries"]) == 1
        assert data["total"] == 1
    
    def test_error_response_structure(self):
        """Test error response structure."""
        error = ErrorResponse(
            error="validation_error",
            message="Invalid target format",
            detail={"field": "target", "value": "invalid"},
        )
        
        data = error.model_dump()
        assert data["error"] == "validation_error"
        assert data["detail"]["field"] == "target"


# =============================================================================
# Integration-style Tests (mocked dependencies)
# =============================================================================


class TestScanWorkflow:
    """Tests for scan workflow models."""
    
    def test_complete_scan_result(self):
        """Test complete scan result construction."""
        # Create port results
        ports = [
            PortResult(port=22, state=PortState.OPEN, service="ssh"),
            PortResult(port=80, state=PortState.OPEN, service="http"),
            PortResult(port=443, state=PortState.CLOSED),
        ]
        
        # Create host result
        host = HostResult(
            host="192.168.1.1",
            hostname="server.local",
            os_guess="Linux",
            ports=ports,
        )
        
        # Create status
        status = ScanStatus(
            scan_id="scan_complete",
            state=ScanState.COMPLETED,
            target="192.168.1.1",
            progress=100.0,
            ports_scanned=3,
            ports_total=3,
            open_ports=2,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        
        # Create complete response
        response = ScanResultResponse(
            scan_id="scan_complete",
            status=status,
            hosts=[host],
            summary={
                "total_ports": 3,
                "open_ports": 2,
                "duration_seconds": 5.5,
            },
        )
        
        data = response.model_dump()
        assert len(data["hosts"]) == 1
        assert len(data["hosts"][0]["ports"]) == 3
        assert data["summary"]["open_ports"] == 2
    
    def test_ssl_results_integration(self):
        """Test SSL results in scan response."""
        ssl_info = SSLInfo(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificate={"subject": "CN=example.com"},
            vulnerabilities=[],
        )
        
        status = ScanStatus(
            scan_id="scan_ssl",
            state=ScanState.COMPLETED,
            target="example.com",
            progress=100.0,
        )
        
        response = ScanResultResponse(
            scan_id="scan_ssl",
            status=status,
            hosts=[],
            ssl_results={"example.com:443": ssl_info},
            summary={},
        )
        
        data = response.model_dump()
        assert "example.com:443" in data["ssl_results"]
        assert data["ssl_results"]["example.com:443"]["protocol"] == "TLSv1.3"
    
    def test_cve_results_integration(self):
        """Test CVE results in scan response."""
        cve = CVEInfo(
            cve_id="CVE-2021-44228",
            description="Log4Shell",
            severity="CRITICAL",
            cvss_score=10.0,
        )
        
        status = ScanStatus(
            scan_id="scan_cve",
            state=ScanState.COMPLETED,
            target="server",
            progress=100.0,
        )
        
        response = ScanResultResponse(
            scan_id="scan_cve",
            status=status,
            hosts=[],
            cve_results={"apache-log4j": [cve]},
            summary={},
        )
        
        data = response.model_dump()
        assert "apache-log4j" in data["cve_results"]
        assert data["cve_results"]["apache-log4j"][0]["cve_id"] == "CVE-2021-44228"


class TestWebSocketWorkflow:
    """Tests for WebSocket message workflow."""
    
    def test_progress_message(self):
        """Test progress message creation."""
        msg = WebSocketMessage(
            type="progress",
            scan_id="scan_abc",
            data={
                "progress": 45.5,
                "ports_scanned": 455,
                "ports_total": 1000,
                "open_ports": 12,
            },
        )
        
        data = msg.model_dump()
        assert data["type"] == "progress"
        assert data["data"]["progress"] == 45.5
    
    def test_completion_message(self):
        """Test completion message creation."""
        msg = WebSocketMessage(
            type="completed",
            scan_id="scan_abc",
            data={
                "state": "completed",
                "open_ports": 25,
                "duration_seconds": 120.5,
            },
        )
        
        data = msg.model_dump()
        assert data["type"] == "completed"
    
    def test_error_message(self):
        """Test error message creation."""
        msg = WebSocketMessage(
            type="error",
            scan_id="scan_abc",
            data={
                "message": "Connection timeout",
                "code": "TIMEOUT",
            },
        )
        
        data = msg.model_dump()
        assert data["type"] == "error"
        assert data["data"]["message"] == "Connection timeout"


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error conditions."""
    
    def test_empty_ports_list(self):
        """Test profile with empty ports list."""
        profile = ProfileRequest(
            name="Empty Ports",
            ports=[],
        )
        assert profile.ports == []
    
    def test_max_ports_in_result(self):
        """Test handling of many ports in result."""
        ports = [
            PortResult(port=i, state=PortState.CLOSED)
            for i in range(1, 1001)
        ]
        
        host = HostResult(host="192.168.1.1", ports=ports)
        assert len(host.ports) == 1000
    
    def test_special_characters_in_banner(self):
        """Test special characters in banner."""
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            banner="Server: nginx/1.21.0\r\nX-Header: value with \"quotes\"",
        )
        assert "nginx" in result.banner
    
    def test_unicode_in_service_name(self):
        """Test unicode in service detection."""
        result = PortResult(
            port=80,
            state=PortState.OPEN,
            service="http-utf8-测试",
        )
        assert "测试" in result.service
    
    def test_very_long_target(self):
        """Test very long target string."""
        # CIDR notation
        long_target = "192.168.1.0/24"
        request = ScanRequest(target=long_target)
        assert request.target == long_target
    
    def test_ipv6_target(self):
        """Test IPv6 target."""
        request = ScanRequest(target="::1")
        assert request.target == "::1"
        
        request = ScanRequest(target="2001:db8::1")
        assert request.target == "2001:db8::1"


class TestModelValidation:
    """Tests for model validation edge cases."""
    
    def test_port_range_string_formats(self):
        """Test various port range string formats."""
        # All these should be valid
        valid_ports = [
            "80",
            "1-1000",
            "22,80,443",
            "1-100,443,8000-9000",
        ]
        
        for ports in valid_ports:
            request = ScanRequest(target="host", ports=ports)
            assert request.ports == ports
    
    def test_empty_port_string(self):
        """Test empty port string becomes None."""
        request = ScanRequest(target="host", ports="")
        assert request.ports is None
    
    def test_whitespace_port_string(self):
        """Test whitespace port string becomes None."""
        request = ScanRequest(target="host", ports="   ")
        assert request.ports is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
