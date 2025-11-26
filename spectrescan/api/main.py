"""
FastAPI main application for SpectreScan REST API.

Provides HTTP endpoints for scan operations, profile management,
history access, and WebSocket support for real-time updates.

by BitSpectreLabs
"""

import asyncio
import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from fastapi import (
        FastAPI,
        HTTPException,
        Depends,
        Header,
        Query,
        WebSocket,
        WebSocketDisconnect,
        status,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from spectrescan.api.auth import (
    get_api_key_auth,
    get_jwt_auth,
    verify_api_key,
    get_current_user,
    require_scope,
    init_auth,
    TokenPayload,
    APIKey,
)
from spectrescan.api.models import (
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanState,
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
    PortState,
    WebSocketMessage,
)


# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# Global State
# =============================================================================

# Active scans storage
_active_scans: Dict[str, Dict[str, Any]] = {}

# WebSocket connections per scan
_websocket_connections: Dict[str, list] = {}

# Server start time
_server_start_time: float = 0.0


def get_active_scans() -> Dict[str, Dict[str, Any]]:
    """Get the active scans dictionary."""
    return _active_scans


def get_websocket_connections() -> Dict[str, list]:
    """Get WebSocket connections dictionary."""
    return _websocket_connections


# =============================================================================
# Authentication Dependencies
# =============================================================================


async def get_api_key_header(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None),
) -> TokenPayload:
    """
    Validate API key or JWT token from headers.
    
    Supports:
    - X-API-Key header with API key
    - Authorization header with "Bearer <token>"
    """
    # Try JWT token first
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        payload = get_current_user(token)
        if payload:
            return payload
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Try API key
    if x_api_key:
        key = verify_api_key(x_api_key)
        if key:
            # Create a pseudo-payload from API key
            return TokenPayload(
                sub=key.key_id,
                scopes=key.scopes,
                exp=int(time.time()) + 3600,
                iat=int(time.time()),
                jti=str(uuid.uuid4()),
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication. Provide X-API-Key header or Authorization: Bearer <token>",
    )


def require_scan_read(payload: TokenPayload = Depends(get_api_key_header)) -> TokenPayload:
    """Require scan:read scope."""
    if not require_scope(payload, "scan:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required scope: scan:read",
        )
    return payload


def require_scan_write(payload: TokenPayload = Depends(get_api_key_header)) -> TokenPayload:
    """Require scan:write scope."""
    if not require_scope(payload, "scan:write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required scope: scan:write",
        )
    return payload


def require_profile_read(payload: TokenPayload = Depends(get_api_key_header)) -> TokenPayload:
    """Require profile:read scope."""
    if not require_scope(payload, "profile:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required scope: profile:read",
        )
    return payload


def require_profile_write(payload: TokenPayload = Depends(get_api_key_header)) -> TokenPayload:
    """Require profile:write scope."""
    if not require_scope(payload, "profile:write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required scope: profile:write",
        )
    return payload


def require_history_read(payload: TokenPayload = Depends(get_api_key_header)) -> TokenPayload:
    """Require history:read scope."""
    if not require_scope(payload, "history:read"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required scope: history:read",
        )
    return payload


def require_history_write(payload: TokenPayload = Depends(get_api_key_header)) -> TokenPayload:
    """Require history:write scope."""
    if not require_scope(payload, "history:write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Required scope: history:write",
        )
    return payload


# =============================================================================
# Application Factory
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global _server_start_time
    _server_start_time = time.time()
    
    # Initialize auth
    init_auth()
    
    logger.info("SpectreScan API server starting...")
    yield
    
    # Cleanup
    logger.info("SpectreScan API server shutting down...")
    
    # Cancel any running scans
    for scan_id, scan_data in _active_scans.items():
        if scan_data.get("task"):
            scan_data["task"].cancel()


def create_app(
    title: str = "SpectreScan API",
    debug: bool = False,
    cors_origins: Optional[list] = None,
) -> "FastAPI":
    """
    Create and configure the FastAPI application.
    
    Args:
        title: API title
        debug: Enable debug mode
        cors_origins: List of allowed CORS origins
        
    Returns:
        Configured FastAPI application
    """
    if not FASTAPI_AVAILABLE:
        raise ImportError(
            "FastAPI is required for the REST API. Install with: pip install fastapi uvicorn"
        )
    
    from spectrescan import __version__
    
    app = FastAPI(
        title=title,
        description="Professional-grade port scanner REST API by BitSpectreLabs",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )
    
    # Add CORS middleware
    if cors_origins is None:
        cors_origins = ["*"]
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register routes
    _register_routes(app)
    
    return app


def _register_routes(app: "FastAPI") -> None:
    """Register all API routes."""
    from spectrescan import __version__
    
    # ==========================================================================
    # Health & Info Endpoints
    # ==========================================================================
    
    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["Health"],
        summary="Health check endpoint",
    )
    async def health_check():
        """Check API server health status."""
        return HealthResponse(
            status="healthy",
            version=__version__,
            uptime_seconds=time.time() - _server_start_time,
            active_scans=len([s for s in _active_scans.values() if s.get("state") == ScanState.RUNNING]),
        )
    
    @app.get(
        "/",
        tags=["Health"],
        summary="API root",
    )
    async def root():
        """API root endpoint with basic info."""
        return {
            "name": "SpectreScan API",
            "version": __version__,
            "vendor": "BitSpectreLabs",
            "docs": "/docs",
            "health": "/health",
        }
    
    # ==========================================================================
    # Authentication Endpoints
    # ==========================================================================
    
    @app.post(
        "/auth/token",
        response_model=TokenResponse,
        tags=["Authentication"],
        summary="Get JWT token from API key",
    )
    async def get_token(request: TokenRequest):
        """Exchange API key for JWT access token."""
        from spectrescan.api.auth import create_access_token
        
        result = create_access_token(request.api_key)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        
        token, expires_in = result
        key = verify_api_key(request.api_key)
        
        return TokenResponse(
            access_token=token,
            token_type="bearer",
            expires_in=expires_in,
            scopes=key.scopes if key else [],
        )
    
    @app.post(
        "/auth/keys",
        response_model=APIKeyResponse,
        tags=["Authentication"],
        summary="Create new API key",
        description="Create a new API key. The key is only shown once!",
    )
    async def create_api_key(
        request: APIKeyRequest,
        payload: TokenPayload = Depends(get_api_key_header),
    ):
        """Create a new API key."""
        # Only allow if user has admin scope or creating keys with subset of their scopes
        auth = get_api_key_auth()
        
        api_key, key_obj = auth.create_key(
            name=request.name,
            scopes=request.scopes,
            expires_in_days=request.expires_in_days,
        )
        
        return APIKeyResponse(
            key_id=key_obj.key_id,
            api_key=api_key,  # Only shown once!
            name=key_obj.name,
            scopes=key_obj.scopes,
            created_at=key_obj.created_at.isoformat(),
            expires_at=key_obj.expires_at.isoformat() if key_obj.expires_at else None,
        )
    
    @app.get(
        "/auth/keys",
        tags=["Authentication"],
        summary="List API keys",
    )
    async def list_api_keys(
        payload: TokenPayload = Depends(get_api_key_header),
    ):
        """List all API keys (without exposing actual keys)."""
        auth = get_api_key_auth()
        keys = auth.list_keys()
        
        return {
            "keys": [
                {
                    "key_id": k.key_id,
                    "name": k.name,
                    "scopes": k.scopes,
                    "is_active": k.is_active,
                    "created_at": k.created_at.isoformat(),
                    "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                }
                for k in keys
            ]
        }
    
    @app.delete(
        "/auth/keys/{key_id}",
        tags=["Authentication"],
        summary="Delete API key",
    )
    async def delete_api_key(
        key_id: str,
        payload: TokenPayload = Depends(get_api_key_header),
    ):
        """Delete an API key."""
        auth = get_api_key_auth()
        
        if not auth.delete_key(key_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"API key not found: {key_id}",
            )
        
        return {"message": f"API key {key_id} deleted"}
    
    # ==========================================================================
    # Scan Endpoints
    # ==========================================================================
    
    @app.post(
        "/scan",
        response_model=ScanResponse,
        tags=["Scans"],
        summary="Initiate a new scan",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_scan(
        request: ScanRequest,
        payload: TokenPayload = Depends(require_scan_write),
    ):
        """
        Start a new port scan.
        
        The scan runs asynchronously. Use GET /scan/{scan_id} to check status
        and GET /scan/{scan_id}/results to retrieve results.
        """
        scan_id = f"scan_{uuid.uuid4().hex[:12]}"
        
        # Create initial status
        scan_status = ScanStatus(
            scan_id=scan_id,
            state=ScanState.PENDING,
            target=request.target,
            progress=0.0,
            ports_scanned=0,
            ports_total=0,
            open_ports=0,
            started_at=datetime.now(timezone.utc),
        )
        
        # Store scan data
        _active_scans[scan_id] = {
            "status": scan_status,
            "request": request,
            "results": [],
            "state": ScanState.PENDING,
            "task": None,
        }
        
        # Start scan in background
        task = asyncio.create_task(_run_scan(scan_id, request))
        _active_scans[scan_id]["task"] = task
        
        return ScanResponse(
            scan_id=scan_id,
            status=scan_status,
            message="Scan initiated successfully",
        )
    
    @app.get(
        "/scan/{scan_id}",
        response_model=ScanStatus,
        tags=["Scans"],
        summary="Get scan status",
    )
    async def get_scan_status(
        scan_id: str,
        payload: TokenPayload = Depends(require_scan_read),
    ):
        """Get the current status of a scan."""
        if scan_id not in _active_scans:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan not found: {scan_id}",
            )
        
        return _active_scans[scan_id]["status"]
    
    @app.get(
        "/scan/{scan_id}/results",
        response_model=ScanResultResponse,
        tags=["Scans"],
        summary="Get scan results",
    )
    async def get_scan_results(
        scan_id: str,
        payload: TokenPayload = Depends(require_scan_read),
    ):
        """Get the full results of a completed scan."""
        if scan_id not in _active_scans:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan not found: {scan_id}",
            )
        
        scan_data = _active_scans[scan_id]
        scan_status = scan_data["status"]
        
        # Build host results
        hosts = _build_host_results(scan_data.get("results", []))
        
        # Build summary
        summary = {
            "total_ports": scan_status.ports_total,
            "open_ports": scan_status.open_ports,
            "closed_ports": scan_data.get("closed_ports", 0),
            "filtered_ports": scan_data.get("filtered_ports", 0),
            "duration_seconds": (
                (scan_status.completed_at - scan_status.started_at).total_seconds()
                if scan_status.completed_at and scan_status.started_at
                else 0
            ),
        }
        
        return ScanResultResponse(
            scan_id=scan_id,
            status=scan_status,
            hosts=hosts,
            ssl_results=scan_data.get("ssl_results"),
            cve_results=scan_data.get("cve_results"),
            summary=summary,
        )
    
    @app.delete(
        "/scan/{scan_id}",
        tags=["Scans"],
        summary="Cancel or delete a scan",
    )
    async def delete_scan(
        scan_id: str,
        payload: TokenPayload = Depends(require_scan_write),
    ):
        """Cancel a running scan or delete a completed scan."""
        if scan_id not in _active_scans:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan not found: {scan_id}",
            )
        
        scan_data = _active_scans[scan_id]
        
        # Cancel if running
        if scan_data.get("task") and not scan_data["task"].done():
            scan_data["task"].cancel()
            scan_data["status"].state = ScanState.CANCELLED
            scan_data["state"] = ScanState.CANCELLED
        
        # Remove from active scans
        del _active_scans[scan_id]
        
        return {"message": f"Scan {scan_id} deleted"}
    
    @app.get(
        "/scans",
        tags=["Scans"],
        summary="List all scans",
    )
    async def list_scans(
        state: Optional[ScanState] = Query(default=None, description="Filter by state"),
        limit: int = Query(default=50, ge=1, le=100, description="Maximum results"),
        payload: TokenPayload = Depends(require_scan_read),
    ):
        """List all scans with optional filtering."""
        scans = []
        
        for scan_id, scan_data in _active_scans.items():
            if state and scan_data["status"].state != state:
                continue
            scans.append(scan_data["status"])
            if len(scans) >= limit:
                break
        
        return {"scans": scans, "total": len(scans)}
    
    # ==========================================================================
    # Profile Endpoints
    # ==========================================================================
    
    @app.get(
        "/profiles",
        tags=["Profiles"],
        summary="List all profiles",
    )
    async def list_profiles(
        payload: TokenPayload = Depends(require_profile_read),
    ):
        """List all saved scan profiles."""
        from spectrescan.core.profiles import ProfileManager
        
        manager = ProfileManager()
        profile_names = manager.list_profiles()
        
        profiles = []
        for name in profile_names:
            try:
                profile = manager.load_profile(name)
                profiles.append(ProfileResponse(
                    name=profile.name,
                    description=profile.description,
                    ports=profile.ports,
                    scan_types=profile.scan_types,
                    threads=profile.threads,
                    timeout=profile.timeout,
                    rate_limit=profile.rate_limit,
                    enable_service_detection=profile.enable_service_detection,
                    enable_os_detection=profile.enable_os_detection,
                    enable_banner_grabbing=profile.enable_banner_grabbing,
                    randomize=profile.randomize,
                    timing_template=profile.timing_template,
                    created_at=profile.created_at,
                    modified_at=profile.modified_at,
                ))
            except Exception:
                continue
        
        return {"profiles": profiles, "total": len(profiles)}
    
    @app.get(
        "/profiles/{name}",
        response_model=ProfileResponse,
        tags=["Profiles"],
        summary="Get a profile",
    )
    async def get_profile(
        name: str,
        payload: TokenPayload = Depends(require_profile_read),
    ):
        """Get a specific scan profile by name."""
        from spectrescan.core.profiles import ProfileManager
        
        manager = ProfileManager()
        
        if not manager.profile_exists(name):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Profile not found: {name}",
            )
        
        profile = manager.load_profile(name)
        
        return ProfileResponse(
            name=profile.name,
            description=profile.description,
            ports=profile.ports,
            scan_types=profile.scan_types,
            threads=profile.threads,
            timeout=profile.timeout,
            rate_limit=profile.rate_limit,
            enable_service_detection=profile.enable_service_detection,
            enable_os_detection=profile.enable_os_detection,
            enable_banner_grabbing=profile.enable_banner_grabbing,
            randomize=profile.randomize,
            timing_template=profile.timing_template,
            created_at=profile.created_at,
            modified_at=profile.modified_at,
        )
    
    @app.post(
        "/profiles",
        response_model=ProfileResponse,
        tags=["Profiles"],
        summary="Create a profile",
        status_code=status.HTTP_201_CREATED,
    )
    async def create_profile(
        request: ProfileRequest,
        payload: TokenPayload = Depends(require_profile_write),
    ):
        """Create a new scan profile."""
        from spectrescan.core.profiles import ProfileManager, ScanProfile
        
        manager = ProfileManager()
        
        profile = ScanProfile(
            name=request.name,
            description=request.description or "",
            ports=request.ports,
            scan_types=request.scan_types,
            threads=request.threads,
            timeout=request.timeout,
            rate_limit=request.rate_limit,
            enable_service_detection=request.enable_service_detection,
            enable_os_detection=request.enable_os_detection,
            enable_banner_grabbing=request.enable_banner_grabbing,
            randomize=request.randomize,
            timing_template=request.timing_template,
        )
        
        manager.save_profile(profile)
        
        return ProfileResponse(
            name=profile.name,
            description=profile.description,
            ports=profile.ports,
            scan_types=profile.scan_types,
            threads=profile.threads,
            timeout=profile.timeout,
            rate_limit=profile.rate_limit,
            enable_service_detection=profile.enable_service_detection,
            enable_os_detection=profile.enable_os_detection,
            enable_banner_grabbing=profile.enable_banner_grabbing,
            randomize=profile.randomize,
            timing_template=profile.timing_template,
            created_at=profile.created_at,
            modified_at=profile.modified_at,
        )
    
    @app.put(
        "/profiles/{name}",
        response_model=ProfileResponse,
        tags=["Profiles"],
        summary="Update a profile",
    )
    async def update_profile(
        name: str,
        request: ProfileRequest,
        payload: TokenPayload = Depends(require_profile_write),
    ):
        """Update an existing scan profile."""
        from spectrescan.core.profiles import ProfileManager, ScanProfile
        
        manager = ProfileManager()
        
        if not manager.profile_exists(name):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Profile not found: {name}",
            )
        
        # Delete old profile if name changed
        if request.name != name:
            manager.delete_profile(name)
        
        profile = ScanProfile(
            name=request.name,
            description=request.description or "",
            ports=request.ports,
            scan_types=request.scan_types,
            threads=request.threads,
            timeout=request.timeout,
            rate_limit=request.rate_limit,
            enable_service_detection=request.enable_service_detection,
            enable_os_detection=request.enable_os_detection,
            enable_banner_grabbing=request.enable_banner_grabbing,
            randomize=request.randomize,
            timing_template=request.timing_template,
        )
        
        manager.save_profile(profile)
        
        return ProfileResponse(
            name=profile.name,
            description=profile.description,
            ports=profile.ports,
            scan_types=profile.scan_types,
            threads=profile.threads,
            timeout=profile.timeout,
            rate_limit=profile.rate_limit,
            enable_service_detection=profile.enable_service_detection,
            enable_os_detection=profile.enable_os_detection,
            enable_banner_grabbing=profile.enable_banner_grabbing,
            randomize=profile.randomize,
            timing_template=profile.timing_template,
            created_at=profile.created_at,
            modified_at=profile.modified_at,
        )
    
    @app.delete(
        "/profiles/{name}",
        tags=["Profiles"],
        summary="Delete a profile",
    )
    async def delete_profile(
        name: str,
        payload: TokenPayload = Depends(require_profile_write),
    ):
        """Delete a scan profile."""
        from spectrescan.core.profiles import ProfileManager
        
        manager = ProfileManager()
        
        if not manager.profile_exists(name):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Profile not found: {name}",
            )
        
        manager.delete_profile(name)
        
        return {"message": f"Profile '{name}' deleted"}
    
    # ==========================================================================
    # History Endpoints
    # ==========================================================================
    
    @app.get(
        "/history",
        response_model=HistoryResponse,
        tags=["History"],
        summary="List scan history",
    )
    async def list_history(
        page: int = Query(default=1, ge=1, description="Page number"),
        page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
        target: Optional[str] = Query(default=None, description="Filter by target"),
        scan_type: Optional[str] = Query(default=None, description="Filter by scan type"),
        payload: TokenPayload = Depends(require_history_read),
    ):
        """List scan history with pagination and filtering."""
        from spectrescan.core.history import HistoryManager
        
        manager = HistoryManager()
        
        entries = manager.list_entries(
            limit=page_size * page,  # Get enough for pagination
            target_filter=target,
            scan_type_filter=scan_type,
        )
        
        # Apply pagination
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_entries = entries[start_idx:end_idx]
        
        return HistoryResponse(
            entries=[
                HistoryEntryResponse(
                    id=e.id,
                    target=e.target,
                    ports=e.ports,
                    scan_type=e.scan_type,
                    timestamp=e.timestamp,
                    duration=e.duration,
                    open_ports=e.open_ports,
                    closed_ports=e.closed_ports,
                    filtered_ports=e.filtered_ports,
                    total_ports=e.total_ports,
                )
                for e in page_entries
            ],
            total=len(entries),
            page=page,
            page_size=page_size,
        )
    
    @app.get(
        "/history/stats",
        response_model=HistoryStatsResponse,
        tags=["History"],
        summary="Get history statistics",
    )
    async def get_history_stats(
        payload: TokenPayload = Depends(require_history_read),
    ):
        """Get aggregate statistics from scan history."""
        from spectrescan.core.history import HistoryManager
        
        manager = HistoryManager()
        stats = manager.get_statistics()
        
        return HistoryStatsResponse(
            total_scans=stats.get("total_scans", 0),
            total_ports_scanned=stats.get("total_ports_scanned", 0),
            total_open_ports=stats.get("total_open_ports", 0),
            total_scan_time=stats.get("total_scan_time", 0.0),
            scan_type_distribution=stats.get("scan_types", {}),
            most_scanned_target=stats.get("most_scanned_target"),
        )
    
    @app.get(
        "/history/{entry_id}",
        response_model=HistoryEntryResponse,
        tags=["History"],
        summary="Get history entry",
    )
    async def get_history_entry(
        entry_id: str,
        payload: TokenPayload = Depends(require_history_read),
    ):
        """Get a specific history entry by ID."""
        from spectrescan.core.history import HistoryManager
        
        manager = HistoryManager()
        entry = manager.get_entry(entry_id)
        
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"History entry not found: {entry_id}",
            )
        
        return HistoryEntryResponse(
            id=entry.id,
            target=entry.target,
            ports=entry.ports,
            scan_type=entry.scan_type,
            timestamp=entry.timestamp,
            duration=entry.duration,
            open_ports=entry.open_ports,
            closed_ports=entry.closed_ports,
            filtered_ports=entry.filtered_ports,
            total_ports=entry.total_ports,
        )
    
    @app.delete(
        "/history/{entry_id}",
        tags=["History"],
        summary="Delete history entry",
    )
    async def delete_history_entry(
        entry_id: str,
        payload: TokenPayload = Depends(require_history_write),
    ):
        """Delete a history entry."""
        from spectrescan.core.history import HistoryManager
        
        manager = HistoryManager()
        
        if not manager.delete_entry(entry_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"History entry not found: {entry_id}",
            )
        
        return {"message": f"History entry {entry_id} deleted"}
    
    @app.delete(
        "/history",
        tags=["History"],
        summary="Clear all history",
    )
    async def clear_history(
        confirm: bool = Query(default=False, description="Confirm deletion"),
        payload: TokenPayload = Depends(require_history_write),
    ):
        """Clear all scan history. Requires confirm=true."""
        if not confirm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must set confirm=true to clear all history",
            )
        
        from spectrescan.core.history import HistoryManager
        
        manager = HistoryManager()
        manager.clear_history()
        
        return {"message": "All history cleared"}
    
    # ==========================================================================
    # WebSocket Endpoint
    # ==========================================================================
    
    @app.websocket("/ws/scan/{scan_id}")
    async def websocket_scan_updates(
        websocket: WebSocket,
        scan_id: str,
    ):
        """
        WebSocket endpoint for real-time scan updates.
        
        Connect to receive live progress updates for a specific scan.
        Messages are JSON formatted with type, scan_id, data, and timestamp.
        """
        await websocket.accept()
        
        # Validate scan exists
        if scan_id not in _active_scans:
            await websocket.send_json({
                "type": "error",
                "message": f"Scan not found: {scan_id}",
            })
            await websocket.close()
            return
        
        # Register connection
        if scan_id not in _websocket_connections:
            _websocket_connections[scan_id] = []
        _websocket_connections[scan_id].append(websocket)
        
        try:
            # Send initial status
            await websocket.send_json({
                "type": "status",
                "scan_id": scan_id,
                "data": _active_scans[scan_id]["status"].model_dump(),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            
            # Keep connection open and handle messages
            while True:
                try:
                    # Wait for messages (ping/pong or commands)
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=30.0,
                    )
                    
                    # Handle ping
                    if data == "ping":
                        await websocket.send_text("pong")
                    
                except asyncio.TimeoutError:
                    # Send heartbeat
                    await websocket.send_json({
                        "type": "heartbeat",
                        "scan_id": scan_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    
        except WebSocketDisconnect:
            pass
        finally:
            # Remove connection
            if scan_id in _websocket_connections:
                if websocket in _websocket_connections[scan_id]:
                    _websocket_connections[scan_id].remove(websocket)


# =============================================================================
# Scan Execution
# =============================================================================


async def _run_scan(scan_id: str, request: ScanRequest) -> None:
    """
    Run a scan asynchronously.
    
    Args:
        scan_id: Unique scan identifier
        request: Scan request parameters
    """
    scan_data = _active_scans.get(scan_id)
    if not scan_data:
        return
    
    try:
        # Update status to running
        scan_data["status"].state = ScanState.RUNNING
        scan_data["state"] = ScanState.RUNNING
        await _broadcast_update(scan_id, "status", scan_data["status"].model_dump())
        
        # Import scanner components
        from spectrescan.core.utils import parse_ports, get_common_ports
        from spectrescan.core.scanner import PortScanner
        from spectrescan.core.presets import ScanConfig
        
        # Parse ports
        if request.ports:
            ports = parse_ports(request.ports)
        else:
            ports = get_common_ports(100)  # Default to top 100
        
        scan_data["status"].ports_total = len(ports)
        
        # Create scanner config
        config = ScanConfig(
            name="API Scan",
            description=f"Scan initiated via API: {scan_id}",
            ports=ports,
            scan_types=[request.scan_type.value],
            threads=request.threads,
            timeout=request.timeout,
            rate_limit=request.rate_limit,
            enable_service_detection=request.service_detection,
            enable_os_detection=request.os_detection,
            enable_banner_grabbing=request.banner_grab,
            randomize=request.randomize,
            timing_template=request.timing_template,
        )
        
        # Create scanner
        scanner = PortScanner(
            timeout=config.timeout,
            threads=config.threads,
            rate_limit=config.rate_limit,
        )
        
        # Progress callback
        async def progress_callback(result):
            if scan_id not in _active_scans:
                return
            
            scan_data["results"].append(result)
            scan_data["status"].ports_scanned += 1
            
            if result.state == "open":
                scan_data["status"].open_ports += 1
            elif result.state == "closed":
                scan_data["closed_ports"] = scan_data.get("closed_ports", 0) + 1
            elif result.state == "filtered":
                scan_data["filtered_ports"] = scan_data.get("filtered_ports", 0) + 1
            
            # Calculate progress
            total = scan_data["status"].ports_total
            scanned = scan_data["status"].ports_scanned
            scan_data["status"].progress = (scanned / total * 100) if total > 0 else 0
            
            # Broadcast update every 10 ports
            if scanned % 10 == 0:
                await _broadcast_update(scan_id, "progress", {
                    "progress": scan_data["status"].progress,
                    "ports_scanned": scanned,
                    "open_ports": scan_data["status"].open_ports,
                })
        
        # Synchronous callback wrapper
        def sync_callback(result):
            asyncio.create_task(progress_callback(result))
        
        # Run scan
        results = scanner.scan(
            target=request.target,
            ports=ports,
            callback=sync_callback,
        )
        
        # Store final results
        scan_data["results"] = results
        scan_data["status"].state = ScanState.COMPLETED
        scan_data["state"] = ScanState.COMPLETED
        scan_data["status"].completed_at = datetime.now(timezone.utc)
        scan_data["status"].progress = 100.0
        scan_data["status"].ports_scanned = len(ports)
        scan_data["status"].open_ports = len([r for r in results if r.state == "open"])
        
        # Broadcast completion
        await _broadcast_update(scan_id, "completed", {
            "status": scan_data["status"].model_dump(),
            "open_ports": scan_data["status"].open_ports,
        })
        
        # Add to history
        try:
            from spectrescan.core.history import HistoryManager
            
            history = HistoryManager()
            history.add_entry(
                target=request.target,
                ports=ports,
                scan_type=request.scan_type.value,
                duration=(
                    scan_data["status"].completed_at - scan_data["status"].started_at
                ).total_seconds() if scan_data["status"].completed_at else 0,
                open_ports=scan_data["status"].open_ports,
                closed_ports=scan_data.get("closed_ports", 0),
                filtered_ports=scan_data.get("filtered_ports", 0),
                config=request.model_dump(),
            )
        except Exception as e:
            logger.warning(f"Failed to save scan to history: {e}")
        
    except asyncio.CancelledError:
        scan_data["status"].state = ScanState.CANCELLED
        scan_data["state"] = ScanState.CANCELLED
        await _broadcast_update(scan_id, "cancelled", {})
        
    except Exception as e:
        logger.exception(f"Scan {scan_id} failed")
        scan_data["status"].state = ScanState.FAILED
        scan_data["state"] = ScanState.FAILED
        scan_data["status"].error = str(e)
        await _broadcast_update(scan_id, "error", {"message": str(e)})


async def _broadcast_update(scan_id: str, msg_type: str, data: Dict[str, Any]) -> None:
    """Broadcast update to all WebSocket connections for a scan."""
    if scan_id not in _websocket_connections:
        return
    
    message = {
        "type": msg_type,
        "scan_id": scan_id,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    dead_connections = []
    
    for ws in _websocket_connections[scan_id]:
        try:
            await ws.send_json(message)
        except Exception:
            dead_connections.append(ws)
    
    # Remove dead connections
    for ws in dead_connections:
        _websocket_connections[scan_id].remove(ws)


def _build_host_results(results: list) -> list:
    """Build host results from scan results."""
    from collections import defaultdict
    
    hosts: Dict[str, HostResult] = defaultdict(
        lambda: HostResult(host="", ports=[])
    )
    
    for result in results:
        host = result.host
        
        if host not in hosts:
            hosts[host] = HostResult(host=host, ports=[])
        
        port_result = PortResult(
            port=result.port,
            protocol=result.protocol,
            state=PortState(result.state) if result.state in [s.value for s in PortState] else PortState.CLOSED,
            service=result.service,
            banner=result.banner,
        )
        
        hosts[host].ports.append(port_result)
    
    return list(hosts.values())


# =============================================================================
# Application Singleton
# =============================================================================


_app: Optional["FastAPI"] = None


def get_app() -> "FastAPI":
    """Get or create the FastAPI application singleton."""
    global _app
    if _app is None:
        _app = create_app()
    return _app
