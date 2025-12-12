"""
SpectreScan Web Dashboard Application.

FastAPI-based web application serving the dashboard frontend and API endpoints.

by BitSpectreLabs
"""

import asyncio
import json
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Check for FastAPI
try:
    from fastapi import (
        FastAPI,
        HTTPException,
        Depends,
        Header,
        Query,
        Request,
        Response,
        WebSocket,
        WebSocketDisconnect,
        status,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("FastAPI not available. Install with: pip install fastapi uvicorn")

from spectrescan.web.auth import (
    User,
    Role,
    Permission,
    UserManager,
    SessionManager,
    RBACManager,
    get_user_manager,
    get_session_manager,
    get_current_user,
    init_auth,
)
from spectrescan.web.websocket import (
    WebSocketManager,
    WebSocketMessage,
    MessageType,
    ScanProgressHandler,
    DashboardUpdater,
    get_websocket_manager,
    get_scan_progress_handler,
    get_dashboard_updater,
)
from spectrescan.web.models import (
    DashboardStats,
    ScanJob,
    ScanJobStatus,
    NetworkTopology,
    TopologyNode,
    UserPreferences,
    ThemeMode,
)


# =============================================================================
# Pydantic Models for API
# =============================================================================

if FASTAPI_AVAILABLE:
    class LoginRequest(BaseModel):
        """Login request model."""
        username: str
        password: str
    
    class LoginResponse(BaseModel):
        """Login response model."""
        session_id: str
        user_id: str
        username: str
        roles: List[str]
        expires_at: str
    
    class UserCreateRequest(BaseModel):
        """User creation request."""
        username: str
        email: str
        password: str
        roles: List[str] = ["viewer"]
    
    class UserResponse(BaseModel):
        """User response model."""
        user_id: str
        username: str
        email: str
        roles: List[str]
        is_active: bool
        created_at: Optional[str]
        last_login: Optional[str]
    
    class ScanCreateRequest(BaseModel):
        """Scan creation request."""
        name: str
        target: str
        ports: str = "1-1000"
        scan_type: str = "tcp"
        profile_name: Optional[str] = None
        options: Dict[str, Any] = Field(default_factory=dict)
    
    class ScanJobResponse(BaseModel):
        """Scan job response."""
        job_id: str
        name: str
        target: str
        ports: str
        status: str
        progress: float
        created_at: Optional[str]
        started_at: Optional[str]
        completed_at: Optional[str]
        results_summary: Dict[str, Any]
    
    class DashboardStatsResponse(BaseModel):
        """Dashboard statistics response."""
        total_scans: int
        active_scans: int
        completed_scans: int
        failed_scans: int
        total_hosts_scanned: int
        total_open_ports: int
        scans_today: int
        top_services: List[Dict[str, Any]]
        recent_scans: List[Dict[str, Any]]
    
    class PreferencesRequest(BaseModel):
        """User preferences update request."""
        theme: Optional[str] = None
        results_per_page: Optional[int] = None
        auto_refresh_interval: Optional[int] = None
        show_closed_ports: Optional[bool] = None
        enable_notifications: Optional[bool] = None


# =============================================================================
# Web Dashboard Application
# =============================================================================

class WebDashboard:
    """Web Dashboard application manager."""
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        debug: bool = False,
        static_dir: Optional[Path] = None,
    ):
        """Initialize web dashboard."""
        self.host = host
        self.port = port
        self.debug = debug
        self.static_dir = static_dir or Path(__file__).parent / "static"
        self.templates_dir = Path(__file__).parent / "templates"
        
        # Ensure directories exist
        self.static_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        
        # State
        self._scan_jobs: Dict[str, ScanJob] = {}
        self._running = False
        
        # Initialize components
        self.ws_manager = get_websocket_manager()
        self.scan_progress = get_scan_progress_handler()
        self.dashboard_updater = get_dashboard_updater()
        
        # Create FastAPI app
        self.app = self._create_app() if FASTAPI_AVAILABLE else None
    
    def _create_app(self) -> "FastAPI":
        """Create the FastAPI application."""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            """Application lifespan handler."""
            # Startup
            logger.info("Starting SpectreScan Web Dashboard")
            init_auth()
            self._running = True
            
            # Create default admin user if none exists
            user_mgr = get_user_manager()
            if not user_mgr.list_users():
                user_mgr.create_user(
                    username="admin",
                    email="admin@spectrescan.local",
                    password="admin",
                    roles=[Role.SUPER_ADMIN],
                )
                logger.info("Created default admin user (username: admin, password: admin)")
            
            yield
            
            # Shutdown
            logger.info("Shutting down SpectreScan Web Dashboard")
            self._running = False
        
        app = FastAPI(
            title="SpectreScan Web Dashboard",
            description="Web-based interface for SpectreScan port scanner",
            version="2.1.0",
            lifespan=lifespan,
        )
        
        # CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Mount static files if directory exists and has content
        if self.static_dir.exists():
            app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
        
        # Register routes
        self._register_routes(app)
        
        return app
    
    def _register_routes(self, app: "FastAPI") -> None:
        """Register all API routes."""
        
        # ---------------------------------------------------------------------
        # Authentication routes
        # ---------------------------------------------------------------------
        
        @app.post("/api/auth/login", response_model=LoginResponse)
        async def login(request: LoginRequest):
            """Authenticate user and create session."""
            user_mgr = get_user_manager()
            session_mgr = get_session_manager()
            
            user = user_mgr.authenticate(request.username, request.password)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid username or password"
                )
            
            session = session_mgr.create_session(user.user_id)
            
            return LoginResponse(
                session_id=session.session_id,
                user_id=user.user_id,
                username=user.username,
                roles=[r.value for r in user.roles],
                expires_at=session.expires_at.isoformat(),
            )
        
        @app.post("/api/auth/logout")
        async def logout(session_id: str = Header(alias="X-Session-ID")):
            """Invalidate session."""
            session_mgr = get_session_manager()
            session_mgr.invalidate_session(session_id)
            return {"message": "Logged out successfully"}
        
        @app.get("/api/auth/me", response_model=UserResponse)
        async def get_current_user_info(session_id: str = Header(alias="X-Session-ID")):
            """Get current user information."""
            user = get_current_user(session_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired session"
                )
            return UserResponse(
                user_id=user.user_id,
                username=user.username,
                email=user.email,
                roles=[r.value for r in user.roles],
                is_active=user.is_active,
                created_at=user.created_at.isoformat() if user.created_at else None,
                last_login=user.last_login.isoformat() if user.last_login else None,
            )
        
        # ---------------------------------------------------------------------
        # User management routes
        # ---------------------------------------------------------------------
        
        @app.get("/api/users", response_model=List[UserResponse])
        async def list_users(session_id: str = Header(alias="X-Session-ID")):
            """List all users (admin only)."""
            user = get_current_user(session_id)
            if not user or not user.has_permission(Permission.USER_READ):
                raise HTTPException(status_code=403, detail="Permission denied")
            
            user_mgr = get_user_manager()
            users = user_mgr.list_users(include_inactive=True)
            
            return [
                UserResponse(
                    user_id=u.user_id,
                    username=u.username,
                    email=u.email,
                    roles=[r.value for r in u.roles],
                    is_active=u.is_active,
                    created_at=u.created_at.isoformat() if u.created_at else None,
                    last_login=u.last_login.isoformat() if u.last_login else None,
                )
                for u in users
            ]
        
        @app.post("/api/users", response_model=UserResponse)
        async def create_user(
            request: UserCreateRequest,
            session_id: str = Header(alias="X-Session-ID"),
        ):
            """Create a new user (admin only)."""
            user = get_current_user(session_id)
            if not user or not user.has_permission(Permission.USER_WRITE):
                raise HTTPException(status_code=403, detail="Permission denied")
            
            user_mgr = get_user_manager()
            try:
                roles = [Role(r) for r in request.roles]
                new_user = user_mgr.create_user(
                    username=request.username,
                    email=request.email,
                    password=request.password,
                    roles=roles,
                )
                return UserResponse(
                    user_id=new_user.user_id,
                    username=new_user.username,
                    email=new_user.email,
                    roles=[r.value for r in new_user.roles],
                    is_active=new_user.is_active,
                    created_at=new_user.created_at.isoformat() if new_user.created_at else None,
                    last_login=None,
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
        
        # ---------------------------------------------------------------------
        # Dashboard routes
        # ---------------------------------------------------------------------
        
        @app.get("/api/dashboard/stats", response_model=DashboardStatsResponse)
        async def get_dashboard_stats(session_id: str = Header(alias="X-Session-ID")):
            """Get dashboard statistics."""
            user = get_current_user(session_id)
            if not user:
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            stats = self._calculate_dashboard_stats()
            return DashboardStatsResponse(**stats.to_dict())
        
        @app.get("/api/dashboard/recent-scans")
        async def get_recent_scans(
            limit: int = Query(default=10, le=100),
            session_id: str = Header(alias="X-Session-ID"),
        ):
            """Get recent scan jobs."""
            user = get_current_user(session_id)
            if not user:
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            scans = sorted(
                self._scan_jobs.values(),
                key=lambda x: x.created_at or datetime.min,
                reverse=True
            )[:limit]
            
            return [s.to_dict() for s in scans]
        
        # ---------------------------------------------------------------------
        # Scan job routes
        # ---------------------------------------------------------------------
        
        @app.get("/api/scans", response_model=List[ScanJobResponse])
        async def list_scans(
            status_filter: Optional[str] = None,
            limit: int = Query(default=50, le=500),
            session_id: str = Header(alias="X-Session-ID"),
        ):
            """List scan jobs."""
            user = get_current_user(session_id)
            if not user or not user.has_permission(Permission.SCAN_READ):
                raise HTTPException(status_code=403, detail="Permission denied")
            
            scans = list(self._scan_jobs.values())
            
            if status_filter:
                try:
                    target_status = ScanJobStatus(status_filter)
                    scans = [s for s in scans if s.status == target_status]
                except ValueError:
                    pass
            
            scans = sorted(
                scans,
                key=lambda x: x.created_at or datetime.min,
                reverse=True
            )[:limit]
            
            return [
                ScanJobResponse(
                    job_id=s.job_id,
                    name=s.name,
                    target=s.target,
                    ports=s.ports,
                    status=s.status.value,
                    progress=s.progress,
                    created_at=s.created_at.isoformat() if s.created_at else None,
                    started_at=s.started_at.isoformat() if s.started_at else None,
                    completed_at=s.completed_at.isoformat() if s.completed_at else None,
                    results_summary=s.results_summary,
                )
                for s in scans
            ]
        
        @app.post("/api/scans", response_model=ScanJobResponse)
        async def create_scan(
            request: ScanCreateRequest,
            session_id: str = Header(alias="X-Session-ID"),
        ):
            """Create and queue a new scan job."""
            user = get_current_user(session_id)
            if not user or not user.has_permission(Permission.SCAN_EXECUTE):
                raise HTTPException(status_code=403, detail="Permission denied")
            
            job = ScanJob(
                job_id=str(uuid.uuid4()),
                name=request.name,
                target=request.target,
                ports=request.ports,
                status=ScanJobStatus.QUEUED,
                created_at=datetime.now(),
                created_by=user.user_id,
                scan_type=request.scan_type,
                profile_name=request.profile_name,
                options=request.options,
            )
            
            self._scan_jobs[job.job_id] = job
            
            # Start scan in background
            asyncio.create_task(self._execute_scan(job))
            
            return ScanJobResponse(
                job_id=job.job_id,
                name=job.name,
                target=job.target,
                ports=job.ports,
                status=job.status.value,
                progress=job.progress,
                created_at=job.created_at.isoformat() if job.created_at else None,
                started_at=None,
                completed_at=None,
                results_summary={},
            )
        
        @app.get("/api/scans/{job_id}", response_model=ScanJobResponse)
        async def get_scan(
            job_id: str,
            session_id: str = Header(alias="X-Session-ID"),
        ):
            """Get scan job details."""
            user = get_current_user(session_id)
            if not user or not user.has_permission(Permission.SCAN_READ):
                raise HTTPException(status_code=403, detail="Permission denied")
            
            job = self._scan_jobs.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            return ScanJobResponse(
                job_id=job.job_id,
                name=job.name,
                target=job.target,
                ports=job.ports,
                status=job.status.value,
                progress=job.progress,
                created_at=job.created_at.isoformat() if job.created_at else None,
                started_at=job.started_at.isoformat() if job.started_at else None,
                completed_at=job.completed_at.isoformat() if job.completed_at else None,
                results_summary=job.results_summary,
            )
        
        @app.delete("/api/scans/{job_id}")
        async def cancel_scan(
            job_id: str,
            session_id: str = Header(alias="X-Session-ID"),
        ):
            """Cancel a running scan."""
            user = get_current_user(session_id)
            if not user or not user.has_permission(Permission.SCAN_DELETE):
                raise HTTPException(status_code=403, detail="Permission denied")
            
            job = self._scan_jobs.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            if job.status in [ScanJobStatus.QUEUED, ScanJobStatus.RUNNING]:
                job.status = ScanJobStatus.CANCELLED
                await self.scan_progress.send_scan_cancelled(job_id)
            
            return {"message": "Scan cancelled"}
        
        # ---------------------------------------------------------------------
        # User preferences routes
        # ---------------------------------------------------------------------
        
        @app.get("/api/preferences")
        async def get_preferences(session_id: str = Header(alias="X-Session-ID")):
            """Get user preferences."""
            user = get_current_user(session_id)
            if not user:
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            # Return default preferences for now
            prefs = UserPreferences(user_id=user.user_id)
            return prefs.to_dict()
        
        @app.put("/api/preferences")
        async def update_preferences(
            request: PreferencesRequest,
            session_id: str = Header(alias="X-Session-ID"),
        ):
            """Update user preferences."""
            user = get_current_user(session_id)
            if not user:
                raise HTTPException(status_code=401, detail="Unauthorized")
            
            # Update preferences (would save to storage in production)
            prefs = UserPreferences(user_id=user.user_id)
            if request.theme:
                prefs.theme = ThemeMode(request.theme)
            if request.results_per_page:
                prefs.results_per_page = request.results_per_page
            if request.auto_refresh_interval:
                prefs.auto_refresh_interval = request.auto_refresh_interval
            if request.show_closed_ports is not None:
                prefs.show_closed_ports = request.show_closed_ports
            if request.enable_notifications is not None:
                prefs.enable_notifications = request.enable_notifications
            
            return prefs.to_dict()
        
        # ---------------------------------------------------------------------
        # WebSocket routes
        # ---------------------------------------------------------------------
        
        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates."""
            await websocket.accept()
            
            # Get session from query params
            session_id = websocket.query_params.get("session_id")
            user = get_current_user(session_id) if session_id else None
            
            # Connect to WebSocket manager
            conn_info = await self.ws_manager.connect(
                websocket,
                user_id=user.user_id if user else None,
                session_id=session_id,
            )
            
            try:
                while True:
                    data = await websocket.receive_text()
                    try:
                        message = WebSocketMessage.from_json(data)
                        await self._handle_ws_message(conn_info.connection_id, message)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid WebSocket message: {data}")
            except WebSocketDisconnect:
                await self.ws_manager.disconnect(conn_info.connection_id)
        
        # ---------------------------------------------------------------------
        # Frontend routes
        # ---------------------------------------------------------------------
        
        @app.get("/", response_class=HTMLResponse)
        async def index(request: Request):
            """Serve the main dashboard page."""
            return self._get_dashboard_html()
        
        @app.get("/login", response_class=HTMLResponse)
        async def login_page():
            """Serve the login page."""
            return self._get_login_html()
        
        @app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {
                "status": "healthy",
                "version": "2.1.0",
                "timestamp": datetime.now().isoformat(),
            }
    
    async def _handle_ws_message(
        self,
        connection_id: str,
        message: WebSocketMessage,
    ) -> None:
        """Handle incoming WebSocket messages."""
        if message.message_type == MessageType.PING:
            await self.ws_manager.send_to_connection(
                connection_id,
                WebSocketMessage(
                    message_type=MessageType.PONG,
                    payload={"timestamp": time.time()}
                )
            )
        elif message.message_type.value.startswith("subscribe"):
            channel = message.payload.get("channel")
            if channel:
                await self.ws_manager.subscribe(connection_id, channel)
        elif message.message_type.value.startswith("unsubscribe"):
            channel = message.payload.get("channel")
            if channel:
                await self.ws_manager.unsubscribe(connection_id, channel)
    
    async def _execute_scan(self, job: ScanJob) -> None:
        """Execute a scan job."""
        try:
            job.status = ScanJobStatus.RUNNING
            job.started_at = datetime.now()
            
            # Notify subscribers
            await self.scan_progress.send_scan_started(
                job.job_id,
                job.target,
                1000,  # Placeholder total ports
            )
            
            # Import scanner
            from spectrescan.core.scanner import PortScanner
            from spectrescan.core.utils import parse_ports
            
            ports = parse_ports(job.ports)
            scanner = PortScanner()
            
            results = []
            total = len(ports)
            open_count = 0
            
            def on_result(result):
                nonlocal open_count
                results.append(result)
                if result.state == "open":
                    open_count += 1
                progress = len(results) / total * 100
                job.progress = progress
                # Send progress (fire and forget)
                asyncio.create_task(
                    self.scan_progress.send_scan_progress(
                        job.job_id,
                        progress,
                        len(results),
                        total,
                        open_count,
                    )
                )
                if result.state == "open":
                    asyncio.create_task(
                        self.scan_progress.send_scan_result(
                            job.job_id,
                            result.host,
                            result.port,
                            result.state,
                            result.service,
                            result.banner,
                        )
                    )
            
            # Execute scan
            scanner.scan(job.target, ports, callback=on_result)
            
            # Update job
            job.status = ScanJobStatus.COMPLETED
            job.completed_at = datetime.now()
            job.progress = 100.0
            job.results_summary = {
                "total_ports": total,
                "open_ports": open_count,
                "closed_ports": total - open_count,
                "duration_seconds": (job.completed_at - job.started_at).total_seconds(),
            }
            
            # Notify completion
            await self.scan_progress.send_scan_completed(job.job_id, job.results_summary)
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            job.status = ScanJobStatus.FAILED
            job.error_message = str(e)
            await self.scan_progress.send_scan_failed(job.job_id, str(e))
    
    def _calculate_dashboard_stats(self) -> DashboardStats:
        """Calculate dashboard statistics."""
        now = datetime.now()
        today = now.date()
        week_ago = now - timedelta(days=7)
        
        scans = list(self._scan_jobs.values())
        
        return DashboardStats(
            total_scans=len(scans),
            active_scans=len([s for s in scans if s.status == ScanJobStatus.RUNNING]),
            completed_scans=len([s for s in scans if s.status == ScanJobStatus.COMPLETED]),
            failed_scans=len([s for s in scans if s.status == ScanJobStatus.FAILED]),
            total_hosts_scanned=len(set(s.target for s in scans)),
            total_open_ports=sum(s.results_summary.get("open_ports", 0) for s in scans),
            scans_today=len([s for s in scans if s.created_at and s.created_at.date() == today]),
            scans_this_week=len([s for s in scans if s.created_at and s.created_at > week_ago]),
            recent_scans=[s.to_dict() for s in sorted(scans, key=lambda x: x.created_at or datetime.min, reverse=True)[:5]],
        )
    
    def _get_dashboard_html(self) -> str:
        """Get the main dashboard HTML."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpectreScan - Web Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --accent-hover: #79c0ff;
            --success: #3fb950;
            --warning: #d29922;
            --danger: #f85149;
        }
        body {
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
        }
        .sidebar {
            background-color: var(--bg-secondary);
            border-right: 1px solid var(--bg-tertiary);
        }
        .card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--bg-tertiary);
            border-radius: 6px;
        }
        .btn-primary {
            background-color: var(--accent);
            color: white;
        }
        .btn-primary:hover {
            background-color: var(--accent-hover);
        }
        .stat-card {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
        }
        .status-running { color: var(--accent); }
        .status-completed { color: var(--success); }
        .status-failed { color: var(--danger); }
        .status-queued { color: var(--warning); }
        .nav-item:hover { background-color: var(--bg-tertiary); }
        .nav-item.active { background-color: var(--bg-tertiary); border-left: 3px solid var(--accent); }
    </style>
</head>
<body class="min-h-screen" id="app">
    <div class="flex min-h-screen">
        <!-- Sidebar -->
        <aside class="sidebar w-64 flex-shrink-0">
            <div class="p-4 border-b border-gray-700">
                <div class="flex items-center space-x-3">
                    <i class="fas fa-ghost text-2xl text-blue-400"></i>
                    <span class="text-xl font-bold">SpectreScan</span>
                </div>
                <p class="text-xs text-gray-500 mt-1">Web Dashboard v2.1.0</p>
            </div>
            <nav class="p-4">
                <ul class="space-y-2">
                    <li class="nav-item active rounded px-3 py-2 cursor-pointer" onclick="showSection('dashboard')">
                        <i class="fas fa-chart-line mr-3"></i> Dashboard
                    </li>
                    <li class="nav-item rounded px-3 py-2 cursor-pointer" onclick="showSection('scans')">
                        <i class="fas fa-radar mr-3"></i> Scans
                    </li>
                    <li class="nav-item rounded px-3 py-2 cursor-pointer" onclick="showSection('history')">
                        <i class="fas fa-history mr-3"></i> History
                    </li>
                    <li class="nav-item rounded px-3 py-2 cursor-pointer" onclick="showSection('profiles')">
                        <i class="fas fa-sliders-h mr-3"></i> Profiles
                    </li>
                    <li class="nav-item rounded px-3 py-2 cursor-pointer" onclick="showSection('topology')">
                        <i class="fas fa-project-diagram mr-3"></i> Topology
                    </li>
                    <li class="nav-item rounded px-3 py-2 cursor-pointer" onclick="showSection('settings')">
                        <i class="fas fa-cog mr-3"></i> Settings
                    </li>
                </ul>
            </nav>
            <div class="absolute bottom-0 left-0 w-64 p-4 border-t border-gray-700">
                <div class="flex items-center space-x-3">
                    <div class="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center">
                        <i class="fas fa-user text-sm"></i>
                    </div>
                    <div>
                        <p class="text-sm font-medium" id="username">Loading...</p>
                        <p class="text-xs text-gray-500" id="user-role">-</p>
                    </div>
                </div>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 p-6">
            <!-- Dashboard Section -->
            <section id="section-dashboard">
                <div class="flex justify-between items-center mb-6">
                    <h1 class="text-2xl font-bold">Dashboard</h1>
                    <button class="btn-primary px-4 py-2 rounded" onclick="showNewScanModal()">
                        <i class="fas fa-plus mr-2"></i> New Scan
                    </button>
                </div>

                <!-- Stats Grid -->
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                    <div class="stat-card card p-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-gray-400 text-sm">Total Scans</p>
                                <p class="text-2xl font-bold" id="stat-total">0</p>
                            </div>
                            <i class="fas fa-radar text-3xl text-blue-400 opacity-50"></i>
                        </div>
                    </div>
                    <div class="stat-card card p-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-gray-400 text-sm">Active Scans</p>
                                <p class="text-2xl font-bold status-running" id="stat-active">0</p>
                            </div>
                            <i class="fas fa-spinner fa-spin text-3xl text-blue-400 opacity-50"></i>
                        </div>
                    </div>
                    <div class="stat-card card p-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-gray-400 text-sm">Open Ports Found</p>
                                <p class="text-2xl font-bold text-green-400" id="stat-ports">0</p>
                            </div>
                            <i class="fas fa-door-open text-3xl text-green-400 opacity-50"></i>
                        </div>
                    </div>
                    <div class="stat-card card p-4">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-gray-400 text-sm">Hosts Scanned</p>
                                <p class="text-2xl font-bold" id="stat-hosts">0</p>
                            </div>
                            <i class="fas fa-server text-3xl text-purple-400 opacity-50"></i>
                        </div>
                    </div>
                </div>

                <!-- Recent Scans -->
                <div class="card p-4 mb-6">
                    <h2 class="text-lg font-semibold mb-4">Recent Scans</h2>
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="text-left text-gray-400 text-sm">
                                    <th class="pb-3">Name</th>
                                    <th class="pb-3">Target</th>
                                    <th class="pb-3">Status</th>
                                    <th class="pb-3">Progress</th>
                                    <th class="pb-3">Open Ports</th>
                                    <th class="pb-3">Actions</th>
                                </tr>
                            </thead>
                            <tbody id="recent-scans-table">
                                <tr>
                                    <td colspan="6" class="text-center text-gray-500 py-4">
                                        No scans yet. Start a new scan to see results here.
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            <!-- Other sections (hidden by default) -->
            <section id="section-scans" class="hidden">
                <h1 class="text-2xl font-bold mb-6">Scan Management</h1>
                <p class="text-gray-400">Manage and monitor your scan jobs here.</p>
            </section>

            <section id="section-history" class="hidden">
                <h1 class="text-2xl font-bold mb-6">Scan History</h1>
                <p class="text-gray-400">View historical scan data and results.</p>
            </section>

            <section id="section-profiles" class="hidden">
                <h1 class="text-2xl font-bold mb-6">Scan Profiles</h1>
                <p class="text-gray-400">Create and manage reusable scan configurations.</p>
            </section>

            <section id="section-topology" class="hidden">
                <h1 class="text-2xl font-bold mb-6">Network Topology</h1>
                <p class="text-gray-400">Visualize discovered network topology.</p>
            </section>

            <section id="section-settings" class="hidden">
                <h1 class="text-2xl font-bold mb-6">Settings</h1>
                <p class="text-gray-400">Configure dashboard preferences.</p>
            </section>
        </main>
    </div>

    <!-- New Scan Modal -->
    <div id="new-scan-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50">
        <div class="card p-6 w-full max-w-md">
            <h2 class="text-xl font-bold mb-4">New Scan</h2>
            <form id="new-scan-form">
                <div class="mb-4">
                    <label class="block text-sm text-gray-400 mb-1">Scan Name</label>
                    <input type="text" name="name" class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2" required>
                </div>
                <div class="mb-4">
                    <label class="block text-sm text-gray-400 mb-1">Target (IP/CIDR/Hostname)</label>
                    <input type="text" name="target" class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2" placeholder="192.168.1.1" required>
                </div>
                <div class="mb-4">
                    <label class="block text-sm text-gray-400 mb-1">Ports</label>
                    <input type="text" name="ports" class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2" placeholder="1-1000" value="1-1000">
                </div>
                <div class="mb-4">
                    <label class="block text-sm text-gray-400 mb-1">Scan Type</label>
                    <select name="scan_type" class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2">
                        <option value="tcp">TCP Connect</option>
                        <option value="syn">SYN Stealth</option>
                        <option value="udp">UDP</option>
                        <option value="async">Async High-Speed</option>
                    </select>
                </div>
                <div class="flex justify-end space-x-3">
                    <button type="button" class="px-4 py-2 rounded border border-gray-600" onclick="hideNewScanModal()">Cancel</button>
                    <button type="submit" class="btn-primary px-4 py-2 rounded">Start Scan</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // State
        let sessionId = localStorage.getItem('session_id');
        let ws = null;

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            if (!sessionId) {
                window.location.href = '/login';
                return;
            }
            loadUserInfo();
            loadDashboardStats();
            connectWebSocket();
        });

        // API calls
        async function apiCall(endpoint, method = 'GET', body = null) {
            const options = {
                method,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Session-ID': sessionId
                }
            };
            if (body) options.body = JSON.stringify(body);
            
            const response = await fetch(`/api${endpoint}`, options);
            if (response.status === 401) {
                localStorage.removeItem('session_id');
                window.location.href = '/login';
                return null;
            }
            return response.json();
        }

        async function loadUserInfo() {
            const user = await apiCall('/auth/me');
            if (user) {
                document.getElementById('username').textContent = user.username;
                document.getElementById('user-role').textContent = user.roles.join(', ');
            }
        }

        async function loadDashboardStats() {
            const stats = await apiCall('/dashboard/stats');
            if (stats) {
                document.getElementById('stat-total').textContent = stats.total_scans;
                document.getElementById('stat-active').textContent = stats.active_scans;
                document.getElementById('stat-ports').textContent = stats.total_open_ports;
                document.getElementById('stat-hosts').textContent = stats.total_hosts_scanned;
                updateRecentScans(stats.recent_scans);
            }
        }

        function updateRecentScans(scans) {
            const table = document.getElementById('recent-scans-table');
            if (!scans || scans.length === 0) {
                table.innerHTML = `<tr><td colspan="6" class="text-center text-gray-500 py-4">No scans yet.</td></tr>`;
                return;
            }
            table.innerHTML = scans.map(scan => `
                <tr class="border-t border-gray-700">
                    <td class="py-3">${scan.name}</td>
                    <td class="py-3">${scan.target}</td>
                    <td class="py-3"><span class="status-${scan.status}">${scan.status}</span></td>
                    <td class="py-3">
                        <div class="w-24 bg-gray-700 rounded-full h-2">
                            <div class="bg-blue-500 h-2 rounded-full" style="width: ${scan.progress}%"></div>
                        </div>
                    </td>
                    <td class="py-3">${scan.results_summary?.open_ports || 0}</td>
                    <td class="py-3">
                        <button class="text-blue-400 hover:text-blue-300" onclick="viewScan('${scan.job_id}')">
                            <i class="fas fa-eye"></i>
                        </button>
                    </td>
                </tr>
            `).join('');
        }

        // WebSocket
        function connectWebSocket() {
            ws = new WebSocket(`ws://${window.location.host}/ws?session_id=${sessionId}`);
            ws.onmessage = (event) => {
                const message = JSON.parse(event.data);
                handleWebSocketMessage(message);
            };
            ws.onclose = () => {
                setTimeout(connectWebSocket, 5000);
            };
        }

        function handleWebSocketMessage(message) {
            if (message.type === 'scan_progress' || message.type === 'scan_completed') {
                loadDashboardStats();
            }
        }

        // UI functions
        function showSection(section) {
            document.querySelectorAll('main > section').forEach(s => s.classList.add('hidden'));
            document.getElementById(`section-${section}`).classList.remove('hidden');
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            event.target.closest('.nav-item').classList.add('active');
        }

        function showNewScanModal() {
            document.getElementById('new-scan-modal').classList.remove('hidden');
            document.getElementById('new-scan-modal').classList.add('flex');
        }

        function hideNewScanModal() {
            document.getElementById('new-scan-modal').classList.add('hidden');
            document.getElementById('new-scan-modal').classList.remove('flex');
        }

        document.getElementById('new-scan-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const scan = {
                name: formData.get('name'),
                target: formData.get('target'),
                ports: formData.get('ports'),
                scan_type: formData.get('scan_type')
            };
            
            const result = await apiCall('/scans', 'POST', scan);
            if (result) {
                hideNewScanModal();
                loadDashboardStats();
            }
        });

        function viewScan(jobId) {
            console.log('View scan:', jobId);
            // Navigate to scan details
        }
    </script>
</body>
</html>
"""
    
    def _get_login_html(self) -> str:
        """Get the login page HTML."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpectreScan - Login</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #21262d 100%);
            min-height: 100vh;
        }
        .login-card {
            background-color: rgba(22, 27, 34, 0.9);
            border: 1px solid #30363d;
            backdrop-filter: blur(10px);
        }
        .btn-primary {
            background: linear-gradient(135deg, #58a6ff 0%, #79c0ff 100%);
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #79c0ff 0%, #a5d6ff 100%);
        }
    </style>
</head>
<body class="flex items-center justify-center">
    <div class="login-card rounded-lg p-8 w-full max-w-md">
        <div class="text-center mb-8">
            <i class="fas fa-ghost text-5xl text-blue-400 mb-4"></i>
            <h1 class="text-2xl font-bold text-white">SpectreScan</h1>
            <p class="text-gray-400 text-sm">Web Dashboard</p>
        </div>
        
        <form id="login-form">
            <div class="mb-4">
                <label class="block text-gray-400 text-sm mb-2">Username</label>
                <div class="relative">
                    <i class="fas fa-user absolute left-3 top-3 text-gray-500"></i>
                    <input type="text" name="username" 
                           class="w-full bg-gray-800 border border-gray-600 rounded pl-10 pr-4 py-2 text-white focus:border-blue-400 focus:outline-none"
                           placeholder="Enter username" required>
                </div>
            </div>
            
            <div class="mb-6">
                <label class="block text-gray-400 text-sm mb-2">Password</label>
                <div class="relative">
                    <i class="fas fa-lock absolute left-3 top-3 text-gray-500"></i>
                    <input type="password" name="password"
                           class="w-full bg-gray-800 border border-gray-600 rounded pl-10 pr-4 py-2 text-white focus:border-blue-400 focus:outline-none"
                           placeholder="Enter password" required>
                </div>
            </div>
            
            <div id="error-message" class="hidden text-red-400 text-sm mb-4 text-center"></div>
            
            <button type="submit" class="btn-primary w-full py-2 rounded text-white font-semibold">
                <i class="fas fa-sign-in-alt mr-2"></i> Login
            </button>
        </form>
        
        <p class="text-gray-500 text-xs text-center mt-6">
            Default credentials: admin / admin
        </p>
    </div>

    <script>
        document.getElementById('login-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: formData.get('username'),
                        password: formData.get('password')
                    })
                });
                
                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem('session_id', data.session_id);
                    window.location.href = '/';
                } else {
                    const error = await response.json();
                    document.getElementById('error-message').textContent = error.detail;
                    document.getElementById('error-message').classList.remove('hidden');
                }
            } catch (err) {
                document.getElementById('error-message').textContent = 'Connection error';
                document.getElementById('error-message').classList.remove('hidden');
            }
        });
    </script>
</body>
</html>
"""
    
    def run(self) -> None:
        """Run the web dashboard server."""
        if not FASTAPI_AVAILABLE:
            logger.error("FastAPI not available. Install with: pip install fastapi uvicorn")
            return
        
        import uvicorn
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="info" if self.debug else "warning",
        )


def create_web_app(
    host: str = "0.0.0.0",
    port: int = 8080,
    debug: bool = False,
) -> WebDashboard:
    """Create a web dashboard instance."""
    return WebDashboard(host=host, port=port, debug=debug)


async def start_web_dashboard(
    host: str = "0.0.0.0",
    port: int = 8080,
    debug: bool = False,
) -> None:
    """Start the web dashboard asynchronously."""
    dashboard = create_web_app(host=host, port=port, debug=debug)
    dashboard.run()
