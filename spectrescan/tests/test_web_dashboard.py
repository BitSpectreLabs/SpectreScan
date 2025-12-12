"""
Unit tests for SpectreScan Web Dashboard.

Tests authentication, WebSocket management, API routes, and dashboard functionality.

by BitSpectreLabs
"""

import asyncio
import json
import pytest
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch


# =============================================================================
# Auth Tests
# =============================================================================

class TestPermission:
    """Test Permission enum."""
    
    def test_permission_values(self):
        """Test permission values are correct."""
        from spectrescan.web.auth import Permission
        
        assert Permission.SCAN_READ.value == "scan:read"
        assert Permission.SCAN_WRITE.value == "scan:write"
        assert Permission.USER_READ.value == "user:read"
        assert Permission.ADMIN_SETTINGS.value == "admin:settings"
        assert Permission.CLUSTER_READ.value == "cluster:read"
    
    def test_all_permissions_exist(self):
        """Test all expected permissions exist."""
        from spectrescan.web.auth import Permission
        
        # Core permissions
        assert hasattr(Permission, "SCAN_READ")
        assert hasattr(Permission, "SCAN_WRITE")
        assert hasattr(Permission, "SCAN_DELETE")
        assert hasattr(Permission, "SCAN_EXECUTE")
        
        # Profile permissions
        assert hasattr(Permission, "PROFILE_READ")
        assert hasattr(Permission, "PROFILE_WRITE")
        assert hasattr(Permission, "PROFILE_DELETE")
        
        # User management
        assert hasattr(Permission, "USER_READ")
        assert hasattr(Permission, "USER_WRITE")
        assert hasattr(Permission, "USER_DELETE")
        
        # Admin permissions
        assert hasattr(Permission, "ADMIN_SETTINGS")
        assert hasattr(Permission, "ADMIN_USERS")
        assert hasattr(Permission, "ADMIN_SYSTEM")


class TestRole:
    """Test Role enum."""
    
    def test_role_values(self):
        """Test role values are correct."""
        from spectrescan.web.auth import Role
        
        assert Role.VIEWER.value == "viewer"
        assert Role.OPERATOR.value == "operator"
        assert Role.ANALYST.value == "analyst"
        assert Role.ADMIN.value == "admin"
        assert Role.SUPER_ADMIN.value == "super_admin"
    
    def test_role_permissions_mapping(self):
        """Test role permissions mapping exists and is valid."""
        from spectrescan.web.auth import Role, Permission, ROLE_PERMISSIONS
        
        # All roles should have mappings
        for role in Role:
            assert role in ROLE_PERMISSIONS
            assert isinstance(ROLE_PERMISSIONS[role], set)
        
        # Super admin should have all permissions
        assert ROLE_PERMISSIONS[Role.SUPER_ADMIN] == set(Permission)
        
        # Viewer should have limited permissions
        assert Permission.SCAN_READ in ROLE_PERMISSIONS[Role.VIEWER]
        assert Permission.SCAN_WRITE not in ROLE_PERMISSIONS[Role.VIEWER]
        
        # Operator should be able to execute scans
        assert Permission.SCAN_EXECUTE in ROLE_PERMISSIONS[Role.OPERATOR]


class TestUser:
    """Test User dataclass."""
    
    def test_user_creation(self):
        """Test user creation."""
        from spectrescan.web.auth import User, Role
        
        user = User(
            user_id="test-id",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles=[Role.VIEWER],
        )
        
        assert user.user_id == "test-id"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.created_at is not None
    
    def test_user_has_permission(self):
        """Test user permission check."""
        from spectrescan.web.auth import User, Role, Permission
        
        user = User(
            user_id="test-id",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles=[Role.VIEWER],
        )
        
        assert user.has_permission(Permission.SCAN_READ)
        assert not user.has_permission(Permission.SCAN_WRITE)
    
    def test_user_has_role(self):
        """Test user role check."""
        from spectrescan.web.auth import User, Role
        
        user = User(
            user_id="test-id",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles=[Role.ADMIN, Role.OPERATOR],
        )
        
        assert user.has_role(Role.ADMIN)
        assert user.has_role(Role.OPERATOR)
        assert not user.has_role(Role.SUPER_ADMIN)
    
    def test_user_locked(self):
        """Test user lock check."""
        from spectrescan.web.auth import User, Role
        
        user = User(
            user_id="test-id",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles=[Role.VIEWER],
        )
        
        # Not locked initially
        assert not user.is_locked()
        
        # Lock user
        user.locked_until = datetime.now() + timedelta(minutes=15)
        assert user.is_locked()
        
        # Expired lock
        user.locked_until = datetime.now() - timedelta(minutes=1)
        assert not user.is_locked()
    
    def test_user_to_dict(self):
        """Test user to dict conversion."""
        from spectrescan.web.auth import User, Role
        
        user = User(
            user_id="test-id",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles=[Role.VIEWER],
        )
        
        data = user.to_dict()
        assert data["user_id"] == "test-id"
        assert data["username"] == "testuser"
        assert "password_hash" not in data
        
        # With sensitive data
        data = user.to_dict(include_sensitive=True)
        assert data["password_hash"] == "hash123"
    
    def test_user_from_dict(self):
        """Test user from dict creation."""
        from spectrescan.web.auth import User, Role
        
        data = {
            "user_id": "test-id",
            "username": "testuser",
            "email": "test@example.com",
            "password_hash": "hash123",
            "roles": ["viewer", "operator"],
            "is_active": True,
        }
        
        user = User.from_dict(data)
        assert user.user_id == "test-id"
        assert Role.VIEWER in user.roles
        assert Role.OPERATOR in user.roles


class TestUserManager:
    """Test UserManager class."""
    
    def test_password_hashing(self):
        """Test password hashing."""
        from spectrescan.web.auth import UserManager
        
        password = "SecurePass123!"
        hash1 = UserManager.hash_password(password)
        hash2 = UserManager.hash_password(password)
        
        # Different hashes (different salts)
        assert hash1 != hash2
        
        # Both verify correctly
        assert UserManager.verify_password(password, hash1)
        assert UserManager.verify_password(password, hash2)
    
    def test_password_verification(self):
        """Test password verification."""
        from spectrescan.web.auth import UserManager
        
        password = "TestPassword123"
        hash_value = UserManager.hash_password(password)
        
        assert UserManager.verify_password(password, hash_value)
        assert not UserManager.verify_password("wrongpassword", hash_value)
        assert not UserManager.verify_password("", hash_value)
    
    def test_create_user(self):
        """Test user creation."""
        from spectrescan.web.auth import UserManager, Role
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            user = manager.create_user(
                username="newuser",
                email="new@example.com",
                password="password123",
                roles=[Role.OPERATOR],
            )
            
            assert user.username == "newuser"
            assert user.email == "new@example.com"
            assert Role.OPERATOR in user.roles
            assert UserManager.verify_password("password123", user.password_hash)
    
    def test_create_user_duplicate_username(self):
        """Test duplicate username prevention."""
        from spectrescan.web.auth import UserManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            manager.create_user("user1", "user1@example.com", "pass1")
            
            with pytest.raises(ValueError, match="already exists"):
                manager.create_user("user1", "user2@example.com", "pass2")
    
    def test_create_user_duplicate_email(self):
        """Test duplicate email prevention."""
        from spectrescan.web.auth import UserManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            manager.create_user("user1", "same@example.com", "pass1")
            
            with pytest.raises(ValueError, match="already exists"):
                manager.create_user("user2", "same@example.com", "pass2")
    
    def test_authenticate_user(self):
        """Test user authentication."""
        from spectrescan.web.auth import UserManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            manager.create_user("testuser", "test@example.com", "correctpassword")
            
            # Correct credentials
            user = manager.authenticate("testuser", "correctpassword")
            assert user is not None
            assert user.username == "testuser"
            
            # By email
            user = manager.authenticate("test@example.com", "correctpassword")
            assert user is not None
            
            # Wrong password
            user = manager.authenticate("testuser", "wrongpassword")
            assert user is None
            
            # Non-existent user
            user = manager.authenticate("nonexistent", "password")
            assert user is None
    
    def test_account_locking(self):
        """Test account locking after failed attempts."""
        from spectrescan.web.auth import UserManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            manager.create_user("lockuser", "lock@example.com", "password123")
            
            # Fail 5 times
            for _ in range(5):
                manager.authenticate("lockuser", "wrongpassword")
            
            # Account should be locked
            user = manager.get_user_by_username("lockuser")
            assert user.is_locked()
            
            # Even correct password should fail
            result = manager.authenticate("lockuser", "password123")
            assert result is None
    
    def test_list_users(self):
        """Test listing users."""
        from spectrescan.web.auth import UserManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            manager.create_user("user1", "user1@example.com", "pass1")
            manager.create_user("user2", "user2@example.com", "pass2")
            
            users = manager.list_users()
            assert len(users) == 2
    
    def test_delete_user(self):
        """Test user deletion."""
        from spectrescan.web.auth import UserManager
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            user = manager.create_user("deleteuser", "delete@example.com", "pass")
            
            assert manager.delete_user(user.user_id)
            assert manager.get_user(user.user_id) is None
    
    def test_assign_role(self):
        """Test role assignment."""
        from spectrescan.web.auth import UserManager, Role
        
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = UserManager(storage_dir=Path(tmpdir))
            
            user = manager.create_user("roleuser", "role@example.com", "pass")
            assert Role.VIEWER in user.roles
            
            manager.assign_role(user.user_id, Role.ADMIN)
            
            user = manager.get_user(user.user_id)
            assert Role.ADMIN in user.roles


class TestSession:
    """Test Session dataclass."""
    
    def test_session_creation(self):
        """Test session creation."""
        from spectrescan.web.auth import Session
        
        session = Session(
            session_id="sess-123",
            user_id="user-456",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        
        assert session.session_id == "sess-123"
        assert session.user_id == "user-456"
        assert session.is_active is True
    
    def test_session_expired(self):
        """Test session expiration check."""
        from spectrescan.web.auth import Session
        
        # Active session
        session = Session(
            session_id="sess-123",
            user_id="user-456",
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
        )
        assert not session.is_expired()
        assert session.is_valid()
        
        # Expired session
        session.expires_at = datetime.now() - timedelta(minutes=1)
        assert session.is_expired()
        assert not session.is_valid()


class TestSessionManager:
    """Test SessionManager class."""
    
    def test_create_session(self):
        """Test session creation."""
        from spectrescan.web.auth import SessionManager
        
        manager = SessionManager()
        session = manager.create_session("user-123")
        
        assert session.user_id == "user-123"
        assert session.is_valid()
    
    def test_get_session(self):
        """Test session retrieval."""
        from spectrescan.web.auth import SessionManager
        
        manager = SessionManager()
        created = manager.create_session("user-123")
        
        retrieved = manager.get_session(created.session_id)
        assert retrieved is not None
        assert retrieved.session_id == created.session_id
    
    def test_invalidate_session(self):
        """Test session invalidation."""
        from spectrescan.web.auth import SessionManager
        
        manager = SessionManager()
        session = manager.create_session("user-123")
        
        assert manager.invalidate_session(session.session_id)
        assert manager.get_session(session.session_id) is None
    
    def test_max_sessions_per_user(self):
        """Test max sessions limit per user."""
        from spectrescan.web.auth import SessionManager
        
        manager = SessionManager(max_sessions_per_user=3)
        
        # Create 4 sessions for same user
        sessions = []
        for _ in range(4):
            sessions.append(manager.create_session("user-123"))
        
        # First session should be invalidated
        assert manager.get_session(sessions[0].session_id) is None
        
        # Remaining sessions should be valid
        assert manager.get_session(sessions[1].session_id) is not None
        assert manager.get_session(sessions[2].session_id) is not None
        assert manager.get_session(sessions[3].session_id) is not None
    
    def test_invalidate_user_sessions(self):
        """Test invalidating all user sessions."""
        from spectrescan.web.auth import SessionManager
        
        manager = SessionManager()
        
        # Create sessions for two users
        manager.create_session("user-1")
        manager.create_session("user-1")
        manager.create_session("user-2")
        
        # Invalidate user-1 sessions
        count = manager.invalidate_user_sessions("user-1")
        assert count == 2
        
        # User-2 session should still exist
        sessions = manager.get_user_sessions("user-2")
        assert len(sessions) == 1


class TestRBACManager:
    """Test RBACManager class."""
    
    def test_check_permission(self):
        """Test permission checking."""
        from spectrescan.web.auth import UserManager, RBACManager, Role, Permission
        
        with tempfile.TemporaryDirectory() as tmpdir:
            user_manager = UserManager(storage_dir=Path(tmpdir))
            rbac = RBACManager(user_manager)
            
            user = user_manager.create_user(
                "testuser", "test@example.com", "pass",
                roles=[Role.OPERATOR]
            )
            
            assert rbac.check_permission(user, Permission.SCAN_READ)
            assert rbac.check_permission(user, Permission.SCAN_EXECUTE)
            assert not rbac.check_permission(user, Permission.ADMIN_SETTINGS)
    
    def test_check_role(self):
        """Test role checking."""
        from spectrescan.web.auth import UserManager, RBACManager, Role
        
        with tempfile.TemporaryDirectory() as tmpdir:
            user_manager = UserManager(storage_dir=Path(tmpdir))
            rbac = RBACManager(user_manager)
            
            user = user_manager.create_user(
                "testuser", "test@example.com", "pass",
                roles=[Role.ADMIN]
            )
            
            assert rbac.check_role(user, Role.ADMIN)
            assert not rbac.check_role(user, Role.SUPER_ADMIN)


# =============================================================================
# Models Tests
# =============================================================================

class TestDashboardStats:
    """Test DashboardStats model."""
    
    def test_creation(self):
        """Test dashboard stats creation."""
        from spectrescan.web.models import DashboardStats
        
        stats = DashboardStats(
            total_scans=100,
            active_scans=5,
            completed_scans=90,
            failed_scans=5,
        )
        
        assert stats.total_scans == 100
        assert stats.active_scans == 5
    
    def test_to_dict(self):
        """Test conversion to dict."""
        from spectrescan.web.models import DashboardStats
        
        stats = DashboardStats(total_scans=50, active_scans=2)
        data = stats.to_dict()
        
        assert data["total_scans"] == 50
        assert data["active_scans"] == 2


class TestScanJob:
    """Test ScanJob model."""
    
    def test_creation(self):
        """Test scan job creation."""
        from spectrescan.web.models import ScanJob, ScanJobStatus
        
        job = ScanJob(
            job_id="job-123",
            name="Test Scan",
            target="192.168.1.1",
            ports="1-1000",
            status=ScanJobStatus.QUEUED,
        )
        
        assert job.job_id == "job-123"
        assert job.status == ScanJobStatus.QUEUED
    
    def test_status_values(self):
        """Test scan job status values."""
        from spectrescan.web.models import ScanJobStatus
        
        assert ScanJobStatus.QUEUED.value == "queued"
        assert ScanJobStatus.RUNNING.value == "running"
        assert ScanJobStatus.COMPLETED.value == "completed"
        assert ScanJobStatus.FAILED.value == "failed"


class TestUserPreferences:
    """Test UserPreferences model."""
    
    def test_defaults(self):
        """Test default preferences."""
        from spectrescan.web.models import UserPreferences, ThemeMode
        
        prefs = UserPreferences(user_id="user-123")
        
        assert prefs.theme == ThemeMode.DARK
        assert prefs.results_per_page == 25
        assert prefs.auto_refresh_interval == 5
    
    def test_to_dict(self):
        """Test conversion to dict."""
        from spectrescan.web.models import UserPreferences
        
        prefs = UserPreferences(user_id="user-123", results_per_page=100)
        data = prefs.to_dict()
        
        assert data["results_per_page"] == 100


class TestNetworkTopology:
    """Test NetworkTopology model."""
    
    def test_creation(self):
        """Test topology creation."""
        from spectrescan.web.models import NetworkTopology, TopologyNode, NodeType
        
        topology = NetworkTopology(topology_id="topo-1", name="Test Network")
        node = TopologyNode(
            node_id="node-1",
            node_type=NodeType.HOST,
            ip_address="192.168.1.1",
        )
        topology.nodes.append(node)
        
        assert len(topology.nodes) == 1
        assert topology.nodes[0].ip_address == "192.168.1.1"


# =============================================================================
# WebSocket Tests
# =============================================================================

class TestWebSocketMessage:
    """Test WebSocketMessage class."""
    
    def test_creation(self):
        """Test message creation."""
        from spectrescan.web.websocket import WebSocketMessage, MessageType
        
        msg = WebSocketMessage(
            message_type=MessageType.SCAN_PROGRESS,
            payload={"progress": 50},
        )
        
        assert msg.message_type == MessageType.SCAN_PROGRESS
        assert msg.payload["progress"] == 50
        assert msg.message_id is not None
    
    def test_to_json(self):
        """Test JSON serialization."""
        from spectrescan.web.websocket import WebSocketMessage, MessageType
        
        msg = WebSocketMessage(
            message_type=MessageType.NOTIFICATION,
            payload={"text": "Test"},
        )
        
        json_str = msg.to_json()
        data = json.loads(json_str)
        
        assert data["type"] == "notification"
        assert data["payload"]["text"] == "Test"
    
    def test_from_json(self):
        """Test JSON deserialization."""
        from spectrescan.web.websocket import WebSocketMessage, MessageType
        
        json_str = '{"type": "ping", "payload": {}}'
        msg = WebSocketMessage.from_json(json_str)
        
        assert msg.message_type == MessageType.PING


class TestWebSocketManager:
    """Test WebSocketManager class."""
    
    @pytest.mark.asyncio
    async def test_connect_disconnect(self):
        """Test connection and disconnection."""
        from spectrescan.web.websocket import WebSocketManager
        
        manager = WebSocketManager()
        mock_ws = AsyncMock()
        
        conn = await manager.connect(mock_ws, user_id="user-123")
        assert conn.connection_id is not None
        assert "user-123" in manager._user_connections
        
        await manager.disconnect(conn.connection_id)
        assert conn.connection_id not in manager._connections
    
    @pytest.mark.asyncio
    async def test_subscribe_unsubscribe(self):
        """Test channel subscription."""
        from spectrescan.web.websocket import WebSocketManager
        
        manager = WebSocketManager()
        mock_ws = AsyncMock()
        
        conn = await manager.connect(mock_ws)
        
        await manager.subscribe(conn.connection_id, "test-channel")
        assert "test-channel" in conn.subscriptions
        
        await manager.unsubscribe(conn.connection_id, "test-channel")
        assert "test-channel" not in conn.subscriptions
    
    @pytest.mark.asyncio
    async def test_broadcast_to_channel(self):
        """Test broadcasting to channel."""
        from spectrescan.web.websocket import WebSocketManager, WebSocketMessage, MessageType
        
        manager = WebSocketManager()
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        conn1 = await manager.connect(mock_ws1)
        conn2 = await manager.connect(mock_ws2)
        
        await manager.subscribe(conn1.connection_id, "updates")
        # conn2 is not subscribed
        
        msg = WebSocketMessage(MessageType.NOTIFICATION, {"text": "Test"})
        await manager.broadcast_to_channel("updates", msg)
        
        # Only subscribed connection should receive
        assert mock_ws1.send_text.called


class TestScanProgressHandler:
    """Test ScanProgressHandler class."""
    
    @pytest.mark.asyncio
    async def test_send_scan_progress(self):
        """Test sending scan progress."""
        from spectrescan.web.websocket import ScanProgressHandler, WebSocketManager
        
        manager = WebSocketManager()
        handler = ScanProgressHandler(manager)
        
        mock_ws = AsyncMock()
        conn = await manager.connect(mock_ws)
        await handler.subscribe_to_scan(conn.connection_id, "scan-123")
        
        await handler.send_scan_progress("scan-123", 50.0, 500, 1000, 10)
        
        assert mock_ws.send_text.called


# =============================================================================
# Web App Tests
# =============================================================================

class TestWebDashboard:
    """Test WebDashboard class."""
    
    def test_creation(self):
        """Test dashboard creation."""
        from spectrescan.web.app import WebDashboard, FASTAPI_AVAILABLE
        
        if not FASTAPI_AVAILABLE:
            pytest.skip("FastAPI not available")
        
        dashboard = WebDashboard(host="127.0.0.1", port=8080)
        
        assert dashboard.host == "127.0.0.1"
        assert dashboard.port == 8080
        assert dashboard.app is not None
    
    def test_calculate_dashboard_stats(self):
        """Test dashboard statistics calculation."""
        from spectrescan.web.app import WebDashboard, FASTAPI_AVAILABLE
        from spectrescan.web.models import ScanJob, ScanJobStatus
        
        if not FASTAPI_AVAILABLE:
            pytest.skip("FastAPI not available")
        
        dashboard = WebDashboard()
        
        # Add some test jobs
        dashboard._scan_jobs["job1"] = ScanJob(
            job_id="job1",
            name="Test 1",
            target="192.168.1.1",
            ports="1-100",
            status=ScanJobStatus.COMPLETED,
            created_at=datetime.now(),
            results_summary={"open_ports": 5},
        )
        dashboard._scan_jobs["job2"] = ScanJob(
            job_id="job2",
            name="Test 2",
            target="192.168.1.2",
            ports="1-100",
            status=ScanJobStatus.RUNNING,
            created_at=datetime.now(),
        )
        
        stats = dashboard._calculate_dashboard_stats()
        
        assert stats.total_scans == 2
        assert stats.active_scans == 1
        assert stats.completed_scans == 1
        assert stats.total_open_ports == 5
    
    def test_get_login_html(self):
        """Test login HTML generation."""
        from spectrescan.web.app import WebDashboard, FASTAPI_AVAILABLE
        
        if not FASTAPI_AVAILABLE:
            pytest.skip("FastAPI not available")
        
        dashboard = WebDashboard()
        html = dashboard._get_login_html()
        
        assert "SpectreScan" in html
        assert "login" in html.lower()
        assert "password" in html.lower()
    
    def test_get_dashboard_html(self):
        """Test dashboard HTML generation."""
        from spectrescan.web.app import WebDashboard, FASTAPI_AVAILABLE
        
        if not FASTAPI_AVAILABLE:
            pytest.skip("FastAPI not available")
        
        dashboard = WebDashboard()
        html = dashboard._get_dashboard_html()
        
        assert "SpectreScan" in html
        assert "Dashboard" in html
        assert "WebSocket" in html


class TestAPIRoutes:
    """Test API routes."""
    
    @pytest.fixture
    def client(self):
        """Create test client."""
        pytest.importorskip("httpx")
        try:
            from fastapi.testclient import TestClient
            from spectrescan.web.app import WebDashboard
            
            dashboard = WebDashboard()
            return TestClient(dashboard.app)
        except ImportError:
            pytest.skip("FastAPI TestClient not available")
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    def test_login_page(self, client):
        """Test login page."""
        response = client.get("/login")
        assert response.status_code == 200
        assert "SpectreScan" in response.text
    
    def test_dashboard_page(self, client):
        """Test dashboard page."""
        response = client.get("/")
        assert response.status_code == 200
        assert "SpectreScan" in response.text
    
    def test_login_success(self, client):
        """Test successful login."""
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data
        assert data["username"] == "admin"
    
    def test_login_failure(self, client):
        """Test failed login."""
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrongpassword"}
        )
        assert response.status_code == 401
    
    def test_dashboard_stats_unauthorized(self, client):
        """Test dashboard stats without auth."""
        response = client.get("/api/dashboard/stats")
        assert response.status_code in [401, 422]  # Unauthorized or missing header
    
    def test_dashboard_stats_authorized(self, client):
        """Test dashboard stats with auth."""
        # Login first
        login_response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        session_id = login_response.json()["session_id"]
        
        # Get stats
        response = client.get(
            "/api/dashboard/stats",
            headers={"X-Session-ID": session_id}
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
    
    def test_create_scan_authorized(self, client):
        """Test creating a scan."""
        # Login first
        login_response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        session_id = login_response.json()["session_id"]
        
        # Create scan
        response = client.post(
            "/api/scans",
            headers={"X-Session-ID": session_id},
            json={
                "name": "Test Scan",
                "target": "127.0.0.1",
                "ports": "80,443",
                "scan_type": "tcp"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Scan"
        assert data["target"] == "127.0.0.1"
    
    def test_list_scans(self, client):
        """Test listing scans."""
        # Login first
        login_response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin"}
        )
        session_id = login_response.json()["session_id"]
        
        # List scans
        response = client.get(
            "/api/scans",
            headers={"X-Session-ID": session_id}
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# =============================================================================
# Integration Tests
# =============================================================================

class TestWebDashboardIntegration:
    """Integration tests for web dashboard."""
    
    @pytest.mark.asyncio
    async def test_websocket_scan_updates(self):
        """Test WebSocket receives scan updates."""
        from spectrescan.web.websocket import (
            WebSocketManager,
            ScanProgressHandler,
            MessageType,
        )
        
        manager = WebSocketManager()
        handler = ScanProgressHandler(manager)
        
        received_messages = []
        
        # Create mock WebSocket
        mock_ws = AsyncMock()
        mock_ws.send_text = AsyncMock(
            side_effect=lambda msg: received_messages.append(json.loads(msg))
        )
        
        conn = await manager.connect(mock_ws)
        await handler.subscribe_to_scan(conn.connection_id, "scan-123")
        
        # Clear the connect message
        received_messages.clear()
        
        # Send progress updates
        await handler.send_scan_started("scan-123", "192.168.1.1", 1000)
        await handler.send_scan_progress("scan-123", 25.0, 250, 1000, 5)
        await handler.send_scan_result("scan-123", "192.168.1.1", 80, "open", "http")
        await handler.send_scan_completed("scan-123", {"open_ports": 5})
        
        assert len(received_messages) == 4
        assert received_messages[0]["type"] == "scan_started"
        assert received_messages[1]["type"] == "scan_progress"
        assert received_messages[2]["type"] == "scan_result"
        assert received_messages[3]["type"] == "scan_completed"
    
    def test_full_user_workflow(self):
        """Test complete user workflow."""
        from spectrescan.web.auth import UserManager, SessionManager, Role, Permission
        
        with tempfile.TemporaryDirectory() as tmpdir:
            user_mgr = UserManager(storage_dir=Path(tmpdir))
            session_mgr = SessionManager()
            
            # Create user
            user = user_mgr.create_user(
                "newoperator",
                "operator@example.com",
                "SecurePass123!",
                roles=[Role.OPERATOR]
            )
            
            # Authenticate
            auth_user = user_mgr.authenticate("newoperator", "SecurePass123!")
            assert auth_user is not None
            
            # Create session
            session = session_mgr.create_session(auth_user.user_id)
            assert session.is_valid()
            
            # Check permissions
            assert auth_user.has_permission(Permission.SCAN_READ)
            assert auth_user.has_permission(Permission.SCAN_EXECUTE)
            assert not auth_user.has_permission(Permission.ADMIN_SETTINGS)
            
            # Logout
            session_mgr.invalidate_session(session.session_id)
            assert session_mgr.get_session(session.session_id) is None
