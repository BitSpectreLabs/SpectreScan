"""
SpectreScan Web Dashboard Module.

Provides a web-based interface for scan management, real-time monitoring,
and interactive results visualization.

by BitSpectreLabs
"""

from spectrescan.web.models import (
    DashboardStats,
    ScanJob,
    ScanJobStatus,
    NetworkTopology,
    TopologyNode,
    TopologyEdge,
    UserPreferences,
    ThemeMode,
)
from spectrescan.web.auth import (
    User,
    Role,
    Permission,
    UserManager,
    RBACManager,
    SessionManager,
    Session,
    ROLE_PERMISSIONS,
    init_auth,
    get_user_manager,
    get_session_manager,
    get_rbac_manager,
    get_current_user,
    require_permission,
    require_role,
)
from spectrescan.web.websocket import (
    WebSocketManager,
    WebSocketMessage,
    MessageType,
    ScanProgressHandler,
    DashboardUpdater,
    ClusterUpdater,
    ConnectionInfo,
    get_websocket_manager,
    get_scan_progress_handler,
    get_dashboard_updater,
)
from spectrescan.web.app import (
    create_web_app,
    start_web_dashboard,
    WebDashboard,
)

__all__ = [
    # App
    "create_web_app",
    "start_web_dashboard",
    "WebDashboard",
    # Auth
    "User",
    "Role",
    "Permission",
    "Session",
    "UserManager",
    "RBACManager",
    "SessionManager",
    "ROLE_PERMISSIONS",
    "init_auth",
    "get_user_manager",
    "get_session_manager",
    "get_rbac_manager",
    "get_current_user",
    "require_permission",
    "require_role",
    # WebSocket
    "WebSocketManager",
    "WebSocketMessage",
    "MessageType",
    "ScanProgressHandler",
    "DashboardUpdater",
    "ClusterUpdater",
    "ConnectionInfo",
    "get_websocket_manager",
    "get_scan_progress_handler",
    "get_dashboard_updater",
    # Models
    "DashboardStats",
    "ScanJob",
    "ScanJobStatus",
    "NetworkTopology",
    "TopologyNode",
    "TopologyEdge",
    "UserPreferences",
    "ThemeMode",
]
