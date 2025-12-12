"""
Authentication and Authorization for SpectreScan Web Dashboard.

Implements OAuth2, session management, RBAC (Role-Based Access Control),
and user management.

by BitSpectreLabs
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
import functools

logger = logging.getLogger(__name__)


class Permission(str, Enum):
    """Permissions for RBAC."""
    # Scan permissions
    SCAN_READ = "scan:read"
    SCAN_WRITE = "scan:write"
    SCAN_DELETE = "scan:delete"
    SCAN_EXECUTE = "scan:execute"
    
    # Profile permissions
    PROFILE_READ = "profile:read"
    PROFILE_WRITE = "profile:write"
    PROFILE_DELETE = "profile:delete"
    
    # History permissions
    HISTORY_READ = "history:read"
    HISTORY_WRITE = "history:write"
    HISTORY_DELETE = "history:delete"
    
    # User management
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    
    # Admin permissions
    ADMIN_SETTINGS = "admin:settings"
    ADMIN_USERS = "admin:users"
    ADMIN_SYSTEM = "admin:system"
    
    # Dashboard permissions
    DASHBOARD_VIEW = "dashboard:view"
    DASHBOARD_EDIT = "dashboard:edit"
    
    # Cluster permissions
    CLUSTER_READ = "cluster:read"
    CLUSTER_WRITE = "cluster:write"
    CLUSTER_ADMIN = "cluster:admin"


class Role(str, Enum):
    """Predefined roles."""
    VIEWER = "viewer"
    OPERATOR = "operator"
    ANALYST = "analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


# Role to permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.VIEWER: {
        Permission.SCAN_READ,
        Permission.PROFILE_READ,
        Permission.HISTORY_READ,
        Permission.DASHBOARD_VIEW,
    },
    Role.OPERATOR: {
        Permission.SCAN_READ,
        Permission.SCAN_WRITE,
        Permission.SCAN_EXECUTE,
        Permission.PROFILE_READ,
        Permission.PROFILE_WRITE,
        Permission.HISTORY_READ,
        Permission.DASHBOARD_VIEW,
        Permission.CLUSTER_READ,
    },
    Role.ANALYST: {
        Permission.SCAN_READ,
        Permission.SCAN_WRITE,
        Permission.SCAN_EXECUTE,
        Permission.PROFILE_READ,
        Permission.PROFILE_WRITE,
        Permission.PROFILE_DELETE,
        Permission.HISTORY_READ,
        Permission.HISTORY_WRITE,
        Permission.DASHBOARD_VIEW,
        Permission.DASHBOARD_EDIT,
        Permission.CLUSTER_READ,
    },
    Role.ADMIN: {
        Permission.SCAN_READ,
        Permission.SCAN_WRITE,
        Permission.SCAN_DELETE,
        Permission.SCAN_EXECUTE,
        Permission.PROFILE_READ,
        Permission.PROFILE_WRITE,
        Permission.PROFILE_DELETE,
        Permission.HISTORY_READ,
        Permission.HISTORY_WRITE,
        Permission.HISTORY_DELETE,
        Permission.USER_READ,
        Permission.USER_WRITE,
        Permission.DASHBOARD_VIEW,
        Permission.DASHBOARD_EDIT,
        Permission.ADMIN_SETTINGS,
        Permission.CLUSTER_READ,
        Permission.CLUSTER_WRITE,
    },
    Role.SUPER_ADMIN: set(Permission),  # All permissions
}


@dataclass
class User:
    """User account."""
    user_id: str
    username: str
    email: str
    password_hash: str
    roles: List[Role] = field(default_factory=list)
    permissions: Set[Permission] = field(default_factory=set)
    is_active: bool = True
    is_verified: bool = False
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize timestamps."""
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def get_all_permissions(self) -> Set[Permission]:
        """Get all permissions from roles and direct permissions."""
        all_perms = set(self.permissions)
        for role in self.roles:
            all_perms.update(ROLE_PERMISSIONS.get(role, set()))
        return all_perms
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        return permission in self.get_all_permissions()
    
    def has_role(self, role: Role) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def is_locked(self) -> bool:
        """Check if account is locked."""
        if self.locked_until is None:
            return False
        return datetime.now() < self.locked_until
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "roles": [r.value for r in self.roles],
            "permissions": [p.value for p in self.permissions],
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "metadata": self.metadata,
        }
        if include_sensitive:
            data["password_hash"] = self.password_hash
            data["failed_login_attempts"] = self.failed_login_attempts
            data["locked_until"] = self.locked_until.isoformat() if self.locked_until else None
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create from dictionary."""
        return cls(
            user_id=data["user_id"],
            username=data["username"],
            email=data["email"],
            password_hash=data.get("password_hash", ""),
            roles=[Role(r) for r in data.get("roles", [])],
            permissions={Permission(p) for p in data.get("permissions", [])},
            is_active=data.get("is_active", True),
            is_verified=data.get("is_verified", False),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            last_login=datetime.fromisoformat(data["last_login"]) if data.get("last_login") else None,
            failed_login_attempts=data.get("failed_login_attempts", 0),
            locked_until=datetime.fromisoformat(data["locked_until"]) if data.get("locked_until") else None,
            metadata=data.get("metadata", {}),
        )


@dataclass
class Session:
    """User session."""
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool = True
    last_activity: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if session is valid."""
        return self.is_active and not self.is_expired()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "is_active": self.is_active,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            is_active=data.get("is_active", True),
            last_activity=datetime.fromisoformat(data["last_activity"]) if data.get("last_activity") else None,
            metadata=data.get("metadata", {}),
        )


class UserManager:
    """Manages user accounts."""
    
    def __init__(self, storage_dir: Optional[Path] = None):
        """Initialize user manager."""
        self.storage_dir = storage_dir or Path.home() / ".spectrescan" / "web" / "users"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._users: Dict[str, User] = {}
        self._users_by_username: Dict[str, str] = {}
        self._users_by_email: Dict[str, str] = {}
        self._load_users()
    
    def _load_users(self) -> None:
        """Load users from storage."""
        users_file = self.storage_dir / "users.json"
        if users_file.exists():
            try:
                with open(users_file, "r") as f:
                    data = json.load(f)
                for user_data in data.get("users", []):
                    user = User.from_dict(user_data)
                    self._users[user.user_id] = user
                    self._users_by_username[user.username.lower()] = user.user_id
                    self._users_by_email[user.email.lower()] = user.user_id
                logger.info(f"Loaded {len(self._users)} users")
            except Exception as e:
                logger.error(f"Failed to load users: {e}")
    
    def _save_users(self) -> None:
        """Save users to storage."""
        users_file = self.storage_dir / "users.json"
        try:
            data = {
                "users": [u.to_dict(include_sensitive=True) for u in self._users.values()]
            }
            with open(users_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
    
    @staticmethod
    def hash_password(password: str, salt: Optional[str] = None) -> str:
        """Hash a password with salt."""
        if salt is None:
            salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            100000
        )
        return f"{salt}${hash_obj.hex()}"
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        try:
            salt, stored_hash = password_hash.split("$")
            computed_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                salt.encode(),
                100000
            ).hex()
            return hmac.compare_digest(computed_hash, stored_hash)
        except (ValueError, AttributeError):
            return False
    
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: Optional[List[Role]] = None,
    ) -> User:
        """Create a new user."""
        # Check for existing user
        if username.lower() in self._users_by_username:
            raise ValueError(f"Username '{username}' already exists")
        if email.lower() in self._users_by_email:
            raise ValueError(f"Email '{email}' already exists")
        
        user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            email=email,
            password_hash=self.hash_password(password),
            roles=roles or [Role.VIEWER],
            created_at=datetime.now(),
        )
        
        self._users[user.user_id] = user
        self._users_by_username[username.lower()] = user.user_id
        self._users_by_email[email.lower()] = user.user_id
        self._save_users()
        
        logger.info(f"Created user: {username}")
        return user
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self._users.get(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        user_id = self._users_by_username.get(username.lower())
        return self._users.get(user_id) if user_id else None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        user_id = self._users_by_email.get(email.lower())
        return self._users.get(user_id) if user_id else None
    
    def authenticate(self, username_or_email: str, password: str) -> Optional[User]:
        """Authenticate a user."""
        # Try username first
        user = self.get_user_by_username(username_or_email)
        if not user:
            user = self.get_user_by_email(username_or_email)
        
        if not user:
            return None
        
        # Check if locked
        if user.is_locked():
            logger.warning(f"Login attempt for locked account: {user.username}")
            return None
        
        # Check if active
        if not user.is_active:
            logger.warning(f"Login attempt for inactive account: {user.username}")
            return None
        
        # Verify password
        if not self.verify_password(password, user.password_hash):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now() + timedelta(minutes=15)
                logger.warning(f"Account locked due to failed attempts: {user.username}")
            self._save_users()
            return None
        
        # Success - reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now()
        self._save_users()
        
        logger.info(f"User authenticated: {user.username}")
        return user
    
    def update_user(self, user_id: str, **kwargs) -> Optional[User]:
        """Update user attributes."""
        user = self._users.get(user_id)
        if not user:
            return None
        
        # Handle password change
        if "password" in kwargs:
            kwargs["password_hash"] = self.hash_password(kwargs.pop("password"))
        
        # Update attributes
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        
        self._save_users()
        return user
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a user."""
        user = self._users.get(user_id)
        if not user:
            return False
        
        del self._users[user_id]
        del self._users_by_username[user.username.lower()]
        del self._users_by_email[user.email.lower()]
        self._save_users()
        
        logger.info(f"Deleted user: {user.username}")
        return True
    
    def list_users(self, include_inactive: bool = False) -> List[User]:
        """List all users."""
        users = list(self._users.values())
        if not include_inactive:
            users = [u for u in users if u.is_active]
        return users
    
    def assign_role(self, user_id: str, role: Role) -> bool:
        """Assign a role to a user."""
        user = self._users.get(user_id)
        if not user:
            return False
        
        if role not in user.roles:
            user.roles.append(role)
            self._save_users()
        return True
    
    def remove_role(self, user_id: str, role: Role) -> bool:
        """Remove a role from a user."""
        user = self._users.get(user_id)
        if not user:
            return False
        
        if role in user.roles:
            user.roles.remove(role)
            self._save_users()
        return True


class SessionManager:
    """Manages user sessions."""
    
    def __init__(
        self,
        session_duration: int = 3600,
        max_sessions_per_user: int = 5,
    ):
        """Initialize session manager."""
        self.session_duration = session_duration
        self.max_sessions_per_user = max_sessions_per_user
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, List[str]] = {}
    
    def create_session(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """Create a new session."""
        # Clean up expired sessions first
        self._cleanup_expired()
        
        # Check max sessions per user
        user_session_ids = self._user_sessions.get(user_id, [])
        if len(user_session_ids) >= self.max_sessions_per_user:
            # Remove oldest session
            oldest_id = user_session_ids[0]
            self.invalidate_session(oldest_id)
        
        session = Session(
            session_id=secrets.token_urlsafe(32),
            user_id=user_id,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(seconds=self.session_duration),
            ip_address=ip_address,
            user_agent=user_agent,
            last_activity=datetime.now(),
        )
        
        self._sessions[session.session_id] = session
        if user_id not in self._user_sessions:
            self._user_sessions[user_id] = []
        self._user_sessions[user_id].append(session.session_id)
        
        logger.debug(f"Created session for user {user_id}")
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        session = self._sessions.get(session_id)
        if session and session.is_valid():
            session.last_activity = datetime.now()
            return session
        return None
    
    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate a session."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        
        session.is_active = False
        del self._sessions[session_id]
        
        if session.user_id in self._user_sessions:
            self._user_sessions[session.user_id] = [
                sid for sid in self._user_sessions[session.user_id]
                if sid != session_id
            ]
        
        logger.debug(f"Invalidated session {session_id}")
        return True
    
    def invalidate_user_sessions(self, user_id: str) -> int:
        """Invalidate all sessions for a user."""
        session_ids = self._user_sessions.get(user_id, []).copy()
        for session_id in session_ids:
            self.invalidate_session(session_id)
        return len(session_ids)
    
    def extend_session(self, session_id: str, duration: Optional[int] = None) -> bool:
        """Extend a session's expiration."""
        session = self._sessions.get(session_id)
        if not session or not session.is_valid():
            return False
        
        extension = duration or self.session_duration
        session.expires_at = datetime.now() + timedelta(seconds=extension)
        session.last_activity = datetime.now()
        return True
    
    def _cleanup_expired(self) -> int:
        """Remove expired sessions."""
        expired = [
            sid for sid, session in self._sessions.items()
            if session.is_expired()
        ]
        for session_id in expired:
            self.invalidate_session(session_id)
        return len(expired)
    
    def get_user_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user."""
        session_ids = self._user_sessions.get(user_id, [])
        return [
            self._sessions[sid] for sid in session_ids
            if sid in self._sessions and self._sessions[sid].is_valid()
        ]


class RBACManager:
    """Role-Based Access Control manager."""
    
    def __init__(self, user_manager: UserManager):
        """Initialize RBAC manager."""
        self.user_manager = user_manager
        self._custom_roles: Dict[str, Set[Permission]] = {}
    
    def create_custom_role(self, role_name: str, permissions: Set[Permission]) -> bool:
        """Create a custom role."""
        if role_name in self._custom_roles:
            return False
        self._custom_roles[role_name] = permissions
        return True
    
    def delete_custom_role(self, role_name: str) -> bool:
        """Delete a custom role."""
        if role_name not in self._custom_roles:
            return False
        del self._custom_roles[role_name]
        return True
    
    def get_role_permissions(self, role: Role) -> Set[Permission]:
        """Get permissions for a role."""
        return ROLE_PERMISSIONS.get(role, set())
    
    def check_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has permission."""
        return user.has_permission(permission)
    
    def check_role(self, user: User, role: Role) -> bool:
        """Check if user has role."""
        return user.has_role(role)
    
    def get_user_permissions(self, user: User) -> Set[Permission]:
        """Get all permissions for a user."""
        return user.get_all_permissions()


# Global instances
_user_manager: Optional[UserManager] = None
_session_manager: Optional[SessionManager] = None
_rbac_manager: Optional[RBACManager] = None


def init_auth(storage_dir: Optional[Path] = None) -> None:
    """Initialize authentication system."""
    global _user_manager, _session_manager, _rbac_manager
    _user_manager = UserManager(storage_dir)
    _session_manager = SessionManager()
    _rbac_manager = RBACManager(_user_manager)
    logger.info("Web authentication initialized")


def get_user_manager() -> UserManager:
    """Get the user manager instance."""
    global _user_manager
    if _user_manager is None:
        init_auth()
    return _user_manager


def get_session_manager() -> SessionManager:
    """Get the session manager instance."""
    global _session_manager
    if _session_manager is None:
        init_auth()
    return _session_manager


def get_rbac_manager() -> RBACManager:
    """Get the RBAC manager instance."""
    global _rbac_manager
    if _rbac_manager is None:
        init_auth()
    return _rbac_manager


def get_current_user(session_id: str) -> Optional[User]:
    """Get the current user from session."""
    session_mgr = get_session_manager()
    user_mgr = get_user_manager()
    
    session = session_mgr.get_session(session_id)
    if not session:
        return None
    
    return user_mgr.get_user(session.user_id)


def require_permission(permission: Permission) -> Callable:
    """Decorator to require a specific permission."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, user: User = None, **kwargs):
            if user is None:
                raise PermissionError("Authentication required")
            if not user.has_permission(permission):
                raise PermissionError(f"Permission denied: {permission.value}")
            return func(*args, user=user, **kwargs)
        return wrapper
    return decorator


def require_role(role: Role) -> Callable:
    """Decorator to require a specific role."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, user: User = None, **kwargs):
            if user is None:
                raise PermissionError("Authentication required")
            if not user.has_role(role):
                raise PermissionError(f"Role required: {role.value}")
            return func(*args, user=user, **kwargs)
        return wrapper
    return decorator
