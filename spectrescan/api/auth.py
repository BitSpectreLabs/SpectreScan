"""
Authentication module for SpectreScan REST API.

Provides API key and JWT token authentication.

by BitSpectreLabs
"""

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# JWT implementation using standard library
import base64


@dataclass
class APIKey:
    """API key data structure."""
    
    key_id: str
    key_hash: str  # We store hash, not the actual key
    name: str
    scopes: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    is_active: bool = True
    
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def has_scope(self, scope: str) -> bool:
        """Check if the key has a specific scope."""
        if "*" in self.scopes:
            return True
        # Check for wildcard patterns
        for s in self.scopes:
            if s.endswith("*"):
                prefix = s[:-1]
                if scope.startswith(prefix):
                    return True
            elif s == scope:
                return True
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "key_id": self.key_id,
            "key_hash": self.key_hash,
            "name": self.name,
            "scopes": self.scopes,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "APIKey":
        """Create from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_hash=data["key_hash"],
            name=data["name"],
            scopes=data.get("scopes", []),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            is_active=data.get("is_active", True),
        )


@dataclass
class TokenPayload:
    """JWT token payload."""
    
    sub: str  # Subject (key_id)
    scopes: List[str]
    exp: int  # Expiration timestamp
    iat: int  # Issued at timestamp
    jti: str  # JWT ID
    
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return int(time.time()) > self.exp
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "sub": self.sub,
            "scopes": self.scopes,
            "exp": self.exp,
            "iat": self.iat,
            "jti": self.jti,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenPayload":
        """Create from dictionary."""
        return cls(
            sub=data["sub"],
            scopes=data.get("scopes", []),
            exp=data["exp"],
            iat=data["iat"],
            jti=data["jti"],
        )


class APIKeyAuth:
    """API key authentication manager."""
    
    DEFAULT_SCOPES = [
        "scan:read",
        "scan:write",
        "profile:read",
        "profile:write",
        "history:read",
        "history:write",
    ]
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize API key auth manager.
        
        Args:
            storage_path: Path to store API keys. Defaults to ~/.spectrescan/api_keys.json
        """
        if storage_path is None:
            storage_path = Path.home() / ".spectrescan" / "api_keys.json"
        self.storage_path = storage_path
        self._keys: Dict[str, APIKey] = {}
        self._load_keys()
    
    def _load_keys(self) -> None:
        """Load API keys from storage."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                    for key_data in data.get("keys", []):
                        key = APIKey.from_dict(key_data)
                        self._keys[key.key_id] = key
            except (json.JSONDecodeError, KeyError, ValueError):
                self._keys = {}
    
    def _save_keys(self) -> None:
        """Save API keys to storage."""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"keys": [k.to_dict() for k in self._keys.values()]}
        with open(self.storage_path, "w") as f:
            json.dump(data, f, indent=2)
    
    def _hash_key(self, api_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def create_key(
        self,
        name: str,
        scopes: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None,
    ) -> tuple[str, APIKey]:
        """
        Create a new API key.
        
        Args:
            name: Human-readable name for the key
            scopes: Permission scopes (defaults to DEFAULT_SCOPES)
            expires_in_days: Days until expiration (None = no expiration)
            
        Returns:
            Tuple of (api_key, APIKey object)
        """
        # Generate secure random key
        api_key = f"ss_{secrets.token_urlsafe(32)}"
        key_id = f"key_{secrets.token_urlsafe(8)}"
        
        if scopes is None:
            scopes = self.DEFAULT_SCOPES.copy()
        
        expires_at = None
        if expires_in_days is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
        
        key_obj = APIKey(
            key_id=key_id,
            key_hash=self._hash_key(api_key),
            name=name,
            scopes=scopes,
            expires_at=expires_at,
        )
        
        self._keys[key_id] = key_obj
        self._save_keys()
        
        return api_key, key_obj
    
    def verify_key(self, api_key: str) -> Optional[APIKey]:
        """
        Verify an API key.
        
        Args:
            api_key: The API key to verify
            
        Returns:
            APIKey object if valid, None otherwise
        """
        key_hash = self._hash_key(api_key)
        
        for key in self._keys.values():
            if key.key_hash == key_hash:
                if not key.is_active:
                    return None
                if key.is_expired():
                    return None
                return key
        
        return None
    
    def revoke_key(self, key_id: str) -> bool:
        """
        Revoke an API key.
        
        Args:
            key_id: The key ID to revoke
            
        Returns:
            True if key was revoked, False if not found
        """
        if key_id in self._keys:
            self._keys[key_id].is_active = False
            self._save_keys()
            return True
        return False
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete an API key.
        
        Args:
            key_id: The key ID to delete
            
        Returns:
            True if key was deleted, False if not found
        """
        if key_id in self._keys:
            del self._keys[key_id]
            self._save_keys()
            return True
        return False
    
    def list_keys(self) -> List[APIKey]:
        """List all API keys (without exposing hashes)."""
        return list(self._keys.values())
    
    def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get a specific API key by ID."""
        return self._keys.get(key_id)


class JWTAuth:
    """JWT authentication manager."""
    
    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = "HS256",
        token_expiry_seconds: int = 3600,
    ):
        """
        Initialize JWT auth manager.
        
        Args:
            secret_key: Secret key for signing tokens. If None, generates a random one.
            algorithm: JWT algorithm (only HS256 supported)
            token_expiry_seconds: Default token expiration time
        """
        if secret_key is None:
            # Try to load from config or generate new
            secret_key = self._load_or_generate_secret()
        
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expiry_seconds = token_expiry_seconds
        self._revoked_tokens: Set[str] = set()
    
    def _load_or_generate_secret(self) -> str:
        """Load secret from file or generate a new one."""
        secret_path = Path.home() / ".spectrescan" / "jwt_secret"
        
        if secret_path.exists():
            return secret_path.read_text().strip()
        
        # Generate new secret
        secret = secrets.token_urlsafe(64)
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        secret_path.write_text(secret)
        # Set restrictive permissions on Unix
        try:
            secret_path.chmod(0o600)
        except (OSError, AttributeError):
            pass  # Windows doesn't support chmod
        
        return secret
    
    def _base64url_encode(self, data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
    
    def _base64url_decode(self, data: str) -> bytes:
        """Base64url decode with padding restoration."""
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
    
    def _sign(self, message: str) -> str:
        """Create HMAC signature."""
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).digest()
        return self._base64url_encode(signature)
    
    def create_token(
        self,
        key_id: str,
        scopes: List[str],
        expiry_seconds: Optional[int] = None,
    ) -> str:
        """
        Create a JWT token.
        
        Args:
            key_id: Subject identifier (API key ID)
            scopes: Permission scopes
            expiry_seconds: Token expiration (defaults to self.token_expiry_seconds)
            
        Returns:
            JWT token string
        """
        if expiry_seconds is None:
            expiry_seconds = self.token_expiry_seconds
        
        now = int(time.time())
        
        payload = TokenPayload(
            sub=key_id,
            scopes=scopes,
            exp=now + expiry_seconds,
            iat=now,
            jti=secrets.token_urlsafe(16),
        )
        
        # Create JWT
        header = {"alg": self.algorithm, "typ": "JWT"}
        header_b64 = self._base64url_encode(json.dumps(header).encode())
        payload_b64 = self._base64url_encode(json.dumps(payload.to_dict()).encode())
        
        message = f"{header_b64}.{payload_b64}"
        signature = self._sign(message)
        
        return f"{message}.{signature}"
    
    def verify_token(self, token: str) -> Optional[TokenPayload]:
        """
        Verify a JWT token.
        
        Args:
            token: JWT token string
            
        Returns:
            TokenPayload if valid, None otherwise
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            
            header_b64, payload_b64, signature = parts
            
            # Verify signature
            message = f"{header_b64}.{payload_b64}"
            expected_signature = self._sign(message)
            
            if not hmac.compare_digest(signature, expected_signature):
                return None
            
            # Decode payload
            payload_json = self._base64url_decode(payload_b64).decode()
            payload_data = json.loads(payload_json)
            
            payload = TokenPayload.from_dict(payload_data)
            
            # Check expiration
            if payload.is_expired():
                return None
            
            # Check if revoked
            if payload.jti in self._revoked_tokens:
                return None
            
            return payload
            
        except (ValueError, KeyError, json.JSONDecodeError):
            return None
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a JWT token.
        
        Args:
            token: JWT token to revoke
            
        Returns:
            True if token was valid and revoked
        """
        payload = self.verify_token(token)
        if payload:
            self._revoked_tokens.add(payload.jti)
            return True
        return False


# =============================================================================
# Authentication Dependencies (for FastAPI)
# =============================================================================


# Global instances (initialized when app starts)
_api_key_auth: Optional[APIKeyAuth] = None
_jwt_auth: Optional[JWTAuth] = None


def init_auth(
    api_key_storage: Optional[Path] = None,
    jwt_secret: Optional[str] = None,
) -> tuple[APIKeyAuth, JWTAuth]:
    """Initialize authentication managers."""
    global _api_key_auth, _jwt_auth
    
    _api_key_auth = APIKeyAuth(storage_path=api_key_storage)
    _jwt_auth = JWTAuth(secret_key=jwt_secret)
    
    return _api_key_auth, _jwt_auth


def get_api_key_auth() -> APIKeyAuth:
    """Get the API key auth manager."""
    global _api_key_auth
    if _api_key_auth is None:
        _api_key_auth = APIKeyAuth()
    return _api_key_auth


def get_jwt_auth() -> JWTAuth:
    """Get the JWT auth manager."""
    global _jwt_auth
    if _jwt_auth is None:
        _jwt_auth = JWTAuth()
    return _jwt_auth


def verify_api_key(api_key: str) -> Optional[APIKey]:
    """
    Verify an API key.
    
    Args:
        api_key: API key string
        
    Returns:
        APIKey if valid, None otherwise
    """
    auth = get_api_key_auth()
    return auth.verify_key(api_key)


def create_access_token(api_key: str) -> Optional[tuple[str, int]]:
    """
    Create a JWT access token from an API key.
    
    Args:
        api_key: Valid API key
        
    Returns:
        Tuple of (token, expires_in_seconds) if valid, None otherwise
    """
    api_key_auth = get_api_key_auth()
    jwt_auth = get_jwt_auth()
    
    key = api_key_auth.verify_key(api_key)
    if key is None:
        return None
    
    token = jwt_auth.create_token(key.key_id, key.scopes)
    return token, jwt_auth.token_expiry_seconds


def get_current_user(token: str) -> Optional[TokenPayload]:
    """
    Get current user from JWT token.
    
    Args:
        token: JWT token (without 'Bearer ' prefix)
        
    Returns:
        TokenPayload if valid, None otherwise
    """
    jwt_auth = get_jwt_auth()
    return jwt_auth.verify_token(token)


def require_scope(payload: TokenPayload, scope: str) -> bool:
    """
    Check if token has required scope.
    
    Args:
        payload: Token payload
        scope: Required scope
        
    Returns:
        True if scope is present
    """
    if "*" in payload.scopes:
        return True
    
    for s in payload.scopes:
        if s.endswith("*"):
            prefix = s[:-1]
            if scope.startswith(prefix):
                return True
        elif s == scope:
            return True
    
    return False
