"""
SpectreScan REST API Module.

FastAPI-based HTTP server for SpectreScan port scanner.
Provides REST endpoints for scan operations, profile management,
history access, and WebSocket support for real-time updates.

by BitSpectreLabs
"""

from spectrescan.api.main import create_app, get_app
from spectrescan.api.models import (
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanResultResponse,
    ProfileRequest,
    ProfileResponse,
    HistoryResponse,
    ErrorResponse,
    TokenResponse,
    APIKeyRequest,
)
from spectrescan.api.auth import (
    APIKeyAuth,
    JWTAuth,
    verify_api_key,
    create_access_token,
    get_current_user,
)

__all__ = [
    # Application
    "create_app",
    "get_app",
    # Models
    "ScanRequest",
    "ScanResponse",
    "ScanStatus",
    "ScanResultResponse",
    "ProfileRequest",
    "ProfileResponse",
    "HistoryResponse",
    "ErrorResponse",
    "TokenResponse",
    "APIKeyRequest",
    # Auth
    "APIKeyAuth",
    "JWTAuth",
    "verify_api_key",
    "create_access_token",
    "get_current_user",
]
