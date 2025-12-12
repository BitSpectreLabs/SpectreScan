"""
WebSocket Manager for SpectreScan Web Dashboard.

Provides real-time updates for scan progress, results, and system notifications.

by BitSpectreLabs
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set
import weakref

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """WebSocket message types."""
    # Connection messages
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    PING = "ping"
    PONG = "pong"
    
    # Scan messages
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_RESULT = "scan_result"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    
    # System messages
    NOTIFICATION = "notification"
    ALERT = "alert"
    ERROR = "error"
    
    # Cluster messages
    WORKER_JOINED = "worker_joined"
    WORKER_LEFT = "worker_left"
    CLUSTER_STATUS = "cluster_status"
    
    # Dashboard messages
    STATS_UPDATE = "stats_update"
    TOPOLOGY_UPDATE = "topology_update"


@dataclass
class WebSocketMessage:
    """WebSocket message structure."""
    message_type: MessageType
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
            "message_id": self.message_id,
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WebSocketMessage":
        """Create from dictionary."""
        return cls(
            message_type=MessageType(data["type"]),
            payload=data.get("payload", {}),
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.now(),
            message_id=data.get("message_id", str(uuid.uuid4())),
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> "WebSocketMessage":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ConnectionInfo:
    """WebSocket connection information."""
    connection_id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    connected_at: datetime = field(default_factory=datetime.now)
    last_ping: Optional[datetime] = None
    subscriptions: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "connection_id": self.connection_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "connected_at": self.connected_at.isoformat(),
            "last_ping": self.last_ping.isoformat() if self.last_ping else None,
            "subscriptions": list(self.subscriptions),
            "metadata": self.metadata,
        }


class WebSocketManager:
    """Manages WebSocket connections and message broadcasting."""
    
    def __init__(self):
        """Initialize WebSocket manager."""
        self._connections: Dict[str, Any] = {}  # connection_id -> websocket
        self._connection_info: Dict[str, ConnectionInfo] = {}
        self._subscriptions: Dict[str, Set[str]] = {}  # channel -> connection_ids
        self._user_connections: Dict[str, Set[str]] = {}  # user_id -> connection_ids
        self._message_handlers: Dict[MessageType, List[Callable]] = {}
        self._lock = asyncio.Lock()
    
    async def connect(
        self,
        websocket: Any,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ConnectionInfo:
        """Register a new WebSocket connection."""
        connection_id = str(uuid.uuid4())
        
        async with self._lock:
            self._connections[connection_id] = websocket
            
            info = ConnectionInfo(
                connection_id=connection_id,
                user_id=user_id,
                session_id=session_id,
            )
            self._connection_info[connection_id] = info
            
            # Track user connections
            if user_id:
                if user_id not in self._user_connections:
                    self._user_connections[user_id] = set()
                self._user_connections[user_id].add(connection_id)
            
            logger.info(f"WebSocket connected: {connection_id}")
        
        # Send connection confirmation
        await self.send_to_connection(
            connection_id,
            WebSocketMessage(
                message_type=MessageType.CONNECT,
                payload={"connection_id": connection_id}
            )
        )
        
        return info
    
    async def disconnect(self, connection_id: str) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            if connection_id not in self._connections:
                return
            
            info = self._connection_info.get(connection_id)
            
            # Remove from subscriptions
            for channel in list(self._subscriptions.keys()):
                self._subscriptions[channel].discard(connection_id)
                if not self._subscriptions[channel]:
                    del self._subscriptions[channel]
            
            # Remove from user connections
            if info and info.user_id and info.user_id in self._user_connections:
                self._user_connections[info.user_id].discard(connection_id)
                if not self._user_connections[info.user_id]:
                    del self._user_connections[info.user_id]
            
            # Remove connection
            del self._connections[connection_id]
            if connection_id in self._connection_info:
                del self._connection_info[connection_id]
            
            logger.info(f"WebSocket disconnected: {connection_id}")
    
    async def subscribe(self, connection_id: str, channel: str) -> bool:
        """Subscribe a connection to a channel."""
        async with self._lock:
            if connection_id not in self._connections:
                return False
            
            if channel not in self._subscriptions:
                self._subscriptions[channel] = set()
            self._subscriptions[channel].add(connection_id)
            
            info = self._connection_info.get(connection_id)
            if info:
                info.subscriptions.add(channel)
            
            logger.debug(f"Connection {connection_id} subscribed to {channel}")
            return True
    
    async def unsubscribe(self, connection_id: str, channel: str) -> bool:
        """Unsubscribe a connection from a channel."""
        async with self._lock:
            if channel in self._subscriptions:
                self._subscriptions[channel].discard(connection_id)
                if not self._subscriptions[channel]:
                    del self._subscriptions[channel]
            
            info = self._connection_info.get(connection_id)
            if info:
                info.subscriptions.discard(channel)
            
            logger.debug(f"Connection {connection_id} unsubscribed from {channel}")
            return True
    
    async def send_to_connection(
        self,
        connection_id: str,
        message: WebSocketMessage,
    ) -> bool:
        """Send a message to a specific connection."""
        websocket = self._connections.get(connection_id)
        if not websocket:
            return False
        
        try:
            await websocket.send_text(message.to_json())
            return True
        except Exception as e:
            logger.error(f"Failed to send to {connection_id}: {e}")
            await self.disconnect(connection_id)
            return False
    
    async def send_to_user(
        self,
        user_id: str,
        message: WebSocketMessage,
    ) -> int:
        """Send a message to all connections of a user."""
        connection_ids = self._user_connections.get(user_id, set()).copy()
        sent = 0
        for conn_id in connection_ids:
            if await self.send_to_connection(conn_id, message):
                sent += 1
        return sent
    
    async def broadcast_to_channel(
        self,
        channel: str,
        message: WebSocketMessage,
    ) -> int:
        """Broadcast a message to all subscribers of a channel."""
        connection_ids = self._subscriptions.get(channel, set()).copy()
        sent = 0
        for conn_id in connection_ids:
            if await self.send_to_connection(conn_id, message):
                sent += 1
        return sent
    
    async def broadcast_all(self, message: WebSocketMessage) -> int:
        """Broadcast a message to all connections."""
        connection_ids = list(self._connections.keys())
        sent = 0
        for conn_id in connection_ids:
            if await self.send_to_connection(conn_id, message):
                sent += 1
        return sent
    
    def register_handler(
        self,
        message_type: MessageType,
        handler: Callable,
    ) -> None:
        """Register a handler for a message type."""
        if message_type not in self._message_handlers:
            self._message_handlers[message_type] = []
        self._message_handlers[message_type].append(handler)
    
    async def handle_message(
        self,
        connection_id: str,
        message: WebSocketMessage,
    ) -> None:
        """Handle an incoming message."""
        handlers = self._message_handlers.get(message.message_type, [])
        info = self._connection_info.get(connection_id)
        
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(connection_id, message, info)
                else:
                    handler(connection_id, message, info)
            except Exception as e:
                logger.error(f"Handler error for {message.message_type}: {e}")
    
    async def ping_connection(self, connection_id: str) -> bool:
        """Send a ping to a connection."""
        result = await self.send_to_connection(
            connection_id,
            WebSocketMessage(
                message_type=MessageType.PING,
                payload={"timestamp": time.time()}
            )
        )
        if result:
            info = self._connection_info.get(connection_id)
            if info:
                info.last_ping = datetime.now()
        return result
    
    def get_connection_info(self, connection_id: str) -> Optional[ConnectionInfo]:
        """Get connection information."""
        return self._connection_info.get(connection_id)
    
    def get_connection_count(self) -> int:
        """Get total number of connections."""
        return len(self._connections)
    
    def get_channel_subscribers(self, channel: str) -> Set[str]:
        """Get connection IDs subscribed to a channel."""
        return self._subscriptions.get(channel, set()).copy()
    
    def get_user_connection_count(self, user_id: str) -> int:
        """Get number of connections for a user."""
        return len(self._user_connections.get(user_id, set()))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics."""
        return {
            "total_connections": len(self._connections),
            "total_subscriptions": sum(len(s) for s in self._subscriptions.values()),
            "channels": list(self._subscriptions.keys()),
            "users_connected": len(self._user_connections),
        }


class ScanProgressHandler:
    """Handler for scan progress updates via WebSocket."""
    
    def __init__(self, ws_manager: WebSocketManager):
        """Initialize scan progress handler."""
        self.ws_manager = ws_manager
        self._scan_subscribers: Dict[str, Set[str]] = {}  # scan_id -> connection_ids
    
    async def subscribe_to_scan(self, connection_id: str, scan_id: str) -> bool:
        """Subscribe a connection to scan updates."""
        channel = f"scan:{scan_id}"
        await self.ws_manager.subscribe(connection_id, channel)
        
        if scan_id not in self._scan_subscribers:
            self._scan_subscribers[scan_id] = set()
        self._scan_subscribers[scan_id].add(connection_id)
        
        return True
    
    async def unsubscribe_from_scan(self, connection_id: str, scan_id: str) -> bool:
        """Unsubscribe a connection from scan updates."""
        channel = f"scan:{scan_id}"
        await self.ws_manager.unsubscribe(connection_id, channel)
        
        if scan_id in self._scan_subscribers:
            self._scan_subscribers[scan_id].discard(connection_id)
            if not self._scan_subscribers[scan_id]:
                del self._scan_subscribers[scan_id]
        
        return True
    
    async def send_scan_started(
        self,
        scan_id: str,
        target: str,
        total_ports: int,
    ) -> int:
        """Send scan started notification."""
        message = WebSocketMessage(
            message_type=MessageType.SCAN_STARTED,
            payload={
                "scan_id": scan_id,
                "target": target,
                "total_ports": total_ports,
            }
        )
        return await self.ws_manager.broadcast_to_channel(f"scan:{scan_id}", message)
    
    async def send_scan_progress(
        self,
        scan_id: str,
        progress: float,
        scanned_ports: int,
        total_ports: int,
        open_ports: int,
        eta_seconds: Optional[float] = None,
    ) -> int:
        """Send scan progress update."""
        message = WebSocketMessage(
            message_type=MessageType.SCAN_PROGRESS,
            payload={
                "scan_id": scan_id,
                "progress": progress,
                "scanned_ports": scanned_ports,
                "total_ports": total_ports,
                "open_ports": open_ports,
                "eta_seconds": eta_seconds,
            }
        )
        return await self.ws_manager.broadcast_to_channel(f"scan:{scan_id}", message)
    
    async def send_scan_result(
        self,
        scan_id: str,
        host: str,
        port: int,
        state: str,
        service: Optional[str] = None,
        banner: Optional[str] = None,
    ) -> int:
        """Send individual scan result."""
        message = WebSocketMessage(
            message_type=MessageType.SCAN_RESULT,
            payload={
                "scan_id": scan_id,
                "host": host,
                "port": port,
                "state": state,
                "service": service,
                "banner": banner,
            }
        )
        return await self.ws_manager.broadcast_to_channel(f"scan:{scan_id}", message)
    
    async def send_scan_completed(
        self,
        scan_id: str,
        summary: Dict[str, Any],
    ) -> int:
        """Send scan completed notification."""
        message = WebSocketMessage(
            message_type=MessageType.SCAN_COMPLETED,
            payload={
                "scan_id": scan_id,
                "summary": summary,
            }
        )
        return await self.ws_manager.broadcast_to_channel(f"scan:{scan_id}", message)
    
    async def send_scan_failed(
        self,
        scan_id: str,
        error: str,
    ) -> int:
        """Send scan failed notification."""
        message = WebSocketMessage(
            message_type=MessageType.SCAN_FAILED,
            payload={
                "scan_id": scan_id,
                "error": error,
            }
        )
        return await self.ws_manager.broadcast_to_channel(f"scan:{scan_id}", message)
    
    async def send_scan_cancelled(self, scan_id: str) -> int:
        """Send scan cancelled notification."""
        message = WebSocketMessage(
            message_type=MessageType.SCAN_CANCELLED,
            payload={"scan_id": scan_id}
        )
        return await self.ws_manager.broadcast_to_channel(f"scan:{scan_id}", message)


class DashboardUpdater:
    """Handler for dashboard real-time updates."""
    
    DASHBOARD_CHANNEL = "dashboard"
    
    def __init__(self, ws_manager: WebSocketManager):
        """Initialize dashboard updater."""
        self.ws_manager = ws_manager
    
    async def subscribe(self, connection_id: str) -> bool:
        """Subscribe to dashboard updates."""
        return await self.ws_manager.subscribe(connection_id, self.DASHBOARD_CHANNEL)
    
    async def unsubscribe(self, connection_id: str) -> bool:
        """Unsubscribe from dashboard updates."""
        return await self.ws_manager.unsubscribe(connection_id, self.DASHBOARD_CHANNEL)
    
    async def send_stats_update(self, stats: Dict[str, Any]) -> int:
        """Send dashboard statistics update."""
        message = WebSocketMessage(
            message_type=MessageType.STATS_UPDATE,
            payload=stats
        )
        return await self.ws_manager.broadcast_to_channel(self.DASHBOARD_CHANNEL, message)
    
    async def send_topology_update(self, topology: Dict[str, Any]) -> int:
        """Send topology update."""
        message = WebSocketMessage(
            message_type=MessageType.TOPOLOGY_UPDATE,
            payload=topology
        )
        return await self.ws_manager.broadcast_to_channel(self.DASHBOARD_CHANNEL, message)
    
    async def send_notification(
        self,
        title: str,
        message_text: str,
        severity: str = "info",
    ) -> int:
        """Send notification to dashboard."""
        message = WebSocketMessage(
            message_type=MessageType.NOTIFICATION,
            payload={
                "title": title,
                "message": message_text,
                "severity": severity,
            }
        )
        return await self.ws_manager.broadcast_to_channel(self.DASHBOARD_CHANNEL, message)
    
    async def send_alert(
        self,
        alert_id: str,
        title: str,
        message_text: str,
        severity: str = "warning",
        data: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Send alert to dashboard."""
        message = WebSocketMessage(
            message_type=MessageType.ALERT,
            payload={
                "alert_id": alert_id,
                "title": title,
                "message": message_text,
                "severity": severity,
                "data": data or {},
            }
        )
        return await self.ws_manager.broadcast_to_channel(self.DASHBOARD_CHANNEL, message)


class ClusterUpdater:
    """Handler for cluster status updates."""
    
    CLUSTER_CHANNEL = "cluster"
    
    def __init__(self, ws_manager: WebSocketManager):
        """Initialize cluster updater."""
        self.ws_manager = ws_manager
    
    async def subscribe(self, connection_id: str) -> bool:
        """Subscribe to cluster updates."""
        return await self.ws_manager.subscribe(connection_id, self.CLUSTER_CHANNEL)
    
    async def send_worker_joined(
        self,
        worker_id: str,
        worker_info: Dict[str, Any],
    ) -> int:
        """Send worker joined notification."""
        message = WebSocketMessage(
            message_type=MessageType.WORKER_JOINED,
            payload={
                "worker_id": worker_id,
                "worker_info": worker_info,
            }
        )
        return await self.ws_manager.broadcast_to_channel(self.CLUSTER_CHANNEL, message)
    
    async def send_worker_left(
        self,
        worker_id: str,
        reason: Optional[str] = None,
    ) -> int:
        """Send worker left notification."""
        message = WebSocketMessage(
            message_type=MessageType.WORKER_LEFT,
            payload={
                "worker_id": worker_id,
                "reason": reason,
            }
        )
        return await self.ws_manager.broadcast_to_channel(self.CLUSTER_CHANNEL, message)
    
    async def send_cluster_status(self, status: Dict[str, Any]) -> int:
        """Send cluster status update."""
        message = WebSocketMessage(
            message_type=MessageType.CLUSTER_STATUS,
            payload=status
        )
        return await self.ws_manager.broadcast_to_channel(self.CLUSTER_CHANNEL, message)


# Global WebSocket manager instance
_ws_manager: Optional[WebSocketManager] = None


def get_websocket_manager() -> WebSocketManager:
    """Get the global WebSocket manager instance."""
    global _ws_manager
    if _ws_manager is None:
        _ws_manager = WebSocketManager()
    return _ws_manager


def get_scan_progress_handler() -> ScanProgressHandler:
    """Get a scan progress handler."""
    return ScanProgressHandler(get_websocket_manager())


def get_dashboard_updater() -> DashboardUpdater:
    """Get a dashboard updater."""
    return DashboardUpdater(get_websocket_manager())


def get_cluster_updater() -> ClusterUpdater:
    """Get a cluster updater."""
    return ClusterUpdater(get_websocket_manager())
