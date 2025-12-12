"""
Data models for SpectreScan Web Dashboard.

Defines structures for dashboard statistics, scan jobs, network topology,
and user preferences.

by BitSpectreLabs
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import json


class ThemeMode(str, Enum):
    """Theme mode for the dashboard."""
    LIGHT = "light"
    DARK = "dark"
    SYSTEM = "system"


class ScanJobStatus(str, Enum):
    """Status of a scan job in the dashboard."""
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class NodeType(str, Enum):
    """Type of node in network topology."""
    HOST = "host"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    WORKSTATION = "workstation"
    UNKNOWN = "unknown"


class EdgeType(str, Enum):
    """Type of edge in network topology."""
    DIRECT = "direct"
    ROUTED = "routed"
    FILTERED = "filtered"


@dataclass
class DashboardStats:
    """Dashboard statistics summary."""
    total_scans: int = 0
    active_scans: int = 0
    completed_scans: int = 0
    failed_scans: int = 0
    total_hosts_scanned: int = 0
    total_open_ports: int = 0
    total_services_detected: int = 0
    avg_scan_duration: float = 0.0
    scans_today: int = 0
    scans_this_week: int = 0
    top_services: List[Dict[str, Any]] = field(default_factory=list)
    top_ports: List[Dict[str, Any]] = field(default_factory=list)
    recent_scans: List[Dict[str, Any]] = field(default_factory=list)
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_scans": self.total_scans,
            "active_scans": self.active_scans,
            "completed_scans": self.completed_scans,
            "failed_scans": self.failed_scans,
            "total_hosts_scanned": self.total_hosts_scanned,
            "total_open_ports": self.total_open_ports,
            "total_services_detected": self.total_services_detected,
            "avg_scan_duration": self.avg_scan_duration,
            "scans_today": self.scans_today,
            "scans_this_week": self.scans_this_week,
            "top_services": self.top_services,
            "top_ports": self.top_ports,
            "recent_scans": self.recent_scans,
            "risk_distribution": self.risk_distribution,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DashboardStats":
        """Create from dictionary."""
        return cls(
            total_scans=data.get("total_scans", 0),
            active_scans=data.get("active_scans", 0),
            completed_scans=data.get("completed_scans", 0),
            failed_scans=data.get("failed_scans", 0),
            total_hosts_scanned=data.get("total_hosts_scanned", 0),
            total_open_ports=data.get("total_open_ports", 0),
            total_services_detected=data.get("total_services_detected", 0),
            avg_scan_duration=data.get("avg_scan_duration", 0.0),
            scans_today=data.get("scans_today", 0),
            scans_this_week=data.get("scans_this_week", 0),
            top_services=data.get("top_services", []),
            top_ports=data.get("top_ports", []),
            recent_scans=data.get("recent_scans", []),
            risk_distribution=data.get("risk_distribution", {}),
        )


@dataclass
class ScanJob:
    """Scan job representation for the dashboard."""
    job_id: str
    name: str
    target: str
    ports: str
    status: ScanJobStatus
    progress: float = 0.0
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: Optional[str] = None
    scan_type: str = "tcp"
    profile_name: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    results_summary: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "job_id": self.job_id,
            "name": self.name,
            "target": self.target,
            "ports": self.ports,
            "status": self.status.value,
            "progress": self.progress,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_by": self.created_by,
            "scan_type": self.scan_type,
            "profile_name": self.profile_name,
            "options": self.options,
            "results_summary": self.results_summary,
            "error_message": self.error_message,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanJob":
        """Create from dictionary."""
        return cls(
            job_id=data["job_id"],
            name=data["name"],
            target=data["target"],
            ports=data["ports"],
            status=ScanJobStatus(data["status"]),
            progress=data.get("progress", 0.0),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            created_by=data.get("created_by"),
            scan_type=data.get("scan_type", "tcp"),
            profile_name=data.get("profile_name"),
            options=data.get("options", {}),
            results_summary=data.get("results_summary", {}),
            error_message=data.get("error_message"),
        )
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class TopologyNode:
    """Node in network topology graph."""
    node_id: str
    ip_address: str
    hostname: Optional[str] = None
    node_type: NodeType = NodeType.UNKNOWN
    os_guess: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    risk_level: str = "low"
    is_up: bool = True
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Position for visualization
    x: Optional[float] = None
    y: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "node_id": self.node_id,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "node_type": self.node_type.value,
            "os_guess": self.os_guess,
            "open_ports": self.open_ports,
            "services": self.services,
            "risk_level": self.risk_level,
            "is_up": self.is_up,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata,
            "x": self.x,
            "y": self.y,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TopologyNode":
        """Create from dictionary."""
        return cls(
            node_id=data["node_id"],
            ip_address=data["ip_address"],
            hostname=data.get("hostname"),
            node_type=NodeType(data.get("node_type", "unknown")),
            os_guess=data.get("os_guess"),
            open_ports=data.get("open_ports", []),
            services=data.get("services", []),
            risk_level=data.get("risk_level", "low"),
            is_up=data.get("is_up", True),
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
            metadata=data.get("metadata", {}),
            x=data.get("x"),
            y=data.get("y"),
        )


@dataclass
class TopologyEdge:
    """Edge connecting nodes in network topology."""
    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType = EdgeType.DIRECT
    latency_ms: Optional[float] = None
    bandwidth: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "latency_ms": self.latency_ms,
            "bandwidth": self.bandwidth,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TopologyEdge":
        """Create from dictionary."""
        return cls(
            edge_id=data["edge_id"],
            source_id=data["source_id"],
            target_id=data["target_id"],
            edge_type=EdgeType(data.get("edge_type", "direct")),
            latency_ms=data.get("latency_ms"),
            bandwidth=data.get("bandwidth"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class NetworkTopology:
    """Network topology graph for visualization."""
    topology_id: str
    name: str
    nodes: List[TopologyNode] = field(default_factory=list)
    edges: List[TopologyEdge] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    scan_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "topology_id": self.topology_id,
            "name": self.name,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "scan_id": self.scan_id,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkTopology":
        """Create from dictionary."""
        return cls(
            topology_id=data["topology_id"],
            name=data["name"],
            nodes=[TopologyNode.from_dict(n) for n in data.get("nodes", [])],
            edges=[TopologyEdge.from_dict(e) for e in data.get("edges", [])],
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            scan_id=data.get("scan_id"),
            metadata=data.get("metadata", {}),
        )
    
    def add_node(self, node: TopologyNode) -> None:
        """Add a node to the topology."""
        self.nodes.append(node)
        self.updated_at = datetime.now()
    
    def add_edge(self, edge: TopologyEdge) -> None:
        """Add an edge to the topology."""
        self.edges.append(edge)
        self.updated_at = datetime.now()
    
    def get_node(self, node_id: str) -> Optional[TopologyNode]:
        """Get a node by ID."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        return None
    
    def get_edges_for_node(self, node_id: str) -> List[TopologyEdge]:
        """Get all edges connected to a node."""
        return [
            e for e in self.edges
            if e.source_id == node_id or e.target_id == node_id
        ]
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class UserPreferences:
    """User preferences for the dashboard."""
    user_id: str
    theme: ThemeMode = ThemeMode.DARK
    default_scan_profile: Optional[str] = None
    results_per_page: int = 25
    auto_refresh_interval: int = 5
    show_closed_ports: bool = False
    show_filtered_ports: bool = True
    enable_notifications: bool = True
    notification_sound: bool = True
    compact_view: bool = False
    show_banners: bool = True
    default_export_format: str = "json"
    timezone: str = "UTC"
    language: str = "en"
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_id": self.user_id,
            "theme": self.theme.value,
            "default_scan_profile": self.default_scan_profile,
            "results_per_page": self.results_per_page,
            "auto_refresh_interval": self.auto_refresh_interval,
            "show_closed_ports": self.show_closed_ports,
            "show_filtered_ports": self.show_filtered_ports,
            "enable_notifications": self.enable_notifications,
            "notification_sound": self.notification_sound,
            "compact_view": self.compact_view,
            "show_banners": self.show_banners,
            "default_export_format": self.default_export_format,
            "timezone": self.timezone,
            "language": self.language,
            "custom_settings": self.custom_settings,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserPreferences":
        """Create from dictionary."""
        return cls(
            user_id=data["user_id"],
            theme=ThemeMode(data.get("theme", "dark")),
            default_scan_profile=data.get("default_scan_profile"),
            results_per_page=data.get("results_per_page", 25),
            auto_refresh_interval=data.get("auto_refresh_interval", 5),
            show_closed_ports=data.get("show_closed_ports", False),
            show_filtered_ports=data.get("show_filtered_ports", True),
            enable_notifications=data.get("enable_notifications", True),
            notification_sound=data.get("notification_sound", True),
            compact_view=data.get("compact_view", False),
            show_banners=data.get("show_banners", True),
            default_export_format=data.get("default_export_format", "json"),
            timezone=data.get("timezone", "UTC"),
            language=data.get("language", "en"),
            custom_settings=data.get("custom_settings", {}),
        )
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


@dataclass
class AlertConfig:
    """Alert configuration for the dashboard."""
    alert_id: str
    name: str
    enabled: bool = True
    condition_type: str = "port_open"  # port_open, service_detected, host_up, scan_complete
    condition_value: str = ""
    notification_channels: List[str] = field(default_factory=list)
    severity: str = "info"  # info, warning, critical
    created_at: Optional[datetime] = None
    created_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "name": self.name,
            "enabled": self.enabled,
            "condition_type": self.condition_type,
            "condition_value": self.condition_value,
            "notification_channels": self.notification_channels,
            "severity": self.severity,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertConfig":
        """Create from dictionary."""
        return cls(
            alert_id=data["alert_id"],
            name=data["name"],
            enabled=data.get("enabled", True),
            condition_type=data.get("condition_type", "port_open"),
            condition_value=data.get("condition_value", ""),
            notification_channels=data.get("notification_channels", []),
            severity=data.get("severity", "info"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            created_by=data.get("created_by"),
        )


@dataclass
class DashboardWidget:
    """Dashboard widget configuration."""
    widget_id: str
    widget_type: str  # stats, chart, table, topology, recent_scans, alerts
    title: str
    position: Dict[str, int] = field(default_factory=dict)  # x, y, width, height
    config: Dict[str, Any] = field(default_factory=dict)
    visible: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "widget_id": self.widget_id,
            "widget_type": self.widget_type,
            "title": self.title,
            "position": self.position,
            "config": self.config,
            "visible": self.visible,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DashboardWidget":
        """Create from dictionary."""
        return cls(
            widget_id=data["widget_id"],
            widget_type=data["widget_type"],
            title=data["title"],
            position=data.get("position", {}),
            config=data.get("config", {}),
            visible=data.get("visible", True),
        )


@dataclass
class DashboardLayout:
    """Dashboard layout configuration."""
    layout_id: str
    name: str
    user_id: str
    widgets: List[DashboardWidget] = field(default_factory=list)
    is_default: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "layout_id": self.layout_id,
            "name": self.name,
            "user_id": self.user_id,
            "widgets": [w.to_dict() for w in self.widgets],
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DashboardLayout":
        """Create from dictionary."""
        return cls(
            layout_id=data["layout_id"],
            name=data["name"],
            user_id=data["user_id"],
            widgets=[DashboardWidget.from_dict(w) for w in data.get("widgets", [])],
            is_default=data.get("is_default", False),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
        )
