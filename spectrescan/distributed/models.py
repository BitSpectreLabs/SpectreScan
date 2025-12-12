"""
Distributed Scanning Data Models.
by BitSpectreLabs

This module defines the data structures used for distributed scanning.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import uuid
import json


class WorkerStatus(Enum):
    """Worker node status."""
    IDLE = "idle"
    BUSY = "busy"
    OFFLINE = "offline"
    ERROR = "error"
    STARTING = "starting"
    STOPPING = "stopping"


class TaskStatus(Enum):
    """Scan task status."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class WorkerInfo:
    """
    Information about a worker node.
    
    Attributes:
        worker_id: Unique worker identifier
        hostname: Worker hostname
        ip_address: Worker IP address
        port: Worker port for communication
        status: Current worker status
        capacity: Maximum concurrent tasks
        current_tasks: Number of running tasks
        cpu_usage: CPU usage percentage
        memory_usage: Memory usage percentage
        last_heartbeat: Last heartbeat timestamp
        registered_at: Registration timestamp
        version: Worker software version
        tags: Worker tags for filtering
        metadata: Additional metadata
    """
    worker_id: str
    hostname: str
    ip_address: str
    port: int = 5000
    status: WorkerStatus = WorkerStatus.IDLE
    capacity: int = 4
    current_tasks: int = 0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    last_heartbeat: Optional[datetime] = None
    registered_at: Optional[datetime] = None
    version: str = "2.1.0"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.registered_at is None:
            self.registered_at = datetime.now()
        if self.last_heartbeat is None:
            self.last_heartbeat = datetime.now()
    
    @property
    def available_capacity(self) -> int:
        """Get available task capacity."""
        return max(0, self.capacity - self.current_tasks)
    
    @property
    def is_available(self) -> bool:
        """Check if worker is available for tasks."""
        return (
            self.status == WorkerStatus.IDLE and 
            self.available_capacity > 0
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "worker_id": self.worker_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "port": self.port,
            "status": self.status.value,
            "capacity": self.capacity,
            "current_tasks": self.current_tasks,
            "cpu_usage": self.cpu_usage,
            "memory_usage": self.memory_usage,
            "last_heartbeat": self.last_heartbeat.isoformat() if self.last_heartbeat else None,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "version": self.version,
            "tags": self.tags,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WorkerInfo':
        """Create from dictionary."""
        return cls(
            worker_id=data["worker_id"],
            hostname=data["hostname"],
            ip_address=data["ip_address"],
            port=data.get("port", 5000),
            status=WorkerStatus(data.get("status", "idle")),
            capacity=data.get("capacity", 4),
            current_tasks=data.get("current_tasks", 0),
            cpu_usage=data.get("cpu_usage", 0.0),
            memory_usage=data.get("memory_usage", 0.0),
            last_heartbeat=datetime.fromisoformat(data["last_heartbeat"]) if data.get("last_heartbeat") else None,
            registered_at=datetime.fromisoformat(data["registered_at"]) if data.get("registered_at") else None,
            version=data.get("version", "2.1.0"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {})
        )


@dataclass
class ScanTask:
    """
    A scan task to be distributed to workers.
    
    Attributes:
        task_id: Unique task identifier
        targets: List of targets to scan
        ports: List of ports to scan
        scan_type: Type of scan (tcp, syn, udp, async)
        options: Scan options
        priority: Task priority
        status: Current task status
        worker_id: Assigned worker ID
        created_at: Task creation time
        started_at: Task start time
        completed_at: Task completion time
        retry_count: Number of retries
        max_retries: Maximum retry attempts
        timeout: Task timeout in seconds
        parent_task_id: Parent task ID for subtasks
        metadata: Additional metadata
    """
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    scan_type: str = "tcp"
    options: Dict[str, Any] = field(default_factory=dict)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    worker_id: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 3600  # 1 hour default
    parent_task_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "targets": self.targets,
            "ports": self.ports,
            "scan_type": self.scan_type,
            "options": self.options,
            "priority": self.priority.value,
            "status": self.status.value,
            "worker_id": self.worker_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "timeout": self.timeout,
            "parent_task_id": self.parent_task_id,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanTask':
        """Create from dictionary."""
        return cls(
            task_id=data.get("task_id", str(uuid.uuid4())),
            targets=data.get("targets", []),
            ports=data.get("ports", []),
            scan_type=data.get("scan_type", "tcp"),
            options=data.get("options", {}),
            priority=TaskPriority(data.get("priority", 2)),
            status=TaskStatus(data.get("status", "pending")),
            worker_id=data.get("worker_id"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 3),
            timeout=data.get("timeout", 3600),
            parent_task_id=data.get("parent_task_id"),
            metadata=data.get("metadata", {})
        )
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ScanTask':
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ScanTaskResult:
    """
    Result of a scan task.
    
    Attributes:
        task_id: Task identifier
        worker_id: Worker that executed the task
        success: Whether the task succeeded
        results: Scan results (list of ScanResult dicts)
        error: Error message if failed
        started_at: When execution started
        completed_at: When execution completed
        duration: Execution duration in seconds
        open_ports: Count of open ports found
        closed_ports: Count of closed ports
        filtered_ports: Count of filtered ports
        hosts_scanned: Number of hosts scanned
        metadata: Additional metadata
    """
    task_id: str
    worker_id: str
    success: bool = True
    results: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: float = 0.0
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0
    hosts_scanned: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "success": self.success,
            "results": self.results,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration": self.duration,
            "open_ports": self.open_ports,
            "closed_ports": self.closed_ports,
            "filtered_ports": self.filtered_ports,
            "hosts_scanned": self.hosts_scanned,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanTaskResult':
        """Create from dictionary."""
        return cls(
            task_id=data["task_id"],
            worker_id=data["worker_id"],
            success=data.get("success", True),
            results=data.get("results", []),
            error=data.get("error"),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            duration=data.get("duration", 0.0),
            open_ports=data.get("open_ports", 0),
            closed_ports=data.get("closed_ports", 0),
            filtered_ports=data.get("filtered_ports", 0),
            hosts_scanned=data.get("hosts_scanned", 0),
            metadata=data.get("metadata", {})
        )
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ScanTaskResult':
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ClusterStatus:
    """
    Status of the distributed scanning cluster.
    
    Attributes:
        cluster_id: Cluster identifier
        master_id: Master node identifier
        total_workers: Total registered workers
        active_workers: Number of active workers
        idle_workers: Number of idle workers
        total_capacity: Total task capacity
        available_capacity: Available capacity
        pending_tasks: Pending task count
        running_tasks: Running task count
        completed_tasks: Completed task count
        failed_tasks: Failed task count
        started_at: Cluster start time
        uptime_seconds: Cluster uptime
        metadata: Additional metadata
    """
    cluster_id: str
    master_id: str
    total_workers: int = 0
    active_workers: int = 0
    idle_workers: int = 0
    total_capacity: int = 0
    available_capacity: int = 0
    pending_tasks: int = 0
    running_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    started_at: Optional[datetime] = None
    uptime_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cluster_id": self.cluster_id,
            "master_id": self.master_id,
            "total_workers": self.total_workers,
            "active_workers": self.active_workers,
            "idle_workers": self.idle_workers,
            "total_capacity": self.total_capacity,
            "available_capacity": self.available_capacity,
            "pending_tasks": self.pending_tasks,
            "running_tasks": self.running_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "uptime_seconds": self.uptime_seconds,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClusterStatus':
        """Create from dictionary."""
        return cls(
            cluster_id=data["cluster_id"],
            master_id=data["master_id"],
            total_workers=data.get("total_workers", 0),
            active_workers=data.get("active_workers", 0),
            idle_workers=data.get("idle_workers", 0),
            total_capacity=data.get("total_capacity", 0),
            available_capacity=data.get("available_capacity", 0),
            pending_tasks=data.get("pending_tasks", 0),
            running_tasks=data.get("running_tasks", 0),
            completed_tasks=data.get("completed_tasks", 0),
            failed_tasks=data.get("failed_tasks", 0),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            uptime_seconds=data.get("uptime_seconds", 0.0),
            metadata=data.get("metadata", {})
        )


@dataclass
class TaskAssignment:
    """
    A task assignment to a worker.
    
    Attributes:
        assignment_id: Unique assignment identifier
        task_id: Task being assigned
        worker_id: Worker receiving the task
        assigned_at: Assignment time
        acknowledged: Whether worker acknowledged
        acknowledged_at: Acknowledgement time
    """
    assignment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: str = ""
    worker_id: str = ""
    assigned_at: Optional[datetime] = None
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.assigned_at is None:
            self.assigned_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assignment_id": self.assignment_id,
            "task_id": self.task_id,
            "worker_id": self.worker_id,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None
        }
