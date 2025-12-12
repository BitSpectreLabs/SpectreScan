"""
Tests for Distributed Scanning Data Models.
by BitSpectreLabs
"""

import pytest
from datetime import datetime
import json

from spectrescan.distributed.models import (
    WorkerInfo,
    WorkerStatus,
    ScanTask,
    ScanTaskResult,
    ClusterStatus,
    TaskStatus,
    TaskPriority,
    TaskAssignment
)


class TestWorkerStatus:
    """Tests for WorkerStatus enum."""
    
    def test_worker_status_values(self):
        """Test all worker status values."""
        assert WorkerStatus.IDLE.value == "idle"
        assert WorkerStatus.BUSY.value == "busy"
        assert WorkerStatus.OFFLINE.value == "offline"
        assert WorkerStatus.ERROR.value == "error"
        assert WorkerStatus.STARTING.value == "starting"
        assert WorkerStatus.STOPPING.value == "stopping"


class TestTaskStatus:
    """Tests for TaskStatus enum."""
    
    def test_task_status_values(self):
        """Test all task status values."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.ASSIGNED.value == "assigned"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.CANCELLED.value == "cancelled"
        assert TaskStatus.RETRYING.value == "retrying"


class TestTaskPriority:
    """Tests for TaskPriority enum."""
    
    def test_task_priority_values(self):
        """Test all priority values."""
        assert TaskPriority.LOW.value == 1
        assert TaskPriority.NORMAL.value == 2
        assert TaskPriority.HIGH.value == 3
        assert TaskPriority.CRITICAL.value == 4


class TestWorkerInfo:
    """Tests for WorkerInfo dataclass."""
    
    def test_worker_info_creation(self):
        """Test WorkerInfo creation."""
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100"
        )
        
        assert worker.worker_id == "worker-1"
        assert worker.hostname == "host1"
        assert worker.ip_address == "192.168.1.100"
        assert worker.port == 5000
        assert worker.status == WorkerStatus.IDLE
        assert worker.capacity == 4
        assert worker.current_tasks == 0
    
    def test_worker_info_available_capacity(self):
        """Test available_capacity property."""
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100",
            capacity=4,
            current_tasks=2
        )
        
        assert worker.available_capacity == 2
    
    def test_worker_info_is_available(self):
        """Test is_available property."""
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100",
            status=WorkerStatus.IDLE,
            capacity=4,
            current_tasks=0
        )
        
        assert worker.is_available is True
        
        worker.status = WorkerStatus.BUSY
        assert worker.is_available is False
        
        worker.status = WorkerStatus.IDLE
        worker.current_tasks = 4
        assert worker.is_available is False
    
    def test_worker_info_to_dict(self):
        """Test to_dict conversion."""
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100",
            tags=["production", "fast"]
        )
        
        data = worker.to_dict()
        
        assert data["worker_id"] == "worker-1"
        assert data["hostname"] == "host1"
        assert data["ip_address"] == "192.168.1.100"
        assert data["status"] == "idle"
        assert data["tags"] == ["production", "fast"]
    
    def test_worker_info_from_dict(self):
        """Test from_dict conversion."""
        data = {
            "worker_id": "worker-1",
            "hostname": "host1",
            "ip_address": "192.168.1.100",
            "port": 5001,
            "status": "busy",
            "capacity": 8,
            "tags": ["gpu"]
        }
        
        worker = WorkerInfo.from_dict(data)
        
        assert worker.worker_id == "worker-1"
        assert worker.port == 5001
        assert worker.status == WorkerStatus.BUSY
        assert worker.capacity == 8
        assert worker.tags == ["gpu"]


class TestScanTask:
    """Tests for ScanTask dataclass."""
    
    def test_scan_task_creation(self):
        """Test ScanTask creation."""
        task = ScanTask(
            targets=["192.168.1.1", "192.168.1.2"],
            ports=[80, 443, 8080],
            scan_type="tcp"
        )
        
        assert len(task.task_id) > 0
        assert task.targets == ["192.168.1.1", "192.168.1.2"]
        assert task.ports == [80, 443, 8080]
        assert task.scan_type == "tcp"
        assert task.status == TaskStatus.PENDING
        assert task.priority == TaskPriority.NORMAL
        assert task.created_at is not None
    
    def test_scan_task_to_dict(self):
        """Test to_dict conversion."""
        task = ScanTask(
            task_id="task-123",
            targets=["192.168.1.1"],
            ports=[80],
            scan_type="syn",
            priority=TaskPriority.HIGH
        )
        
        data = task.to_dict()
        
        assert data["task_id"] == "task-123"
        assert data["targets"] == ["192.168.1.1"]
        assert data["ports"] == [80]
        assert data["scan_type"] == "syn"
        assert data["priority"] == 3
        assert data["status"] == "pending"
    
    def test_scan_task_from_dict(self):
        """Test from_dict conversion."""
        data = {
            "task_id": "task-456",
            "targets": ["10.0.0.1"],
            "ports": [22, 23],
            "scan_type": "udp",
            "priority": 4,
            "status": "running",
            "worker_id": "worker-1"
        }
        
        task = ScanTask.from_dict(data)
        
        assert task.task_id == "task-456"
        assert task.targets == ["10.0.0.1"]
        assert task.priority == TaskPriority.CRITICAL
        assert task.status == TaskStatus.RUNNING
        assert task.worker_id == "worker-1"
    
    def test_scan_task_json_serialization(self):
        """Test JSON serialization."""
        task = ScanTask(
            targets=["192.168.1.1"],
            ports=[80, 443]
        )
        
        json_str = task.to_json()
        restored = ScanTask.from_json(json_str)
        
        assert restored.task_id == task.task_id
        assert restored.targets == task.targets
        assert restored.ports == task.ports


class TestScanTaskResult:
    """Tests for ScanTaskResult dataclass."""
    
    def test_scan_task_result_creation(self):
        """Test ScanTaskResult creation."""
        result = ScanTaskResult(
            task_id="task-123",
            worker_id="worker-1",
            success=True,
            open_ports=5,
            closed_ports=95,
            filtered_ports=0
        )
        
        assert result.task_id == "task-123"
        assert result.worker_id == "worker-1"
        assert result.success is True
        assert result.open_ports == 5
    
    def test_scan_task_result_with_error(self):
        """Test ScanTaskResult with error."""
        result = ScanTaskResult(
            task_id="task-123",
            worker_id="worker-1",
            success=False,
            error="Connection timeout"
        )
        
        assert result.success is False
        assert result.error == "Connection timeout"
    
    def test_scan_task_result_to_dict(self):
        """Test to_dict conversion."""
        result = ScanTaskResult(
            task_id="task-123",
            worker_id="worker-1",
            results=[
                {"host": "192.168.1.1", "port": 80, "state": "open"}
            ],
            open_ports=1
        )
        
        data = result.to_dict()
        
        assert data["task_id"] == "task-123"
        assert data["worker_id"] == "worker-1"
        assert len(data["results"]) == 1
        assert data["open_ports"] == 1
    
    def test_scan_task_result_json_serialization(self):
        """Test JSON serialization."""
        result = ScanTaskResult(
            task_id="task-123",
            worker_id="worker-1",
            success=True
        )
        
        json_str = result.to_json()
        restored = ScanTaskResult.from_json(json_str)
        
        assert restored.task_id == result.task_id
        assert restored.worker_id == result.worker_id


class TestClusterStatus:
    """Tests for ClusterStatus dataclass."""
    
    def test_cluster_status_creation(self):
        """Test ClusterStatus creation."""
        status = ClusterStatus(
            cluster_id="cluster-abc",
            master_id="master-1",
            total_workers=5,
            active_workers=4,
            idle_workers=2
        )
        
        assert status.cluster_id == "cluster-abc"
        assert status.master_id == "master-1"
        assert status.total_workers == 5
        assert status.active_workers == 4
        assert status.idle_workers == 2
    
    def test_cluster_status_to_dict(self):
        """Test to_dict conversion."""
        status = ClusterStatus(
            cluster_id="cluster-abc",
            master_id="master-1",
            pending_tasks=10,
            running_tasks=5
        )
        
        data = status.to_dict()
        
        assert data["cluster_id"] == "cluster-abc"
        assert data["pending_tasks"] == 10
        assert data["running_tasks"] == 5


class TestTaskAssignment:
    """Tests for TaskAssignment dataclass."""
    
    def test_task_assignment_creation(self):
        """Test TaskAssignment creation."""
        assignment = TaskAssignment(
            task_id="task-123",
            worker_id="worker-1"
        )
        
        assert assignment.task_id == "task-123"
        assert assignment.worker_id == "worker-1"
        assert assignment.acknowledged is False
        assert assignment.assigned_at is not None
    
    def test_task_assignment_to_dict(self):
        """Test to_dict conversion."""
        assignment = TaskAssignment(
            task_id="task-123",
            worker_id="worker-1",
            acknowledged=True
        )
        
        data = assignment.to_dict()
        
        assert data["task_id"] == "task-123"
        assert data["worker_id"] == "worker-1"
        assert data["acknowledged"] is True
