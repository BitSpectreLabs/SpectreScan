"""
Tests for Distributed Scanning Master Node.
by BitSpectreLabs
"""

import pytest
import asyncio
from datetime import datetime, timedelta

from spectrescan.distributed.master import DistributedMaster, MasterConfig
from spectrescan.distributed.queue import MemoryQueue
from spectrescan.distributed.models import (
    WorkerInfo,
    WorkerStatus,
    ScanTask,
    ScanTaskResult,
    TaskStatus,
    TaskPriority
)


class TestMasterConfig:
    """Tests for MasterConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = MasterConfig()
        
        assert config.host == "0.0.0.0"
        assert config.port == 5000
        assert config.heartbeat_interval == 30
        assert config.heartbeat_timeout == 90
        assert config.task_timeout == 3600
        assert config.max_task_retries == 3
        assert config.targets_per_task == 16
        assert config.ports_per_task == 1000
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = MasterConfig(
            cluster_id="test-cluster",
            heartbeat_interval=60,
            targets_per_task=32
        )
        
        assert config.cluster_id == "test-cluster"
        assert config.heartbeat_interval == 60
        assert config.targets_per_task == 32


class TestDistributedMaster:
    """Tests for DistributedMaster class."""
    
    @pytest.fixture
    def queue(self):
        """Create a MemoryQueue instance."""
        return MemoryQueue()
    
    @pytest.fixture
    def master(self, queue):
        """Create a DistributedMaster instance."""
        config = MasterConfig(
            heartbeat_interval=1,
            heartbeat_timeout=5
        )
        return DistributedMaster(config=config, queue=queue)
    
    @pytest.mark.asyncio
    async def test_start_stop(self, master):
        """Test starting and stopping master."""
        assert await master.start() is True
        assert master._running is True
        assert master._started_at is not None
        
        await master.stop()
        assert master._running is False
    
    @pytest.mark.asyncio
    async def test_register_worker(self, master):
        """Test worker registration."""
        await master.start()
        
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100"
        )
        
        assert await master.register_worker(worker) is True
        assert len(master._workers) == 1
        assert "worker-1" in master._workers
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_unregister_worker(self, master):
        """Test worker unregistration."""
        await master.start()
        
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100"
        )
        
        await master.register_worker(worker)
        assert len(master._workers) == 1
        
        assert await master.unregister_worker("worker-1") is True
        assert len(master._workers) == 0
        
        # Unregistering non-existent worker
        assert await master.unregister_worker("worker-999") is False
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_update_worker_heartbeat(self, master):
        """Test worker heartbeat update."""
        await master.start()
        
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100"
        )
        
        await master.register_worker(worker)
        
        # Update heartbeat
        status = {
            "cpu_usage": 50.0,
            "memory_usage": 60.0,
            "current_tasks": 2
        }
        
        assert await master.update_worker_heartbeat("worker-1", status) is True
        
        updated_worker = master._workers["worker-1"]
        assert updated_worker.cpu_usage == 50.0
        assert updated_worker.memory_usage == 60.0
        assert updated_worker.current_tasks == 2
        assert updated_worker.status == WorkerStatus.BUSY
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_submit_scan(self, master):
        """Test scan submission."""
        await master.start()
        
        task_id = await master.submit_scan(
            targets=["192.168.1.1", "192.168.1.2"],
            ports=[80, 443, 8080],
            scan_type="tcp"
        )
        
        assert task_id is not None
        assert task_id in master._tasks
        assert len(master._pending_tasks) > 0
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_submit_scan_creates_subtasks(self, master):
        """Test that submit_scan creates subtasks."""
        await master.start()
        
        # Submit a scan that should create multiple subtasks
        targets = [f"192.168.1.{i}" for i in range(20)]
        ports = list(range(1, 2001))  # 2000 ports
        
        task_id = await master.submit_scan(
            targets=targets,
            ports=ports,
            scan_type="tcp"
        )
        
        # Check subtasks were created
        subtask_count = master._tasks[task_id].metadata.get("subtask_count", 0)
        assert subtask_count > 1
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_get_scan_status(self, master):
        """Test getting scan status."""
        await master.start()
        
        task_id = await master.submit_scan(
            targets=["192.168.1.1"],
            ports=[80],
            scan_type="tcp"
        )
        
        status = await master.get_scan_status(task_id)
        
        assert status is not None
        assert status["task_id"] == task_id
        assert status["status"] == "pending"
        assert "subtasks" in status
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_cancel_scan(self, master):
        """Test scan cancellation."""
        await master.start()
        
        task_id = await master.submit_scan(
            targets=["192.168.1.1"],
            ports=[80],
            scan_type="tcp"
        )
        
        assert await master.cancel_scan(task_id) is True
        assert master._tasks[task_id].status == TaskStatus.CANCELLED
        
        # Cancel non-existent task
        assert await master.cancel_scan("non-existent") is False
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_get_cluster_status(self, master):
        """Test getting cluster status."""
        await master.start()
        
        # Add some workers
        for i in range(3):
            worker = WorkerInfo(
                worker_id=f"worker-{i}",
                hostname=f"host{i}",
                ip_address=f"192.168.1.{100+i}",
                capacity=4
            )
            await master.register_worker(worker)
        
        status = master.get_cluster_status()
        
        assert status.total_workers == 3
        assert status.active_workers == 3
        assert status.total_capacity == 12
        assert status.uptime_seconds >= 0
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_get_workers(self, master):
        """Test getting worker list."""
        await master.start()
        
        for i in range(2):
            worker = WorkerInfo(
                worker_id=f"worker-{i}",
                hostname=f"host{i}",
                ip_address=f"192.168.1.{100+i}"
            )
            await master.register_worker(worker)
        
        workers = master.get_workers()
        
        assert len(workers) == 2
        assert all(isinstance(w, WorkerInfo) for w in workers)
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_get_worker(self, master):
        """Test getting specific worker."""
        await master.start()
        
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100"
        )
        await master.register_worker(worker)
        
        found = master.get_worker("worker-1")
        assert found is not None
        assert found.worker_id == "worker-1"
        
        not_found = master.get_worker("worker-999")
        assert not_found is None
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_task_result_handling(self, master, queue):
        """Test handling task results."""
        await master.start()
        
        # Register a worker
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100"
        )
        await master.register_worker(worker)
        
        # Submit a scan
        task_id = await master.submit_scan(
            targets=["192.168.1.1"],
            ports=[80],
            scan_type="tcp"
        )
        
        # Wait a bit for task scheduling
        await asyncio.sleep(0.2)
        
        # Get subtask IDs
        subtask_ids = [
            t.task_id for t in master._tasks.values()
            if t.parent_task_id == task_id
        ]
        
        # Simulate result for each subtask
        for subtask_id in subtask_ids:
            result = ScanTaskResult(
                task_id=subtask_id,
                worker_id="worker-1",
                success=True,
                results=[{"host": "192.168.1.1", "port": 80, "state": "open"}],
                open_ports=1
            )
            await queue.publish_result(result)
        
        # Wait for result processing
        await asyncio.sleep(0.5)
        
        # Check results were aggregated
        results = await master.get_scan_results(task_id)
        assert len(results) > 0
        
        await master.stop()
    
    @pytest.mark.asyncio
    async def test_callbacks(self, master):
        """Test callback functionality."""
        await master.start()
        
        task_completed_called = []
        worker_joined_called = []
        worker_left_called = []
        
        async def on_task_complete(result):
            task_completed_called.append(result)
        
        async def on_worker_joined(worker):
            worker_joined_called.append(worker)
        
        async def on_worker_left(worker):
            worker_left_called.append(worker)
        
        master.set_task_complete_callback(on_task_complete)
        master.set_worker_joined_callback(on_worker_joined)
        master.set_worker_left_callback(on_worker_left)
        
        # Register worker
        worker = WorkerInfo(
            worker_id="worker-1",
            hostname="host1",
            ip_address="192.168.1.100"
        )
        await master.register_worker(worker)
        
        assert len(worker_joined_called) == 1
        
        # Unregister worker
        await master.unregister_worker("worker-1")
        
        assert len(worker_left_called) == 1
        
        await master.stop()


class TestMasterSubtaskCreation:
    """Tests for subtask creation in master."""
    
    @pytest.fixture
    def master(self):
        """Create a master with specific chunk sizes."""
        config = MasterConfig(
            targets_per_task=4,
            ports_per_task=100
        )
        queue = MemoryQueue()
        return DistributedMaster(config=config, queue=queue)
    
    def test_create_subtasks_single_chunk(self, master):
        """Test subtask creation with single chunk."""
        subtasks = master._create_subtasks(
            parent_task_id="parent-1",
            targets=["192.168.1.1", "192.168.1.2"],
            ports=[80, 443],
            scan_type="tcp",
            options={},
            priority=TaskPriority.NORMAL
        )
        
        # Should create 1 subtask (2 targets < 4, 2 ports < 100)
        assert len(subtasks) == 1
        assert subtasks[0].parent_task_id == "parent-1"
    
    def test_create_subtasks_multiple_target_chunks(self, master):
        """Test subtask creation with multiple target chunks."""
        subtasks = master._create_subtasks(
            parent_task_id="parent-1",
            targets=[f"192.168.1.{i}" for i in range(10)],
            ports=[80],
            scan_type="tcp",
            options={},
            priority=TaskPriority.NORMAL
        )
        
        # 10 targets / 4 per task = 3 chunks
        assert len(subtasks) == 3
    
    def test_create_subtasks_multiple_port_chunks(self, master):
        """Test subtask creation with multiple port chunks."""
        subtasks = master._create_subtasks(
            parent_task_id="parent-1",
            targets=["192.168.1.1"],
            ports=list(range(1, 251)),  # 250 ports
            scan_type="tcp",
            options={},
            priority=TaskPriority.NORMAL
        )
        
        # 250 ports / 100 per task = 3 chunks
        assert len(subtasks) == 3
    
    def test_create_subtasks_combined_chunks(self, master):
        """Test subtask creation with both target and port chunks."""
        subtasks = master._create_subtasks(
            parent_task_id="parent-1",
            targets=[f"192.168.1.{i}" for i in range(8)],  # 8 targets = 2 chunks
            ports=list(range(1, 201)),  # 200 ports = 2 chunks
            scan_type="tcp",
            options={},
            priority=TaskPriority.NORMAL
        )
        
        # 2 target chunks * 2 port chunks = 4 subtasks
        assert len(subtasks) == 4
