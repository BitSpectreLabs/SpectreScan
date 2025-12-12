"""
Tests for Distributed Scanning Cluster Management.
by BitSpectreLabs
"""

import pytest
import asyncio
from pathlib import Path
from datetime import datetime

from spectrescan.distributed.cluster import (
    ClusterManager,
    ClusterConfig,
    create_cluster,
    run_distributed_scan
)
from spectrescan.distributed.queue import MemoryQueue
from spectrescan.distributed.models import (
    ClusterStatus,
    TaskPriority
)


class TestClusterConfig:
    """Tests for ClusterConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = ClusterConfig()
        
        assert config.queue_type == "memory"
        assert config.default_worker_capacity == 4
        assert config.heartbeat_interval == 30
        assert config.heartbeat_timeout == 90
        assert config.task_timeout == 3600
        assert config.max_task_retries == 3
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = ClusterConfig(
            name="Test Cluster",
            queue_type="redis",
            default_worker_capacity=8,
            targets_per_task=32
        )
        
        assert config.name == "Test Cluster"
        assert config.queue_type == "redis"
        assert config.default_worker_capacity == 8
        assert config.targets_per_task == 32
    
    def test_to_dict(self):
        """Test to_dict conversion."""
        config = ClusterConfig(
            cluster_id="test-cluster",
            name="Test Cluster"
        )
        
        data = config.to_dict()
        
        assert data["cluster_id"] == "test-cluster"
        assert data["name"] == "Test Cluster"
    
    def test_from_dict(self):
        """Test from_dict conversion."""
        data = {
            "cluster_id": "test-cluster",
            "name": "Test Cluster",
            "queue_type": "memory"
        }
        
        config = ClusterConfig.from_dict(data)
        
        assert config.cluster_id == "test-cluster"
        assert config.name == "Test Cluster"


class TestClusterManager:
    """Tests for ClusterManager class."""
    
    @pytest.fixture
    def manager(self):
        """Create a ClusterManager instance."""
        config = ClusterConfig(
            heartbeat_interval=1,
            heartbeat_timeout=5
        )
        return ClusterManager(config=config)
    
    @pytest.mark.asyncio
    async def test_initialize(self, manager):
        """Test cluster initialization."""
        assert await manager.initialize() is True
        assert manager._initialized is True
        assert manager._queue is not None
        assert manager._master is not None
    
    @pytest.mark.asyncio
    async def test_start_stop(self, manager):
        """Test starting and stopping cluster."""
        assert await manager.start() is True
        assert manager._running is True
        
        await manager.stop()
        assert manager._running is False
    
    @pytest.mark.asyncio
    async def test_add_local_worker(self, manager):
        """Test adding local worker."""
        await manager.start()
        
        worker_id = await manager.add_local_worker(
            capacity=4,
            tags=["test"]
        )
        
        assert worker_id is not None
        assert manager.local_worker_count == 1
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_remove_local_worker(self, manager):
        """Test removing local worker."""
        await manager.start()
        
        worker_id = await manager.add_local_worker()
        assert manager.local_worker_count == 1
        
        assert await manager.remove_local_worker(worker_id) is True
        assert manager.local_worker_count == 0
        
        # Remove non-existent worker
        assert await manager.remove_local_worker("non-existent") is False
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_scale_workers(self, manager):
        """Test scaling workers."""
        await manager.start()
        
        # Scale up
        count = await manager.scale_workers(3)
        assert count == 3
        assert manager.local_worker_count == 3
        
        # Scale down
        count = await manager.scale_workers(1)
        assert count == 1
        assert manager.local_worker_count == 1
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_submit_scan(self, manager):
        """Test submitting a scan."""
        await manager.start()
        
        # Add a worker
        await manager.add_local_worker()
        
        task_id = await manager.submit_scan(
            targets=["192.168.1.1"],
            ports=[80, 443],
            scan_type="tcp"
        )
        
        assert task_id is not None
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_get_scan_status(self, manager):
        """Test getting scan status."""
        await manager.start()
        
        await manager.add_local_worker()
        
        task_id = await manager.submit_scan(
            targets=["192.168.1.1"],
            ports=[80]
        )
        
        status = await manager.get_scan_status(task_id)
        
        assert status is not None
        assert status["task_id"] == task_id
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_cancel_scan(self, manager):
        """Test canceling a scan."""
        await manager.start()
        
        await manager.add_local_worker()
        
        task_id = await manager.submit_scan(
            targets=["192.168.1.1"],
            ports=[80]
        )
        
        assert await manager.cancel_scan(task_id) is True
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_get_cluster_status(self, manager):
        """Test getting cluster status."""
        await manager.start()
        
        # Add workers
        await manager.add_local_worker()
        await manager.add_local_worker()
        
        status = manager.get_cluster_status()
        
        assert isinstance(status, ClusterStatus)
        assert status.total_workers == 2
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_get_workers(self, manager):
        """Test getting worker list."""
        await manager.start()
        
        await manager.add_local_worker()
        await manager.add_local_worker()
        
        workers = manager.get_workers()
        
        assert len(workers) == 2
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_get_local_workers(self, manager):
        """Test getting local worker list."""
        await manager.start()
        
        await manager.add_local_worker()
        
        local_workers = manager.get_local_workers()
        
        assert len(local_workers) == 1
        
        await manager.stop()
    
    @pytest.mark.asyncio
    async def test_is_running_property(self, manager):
        """Test is_running property."""
        assert manager.is_running is False
        
        await manager.start()
        assert manager.is_running is True
        
        await manager.stop()
        assert manager.is_running is False
    
    @pytest.mark.asyncio
    async def test_worker_count_property(self, manager):
        """Test worker_count property."""
        assert manager.worker_count == 0
        
        await manager.start()
        await manager.add_local_worker()
        await manager.add_local_worker()
        
        assert manager.worker_count == 2
        
        await manager.stop()


class TestCreateCluster:
    """Tests for create_cluster convenience function."""
    
    @pytest.mark.asyncio
    async def test_create_cluster(self):
        """Test create_cluster function."""
        cluster = await create_cluster(
            workers=2,
            queue_type="memory"
        )
        
        assert cluster is not None
        assert cluster.is_running is True
        assert cluster.local_worker_count == 2
        
        await cluster.stop()
    
    @pytest.mark.asyncio
    async def test_create_cluster_with_custom_config(self):
        """Test create_cluster with custom config."""
        cluster = await create_cluster(
            workers=1,
            queue_type="memory",
            name="Custom Cluster",
            default_worker_capacity=8
        )
        
        assert cluster.config.name == "Custom Cluster"
        assert cluster.config.default_worker_capacity == 8
        
        await cluster.stop()


class TestRunDistributedScan:
    """Tests for run_distributed_scan convenience function."""
    
    @pytest.mark.asyncio
    async def test_run_distributed_scan_basic(self):
        """Test basic distributed scan."""
        # This will create a temporary cluster and run a scan
        # Note: actual scan results depend on network
        results = await run_distributed_scan(
            targets=["127.0.0.1"],
            ports=[80, 443],
            workers=1,
            scan_type="tcp",
            timeout=10
        )
        
        # Results may be empty if ports are closed
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_run_distributed_scan_with_options(self):
        """Test distributed scan with options."""
        results = await run_distributed_scan(
            targets=["127.0.0.1"],
            ports=[80],
            workers=2,
            scan_type="tcp",
            options={
                "threads": 50,
                "timeout": 1.0
            },
            timeout=10
        )
        
        assert isinstance(results, list)
