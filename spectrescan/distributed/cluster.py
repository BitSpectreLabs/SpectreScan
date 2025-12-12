"""
Cluster Management for Distributed Scanning.
by BitSpectreLabs

This module provides cluster management functionality including:
- Cluster initialization and configuration
- Worker management
- Health monitoring
- Load balancing
- Result aggregation
"""

import asyncio
import logging
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, field, asdict

from spectrescan.distributed.models import (
    WorkerInfo,
    WorkerStatus,
    ScanTask,
    ScanTaskResult,
    ClusterStatus,
    TaskPriority
)
from spectrescan.distributed.master import DistributedMaster, MasterConfig
from spectrescan.distributed.worker import DistributedWorker, WorkerConfig
from spectrescan.distributed.queue import MessageQueue, MemoryQueue, RedisQueue, create_queue

logger = logging.getLogger(__name__)


@dataclass
class ClusterConfig:
    """
    Cluster configuration.
    
    Attributes:
        cluster_id: Unique cluster identifier
        name: Cluster name
        description: Cluster description
        queue_type: Message queue type (memory, redis)
        queue_config: Queue-specific configuration
        master_config: Master node configuration
        default_worker_capacity: Default worker capacity
        heartbeat_interval: Worker heartbeat interval
        heartbeat_timeout: Heartbeat timeout before marking offline
        task_timeout: Default task timeout
        max_task_retries: Maximum task retries
        targets_per_task: Targets per distributed task
        ports_per_task: Ports per distributed task
        enable_ssl: Enable SSL/TLS
        ssl_cert: Path to SSL certificate
        ssl_key: Path to SSL key
        persist_results: Persist results to disk
        results_dir: Results storage directory
    """
    cluster_id: str = field(default_factory=lambda: f"cluster-{uuid.uuid4().hex[:8]}")
    name: str = "SpectreScan Cluster"
    description: str = ""
    queue_type: str = "memory"
    queue_config: Dict[str, Any] = field(default_factory=dict)
    master_config: Dict[str, Any] = field(default_factory=dict)
    default_worker_capacity: int = 4
    heartbeat_interval: int = 30
    heartbeat_timeout: int = 90
    task_timeout: int = 3600
    max_task_retries: int = 3
    targets_per_task: int = 16
    ports_per_task: int = 1000
    enable_ssl: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    persist_results: bool = True
    results_dir: str = "~/.spectrescan/cluster_results"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ClusterConfig':
        """Create from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
    
    def to_json(self, path: Path) -> None:
        """Save configuration to JSON file."""
        path = Path(path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def from_json(cls, path: Path) -> 'ClusterConfig':
        """Load configuration from JSON file."""
        path = Path(path).expanduser()
        with open(path) as f:
            return cls.from_dict(json.load(f))


class ClusterManager:
    """
    Manager for distributed scanning cluster.
    
    Provides high-level API for:
    - Cluster initialization and shutdown
    - Worker management
    - Scan submission and monitoring
    - Result retrieval
    """
    
    def __init__(self, config: Optional[ClusterConfig] = None):
        """
        Initialize cluster manager.
        
        Args:
            config: Cluster configuration
        """
        self.config = config or ClusterConfig()
        
        # Components
        self._queue: Optional[MessageQueue] = None
        self._master: Optional[DistributedMaster] = None
        self._local_workers: List[DistributedWorker] = []
        
        # State
        self._initialized = False
        self._running = False
        self._started_at: Optional[datetime] = None
        
        # Results storage
        self._results_dir = Path(self.config.results_dir).expanduser()
        
        logger.info(f"ClusterManager initialized for cluster {self.config.cluster_id}")
    
    async def initialize(self) -> bool:
        """
        Initialize the cluster.
        
        Creates queue and master node.
        
        Returns:
            True if initialized successfully
        """
        if self._initialized:
            logger.warning("Cluster already initialized")
            return True
        
        try:
            # Create message queue
            self._queue = create_queue(
                self.config.queue_type,
                **self.config.queue_config
            )
            
            # Create master configuration
            master_config = MasterConfig(
                cluster_id=self.config.cluster_id,
                heartbeat_interval=self.config.heartbeat_interval,
                heartbeat_timeout=self.config.heartbeat_timeout,
                task_timeout=self.config.task_timeout,
                max_task_retries=self.config.max_task_retries,
                targets_per_task=self.config.targets_per_task,
                ports_per_task=self.config.ports_per_task,
                enable_ssl=self.config.enable_ssl,
                ssl_cert=self.config.ssl_cert,
                ssl_key=self.config.ssl_key,
                **self.config.master_config
            )
            
            # Create master
            self._master = DistributedMaster(
                config=master_config,
                queue=self._queue
            )
            
            # Set up results directory
            if self.config.persist_results:
                self._results_dir.mkdir(parents=True, exist_ok=True)
            
            self._initialized = True
            logger.info("Cluster initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize cluster: {e}")
            return False
    
    async def start(self) -> bool:
        """
        Start the cluster.
        
        Returns:
            True if started successfully
        """
        if not self._initialized:
            if not await self.initialize():
                return False
        
        if self._running:
            logger.warning("Cluster already running")
            return True
        
        try:
            # Start master
            if self._master:
                if not await self._master.start():
                    return False
            
            self._running = True
            self._started_at = datetime.now()
            
            logger.info("Cluster started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start cluster: {e}")
            return False
    
    async def stop(self) -> None:
        """Stop the cluster."""
        # Stop local workers first
        for worker in self._local_workers:
            await worker.stop()
        self._local_workers.clear()
        
        # Stop master
        if self._master:
            await self._master.stop()
        
        self._running = False
        logger.info("Cluster stopped")
    
    async def add_local_worker(
        self,
        capacity: Optional[int] = None,
        tags: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Add a local worker to the cluster.
        
        Args:
            capacity: Worker capacity (default from config)
            tags: Worker tags
            
        Returns:
            Worker ID or None if failed
        """
        if not self._running or not self._queue or not self._master:
            logger.error("Cluster not running")
            return None
        
        try:
            config = WorkerConfig(
                capacity=capacity or self.config.default_worker_capacity,
                heartbeat_interval=self.config.heartbeat_interval,
                tags=tags or []
            )
            
            worker = DistributedWorker(config=config, queue=self._queue)
            
            if await worker.start():
                # Register with master
                await self._master.register_worker(worker.get_info())
                self._local_workers.append(worker)
                
                logger.info(f"Added local worker {config.worker_id}")
                return config.worker_id
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to add local worker: {e}")
            return None
    
    async def remove_local_worker(self, worker_id: str) -> bool:
        """
        Remove a local worker.
        
        Args:
            worker_id: Worker identifier
            
        Returns:
            True if removed successfully
        """
        for i, worker in enumerate(self._local_workers):
            if worker.config.worker_id == worker_id:
                await worker.stop()
                self._local_workers.pop(i)
                
                if self._master:
                    await self._master.unregister_worker(worker_id)
                
                logger.info(f"Removed local worker {worker_id}")
                return True
        
        return False
    
    async def scale_workers(self, count: int) -> int:
        """
        Scale to specified number of local workers.
        
        Args:
            count: Desired worker count
            
        Returns:
            Actual worker count after scaling
        """
        current = len(self._local_workers)
        
        if count > current:
            # Add workers
            for _ in range(count - current):
                await self.add_local_worker()
        elif count < current:
            # Remove workers
            workers_to_remove = self._local_workers[count:]
            for worker in workers_to_remove:
                await self.remove_local_worker(worker.config.worker_id)
        
        return len(self._local_workers)
    
    async def submit_scan(
        self,
        targets: List[str],
        ports: List[int],
        scan_type: str = "tcp",
        options: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL
    ) -> Optional[str]:
        """
        Submit a distributed scan.
        
        Args:
            targets: List of targets
            ports: List of ports
            scan_type: Scan type
            options: Scan options
            priority: Task priority
            
        Returns:
            Task ID or None if failed
        """
        if not self._running or not self._master:
            logger.error("Cluster not running")
            return None
        
        task_id = await self._master.submit_scan(
            targets=targets,
            ports=ports,
            scan_type=scan_type,
            options=options,
            priority=priority
        )
        
        return task_id
    
    async def get_scan_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get scan status.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Status dictionary or None
        """
        if not self._master:
            return None
        
        return await self._master.get_scan_status(task_id)
    
    async def get_scan_results(self, task_id: str) -> List[Dict[str, Any]]:
        """
        Get scan results.
        
        Args:
            task_id: Task identifier
            
        Returns:
            List of results
        """
        if not self._master:
            return []
        
        return await self._master.get_scan_results(task_id)
    
    async def cancel_scan(self, task_id: str) -> bool:
        """
        Cancel a scan.
        
        Args:
            task_id: Task identifier
            
        Returns:
            True if cancelled
        """
        if not self._master:
            return False
        
        return await self._master.cancel_scan(task_id)
    
    async def wait_for_scan(
        self,
        task_id: str,
        timeout: Optional[float] = None,
        poll_interval: float = 1.0
    ) -> Optional[Dict[str, Any]]:
        """
        Wait for a scan to complete.
        
        Args:
            task_id: Task identifier
            timeout: Maximum wait time in seconds
            poll_interval: Status check interval
            
        Returns:
            Final status or None if timeout
        """
        start = datetime.now()
        
        while True:
            status = await self.get_scan_status(task_id)
            
            if not status:
                return None
            
            if status.get("status") in ("completed", "failed", "cancelled"):
                return status
            
            if timeout:
                elapsed = (datetime.now() - start).total_seconds()
                if elapsed >= timeout:
                    return None
            
            await asyncio.sleep(poll_interval)
    
    def get_cluster_status(self) -> ClusterStatus:
        """
        Get cluster status.
        
        Returns:
            ClusterStatus object
        """
        if not self._master:
            return ClusterStatus(
                cluster_id=self.config.cluster_id,
                master_id="",
                started_at=self._started_at
            )
        
        return self._master.get_cluster_status()
    
    def get_workers(self) -> List[WorkerInfo]:
        """
        Get list of all workers.
        
        Returns:
            List of WorkerInfo
        """
        if not self._master:
            return []
        
        return self._master.get_workers()
    
    def get_local_workers(self) -> List[DistributedWorker]:
        """
        Get list of local workers.
        
        Returns:
            List of local DistributedWorker instances
        """
        return self._local_workers.copy()
    
    async def save_results(
        self,
        task_id: str,
        format: str = "json"
    ) -> Optional[Path]:
        """
        Save scan results to file.
        
        Args:
            task_id: Task identifier
            format: Output format (json)
            
        Returns:
            Path to saved file or None
        """
        results = await self.get_scan_results(task_id)
        
        if not results:
            return None
        
        output_path = self._results_dir / f"{task_id}.{format}"
        
        with open(output_path, 'w') as f:
            json.dump({
                "task_id": task_id,
                "timestamp": datetime.now().isoformat(),
                "results": results
            }, f, indent=2)
        
        logger.info(f"Results saved to {output_path}")
        return output_path
    
    @property
    def is_running(self) -> bool:
        """Check if cluster is running."""
        return self._running
    
    @property
    def worker_count(self) -> int:
        """Get total worker count."""
        if not self._master:
            return 0
        return len(self._master.get_workers())
    
    @property
    def local_worker_count(self) -> int:
        """Get local worker count."""
        return len(self._local_workers)


async def create_cluster(
    workers: int = 1,
    queue_type: str = "memory",
    **kwargs
) -> ClusterManager:
    """
    Create and start a cluster.
    
    Convenience function to create a cluster with local workers.
    
    Args:
        workers: Number of local workers to start
        queue_type: Message queue type
        **kwargs: Additional cluster config options
        
    Returns:
        Running ClusterManager instance
    """
    config = ClusterConfig(
        queue_type=queue_type,
        **kwargs
    )
    
    manager = ClusterManager(config=config)
    
    if not await manager.start():
        raise RuntimeError("Failed to start cluster")
    
    # Add local workers
    for _ in range(workers):
        await manager.add_local_worker()
    
    return manager


async def run_distributed_scan(
    targets: List[str],
    ports: List[int],
    workers: int = 2,
    scan_type: str = "tcp",
    options: Optional[Dict[str, Any]] = None,
    timeout: Optional[float] = None
) -> List[Dict[str, Any]]:
    """
    Run a distributed scan.
    
    Convenience function that creates a temporary cluster,
    runs a scan, and returns results.
    
    Args:
        targets: List of targets
        ports: List of ports
        workers: Number of workers
        scan_type: Scan type
        options: Scan options
        timeout: Maximum wait time
        
    Returns:
        List of scan results
    """
    cluster = await create_cluster(workers=workers)
    
    try:
        task_id = await cluster.submit_scan(
            targets=targets,
            ports=ports,
            scan_type=scan_type,
            options=options
        )
        
        if not task_id:
            return []
        
        # Wait for completion
        status = await cluster.wait_for_scan(task_id, timeout=timeout)
        
        if not status:
            return []
        
        return await cluster.get_scan_results(task_id)
        
    finally:
        await cluster.stop()
