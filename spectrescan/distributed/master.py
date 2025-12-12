"""
Distributed Scanning Master Node.
by BitSpectreLabs

This module implements the master node coordinator for distributed scanning.
The master is responsible for:
- Worker registration and discovery
- Task distribution and load balancing
- Result aggregation
- Worker health monitoring
- Automatic failover and retry
"""

import asyncio
import logging
import uuid
import socket
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable, Awaitable, Set
from dataclasses import dataclass, field
import json
import ipaddress

from spectrescan.distributed.models import (
    WorkerInfo,
    WorkerStatus,
    ScanTask,
    ScanTaskResult,
    TaskStatus,
    TaskPriority,
    ClusterStatus
)
from spectrescan.distributed.queue import MessageQueue, MemoryQueue, TaskMessage, ResultMessage
from spectrescan.core.utils import parse_target, parse_ports

logger = logging.getLogger(__name__)


@dataclass
class MasterConfig:
    """
    Master node configuration.
    
    Attributes:
        master_id: Unique master identifier
        cluster_id: Cluster identifier
        host: Master host address
        port: Master port
        heartbeat_interval: Worker heartbeat interval in seconds
        heartbeat_timeout: Heartbeat timeout before marking worker offline
        task_timeout: Default task timeout in seconds
        max_task_retries: Maximum task retry attempts
        targets_per_task: Targets per task for load distribution
        ports_per_task: Ports per task for load distribution
        enable_ssl: Enable SSL/TLS for communication
        ssl_cert: Path to SSL certificate
        ssl_key: Path to SSL private key
    """
    master_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    cluster_id: str = field(default_factory=lambda: f"cluster-{uuid.uuid4().hex[:6]}")
    host: str = "0.0.0.0"
    port: int = 5000
    heartbeat_interval: int = 30
    heartbeat_timeout: int = 90
    task_timeout: int = 3600
    max_task_retries: int = 3
    targets_per_task: int = 16
    ports_per_task: int = 1000
    enable_ssl: bool = False
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None


class DistributedMaster:
    """
    Master node coordinator for distributed scanning.
    
    The master orchestrates scan tasks across multiple worker nodes,
    handles load balancing, monitors worker health, and aggregates results.
    """
    
    def __init__(
        self,
        config: Optional[MasterConfig] = None,
        queue: Optional[MessageQueue] = None
    ):
        """
        Initialize the master node.
        
        Args:
            config: Master configuration
            queue: Message queue instance
        """
        self.config = config or MasterConfig()
        self.queue = queue or MemoryQueue()
        
        # State tracking
        self._workers: Dict[str, WorkerInfo] = {}
        self._tasks: Dict[str, ScanTask] = {}
        self._results: Dict[str, List[ScanTaskResult]] = {}
        self._running = False
        self._started_at: Optional[datetime] = None
        
        # Task tracking
        self._pending_tasks: Set[str] = set()
        self._running_tasks: Dict[str, str] = {}  # task_id -> worker_id
        self._completed_tasks: Set[str] = set()
        self._failed_tasks: Set[str] = set()
        
        # Callbacks
        self._on_task_complete: Optional[Callable[[ScanTaskResult], Awaitable[None]]] = None
        self._on_worker_joined: Optional[Callable[[WorkerInfo], Awaitable[None]]] = None
        self._on_worker_left: Optional[Callable[[WorkerInfo], Awaitable[None]]] = None
        
        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._result_collector_task: Optional[asyncio.Task] = None
        self._task_scheduler_task: Optional[asyncio.Task] = None
        
        logger.info(f"Master {self.config.master_id} initialized for cluster {self.config.cluster_id}")
    
    async def start(self) -> bool:
        """
        Start the master node.
        
        Returns:
            True if started successfully
        """
        try:
            # Connect to message queue
            if not await self.queue.connect():
                logger.error("Failed to connect to message queue")
                return False
            
            self._running = True
            self._started_at = datetime.now()
            
            # Start background tasks
            self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())
            self._result_collector_task = asyncio.create_task(self._collect_results())
            self._task_scheduler_task = asyncio.create_task(self._schedule_tasks())
            
            logger.info(f"Master {self.config.master_id} started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start master: {e}")
            return False
    
    async def stop(self) -> None:
        """Stop the master node."""
        self._running = False
        
        # Cancel background tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self._result_collector_task:
            self._result_collector_task.cancel()
            try:
                await self._result_collector_task
            except asyncio.CancelledError:
                pass
        
        if self._task_scheduler_task:
            self._task_scheduler_task.cancel()
            try:
                await self._task_scheduler_task
            except asyncio.CancelledError:
                pass
        
        # Disconnect from queue
        await self.queue.disconnect()
        
        logger.info(f"Master {self.config.master_id} stopped")
    
    async def register_worker(self, worker: WorkerInfo) -> bool:
        """
        Register a worker node.
        
        Args:
            worker: Worker information
            
        Returns:
            True if registered successfully
        """
        worker.registered_at = datetime.now()
        worker.last_heartbeat = datetime.now()
        worker.status = WorkerStatus.IDLE
        
        self._workers[worker.worker_id] = worker
        
        logger.info(f"Worker {worker.worker_id} registered from {worker.ip_address}:{worker.port}")
        
        if self._on_worker_joined:
            await self._on_worker_joined(worker)
        
        return True
    
    async def unregister_worker(self, worker_id: str) -> bool:
        """
        Unregister a worker node.
        
        Args:
            worker_id: Worker identifier
            
        Returns:
            True if unregistered successfully
        """
        if worker_id not in self._workers:
            return False
        
        worker = self._workers.pop(worker_id)
        
        # Reschedule any tasks assigned to this worker
        tasks_to_reschedule = [
            task_id for task_id, w_id in self._running_tasks.items()
            if w_id == worker_id
        ]
        
        for task_id in tasks_to_reschedule:
            if task_id in self._tasks:
                task = self._tasks[task_id]
                task.status = TaskStatus.PENDING
                task.worker_id = None
                self._pending_tasks.add(task_id)
                del self._running_tasks[task_id]
                await self.queue.publish_task(task)
                logger.info(f"Rescheduled task {task_id} from offline worker {worker_id}")
        
        logger.info(f"Worker {worker_id} unregistered")
        
        if self._on_worker_left:
            await self._on_worker_left(worker)
        
        return True
    
    async def update_worker_heartbeat(self, worker_id: str, status: Dict[str, Any]) -> bool:
        """
        Update worker heartbeat.
        
        Args:
            worker_id: Worker identifier
            status: Worker status update
            
        Returns:
            True if updated successfully
        """
        if worker_id not in self._workers:
            return False
        
        worker = self._workers[worker_id]
        worker.last_heartbeat = datetime.now()
        worker.cpu_usage = status.get("cpu_usage", worker.cpu_usage)
        worker.memory_usage = status.get("memory_usage", worker.memory_usage)
        worker.current_tasks = status.get("current_tasks", worker.current_tasks)
        
        # Update status based on tasks
        if worker.current_tasks > 0:
            worker.status = WorkerStatus.BUSY
        else:
            worker.status = WorkerStatus.IDLE
        
        return True
    
    async def submit_scan(
        self,
        targets: List[str],
        ports: List[int],
        scan_type: str = "tcp",
        options: Optional[Dict[str, Any]] = None,
        priority: TaskPriority = TaskPriority.NORMAL
    ) -> str:
        """
        Submit a distributed scan.
        
        Args:
            targets: List of targets to scan
            ports: List of ports to scan
            scan_type: Scan type (tcp, syn, udp, async)
            options: Scan options
            priority: Task priority
            
        Returns:
            Parent task ID
        """
        parent_task_id = str(uuid.uuid4())
        options = options or {}
        
        # Split into subtasks for distribution
        subtasks = self._create_subtasks(
            parent_task_id,
            targets,
            ports,
            scan_type,
            options,
            priority
        )
        
        # Store parent task
        parent_task = ScanTask(
            task_id=parent_task_id,
            targets=targets,
            ports=ports,
            scan_type=scan_type,
            options=options,
            priority=priority,
            status=TaskStatus.PENDING,
            metadata={"subtask_count": len(subtasks)}
        )
        self._tasks[parent_task_id] = parent_task
        self._results[parent_task_id] = []
        
        # Queue subtasks
        for subtask in subtasks:
            self._tasks[subtask.task_id] = subtask
            self._pending_tasks.add(subtask.task_id)
            await self.queue.publish_task(subtask)
        
        logger.info(
            f"Submitted scan {parent_task_id} with {len(subtasks)} subtasks "
            f"({len(targets)} targets, {len(ports)} ports)"
        )
        
        return parent_task_id
    
    def _create_subtasks(
        self,
        parent_task_id: str,
        targets: List[str],
        ports: List[int],
        scan_type: str,
        options: Dict[str, Any],
        priority: TaskPriority
    ) -> List[ScanTask]:
        """
        Create subtasks for distributed execution.
        
        Splits the scan into smaller chunks based on configuration.
        """
        subtasks = []
        
        # Split targets into chunks
        target_chunks = [
            targets[i:i + self.config.targets_per_task]
            for i in range(0, len(targets), self.config.targets_per_task)
        ]
        
        # Split ports into chunks
        port_chunks = [
            ports[i:i + self.config.ports_per_task]
            for i in range(0, len(ports), self.config.ports_per_task)
        ]
        
        # Create subtask for each combination
        for target_chunk in target_chunks:
            for port_chunk in port_chunks:
                subtask = ScanTask(
                    targets=target_chunk,
                    ports=port_chunk,
                    scan_type=scan_type,
                    options=options.copy(),
                    priority=priority,
                    parent_task_id=parent_task_id,
                    max_retries=self.config.max_task_retries,
                    timeout=self.config.task_timeout
                )
                subtasks.append(subtask)
        
        return subtasks
    
    async def get_scan_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a scan.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Task status dictionary or None
        """
        if task_id not in self._tasks:
            return None
        
        task = self._tasks[task_id]
        
        # Count subtask statuses
        subtask_ids = [
            t.task_id for t in self._tasks.values()
            if t.parent_task_id == task_id
        ]
        
        pending = sum(1 for t_id in subtask_ids if t_id in self._pending_tasks)
        running = sum(1 for t_id in subtask_ids if t_id in self._running_tasks)
        completed = sum(1 for t_id in subtask_ids if t_id in self._completed_tasks)
        failed = sum(1 for t_id in subtask_ids if t_id in self._failed_tasks)
        
        # Aggregate results
        results = self._results.get(task_id, [])
        total_open = sum(r.open_ports for r in results)
        total_closed = sum(r.closed_ports for r in results)
        total_filtered = sum(r.filtered_ports for r in results)
        
        return {
            "task_id": task_id,
            "status": task.status.value,
            "targets": len(task.targets),
            "ports": len(task.ports),
            "subtasks": {
                "total": len(subtask_ids),
                "pending": pending,
                "running": running,
                "completed": completed,
                "failed": failed
            },
            "results": {
                "open_ports": total_open,
                "closed_ports": total_closed,
                "filtered_ports": total_filtered
            },
            "created_at": task.created_at.isoformat() if task.created_at else None,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None
        }
    
    async def get_scan_results(self, task_id: str) -> List[Dict[str, Any]]:
        """
        Get results of a scan.
        
        Args:
            task_id: Task identifier
            
        Returns:
            List of scan results
        """
        results = self._results.get(task_id, [])
        
        # Flatten all results
        all_results = []
        for result in results:
            all_results.extend(result.results)
        
        return all_results
    
    async def cancel_scan(self, task_id: str) -> bool:
        """
        Cancel a scan.
        
        Args:
            task_id: Task identifier
            
        Returns:
            True if cancelled successfully
        """
        if task_id not in self._tasks:
            return False
        
        task = self._tasks[task_id]
        task.status = TaskStatus.CANCELLED
        
        # Cancel subtasks
        for t in self._tasks.values():
            if t.parent_task_id == task_id:
                t.status = TaskStatus.CANCELLED
                if t.task_id in self._pending_tasks:
                    self._pending_tasks.remove(t.task_id)
        
        logger.info(f"Cancelled scan {task_id}")
        return True
    
    def get_cluster_status(self) -> ClusterStatus:
        """
        Get cluster status.
        
        Returns:
            ClusterStatus object
        """
        active_workers = [
            w for w in self._workers.values()
            if w.status in (WorkerStatus.IDLE, WorkerStatus.BUSY)
        ]
        idle_workers = [
            w for w in self._workers.values()
            if w.status == WorkerStatus.IDLE
        ]
        
        total_capacity = sum(w.capacity for w in self._workers.values())
        available_capacity = sum(w.available_capacity for w in active_workers)
        
        uptime = 0.0
        if self._started_at:
            uptime = (datetime.now() - self._started_at).total_seconds()
        
        return ClusterStatus(
            cluster_id=self.config.cluster_id,
            master_id=self.config.master_id,
            total_workers=len(self._workers),
            active_workers=len(active_workers),
            idle_workers=len(idle_workers),
            total_capacity=total_capacity,
            available_capacity=available_capacity,
            pending_tasks=len(self._pending_tasks),
            running_tasks=len(self._running_tasks),
            completed_tasks=len(self._completed_tasks),
            failed_tasks=len(self._failed_tasks),
            started_at=self._started_at,
            uptime_seconds=uptime
        )
    
    def get_workers(self) -> List[WorkerInfo]:
        """Get list of registered workers."""
        return list(self._workers.values())
    
    def get_worker(self, worker_id: str) -> Optional[WorkerInfo]:
        """Get a specific worker."""
        return self._workers.get(worker_id)
    
    def set_task_complete_callback(
        self,
        callback: Callable[[ScanTaskResult], Awaitable[None]]
    ) -> None:
        """Set callback for task completion."""
        self._on_task_complete = callback
    
    def set_worker_joined_callback(
        self,
        callback: Callable[[WorkerInfo], Awaitable[None]]
    ) -> None:
        """Set callback for worker joining."""
        self._on_worker_joined = callback
    
    def set_worker_left_callback(
        self,
        callback: Callable[[WorkerInfo], Awaitable[None]]
    ) -> None:
        """Set callback for worker leaving."""
        self._on_worker_left = callback
    
    async def _heartbeat_monitor(self) -> None:
        """Monitor worker heartbeats."""
        while self._running:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                
                now = datetime.now()
                timeout_threshold = timedelta(seconds=self.config.heartbeat_timeout)
                
                for worker_id in list(self._workers.keys()):
                    worker = self._workers[worker_id]
                    
                    if worker.last_heartbeat:
                        elapsed = now - worker.last_heartbeat
                        if elapsed > timeout_threshold:
                            logger.warning(f"Worker {worker_id} heartbeat timeout")
                            worker.status = WorkerStatus.OFFLINE
                            await self.unregister_worker(worker_id)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat monitor error: {e}")
    
    async def _collect_results(self) -> None:
        """Collect results from workers."""
        while self._running:
            try:
                # Get result from queue
                result_msg = await self.queue.consume_result(timeout=1.0)
                
                if result_msg and result_msg.result:
                    result = result_msg.result
                    task_id = result.task_id
                    
                    if task_id in self._tasks:
                        task = self._tasks[task_id]
                        
                        if result.success:
                            task.status = TaskStatus.COMPLETED
                            task.completed_at = datetime.now()
                            
                            if task_id in self._running_tasks:
                                del self._running_tasks[task_id]
                            self._completed_tasks.add(task_id)
                            
                            # Add to parent task results
                            if task.parent_task_id:
                                if task.parent_task_id not in self._results:
                                    self._results[task.parent_task_id] = []
                                self._results[task.parent_task_id].append(result)
                                
                                # Check if parent is complete
                                await self._check_parent_completion(task.parent_task_id)
                        else:
                            # Handle failure
                            if task.retry_count < task.max_retries:
                                task.retry_count += 1
                                task.status = TaskStatus.RETRYING
                                task.worker_id = None
                                
                                if task_id in self._running_tasks:
                                    del self._running_tasks[task_id]
                                
                                self._pending_tasks.add(task_id)
                                await self.queue.publish_task(task)
                                logger.info(f"Retrying task {task_id} (attempt {task.retry_count})")
                            else:
                                task.status = TaskStatus.FAILED
                                
                                if task_id in self._running_tasks:
                                    del self._running_tasks[task_id]
                                self._failed_tasks.add(task_id)
                                
                                logger.error(f"Task {task_id} failed: {result.error}")
                        
                        if self._on_task_complete:
                            await self._on_task_complete(result)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Result collector error: {e}")
    
    async def _check_parent_completion(self, parent_task_id: str) -> None:
        """Check if a parent task is complete."""
        if parent_task_id not in self._tasks:
            return
        
        parent_task = self._tasks[parent_task_id]
        
        # Count subtask statuses
        subtask_ids = [
            t.task_id for t in self._tasks.values()
            if t.parent_task_id == parent_task_id
        ]
        
        completed = all(
            t_id in self._completed_tasks or t_id in self._failed_tasks
            for t_id in subtask_ids
        )
        
        if completed:
            all_failed = all(t_id in self._failed_tasks for t_id in subtask_ids)
            
            if all_failed:
                parent_task.status = TaskStatus.FAILED
            else:
                parent_task.status = TaskStatus.COMPLETED
            
            parent_task.completed_at = datetime.now()
            logger.info(f"Parent task {parent_task_id} completed with status {parent_task.status.value}")
    
    async def _schedule_tasks(self) -> None:
        """Schedule tasks to workers."""
        while self._running:
            try:
                await asyncio.sleep(0.1)  # Small delay to prevent tight loop
                
                # Get available workers
                available_workers = [
                    w for w in self._workers.values()
                    if w.is_available
                ]
                
                if not available_workers:
                    continue
                
                # Get pending tasks
                pending_count = await self.queue.get_queue_size("tasks")
                
                if pending_count == 0:
                    continue
                
                # Assign tasks to workers
                for worker in available_workers:
                    if worker.available_capacity <= 0:
                        continue
                    
                    task_msg = await self.queue.consume_task(timeout=0)
                    if not task_msg or not task_msg.task:
                        break
                    
                    task = task_msg.task
                    
                    # Update task state
                    if task.task_id in self._tasks:
                        self._tasks[task.task_id].status = TaskStatus.ASSIGNED
                        self._tasks[task.task_id].worker_id = worker.worker_id
                        self._tasks[task.task_id].started_at = datetime.now()
                    
                    if task.task_id in self._pending_tasks:
                        self._pending_tasks.remove(task.task_id)
                    self._running_tasks[task.task_id] = worker.worker_id
                    
                    worker.current_tasks += 1
                    if worker.current_tasks > 0:
                        worker.status = WorkerStatus.BUSY
                    
                    # Acknowledge task
                    await self.queue.acknowledge_task(task_msg.message_id)
                    
                    logger.debug(f"Assigned task {task.task_id} to worker {worker.worker_id}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Task scheduler error: {e}")
