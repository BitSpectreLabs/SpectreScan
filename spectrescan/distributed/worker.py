"""
Distributed Scanning Worker Node.
by BitSpectreLabs

This module implements the worker node for distributed scanning.
Workers receive tasks from the master, execute scans, and report results.
"""

import asyncio
import logging
import uuid
import socket
import platform
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, field

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from spectrescan.distributed.models import (
    WorkerInfo,
    WorkerStatus,
    ScanTask,
    ScanTaskResult,
    TaskStatus
)
from spectrescan.distributed.queue import MessageQueue, MemoryQueue, TaskMessage
from spectrescan.core.scanner import PortScanner
from spectrescan.core.utils import ScanResult

logger = logging.getLogger(__name__)


@dataclass
class WorkerConfig:
    """
    Worker node configuration.
    
    Attributes:
        worker_id: Unique worker identifier
        hostname: Worker hostname
        ip_address: Worker IP address
        port: Worker port
        capacity: Maximum concurrent tasks
        master_host: Master node host
        master_port: Master node port
        heartbeat_interval: Heartbeat interval in seconds
        task_timeout: Default task timeout
        enable_ssl: Enable SSL/TLS
        tags: Worker tags for filtering
    """
    worker_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    hostname: str = field(default_factory=socket.gethostname)
    ip_address: str = field(default_factory=lambda: _get_local_ip())
    port: int = 5001
    capacity: int = 4
    master_host: str = "localhost"
    master_port: int = 5000
    heartbeat_interval: int = 30
    task_timeout: int = 3600
    enable_ssl: bool = False
    tags: List[str] = field(default_factory=list)


def _get_local_ip() -> str:
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


class DistributedWorker:
    """
    Worker node for distributed scanning.
    
    Workers receive scan tasks from the master, execute them using the
    local scanner, and report results back to the master.
    """
    
    def __init__(
        self,
        config: Optional[WorkerConfig] = None,
        queue: Optional[MessageQueue] = None
    ):
        """
        Initialize the worker node.
        
        Args:
            config: Worker configuration
            queue: Message queue instance
        """
        self.config = config or WorkerConfig()
        self.queue = queue or MemoryQueue()
        
        # State tracking
        self._running = False
        self._started_at: Optional[datetime] = None
        self._current_tasks: Dict[str, asyncio.Task] = {}
        self._completed_count = 0
        self._failed_count = 0
        
        # Scanner instance
        self._scanner: Optional[PortScanner] = None
        
        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._task_executor_task: Optional[asyncio.Task] = None
        
        # Callbacks
        self._on_task_start: Optional[Callable[[ScanTask], Awaitable[None]]] = None
        self._on_task_complete: Optional[Callable[[ScanTaskResult], Awaitable[None]]] = None
        
        logger.info(f"Worker {self.config.worker_id} initialized")
    
    def get_info(self) -> WorkerInfo:
        """
        Get worker information.
        
        Returns:
            WorkerInfo object
        """
        cpu_usage = 0.0
        memory_usage = 0.0
        
        if PSUTIL_AVAILABLE:
            cpu_usage = psutil.cpu_percent(interval=0.1)
            memory_usage = psutil.virtual_memory().percent
        
        return WorkerInfo(
            worker_id=self.config.worker_id,
            hostname=self.config.hostname,
            ip_address=self.config.ip_address,
            port=self.config.port,
            status=self._get_status(),
            capacity=self.config.capacity,
            current_tasks=len(self._current_tasks),
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            last_heartbeat=datetime.now(),
            registered_at=self._started_at,
            version="2.1.0",
            tags=self.config.tags
        )
    
    def _get_status(self) -> WorkerStatus:
        """Get current worker status."""
        if not self._running:
            return WorkerStatus.OFFLINE
        elif len(self._current_tasks) >= self.config.capacity:
            return WorkerStatus.BUSY
        elif len(self._current_tasks) > 0:
            return WorkerStatus.BUSY
        else:
            return WorkerStatus.IDLE
    
    async def start(self) -> bool:
        """
        Start the worker node.
        
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
            self._heartbeat_task = asyncio.create_task(self._send_heartbeats())
            self._task_executor_task = asyncio.create_task(self._execute_tasks())
            
            logger.info(f"Worker {self.config.worker_id} started")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start worker: {e}")
            return False
    
    async def stop(self) -> None:
        """Stop the worker node."""
        self._running = False
        
        # Cancel running tasks
        for task_id, task in list(self._current_tasks.items()):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        # Cancel background tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self._task_executor_task:
            self._task_executor_task.cancel()
            try:
                await self._task_executor_task
            except asyncio.CancelledError:
                pass
        
        # Disconnect from queue
        await self.queue.disconnect()
        
        logger.info(f"Worker {self.config.worker_id} stopped")
    
    async def _send_heartbeats(self) -> None:
        """Send periodic heartbeats to master."""
        while self._running:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                
                # Get worker status
                info = self.get_info()
                
                # Log heartbeat
                logger.debug(
                    f"Heartbeat: {info.current_tasks}/{info.capacity} tasks, "
                    f"CPU: {info.cpu_usage:.1f}%, MEM: {info.memory_usage:.1f}%"
                )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    async def _execute_tasks(self) -> None:
        """Execute tasks from the queue."""
        while self._running:
            try:
                # Check capacity
                if len(self._current_tasks) >= self.config.capacity:
                    await asyncio.sleep(0.1)
                    continue
                
                # Get task from queue
                task_msg = await self.queue.consume_task(timeout=1.0)
                
                if task_msg and task_msg.task:
                    task = task_msg.task
                    
                    # Start task execution
                    exec_task = asyncio.create_task(
                        self._execute_scan_task(task, task_msg.message_id)
                    )
                    self._current_tasks[task.task_id] = exec_task
                    
                    # Cleanup completed task
                    exec_task.add_done_callback(
                        lambda t, tid=task.task_id: self._cleanup_task(tid)
                    )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Task executor error: {e}")
    
    def _cleanup_task(self, task_id: str) -> None:
        """Remove completed task from tracking."""
        if task_id in self._current_tasks:
            del self._current_tasks[task_id]
    
    async def _execute_scan_task(self, task: ScanTask, message_id: str) -> None:
        """
        Execute a scan task.
        
        Args:
            task: The scan task to execute
            message_id: Queue message ID for acknowledgement
        """
        logger.info(f"Executing task {task.task_id}: {len(task.targets)} targets, {len(task.ports)} ports")
        
        start_time = datetime.now()
        result = ScanTaskResult(
            task_id=task.task_id,
            worker_id=self.config.worker_id,
            started_at=start_time
        )
        
        if self._on_task_start:
            await self._on_task_start(task)
        
        try:
            # Execute the scan
            scan_results = await self._run_scan(task)
            
            # Process results
            result.success = True
            result.results = [self._scan_result_to_dict(r) for r in scan_results]
            result.open_ports = sum(1 for r in scan_results if r.state == "open")
            result.closed_ports = sum(1 for r in scan_results if r.state == "closed")
            result.filtered_ports = sum(1 for r in scan_results if r.state == "filtered")
            result.hosts_scanned = len(task.targets)
            
            self._completed_count += 1
            logger.info(f"Task {task.task_id} completed: {result.open_ports} open ports")
            
        except asyncio.CancelledError:
            result.success = False
            result.error = "Task cancelled"
            self._failed_count += 1
            logger.warning(f"Task {task.task_id} cancelled")
            
        except Exception as e:
            result.success = False
            result.error = str(e)
            self._failed_count += 1
            logger.error(f"Task {task.task_id} failed: {e}")
        
        finally:
            result.completed_at = datetime.now()
            result.duration = (result.completed_at - start_time).total_seconds()
            
            # Publish result
            await self.queue.publish_result(result)
            
            # Acknowledge task
            await self.queue.acknowledge_task(message_id)
            
            if self._on_task_complete:
                await self._on_task_complete(result)
    
    async def _run_scan(self, task: ScanTask) -> List[ScanResult]:
        """
        Run the actual port scan.
        
        Args:
            task: Scan task
            
        Returns:
            List of scan results
        """
        from spectrescan.core.presets import get_scan_config
        
        # Get scan configuration
        options = task.options.copy()
        
        # Set up scanner options
        threads = options.get("threads", 100)
        timeout = options.get("timeout", 2.0)
        
        # Use presets module to get config
        config = get_scan_config("TOP_PORTS")
        config.threads = threads
        config.timeout = timeout
        
        # Override with task options
        if "service_detection" in options:
            config.enable_service_detection = options["service_detection"]
        if "os_detection" in options:
            config.enable_os_detection = options["os_detection"]
        if "banner_grab" in options:
            config.enable_banner_grabbing = options["banner_grab"]
        
        # Create scanner
        scanner = PortScanner(
            timeout=config.timeout,
            threads=config.threads
        )
        
        all_results = []
        
        # Scan each target
        for target in task.targets:
            try:
                results = await self._scan_target(
                    scanner,
                    target,
                    task.ports,
                    task.scan_type,
                    config
                )
                all_results.extend(results)
                
            except Exception as e:
                logger.error(f"Error scanning {target}: {e}")
        
        return all_results
    
    async def _scan_target(
        self,
        scanner: PortScanner,
        target: str,
        ports: List[int],
        scan_type: str,
        config: Any
    ) -> List[ScanResult]:
        """
        Scan a single target.
        
        Args:
            scanner: Scanner instance
            target: Target to scan
            ports: Ports to scan
            scan_type: Scan type
            config: Scan configuration
            
        Returns:
            List of scan results
        """
        # Run scan in thread pool to not block async
        loop = asyncio.get_event_loop()
        
        results = await loop.run_in_executor(
            None,
            lambda: scanner.scan(
                target=target,
                ports=ports,
                scan_type=scan_type
            )
        )
        
        return results
    
    def _scan_result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to dictionary."""
        return {
            "host": result.host,
            "port": result.port,
            "state": result.state,
            "protocol": result.protocol,
            "service": result.service,
            "banner": result.banner,
            "timestamp": result.timestamp.isoformat() if result.timestamp else None
        }
    
    def set_task_start_callback(
        self,
        callback: Callable[[ScanTask], Awaitable[None]]
    ) -> None:
        """Set callback for task start."""
        self._on_task_start = callback
    
    def set_task_complete_callback(
        self,
        callback: Callable[[ScanTaskResult], Awaitable[None]]
    ) -> None:
        """Set callback for task completion."""
        self._on_task_complete = callback
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get worker statistics.
        
        Returns:
            Statistics dictionary
        """
        uptime = 0.0
        if self._started_at:
            uptime = (datetime.now() - self._started_at).total_seconds()
        
        return {
            "worker_id": self.config.worker_id,
            "status": self._get_status().value,
            "current_tasks": len(self._current_tasks),
            "capacity": self.config.capacity,
            "completed_tasks": self._completed_count,
            "failed_tasks": self._failed_count,
            "uptime_seconds": uptime
        }


async def start_worker(
    master_host: str = "localhost",
    master_port: int = 5000,
    worker_port: int = 5001,
    capacity: int = 4,
    tags: Optional[List[str]] = None,
    queue: Optional[MessageQueue] = None
) -> DistributedWorker:
    """
    Start a distributed worker.
    
    Convenience function to create and start a worker node.
    
    Args:
        master_host: Master node host
        master_port: Master node port
        worker_port: Worker port
        capacity: Maximum concurrent tasks
        tags: Worker tags
        queue: Message queue instance
        
    Returns:
        Running DistributedWorker instance
    """
    config = WorkerConfig(
        master_host=master_host,
        master_port=master_port,
        port=worker_port,
        capacity=capacity,
        tags=tags or []
    )
    
    worker = DistributedWorker(config=config, queue=queue)
    await worker.start()
    
    return worker
