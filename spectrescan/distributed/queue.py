"""
Message Queue Implementation for Distributed Scanning.
by BitSpectreLabs

This module provides message queue abstractions for distributing scan tasks
and collecting results across worker nodes.
"""

import asyncio
import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Awaitable
from collections import deque
import threading

from spectrescan.distributed.models import ScanTask, ScanTaskResult, TaskPriority

logger = logging.getLogger(__name__)


@dataclass
class TaskMessage:
    """
    A message containing a scan task.
    
    Attributes:
        message_id: Unique message identifier
        task: The scan task
        created_at: Message creation time
        attempts: Number of delivery attempts
        max_attempts: Maximum delivery attempts
    """
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task: Optional[ScanTask] = None
    created_at: Optional[datetime] = None
    attempts: int = 0
    max_attempts: int = 3
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "message_id": self.message_id,
            "task": self.task.to_dict() if self.task else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskMessage':
        """Create from dictionary."""
        return cls(
            message_id=data.get("message_id", str(uuid.uuid4())),
            task=ScanTask.from_dict(data["task"]) if data.get("task") else None,
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            attempts=data.get("attempts", 0),
            max_attempts=data.get("max_attempts", 3)
        )
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'TaskMessage':
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class ResultMessage:
    """
    A message containing scan results.
    
    Attributes:
        message_id: Unique message identifier
        result: The scan result
        created_at: Message creation time
    """
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    result: Optional[ScanTaskResult] = None
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "message_id": self.message_id,
            "result": self.result.to_dict() if self.result else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ResultMessage':
        """Create from dictionary."""
        return cls(
            message_id=data.get("message_id", str(uuid.uuid4())),
            result=ScanTaskResult.from_dict(data["result"]) if data.get("result") else None,
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None
        )
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str: str) -> 'ResultMessage':
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


class MessageQueue(ABC):
    """
    Abstract base class for message queues.
    
    Provides a common interface for different queue implementations
    (Redis, RabbitMQ, in-memory, etc.).
    """
    
    @abstractmethod
    async def connect(self) -> bool:
        """Connect to the queue backend."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the queue backend."""
        pass
    
    @abstractmethod
    async def publish_task(self, task: ScanTask) -> bool:
        """
        Publish a scan task to the queue.
        
        Args:
            task: Scan task to publish
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    async def consume_task(self, timeout: float = 0) -> Optional[TaskMessage]:
        """
        Consume a task from the queue.
        
        Args:
            timeout: Timeout in seconds (0 = non-blocking)
            
        Returns:
            TaskMessage or None if queue is empty
        """
        pass
    
    @abstractmethod
    async def publish_result(self, result: ScanTaskResult) -> bool:
        """
        Publish a scan result to the queue.
        
        Args:
            result: Scan result to publish
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    async def consume_result(self, timeout: float = 0) -> Optional[ResultMessage]:
        """
        Consume a result from the queue.
        
        Args:
            timeout: Timeout in seconds (0 = non-blocking)
            
        Returns:
            ResultMessage or None if queue is empty
        """
        pass
    
    @abstractmethod
    async def acknowledge_task(self, message_id: str) -> bool:
        """
        Acknowledge that a task has been processed.
        
        Args:
            message_id: Message ID to acknowledge
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    async def reject_task(self, message_id: str, requeue: bool = True) -> bool:
        """
        Reject a task and optionally requeue it.
        
        Args:
            message_id: Message ID to reject
            requeue: Whether to requeue the task
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    async def get_queue_size(self, queue_name: str = "tasks") -> int:
        """
        Get the size of a queue.
        
        Args:
            queue_name: Name of the queue
            
        Returns:
            Number of messages in queue
        """
        pass
    
    @abstractmethod
    async def clear_queue(self, queue_name: str = "tasks") -> int:
        """
        Clear all messages from a queue.
        
        Args:
            queue_name: Name of the queue
            
        Returns:
            Number of messages cleared
        """
        pass


class MemoryQueue(MessageQueue):
    """
    In-memory message queue implementation.
    
    Useful for testing and single-node deployments.
    Thread-safe implementation using locks.
    """
    
    def __init__(self):
        """Initialize the memory queue."""
        self._task_queue: deque[TaskMessage] = deque()
        self._result_queue: deque[ResultMessage] = deque()
        self._pending_tasks: Dict[str, TaskMessage] = {}
        self._lock = threading.Lock()
        self._connected = False
        self._task_event = asyncio.Event()
        self._result_event = asyncio.Event()
    
    async def connect(self) -> bool:
        """Connect to the queue (no-op for memory queue)."""
        self._connected = True
        logger.info("Memory queue connected")
        return True
    
    async def disconnect(self) -> None:
        """Disconnect from the queue."""
        self._connected = False
        logger.info("Memory queue disconnected")
    
    async def publish_task(self, task: ScanTask) -> bool:
        """Publish a task to the queue."""
        if not self._connected:
            return False
        
        with self._lock:
            message = TaskMessage(task=task)
            
            # Priority queue - insert based on priority
            if task.priority == TaskPriority.CRITICAL:
                self._task_queue.appendleft(message)
            else:
                self._task_queue.append(message)
            
            self._task_event.set()
            logger.debug(f"Published task {task.task_id} to queue")
        
        return True
    
    async def consume_task(self, timeout: float = 0) -> Optional[TaskMessage]:
        """Consume a task from the queue."""
        if not self._connected:
            return None
        
        # Wait for task if timeout specified
        if timeout > 0 and len(self._task_queue) == 0:
            try:
                self._task_event.clear()
                await asyncio.wait_for(self._task_event.wait(), timeout)
            except asyncio.TimeoutError:
                return None
        
        with self._lock:
            if len(self._task_queue) == 0:
                return None
            
            message = self._task_queue.popleft()
            message.attempts += 1
            self._pending_tasks[message.message_id] = message
            logger.debug(f"Consumed task {message.task.task_id if message.task else 'unknown'}")
            return message
    
    async def publish_result(self, result: ScanTaskResult) -> bool:
        """Publish a result to the queue."""
        if not self._connected:
            return False
        
        with self._lock:
            message = ResultMessage(result=result)
            self._result_queue.append(message)
            self._result_event.set()
            logger.debug(f"Published result for task {result.task_id}")
        
        return True
    
    async def consume_result(self, timeout: float = 0) -> Optional[ResultMessage]:
        """Consume a result from the queue."""
        if not self._connected:
            return None
        
        # Wait for result if timeout specified
        if timeout > 0 and len(self._result_queue) == 0:
            try:
                self._result_event.clear()
                await asyncio.wait_for(self._result_event.wait(), timeout)
            except asyncio.TimeoutError:
                return None
        
        with self._lock:
            if len(self._result_queue) == 0:
                return None
            
            message = self._result_queue.popleft()
            logger.debug(f"Consumed result for task {message.result.task_id if message.result else 'unknown'}")
            return message
    
    async def acknowledge_task(self, message_id: str) -> bool:
        """Acknowledge a task has been processed."""
        with self._lock:
            if message_id in self._pending_tasks:
                del self._pending_tasks[message_id]
                logger.debug(f"Acknowledged message {message_id}")
                return True
        return False
    
    async def reject_task(self, message_id: str, requeue: bool = True) -> bool:
        """Reject a task and optionally requeue it."""
        with self._lock:
            if message_id not in self._pending_tasks:
                return False
            
            message = self._pending_tasks.pop(message_id)
            
            if requeue and message.attempts < message.max_attempts:
                self._task_queue.append(message)
                self._task_event.set()
                logger.debug(f"Requeued message {message_id}")
            else:
                logger.debug(f"Rejected message {message_id} (no requeue)")
            
            return True
    
    async def get_queue_size(self, queue_name: str = "tasks") -> int:
        """Get queue size."""
        with self._lock:
            if queue_name == "tasks":
                return len(self._task_queue)
            elif queue_name == "results":
                return len(self._result_queue)
            return 0
    
    async def clear_queue(self, queue_name: str = "tasks") -> int:
        """Clear a queue."""
        with self._lock:
            if queue_name == "tasks":
                count = len(self._task_queue)
                self._task_queue.clear()
                return count
            elif queue_name == "results":
                count = len(self._result_queue)
                self._result_queue.clear()
                return count
            return 0
    
    def get_pending_count(self) -> int:
        """Get count of pending (unacknowledged) tasks."""
        with self._lock:
            return len(self._pending_tasks)


class RedisQueue(MessageQueue):
    """
    Redis-based message queue implementation.
    
    Provides durable, distributed queue functionality using Redis.
    Supports priority queues and message acknowledgement.
    """
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        prefix: str = "spectrescan:",
        ssl: bool = False
    ):
        """
        Initialize Redis queue.
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            prefix: Key prefix for queue names
            ssl: Use SSL/TLS
        """
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.prefix = prefix
        self.ssl = ssl
        self._redis = None
        self._connected = False
        
        # Queue names
        self.task_queue = f"{prefix}tasks"
        self.result_queue = f"{prefix}results"
        self.pending_set = f"{prefix}pending"
        self.processing_hash = f"{prefix}processing"
    
    async def connect(self) -> bool:
        """Connect to Redis."""
        try:
            import redis.asyncio as aioredis
            
            self._redis = aioredis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                ssl=self.ssl,
                decode_responses=True
            )
            
            # Test connection
            await self._redis.ping()
            self._connected = True
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
            return True
            
        except ImportError:
            logger.error("redis package not installed. Install with: pip install redis")
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._redis:
            await self._redis.close()
            self._connected = False
            logger.info("Disconnected from Redis")
    
    async def publish_task(self, task: ScanTask) -> bool:
        """Publish a task to Redis queue."""
        if not self._connected or not self._redis:
            return False
        
        try:
            message = TaskMessage(task=task)
            
            # Use sorted set for priority queue
            # Lower score = higher priority
            score = (5 - task.priority.value) * 1000000 + message.created_at.timestamp()
            
            await self._redis.zadd(
                self.task_queue,
                {message.to_json(): score}
            )
            
            logger.debug(f"Published task {task.task_id} to Redis")
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish task: {e}")
            return False
    
    async def consume_task(self, timeout: float = 0) -> Optional[TaskMessage]:
        """Consume a task from Redis queue."""
        if not self._connected or not self._redis:
            return None
        
        try:
            if timeout > 0:
                # Blocking pop with timeout
                result = await self._redis.bzpopmin(self.task_queue, timeout)
                if not result:
                    return None
                _, json_str, _ = result
            else:
                # Non-blocking pop
                result = await self._redis.zpopmin(self.task_queue)
                if not result:
                    return None
                json_str, _ = result[0]
            
            message = TaskMessage.from_json(json_str)
            message.attempts += 1
            
            # Store in processing hash
            await self._redis.hset(
                self.processing_hash,
                message.message_id,
                message.to_json()
            )
            
            logger.debug(f"Consumed task {message.task.task_id if message.task else 'unknown'}")
            return message
            
        except Exception as e:
            logger.error(f"Failed to consume task: {e}")
            return None
    
    async def publish_result(self, result: ScanTaskResult) -> bool:
        """Publish a result to Redis queue."""
        if not self._connected or not self._redis:
            return False
        
        try:
            message = ResultMessage(result=result)
            
            await self._redis.lpush(
                self.result_queue,
                message.to_json()
            )
            
            logger.debug(f"Published result for task {result.task_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish result: {e}")
            return False
    
    async def consume_result(self, timeout: float = 0) -> Optional[ResultMessage]:
        """Consume a result from Redis queue."""
        if not self._connected or not self._redis:
            return None
        
        try:
            if timeout > 0:
                result = await self._redis.brpop(self.result_queue, timeout)
                if not result:
                    return None
                _, json_str = result
            else:
                json_str = await self._redis.rpop(self.result_queue)
                if not json_str:
                    return None
            
            message = ResultMessage.from_json(json_str)
            logger.debug(f"Consumed result for task {message.result.task_id if message.result else 'unknown'}")
            return message
            
        except Exception as e:
            logger.error(f"Failed to consume result: {e}")
            return None
    
    async def acknowledge_task(self, message_id: str) -> bool:
        """Acknowledge a task has been processed."""
        if not self._connected or not self._redis:
            return False
        
        try:
            deleted = await self._redis.hdel(self.processing_hash, message_id)
            logger.debug(f"Acknowledged message {message_id}")
            return deleted > 0
            
        except Exception as e:
            logger.error(f"Failed to acknowledge task: {e}")
            return False
    
    async def reject_task(self, message_id: str, requeue: bool = True) -> bool:
        """Reject a task and optionally requeue it."""
        if not self._connected or not self._redis:
            return False
        
        try:
            # Get the message from processing hash
            json_str = await self._redis.hget(self.processing_hash, message_id)
            if not json_str:
                return False
            
            # Remove from processing
            await self._redis.hdel(self.processing_hash, message_id)
            
            if requeue:
                message = TaskMessage.from_json(json_str)
                if message.attempts < message.max_attempts and message.task:
                    # Requeue with same priority
                    await self.publish_task(message.task)
                    logger.debug(f"Requeued message {message_id}")
                else:
                    logger.debug(f"Max retries reached for message {message_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to reject task: {e}")
            return False
    
    async def get_queue_size(self, queue_name: str = "tasks") -> int:
        """Get queue size."""
        if not self._connected or not self._redis:
            return 0
        
        try:
            if queue_name == "tasks":
                return await self._redis.zcard(self.task_queue)
            elif queue_name == "results":
                return await self._redis.llen(self.result_queue)
            return 0
            
        except Exception as e:
            logger.error(f"Failed to get queue size: {e}")
            return 0
    
    async def clear_queue(self, queue_name: str = "tasks") -> int:
        """Clear a queue."""
        if not self._connected or not self._redis:
            return 0
        
        try:
            if queue_name == "tasks":
                count = await self._redis.zcard(self.task_queue)
                await self._redis.delete(self.task_queue)
                return count
            elif queue_name == "results":
                count = await self._redis.llen(self.result_queue)
                await self._redis.delete(self.result_queue)
                return count
            return 0
            
        except Exception as e:
            logger.error(f"Failed to clear queue: {e}")
            return 0
    
    async def get_processing_count(self) -> int:
        """Get count of messages being processed."""
        if not self._connected or not self._redis:
            return 0
        
        try:
            return await self._redis.hlen(self.processing_hash)
        except Exception as e:
            logger.error(f"Failed to get processing count: {e}")
            return 0
    
    async def recover_stale_tasks(self, timeout_seconds: int = 3600) -> int:
        """
        Recover tasks that have been processing too long.
        
        Args:
            timeout_seconds: Time after which a task is considered stale
            
        Returns:
            Number of tasks recovered
        """
        if not self._connected or not self._redis:
            return 0
        
        try:
            recovered = 0
            now = datetime.now()
            
            # Get all processing tasks
            processing = await self._redis.hgetall(self.processing_hash)
            
            for message_id, json_str in processing.items():
                message = TaskMessage.from_json(json_str)
                
                if message.created_at:
                    age = (now - message.created_at).total_seconds()
                    if age > timeout_seconds:
                        await self.reject_task(message_id, requeue=True)
                        recovered += 1
            
            if recovered > 0:
                logger.info(f"Recovered {recovered} stale tasks")
            
            return recovered
            
        except Exception as e:
            logger.error(f"Failed to recover stale tasks: {e}")
            return 0


def create_queue(queue_type: str = "memory", **kwargs) -> MessageQueue:
    """
    Factory function to create a message queue.
    
    Args:
        queue_type: Type of queue ("memory" or "redis")
        **kwargs: Additional arguments for the queue
        
    Returns:
        MessageQueue instance
    """
    if queue_type == "memory":
        return MemoryQueue()
    elif queue_type == "redis":
        return RedisQueue(**kwargs)
    else:
        raise ValueError(f"Unknown queue type: {queue_type}")
