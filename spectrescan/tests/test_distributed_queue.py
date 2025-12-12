"""
Tests for Distributed Scanning Message Queue.
by BitSpectreLabs
"""

import pytest
import asyncio
from datetime import datetime

from spectrescan.distributed.queue import (
    MessageQueue,
    MemoryQueue,
    TaskMessage,
    ResultMessage,
    create_queue
)
from spectrescan.distributed.models import (
    ScanTask,
    ScanTaskResult,
    TaskPriority
)


class TestTaskMessage:
    """Tests for TaskMessage class."""
    
    def test_task_message_creation(self):
        """Test TaskMessage creation."""
        task = ScanTask(targets=["192.168.1.1"], ports=[80])
        msg = TaskMessage(task=task)
        
        assert msg.message_id is not None
        assert msg.task == task
        assert msg.created_at is not None
        assert msg.attempts == 0
    
    def test_task_message_to_dict(self):
        """Test to_dict conversion."""
        task = ScanTask(targets=["192.168.1.1"], ports=[80])
        msg = TaskMessage(task=task, attempts=2)
        
        data = msg.to_dict()
        
        assert data["message_id"] == msg.message_id
        assert data["attempts"] == 2
        assert data["task"]["targets"] == ["192.168.1.1"]
    
    def test_task_message_from_dict(self):
        """Test from_dict conversion."""
        data = {
            "message_id": "msg-123",
            "task": {
                "task_id": "task-456",
                "targets": ["10.0.0.1"],
                "ports": [22]
            },
            "attempts": 1
        }
        
        msg = TaskMessage.from_dict(data)
        
        assert msg.message_id == "msg-123"
        assert msg.attempts == 1
        assert msg.task.targets == ["10.0.0.1"]
    
    def test_task_message_json_roundtrip(self):
        """Test JSON serialization roundtrip."""
        task = ScanTask(targets=["192.168.1.1"], ports=[80, 443])
        msg = TaskMessage(task=task)
        
        json_str = msg.to_json()
        restored = TaskMessage.from_json(json_str)
        
        assert restored.message_id == msg.message_id
        assert restored.task.targets == task.targets


class TestResultMessage:
    """Tests for ResultMessage class."""
    
    def test_result_message_creation(self):
        """Test ResultMessage creation."""
        result = ScanTaskResult(task_id="task-123", worker_id="worker-1")
        msg = ResultMessage(result=result)
        
        assert msg.message_id is not None
        assert msg.result == result
        assert msg.created_at is not None
    
    def test_result_message_to_dict(self):
        """Test to_dict conversion."""
        result = ScanTaskResult(
            task_id="task-123",
            worker_id="worker-1",
            success=True,
            open_ports=5
        )
        msg = ResultMessage(result=result)
        
        data = msg.to_dict()
        
        assert data["message_id"] == msg.message_id
        assert data["result"]["task_id"] == "task-123"
        assert data["result"]["open_ports"] == 5


class TestMemoryQueue:
    """Tests for MemoryQueue class."""
    
    @pytest.fixture
    def queue(self):
        """Create a MemoryQueue instance."""
        return MemoryQueue()
    
    @pytest.mark.asyncio
    async def test_connect_disconnect(self, queue):
        """Test connect and disconnect."""
        assert await queue.connect() is True
        assert queue._connected is True
        
        await queue.disconnect()
        assert queue._connected is False
    
    @pytest.mark.asyncio
    async def test_publish_consume_task(self, queue):
        """Test publishing and consuming tasks."""
        await queue.connect()
        
        task = ScanTask(targets=["192.168.1.1"], ports=[80])
        
        # Publish task
        assert await queue.publish_task(task) is True
        
        # Check queue size
        assert await queue.get_queue_size("tasks") == 1
        
        # Consume task
        msg = await queue.consume_task()
        
        assert msg is not None
        assert msg.task.targets == task.targets
        assert msg.attempts == 1
        
        # Queue should be empty now
        assert await queue.get_queue_size("tasks") == 0
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_publish_consume_result(self, queue):
        """Test publishing and consuming results."""
        await queue.connect()
        
        result = ScanTaskResult(
            task_id="task-123",
            worker_id="worker-1",
            success=True
        )
        
        # Publish result
        assert await queue.publish_result(result) is True
        
        # Check queue size
        assert await queue.get_queue_size("results") == 1
        
        # Consume result
        msg = await queue.consume_result()
        
        assert msg is not None
        assert msg.result.task_id == "task-123"
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_acknowledge_task(self, queue):
        """Test task acknowledgement."""
        await queue.connect()
        
        task = ScanTask(targets=["192.168.1.1"], ports=[80])
        await queue.publish_task(task)
        
        msg = await queue.consume_task()
        assert msg is not None
        
        # Task should be pending
        assert queue.get_pending_count() == 1
        
        # Acknowledge
        assert await queue.acknowledge_task(msg.message_id) is True
        
        # No longer pending
        assert queue.get_pending_count() == 0
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_reject_task_with_requeue(self, queue):
        """Test task rejection with requeue."""
        await queue.connect()
        
        task = ScanTask(targets=["192.168.1.1"], ports=[80])
        await queue.publish_task(task)
        
        msg = await queue.consume_task()
        assert msg is not None
        
        # Reject with requeue
        assert await queue.reject_task(msg.message_id, requeue=True) is True
        
        # Task should be back in queue
        assert await queue.get_queue_size("tasks") == 1
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_reject_task_without_requeue(self, queue):
        """Test task rejection without requeue."""
        await queue.connect()
        
        task = ScanTask(targets=["192.168.1.1"], ports=[80])
        await queue.publish_task(task)
        
        msg = await queue.consume_task()
        assert msg is not None
        
        # Reject without requeue
        assert await queue.reject_task(msg.message_id, requeue=False) is True
        
        # Task should not be in queue
        assert await queue.get_queue_size("tasks") == 0
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_clear_queue(self, queue):
        """Test clearing queue."""
        await queue.connect()
        
        # Add multiple tasks
        for i in range(5):
            task = ScanTask(targets=[f"192.168.1.{i}"], ports=[80])
            await queue.publish_task(task)
        
        assert await queue.get_queue_size("tasks") == 5
        
        # Clear queue
        cleared = await queue.clear_queue("tasks")
        
        assert cleared == 5
        assert await queue.get_queue_size("tasks") == 0
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_priority_queue(self, queue):
        """Test priority-based task ordering."""
        await queue.connect()
        
        # Add tasks with different priorities
        low_task = ScanTask(
            targets=["192.168.1.1"],
            ports=[80],
            priority=TaskPriority.LOW
        )
        normal_task = ScanTask(
            targets=["192.168.1.2"],
            ports=[80],
            priority=TaskPriority.NORMAL
        )
        critical_task = ScanTask(
            targets=["192.168.1.3"],
            ports=[80],
            priority=TaskPriority.CRITICAL
        )
        
        # Publish in order: low, normal, critical
        await queue.publish_task(low_task)
        await queue.publish_task(normal_task)
        await queue.publish_task(critical_task)
        
        # Critical should be first due to appendleft
        msg1 = await queue.consume_task()
        assert msg1.task.targets == ["192.168.1.3"]
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_consume_with_timeout(self, queue):
        """Test consuming with timeout on empty queue."""
        await queue.connect()
        
        # Should timeout quickly
        msg = await queue.consume_task(timeout=0.1)
        assert msg is None
        
        await queue.disconnect()
    
    @pytest.mark.asyncio
    async def test_operations_when_disconnected(self, queue):
        """Test operations fail when disconnected."""
        # Don't connect
        task = ScanTask(targets=["192.168.1.1"], ports=[80])
        
        assert await queue.publish_task(task) is False
        assert await queue.consume_task() is None
        
        result = ScanTaskResult(task_id="task-123", worker_id="worker-1")
        assert await queue.publish_result(result) is False


class TestCreateQueue:
    """Tests for create_queue factory function."""
    
    def test_create_memory_queue(self):
        """Test creating memory queue."""
        queue = create_queue("memory")
        assert isinstance(queue, MemoryQueue)
    
    def test_create_unknown_queue_type(self):
        """Test creating unknown queue type raises error."""
        with pytest.raises(ValueError):
            create_queue("unknown")
    
    def test_create_redis_queue(self):
        """Test creating Redis queue (may fail if redis not installed)."""
        try:
            from spectrescan.distributed.queue import RedisQueue
            queue = create_queue("redis", host="localhost", port=6379)
            assert isinstance(queue, RedisQueue)
        except ImportError:
            pytest.skip("redis package not installed")
