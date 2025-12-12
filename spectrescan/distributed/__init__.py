"""
SpectreScan Distributed Scanning Module.
by BitSpectreLabs

This module provides distributed scanning capabilities with a master-worker
architecture for large-scale network reconnaissance.

Features:
- Master-worker architecture
- Worker node registration and discovery
- Task distribution and load balancing
- Result aggregation from workers
- Worker health monitoring
- Automatic failover and retry
- Secure communication (TLS/mTLS)
- Redis/RabbitMQ message queue support
"""

from spectrescan.distributed.master import DistributedMaster
from spectrescan.distributed.worker import DistributedWorker
from spectrescan.distributed.cluster import ClusterManager, ClusterConfig
from spectrescan.distributed.queue import (
    MessageQueue,
    RedisQueue,
    MemoryQueue,
    TaskMessage,
    ResultMessage
)
from spectrescan.distributed.models import (
    WorkerInfo,
    WorkerStatus,
    ScanTask,
    ScanTaskResult,
    ClusterStatus
)

__all__ = [
    # Master/Worker
    'DistributedMaster',
    'DistributedWorker',
    
    # Cluster
    'ClusterManager',
    'ClusterConfig',
    
    # Queue
    'MessageQueue',
    'RedisQueue',
    'MemoryQueue',
    'TaskMessage',
    'ResultMessage',
    
    # Models
    'WorkerInfo',
    'WorkerStatus',
    'ScanTask',
    'ScanTaskResult',
    'ClusterStatus',
]

# Check if Redis is available
REDIS_AVAILABLE = False
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    pass

# Check if Celery is available
CELERY_AVAILABLE = False
try:
    import celery
    CELERY_AVAILABLE = True
except ImportError:
    pass
