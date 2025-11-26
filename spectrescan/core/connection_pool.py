"""
Connection pooling for efficient socket reuse
by BitSpectreLabs

Maintains pool of reusable TCP connections to reduce overhead.
"""

import asyncio
import socket
import ssl
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class PooledConnection:
    """Represents a pooled connection."""
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    host: str
    port: int
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    is_ssl: bool = False
    use_count: int = 0
    
    def is_expired(self, max_age: float = 30.0) -> bool:
        """Check if connection has expired."""
        return (time.time() - self.created_at) > max_age
    
    def is_idle(self, idle_timeout: float = 5.0) -> bool:
        """Check if connection has been idle too long."""
        return (time.time() - self.last_used) > idle_timeout
    
    async def close(self) -> None:
        """Close the connection."""
        try:
            if not self.writer.is_closing():
                self.writer.close()
                await self.writer.wait_closed()
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")


class ConnectionPool:
    """
    Async connection pool for socket reuse.
    
    Maintains a pool of open connections to reduce TCP handshake overhead.
    Implements connection limits, expiration, and health checking.
    """
    
    def __init__(
        self,
        max_connections: int = 1000,
        max_connections_per_host: int = 10,
        max_age: float = 30.0,
        idle_timeout: float = 5.0,
        enable_pooling: bool = True
    ):
        """
        Initialize connection pool.
        
        Args:
            max_connections: Maximum total connections in pool
            max_connections_per_host: Maximum connections per host
            max_age: Maximum connection age in seconds
            idle_timeout: Idle timeout in seconds
            enable_pooling: Enable/disable pooling (for testing)
        """
        self.max_connections = max_connections
        self.max_connections_per_host = max_connections_per_host
        self.max_age = max_age
        self.idle_timeout = idle_timeout
        self.enable_pooling = enable_pooling
        
        # Pool storage: {(host, port): [PooledConnection]}
        self._pool: Dict[Tuple[str, int], list] = {}
        self._pool_lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "creates": 0,
            "closes": 0,
            "expirations": 0,
            "errors": 0
        }
    
    async def acquire(
        self,
        host: str,
        port: int,
        timeout: float = 3.0,
        use_ssl: bool = False
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Acquire a connection from the pool or create new one.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            use_ssl: Use SSL/TLS
            
        Returns:
            Tuple of (reader, writer)
        """
        if not self.enable_pooling:
            return await self._create_connection(host, port, timeout, use_ssl)
        
        key = (host, port)
        
        # Try to get from pool
        async with self._pool_lock:
            if key in self._pool and self._pool[key]:
                # Try connections until we find a valid one
                while self._pool[key]:
                    conn = self._pool[key].pop(0)
                    
                    # Check if connection is still valid
                    if not conn.is_expired(self.max_age) and not conn.writer.is_closing():
                        conn.last_used = time.time()
                        conn.use_count += 1
                        self.stats["hits"] += 1
                        logger.debug(f"Reusing connection to {host}:{port} (uses: {conn.use_count})")
                        return conn.reader, conn.writer
                    else:
                        await conn.close()
                        self.stats["expirations"] += 1
        
        # No valid connection in pool, create new one
        self.stats["misses"] += 1
        return await self._create_connection(host, port, timeout, use_ssl)
    
    async def release(
        self,
        host: str,
        port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        reusable: bool = True
    ) -> None:
        """
        Release connection back to pool or close it.
        
        Args:
            host: Target host
            port: Target port
            reader: Stream reader
            writer: Stream writer
            reusable: Whether connection can be reused
        """
        if not self.enable_pooling or not reusable or writer.is_closing():
            # Close connection
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
                self.stats["closes"] += 1
            except Exception as e:
                logger.debug(f"Error closing connection: {e}")
            return
        
        key = (host, port)
        
        async with self._pool_lock:
            # Check pool limits
            if key not in self._pool:
                self._pool[key] = []
            
            # Check if we can add to pool
            if len(self._pool[key]) < self.max_connections_per_host:
                total_connections = sum(len(conns) for conns in self._pool.values())
                
                if total_connections < self.max_connections:
                    # Add to pool
                    conn = PooledConnection(
                        reader=reader,
                        writer=writer,
                        host=host,
                        port=port,
                        created_at=time.time(),
                        last_used=time.time()
                    )
                    self._pool[key].append(conn)
                    logger.debug(f"Returned connection to pool: {host}:{port}")
                    return
        
        # Pool is full, close connection
        try:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
            self.stats["closes"] += 1
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")
    
    async def _create_connection(
        self,
        host: str,
        port: int,
        timeout: float,
        use_ssl: bool = False
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Create a new connection.
        
        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            use_ssl: Use SSL/TLS
            
        Returns:
            Tuple of (reader, writer)
        """
        try:
            if use_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context),
                    timeout=timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=timeout
                )
            
            self.stats["creates"] += 1
            logger.debug(f"Created new connection to {host}:{port}")
            return reader, writer
            
        except Exception as e:
            self.stats["errors"] += 1
            raise
    
    async def cleanup(self) -> None:
        """Clean up expired and idle connections."""
        async with self._pool_lock:
            keys_to_remove = []
            
            for key, connections in self._pool.items():
                valid_connections = []
                
                for conn in connections:
                    if conn.is_expired(self.max_age) or conn.is_idle(self.idle_timeout):
                        await conn.close()
                        self.stats["expirations"] += 1
                    else:
                        valid_connections.append(conn)
                
                if valid_connections:
                    self._pool[key] = valid_connections
                else:
                    keys_to_remove.append(key)
            
            # Remove empty entries
            for key in keys_to_remove:
                del self._pool[key]
    
    async def close_all(self) -> None:
        """Close all connections in pool."""
        async with self._pool_lock:
            for connections in self._pool.values():
                for conn in connections:
                    await conn.close()
                    self.stats["closes"] += 1
            
            self._pool.clear()
    
    def get_stats(self) -> dict:
        """
        Get pool statistics.
        
        Returns:
            Dictionary with pool statistics
        """
        total_connections = sum(len(conns) for conns in self._pool.values())
        hit_rate = 0.0
        if (self.stats["hits"] + self.stats["misses"]) > 0:
            hit_rate = self.stats["hits"] / (self.stats["hits"] + self.stats["misses"])
        
        return {
            **self.stats,
            "total_connections": total_connections,
            "unique_hosts": len(self._pool),
            "hit_rate": hit_rate
        }
    
    def __repr__(self) -> str:
        """String representation of pool."""
        stats = self.get_stats()
        return (
            f"ConnectionPool(connections={stats['total_connections']}, "
            f"hosts={stats['unique_hosts']}, hit_rate={stats['hit_rate']:.2%})"
        )


# Global connection pool (can be shared across scans)
_global_pool: Optional[ConnectionPool] = None


def get_global_pool() -> ConnectionPool:
    """
    Get or create global connection pool.
    
    Returns:
        Global ConnectionPool instance
    """
    global _global_pool
    if _global_pool is None:
        _global_pool = ConnectionPool()
    return _global_pool


def reset_global_pool() -> None:
    """Reset global connection pool."""
    global _global_pool
    _global_pool = None
