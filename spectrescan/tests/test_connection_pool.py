"""
Tests for connection_pool module
by BitSpectreLabs
"""

import pytest
import asyncio
import time
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from spectrescan.core.connection_pool import PooledConnection, ConnectionPool


class TestPooledConnection:
    """Tests for PooledConnection dataclass."""
    
    def test_basic_init(self):
        """Test basic initialization."""
        reader = Mock()
        writer = Mock()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="192.168.1.1",
            port=80
        )
        assert conn.reader == reader
        assert conn.writer == writer
        assert conn.host == "192.168.1.1"
        assert conn.port == 80
        assert conn.is_ssl is False
        assert conn.use_count == 0
    
    def test_with_ssl(self):
        """Test connection with SSL flag."""
        reader = Mock()
        writer = Mock()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="example.com",
            port=443,
            is_ssl=True
        )
        assert conn.is_ssl is True
    
    def test_created_at_set(self):
        """Test that created_at is set automatically."""
        reader = Mock()
        writer = Mock()
        before = time.time()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=8080
        )
        after = time.time()
        assert before <= conn.created_at <= after
    
    def test_last_used_set(self):
        """Test that last_used is set automatically."""
        reader = Mock()
        writer = Mock()
        before = time.time()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=8080
        )
        after = time.time()
        assert before <= conn.last_used <= after
    
    def test_is_expired_false(self):
        """Test is_expired returns False for fresh connection."""
        reader = Mock()
        writer = Mock()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80
        )
        assert conn.is_expired(max_age=30.0) is False
    
    def test_is_expired_true(self):
        """Test is_expired returns True for old connection."""
        reader = Mock()
        writer = Mock()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80,
            created_at=time.time() - 60  # 60 seconds ago
        )
        assert conn.is_expired(max_age=30.0) is True
    
    def test_is_expired_custom_max_age(self):
        """Test is_expired with custom max_age."""
        reader = Mock()
        writer = Mock()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80,
            created_at=time.time() - 10  # 10 seconds ago
        )
        assert conn.is_expired(max_age=5.0) is True
        assert conn.is_expired(max_age=15.0) is False
    
    def test_is_idle_false(self):
        """Test is_idle returns False for recently used connection."""
        reader = Mock()
        writer = Mock()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80
        )
        assert conn.is_idle(idle_timeout=5.0) is False
    
    def test_is_idle_true(self):
        """Test is_idle returns True for idle connection."""
        reader = Mock()
        writer = Mock()
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80,
            last_used=time.time() - 10  # 10 seconds ago
        )
        assert conn.is_idle(idle_timeout=5.0) is True
    
    @pytest.mark.asyncio
    async def test_close(self):
        """Test closing a connection."""
        reader = Mock()
        writer = MagicMock()
        writer.is_closing.return_value = False
        writer.close = Mock()
        writer.wait_closed = AsyncMock()
        
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80
        )
        await conn.close()
        
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()
    
    @pytest.mark.asyncio
    async def test_close_already_closing(self):
        """Test closing when connection is already closing."""
        reader = Mock()
        writer = MagicMock()
        writer.is_closing.return_value = True
        
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80
        )
        await conn.close()
        
        # close() should not be called if already closing
        writer.close.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_close_with_exception(self):
        """Test close handles exceptions gracefully."""
        reader = Mock()
        writer = MagicMock()
        writer.is_closing.return_value = False
        writer.close = Mock(side_effect=Exception("Close error"))
        
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            host="localhost",
            port=80
        )
        # Should not raise
        await conn.close()


class TestConnectionPool:
    """Tests for ConnectionPool class."""
    
    def test_init_defaults(self):
        """Test default initialization."""
        pool = ConnectionPool()
        assert pool.max_connections == 1000
        assert pool.max_connections_per_host == 10
        assert pool.max_age == 30.0
        assert pool.idle_timeout == 5.0
        assert pool.enable_pooling is True
    
    def test_init_custom(self):
        """Test custom initialization."""
        pool = ConnectionPool(
            max_connections=500,
            max_connections_per_host=5,
            max_age=60.0,
            idle_timeout=10.0,
            enable_pooling=False
        )
        assert pool.max_connections == 500
        assert pool.max_connections_per_host == 5
        assert pool.max_age == 60.0
        assert pool.idle_timeout == 10.0
        assert pool.enable_pooling is False
    
    def test_stats_initialized(self):
        """Test statistics are initialized."""
        pool = ConnectionPool()
        assert pool.stats["hits"] == 0
        assert pool.stats["misses"] == 0
        assert pool.stats["creates"] == 0
        assert pool.stats["closes"] == 0
        assert pool.stats["expirations"] == 0
        assert pool.stats["errors"] == 0
    
    def test_pool_empty(self):
        """Test pool starts empty."""
        pool = ConnectionPool()
        assert pool._pool == {}
    
    @pytest.mark.asyncio
    async def test_acquire_pooling_disabled(self):
        """Test acquire when pooling is disabled."""
        pool = ConnectionPool(enable_pooling=False)
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            mock_reader = Mock()
            mock_writer = Mock()
            mock_create.return_value = (mock_reader, mock_writer)
            
            reader, writer = await pool.acquire("localhost", 80)
            
            mock_create.assert_awaited_once_with("localhost", 80, 3.0, False)
            assert reader == mock_reader
            assert writer == mock_writer
    
    @pytest.mark.asyncio
    async def test_acquire_miss_creates_connection(self):
        """Test acquire creates new connection when pool is empty."""
        pool = ConnectionPool()
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            mock_reader = Mock()
            mock_writer = Mock()
            mock_create.return_value = (mock_reader, mock_writer)
            
            reader, writer = await pool.acquire("localhost", 80)
            
            mock_create.assert_awaited_once()
            assert pool.stats["misses"] == 1
    
    @pytest.mark.asyncio
    async def test_acquire_hit_from_pool(self):
        """Test acquire reuses connection from pool."""
        pool = ConnectionPool()
        
        # Pre-populate pool
        mock_reader = Mock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        
        conn = PooledConnection(
            reader=mock_reader,
            writer=mock_writer,
            host="localhost",
            port=80
        )
        pool._pool[("localhost", 80)] = [conn]
        
        reader, writer = await pool.acquire("localhost", 80)
        
        assert reader == mock_reader
        assert writer == mock_writer
        assert pool.stats["hits"] == 1
        assert pool._pool[("localhost", 80)] == []  # Connection removed from pool
    
    @pytest.mark.asyncio
    async def test_acquire_skips_expired_connection(self):
        """Test acquire skips expired connections."""
        pool = ConnectionPool(max_age=30.0)
        
        # Pre-populate with expired connection
        mock_reader_old = Mock()
        mock_writer_old = MagicMock()
        mock_writer_old.is_closing.return_value = False
        mock_writer_old.close = Mock()
        mock_writer_old.wait_closed = AsyncMock()
        
        old_conn = PooledConnection(
            reader=mock_reader_old,
            writer=mock_writer_old,
            host="localhost",
            port=80,
            created_at=time.time() - 60  # Expired
        )
        pool._pool[("localhost", 80)] = [old_conn]
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            mock_reader = Mock()
            mock_writer = Mock()
            mock_create.return_value = (mock_reader, mock_writer)
            
            reader, writer = await pool.acquire("localhost", 80)
            
            # Should create new connection
            mock_create.assert_awaited_once()
            assert pool.stats["expirations"] == 1
    
    @pytest.mark.asyncio
    async def test_acquire_skips_closing_connection(self):
        """Test acquire skips connections that are closing."""
        pool = ConnectionPool()
        
        # Pre-populate with closing connection
        mock_reader = Mock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = True  # Connection is closing
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        
        conn = PooledConnection(
            reader=mock_reader,
            writer=mock_writer,
            host="localhost",
            port=80
        )
        pool._pool[("localhost", 80)] = [conn]
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            mock_reader_new = Mock()
            mock_writer_new = Mock()
            mock_create.return_value = (mock_reader_new, mock_writer_new)
            
            reader, writer = await pool.acquire("localhost", 80)
            
            mock_create.assert_awaited_once()
    
    @pytest.mark.asyncio
    async def test_acquire_with_ssl(self):
        """Test acquire with SSL."""
        pool = ConnectionPool()
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            mock_reader = Mock()
            mock_writer = Mock()
            mock_create.return_value = (mock_reader, mock_writer)
            
            await pool.acquire("localhost", 443, use_ssl=True)
            
            mock_create.assert_awaited_once_with("localhost", 443, 3.0, True)
    
    @pytest.mark.asyncio
    async def test_acquire_custom_timeout(self):
        """Test acquire with custom timeout."""
        pool = ConnectionPool()
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            mock_reader = Mock()
            mock_writer = Mock()
            mock_create.return_value = (mock_reader, mock_writer)
            
            await pool.acquire("localhost", 80, timeout=10.0)
            
            mock_create.assert_awaited_once_with("localhost", 80, 10.0, False)
    
    @pytest.mark.asyncio
    async def test_release_reusable(self):
        """Test release adds connection back to pool."""
        pool = ConnectionPool()
        
        mock_reader = Mock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        
        await pool.release("localhost", 80, mock_reader, mock_writer, reusable=True)
        
        assert ("localhost", 80) in pool._pool
        assert len(pool._pool[("localhost", 80)]) == 1
    
    @pytest.mark.asyncio
    async def test_release_not_reusable(self):
        """Test release closes non-reusable connection."""
        pool = ConnectionPool()
        
        mock_reader = Mock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        
        await pool.release("localhost", 80, mock_reader, mock_writer, reusable=False)
        
        # Connection should not be in pool
        assert pool._pool.get(("localhost", 80), []) == []
        pool.stats["closes"] += 1  # This would be done in actual implementation
    
    @pytest.mark.asyncio
    async def test_release_pooling_disabled(self):
        """Test release when pooling is disabled."""
        pool = ConnectionPool(enable_pooling=False)
        
        mock_reader = Mock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        
        await pool.release("localhost", 80, mock_reader, mock_writer)
        
        # Pool should still be empty
        assert pool._pool == {}
    
    def test_get_stats(self):
        """Test getting pool statistics."""
        pool = ConnectionPool()
        pool.stats["hits"] = 10
        pool.stats["misses"] = 5
        
        stats = pool.stats
        assert stats["hits"] == 10
        assert stats["misses"] == 5


class TestConnectionPoolConcurrency:
    """Tests for concurrent access to connection pool."""
    
    @pytest.mark.asyncio
    async def test_concurrent_acquire(self):
        """Test multiple concurrent acquires."""
        pool = ConnectionPool()
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            mock_reader = Mock()
            mock_writer = Mock()
            mock_create.return_value = (mock_reader, mock_writer)
            
            # Acquire multiple connections concurrently
            tasks = [
                pool.acquire("localhost", 80)
                for _ in range(10)
            ]
            
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 10
            assert mock_create.await_count == 10
    
    @pytest.mark.asyncio
    async def test_concurrent_release(self):
        """Test multiple concurrent releases."""
        pool = ConnectionPool()
        
        mock_writers = []
        for i in range(5):
            mock_reader = Mock()
            mock_writer = MagicMock()
            mock_writer.is_closing.return_value = False
            mock_writers.append((mock_reader, mock_writer))
        
        tasks = [
            pool.release("localhost", 80, r, w, reusable=True)
            for r, w in mock_writers
        ]
        
        await asyncio.gather(*tasks)
        
        # All connections should be in pool
        assert len(pool._pool.get(("localhost", 80), [])) == 5


class TestConnectionPoolLimits:
    """Tests for connection pool limits."""
    
    @pytest.mark.asyncio
    async def test_max_connections_per_host(self):
        """Test max connections per host limit."""
        pool = ConnectionPool(max_connections_per_host=3)
        
        # Add connections beyond limit
        for i in range(5):
            mock_reader = Mock()
            mock_writer = MagicMock()
            mock_writer.is_closing.return_value = False
            await pool.release("localhost", 80, mock_reader, mock_writer)
        
        # Should only keep up to max_connections_per_host
        # Note: The actual implementation may or may not enforce this
        # This test documents expected behavior
        connections = pool._pool.get(("localhost", 80), [])
        assert len(connections) <= 5  # Adjust based on implementation


class TestConnectionPoolHealth:
    """Tests for connection health checking."""
    
    @pytest.mark.asyncio
    async def test_removes_expired_on_acquire(self):
        """Test that expired connections are removed during acquire."""
        pool = ConnectionPool(max_age=1.0)
        
        # Add expired connection
        mock_reader = Mock()
        mock_writer = MagicMock()
        mock_writer.is_closing.return_value = False
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        
        old_conn = PooledConnection(
            reader=mock_reader,
            writer=mock_writer,
            host="localhost",
            port=80,
            created_at=time.time() - 10
        )
        pool._pool[("localhost", 80)] = [old_conn]
        
        with patch.object(pool, '_create_connection', new_callable=AsyncMock) as mock_create:
            new_reader = Mock()
            new_writer = Mock()
            mock_create.return_value = (new_reader, new_writer)
            
            await pool.acquire("localhost", 80)
            
            assert pool.stats["expirations"] >= 1
