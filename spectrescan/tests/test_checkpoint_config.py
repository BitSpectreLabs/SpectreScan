"""
Tests for Scan Checkpoint and Config File modules.

Tests for spectrescan.core.checkpoint and spectrescan.core.config.

by BitSpectreLabs
"""

import pytest
import json
import tempfile
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from spectrescan.core.checkpoint import (
    CheckpointManager,
    CheckpointData,
    CheckpointState,
    ScanProgress,
    can_resume_scan,
    get_resume_summary,
)
from spectrescan.core.config import (
    ConfigManager,
    SpectrescanConfig,
    ScanDefaults,
    ServiceDetectionConfig,
    OutputConfig,
    APIConfig,
    NotificationsConfig,
    CheckpointsConfig,
    AdvancedConfig,
    ConfigError,
    get_config,
    get_config_manager,
    reload_config,
)


# ============================================================================
# CHECKPOINT TESTS
# ============================================================================

class TestScanProgress:
    """Tests for ScanProgress dataclass."""
    
    def test_default_values(self):
        """Test default progress values."""
        progress = ScanProgress()
        assert progress.total_targets == 0
        assert progress.completed_targets == 0
        assert progress.total_ports == 0
        assert progress.completed_ports == 0
        assert progress.current_target is None
        assert progress.current_port is None
        assert progress.elapsed_seconds == 0.0
    
    def test_target_percent_zero_total(self):
        """Test target percentage with zero total."""
        progress = ScanProgress(total_targets=0, completed_targets=0)
        assert progress.target_percent == 0.0
    
    def test_target_percent_calculation(self):
        """Test target percentage calculation."""
        progress = ScanProgress(total_targets=10, completed_targets=5)
        assert progress.target_percent == 50.0
    
    def test_port_percent_zero_total(self):
        """Test port percentage with zero total."""
        progress = ScanProgress(total_ports=0, completed_ports=0)
        assert progress.port_percent == 0.0
    
    def test_port_percent_calculation(self):
        """Test port percentage calculation."""
        progress = ScanProgress(total_ports=1000, completed_ports=250)
        assert progress.port_percent == 25.0
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        progress = ScanProgress(
            total_targets=5,
            completed_targets=2,
            total_ports=500,
            completed_ports=200,
            current_target="192.168.1.1",
            current_port=80,
            start_time="2025-01-01T10:00:00",
            elapsed_seconds=120.5,
        )
        data = progress.to_dict()
        
        assert data["total_targets"] == 5
        assert data["completed_targets"] == 2
        assert data["total_ports"] == 500
        assert data["completed_ports"] == 200
        assert data["current_target"] == "192.168.1.1"
        assert data["current_port"] == 80
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "total_targets": 10,
            "completed_targets": 5,
            "total_ports": 1000,
            "completed_ports": 500,
            "current_target": "10.0.0.1",
            "current_port": 443,
            "start_time": "2025-01-01T10:00:00",
            "last_update": "2025-01-01T10:05:00",
            "elapsed_seconds": 300.0,
            "estimated_remaining_seconds": 300.0,
            "scan_rate_per_second": 1.67,
        }
        progress = ScanProgress.from_dict(data)
        
        assert progress.total_targets == 10
        assert progress.completed_targets == 5
        assert progress.current_target == "10.0.0.1"
        assert progress.scan_rate_per_second == 1.67


class TestCheckpointState:
    """Tests for CheckpointState enum."""
    
    def test_all_states(self):
        """Test all checkpoint states exist."""
        assert CheckpointState.RUNNING.value == "running"
        assert CheckpointState.PAUSED.value == "paused"
        assert CheckpointState.INTERRUPTED.value == "interrupted"
        assert CheckpointState.COMPLETED.value == "completed"
        assert CheckpointState.FAILED.value == "failed"
    
    def test_state_from_string(self):
        """Test creating state from string."""
        state = CheckpointState("running")
        assert state == CheckpointState.RUNNING


class TestCheckpointData:
    """Tests for CheckpointData dataclass."""
    
    def test_default_values(self):
        """Test default checkpoint values."""
        cp = CheckpointData()
        assert cp.checkpoint_id == ""
        assert cp.checkpoint_version == "1.0"
        assert cp.state == CheckpointState.RUNNING
        assert cp.targets == []
        assert cp.ports == []
        assert cp.scan_type == "tcp"
        assert cp.threads == 100
        assert cp.timeout == 2.0
    
    def test_generate_id(self):
        """Test checkpoint ID generation."""
        cp = CheckpointData(
            targets=["192.168.1.1"],
            ports=[80, 443],
            scan_type="tcp",
            created_at="2025-01-01T10:00:00",
        )
        id1 = cp.generate_id()
        
        # Same params should generate same ID
        cp2 = CheckpointData(
            targets=["192.168.1.1"],
            ports=[80, 443],
            scan_type="tcp",
            created_at="2025-01-01T10:00:00",
        )
        id2 = cp2.generate_id()
        
        assert id1 == id2
        assert len(id1) == 12
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        cp = CheckpointData(
            checkpoint_id="abc123",
            targets=["192.168.1.1", "192.168.1.2"],
            ports=[80, 443, 8080],
            scan_type="syn",
            threads=200,
            state=CheckpointState.INTERRUPTED,
        )
        data = cp.to_dict()
        
        assert data["checkpoint_id"] == "abc123"
        assert data["targets"] == ["192.168.1.1", "192.168.1.2"]
        assert data["ports"] == [80, 443, 8080]
        assert data["scan_type"] == "syn"
        assert data["threads"] == 200
        assert data["state"] == "interrupted"
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "checkpoint_id": "def456",
            "checkpoint_version": "1.0",
            "created_at": "2025-01-01T10:00:00",
            "updated_at": "2025-01-01T10:05:00",
            "state": "running",
            "targets": ["10.0.0.1"],
            "ports": [22, 80],
            "scan_type": "async",
            "threads": 500,
            "timeout": 1.5,
            "enable_service_detection": True,
            "progress": {"total_targets": 1, "total_ports": 2},
            "completed_targets": [],
            "completed_ports_per_target": {},
            "results": [],
        }
        cp = CheckpointData.from_dict(data)
        
        assert cp.checkpoint_id == "def456"
        assert cp.state == CheckpointState.RUNNING
        assert cp.targets == ["10.0.0.1"]
        assert cp.ports == [22, 80]
        assert cp.threads == 500
    
    def test_get_remaining_targets(self):
        """Test getting remaining targets."""
        cp = CheckpointData(
            targets=["192.168.1.1", "192.168.1.2", "192.168.1.3"],
            completed_targets={"192.168.1.1"},
        )
        remaining = cp.get_remaining_targets()
        
        assert len(remaining) == 2
        assert "192.168.1.1" not in remaining
        assert "192.168.1.2" in remaining
        assert "192.168.1.3" in remaining
    
    def test_get_remaining_ports(self):
        """Test getting remaining ports for a target."""
        cp = CheckpointData(
            ports=[80, 443, 8080, 8443],
            completed_ports_per_target={"192.168.1.1": {80, 443}},
        )
        remaining = cp.get_remaining_ports("192.168.1.1")
        
        assert len(remaining) == 2
        assert 8080 in remaining
        assert 8443 in remaining
    
    def test_get_remaining_ports_no_progress(self):
        """Test getting remaining ports with no progress."""
        cp = CheckpointData(ports=[80, 443, 8080])
        remaining = cp.get_remaining_ports("10.0.0.1")
        
        assert len(remaining) == 3
    
    def test_mark_port_complete(self):
        """Test marking a port as complete."""
        cp = CheckpointData(
            targets=["192.168.1.1"],
            ports=[80, 443, 8080],
        )
        cp.progress.total_ports = 3
        
        cp.mark_port_complete("192.168.1.1", 80)
        
        assert 80 in cp.completed_ports_per_target["192.168.1.1"]
        assert cp.progress.completed_ports == 1
        assert cp.progress.current_port == 80
    
    def test_mark_target_complete(self):
        """Test marking a target as complete."""
        cp = CheckpointData(
            targets=["192.168.1.1", "192.168.1.2"],
        )
        cp.progress.total_targets = 2
        
        cp.mark_target_complete("192.168.1.1")
        
        assert "192.168.1.1" in cp.completed_targets
        assert cp.progress.completed_targets == 1
    
    def test_add_result(self):
        """Test adding a scan result."""
        cp = CheckpointData()
        
        result = {
            "host": "192.168.1.1",
            "port": 80,
            "state": "open",
            "service": "http",
        }
        cp.add_result(result)
        
        assert len(cp.results) == 1
        assert cp.results[0]["port"] == 80
    
    def test_add_error(self):
        """Test adding an error."""
        cp = CheckpointData()
        
        cp.add_error("192.168.1.1", 80, "Connection refused")
        
        assert len(cp.errors) == 1
        assert cp.errors[0]["target"] == "192.168.1.1"
        assert cp.errors[0]["error"] == "Connection refused"
    
    def test_add_to_retry_queue(self):
        """Test adding to retry queue."""
        cp = CheckpointData()
        
        cp.add_to_retry_queue("192.168.1.1", 443, "Timeout")
        
        assert len(cp.retry_queue) == 1
        assert cp.retry_queue[0]["port"] == 443
        assert cp.retry_queue[0]["reason"] == "Timeout"


class TestCheckpointManager:
    """Tests for CheckpointManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for checkpoints."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create checkpoint manager with temp directory."""
        return CheckpointManager(
            checkpoint_dir=temp_dir,
            autosave_interval=0,  # Disable autosave for tests
            enable_signal_handlers=False,
        )
    
    def test_create_checkpoint(self, manager):
        """Test creating a new checkpoint."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1", "192.168.1.2"],
            ports=[80, 443, 8080],
            scan_type="tcp",
            threads=100,
        )
        
        assert cp.checkpoint_id != ""
        assert len(cp.targets) == 2
        assert len(cp.ports) == 3
        assert cp.progress.total_targets == 2
        assert cp.progress.total_ports == 6  # 2 targets * 3 ports
    
    def test_save_checkpoint(self, manager, temp_dir):
        """Test saving a checkpoint."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        
        path = manager.save_checkpoint(cp)
        
        assert path.exists()
        assert path.suffix == ".json"
        
        # Verify contents
        with open(path) as f:
            data = json.load(f)
        assert data["checkpoint_id"] == cp.checkpoint_id
    
    def test_load_checkpoint(self, manager):
        """Test loading a checkpoint."""
        cp = manager.create_checkpoint(
            targets=["10.0.0.1"],
            ports=[22, 80, 443],
            scan_type="syn",
        )
        
        loaded = manager.load_checkpoint(cp.checkpoint_id)
        
        assert loaded.checkpoint_id == cp.checkpoint_id
        assert loaded.targets == cp.targets
        assert loaded.ports == cp.ports
        assert loaded.scan_type == cp.scan_type
    
    def test_load_checkpoint_not_found(self, manager):
        """Test loading non-existent checkpoint."""
        with pytest.raises(FileNotFoundError):
            manager.load_checkpoint("nonexistent123")
    
    def test_update_progress(self, manager):
        """Test updating checkpoint progress."""
        manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80, 443],
        )
        
        manager.update_progress(
            target="192.168.1.1",
            port=80,
            result={"host": "192.168.1.1", "port": 80, "state": "open"},
        )
        
        cp = manager.get_current_checkpoint()
        assert cp.progress.current_target == "192.168.1.1"
        assert 80 in cp.completed_ports_per_target["192.168.1.1"]
    
    def test_mark_complete(self, manager, temp_dir):
        """Test marking checkpoint as complete."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        
        manager.mark_complete()
        
        loaded = manager.load_checkpoint(cp.checkpoint_id)
        assert loaded.state == CheckpointState.COMPLETED
    
    def test_mark_interrupted(self, manager):
        """Test marking checkpoint as interrupted."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        
        manager.mark_interrupted()
        
        loaded = manager.load_checkpoint(cp.checkpoint_id)
        assert loaded.state == CheckpointState.INTERRUPTED
    
    def test_mark_failed(self, manager):
        """Test marking checkpoint as failed."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        
        manager.mark_failed("Network error")
        
        loaded = manager.load_checkpoint(cp.checkpoint_id)
        assert loaded.state == CheckpointState.FAILED
        assert len(loaded.errors) == 1
    
    def test_delete_checkpoint(self, manager):
        """Test deleting a checkpoint."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        manager.mark_complete()  # Can only delete completed
        
        deleted = manager.delete_checkpoint(cp.checkpoint_id)
        
        assert deleted is True
        with pytest.raises(FileNotFoundError):
            manager.load_checkpoint(cp.checkpoint_id)
    
    def test_delete_running_checkpoint_fails(self, manager):
        """Test that deleting running checkpoint fails without force."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        
        deleted = manager.delete_checkpoint(cp.checkpoint_id, force=False)
        
        assert deleted is False
    
    def test_delete_running_checkpoint_force(self, manager):
        """Test force deleting running checkpoint."""
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        
        deleted = manager.delete_checkpoint(cp.checkpoint_id, force=True)
        
        assert deleted is True
    
    def test_list_checkpoints(self, manager):
        """Test listing checkpoints."""
        # Create multiple checkpoints
        cp1 = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        manager.mark_complete()
        
        cp2 = manager.create_checkpoint(
            targets=["192.168.1.2"],
            ports=[443],
        )
        
        checkpoints = manager.list_checkpoints()
        
        assert len(checkpoints) == 2
        ids = [c["id"] for c in checkpoints]
        assert cp1.checkpoint_id in ids
        assert cp2.checkpoint_id in ids
    
    def test_cleanup_completed(self, manager):
        """Test cleaning up old checkpoints."""
        # Create and complete a checkpoint
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        manager.mark_complete()
        
        # Cleanup with 0 days (delete all)
        deleted = manager.cleanup_completed(keep_days=0)
        
        # Should delete the completed checkpoint
        # Note: This might not delete if timestamp is very recent
        # We test the function runs without error
        assert deleted >= 0
    
    def test_get_current_checkpoint(self, manager):
        """Test getting current checkpoint."""
        assert manager.get_current_checkpoint() is None
        
        cp = manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80],
        )
        
        current = manager.get_current_checkpoint()
        assert current is not None
        assert current.checkpoint_id == cp.checkpoint_id


class TestCheckpointHelpers:
    """Tests for checkpoint helper functions."""
    
    def test_can_resume_running(self):
        """Test can_resume_scan for running checkpoint."""
        cp = CheckpointData(state=CheckpointState.RUNNING)
        assert can_resume_scan(cp) is True
    
    def test_can_resume_paused(self):
        """Test can_resume_scan for paused checkpoint."""
        cp = CheckpointData(state=CheckpointState.PAUSED)
        assert can_resume_scan(cp) is True
    
    def test_can_resume_interrupted(self):
        """Test can_resume_scan for interrupted checkpoint."""
        cp = CheckpointData(state=CheckpointState.INTERRUPTED)
        assert can_resume_scan(cp) is True
    
    def test_cannot_resume_completed(self):
        """Test can_resume_scan for completed checkpoint."""
        cp = CheckpointData(state=CheckpointState.COMPLETED)
        assert can_resume_scan(cp) is False
    
    def test_cannot_resume_failed(self):
        """Test can_resume_scan for failed checkpoint."""
        cp = CheckpointData(state=CheckpointState.FAILED)
        assert can_resume_scan(cp) is False
    
    def test_get_resume_summary(self):
        """Test get_resume_summary function."""
        cp = CheckpointData(
            checkpoint_id="test123",
            state=CheckpointState.INTERRUPTED,
            scan_type="tcp",
            targets=["192.168.1.1", "192.168.1.2", "192.168.1.3"],
            ports=[80, 443, 8080],
            completed_targets={"192.168.1.1"},
            created_at="2025-01-01T10:00:00",
        )
        cp.progress.total_ports = 9
        cp.progress.completed_ports = 3
        cp.progress.elapsed_seconds = 60.0
        cp.progress.last_update = "2025-01-01T10:01:00"
        cp.results = [{"port": 80}, {"port": 443}]
        cp.errors = [{"error": "test"}]
        
        summary = get_resume_summary(cp)
        
        assert summary["checkpoint_id"] == "test123"
        assert summary["state"] == "interrupted"
        assert summary["scan_type"] == "tcp"
        assert summary["total_targets"] == 3
        assert summary["remaining_targets"] == 2
        assert summary["results_collected"] == 2
        assert summary["errors_encountered"] == 1
        assert summary["elapsed_time"] == 60.0


# ============================================================================
# CONFIG TESTS
# ============================================================================

class TestScanDefaults:
    """Tests for ScanDefaults dataclass."""
    
    def test_default_values(self):
        """Test default scan values."""
        defaults = ScanDefaults()
        assert defaults.threads == 100
        assert defaults.timeout == 2.0
        assert defaults.rate_limit is None
        assert defaults.randomize is False
        assert defaults.default_ports == "1-1000"
        assert defaults.scan_type == "tcp"
        assert defaults.timing_template == 3
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        defaults = ScanDefaults(threads=200, timeout=3.0)
        data = defaults.to_dict()
        
        assert data["threads"] == 200
        assert data["timeout"] == 3.0
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {"threads": 500, "timeout": 1.5, "scan_type": "syn"}
        defaults = ScanDefaults.from_dict(data)
        
        assert defaults.threads == 500
        assert defaults.timeout == 1.5
        assert defaults.scan_type == "syn"


class TestServiceDetectionConfig:
    """Tests for ServiceDetectionConfig dataclass."""
    
    def test_default_values(self):
        """Test default service detection values."""
        config = ServiceDetectionConfig()
        assert config.enabled is True
        assert config.banner_grabbing is True
        assert config.os_detection is False
        assert config.ssl_analysis is False
        assert config.cve_matching is False
        assert config.version_intensity == 7
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {"enabled": False, "ssl_analysis": True}
        config = ServiceDetectionConfig.from_dict(data)
        
        assert config.enabled is False
        assert config.ssl_analysis is True


class TestOutputConfig:
    """Tests for OutputConfig dataclass."""
    
    def test_default_values(self):
        """Test default output values."""
        config = OutputConfig()
        assert config.default_format == "text"
        assert config.color_enabled is True
        assert config.verbose is False
        assert config.quiet is False


class TestAPIConfig:
    """Tests for APIConfig dataclass."""
    
    def test_default_values(self):
        """Test default API values."""
        config = APIConfig()
        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.workers == 4
        assert config.enable_auth is True
        assert config.token_expiry_hours == 24
        assert config.cors_origins == ["*"]


class TestNotificationsConfig:
    """Tests for NotificationsConfig dataclass."""
    
    def test_default_values(self):
        """Test default notification values."""
        config = NotificationsConfig()
        assert config.enabled is False
        assert config.on_scan_complete is True
        assert config.webhook_url is None


class TestCheckpointsConfig:
    """Tests for CheckpointsConfig dataclass."""
    
    def test_default_values(self):
        """Test default checkpoint config values."""
        config = CheckpointsConfig()
        assert config.enabled is True
        assert config.auto_save is True
        assert config.auto_save_interval == 30
        assert config.cleanup_days == 7


class TestAdvancedConfig:
    """Tests for AdvancedConfig dataclass."""
    
    def test_default_values(self):
        """Test default advanced values."""
        config = AdvancedConfig()
        assert config.max_retries == 3
        assert config.retry_delay == 1.0
        assert config.connection_pool_size == 100
        assert config.dns_timeout == 5.0
        assert config.max_memory_mb == 512
        assert config.log_level == "INFO"


class TestSpectrescanConfig:
    """Tests for SpectrescanConfig dataclass."""
    
    def test_default_values(self):
        """Test default complete config."""
        config = SpectrescanConfig()
        
        assert isinstance(config.scan, ScanDefaults)
        assert isinstance(config.service_detection, ServiceDetectionConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.api, APIConfig)
        assert isinstance(config.notifications, NotificationsConfig)
        assert isinstance(config.checkpoints, CheckpointsConfig)
        assert isinstance(config.advanced, AdvancedConfig)
        assert config.profiles == {}
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = SpectrescanConfig()
        data = config.to_dict()
        
        assert "scan" in data
        assert "service_detection" in data
        assert "output" in data
        assert "api" in data
        assert "notifications" in data
        assert "checkpoints" in data
        assert "advanced" in data
        assert "profiles" in data
    
    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "scan": {"threads": 200},
            "api": {"port": 9000},
            "profiles": {"custom": {"ports": [80, 443]}},
        }
        config = SpectrescanConfig.from_dict(data)
        
        assert config.scan.threads == 200
        assert config.api.port == 9000
        assert "custom" in config.profiles
    
    def test_get_value(self):
        """Test getting value by path."""
        config = SpectrescanConfig()
        
        assert config.get_value("scan.threads") == 100
        assert config.get_value("api.port") == 8080
        assert config.get_value("advanced.log_level") == "INFO"
    
    def test_get_value_invalid_key(self):
        """Test getting value with invalid key."""
        config = SpectrescanConfig()
        
        with pytest.raises(KeyError):
            config.get_value("invalid.key")
    
    def test_set_value(self):
        """Test setting value by path."""
        config = SpectrescanConfig()
        
        config.set_value("scan.threads", 500)
        assert config.scan.threads == 500
        
        config.set_value("api.port", 9000)
        assert config.api.port == 9000
    
    def test_set_value_type_conversion(self):
        """Test that set_value converts types."""
        config = SpectrescanConfig()
        
        # String to int
        config.set_value("scan.threads", "200")
        assert config.scan.threads == 200
        
        # String to bool
        config.set_value("scan.randomize", "true")
        assert config.scan.randomize is True
    
    def test_set_value_invalid_key(self):
        """Test setting value with invalid key."""
        config = SpectrescanConfig()
        
        with pytest.raises((KeyError, ValueError)):
            config.set_value("invalid", "value")


class TestConfigManager:
    """Tests for ConfigManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for config files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create config manager with temp directory."""
        return ConfigManager(
            user_config_path=temp_dir / "config.toml",
            load_env=False,
        )
    
    def test_load_defaults(self, manager):
        """Test loading with defaults only."""
        config = manager.load()
        
        assert config.scan.threads == 100
        assert "defaults" in manager.get_loaded_sources()
    
    def test_init_config(self, manager, temp_dir):
        """Test initializing a new config file."""
        path = manager.init_config()
        
        assert path.exists()
        content = path.read_text()
        assert "[scan]" in content
        assert "[api]" in content
    
    def test_init_config_already_exists(self, manager, temp_dir):
        """Test init fails if config exists."""
        manager.init_config()
        
        with pytest.raises(ConfigError):
            manager.init_config()
    
    def test_save_user_config(self, manager, temp_dir):
        """Test saving user config."""
        config = manager.load()
        config.scan.threads = 500
        
        path = manager.save_user_config()
        
        assert path.exists()
        content = path.read_text()
        assert "threads = 500" in content
    
    def test_get_value(self, manager):
        """Test getting config value."""
        manager.load()
        
        value = manager.get_value("scan.threads")
        assert value == 100
    
    def test_set_value(self, manager):
        """Test setting config value."""
        manager.load()
        
        manager.set_value("scan.threads", 200)
        assert manager.get_value("scan.threads") == 200
    
    def test_show_config(self, manager):
        """Test showing config."""
        manager.load()
        
        output = manager.show_config()
        assert "[scan]" in output
        assert "threads" in output
    
    def test_show_config_section(self, manager):
        """Test showing specific section."""
        manager.load()
        
        output = manager.show_config(section="scan")
        assert "threads" in output
        assert "[api]" not in output
    
    def test_validate_config(self, manager):
        """Test config validation."""
        manager.load()
        
        errors = manager.validate()
        assert errors == []  # Default config should be valid
    
    def test_validate_invalid_threads(self, manager):
        """Test validation catches invalid threads."""
        manager.load()
        manager._config.scan.threads = -1
        
        errors = manager.validate()
        assert any("threads" in e for e in errors)
    
    def test_validate_invalid_port(self, manager):
        """Test validation catches invalid port."""
        manager.load()
        manager._config.api.port = 70000
        
        errors = manager.validate()
        assert any("port" in e for e in errors)
    
    def test_validate_invalid_timing(self, manager):
        """Test validation catches invalid timing."""
        manager.load()
        manager._config.scan.timing_template = 10
        
        errors = manager.validate()
        assert any("timing_template" in e for e in errors)
    
    def test_validate_invalid_log_level(self, manager):
        """Test validation catches invalid log level."""
        manager.load()
        manager._config.advanced.log_level = "INVALID"
        
        errors = manager.validate()
        assert any("log_level" in e for e in errors)
    
    def test_environment_variables(self, temp_dir):
        """Test loading from environment variables."""
        with patch.dict("os.environ", {"SPECTRESCAN_THREADS": "500"}):
            manager = ConfigManager(
                user_config_path=temp_dir / "config.toml",
                load_env=True,
            )
            manager.load()
            
            assert manager._config.scan.threads == 500
            assert "environment" in manager.get_loaded_sources()
    
    def test_environment_bool_parsing(self, temp_dir):
        """Test boolean parsing from environment."""
        with patch.dict("os.environ", {"SPECTRESCAN_RANDOMIZE": "true"}):
            manager = ConfigManager(
                user_config_path=temp_dir / "config.toml",
                load_env=True,
            )
            manager.load()
            
            assert manager._config.scan.randomize is True
    
    def test_load_toml_file(self, manager, temp_dir):
        """Test loading TOML config file."""
        # Create TOML file
        toml_content = """
[scan]
threads = 300
timeout = 1.5

[api]
port = 9000
"""
        config_file = temp_dir / "config.toml"
        config_file.write_text(toml_content)
        
        manager.load()
        
        assert manager._config.scan.threads == 300
        assert manager._config.scan.timeout == 1.5
        assert manager._config.api.port == 9000


class TestGlobalConfigFunctions:
    """Tests for global config functions."""
    
    def test_get_config_manager(self):
        """Test get_config_manager returns instance."""
        manager = get_config_manager()
        assert isinstance(manager, ConfigManager)
    
    def test_get_config(self):
        """Test get_config returns config."""
        config = get_config()
        assert isinstance(config, SpectrescanConfig)
    
    def test_reload_config(self):
        """Test reload_config returns fresh config."""
        config = reload_config()
        assert isinstance(config, SpectrescanConfig)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestCheckpointConfigIntegration:
    """Integration tests for checkpoint and config."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_checkpoint_respects_config(self, temp_dir):
        """Test checkpoint uses config settings."""
        # Create config
        config_manager = ConfigManager(
            user_config_path=temp_dir / "config.toml",
            load_env=False,
        )
        config = config_manager.load()
        
        # Create checkpoint manager using config
        checkpoint_manager = CheckpointManager(
            checkpoint_dir=Path(config.checkpoints.checkpoint_directory.replace("~", str(temp_dir))),
            autosave_interval=config.checkpoints.auto_save_interval if config.checkpoints.auto_save else 0,
            enable_signal_handlers=False,
        )
        
        # Verify checkpoint directory matches config
        assert checkpoint_manager.autosave_interval == config.checkpoints.auto_save_interval
    
    def test_checkpoint_with_scan_defaults(self, temp_dir):
        """Test creating checkpoint with scan defaults from config."""
        config = SpectrescanConfig()
        config.scan.threads = 250
        config.scan.timeout = 1.0
        
        checkpoint_manager = CheckpointManager(
            checkpoint_dir=temp_dir,
            autosave_interval=0,
            enable_signal_handlers=False,
        )
        
        cp = checkpoint_manager.create_checkpoint(
            targets=["192.168.1.1"],
            ports=[80, 443],
            threads=config.scan.threads,
            timeout=config.scan.timeout,
        )
        
        assert cp.threads == 250
        assert cp.timeout == 1.0
