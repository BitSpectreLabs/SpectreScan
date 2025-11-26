"""
Tests for Database Updater Module.

Author: BitSpectreLabs
License: MIT
"""

import pytest
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
from spectrescan.core.database_updater import (
    DatabaseUpdater,
    update_databases,
    check_database_updates
)


class TestDatabaseUpdater:
    """Tests for DatabaseUpdater class."""
    
    def test_init_default_dir(self):
        """Test initialization with default directory."""
        updater = DatabaseUpdater()
        
        assert updater.data_dir.exists()
        assert "spectrescan" in str(updater.data_dir).lower()
    
    def test_init_custom_dir(self, tmp_path):
        """Test initialization with custom directory."""
        custom_dir = tmp_path / "databases"
        updater = DatabaseUpdater(data_dir=custom_dir)
        
        assert updater.data_dir == custom_dir
        assert custom_dir.exists()
    
    def test_database_files_constant(self):
        """Test DATABASE_FILES constant."""
        assert "nmap-service-probes" in DatabaseUpdater.DATABASE_FILES
        assert "nmap-services" in DatabaseUpdater.DATABASE_FILES
    
    def test_repo_base_constant(self):
        """Test REPO_BASE constant."""
        assert "github" in DatabaseUpdater.REPO_BASE.lower()
        assert "raw" in DatabaseUpdater.REPO_BASE.lower()
    
    def test_fallback_repo_constant(self):
        """Test FALLBACK_REPO constant."""
        assert "nmap" in DatabaseUpdater.FALLBACK_REPO.lower()


class TestDatabaseUpdaterMetadata:
    """Tests for metadata handling."""
    
    def test_load_metadata_empty(self, tmp_path):
        """Test loading metadata when file doesn't exist."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        metadata = updater._load_metadata()
        
        assert metadata == {}
    
    def test_load_metadata_valid(self, tmp_path):
        """Test loading valid metadata."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        # Create metadata file
        metadata = {
            "nmap-service-probes": {
                "hash": "abc123",
                "version": "20250101"
            }
        }
        with open(updater.metadata_file, 'w') as f:
            json.dump(metadata, f)
        
        loaded = updater._load_metadata()
        
        assert loaded["nmap-service-probes"]["hash"] == "abc123"
    
    def test_update_metadata(self, tmp_path):
        """Test updating metadata."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        updater._update_metadata("test-db", "def456")
        
        # Read back
        metadata = updater._load_metadata()
        
        assert "test-db" in metadata
        assert metadata["test-db"]["hash"] == "def456"
        assert "updated" in metadata["test-db"]
        assert "version" in metadata["test-db"]
    
    def test_update_metadata_preserves_existing(self, tmp_path):
        """Test updating metadata preserves existing entries."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        # Add first entry
        updater._update_metadata("db1", "hash1")
        
        # Add second entry
        updater._update_metadata("db2", "hash2")
        
        metadata = updater._load_metadata()
        
        assert "db1" in metadata
        assert "db2" in metadata


class TestDatabaseUpdaterInfo:
    """Tests for database info methods."""
    
    def test_get_database_info_empty(self, tmp_path):
        """Test getting info when no databases installed."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        info = updater.get_database_info()
        
        assert len(info) == len(DatabaseUpdater.DATABASE_FILES)
        for db_name in info:
            assert info[db_name]["installed"] is False
    
    def test_get_database_info_with_file(self, tmp_path):
        """Test getting info with installed database."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        # Create a database file
        db_file = tmp_path / "nmap-service-probes"
        db_file.write_text("test content")
        
        info = updater.get_database_info()
        
        assert info["nmap-service-probes"]["installed"] is True
        assert info["nmap-service-probes"]["size"] > 0
    
    def test_verify_databases_empty(self, tmp_path):
        """Test verifying when no databases exist."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        results = updater.verify_databases()
        
        for db_name, status in results.items():
            assert status is False


class TestDatabaseUpdaterDownload:
    """Tests for download functionality."""
    
    @patch('urllib.request.urlopen')
    def test_download_file_success(self, mock_urlopen, tmp_path):
        """Test successful file download."""
        # Mock response
        mock_response = MagicMock()
        mock_response.read.return_value = b"test content"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        content = updater._download_file("test-file")
        
        assert content == b"test content"
    
    @patch('urllib.request.urlopen')
    def test_download_file_fallback(self, mock_urlopen, tmp_path):
        """Test fallback to secondary repository."""
        import urllib.error
        
        # First call fails, second succeeds
        mock_response = MagicMock()
        mock_response.read.return_value = b"fallback content"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        
        mock_urlopen.side_effect = [
            urllib.error.URLError("Primary failed"),
            mock_response
        ]
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        content = updater._download_file("test-file")
        
        assert content == b"fallback content"


class TestDatabaseUpdaterUpdate:
    """Tests for update functionality."""
    
    def test_update_database_unknown(self, tmp_path):
        """Test updating unknown database."""
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        result = updater.update_database("unknown-db")
        
        assert result is False
    
    @patch.object(DatabaseUpdater, '_download_file')
    @patch.object(DatabaseUpdater, 'check_for_updates')
    def test_update_database_no_update_needed(
        self, mock_check, mock_download, tmp_path
    ):
        """Test update when already up to date."""
        mock_check.return_value = {"nmap-service-probes": False}
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        result = updater.update_database("nmap-service-probes")
        
        assert result is True
        mock_download.assert_not_called()
    
    @patch.object(DatabaseUpdater, '_download_file')
    def test_update_database_success(self, mock_download, tmp_path):
        """Test successful database update."""
        mock_download.return_value = b"new content"
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        result = updater.update_database("nmap-service-probes", force=True)
        
        assert result is True
        
        # Check file was written
        db_file = tmp_path / "nmap-service-probes"
        assert db_file.exists()
        assert db_file.read_bytes() == b"new content"
    
    @patch.object(DatabaseUpdater, '_download_file')
    def test_update_database_backup(self, mock_download, tmp_path):
        """Test backup is created during update."""
        # Create existing file
        db_file = tmp_path / "nmap-service-probes"
        db_file.write_text("old content")
        
        mock_download.return_value = b"new content"
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        result = updater.update_database("nmap-service-probes", force=True)
        
        assert result is True
        
        # Check backup exists
        backup_file = tmp_path / "nmap-service-probes.backup"
        assert backup_file.exists()
        assert backup_file.read_text() == "old content"
    
    @patch.object(DatabaseUpdater, '_download_file')
    def test_update_all(self, mock_download, tmp_path):
        """Test updating all databases."""
        mock_download.return_value = b"content"
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        results = updater.update_all(force=True)
        
        assert len(results) == len(DatabaseUpdater.DATABASE_FILES)
        for db_name, status in results.items():
            assert status is True


class TestDatabaseUpdaterCheckUpdates:
    """Tests for update checking."""
    
    @patch.object(DatabaseUpdater, '_get_remote_hash')
    def test_check_for_updates_no_local(self, mock_hash, tmp_path):
        """Test checking updates when no local files."""
        mock_hash.return_value = "remotehash"
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        updates = updater.check_for_updates()
        
        # All should be marked as needing update
        for db_name, needs_update in updates.items():
            assert needs_update is True
    
    @patch.object(DatabaseUpdater, '_get_remote_hash')
    def test_check_for_updates_up_to_date(self, mock_hash, tmp_path):
        """Test checking when files are up to date."""
        mock_hash.return_value = "samehash"
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        
        # Set metadata with same hash
        updater._update_metadata("nmap-service-probes", "samehash")
        
        updates = updater.check_for_updates()
        
        assert updates["nmap-service-probes"] is False
    
    @patch.object(DatabaseUpdater, '_get_remote_hash')
    def test_check_for_updates_error(self, mock_hash, tmp_path):
        """Test checking when error occurs."""
        mock_hash.side_effect = Exception("Network error")
        
        updater = DatabaseUpdater(data_dir=tmp_path)
        updates = updater.check_for_updates()
        
        # Should return False on error
        for db_name, needs_update in updates.items():
            assert needs_update is False


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    @patch.object(DatabaseUpdater, 'update_all')
    def test_update_databases(self, mock_update, tmp_path):
        """Test update_databases convenience function."""
        mock_update.return_value = {"db1": True}
        
        result = update_databases(data_dir=tmp_path)
        
        mock_update.assert_called_once()
    
    @patch.object(DatabaseUpdater, 'check_for_updates')
    def test_check_database_updates(self, mock_check, tmp_path):
        """Test check_database_updates convenience function."""
        mock_check.return_value = {"db1": True}
        
        result = check_database_updates(data_dir=tmp_path)
        
        mock_check.assert_called_once()
