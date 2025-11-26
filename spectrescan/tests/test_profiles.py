"""
Tests for Scan Profile Management
by BitSpectreLabs
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from spectrescan.core.profiles import ScanProfile, ProfileManager


class TestScanProfile:
    """Test ScanProfile dataclass."""
    
    def test_create_profile(self):
        """Test creating a scan profile."""
        profile = ScanProfile(
            name="Quick Scan",
            description="Fast scan of common ports",
            ports=[80, 443, 22, 21],
            scan_types=["tcp"],
            threads=50,
            timeout=1.0
        )
        
        assert profile.name == "Quick Scan"
        assert profile.description == "Fast scan of common ports"
        assert len(profile.ports) == 4
        assert profile.threads == 50
        assert profile.timeout == 1.0
        assert profile.enable_service_detection is True
        assert profile.enable_os_detection is False
        assert profile.created_at is not None
        assert profile.modified_at is not None
    
    def test_profile_with_all_options(self):
        """Test profile with all options specified."""
        profile = ScanProfile(
            name="Full Scan",
            description="Complete scan with all features",
            ports=list(range(1, 1001)),
            scan_types=["tcp", "syn"],
            threads=100,
            timeout=2.0,
            rate_limit=1000,
            enable_service_detection=True,
            enable_os_detection=True,
            enable_banner_grabbing=True,
            randomize=True,
            timing_template=4
        )
        
        assert len(profile.ports) == 1000
        assert profile.rate_limit == 1000
        assert profile.enable_os_detection is True
        assert profile.randomize is True
        assert profile.timing_template == 4
    
    def test_profile_to_dict(self):
        """Test converting profile to dictionary."""
        profile = ScanProfile(
            name="Test",
            description="Test profile",
            ports=[80, 443],
            scan_types=["tcp"],
            threads=50,
            timeout=1.0
        )
        
        data = profile.to_dict()
        
        assert isinstance(data, dict)
        assert data['name'] == "Test"
        assert data['ports'] == [80, 443]
        assert 'created_at' in data
    
    def test_profile_from_dict(self):
        """Test creating profile from dictionary."""
        data = {
            'name': "Test",
            'description': "Test profile",
            'ports': [80, 443],
            'scan_types': ["tcp"],
            'threads': 50,
            'timeout': 1.0,
            'rate_limit': None,
            'enable_service_detection': True,
            'enable_os_detection': False,
            'enable_banner_grabbing': True,
            'randomize': False,
            'timing_template': 3,
            'created_at': datetime.now().isoformat(),
            'modified_at': datetime.now().isoformat()
        }
        
        profile = ScanProfile.from_dict(data)
        
        assert profile.name == "Test"
        assert profile.ports == [80, 443]
        assert profile.threads == 50


class TestProfileManager:
    """Test ProfileManager class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for profiles."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def manager(self, temp_dir):
        """Create ProfileManager with temp directory."""
        return ProfileManager(temp_dir)
    
    @pytest.fixture
    def sample_profile(self):
        """Create sample profile for testing."""
        return ScanProfile(
            name="Test Profile",
            description="Test description",
            ports=[80, 443, 22],
            scan_types=["tcp"],
            threads=50,
            timeout=1.0
        )
    
    def test_manager_initialization(self, temp_dir):
        """Test ProfileManager initialization."""
        manager = ProfileManager(temp_dir)
        
        assert manager.profiles_dir == temp_dir
        assert temp_dir.exists()
    
    def test_save_profile(self, manager, sample_profile):
        """Test saving a profile."""
        manager.save_profile(sample_profile)
        
        # Check file was created
        profiles = list(manager.profiles_dir.glob("*.json"))
        assert len(profiles) == 1
        
        # Verify file content
        with open(profiles[0], 'r') as f:
            data = json.load(f)
        
        assert data['name'] == "Test Profile"
        assert data['ports'] == [80, 443, 22]
    
    def test_save_profile_empty_name(self, manager):
        """Test saving profile with empty name raises error."""
        profile = ScanProfile(
            name="",
            description="Test",
            ports=[80],
            scan_types=["tcp"],
            threads=50,
            timeout=1.0
        )
        
        with pytest.raises(ValueError, match="Profile name cannot be empty"):
            manager.save_profile(profile)
    
    def test_load_profile(self, manager, sample_profile):
        """Test loading a profile."""
        manager.save_profile(sample_profile)
        
        loaded = manager.load_profile("Test Profile")
        
        assert loaded.name == sample_profile.name
        assert loaded.ports == sample_profile.ports
        assert loaded.threads == sample_profile.threads
    
    def test_load_nonexistent_profile(self, manager):
        """Test loading non-existent profile raises error."""
        with pytest.raises(FileNotFoundError, match="Profile 'NonExistent' not found"):
            manager.load_profile("NonExistent")
    
    def test_delete_profile(self, manager, sample_profile):
        """Test deleting a profile."""
        manager.save_profile(sample_profile)
        assert manager.profile_exists("Test Profile")
        
        manager.delete_profile("Test Profile")
        assert not manager.profile_exists("Test Profile")
    
    def test_delete_nonexistent_profile(self, manager):
        """Test deleting non-existent profile raises error."""
        with pytest.raises(FileNotFoundError, match="Profile 'NonExistent' not found"):
            manager.delete_profile("NonExistent")
    
    def test_list_profiles(self, manager):
        """Test listing profiles."""
        # Create multiple profiles
        profiles = [
            ScanProfile("Profile A", "Desc A", [80], ["tcp"], 50, 1.0),
            ScanProfile("Profile B", "Desc B", [443], ["tcp"], 50, 1.0),
            ScanProfile("Profile C", "Desc C", [22], ["tcp"], 50, 1.0)
        ]
        
        for profile in profiles:
            manager.save_profile(profile)
        
        names = manager.list_profiles()
        
        assert len(names) == 3
        assert "Profile A" in names
        assert "Profile B" in names
        assert "Profile C" in names
        assert names == sorted(names)  # Should be sorted
    
    def test_list_profiles_empty(self, manager):
        """Test listing profiles when none exist."""
        names = manager.list_profiles()
        assert names == []
    
    def test_profile_exists(self, manager, sample_profile):
        """Test checking if profile exists."""
        assert not manager.profile_exists("Test Profile")
        
        manager.save_profile(sample_profile)
        assert manager.profile_exists("Test Profile")
    
    def test_export_profile(self, manager, sample_profile, temp_dir):
        """Test exporting a profile."""
        manager.save_profile(sample_profile)
        
        export_path = temp_dir / "exported.json"
        manager.export_profile("Test Profile", export_path)
        
        assert export_path.exists()
        
        with open(export_path, 'r') as f:
            data = json.load(f)
        
        assert data['name'] == "Test Profile"
        assert data['ports'] == [80, 443, 22]
    
    def test_import_profile(self, manager, temp_dir):
        """Test importing a profile."""
        # Create export file
        profile_data = {
            'name': "Imported Profile",
            'description': "Imported",
            'ports': [80, 443],
            'scan_types': ["tcp"],
            'threads': 50,
            'timeout': 1.0,
            'rate_limit': None,
            'enable_service_detection': True,
            'enable_os_detection': False,
            'enable_banner_grabbing': True,
            'randomize': False,
            'timing_template': 3,
            'created_at': datetime.now().isoformat(),
            'modified_at': datetime.now().isoformat()
        }
        
        import_path = temp_dir / "import.json"
        with open(import_path, 'w') as f:
            json.dump(profile_data, f)
        
        profile = manager.import_profile(import_path)
        
        assert profile.name == "Imported Profile"
        assert manager.profile_exists("Imported Profile")
    
    def test_import_nonexistent_file(self, manager, temp_dir):
        """Test importing non-existent file raises error."""
        import_path = temp_dir / "nonexistent.json"
        
        with pytest.raises(FileNotFoundError, match="Import file not found"):
            manager.import_profile(import_path)
    
    def test_sanitize_filename(self, manager):
        """Test filename sanitization."""
        # Test with invalid characters
        result = manager._sanitize_filename("Test:Profile/With*Invalid?Chars")
        assert result == "Test_Profile_With_Invalid_Chars"
        
        # Test with spaces
        result = manager._sanitize_filename("  Test Profile  ")
        assert result == "Test Profile"
    
    def test_update_profile(self, manager, sample_profile):
        """Test updating an existing profile."""
        # Save initial profile
        manager.save_profile(sample_profile)
        original_modified = sample_profile.modified_at
        
        # Wait a bit to ensure timestamp changes
        import time
        time.sleep(0.01)
        
        # Modify and save again
        sample_profile.description = "Updated description"
        sample_profile.ports = [80, 443, 22, 21, 25]
        manager.save_profile(sample_profile)
        
        # Load and verify
        loaded = manager.load_profile("Test Profile")
        assert loaded.description == "Updated description"
        assert len(loaded.ports) == 5
        assert loaded.modified_at != original_modified
    
    def test_multiple_profiles_same_name(self, manager, sample_profile):
        """Test that saving profile with same name overwrites."""
        manager.save_profile(sample_profile)
        
        # Create different profile with same name
        modified_profile = ScanProfile(
            name="Test Profile",
            description="Different description",
            ports=[8080],
            scan_types=["syn"],
            threads=100,
            timeout=2.0
        )
        
        manager.save_profile(modified_profile)
        
        # Should only have one profile file
        profiles = list(manager.profiles_dir.glob("*.json"))
        assert len(profiles) == 1
        
        # Should have updated content
        loaded = manager.load_profile("Test Profile")
        assert loaded.description == "Different description"
        assert loaded.ports == [8080]
