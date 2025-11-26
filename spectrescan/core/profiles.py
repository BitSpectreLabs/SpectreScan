"""
Scan Profile Management
by BitSpectreLabs

Manages scan configurations as reusable profiles.
"""

import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import os


@dataclass
class ScanProfile:
    """Scan profile configuration."""
    
    name: str
    description: str
    ports: List[int]
    scan_types: List[str]
    threads: int
    timeout: float
    rate_limit: Optional[int] = None
    enable_service_detection: bool = True
    enable_os_detection: bool = False
    enable_banner_grabbing: bool = True
    randomize: bool = False
    timing_template: int = 3
    created_at: Optional[str] = None
    modified_at: Optional[str] = None
    
    def __post_init__(self):
        """Set timestamps if not provided."""
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()
        if self.modified_at is None:
            self.modified_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert profile to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanProfile':
        """Create profile from dictionary."""
        return cls(**data)


class ProfileManager:
    """Manages scan profiles."""
    
    def __init__(self, profiles_dir: Optional[Path] = None):
        """
        Initialize profile manager.
        
        Args:
            profiles_dir: Directory to store profiles (default: ~/.spectrescan/profiles/)
        """
        if profiles_dir is None:
            home = Path.home()
            profiles_dir = home / ".spectrescan" / "profiles"
        
        self.profiles_dir = Path(profiles_dir)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
    
    def save_profile(self, profile: ScanProfile) -> None:
        """
        Save a scan profile.
        
        Args:
            profile: ScanProfile to save
        
        Raises:
            ValueError: If profile name is invalid
            IOError: If save fails
        """
        if not profile.name:
            raise ValueError("Profile name cannot be empty")
        
        # Sanitize filename
        filename = self._sanitize_filename(profile.name)
        filepath = self.profiles_dir / f"{filename}.json"
        
        # Update modified timestamp
        profile.modified_at = datetime.now().isoformat()
        
        try:
            with open(filepath, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2)
        except Exception as e:
            raise IOError(f"Failed to save profile: {e}")
    
    def load_profile(self, name: str) -> ScanProfile:
        """
        Load a scan profile.
        
        Args:
            name: Profile name
        
        Returns:
            ScanProfile
        
        Raises:
            FileNotFoundError: If profile doesn't exist
            ValueError: If profile data is invalid
        """
        filename = self._sanitize_filename(name)
        filepath = self.profiles_dir / f"{filename}.json"
        
        if not filepath.exists():
            raise FileNotFoundError(f"Profile '{name}' not found")
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            return ScanProfile.from_dict(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid profile data: {e}")
        except Exception as e:
            raise ValueError(f"Failed to load profile: {e}")
    
    def delete_profile(self, name: str) -> None:
        """
        Delete a scan profile.
        
        Args:
            name: Profile name
        
        Raises:
            FileNotFoundError: If profile doesn't exist
        """
        filename = self._sanitize_filename(name)
        filepath = self.profiles_dir / f"{filename}.json"
        
        if not filepath.exists():
            raise FileNotFoundError(f"Profile '{name}' not found")
        
        filepath.unlink()
    
    def list_profiles(self) -> List[str]:
        """
        List all available profiles.
        
        Returns:
            List of profile names
        """
        profiles = []
        for filepath in self.profiles_dir.glob("*.json"):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                profiles.append(data['name'])
            except:
                continue
        return sorted(profiles)
    
    def profile_exists(self, name: str) -> bool:
        """
        Check if a profile exists.
        
        Args:
            name: Profile name
        
        Returns:
            True if profile exists
        """
        filename = self._sanitize_filename(name)
        filepath = self.profiles_dir / f"{filename}.json"
        return filepath.exists()
    
    def export_profile(self, name: str, export_path: Path) -> None:
        """
        Export a profile to a file.
        
        Args:
            name: Profile name
            export_path: Path to export file
        
        Raises:
            FileNotFoundError: If profile doesn't exist
        """
        profile = self.load_profile(name)
        
        with open(export_path, 'w') as f:
            json.dump(profile.to_dict(), f, indent=2)
    
    def import_profile(self, import_path: Path) -> ScanProfile:
        """
        Import a profile from a file.
        
        Args:
            import_path: Path to import file
        
        Returns:
            Imported ScanProfile
        
        Raises:
            FileNotFoundError: If import file doesn't exist
            ValueError: If import data is invalid
        """
        if not import_path.exists():
            raise FileNotFoundError(f"Import file not found: {import_path}")
        
        with open(import_path, 'r') as f:
            data = json.load(f)
        
        profile = ScanProfile.from_dict(data)
        self.save_profile(profile)
        return profile
    
    def _sanitize_filename(self, name: str) -> str:
        """
        Sanitize profile name for use as filename.
        
        Args:
            name: Profile name
        
        Returns:
            Sanitized filename
        """
        # Replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            name = name.replace(char, '_')
        return name.strip()
