"""
Database Auto-Update Mechanism

Download and update service signature databases from GitHub repository.

File: spectrescan/core/database_updater.py
Author: BitSpectreLabs
"""

import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime
import logging
import hashlib

logger = logging.getLogger(__name__)


class DatabaseUpdater:
    """Manage service signature database updates."""
    
    # GitHub repository for signature databases
    REPO_BASE = "https://raw.githubusercontent.com/nmap/nmap/master"
    FALLBACK_REPO = "https://svn.nmap.org/nmap"
    
    # Database files to update
    DATABASE_FILES = {
        "nmap-service-probes": "nmap-service-probes",
        "nmap-services": "nmap-services",
    }
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize database updater.
        
        Args:
            data_dir: Directory to store databases (default: spectrescan/data/)
        """
        if data_dir is None:
            # Default to spectrescan/data/
            self.data_dir = Path(__file__).parent.parent / "data"
        else:
            self.data_dir = Path(data_dir)
        
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.data_dir / "database_metadata.json"
    
    def check_for_updates(self) -> Dict[str, bool]:
        """
        Check if database updates are available.
        
        Returns:
            Dictionary mapping database names to update available status
        """
        updates_available = {}
        metadata = self._load_metadata()
        
        for db_name, filename in self.DATABASE_FILES.items():
            local_version = metadata.get(db_name, {}).get("version", "0")
            local_hash = metadata.get(db_name, {}).get("hash", "")
            
            try:
                # Check if remote file is different
                remote_hash = self._get_remote_hash(filename)
                updates_available[db_name] = (remote_hash != local_hash)
            except Exception as e:
                logger.debug(f"Error checking updates for {db_name}: {e}")
                updates_available[db_name] = False
        
        return updates_available
    
    def update_database(self, db_name: str, force: bool = False) -> bool:
        """
        Update a specific database.
        
        Args:
            db_name: Database name (e.g., "nmap-service-probes")
            force: Force update even if no changes detected
            
        Returns:
            True if updated successfully, False otherwise
        """
        if db_name not in self.DATABASE_FILES:
            logger.error(f"Unknown database: {db_name}")
            return False
        
        filename = self.DATABASE_FILES[db_name]
        local_file = self.data_dir / filename
        
        # Check if update needed
        if not force:
            updates = self.check_for_updates()
            if not updates.get(db_name, False):
                logger.info(f"{db_name} is already up to date")
                return True
        
        # Download new database
        try:
            logger.info(f"Downloading {db_name} from {self.REPO_BASE}")
            content = self._download_file(filename)
            
            # Backup existing file
            if local_file.exists():
                backup_file = local_file.with_suffix(local_file.suffix + '.backup')
                local_file.rename(backup_file)
                logger.debug(f"Backed up existing file to {backup_file}")
            
            # Write new file
            with open(local_file, 'wb') as f:
                f.write(content)
            
            # Update metadata
            file_hash = hashlib.sha256(content).hexdigest()
            self._update_metadata(db_name, file_hash)
            
            logger.info(f"Successfully updated {db_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to update {db_name}: {e}")
            
            # Restore backup if exists
            backup_file = local_file.with_suffix(local_file.suffix + '.backup')
            if backup_file.exists() and not local_file.exists():
                backup_file.rename(local_file)
                logger.info("Restored backup file")
            
            return False
    
    def update_all(self, force: bool = False) -> Dict[str, bool]:
        """
        Update all databases.
        
        Args:
            force: Force update even if no changes detected
            
        Returns:
            Dictionary mapping database names to success status
        """
        results = {}
        
        for db_name in self.DATABASE_FILES.keys():
            results[db_name] = self.update_database(db_name, force)
        
        return results
    
    def _download_file(self, filename: str) -> bytes:
        """
        Download file from GitHub repository.
        
        Args:
            filename: File name to download
            
        Returns:
            File content as bytes
        """
        url = f"{self.REPO_BASE}/{filename}"
        
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return response.read()
        except urllib.error.URLError:
            # Try fallback repository
            logger.warning(f"Primary repository failed, trying fallback")
            fallback_url = f"{self.FALLBACK_REPO}/{filename}"
            with urllib.request.urlopen(fallback_url, timeout=30) as response:
                return response.read()
    
    def _get_remote_hash(self, filename: str) -> str:
        """
        Get hash of remote file without downloading entire file.
        
        Args:
            filename: File name
            
        Returns:
            SHA256 hash of file
        """
        # For now, download and hash (could be optimized with HEAD request)
        content = self._download_file(filename)
        return hashlib.sha256(content).hexdigest()
    
    def _load_metadata(self) -> Dict:
        """
        Load database metadata.
        
        Returns:
            Metadata dictionary
        """
        if not self.metadata_file.exists():
            return {}
        
        try:
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading metadata: {e}")
            return {}
    
    def _update_metadata(self, db_name: str, file_hash: str):
        """
        Update metadata for a database.
        
        Args:
            db_name: Database name
            file_hash: SHA256 hash of file
        """
        metadata = self._load_metadata()
        
        metadata[db_name] = {
            "hash": file_hash,
            "updated": datetime.now().isoformat(),
            "version": datetime.now().strftime("%Y%m%d")
        }
        
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def get_database_info(self) -> Dict[str, Dict]:
        """
        Get information about installed databases.
        
        Returns:
            Dictionary with database information
        """
        metadata = self._load_metadata()
        info = {}
        
        for db_name, filename in self.DATABASE_FILES.items():
            local_file = self.data_dir / filename
            
            info[db_name] = {
                "installed": local_file.exists(),
                "path": str(local_file),
                "size": local_file.stat().st_size if local_file.exists() else 0,
                "version": metadata.get(db_name, {}).get("version", "unknown"),
                "updated": metadata.get(db_name, {}).get("updated", "never")
            }
        
        return info
    
    def verify_databases(self) -> Dict[str, bool]:
        """
        Verify integrity of installed databases.
        
        Returns:
            Dictionary mapping database names to verification status
        """
        results = {}
        metadata = self._load_metadata()
        
        for db_name, filename in self.DATABASE_FILES.items():
            local_file = self.data_dir / filename
            
            if not local_file.exists():
                results[db_name] = False
                continue
            
            # Calculate hash
            with open(local_file, 'rb') as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
            
            # Compare with metadata
            expected_hash = metadata.get(db_name, {}).get("hash", "")
            results[db_name] = (file_hash == expected_hash) if expected_hash else True
        
        return results


def update_databases(data_dir: Optional[Path] = None, force: bool = False) -> Dict[str, bool]:
    """
    Convenience function to update all databases.
    
    Args:
        data_dir: Directory to store databases
        force: Force update even if no changes
        
    Returns:
        Dictionary with update results
    """
    updater = DatabaseUpdater(data_dir)
    return updater.update_all(force)


def check_database_updates(data_dir: Optional[Path] = None) -> Dict[str, bool]:
    """
    Convenience function to check for updates.
    
    Args:
        data_dir: Directory containing databases
        
    Returns:
        Dictionary with update availability
    """
    updater = DatabaseUpdater(data_dir)
    return updater.check_for_updates()
