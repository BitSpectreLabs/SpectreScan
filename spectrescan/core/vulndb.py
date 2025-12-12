"""
Custom Vulnerability Database Module
by BitSpectreLabs

Handles local vulnerability database management, matching, and scoring.
"""

import sqlite3
import json
import csv
import re
import logging
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Represents a single vulnerability definition."""
    id: str  # CVE-ID or custom ID
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low
    cvss_score: float
    affected_product: str  # Regex for product name (e.g. "Apache.*")
    affected_version_range: str  # e.g. "< 2.4.49", "== 1.0.0", "ALL"
    remediation: Optional[str] = None
    reference_urls: Optional[str] = None  # JSON list of URLs
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class VulnerabilityDatabase:
    """Manages the local SQLite vulnerability database."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            # Default to ~/.spectrescan/vulndb.sqlite
            home = Path.home()
            self.db_path = home / ".spectrescan" / "vulndb.sqlite"
        else:
            self.db_path = db_path
        
        self._ensure_db_dir()
        self._init_db()

    def _ensure_db_dir(self):
        """Ensure the database directory exists."""
        if not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _init_db(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_product TEXT,
                affected_version_range TEXT,
                remediation TEXT,
                reference_urls TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        ''')
        
        # Create indexes for faster searching
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_product ON vulnerabilities(affected_product)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity)')
        
        conn.commit()
        conn.close()

    def add_vulnerability(self, vuln: Vulnerability) -> bool:
        """Add or update a vulnerability in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        if not vuln.created_at:
            vuln.created_at = now
        vuln.updated_at = now

        try:
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities (
                    id, title, description, severity, cvss_score,
                    affected_product, affected_version_range, remediation,
                    reference_urls, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln.id, vuln.title, vuln.description, vuln.severity, vuln.cvss_score,
                vuln.affected_product, vuln.affected_version_range, vuln.remediation,
                vuln.reference_urls, vuln.created_at, vuln.updated_at
            ))
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Database error adding vulnerability {vuln.id}: {e}")
            return False
        finally:
            conn.close()

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """Retrieve a vulnerability by ID."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE id = ?', (vuln_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_vuln(row)
        return None

    def search_vulnerabilities(self, query: str) -> List[Vulnerability]:
        """Search vulnerabilities by title, description, or product."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        search_term = f"%{query}%"
        cursor.execute('''
            SELECT * FROM vulnerabilities 
            WHERE title LIKE ? 
            OR description LIKE ? 
            OR affected_product LIKE ?
            OR id LIKE ?
        ''', (search_term, search_term, search_term, search_term))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_vuln(row) for row in rows]

    def get_all_vulnerabilities(self) -> List[Vulnerability]:
        """Retrieve all vulnerabilities."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vulnerabilities')
        rows = cursor.fetchall()
        conn.close()
        
        return [self._row_to_vuln(row) for row in rows]

    def delete_vulnerability(self, vuln_id: str) -> bool:
        """Delete a vulnerability by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM vulnerabilities WHERE id = ?', (vuln_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Database error deleting vulnerability {vuln_id}: {e}")
            return False
        finally:
            conn.close()

    def import_from_json(self, json_path: Path) -> int:
        """Import vulnerabilities from a JSON file."""
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            count = 0
            for item in data:
                vuln = Vulnerability(**item)
                if self.add_vulnerability(vuln):
                    count += 1
            return count
        except Exception as e:
            logger.error(f"Error importing from JSON: {e}")
            return 0

    def export_to_json(self, json_path: Path) -> bool:
        """Export all vulnerabilities to a JSON file."""
        try:
            vulns = self.get_all_vulnerabilities()
            data = [v.to_dict() for v in vulns]
            
            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            return False

    def import_from_csv(self, csv_path: Path) -> int:
        """Import vulnerabilities from a CSV file."""
        try:
            count = 0
            with open(csv_path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Convert types
                    row['cvss_score'] = float(row['cvss_score'])
                    vuln = Vulnerability(**row)
                    if self.add_vulnerability(vuln):
                        count += 1
            return count
        except Exception as e:
            logger.error(f"Error importing from CSV: {e}")
            return 0

    def _row_to_vuln(self, row: sqlite3.Row) -> Vulnerability:
        """Convert a database row to a Vulnerability object."""
        return Vulnerability(
            id=row['id'],
            title=row['title'],
            description=row['description'],
            severity=row['severity'],
            cvss_score=row['cvss_score'],
            affected_product=row['affected_product'],
            affected_version_range=row['affected_version_range'],
            remediation=row['remediation'],
            reference_urls=row['reference_urls'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )

class VulnMatcher:
    """Matches detected services against the vulnerability database."""

    def __init__(self, db: VulnerabilityDatabase):
        self.db = db

    def match_service(self, product: str, version: str) -> List[Vulnerability]:
        """
        Match a service product and version against known vulnerabilities.
        
        Args:
            product: The detected product name (e.g., "Apache httpd")
            version: The detected version string (e.g., "2.4.49")
            
        Returns:
            List of matching Vulnerability objects
        """
        if not product or not version:
            return []

        matches = []
        # Get all potential matches based on product name regex
        # This is a bit inefficient for large DBs, but SQLite regex support is limited by default.
        # We'll fetch all and filter in Python for now, or use LIKE for basic filtering.
        
        # Optimization: Fetch candidates where product name is contained in affected_product regex
        # or vice versa. For now, we iterate all. In production, we'd want a better index strategy.
        all_vulns = self.db.get_all_vulnerabilities()
        
        for vuln in all_vulns:
            # 1. Check Product Match
            try:
                if not re.search(vuln.affected_product, product, re.IGNORECASE):
                    continue
            except re.error:
                logger.warning(f"Invalid regex for vulnerability {vuln.id}: {vuln.affected_product}")
                continue

            # 2. Check Version Match
            if self._check_version(version, vuln.affected_version_range):
                matches.append(vuln)
                
        return matches

    def _check_version(self, current_version: str, version_range: str) -> bool:
        """
        Check if a version falls within a range.
        Supports: <, <=, >, >=, ==, !=, and comma-separated ranges.
        Example: ">= 1.0.0, < 2.0.0"
        """
        if version_range == "ALL":
            return True
            
        try:
            # Split into individual conditions
            conditions = [c.strip() for c in version_range.split(',')]
            
            for condition in conditions:
                if not self._evaluate_condition(current_version, condition):
                    return False
            return True
        except Exception as e:
            logger.debug(f"Version check error: {e}")
            return False

    def _evaluate_condition(self, version: str, condition: str) -> bool:
        """Evaluate a single version condition."""
        # Parse operator and target version
        match = re.match(r'([<>!=]=?)\s*(.+)', condition)
        if not match:
            # Assume equality if no operator
            return version == condition
            
        operator, target = match.groups()
        
        # Simple semantic version comparison
        v1 = self._parse_version(version)
        v2 = self._parse_version(target)
        
        if operator == '==': return v1 == v2
        if operator == '!=': return v1 != v2
        if operator == '<':  return v1 < v2
        if operator == '<=': return v1 <= v2
        if operator == '>':  return v1 > v2
        if operator == '>=': return v1 >= v2
        
        return False

    def _parse_version(self, version_str: str) -> Tuple[int, ...]:
        """Parse version string into a comparable tuple of integers."""
        # Remove non-numeric prefixes like 'v'
        clean_ver = re.sub(r'^[a-zA-Z]+', '', version_str)
        # Extract numeric components
        parts = re.findall(r'\d+', clean_ver)
        return tuple(map(int, parts))
