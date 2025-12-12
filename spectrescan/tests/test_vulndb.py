"""
Tests for Custom Vulnerability Database
by BitSpectreLabs
"""

import pytest
import os
import json
import csv
from pathlib import Path
from spectrescan.core.vulndb import Vulnerability, VulnerabilityDatabase, VulnMatcher

@pytest.fixture
def temp_db_path(tmp_path):
    """Create a temporary database path."""
    return tmp_path / "test_vulndb.sqlite"

@pytest.fixture
def db(temp_db_path):
    """Initialize a VulnerabilityDatabase with a temp path."""
    return VulnerabilityDatabase(temp_db_path)

@pytest.fixture
def sample_vuln():
    """Create a sample vulnerability object."""
    return Vulnerability(
        id="CVE-2021-41773",
        title="Apache Path Traversal",
        description="Path traversal in Apache HTTP Server 2.4.49",
        severity="Critical",
        cvss_score=9.8,
        affected_product="Apache.*",
        affected_version_range="== 2.4.49",
        remediation="Upgrade to 2.4.50",
        reference_urls='["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]'
    )

class TestVulnerabilityDatabase:
    """Test suite for VulnerabilityDatabase."""

    def test_init_db(self, db, temp_db_path):
        """Test database initialization."""
        assert temp_db_path.exists()
        assert db.get_all_vulnerabilities() == []

    def test_add_get_vulnerability(self, db, sample_vuln):
        """Test adding and retrieving a vulnerability."""
        assert db.add_vulnerability(sample_vuln) is True
        
        retrieved = db.get_vulnerability(sample_vuln.id)
        assert retrieved is not None
        assert retrieved.id == sample_vuln.id
        assert retrieved.title == sample_vuln.title
        assert retrieved.cvss_score == sample_vuln.cvss_score
        assert retrieved.created_at is not None

    def test_update_vulnerability(self, db, sample_vuln):
        """Test updating an existing vulnerability."""
        db.add_vulnerability(sample_vuln)
        
        sample_vuln.title = "Updated Title"
        db.add_vulnerability(sample_vuln)
        
        retrieved = db.get_vulnerability(sample_vuln.id)
        assert retrieved.title == "Updated Title"

    def test_delete_vulnerability(self, db, sample_vuln):
        """Test deleting a vulnerability."""
        db.add_vulnerability(sample_vuln)
        assert db.delete_vulnerability(sample_vuln.id) is True
        assert db.get_vulnerability(sample_vuln.id) is None

    def test_search_vulnerabilities(self, db, sample_vuln):
        """Test searching vulnerabilities."""
        db.add_vulnerability(sample_vuln)
        
        # Search by title
        results = db.search_vulnerabilities("Apache")
        assert len(results) == 1
        assert results[0].id == sample_vuln.id
        
        # Search by ID
        results = db.search_vulnerabilities("CVE-2021")
        assert len(results) == 1
        
        # No match
        results = db.search_vulnerabilities("Nginx")
        assert len(results) == 0

    def test_json_import_export(self, db, sample_vuln, tmp_path):
        """Test JSON import and export."""
        db.add_vulnerability(sample_vuln)
        json_file = tmp_path / "export.json"
        
        # Export
        assert db.export_to_json(json_file) is True
        assert json_file.exists()
        
        # Clear DB
        db.delete_vulnerability(sample_vuln.id)
        assert len(db.get_all_vulnerabilities()) == 0
        
        # Import
        count = db.import_from_json(json_file)
        assert count == 1
        assert len(db.get_all_vulnerabilities()) == 1

class TestVulnMatcher:
    """Test suite for VulnMatcher."""

    def test_match_service_exact(self, db, sample_vuln):
        """Test matching exact version."""
        db.add_vulnerability(sample_vuln)
        matcher = VulnMatcher(db)
        
        matches = matcher.match_service("Apache httpd", "2.4.49")
        assert len(matches) == 1
        assert matches[0].id == sample_vuln.id

    def test_match_service_regex(self, db):
        """Test matching with regex product name."""
        vuln = Vulnerability(
            id="TEST-1", title="Test", description="Desc", severity="Low", cvss_score=1.0,
            affected_product="Nginx.*", affected_version_range="< 1.18.0",
            remediation="", reference_urls=""
        )
        db.add_vulnerability(vuln)
        matcher = VulnMatcher(db)
        
        # Should match
        assert len(matcher.match_service("Nginx Web Server", "1.16.1")) == 1
        
        # Should not match product
        assert len(matcher.match_service("Apache", "1.16.1")) == 0

    def test_version_ranges(self, db):
        """Test various version range operators."""
        matcher = VulnMatcher(db)
        
        # Test <
        assert matcher._check_version("1.0.0", "< 2.0.0") is True
        assert matcher._check_version("2.0.0", "< 2.0.0") is False
        
        # Test <=
        assert matcher._check_version("2.0.0", "<= 2.0.0") is True
        assert matcher._check_version("2.0.1", "<= 2.0.0") is False
        
        # Test >
        assert matcher._check_version("3.0.0", "> 2.0.0") is True
        
        # Test >=
        assert matcher._check_version("2.0.0", ">= 2.0.0") is True
        
        # Test complex range
        range_str = ">= 1.0.0, < 2.0.0"
        assert matcher._check_version("1.5.0", range_str) is True
        assert matcher._check_version("0.9.0", range_str) is False
        assert matcher._check_version("2.0.0", range_str) is False

    def test_version_parsing(self, db):
        """Test version string parsing."""
        matcher = VulnMatcher(db)
        
        assert matcher._parse_version("1.2.3") == (1, 2, 3)
        assert matcher._parse_version("v1.2.3") == (1, 2, 3)
        assert matcher._parse_version("1.2.3-beta") == (1, 2, 3)
        assert matcher._parse_version("2.4.49") == (2, 4, 49)
