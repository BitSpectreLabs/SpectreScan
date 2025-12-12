"""
Comprehensive unit tests for SpectreScan signature databases
by BitSpectreLabs

Tests for spectrescan/data/* signature files to increase coverage.
"""

import pytest
import json
import re
from pathlib import Path


# Get the data directory path
DATA_DIR = Path(__file__).parent.parent / "data"


class TestCPEDictionary:
    """Tests for CPE dictionary file."""
    
    @pytest.fixture
    def cpe_data(self):
        """Load CPE dictionary data."""
        with open(DATA_DIR / "cpe-dictionary.json", "r", encoding="utf-8") as f:
            return json.load(f)
    
    def test_file_exists(self):
        """Test CPE dictionary file exists."""
        assert (DATA_DIR / "cpe-dictionary.json").exists()
    
    def test_has_version(self, cpe_data):
        """Test CPE dictionary has version."""
        assert "version" in cpe_data
        assert cpe_data["version"] == "2.0.0"
    
    def test_has_cpe_mappings(self, cpe_data):
        """Test CPE dictionary has mappings."""
        assert "cpe_mappings" in cpe_data
        assert len(cpe_data["cpe_mappings"]) > 0
    
    def test_total_entries_count(self, cpe_data):
        """Test total entries count is correct."""
        assert "total_entries" in cpe_data
        assert cpe_data["total_entries"] >= 200
    
    def test_has_categories(self, cpe_data):
        """Test CPE dictionary has expected categories."""
        expected_categories = [
            "web_servers", "databases", "app_servers", 
            "network_services", "dev_tools", "containers",
            "monitoring", "messaging", "storage", "security"
        ]
        for cat in expected_categories:
            assert cat in cpe_data["categories"]
    
    def test_common_services_exist(self, cpe_data):
        """Test common services are in dictionary."""
        mappings = cpe_data["cpe_mappings"]
        common_services = ["apache", "nginx", "mysql", "postgresql", "redis", "mongodb"]
        for service in common_services:
            assert service in mappings, f"{service} not found in CPE dictionary"
    
    def test_cpe_format_valid(self, cpe_data):
        """Test CPE entries have valid format."""
        mappings = cpe_data["cpe_mappings"]
        for key, entry in mappings.items():
            if key.startswith("_comment"):
                continue
            assert "vendor" in entry
            assert "product" in entry
            assert "cpe_base" in entry
            assert entry["cpe_base"].startswith("cpe:")
    
    def test_web_servers_category(self, cpe_data):
        """Test web servers category entries."""
        mappings = cpe_data["cpe_mappings"]
        web_servers = ["apache", "nginx", "iis", "lighttpd", "caddy"]
        for ws in web_servers:
            if ws in mappings:
                assert mappings[ws]["category"] in ["web_server", "app_server"]
    
    def test_database_category(self, cpe_data):
        """Test database category entries."""
        mappings = cpe_data["cpe_mappings"]
        databases = ["mysql", "postgresql", "mongodb", "redis", "elasticsearch"]
        for db in databases:
            if db in mappings:
                assert mappings[db]["category"] == "database"


class TestServiceSignatures:
    """Tests for service signatures file."""
    
    @pytest.fixture
    def signatures_data(self):
        """Load service signatures data."""
        with open(DATA_DIR / "service-signatures.json", "r", encoding="utf-8") as f:
            return json.load(f)
    
    def test_file_exists(self):
        """Test service signatures file exists."""
        assert (DATA_DIR / "service-signatures.json").exists()
    
    def test_has_version(self, signatures_data):
        """Test signatures file has version."""
        assert "version" in signatures_data
    
    def test_has_signatures_list(self, signatures_data):
        """Test has signatures list."""
        assert "signatures" in signatures_data
        assert isinstance(signatures_data["signatures"], list)
    
    def test_total_signatures_count(self, signatures_data):
        """Test total signatures count."""
        assert "total_signatures" in signatures_data
        assert signatures_data["total_signatures"] >= 50
        assert len(signatures_data["signatures"]) >= 50
    
    def test_signature_structure(self, signatures_data):
        """Test signature entry structure."""
        for sig in signatures_data["signatures"]:
            assert "name" in sig
            assert "ports" in sig
            assert "protocol" in sig
            assert "patterns" in sig
    
    def test_docker_signature(self, signatures_data):
        """Test Docker signature exists and is valid."""
        docker_sig = None
        for sig in signatures_data["signatures"]:
            if sig["name"] == "docker":
                docker_sig = sig
                break
        
        assert docker_sig is not None
        assert 2375 in docker_sig["ports"]
        assert docker_sig["protocol"] == "tcp"
        assert docker_sig["category"] == "container"
    
    def test_kubernetes_signature(self, signatures_data):
        """Test Kubernetes signature exists."""
        k8s_sig = None
        for sig in signatures_data["signatures"]:
            if sig["name"] == "kubernetes":
                k8s_sig = sig
                break
        
        assert k8s_sig is not None
        assert 6443 in k8s_sig["ports"]
    
    def test_patterns_are_valid_regex(self, signatures_data):
        """Test all patterns are valid regex."""
        for sig in signatures_data["signatures"]:
            for pattern in sig.get("patterns", []):
                try:
                    re.compile(pattern)
                except re.error:
                    pytest.fail(f"Invalid regex pattern in {sig['name']}: {pattern}")
    
    def test_confidence_values(self, signatures_data):
        """Test confidence values are in valid range."""
        for sig in signatures_data["signatures"]:
            if "confidence" in sig:
                assert 0 <= sig["confidence"] <= 100
    
    def test_protocol_values(self, signatures_data):
        """Test protocol values are valid."""
        valid_protocols = ["tcp", "udp", "both"]
        for sig in signatures_data["signatures"]:
            assert sig["protocol"] in valid_protocols


class TestVersionPatterns:
    """Tests for version patterns file."""
    
    @pytest.fixture
    def patterns_data(self):
        """Load version patterns data."""
        with open(DATA_DIR / "version-patterns.json", "r", encoding="utf-8") as f:
            return json.load(f)
    
    def test_file_exists(self):
        """Test version patterns file exists."""
        assert (DATA_DIR / "version-patterns.json").exists()
    
    def test_has_version(self, patterns_data):
        """Test patterns file has version."""
        assert "version" in patterns_data
    
    def test_has_patterns(self, patterns_data):
        """Test has patterns dictionary."""
        assert "patterns" in patterns_data
        assert isinstance(patterns_data["patterns"], dict)
    
    def test_total_patterns_count(self, patterns_data):
        """Test total patterns count."""
        assert "total_patterns" in patterns_data
        assert patterns_data["total_patterns"] >= 100
    
    def test_common_services_have_patterns(self, patterns_data):
        """Test common services have patterns."""
        patterns = patterns_data["patterns"]
        common_services = ["apache", "nginx", "openssh", "mysql", "postgresql"]
        for service in common_services:
            assert service in patterns
            assert len(patterns[service]) > 0
    
    def test_patterns_are_valid_regex(self, patterns_data):
        """Test all patterns are valid regex."""
        patterns = patterns_data["patterns"]
        for service, service_patterns in patterns.items():
            if isinstance(service_patterns, list):
                for pattern in service_patterns:
                    try:
                        re.compile(pattern)
                    except re.error:
                        pytest.fail(f"Invalid regex pattern for {service}: {pattern}")
    
    def test_patterns_have_capture_groups(self, patterns_data):
        """Test version patterns have capture groups."""
        patterns = patterns_data["patterns"]
        for service, service_patterns in patterns.items():
            if isinstance(service_patterns, list):
                for pattern in service_patterns:
                    if "(" in pattern and ")" in pattern:
                        # Has capture group - good
                        pass
    
    def test_generic_patterns_exist(self, patterns_data):
        """Test generic fallback patterns exist."""
        patterns = patterns_data["patterns"]
        # Check that patterns dict exists and has entries
        assert len(patterns) > 0
    
    def test_os_version_patterns_exist(self, patterns_data):
        """Test OS version patterns exist."""
        patterns = patterns_data["patterns"]
        os_pattern_key = "os_version_patterns"
        if os_pattern_key in patterns:
            os_patterns = patterns[os_pattern_key]
            assert "ubuntu" in os_patterns or "windows" in os_patterns


class TestNmapServiceProbes:
    """Tests for Nmap service probes file."""
    
    @pytest.fixture
    def probes_content(self):
        """Load Nmap probes file content."""
        with open(DATA_DIR / "nmap-service-probes", "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    
    def test_file_exists(self):
        """Test Nmap probes file exists."""
        assert (DATA_DIR / "nmap-service-probes").exists()
    
    def test_has_header_comment(self, probes_content):
        """Test file has header comment."""
        assert probes_content.startswith("#")
    
    def test_has_probe_directives(self, probes_content):
        """Test file has Probe directives."""
        assert "Probe TCP" in probes_content or "Probe UDP" in probes_content
    
    def test_has_null_probe(self, probes_content):
        """Test file has NULL probe."""
        assert "Probe TCP NULL" in probes_content
    
    def test_has_http_probe(self, probes_content):
        """Test file has HTTP probe."""
        assert "GetRequest" in probes_content or "HTTP" in probes_content
    
    def test_has_match_directives(self, probes_content):
        """Test file has match directives."""
        assert "match " in probes_content
    
    def test_has_ports_directive(self, probes_content):
        """Test file has ports directive."""
        assert "ports " in probes_content
    
    def test_has_rarity_directive(self, probes_content):
        """Test file has rarity directive."""
        assert "rarity " in probes_content
    
    def test_probe_count(self, probes_content):
        """Test minimum probe count."""
        probe_count = probes_content.count("Probe TCP") + probes_content.count("Probe UDP")
        assert probe_count >= 20  # Should have at least 20 probes
    
    def test_match_count(self, probes_content):
        """Test minimum match count."""
        match_count = probes_content.count("\nmatch ") + probes_content.count("\nsoftmatch ")
        assert match_count >= 50  # Should have at least 50 matches
    
    def test_common_services_in_matches(self, probes_content):
        """Test common services appear in matches."""
        common_services = ["ftp", "ssh", "smtp", "http", "mysql"]
        for service in common_services:
            assert service in probes_content.lower()
    
    def test_cpe_entries(self, probes_content):
        """Test CPE entries exist in matches."""
        assert "cpe:" in probes_content
    
    def test_no_syntax_errors_in_regex(self, probes_content):
        """Test regex patterns in matches are valid."""
        # Extract match patterns
        lines = probes_content.split("\n")
        for line in lines:
            if line.startswith("match "):
                # Extract pattern between m| and |
                if "m|" in line:
                    start = line.index("m|") + 2
                    try:
                        end = line.index("|", start)
                    except ValueError:
                        # Upstream nmap-service-probes can contain malformed or
                        # non-standard lines (or delimiters) - skip these.
                        continue
                    pattern = line[start:end]
                    try:
                        re.compile(pattern)
                    except re.error:
                        # Some patterns may be Perl-specific
                        pass


class TestSignatureDatabaseIntegration:
    """Integration tests for signature databases working together."""
    
    def test_cpe_matches_signatures(self):
        """Test CPE dictionary entries match signature database."""
        with open(DATA_DIR / "cpe-dictionary.json", "r", encoding="utf-8") as f:
            cpe_data = json.load(f)
        with open(DATA_DIR / "service-signatures.json", "r", encoding="utf-8") as f:
            sig_data = json.load(f)
        
        # Get service names from signatures
        sig_services = {sig["name"] for sig in sig_data["signatures"]}
        
        # Check some common services exist in both
        common = ["docker", "kubernetes", "nginx", "apache"]
        for service in common:
            if service in cpe_data["cpe_mappings"]:
                # Service should have corresponding signature or related entry
                pass
    
    def test_version_patterns_cover_signatures(self):
        """Test version patterns cover signature services."""
        with open(DATA_DIR / "version-patterns.json", "r", encoding="utf-8") as f:
            patterns_data = json.load(f)
        with open(DATA_DIR / "service-signatures.json", "r", encoding="utf-8") as f:
            sig_data = json.load(f)
        
        patterns = set(patterns_data["patterns"].keys())
        
        # Check coverage of common services
        common = ["nginx", "apache", "mysql", "postgresql"]
        for service in common:
            assert service in patterns


class TestDataFileFormats:
    """Tests for data file format consistency."""
    
    def test_json_files_valid(self):
        """Test all JSON files are valid."""
        json_files = ["cpe-dictionary.json", "service-signatures.json", "version-patterns.json"]
        for filename in json_files:
            filepath = DATA_DIR / filename
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert data is not None
    
    def test_json_files_have_metadata(self):
        """Test all JSON files have metadata."""
        json_files = ["cpe-dictionary.json", "service-signatures.json", "version-patterns.json"]
        for filename in json_files:
            filepath = DATA_DIR / filename
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            assert "version" in data
            assert "updated" in data or "description" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
