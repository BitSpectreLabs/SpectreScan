"""
Unit tests for multi-target scanning functionality
by BitSpectreLabs
"""

import unittest
import tempfile
from pathlib import Path
from spectrescan.core.utils import parse_target, parse_targets_from_file


class TestMultiTargetParsing(unittest.TestCase):
    """Test multi-target parsing functionality."""
    
    def test_single_target(self):
        """Test single IP target."""
        result = parse_target("192.168.1.1")
        self.assertEqual(result, ["192.168.1.1"])
    
    def test_comma_separated_targets(self):
        """Test comma-separated targets."""
        result = parse_target("192.168.1.1,192.168.1.2")
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.2", result)
    
    def test_comma_separated_with_spaces(self):
        """Test comma-separated with spaces."""
        result = parse_target("192.168.1.1, 192.168.1.2 , 192.168.1.3")
        self.assertEqual(len(result), 3)
    
    def test_list_input(self):
        """Test list of targets as input."""
        result = parse_target(["192.168.1.1", "192.168.1.2"])
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.2", result)
    
    def test_mixed_formats(self):
        """Test mixed target formats."""
        result = parse_target("192.168.1.1,192.168.1.10-12")
        self.assertEqual(len(result), 4)  # 1.1, 1.10, 1.11, 1.12
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.10", result)
        self.assertIn("192.168.1.11", result)
        self.assertIn("192.168.1.12", result)
    
    def test_cidr_in_list(self):
        """Test CIDR notation in multi-target."""
        result = parse_target("192.168.1.0/30")
        # /30 gives .1 and .2 (host IPs)
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.2", result)
    
    def test_hostname_in_list(self):
        """Test hostname resolution in multi-target."""
        # Using localhost which should always resolve
        result = parse_target("127.0.0.1,localhost")
        self.assertGreaterEqual(len(result), 2)
        self.assertIn("127.0.0.1", result)


class TestTargetFileParser(unittest.TestCase):
    """Test target file parsing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
    
    def test_simple_file(self):
        """Test simple target file."""
        target_file = self.temp_path / "targets.txt"
        target_file.write_text("192.168.1.1\n192.168.1.2\n192.168.1.3\n")
        
        result = parse_targets_from_file(target_file)
        self.assertEqual(len(result), 3)
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])
    
    def test_file_with_comments(self):
        """Test file with comments."""
        target_file = self.temp_path / "targets.txt"
        content = """# Web servers
192.168.1.1
# Database server
192.168.1.10
"""
        target_file.write_text(content)
        
        result = parse_targets_from_file(target_file)
        self.assertEqual(len(result), 2)
        self.assertIn("192.168.1.1", result)
        self.assertIn("192.168.1.10", result)
    
    def test_file_with_empty_lines(self):
        """Test file with empty lines."""
        target_file = self.temp_path / "targets.txt"
        content = """192.168.1.1

192.168.1.2

192.168.1.3
"""
        target_file.write_text(content)
        
        result = parse_targets_from_file(target_file)
        self.assertEqual(len(result), 3)
    
    def test_file_with_cidr(self):
        """Test file with CIDR notation."""
        target_file = self.temp_path / "targets.txt"
        content = "192.168.1.0/30\n"
        target_file.write_text(content)
        
        result = parse_targets_from_file(target_file)
        self.assertEqual(len(result), 2)  # /30 = 2 hosts
    
    def test_file_with_ranges(self):
        """Test file with IP ranges."""
        target_file = self.temp_path / "targets.txt"
        content = "192.168.1.10-12\n"
        target_file.write_text(content)
        
        result = parse_targets_from_file(target_file)
        self.assertEqual(len(result), 3)
        self.assertIn("192.168.1.10", result)
        self.assertIn("192.168.1.11", result)
        self.assertIn("192.168.1.12", result)
    
    def test_file_with_mixed_content(self):
        """Test file with mixed formats."""
        target_file = self.temp_path / "targets.txt"
        content = """# Production servers
192.168.1.1
192.168.1.10-12

# Development
10.0.0.0/29

# External
127.0.0.1
"""
        target_file.write_text(content)
        
        result = parse_targets_from_file(target_file)
        self.assertGreater(len(result), 5)
        self.assertIn("192.168.1.1", result)
        self.assertIn("127.0.0.1", result)
    
    def test_duplicate_removal(self):
        """Test that duplicates are removed."""
        target_file = self.temp_path / "targets.txt"
        content = """192.168.1.1
192.168.1.1
192.168.1.2
192.168.1.1
"""
        target_file.write_text(content)
        
        result = parse_targets_from_file(target_file)
        self.assertEqual(len(result), 2)
        self.assertEqual(result, ["192.168.1.1", "192.168.1.2"])
    
    def test_file_not_found(self):
        """Test file not found error."""
        with self.assertRaises(FileNotFoundError):
            parse_targets_from_file(self.temp_path / "nonexistent.txt")
    
    def test_empty_file(self):
        """Test empty file error."""
        target_file = self.temp_path / "empty.txt"
        target_file.write_text("")
        
        with self.assertRaises(ValueError):
            parse_targets_from_file(target_file)
    
    def test_file_with_only_comments(self):
        """Test file with only comments."""
        target_file = self.temp_path / "comments.txt"
        content = """# Comment 1
# Comment 2
# Comment 3
"""
        target_file.write_text(content)
        
        with self.assertRaises(ValueError):
            parse_targets_from_file(target_file)
    
    def test_invalid_target_in_file(self):
        """Test invalid target in file."""
        target_file = self.temp_path / "invalid.txt"
        content = """192.168.1.1
999.999.999.999
192.168.1.2
"""
        target_file.write_text(content)
        
        with self.assertRaises(ValueError) as cm:
            parse_targets_from_file(target_file)
        
        # Should mention line number
        self.assertIn("Line 2", str(cm.exception))


class TestMultiTargetScanning(unittest.TestCase):
    """Test multi-target scanning with PortScanner."""
    
    def test_scan_multiple_targets(self):
        """Test scanning multiple targets."""
        from spectrescan.core.scanner import PortScanner
        from spectrescan.core.presets import get_preset_config, ScanPreset
        
        config = get_preset_config(ScanPreset.QUICK)
        config.ports = [80, 443]
        
        scanner = PortScanner(config)
        
        # Scan localhost multiple times (comma-separated)
        results = scanner.scan("127.0.0.1,127.0.0.1")
        
        # Should have results for both "targets" (even though same IP)
        self.assertGreater(len(results), 0)
        
        # All results should be for localhost
        for result in results:
            self.assertEqual(result.host, "127.0.0.1")
    
    def test_target_callback(self):
        """Test target progress callback."""
        from spectrescan.core.scanner import PortScanner
        from spectrescan.core.presets import get_preset_config, ScanPreset
        
        config = get_preset_config(ScanPreset.QUICK)
        config.ports = [80]
        
        scanner = PortScanner(config)
        
        # Track callback invocations
        callbacks = []
        
        def target_callback(target, current, total):
            callbacks.append((target, current, total))
        
        # Scan multiple targets
        scanner.scan("127.0.0.1,127.0.0.1", target_callback=target_callback)
        
        # Should have been called for each target
        self.assertGreater(len(callbacks), 0)
        
        # Check callback data structure
        if callbacks:
            target, current, total = callbacks[0]
            self.assertIsInstance(target, str)
            self.assertIsInstance(current, int)
            self.assertIsInstance(total, int)
            self.assertGreater(current, 0)
            self.assertGreater(total, 0)
    
    def test_scan_summary_with_multiple_hosts(self):
        """Test scan summary with multiple hosts."""
        from spectrescan.core.scanner import PortScanner
        from spectrescan.core.presets import get_preset_config, ScanPreset
        
        config = get_preset_config(ScanPreset.QUICK)
        config.ports = [80]
        
        scanner = PortScanner(config)
        scanner.scan("127.0.0.1,127.0.0.1")
        
        summary = scanner.get_scan_summary()
        
        self.assertIn("hosts_scanned", summary)
        self.assertGreater(summary["hosts_scanned"], 0)
        self.assertIn("total_ports", summary)
        self.assertIn("scan_duration", summary)


class TestMultiTargetReporting(unittest.TestCase):
    """Test reporting with multi-target results."""
    
    def test_json_report_with_multiple_hosts(self):
        """Test JSON report generation with multiple hosts."""
        from spectrescan.core.utils import ScanResult
        from spectrescan.reports import generate_json_report
        import json
        
        results = [
            ScanResult(host="192.168.1.1", port=80, state="open", protocol="tcp"),
            ScanResult(host="192.168.1.1", port=443, state="open", protocol="tcp"),
            ScanResult(host="192.168.1.2", port=22, state="open", protocol="tcp"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = Path(f.name)
        
        try:
            generate_json_report(results, temp_path)
            
            # Read and verify
            with open(temp_path, 'r') as f:
                data = json.load(f)
            
            self.assertIn("results", data)
            self.assertEqual(len(data["results"]), 3)
            
            # Verify hosts
            hosts = set(r["host"] for r in data["results"])
            self.assertEqual(len(hosts), 2)
            self.assertIn("192.168.1.1", hosts)
            self.assertIn("192.168.1.2", hosts)
        
        finally:
            if temp_path.exists():
                temp_path.unlink()
    
    def test_csv_report_with_multiple_hosts(self):
        """Test CSV report generation with multiple hosts."""
        from spectrescan.core.utils import ScanResult
        from spectrescan.reports import generate_csv_report
        
        results = [
            ScanResult(host="192.168.1.1", port=80, state="open", protocol="tcp"),
            ScanResult(host="192.168.1.2", port=22, state="open", protocol="tcp"),
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
            temp_path = Path(f.name)
        
        try:
            generate_csv_report(results, temp_path)
            
            # Read and verify
            content = temp_path.read_text()
            
            self.assertIn("192.168.1.1", content)
            self.assertIn("192.168.1.2", content)
            self.assertIn("80", content)
            self.assertIn("22", content)
        
        finally:
            if temp_path.exists():
                temp_path.unlink()


if __name__ == "__main__":
    unittest.main()
