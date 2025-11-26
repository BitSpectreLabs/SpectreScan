"""
Service Detection Accuracy Testing

Test service detection against known services to measure accuracy.

File: spectrescan/tests/test_service_detection.py
Author: BitSpectreLabs
"""

import asyncio
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from spectrescan.core.service_detection import ServiceDetector, ServiceInfo
from spectrescan.core.version_detection import VersionExtractor
from spectrescan.core.banner_parser import BannerParser


@dataclass
class TestCase:
    """A test case for service detection."""
    
    name: str
    banner: str
    expected_service: str
    expected_version: str = None
    port: int = 80
    protocol: str = "TCP"


# Test cases with known banners
TEST_CASES = [
    # HTTP servers
    TestCase(
        name="nginx",
        banner="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
        expected_service="http",
        expected_version="1.18.0",
        port=80
    ),
    TestCase(
        name="Apache",
        banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
        expected_service="http",
        expected_version="2.4.41",
        port=80
    ),
    TestCase(
        name="IIS",
        banner="HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n",
        expected_service="http",
        expected_version="10.0",
        port=80
    ),
    
    # SSH servers
    TestCase(
        name="OpenSSH",
        banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        expected_service="ssh",
        expected_version="8.2p1",
        port=22
    ),
    TestCase(
        name="Dropbear SSH",
        banner="SSH-2.0-dropbear_2020.81",
        expected_service="ssh",
        expected_version="2020.81",
        port=22
    ),
    
    # FTP servers
    TestCase(
        name="ProFTPD",
        banner="220 ProFTPD 1.3.5 Server ready",
        expected_service="ftp",
        expected_version="1.3.5",
        port=21
    ),
    TestCase(
        name="vsftpd",
        banner="220 (vsFTPd 3.0.3)",
        expected_service="ftp",
        expected_version="3.0.3",
        port=21
    ),
    
    # SMTP servers
    TestCase(
        name="Postfix",
        banner="220 mail.example.com ESMTP Postfix",
        expected_service="smtp",
        expected_version=None,
        port=25
    ),
    TestCase(
        name="Exim",
        banner="220 mail.example.com ESMTP Exim 4.94.2",
        expected_service="smtp",
        expected_version="4.94.2",
        port=25
    ),
    
    # Databases
    TestCase(
        name="MySQL",
        banner="\x4a\x00\x00\x00\x0a5.7.33-0ubuntu0.18.04.1",
        expected_service="mysql",
        expected_version="5.7.33",
        port=3306
    ),
    TestCase(
        name="MariaDB",
        banner="\x4a\x00\x00\x00\x0a10.3.31-MariaDB-0ubuntu0.20.04.1",
        expected_service="mysql",
        expected_version="10.3.31",
        port=3306
    ),
    TestCase(
        name="Redis",
        banner="-ERR unknown command",
        expected_service="redis",
        expected_version=None,
        port=6379
    ),
    TestCase(
        name="Redis INFO",
        banner="# Server\r\nredis_version:6.2.6\r\n",
        expected_service="redis",
        expected_version="6.2.6",
        port=6379
    ),
    TestCase(
        name="MongoDB",
        banner='{"version":"4.4.10","gitVersion":"58971da1ef99a1b949ef"}',
        expected_service="mongodb",
        expected_version="4.4.10",
        port=27017
    ),
    
    # Modern services
    TestCase(
        name="Elasticsearch",
        banner='{"name":"node1","cluster_name":"elasticsearch","version":{"number":"7.15.0"}}',
        expected_service="elasticsearch",
        expected_version="7.15.0",
        port=9200
    ),
    TestCase(
        name="Docker API",
        banner='{"Version":"20.10.12","ApiVersion":"1.41","MinAPIVersion":"1.12"}',
        expected_service="docker",
        expected_version="20.10.12",
        port=2375
    ),
    TestCase(
        name="Kubernetes API",
        banner='{"major":"1","minor":"22","gitVersion":"v1.22.5","gitCommit":"5c99e2a"}',
        expected_service="kubernetes",
        expected_version="1.22.5",
        port=6443
    ),
]


class ServiceDetectionTester:
    """Test service detection accuracy."""
    
    def __init__(self):
        self.parser = BannerParser()
        self.version_extractor = VersionExtractor()
        self.results: List[Dict] = []
    
    def run_tests(self, test_cases: List[TestCase]) -> Dict[str, any]:
        """
        Run all test cases.
        
        Args:
            test_cases: List of TestCase objects
            
        Returns:
            Dictionary with test results
        """
        total = len(test_cases)
        passed = 0
        failed = 0
        
        print(f"\n{'='*70}")
        print(f"Running Service Detection Accuracy Tests")
        print(f"{'='*70}\n")
        
        for i, test_case in enumerate(test_cases, 1):
            result = self.run_single_test(test_case)
            self.results.append(result)
            
            status = "✓ PASS" if result['passed'] else "✗ FAIL"
            print(f"[{i}/{total}] {status} | {test_case.name}")
            
            if result['passed']:
                passed += 1
            else:
                failed += 1
                print(f"         Expected: {test_case.expected_service}/{test_case.expected_version}")
                print(f"         Got:      {result['detected_service']}/{result['detected_version']}")
        
        # Calculate accuracy
        service_accuracy = passed / total * 100 if total > 0 else 0
        
        # Calculate version detection accuracy
        version_tests = [tc for tc in test_cases if tc.expected_version]
        version_correct = sum(1 for r in self.results if r.get('version_correct', False))
        version_accuracy = version_correct / len(version_tests) * 100 if version_tests else 0
        
        print(f"\n{'='*70}")
        print(f"Test Results Summary")
        print(f"{'='*70}")
        print(f"Total Tests:              {total}")
        print(f"Passed:                   {passed}")
        print(f"Failed:                   {failed}")
        print(f"Service Detection:        {service_accuracy:.1f}%")
        print(f"Version Detection:        {version_accuracy:.1f}%")
        print(f"{'='*70}\n")
        
        return {
            'total': total,
            'passed': passed,
            'failed': failed,
            'service_accuracy': service_accuracy,
            'version_accuracy': version_accuracy,
            'results': self.results
        }
    
    def run_single_test(self, test_case: TestCase) -> Dict:
        """
        Run a single test case.
        
        Args:
            test_case: TestCase object
            
        Returns:
            Dictionary with test result
        """
        # Parse banner with service hint
        parsed = self.parser.parse(test_case.banner, service=test_case.expected_service)
        
        # Extract version
        version_info = self.version_extractor.extract_version(
            test_case.banner,
            test_case.expected_service,
            test_case.port
        )
        
        # Determine detected service
        detected_service = parsed.service or "unknown"
        detected_version = parsed.version or version_info.version
        
        # Check if service matches
        service_match = (
            detected_service.lower() == test_case.expected_service.lower() or
            test_case.expected_service.lower() in detected_service.lower()
        )
        
        # Check if version matches
        version_match = True
        if test_case.expected_version:
            if detected_version:
                version_match = test_case.expected_version in detected_version
            else:
                version_match = False
        
        passed = service_match and (not test_case.expected_version or version_match)
        
        return {
            'test_name': test_case.name,
            'expected_service': test_case.expected_service,
            'expected_version': test_case.expected_version,
            'detected_service': detected_service,
            'detected_version': detected_version,
            'service_correct': service_match,
            'version_correct': version_match if test_case.expected_version else None,
            'passed': passed
        }


def main():
    """Run service detection tests."""
    tester = ServiceDetectionTester()
    results = tester.run_tests(TEST_CASES)
    
    # Check if we meet accuracy targets
    if results['service_accuracy'] >= 95.0:
        print("✓ Service detection accuracy target achieved (95%+)")
    else:
        print(f"✗ Service detection accuracy below target: {results['service_accuracy']:.1f}% < 95%")
    
    if results['version_accuracy'] >= 80.0:
        print("✓ Version detection accuracy target achieved (80%+)")
    else:
        print(f"✗ Version detection accuracy below target: {results['version_accuracy']:.1f}% < 80%")
    
    # Return exit code based on results
    return 0 if results['passed'] == results['total'] else 1


if __name__ == "__main__":
    exit(main())
