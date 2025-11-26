"""
Nmap Comparison Benchmark
Compare SpectreScan against Nmap for speed, accuracy, and resource usage.

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import subprocess
import time
import logging
import psutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkResult:
    """Benchmark result for a single test."""
    scanner: str
    target: str
    ports: List[int]
    scan_type: str
    duration: float
    open_ports: int
    closed_ports: int
    filtered_ports: int
    cpu_percent_avg: float
    memory_mb_peak: float
    accuracy_score: Optional[float] = None


class NmapComparator:
    """Compare SpectreScan against Nmap."""
    
    def __init__(self, nmap_path: str = "nmap"):
        """
        Initialize Nmap comparator.
        
        Args:
            nmap_path: Path to nmap executable
        """
        self.nmap_path = nmap_path
        self.verify_nmap()
    
    def verify_nmap(self) -> bool:
        """Verify Nmap is available."""
        try:
            result = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                logger.info(f"Nmap found: {result.stdout.split()[2]}")
                return True
            else:
                logger.error("Nmap not found")
                return False
        
        except Exception as e:
            logger.error(f"Nmap verification failed: {e}")
            return False
    
    async def benchmark_nmap(
        self,
        target: str,
        ports: List[int],
        scan_type: str = "tcp"
    ) -> BenchmarkResult:
        """
        Benchmark Nmap.
        
        Args:
            target: Target to scan
            ports: List of ports
            scan_type: Scan type (tcp/syn/udp)
        
        Returns:
            BenchmarkResult
        """
        # Build Nmap command
        port_spec = ",".join(str(p) for p in ports)
        
        scan_flags = {
            "tcp": "-sT",
            "syn": "-sS",
            "udp": "-sU"
        }
        
        output_file = Path(f"nmap_benchmark_{int(time.time())}.xml")
        
        cmd = [
            self.nmap_path,
            scan_flags.get(scan_type, "-sT"),
            "-p", port_spec,
            "-oX", str(output_file),
            target
        ]
        
        logger.info(f"Running Nmap: {' '.join(cmd)}")
        
        # Start monitoring
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        cpu_samples = []
        peak_memory = initial_memory
        
        start_time = time.time()
        
        # Run Nmap
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Monitor resources
            while proc.returncode is None:
                try:
                    cpu_samples.append(process.cpu_percent())
                    current_memory = process.memory_info().rss / 1024 / 1024
                    peak_memory = max(peak_memory, current_memory)
                except:
                    pass
                
                await asyncio.sleep(0.1)
                
                try:
                    await asyncio.wait_for(proc.wait(), timeout=0.1)
                except asyncio.TimeoutError:
                    pass
            
            duration = time.time() - start_time
            
            # Parse results
            open_ports, closed_ports, filtered_ports = self._parse_nmap_xml(output_file)
            
            # Cleanup
            output_file.unlink(missing_ok=True)
            
            return BenchmarkResult(
                scanner="nmap",
                target=target,
                ports=ports,
                scan_type=scan_type,
                duration=duration,
                open_ports=open_ports,
                closed_ports=closed_ports,
                filtered_ports=filtered_ports,
                cpu_percent_avg=sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0,
                memory_mb_peak=peak_memory
            )
        
        except Exception as e:
            logger.error(f"Nmap benchmark failed: {e}")
            raise
    
    def _parse_nmap_xml(self, xml_file: Path) -> tuple:
        """Parse Nmap XML output."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            open_count = 0
            closed_count = 0
            filtered_count = 0
            
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None:
                    state_val = state.get("state")
                    if state_val == "open":
                        open_count += 1
                    elif state_val == "closed":
                        closed_count += 1
                    elif state_val == "filtered":
                        filtered_count += 1
            
            return open_count, closed_count, filtered_count
        
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            return 0, 0, 0


class SpectreScanBenchmark:
    """Benchmark SpectreScan."""
    
    async def benchmark_spectrescan(
        self,
        target: str,
        ports: List[int],
        scan_type: str = "tcp"
    ) -> BenchmarkResult:
        """
        Benchmark SpectreScan.
        
        Args:
            target: Target to scan
            ports: List of ports
            scan_type: Scan type
        
        Returns:
            BenchmarkResult
        """
        from spectrescan.core.scanner import PortScanner
        from spectrescan.core.config import ScanConfig
        
        # Create scanner
        config = ScanConfig(
            threads=100,
            timeout=2.0,
            enable_service_detection=False,
            enable_os_detection=False,
            enable_banner_grabbing=False
        )
        
        scanner = PortScanner(config)
        
        # Start monitoring
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        cpu_samples = []
        peak_memory = initial_memory
        
        start_time = time.time()
        
        # Monitor task
        monitoring = True
        
        async def monitor_resources():
            while monitoring:
                try:
                    cpu_samples.append(process.cpu_percent())
                    current_memory = process.memory_info().rss / 1024 / 1024
                    peak_memory_local = max(peak_memory, current_memory)
                except:
                    pass
                await asyncio.sleep(0.1)
        
        monitor_task = asyncio.create_task(monitor_resources())
        
        try:
            # Run scan
            results = await scanner.scan(target, ports, scan_type=scan_type)
            
            duration = time.time() - start_time
            
            # Count results
            open_ports = sum(1 for r in results if r.state == "open")
            closed_ports = sum(1 for r in results if r.state == "closed")
            filtered_ports = sum(1 for r in results if r.state == "filtered")
            
            return BenchmarkResult(
                scanner="spectrescan",
                target=target,
                ports=ports,
                scan_type=scan_type,
                duration=duration,
                open_ports=open_ports,
                closed_ports=closed_ports,
                filtered_ports=filtered_ports,
                cpu_percent_avg=sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0,
                memory_mb_peak=peak_memory
            )
        
        finally:
            monitoring = False
            await monitor_task


class BenchmarkSuite:
    """Complete benchmark suite."""
    
    def __init__(self):
        """Initialize benchmark suite."""
        self.nmap = NmapComparator()
        self.spectrescan = SpectreScanBenchmark()
    
    async def run_comparison(
        self,
        target: str,
        port_ranges: List[List[int]],
        scan_types: List[str] = ["tcp"]
    ) -> Dict[str, List[BenchmarkResult]]:
        """
        Run full comparison.
        
        Args:
            target: Target to scan
            port_ranges: List of port ranges to test
            scan_types: Scan types to test
        
        Returns:
            Dictionary of results by scanner
        """
        results = {
            "nmap": [],
            "spectrescan": []
        }
        
        for ports in port_ranges:
            for scan_type in scan_types:
                logger.info(f"Benchmarking {len(ports)} ports with {scan_type}")
                
                # Benchmark Nmap
                try:
                    nmap_result = await self.nmap.benchmark_nmap(target, ports, scan_type)
                    results["nmap"].append(nmap_result)
                except Exception as e:
                    logger.error(f"Nmap benchmark failed: {e}")
                
                # Benchmark SpectreScan
                try:
                    spectrescan_result = await self.spectrescan.benchmark_spectrescan(target, ports, scan_type)
                    results["spectrescan"].append(spectrescan_result)
                except Exception as e:
                    logger.error(f"SpectreScan benchmark failed: {e}")
        
        return results
    
    def generate_report(self, results: Dict[str, List[BenchmarkResult]]) -> str:
        """
        Generate comparison report.
        
        Args:
            results: Benchmark results
        
        Returns:
            Formatted report
        """
        report = []
        report.append("=" * 80)
        report.append("SPECTRESCAN VS NMAP BENCHMARK")
        report.append("=" * 80)
        report.append("")
        
        # Compare each test
        for i in range(len(results["nmap"])):
            nmap = results["nmap"][i]
            spectrescan = results["spectrescan"][i]
            
            report.append(f"Test {i + 1}: {len(nmap.ports)} ports, {nmap.scan_type} scan")
            report.append("-" * 80)
            
            # Speed comparison
            speedup = nmap.duration / spectrescan.duration if spectrescan.duration > 0 else 0
            report.append(f"Speed:")
            report.append(f"  Nmap:        {nmap.duration:.2f}s")
            report.append(f"  SpectreScan: {spectrescan.duration:.2f}s")
            report.append(f"  Speedup:     {speedup:.2f}x {'FASTER' if speedup > 1 else 'SLOWER'}")
            report.append("")
            
            # Resource comparison
            report.append(f"Resources:")
            report.append(f"  Nmap CPU:        {nmap.cpu_percent_avg:.1f}%")
            report.append(f"  SpectreScan CPU: {spectrescan.cpu_percent_avg:.1f}%")
            report.append(f"  Nmap Memory:        {nmap.memory_mb_peak:.1f} MB")
            report.append(f"  SpectreScan Memory: {spectrescan.memory_mb_peak:.1f} MB")
            report.append("")
            
            # Accuracy comparison
            report.append(f"Accuracy:")
            report.append(f"  Nmap:        {nmap.open_ports} open, {nmap.closed_ports} closed, {nmap.filtered_ports} filtered")
            report.append(f"  SpectreScan: {spectrescan.open_ports} open, {spectrescan.closed_ports} closed, {spectrescan.filtered_ports} filtered")
            
            # Check for differences
            if nmap.open_ports != spectrescan.open_ports:
                report.append(f"  ⚠️  Open port count differs!")
            
            report.append("")
            report.append("")
        
        # Overall summary
        report.append("=" * 80)
        report.append("OVERALL SUMMARY")
        report.append("=" * 80)
        
        avg_nmap_speed = sum(r.duration for r in results["nmap"]) / len(results["nmap"])
        avg_spectrescan_speed = sum(r.duration for r in results["spectrescan"]) / len(results["spectrescan"])
        avg_speedup = avg_nmap_speed / avg_spectrescan_speed if avg_spectrescan_speed > 0 else 0
        
        report.append(f"Average Speed:    {avg_speedup:.2f}x faster")
        report.append(f"Total Tests:      {len(results['nmap'])}")
        report.append("")
        
        return "\n".join(report)


async def main():
    """Run benchmark."""
    suite = BenchmarkSuite()
    
    # Test configurations
    target = "scanme.nmap.org"
    port_ranges = [
        list(range(1, 101)),      # 100 ports
        list(range(1, 1001)),     # 1000 ports
        [22, 80, 443, 3306, 8080]  # Common ports
    ]
    
    logger.info("Starting benchmark suite")
    
    results = await suite.run_comparison(target, port_ranges)
    
    report = suite.generate_report(results)
    print(report)
    
    # Save report
    report_file = Path("benchmark_report.txt")
    report_file.write_text(report)
    logger.info(f"Report saved to {report_file}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
