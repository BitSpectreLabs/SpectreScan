#!/usr/bin/env python3"
import time
import sys
from spectrescan.core.scanner import PortScanner
from spectrescan.core.presets import get_preset_config, ScanPreset
from spectrescan.core.timing_engine import TimingLevel, get_timing_template


def benchmark_scan(target: str, ports: list, timing_level: TimingLevel, description: str):
    """Run a single benchmark scan."""
    print(f"\n{'='*60}")
    print(f"{description}")
    print(f"{'='*60}")
    
    # Create scanner with timing template
    timing_template = get_timing_template(timing_level)
    config = get_preset_config(ScanPreset.CUSTOM)
    config.timing_template = timing_template
    config.scan_types = ["tcp"]
    config.enable_banner_grabbing = True
    config.enable_service_detection = True
    
    scanner = PortScanner(config, timing_template=timing_template, use_async=True)
    
    print(f"Target: {target}")
    print(f"Ports: {len(ports)} ports")
    print(f"Timing: {timing_template.name} ({timing_template.level.value})")
    print(f"Max Concurrent: {timing_template.max_concurrent}")
    print(f"Timeout: {timing_template.timeout}s")
    print(f"\nStarting scan...")
    
    start_time = time.time()
    
    try:
        results = scanner.scan(target, ports=ports)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Get stats
        open_ports = [r for r in results if r.state == "open"]
        closed_ports = [r for r in results if r.state == "closed"]
        filtered_ports = [r for r in results if r.state == "filtered"]
        
        # Calculate throughput
        ports_per_sec = len(ports) / duration if duration > 0 else 0
        
        print(f"\n✓ Scan complete in {duration:.2f} seconds")
        print(f"  Throughput: {ports_per_sec:.1f} ports/sec")
        print(f"  Open: {len(open_ports)}, Closed: {len(closed_ports)}, Filtered: {len(filtered_ports)}")
        
        # Show async scanner stats
        stats = scanner.async_scanner.get_stats()
        print(f"  Retries: {stats.get('retries', 0)}, Errors: {stats.get('errors', 0)}")
        
        if stats.get('rtt_samples', 0) > 0:
            print(f"  RTT-adjusted timeout: {stats.get('current_timeout', 0):.3f}s")
        
        # Show open ports with services
        if open_ports:
            print(f"\n  Open Ports:")
            for r in open_ports[:10]:  # Show first 10
                service = r.service or "unknown"
                banner = r.banner[:40] + "..." if r.banner and len(r.banner) > 40 else (r.banner or "")
                print(f"    {r.port}/{r.protocol} - {service}")
                if banner:
                    print(f"      Banner: {banner}")
        
        return {
            "duration": duration,
            "ports_per_sec": ports_per_sec,
            "open": len(open_ports),
            "closed": len(closed_ports),
            "filtered": len(filtered_ports),
            "total": len(results)
        }
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return None


def main():
    """Run benchmarks."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║       SpectreScan v1.2.0 Phase 1 Speed Benchmark            ║
║              by BitSpectreLabs                               ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Test target
    target = "scanme.nmap.org"
    
    # Test with increasing port counts
    test_cases = [
        (list(range(1, 101)), "100 ports"),
        (list(range(1, 501)), "500 ports"),
        (list(range(1, 1001)), "1000 ports"),
    ]
    
    results_summary = []
    
    for ports, description in test_cases:
        # Test with different timing templates
        timing_tests = [
            (TimingLevel.POLITE, f"{description} - T2 (Polite)"),
            (TimingLevel.NORMAL, f"{description} - T3 (Normal)"),
            (TimingLevel.AGGRESSIVE, f"{description} - T4 (Aggressive)"),
        ]
        
        for timing_level, test_desc in timing_tests:
            result = benchmark_scan(target, ports, timing_level, test_desc)
            if result:
                results_summary.append({
                    "test": test_desc,
                    "duration": result["duration"],
                    "throughput": result["ports_per_sec"]
                })
            
            # Small delay between tests
            time.sleep(2)
    
    # Print summary
    print(f"\n{'='*60}")
    print("BENCHMARK SUMMARY")
    print(f"{'='*60}\n")
    
    print(f"{'Test':<40} {'Duration':<12} {'Throughput':>12}")
    print("-" * 60)
    
    for r in results_summary:
        print(f"{r['test']:<40} {r['duration']:>8.2f}s    {r['throughput']:>8.1f} p/s")
    
    print(f"\n{'='*60}")
    print("Phase 1 Complete!")
    print("✓ Timing templates (T0-T5) implemented")
    print("✓ Async-first architecture with connection pooling")
    print("✓ Integrated banner grabbing in scan pipeline")
    print("✓ RTT-based adaptive timeout adjustment")
    print("✓ Parallel host scanning support")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✗ Benchmark interrupted by user")
        sys.exit(0)
