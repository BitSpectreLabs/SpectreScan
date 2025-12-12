"""
Performance CLI Commands
Profiling, benchmarking, and optimization utilities.

Author: BitSpectreLabs
License: MIT
"""

import typer
from typing import Optional
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import asyncio
import time

app = typer.Typer(help="Performance profiling and benchmarking tools")
console = Console()


@app.command("benchmark")
def run_benchmark(
    target: str = typer.Argument(..., help="Target host to benchmark against"),
    ports: str = typer.Option("1-100", "-p", "--ports", help="Port range to test"),
    iterations: int = typer.Option(3, "-n", "--iterations", help="Number of iterations"),
    warmup: int = typer.Option(1, "-w", "--warmup", help="Warmup iterations")
):
    """
    Run performance benchmarks on scanning operations.
    """
    from spectrescan.core.performance import Benchmark, BatchPortChecker, AsyncDNSResolver
    from spectrescan.core.utils import parse_ports
    
    port_list = parse_ports(ports)
    
    console.print(Panel.fit(
        f"[bold cyan]Performance Benchmark[/bold cyan]\n"
        f"Target: {target}\n"
        f"Ports: {len(port_list)} ports\n"
        f"Iterations: {iterations}"
    ))
    
    results = []
    
    async def run_benchmarks():
        # DNS Resolution benchmark
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task("Running DNS benchmark...", total=None)
            
            resolver = AsyncDNSResolver()
            dns_result = await Benchmark.run_async(
                "DNS Resolution",
                lambda: resolver.resolve(target),
                iterations=iterations * 10,
                warmup=warmup
            )
            results.append(dns_result)
        
        # Batch port checking benchmark
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task("Running batch port check benchmark...", total=None)
            
            checker = BatchPortChecker(batch_size=50)
            
            async def check_batch():
                await checker.check_ports(target, port_list[:50])
            
            batch_result = await Benchmark.run_async(
                "Batch Port Check (50 ports)",
                check_batch,
                iterations=iterations,
                warmup=warmup
            )
            results.append(batch_result)
    
    asyncio.run(run_benchmarks())
    
    # Display results
    table = Table(title="Benchmark Results", show_header=True, header_style="bold magenta")
    table.add_column("Benchmark", style="cyan")
    table.add_column("Iterations", justify="right")
    table.add_column("Ops/sec", justify="right", style="green")
    table.add_column("Avg (ms)", justify="right")
    table.add_column("Min (ms)", justify="right")
    table.add_column("Max (ms)", justify="right")
    table.add_column("Std Dev", justify="right")
    
    for r in results:
        table.add_row(
            r.name,
            str(r.iterations),
            f"{r.ops_per_second:.1f}",
            f"{r.avg_time_ms:.3f}",
            f"{r.min_time_ms:.3f}",
            f"{r.max_time_ms:.3f}",
            f"{r.std_dev_ms:.3f}"
        )
    
    console.print(table)


@app.command("profile")
def show_profile(
    reset: bool = typer.Option(False, "--reset", "-r", help="Reset profiling data"),
    top: int = typer.Option(20, "--top", "-n", help="Show top N results")
):
    """
    Show profiling results from recent operations.
    """
    from spectrescan.core.performance import Profiler
    
    if reset:
        Profiler.reset()
        console.print("[green]Profiling data reset.[/green]")
        return
    
    results = Profiler.get_results()
    
    if not results:
        console.print("[yellow]No profiling data available.[/yellow]")
        console.print("Run scans with profiling enabled to collect data.")
        return
    
    table = Table(title="Profiling Results", show_header=True, header_style="bold magenta")
    table.add_column("Function", style="cyan", max_width=40)
    table.add_column("Calls", justify="right")
    table.add_column("Total (ms)", justify="right", style="yellow")
    table.add_column("Avg (ms)", justify="right")
    table.add_column("Min (ms)", justify="right")
    table.add_column("Max (ms)", justify="right")
    
    for r in results[:top]:
        table.add_row(
            r.name[:40],
            str(r.calls),
            f"{r.total_time * 1000:.2f}",
            f"{r.avg_time * 1000:.3f}",
            f"{r.min_time * 1000:.3f}",
            f"{r.max_time * 1000:.3f}"
        )
    
    console.print(table)


@app.command("gc")
def gc_command(
    collect: bool = typer.Option(False, "--collect", "-c", help="Force garbage collection"),
    tune: str = typer.Option(None, "--tune", "-t", help="Tune GC (throughput/latency)"),
    stats: bool = typer.Option(False, "--stats", "-s", help="Show GC statistics")
):
    """
    Garbage collection management.
    """
    from spectrescan.core.performance import GCOptimizer
    
    if collect:
        collected = GCOptimizer.collect()
        console.print(f"[green]Collected {collected} objects.[/green]")
    
    if tune:
        if tune.lower() == "throughput":
            GCOptimizer.tune_for_throughput()
            console.print("[green]GC tuned for throughput.[/green]")
        elif tune.lower() == "latency":
            GCOptimizer.tune_for_latency()
            console.print("[green]GC tuned for latency.[/green]")
        else:
            console.print(f"[red]Unknown tuning mode: {tune}[/red]")
            console.print("Use 'throughput' or 'latency'.")
    
    if stats or (not collect and not tune):
        gc_stats = GCOptimizer.get_stats()
        
        table = Table(title="GC Statistics", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Enabled", "Yes" if gc_stats["enabled"] else "No")
        table.add_row("Threshold", str(gc_stats["threshold"]))
        table.add_row("Generation Counts", str(gc_stats["counts"]))
        table.add_row("Objects Tracked", f"{gc_stats['objects_tracked']:,}")
        
        console.print(table)


@app.command("memory")
def memory_stats():
    """
    Show memory usage statistics.
    """
    from spectrescan.core.memory_optimizer import MemoryMonitor
    
    monitor = MemoryMonitor()
    stats = monitor.get_memory_usage()
    summary = monitor.get_memory_summary()
    
    table = Table(title="Memory Statistics", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("RSS (Resident Set)", f"{stats.rss_mb:.2f} MB")
    table.add_row("VMS (Virtual Memory)", f"{stats.vms_mb:.2f} MB")
    table.add_row("Usage %", f"{stats.percent:.1f}%")
    table.add_row("Available", f"{stats.available_mb:.0f} MB")
    
    console.print(table)


@app.command("dns")
def dns_benchmark(
    hostname: str = typer.Argument(..., help="Hostname to resolve"),
    iterations: int = typer.Option(10, "-n", help="Number of resolutions"),
    ipv6: bool = typer.Option(False, "--ipv6", help="Resolve IPv6 addresses")
):
    """
    Benchmark DNS resolution.
    """
    from spectrescan.core.performance import AsyncDNSResolver
    
    resolver = AsyncDNSResolver()
    
    async def run_dns():
        times = []
        
        for i in range(iterations):
            # Clear cache for fair benchmark
            if i == 0:
                resolver.clear_cache()
            
            start = time.perf_counter()
            result = await resolver.resolve(hostname, ipv6=ipv6)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            
            console.print(f"  [{i+1}] {hostname} -> {result or 'FAILED'} ({elapsed:.2f}ms)")
        
        return times
    
    console.print(f"\n[bold]DNS Resolution Benchmark: {hostname}[/bold]\n")
    
    times = asyncio.run(run_dns())
    
    if times:
        import statistics
        console.print(f"\n[bold green]Results:[/bold green]")
        console.print(f"  Average: {statistics.mean(times):.2f}ms")
        console.print(f"  Min: {min(times):.2f}ms")
        console.print(f"  Max: {max(times):.2f}ms")
        console.print(f"  First (uncached): {times[0]:.2f}ms")
        if len(times) > 1:
            console.print(f"  Subsequent (cached): {statistics.mean(times[1:]):.2f}ms")


@app.command("pool")
def pool_stats():
    """
    Show connection pool statistics.
    """
    from spectrescan.core.performance import EnhancedConnectionPool
    
    pool = EnhancedConnectionPool()
    stats = pool.get_stats()
    
    table = Table(title="Connection Pool Statistics", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in stats.items():
        table.add_row(key.replace("_", " ").title(), str(value))
    
    console.print(table)


if __name__ == "__main__":
    app()
