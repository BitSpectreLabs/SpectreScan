"""
SpectreScan CLI - Command Line Interface
by BitSpectreLabs
"""

import typer
import sys
from typing import Optional, List
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint
from spectrescan.core.scanner import PortScanner
from spectrescan.core.presets import (
    ScanPreset, get_preset_config, list_presets, ScanConfig
)
from spectrescan.core.utils import parse_ports, get_common_ports, ScanResult, parse_targets_from_file
from spectrescan.core.profiles import ProfileManager, ScanProfile
from spectrescan.core.history import HistoryManager
from spectrescan.core.comparison import ScanComparer
from spectrescan.reports.html_report import generate_html_report
from spectrescan.reports import (
    generate_json_report, generate_csv_report, generate_xml_report
)


app = typer.Typer(
    name="spectrescan",
    help="SpectreScan - Professional-grade Port Scanner by BitSpectreLabs",
    add_completion=False,
    no_args_is_help=True
)

console = Console()


ASCII_LOGO = r"""
  ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
  ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
  ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
                                                             
   ███████╗ ██████╗ █████╗ ███╗   ██╗                      
   ██╔════╝██╔════╝██╔══██╗████╗  ██║                      
   ███████╗██║     ███████║██╔██╗ ██║                      
   ╚════██║██║     ██╔══██║██║╚██╗██║                      
   ███████║╚██████╗██║  ██║██║ ╚████║                      
   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                      
                                                             
        Professional Port Scanner by BitSpectreLabs
"""


def print_logo():
    """Print ASCII logo."""
    console.print(ASCII_LOGO, style="bold cyan")


def result_callback(result: ScanResult):
    """Callback for scan progress."""
    if result.state == "open":
        service = result.service or "unknown"
        console.print(
            f"[green]✓[/green] {result.host}:{result.port}/{result.protocol} "
            f"[yellow]{service}[/yellow]"
        )


@app.command(name="scan", help="Scan target for open ports and services")
def scan(
    target: Optional[str] = typer.Argument(None, help="Target IP, hostname, CIDR, range, or comma-separated list"),
    ports: Optional[str] = typer.Option(None, "-p", "--ports", help="Port specification (e.g., 1-1000, 80,443)"),
    
    # Multi-target options
    target_file: Optional[Path] = typer.Option(None, "--target-file", "-iL", help="Read targets from file (one per line)"),
    
    # Scan types
    tcp: bool = typer.Option(False, "--tcp", help="TCP connect scan"),
    syn: bool = typer.Option(False, "--syn", help="TCP SYN scan (requires privileges)"),
    udp: bool = typer.Option(False, "--udp", help="UDP scan"),
    async_scan: bool = typer.Option(False, "--async", help="Async high-speed scan"),
    
    # Presets
    quick: bool = typer.Option(False, "--quick", help="Quick scan (top 100 ports)"),
    top_ports: bool = typer.Option(False, "--top-ports", help="Top 1000 ports"),
    full: bool = typer.Option(False, "--full", help="Full scan (all 65535 ports)"),
    stealth: bool = typer.Option(False, "--stealth", help="Stealth scan mode"),
    safe: bool = typer.Option(False, "--safe", help="Safe, non-intrusive scan"),
    aggressive: bool = typer.Option(False, "--aggressive", help="Aggressive scan"),
    
    # Options
    threads: int = typer.Option(100, "--threads", help="Number of threads"),
    timeout: float = typer.Option(2.0, "--timeout", help="Timeout in seconds"),
    rate_limit: Optional[int] = typer.Option(None, "--rate-limit", help="Rate limit (packets/sec)"),
    
    # Timing templates (like Nmap's -T flag)
    timing: Optional[str] = typer.Option(None, "-T", "--timing", help="Timing template: T0 (paranoid), T1 (sneaky), T2 (polite), T3 (normal), T4 (aggressive), T5 (insane)"),
    
    # Features
    service_detection: bool = typer.Option(True, "--service-detection/--no-service-detection", help="Enable service detection"),
    os_detection: bool = typer.Option(False, "--os-detection", help="Enable OS detection"),
    banner_grab: bool = typer.Option(True, "--banner-grab/--no-banner-grab", help="Enable banner grabbing"),
    ssl_analysis: bool = typer.Option(False, "--ssl-analysis", help="Enable SSL/TLS analysis on HTTPS ports"),
    cve_check: bool = typer.Option(False, "--cve-check", help="Check detected services for CVEs (requires internet)"),
    randomize: bool = typer.Option(False, "--randomize", help="Randomize scan order"),
    
    # Proxy options
    proxy: Optional[str] = typer.Option(None, "--proxy", help="Proxy URL (e.g., socks5://127.0.0.1:9050)"),
    proxy_file: Optional[Path] = typer.Option(None, "--proxy-file", help="File with proxy URLs (one per line)"),
    proxy_rotate: bool = typer.Option(False, "--proxy-rotate", help="Rotate through proxies in pool"),
    proxy_strategy: str = typer.Option("round_robin", "--proxy-strategy", help="Rotation strategy: round_robin, random, least_used, fastest"),
    tor: bool = typer.Option(False, "--tor", help="Use Tor network (socks5://127.0.0.1:9050)"),
    proxy_check: bool = typer.Option(False, "--proxy-check", help="Check proxy health before scanning"),
    
    # Evasion options
    evasion: Optional[str] = typer.Option(None, "--evasion", "-e", help="Evasion profile: none, stealth, paranoid, aggressive"),
    decoys: Optional[str] = typer.Option(None, "-D", "--decoys", help="Decoy IPs (comma-separated, use RND for random)"),
    decoy_count: int = typer.Option(0, "--decoy-count", help="Number of random decoys to generate"),
    source_port: Optional[int] = typer.Option(None, "-g", "--source-port", help="Use specific source port"),
    random_source_port: bool = typer.Option(False, "--random-source-port", help="Randomize source port"),
    common_source_port: bool = typer.Option(False, "--common-source-port", help="Use common source port (53, 80, 443)"),
    ttl: Optional[int] = typer.Option(None, "--ttl", help="Set IP Time-To-Live"),
    ttl_style: str = typer.Option("default", "--ttl-style", help="TTL style: linux, windows, solaris, random"),
    fragment: bool = typer.Option(False, "-f", "--fragment", help="Fragment packets"),
    fragment_mtu: int = typer.Option(8, "--mtu", help="Set MTU for fragmentation"),
    bad_checksum: bool = typer.Option(False, "--badsum", help="Send packets with bad checksums"),
    randomize_hosts: bool = typer.Option(False, "--randomize-hosts", help="Randomize target host order"),
    scan_delay: Optional[float] = typer.Option(None, "--scan-delay", help="Delay between probes (ms)"),
    max_parallelism: int = typer.Option(100, "--max-parallelism", help="Maximum concurrent probes"),
    zombie_host: Optional[str] = typer.Option(None, "-sI", "--idle-scan", help="Idle scan using zombie host"),
    zombie_port: int = typer.Option(80, "--zombie-port", help="Zombie host port for idle scan"),
    data_length: int = typer.Option(0, "--data-length", help="Append random data to packets"),
    
    # Output
    json_output: Optional[Path] = typer.Option(None, "--json", help="Save JSON output"),
    csv_output: Optional[Path] = typer.Option(None, "--csv", help="Save CSV output"),
    xml_output: Optional[Path] = typer.Option(None, "--xml", help="Save XML output"),
    html_output: Optional[Path] = typer.Option(None, "--html", help="Save HTML report"),
    pdf_output: Optional[Path] = typer.Option(None, "--pdf", help="Save PDF report with charts"),
    markdown_output: Optional[Path] = typer.Option(None, "--markdown", "--md", help="Save Markdown report"),
    executive_summary: Optional[Path] = typer.Option(None, "--exec-summary", help="Save executive summary"),
    ssl_output: Optional[Path] = typer.Option(None, "--ssl-output", help="Save SSL/TLS analysis report (JSON)"),
    cve_output: Optional[Path] = typer.Option(None, "--cve-output", help="Save CVE check results (JSON)"),
    
    # Misc
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Quiet mode (only show open ports)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    
):
    """
    Scan target for open ports and services.
    
    Examples:
    
      spectrescan scan 192.168.1.1 --quick
      
      spectrescan scan scanme.nmap.org -p 1-1000 --tcp --service-detection
      
      spectrescan scan 10.0.0.0/24 --top-ports --async --threads 500
      
      spectrescan scan 192.168.1.1-254 --stealth --json results.json
      
      # Multi-target scanning
      spectrescan scan 192.168.1.1,192.168.1.2,example.com --quick
      
      spectrescan scan --target-file targets.txt --top-ports
      
      # Proxy scanning
      spectrescan scan 192.168.1.1 --proxy socks5://127.0.0.1:9050
      
      spectrescan scan 192.168.1.1 --tor
      
      spectrescan scan 192.168.1.1 --proxy-file proxies.txt --proxy-rotate
      
      # Evasion scanning
      spectrescan scan 192.168.1.1 --evasion stealth
      
      spectrescan scan 192.168.1.1 -D 1.1.1.1,2.2.2.2,RND,RND --quick
      
      spectrescan scan 192.168.1.1 -f --mtu 8 --ttl 64
      
      spectrescan scan 192.168.1.1 -g 53 --randomize-hosts
      
      spectrescan scan 192.168.1.1 -sI zombie.example.com
    """
    # Validate input
    if not target and not target_file:
        console.print("[red]Error:[/red] Either target or --target-file must be specified", style="bold")
        sys.exit(1)
    
    if target and target_file:
        console.print("[red]Error:[/red] Cannot specify both target and --target-file", style="bold")
        sys.exit(1)
    
    # Handle target file input
    if target_file:
        try:
            from spectrescan.core.utils import parse_targets_from_file
            targets = parse_targets_from_file(target_file)
            # Convert list to comma-separated string for scanner
            target = ','.join(targets)
            if not quiet:
                console.print(f"[cyan]Loaded {len(targets)} targets from {target_file}[/cyan]\n")
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Target file not found: {target_file}", style="bold")
            sys.exit(1)
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}", style="bold")
            sys.exit(1)
    
    # Print logo
    if not quiet:
        print_logo()
    
    # Determine scan configuration
    config = None
    
    if quick:
        config = get_preset_config(ScanPreset.QUICK)
    elif top_ports:
        config = get_preset_config(ScanPreset.TOP_PORTS)
    elif full:
        config = get_preset_config(ScanPreset.FULL)
    elif stealth:
        config = get_preset_config(ScanPreset.STEALTH)
    elif safe:
        config = get_preset_config(ScanPreset.SAFE)
    elif aggressive:
        config = get_preset_config(ScanPreset.AGGRESSIVE)
    else:
        # Custom configuration
        config = get_preset_config(ScanPreset.CUSTOM)
        
        # Determine scan types
        scan_types = []
        if tcp or (not syn and not udp):
            scan_types.append("tcp")
        if syn:
            scan_types.append("syn")
        if udp:
            scan_types.append("udp")
        
        config.scan_types = scan_types
        config.threads = threads
        config.timeout = timeout
        config.rate_limit = rate_limit
        config.enable_service_detection = service_detection
        config.enable_os_detection = os_detection
        config.enable_banner_grabbing = banner_grab
        config.randomize = randomize
    
    # Apply timing template if specified
    if timing:
        from spectrescan.core.timing_engine import get_timing_template_by_name
        timing_template = get_timing_template_by_name(timing.upper())
        if timing_template:
            config.timing_template = timing_template
            if not quiet:
                console.print(f"[cyan]Using timing template: {timing_template.name} ({timing_template.level.value})[/cyan]\n")
        else:
            console.print(f"[yellow]Warning: Invalid timing template '{timing}'. Using default.[/yellow]")
            console.print("[cyan]Valid options: T0, T1, T2, T3 (default), T4, T5[/cyan]\n")
    
    # Parse ports
    if ports:
        try:
            port_list = parse_ports(ports)
            config.ports = port_list
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}", style="bold")
            sys.exit(1)
    
    # Configure proxy
    proxy_config = None
    proxy_pool_config = None
    
    if tor:
        # Use Tor network
        from spectrescan.core.proxy import create_tor_proxy
        proxy_config = create_tor_proxy()
        if not quiet:
            console.print("[cyan]Using Tor network (socks5://127.0.0.1:9050)[/cyan]\n")
    elif proxy:
        # Single proxy
        from spectrescan.core.proxy import ProxyConfig
        try:
            proxy_config = ProxyConfig.from_url(proxy, timeout=config.timeout)
            if not quiet:
                console.print(f"[cyan]Using proxy: {proxy_config.url}[/cyan]\n")
        except ValueError as e:
            console.print(f"[red]Error:[/red] Invalid proxy URL: {e}", style="bold")
            sys.exit(1)
    elif proxy_file:
        # Load proxies from file
        from spectrescan.core.proxy import load_proxies_from_file, create_proxy_pool, ProxyHealthChecker
        import asyncio
        
        try:
            proxies = load_proxies_from_file(proxy_file)
            if not proxies:
                console.print(f"[red]Error:[/red] No valid proxies found in {proxy_file}", style="bold")
                sys.exit(1)
            
            if proxy_rotate:
                proxy_pool_config = create_proxy_pool(proxies, rotation_strategy=proxy_strategy)
                if not quiet:
                    console.print(f"[cyan]Loaded {len(proxies)} proxies with {proxy_strategy} rotation[/cyan]\n")
            else:
                # Use first proxy
                proxy_config = proxies[0]
                if not quiet:
                    console.print(f"[cyan]Using proxy: {proxy_config.url}[/cyan]\n")
            
            # Health check if requested
            if proxy_check and (proxy_pool_config or proxy_config):
                if not quiet:
                    console.print("[dim]Checking proxy health...[/dim]")
                checker = ProxyHealthChecker(timeout=5.0)
                
                if proxy_pool_config:
                    results = asyncio.run(checker.check_pool(proxy_pool_config))
                    healthy_count = sum(1 for s in results.values() if s.value == "healthy")
                    console.print(f"[cyan]Healthy proxies: {healthy_count}/{len(results)}[/cyan]\n")
                elif proxy_config:
                    status = asyncio.run(checker.check_proxy(proxy_config))
                    if status.value != "healthy":
                        console.print(f"[yellow]Warning: Proxy status: {status.value}[/yellow]\n")
                    else:
                        console.print(f"[green]Proxy is healthy (latency: {proxy_config.latency_ms:.0f}ms)[/green]\n")
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Proxy file not found: {proxy_file}", style="bold")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to load proxies: {e}", style="bold")
            sys.exit(1)
    
    # Configure evasion
    evasion_manager = None
    
    # Parse decoys
    decoy_list = None
    random_decoy_count = decoy_count
    if decoys:
        decoy_list = []
        for d in decoys.split(","):
            d = d.strip()
            if d.upper() == "RND":
                random_decoy_count += 1
            else:
                decoy_list.append(d)
    
    # Check if any evasion option is specified
    has_evasion = any([
        evasion, decoy_list, random_decoy_count > 0, source_port,
        random_source_port, common_source_port, ttl,
        ttl_style != "default", fragment, bad_checksum,
        randomize_hosts, scan_delay, zombie_host, data_length > 0,
    ])
    
    if has_evasion:
        from spectrescan.core.evasion import EvasionManager
        
        # Get timing level from timing option or default
        timing_level = 3  # Normal
        if timing:
            timing_map = {"T0": 0, "T1": 1, "T2": 2, "T3": 3, "T4": 4, "T5": 5}
            timing_level = timing_map.get(timing.upper(), 3)
        
        evasion_manager = EvasionManager.from_cli_args(
            evasion=evasion,
            decoys=decoy_list,
            decoy_count=random_decoy_count,
            source_port=source_port,
            randomize_source_port=random_source_port,
            common_source_port=common_source_port,
            ttl=ttl,
            ttl_style=ttl_style,
            fragment=fragment,
            fragment_mtu=fragment_mtu,
            bad_checksum=bad_checksum,
            randomize_hosts=randomize_hosts,
            randomize_ports=randomize,
            timing_level=timing_level,
            max_parallelism=max_parallelism,
            scan_delay=scan_delay,
            zombie_host=zombie_host,
            zombie_port=zombie_port,
            data_length=data_length,
        )
        
        if not quiet:
            summary = evasion_manager.get_summary()
            console.print("[cyan]Evasion Mode Enabled[/cyan]")
            if summary["profile"] != "none":
                console.print(f"  Profile: {summary['profile']}")
            if summary["techniques"]:
                console.print(f"  Techniques: {', '.join(summary['techniques'])}")
            if summary["decoys"] > 0:
                console.print(f"  Decoys: {summary['decoys']}")
            if summary["fragmentation"]:
                console.print(f"  Fragmentation: MTU {fragment_mtu}")
            if summary["source_port"]:
                console.print(f"  Source Port: {summary['source_port']}")
            if summary["ttl"]:
                console.print(f"  TTL: {summary['ttl']}")
            if summary["idle_scan"]:
                console.print(f"  Idle Scan: {zombie_host}:{zombie_port}")
            console.print()
    
    # Display scan info
    if not quiet:
        info_table = Table(show_header=False, box=None)
        info_table.add_row("Target:", f"[cyan]{target}[/cyan]")
        info_table.add_row("Ports:", f"{len(config.ports)}")
        info_table.add_row("Scan Type:", f"{', '.join(config.scan_types).upper()}")
        
        # Show proxy info
        if proxy_config:
            info_table.add_row("Proxy:", f"{proxy_config.url}")
        elif proxy_pool_config:
            info_table.add_row("Proxy Pool:", f"{len(proxy_pool_config)} proxies ({proxy_strategy})")
        
        # Show timing template info
        if hasattr(config, 'timing_template') and config.timing_template:
            tt = config.timing_template
            info_table.add_row("Timing:", f"{tt.name} ({tt.level.value})")
            info_table.add_row("Concurrency:", f"{tt.max_concurrent}")
            info_table.add_row("Timeout:", f"{tt.timeout}s")
        else:
            info_table.add_row("Threads:", f"{config.threads}")
            info_table.add_row("Timeout:", f"{config.timeout}s")
        
        # Show evasion info
        if evasion_manager and evasion_manager.is_evasion_enabled():
            info_table.add_row("Evasion:", "[yellow]Enabled[/yellow]")
        
        console.print(Panel(info_table, title="[bold]Scan Configuration[/bold]", border_style="blue"))
        console.print()
    
    # Create scanner
    scanner = PortScanner(config, proxy=proxy_config, proxy_pool=proxy_pool_config, evasion=evasion_manager)
    
    # Perform scan
    try:
        if quiet:
            results = scanner.scan(target)
        else:
            console.print("[bold yellow]Starting scan...[/bold yellow]\n")
            results = scanner.scan(target, callback=result_callback)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error during scan:[/red] {e}")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)
    
    # Display results
    if not quiet:
        console.print("\n" + "="*60)
        console.print("[bold green]Scan Complete![/bold green]")
        console.print("="*60 + "\n")
    
    # Summary
    summary = scanner.get_scan_summary()
    open_results = scanner.get_open_ports()
    
    if not quiet:
        summary_table = Table(title="Scan Summary", show_header=False)
        summary_table.add_row("Total Ports Scanned:", f"{summary['total_ports']}")
        summary_table.add_row("[green]Open Ports:[/green]", f"[green]{summary['open_ports']}[/green]")
        summary_table.add_row("Closed Ports:", f"{summary['closed_ports']}")
        summary_table.add_row("Filtered Ports:", f"{summary['filtered_ports']}")
        summary_table.add_row("Scan Duration:", f"{summary['scan_duration']}")
        console.print(summary_table)
        console.print()
    
    # Display open ports
    if open_results:
        results_table = Table(title="Open Ports", show_header=True, header_style="bold cyan")
        results_table.add_column("Host", style="cyan")
        results_table.add_column("Port", style="magenta")
        results_table.add_column("Protocol", style="blue")
        results_table.add_column("Service", style="yellow")
        results_table.add_column("Banner", style="green")
        
        for result in open_results:
            service = result.service or "unknown"
            banner = result.banner[:50] + "..." if result.banner and len(result.banner) > 50 else (result.banner or "")
            
            results_table.add_row(
                result.host,
                str(result.port),
                result.protocol,
                service,
                banner
            )
        
        console.print(results_table)
    else:
        if not quiet:
            console.print("[yellow]No open ports found[/yellow]")
    
    # OS detection results
    if config.enable_os_detection and scanner.host_info:
        console.print("\n[bold]OS Detection:[/bold]")
        for host, info in scanner.host_info.items():
            if info.os_guess:
                console.print(f"  {host}: [cyan]{info.os_guess}[/cyan]")
    
    # SSL/TLS Analysis
    ssl_results = {}
    if ssl_analysis:
        from spectrescan.core.ssl_analyzer import SSLAnalyzer, VulnerabilityStatus
        ssl_ports = [443, 8443, 8080, 993, 995, 465, 636, 989, 990]
        https_ports = [r for r in open_results if r.port in ssl_ports]
        
        if https_ports:
            console.print("\n[bold]SSL/TLS Analysis:[/bold]")
            analyzer = SSLAnalyzer(timeout=config.timeout)
            
            for result in https_ports:
                console.print(f"\n  Analyzing {result.host}:{result.port}...")
                ssl_result = analyzer.analyze(result.host, result.port)
                ssl_results[f"{result.host}:{result.port}"] = ssl_result
                
                if ssl_result.certificate:
                    cert = ssl_result.certificate
                    cn = cert.subject.get("commonName", "Unknown")
                    console.print(f"    [cyan]Certificate:[/cyan] {cn}")
                    
                    if cert.is_expired:
                        console.print(f"    [red]EXPIRED[/red] - Certificate has expired!")
                    elif cert.days_until_expiry < 30:
                        console.print(f"    [yellow]WARNING[/yellow] - Expires in {cert.days_until_expiry} days")
                    else:
                        console.print(f"    [green]Valid[/green] - Expires in {cert.days_until_expiry} days")
                    
                    if cert.is_self_signed:
                        console.print(f"    [yellow]Self-signed certificate[/yellow]")
                
                # Show supported protocols
                if ssl_result.supported_protocols:
                    protocols = [p.value for p in ssl_result.supported_protocols]
                    console.print(f"    [cyan]Protocols:[/cyan] {', '.join(protocols)}")
                
                # Show preferred cipher
                if ssl_result.preferred_cipher:
                    cipher = ssl_result.preferred_cipher
                    console.print(f"    [cyan]Cipher:[/cyan] {cipher.name} ({cipher.bits}-bit)")
                
                # Show vulnerabilities
                vulns = [v for v in ssl_result.vulnerabilities 
                         if v.status == VulnerabilityStatus.VULNERABLE]
                if vulns:
                    console.print(f"    [red]Vulnerabilities:[/red]")
                    for v in vulns:
                        console.print(f"      - {v.name}: {v.severity}")
                
                # Show risk score
                risk = ssl_result.get_risk_score()
                if risk >= 75:
                    console.print(f"    [red]Risk Score: {risk}/100 (CRITICAL)[/red]")
                elif risk >= 50:
                    console.print(f"    [yellow]Risk Score: {risk}/100 (HIGH)[/yellow]")
                elif risk >= 25:
                    console.print(f"    [yellow]Risk Score: {risk}/100 (MEDIUM)[/yellow]")
                else:
                    console.print(f"    [green]Risk Score: {risk}/100 (LOW)[/green]")
    
    # CVE Check
    cve_results = {}
    if cve_check:
        from spectrescan.core.cve_matcher import CVEMatcher, CVESeverity, cve_result_to_dict
        import asyncio
        
        # Collect unique services from open ports
        services_to_check = []
        seen_services = set()
        
        for result in open_results:
            if result.service and result.service != "unknown":
                service_key = result.service.lower()
                
                # Extract version from banner if available
                version = None
                if result.banner:
                    # Try to extract version from banner
                    import re
                    version_patterns = [
                        r'(\d+\.\d+\.\d+)',
                        r'v(\d+\.\d+)',
                        r'/(\d+\.\d+)',
                    ]
                    for pattern in version_patterns:
                        match = re.search(pattern, result.banner)
                        if match:
                            version = match.group(1)
                            break
                
                if (service_key, version) not in seen_services:
                    seen_services.add((service_key, version))
                    services_to_check.append({
                        "product": result.service,
                        "version": version,
                        "host": result.host,
                        "port": result.port
                    })
        
        if services_to_check:
            console.print("\n[bold]CVE Vulnerability Check:[/bold]")
            console.print("[dim]Querying NVD API for known vulnerabilities...[/dim]\n")
            
            matcher = CVEMatcher(timeout=30.0)
            
            for service_info in services_to_check:
                product = service_info["product"]
                version = service_info.get("version")
                host = service_info["host"]
                port = service_info["port"]
                
                console.print(f"  Checking {product}" + (f" v{version}" if version else "") + f" ({host}:{port})...")
                
                try:
                    result = matcher.lookup_by_product_sync(product, version)
                    key = f"{host}:{port}:{product}"
                    cve_results[key] = result
                    
                    if result.error:
                        console.print(f"    [yellow]Could not check: {result.error}[/yellow]")
                    elif result.total_found == 0:
                        console.print(f"    [green]No known CVEs found[/green]")
                    else:
                        # Display results by severity
                        if result.critical_count > 0:
                            console.print(f"    [red]CRITICAL: {result.critical_count} vulnerabilities[/red]")
                        if result.high_count > 0:
                            console.print(f"    [red]HIGH: {result.high_count} vulnerabilities[/red]")
                        if result.medium_count > 0:
                            console.print(f"    [yellow]MEDIUM: {result.medium_count} vulnerabilities[/yellow]")
                        if result.low_count > 0:
                            console.print(f"    [dim]LOW: {result.low_count} vulnerabilities[/dim]")
                        
                        # Show top 3 critical/high CVEs
                        top_cves = [c for c in result.cves if c.severity in [CVESeverity.CRITICAL, CVESeverity.HIGH]][:3]
                        for cve in top_cves:
                            score = cve.highest_cvss_score
                            score_str = f" (CVSS: {score:.1f})" if score else ""
                            exploit_str = " [EXPLOIT]" if cve.exploit_available else ""
                            console.print(f"      - {cve.cve_id}{score_str}{exploit_str}")
                            if len(cve.description) > 100:
                                console.print(f"        {cve.description[:100]}...")
                        
                        if len(result.cves) > 3:
                            console.print(f"      ... and {len(result.cves) - 3} more")
                
                except Exception as e:
                    console.print(f"    [red]Error: {e}[/red]")
            
            # Save CVE cache
            matcher.save_cache()
        else:
            console.print("\n[yellow]No services detected to check for CVEs[/yellow]")
            console.print("[dim]Try enabling service detection with --service-detection[/dim]")
    
    # Save outputs
    if json_output:
        generate_json_report(results, json_output, summary)
        console.print(f"\n[green]✓[/green] JSON report saved to: {json_output}")
    
    if csv_output:
        generate_csv_report(results, csv_output)
        console.print(f"[green]✓[/green] CSV report saved to: {csv_output}")
    
    if xml_output:
        generate_xml_report(results, xml_output, summary)
        console.print(f"[green]✓[/green] XML report saved to: {xml_output}")
    
    if html_output:
        generate_html_report(results, html_output, summary, scanner.host_info)
        console.print(f"[green]✓[/green] HTML report saved to: {html_output}")

    if markdown_output:
        from spectrescan.reports import generate_markdown_report
        generate_markdown_report(
            results, 
            markdown_output, 
            summary, 
            scanner.host_info,
            include_toc=True,
            include_mermaid=True,
            include_banners=True
        )
        console.print(f"[green]✓[/green] Markdown report saved to: {markdown_output}")
    
    if pdf_output:
        try:
            from spectrescan.reports import generate_pdf_report
            generate_pdf_report(results, pdf_output, summary, scanner.host_info, include_charts=True)
            console.print(f"[green]✓[/green] PDF report saved to: {pdf_output}")
        except ImportError as e:
            console.print(f"[red]Error:[/red] {str(e)}")
            console.print("Install reportlab: [cyan]pip install reportlab[/cyan]")
    
    if executive_summary:
        from spectrescan.reports import generate_executive_summary
        generate_executive_summary(results, summary, scanner.host_info, executive_summary)
        console.print(f"[green]✓[/green] Executive summary saved to: {executive_summary}")
    
    if ssl_output and ssl_results:
        import json
        ssl_data = {host: result.to_dict() for host, result in ssl_results.items()}
        with open(ssl_output, 'w') as f:
            json.dump(ssl_data, f, indent=2, default=str)
        console.print(f"[green]✓[/green] SSL/TLS analysis saved to: {ssl_output}")
    
    if cve_output and cve_results:
        import json
        from spectrescan.core.cve_matcher import cve_result_to_dict
        cve_data = {key: cve_result_to_dict(result) for key, result in cve_results.items()}
        with open(cve_output, 'w') as f:
            json.dump(cve_data, f, indent=2, default=str)
        console.print(f"[green]✓[/green] CVE check results saved to: {cve_output}")


@app.command(name="presets")
def list_scan_presets():
    """List available scan presets."""
    print_logo()
    console.print(list_presets())


@app.command(name="ssl")
def ssl_analyze(
    target: str = typer.Argument(..., help="Target hostname or IP address"),
    port: int = typer.Option(443, "-p", "--port", help="Target port (default: 443)"),
    timeout: float = typer.Option(5.0, "--timeout", help="Connection timeout in seconds"),
    json_output: Optional[Path] = typer.Option(None, "--json", help="Save JSON output"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    """
    Perform SSL/TLS analysis on a target.
    
    Examples:
    
      spectrescan ssl example.com
      
      spectrescan ssl 192.168.1.1 -p 8443
      
      spectrescan ssl example.com --json ssl_report.json
    """
    from spectrescan.core.ssl_analyzer import SSLAnalyzer, VulnerabilityStatus
    
    print_logo()
    console.print(f"\n[bold]SSL/TLS Analysis: {target}:{port}[/bold]\n")
    
    analyzer = SSLAnalyzer(timeout=timeout)
    result = analyzer.analyze(target, port)
    
    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        return
    
    # Certificate Information
    console.print("[bold cyan]Certificate Information:[/bold cyan]")
    if result.certificate:
        cert = result.certificate
        console.print(f"  Subject: {cert.subject.get('commonName', 'N/A')}")
        console.print(f"  Issuer: {cert.issuer.get('organizationName', 'N/A')}")
        console.print(f"  Serial: {cert.serial_number[:20]}..." if len(cert.serial_number) > 20 else f"  Serial: {cert.serial_number}")
        
        if cert.not_before:
            console.print(f"  Valid From: {cert.not_before.strftime('%Y-%m-%d %H:%M:%S')}")
        if cert.not_after:
            console.print(f"  Valid Until: {cert.not_after.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if cert.is_expired:
            console.print(f"  [red]Status: EXPIRED[/red]")
        elif cert.days_until_expiry < 30:
            console.print(f"  [yellow]Status: Expires in {cert.days_until_expiry} days[/yellow]")
        else:
            console.print(f"  [green]Status: Valid ({cert.days_until_expiry} days remaining)[/green]")
        
        if cert.is_self_signed:
            console.print(f"  [yellow]Self-Signed: Yes[/yellow]")
        
        if verbose and cert.san:
            console.print(f"  SANs: {', '.join(cert.san[:5])}" + ("..." if len(cert.san) > 5 else ""))
        
        console.print(f"  Fingerprint (SHA256): {cert.fingerprint_sha256[:32]}...")
    else:
        console.print("  [yellow]No certificate available[/yellow]")
    
    # Protocol Support
    console.print(f"\n[bold cyan]Protocol Support:[/bold cyan]")
    if result.supported_protocols:
        for protocol in result.supported_protocols:
            if protocol.value in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
                console.print(f"  [red]{protocol.value}[/red] (deprecated)")
            else:
                console.print(f"  [green]{protocol.value}[/green]")
    else:
        console.print("  [yellow]Could not determine supported protocols[/yellow]")
    
    # Cipher Suites
    console.print(f"\n[bold cyan]Cipher Suites:[/bold cyan]")
    if result.cipher_suites:
        for cipher in result.cipher_suites[:10 if not verbose else None]:
            strength_color = {
                "Strong": "green",
                "Acceptable": "cyan",
                "Weak": "yellow",
                "Insecure": "red",
            }.get(cipher.strength.value, "white")
            fs = " (FS)" if cipher.is_forward_secrecy else ""
            console.print(f"  [{strength_color}]{cipher.name}[/{strength_color}] - {cipher.bits}-bit{fs}")
        if not verbose and len(result.cipher_suites) > 10:
            console.print(f"  ... and {len(result.cipher_suites) - 10} more")
    else:
        console.print("  [yellow]Could not enumerate ciphers[/yellow]")
    
    # Security Headers
    console.print(f"\n[bold cyan]Security Features:[/bold cyan]")
    if result.hsts_enabled:
        console.print(f"  [green]HSTS: Enabled[/green] (max-age: {result.hsts_max_age})")
    else:
        console.print(f"  [yellow]HSTS: Not enabled[/yellow]")
    
    if result.ocsp_stapling:
        console.print(f"  [green]OCSP Stapling: Enabled[/green]")
    else:
        console.print(f"  [yellow]OCSP Stapling: Not detected[/yellow]")
    
    # Vulnerabilities
    console.print(f"\n[bold cyan]Vulnerability Assessment:[/bold cyan]")
    vulnerable = [v for v in result.vulnerabilities if v.status == VulnerabilityStatus.VULNERABLE]
    not_vulnerable = [v for v in result.vulnerabilities if v.status == VulnerabilityStatus.NOT_VULNERABLE]
    
    if vulnerable:
        console.print(f"  [red]Found {len(vulnerable)} vulnerabilities:[/red]")
        for vuln in vulnerable:
            cve = f" ({vuln.cve})" if vuln.cve else ""
            console.print(f"    - {vuln.name}{cve}: {vuln.severity}")
            if verbose:
                console.print(f"      {vuln.description}")
                console.print(f"      Recommendation: {vuln.recommendation}")
    else:
        console.print(f"  [green]No critical vulnerabilities detected[/green]")
    
    if verbose and not_vulnerable:
        console.print(f"\n  [green]Passed checks:[/green]")
        for vuln in not_vulnerable:
            console.print(f"    - {vuln.name}")
    
    # Risk Score
    risk = result.get_risk_score()
    console.print(f"\n[bold cyan]Overall Risk Score:[/bold cyan]")
    if risk >= 75:
        console.print(f"  [red bold]{risk}/100 - CRITICAL[/red bold]")
        console.print("  [red]Immediate action required![/red]")
    elif risk >= 50:
        console.print(f"  [yellow bold]{risk}/100 - HIGH[/yellow bold]")
        console.print("  [yellow]Significant security issues detected[/yellow]")
    elif risk >= 25:
        console.print(f"  [yellow]{risk}/100 - MEDIUM[/yellow]")
        console.print("  [yellow]Some improvements recommended[/yellow]")
    else:
        console.print(f"  [green bold]{risk}/100 - LOW[/green bold]")
        console.print("  [green]Good security posture[/green]")
    
    # Save output
    if json_output:
        import json
        with open(json_output, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        console.print(f"\n[green]✓[/green] SSL analysis saved to: {json_output}")


@app.command(name="cve")
def cve_lookup(
    query: str = typer.Argument(..., help="Product name, CPE string, or CVE ID to lookup"),
    version: Optional[str] = typer.Option(None, "-v", "--version", help="Product version"),
    vendor: Optional[str] = typer.Option(None, "--vendor", help="Vendor name"),
    severity: Optional[str] = typer.Option(None, "-s", "--severity", help="Minimum severity filter (critical, high, medium, low)"),
    max_results: int = typer.Option(20, "--max", help="Maximum number of results"),
    json_output: Optional[Path] = typer.Option(None, "--json", help="Save JSON output"),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose output with full descriptions"),
):
    """
    Look up CVE vulnerabilities for a product or CVE ID.
    
    Uses the NVD (National Vulnerability Database) API to fetch real-time
    vulnerability information.
    
    Examples:
    
      spectrescan cve nginx
      
      spectrescan cve openssh -v 8.2
      
      spectrescan cve CVE-2021-44228
      
      spectrescan cve apache --vendor apache -s critical
      
      spectrescan cve "cpe:2.3:a:nginx:nginx:1.19.0:*:*:*:*:*:*:*"
    """
    from spectrescan.core.cve_matcher import (
        CVEMatcher, CVESeverity, format_cve_report, cve_result_to_dict
    )
    import re
    
    print_logo()
    console.print(f"\n[bold]CVE Vulnerability Lookup[/bold]\n")
    
    # Parse severity filter
    severity_filter = None
    if severity:
        severity_map = {
            "critical": CVESeverity.CRITICAL,
            "high": CVESeverity.HIGH,
            "medium": CVESeverity.MEDIUM,
            "low": CVESeverity.LOW
        }
        severity_filter = severity_map.get(severity.lower())
        if not severity_filter:
            console.print(f"[red]Error:[/red] Invalid severity '{severity}'")
            console.print("Valid options: critical, high, medium, low")
            return
    
    matcher = CVEMatcher(timeout=30.0)
    
    # Determine query type
    if re.match(r"^CVE-\d{4}-\d{4,}$", query.upper()):
        # CVE ID lookup
        console.print(f"Looking up [cyan]{query.upper()}[/cyan]...\n")
        
        cve = matcher.lookup_cve_id_sync(query)
        
        if not cve:
            console.print(f"[yellow]CVE not found: {query}[/yellow]")
            return
        
        # Display CVE details
        console.print(f"[bold cyan]{cve.cve_id}[/bold cyan]")
        
        severity_colors = {
            CVESeverity.CRITICAL: "red bold",
            CVESeverity.HIGH: "red",
            CVESeverity.MEDIUM: "yellow",
            CVESeverity.LOW: "dim",
        }
        color = severity_colors.get(cve.severity, "white")
        
        score = cve.highest_cvss_score
        score_str = f" (CVSS: {score:.1f})" if score else ""
        console.print(f"Severity: [{color}]{cve.severity.value.upper()}{score_str}[/{color}]")
        
        if cve.published_date:
            console.print(f"Published: {cve.published_date.strftime('%Y-%m-%d')}")
        
        if cve.exploit_available:
            console.print("[red]** EXPLOIT AVAILABLE **[/red]")
        
        if cve.patch_available:
            console.print("[green]Patch Available[/green]")
        
        console.print(f"\n[bold]Description:[/bold]")
        console.print(f"  {cve.description}")
        
        if cve.cwe_ids:
            console.print(f"\n[bold]CWE:[/bold] {', '.join(cve.cwe_ids)}")
        
        if cve.primary_cvss:
            cvss = cve.primary_cvss
            console.print(f"\n[bold]CVSS {cvss.version.value}:[/bold]")
            console.print(f"  Base Score: {cvss.base_score}")
            if cvss.vector_string:
                console.print(f"  Vector: {cvss.vector_string}")
        
        if verbose and cve.references:
            console.print(f"\n[bold]References:[/bold]")
            for ref in cve.references[:10]:
                tags = f" [{', '.join(ref.tags)}]" if ref.tags else ""
                console.print(f"  - {ref.url}{tags}")
        
        if json_output:
            import json
            cve_data = {
                "cve_id": cve.cve_id,
                "description": cve.description,
                "severity": cve.severity.value,
                "cvss_score": cve.highest_cvss_score,
                "published": cve.published_date.isoformat() if cve.published_date else None,
                "exploit_available": cve.exploit_available,
                "patch_available": cve.patch_available,
                "cwe_ids": cve.cwe_ids,
                "references": [{"url": r.url, "tags": r.tags} for r in cve.references]
            }
            with open(json_output, 'w') as f:
                json.dump(cve_data, f, indent=2)
            console.print(f"\n[green]✓[/green] CVE details saved to: {json_output}")
    
    elif query.startswith("cpe:"):
        # CPE lookup
        console.print(f"Looking up CVEs for CPE: [cyan]{query}[/cyan]...\n")
        
        result = matcher.lookup_by_cpe_sync(query, severity_filter, max_results)
        
        if result.error:
            console.print(f"[red]Error:[/red] {result.error}")
            return
        
        # Display results
        report = format_cve_report(result, verbose=verbose)
        console.print(report)
        
        if json_output:
            import json
            with open(json_output, 'w') as f:
                json.dump(cve_result_to_dict(result), f, indent=2)
            console.print(f"\n[green]✓[/green] CVE results saved to: {json_output}")
    
    else:
        # Product name lookup
        display_name = query + (f" v{version}" if version else "")
        console.print(f"Looking up CVEs for [cyan]{display_name}[/cyan]...\n")
        
        result = matcher.lookup_by_product_sync(
            product=query,
            version=version,
            vendor=vendor,
            severity_filter=severity_filter,
            max_results=max_results
        )
        
        if result.error:
            console.print(f"[red]Error:[/red] {result.error}")
            return
        
        # Display results
        report = format_cve_report(result, verbose=verbose)
        console.print(report)
        
        if json_output:
            import json
            with open(json_output, 'w') as f:
                json.dump(cve_result_to_dict(result), f, indent=2)
            console.print(f"\n[green]✓[/green] CVE results saved to: {json_output}")
    
    # Save cache
    matcher.save_cache()


@app.command(name="dns")
def dns_enumerate(
    target: str = typer.Argument(..., help="Target domain to enumerate"),
    
    # Record types
    record_types: Optional[str] = typer.Option(
        None, "-t", "--types",
        help="DNS record types to query (comma-separated: A,AAAA,MX,TXT,NS,SOA,CNAME,SRV,CAA)"
    ),
    
    # Subdomain enumeration
    subdomains: bool = typer.Option(False, "-s", "--subdomains", help="Enable subdomain enumeration"),
    wordlist: Optional[Path] = typer.Option(
        None, "-w", "--wordlist",
        help="Custom wordlist for subdomain enumeration"
    ),
    wordlist_size: str = typer.Option(
        "medium", "--wordlist-size",
        help="Built-in wordlist size: small (~100), medium (~500)"
    ),
    
    # Zone transfer
    zone_transfer: bool = typer.Option(False, "-z", "--zone-transfer", help="Attempt DNS zone transfers"),
    
    # Reverse lookup
    reverse: bool = typer.Option(False, "-r", "--reverse", help="Perform reverse DNS lookups on discovered IPs"),
    
    # Options
    timeout: float = typer.Option(5.0, "--timeout", help="DNS query timeout in seconds"),
    threads: int = typer.Option(50, "--threads", help="Number of threads for subdomain enumeration"),
    nameservers: Optional[str] = typer.Option(
        None, "-n", "--nameservers",
        help="Custom nameservers to use (comma-separated)"
    ),
    
    # Output
    json_output: Optional[Path] = typer.Option(None, "--json", help="Save JSON output"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Verbose output"),
):
    """
    Perform DNS enumeration on a target domain.
    
    Features:
    - Forward DNS lookups (A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, CAA)
    - Reverse DNS lookups (PTR records)
    - Subdomain enumeration with wordlists
    - DNS zone transfer attempts (AXFR)
    - Wildcard DNS detection
    
    Examples:
    
      # Basic DNS lookup
      spectrescan dns example.com
      
      # Subdomain enumeration
      spectrescan dns example.com --subdomains
      
      # With custom wordlist
      spectrescan dns example.com -s -w /path/to/wordlist.txt
      
      # Zone transfer attempt
      spectrescan dns example.com --zone-transfer
      
      # Full enumeration with all options
      spectrescan dns example.com -s -z -r --json dns_report.json
      
      # Specific record types only
      spectrescan dns example.com -t MX,TXT,NS
    """
    try:
        from spectrescan.core.dns_enum import (
            DNSEnumerator, DNSRecordType, format_dns_report
        )
    except ImportError:
        console.print(
            "[red]Error:[/red] dnspython is required for DNS enumeration.\n"
            "Install with: [yellow]pip install dnspython[/yellow]"
        )
        sys.exit(1)
    
    print_logo()
    console.print(f"\n[bold]DNS Enumeration: {target}[/bold]\n")
    
    # Parse nameservers
    ns_list = None
    if nameservers:
        ns_list = [ns.strip() for ns in nameservers.split(",")]
    
    # Parse record types
    rtypes = None
    if record_types:
        rtypes = []
        for rt in record_types.upper().split(","):
            rt = rt.strip()
            try:
                rtypes.append(DNSRecordType(rt))
            except ValueError:
                console.print(f"[yellow]Warning:[/yellow] Unknown record type '{rt}', skipping")
    
    # Determine wordlist path
    wordlist_path = wordlist
    if subdomains and not wordlist:
        from pathlib import Path
        data_dir = Path(__file__).parent.parent / "data"
        built_in = data_dir / f"subdomains-{wordlist_size}.txt"
        if built_in.exists():
            wordlist_path = built_in
    
    # Create enumerator
    enumerator = DNSEnumerator(
        timeout=timeout,
        threads=threads,
        nameservers=ns_list,
    )
    
    # Progress callback
    def progress_callback(event_type: str, data):
        if event_type == "status":
            console.print(f"[cyan]>[/cyan] {data}")
        elif event_type == "records" and verbose:
            console.print(f"  Found {data['count']} {data['type']} records")
        elif event_type == "subdomain":
            ips = ", ".join(data['ip_addresses']) if data['ip_addresses'] else "N/A"
            console.print(f"[green]✓[/green] {data['full_domain']} -> {ips}")
        elif event_type == "zone_transfer":
            if data['success']:
                console.print(f"[green]✓[/green] Zone transfer SUCCESS from {data['nameserver']} ({len(data['records'])} records)")
            elif verbose:
                console.print(f"[yellow]![/yellow] Zone transfer failed from {data['nameserver']}: {data['error_message']}")
        elif event_type == "wildcard":
            if data['detected']:
                console.print(f"[yellow]![/yellow] Wildcard DNS detected! IPs: {', '.join(data['ips'])}")
        elif event_type == "wordlist":
            console.print(f"  Loaded {data['count']} subdomain words")
        elif event_type == "progress" and verbose:
            console.print(f"  Progress: {data['completed']}/{data['total']} (found: {data['found']})")
    
    # Run enumeration
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Enumerating...", total=None)
        
        result = enumerator.enumerate(
            domain=target,
            record_types=rtypes,
            subdomains=subdomains,
            wordlist=wordlist_path,
            zone_transfer=zone_transfer,
            reverse_lookup=reverse,
            callback=progress_callback if verbose else None,
        )
    
    # Display summary
    console.print("\n" + "=" * 70)
    console.print("[bold cyan]DNS ENUMERATION SUMMARY[/bold cyan]")
    console.print("=" * 70)
    
    console.print(f"\n[bold]Domain:[/bold] {result.domain}")
    console.print(f"[bold]Duration:[/bold] {result.duration:.2f} seconds")
    console.print(f"[bold]Total Records:[/bold] {result.total_records}")
    console.print(f"[bold]Subdomains Found:[/bold] {len(result.subdomains)}")
    console.print(f"[bold]Unique IPs:[/bold] {len(result.unique_ips)}")
    console.print(f"[bold]Wildcard DNS:[/bold] {'Yes' if result.has_wildcard else 'No'}")
    
    # DNS Records table
    if result.records:
        console.print("\n[bold]DNS Records:[/bold]")
        records_table = Table(show_header=True, header_style="bold magenta")
        records_table.add_column("Type")
        records_table.add_column("Name")
        records_table.add_column("Value")
        records_table.add_column("TTL")
        
        for rtype, records in sorted(result.records.items()):
            for record in records:
                priority_prefix = f"{record.priority} " if record.priority is not None else ""
                records_table.add_row(
                    rtype,
                    record.name,
                    f"{priority_prefix}{record.value}",
                    str(record.ttl)
                )
        
        console.print(records_table)
    
    # Nameservers
    if result.nameservers:
        console.print(f"\n[bold]Nameservers:[/bold]")
        for ns in result.nameservers:
            console.print(f"  - {ns}")
    
    # Mail servers
    if result.mail_servers:
        console.print(f"\n[bold]Mail Servers:[/bold]")
        for mx in result.mail_servers:
            console.print(f"  - {mx}")
    
    # Zone transfers
    if result.zone_transfers:
        console.print(f"\n[bold]Zone Transfer Attempts:[/bold]")
        for zt in result.zone_transfers:
            status = "[green]SUCCESS[/green]" if zt.success else "[red]FAILED[/red]"
            console.print(f"  {zt.nameserver}: {status}")
            if zt.success:
                console.print(f"    Records obtained: {len(zt.records)}")
            elif verbose and zt.error_message:
                console.print(f"    [dim]{zt.error_message}[/dim]")
    
    # Subdomains
    if result.subdomains:
        console.print(f"\n[bold]Discovered Subdomains ({len(result.subdomains)}):[/bold]")
        subdomain_table = Table(show_header=True, header_style="bold magenta")
        subdomain_table.add_column("Subdomain")
        subdomain_table.add_column("IP Addresses")
        subdomain_table.add_column("CNAME")
        
        for sub in sorted(result.subdomains, key=lambda x: x.subdomain)[:50]:  # Limit to 50
            ips = ", ".join(sub.ip_addresses) if sub.ip_addresses else "-"
            cname = sub.cname or "-"
            subdomain_table.add_row(sub.full_domain, ips, cname)
        
        console.print(subdomain_table)
        
        if len(result.subdomains) > 50:
            console.print(f"[dim]... and {len(result.subdomains) - 50} more (see JSON output for full list)[/dim]")
    
    # Unique IPs
    if result.unique_ips and verbose:
        console.print(f"\n[bold]Unique IP Addresses ({len(result.unique_ips)}):[/bold]")
        for ip in sorted(result.unique_ips):
            console.print(f"  - {ip}")
    
    # Errors
    if result.errors:
        console.print(f"\n[yellow]Errors:[/yellow]")
        for error in result.errors:
            console.print(f"  [red]-[/red] {error}")
    
    # Save output
    if json_output:
        import json
        with open(json_output, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        console.print(f"\n[green]✓[/green] DNS enumeration saved to: {json_output}")
    
    console.print("\n" + "=" * 70)


@app.command(name="version")
def show_version():
    """Show version information."""
    from spectrescan import __version__
    console.print(f"[bold cyan]SpectreScan[/bold cyan] version [yellow]{__version__}[/yellow]")
    console.print("by [bold]BitSpectreLabs[/bold]")


@app.command(name="gui")
def launch_gui():
    """Launch graphical user interface."""
    from spectrescan.gui.app import run_gui
    print_logo()
    console.print("\n[bold cyan]Launching GUI...[/bold cyan]\n")
    run_gui()


@app.command(name="tui")
def launch_tui(
    target: Optional[str] = typer.Argument(None, help="Pre-fill target"),
    ports: Optional[str] = typer.Option(None, "-p", "--ports", help="Pre-fill port specification"),
):
    """Launch terminal user interface."""
    from spectrescan.tui.app import run_tui
    run_tui(target, ports)


@app.command(name="script")
def script_command(
    action: str = typer.Argument(..., help="Action: list, info, run, categories"),
    script_name: Optional[str] = typer.Argument(None, help="Script name (for info/run)"),
    target: Optional[str] = typer.Option(None, "-t", "--target", help="Target host for script execution"),
    port: Optional[int] = typer.Option(None, "-p", "--port", help="Target port for script execution"),
    script_args: Optional[str] = typer.Option(None, "--script-args", help="Script arguments (key=value,...)"),
    category: Optional[str] = typer.Option(None, "-c", "--category", help="Filter by category (for list)"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose output"),
):
    """
    Manage and run NSE (Nmap Script Engine) compatible scripts.
    
    SpectreScan supports executing Lua-based NSE scripts for advanced
    service detection, vulnerability scanning, and security assessment.
    
    Examples:
    
      # List all available scripts
      spectrescan script list
      
      # List scripts by category
      spectrescan script list --category discovery
      
      # Show script information
      spectrescan script info http-title
      
      # Run a script against a target
      spectrescan script run http-title --target 192.168.1.1 --port 80
      
      # Run with script arguments
      spectrescan script run http-methods --target example.com --port 443 --script-args "http.useragent=Mozilla/5.0"
      
      # Show available categories
      spectrescan script categories
    
    Note: Lua script execution requires the 'lupa' package:
      pip install lupa
    """
    import asyncio
    
    if action == "list":
        # List available scripts
        _script_list(category, verbose)
    
    elif action == "categories":
        # Show available categories
        _script_categories()
    
    elif action == "info":
        # Show script information
        if not script_name:
            console.print("[red]Error:[/red] Script name required for 'info' action")
            sys.exit(1)
        _script_info(script_name, verbose)
    
    elif action == "run":
        # Run a script
        if not script_name:
            console.print("[red]Error:[/red] Script name required for 'run' action")
            sys.exit(1)
        if not target:
            console.print("[red]Error:[/red] Target required for 'run' action (use --target)")
            sys.exit(1)
        
        # Parse script args
        args = {}
        if script_args:
            from spectrescan.core.nse_engine import parse_script_args
            args = parse_script_args(script_args)
        
        asyncio.run(_script_run(script_name, target, port, args, verbose))
    
    else:
        console.print(f"[red]Error:[/red] Unknown action '{action}'")
        console.print("Valid actions: list, info, run, categories")
        sys.exit(1)


def _script_list(category: Optional[str] = None, verbose: bool = False):
    """List available NSE scripts."""
    try:
        from spectrescan.core.nse_engine import NSEEngine, NSECategory
        
        engine = NSEEngine()
        engine.load_scripts()  # Load all scripts from directory
        scripts = [engine.get_script(name) for name in engine.list_scripts()]
        
        if not scripts:
            console.print("[yellow]No NSE scripts found.[/yellow]")
            console.print(f"Scripts are loaded from: {engine.scripts_dir}")
            return
        
        # Filter by category if specified
        if category:
            try:
                cat_enum = NSECategory(category.lower())
                scripts = [s for s in scripts if cat_enum in s.categories]
            except ValueError:
                console.print(f"[red]Error:[/red] Unknown category '{category}'")
                console.print(f"Valid categories: {', '.join(c.value for c in NSECategory)}")
                sys.exit(1)
        
        # Create table
        table = Table(title="Available NSE Scripts", box=None)
        table.add_column("Script", style="cyan")
        table.add_column("Categories", style="yellow")
        if verbose:
            table.add_column("Description", style="white")
        
        for script in sorted(scripts, key=lambda s: s.name):
            cats = ", ".join(c.value for c in script.categories[:3])
            if len(script.categories) > 3:
                cats += f" (+{len(script.categories) - 3})"
            
            if verbose:
                desc = script.description[:60] + "..." if len(script.description) > 60 else script.description
                table.add_row(script.name, cats, desc)
            else:
                table.add_row(script.name, cats)
        
        console.print(table)
        console.print(f"\n[green]Total:[/green] {len(scripts)} scripts")
        
        if not engine.lua_available:
            console.print("\n[yellow]Note:[/yellow] Lua runtime not available. Install with: pip install lupa")
    
    except Exception as e:
        console.print(f"[red]Error listing scripts:[/red] {e}")
        sys.exit(1)


def _script_categories():
    """Show available script categories."""
    from spectrescan.core.nse_engine import NSECategory
    
    table = Table(title="NSE Script Categories", box=None)
    table.add_column("Category", style="cyan")
    table.add_column("Description", style="white")
    
    category_descriptions = {
        "auth": "Authentication and credential testing",
        "broadcast": "Broadcast network discovery",
        "brute": "Brute-force password attacks",
        "default": "Default scripts run with -sC",
        "discovery": "Host and service discovery",
        "dos": "Denial of service testing",
        "exploit": "Exploitation scripts",
        "external": "External service queries",
        "fuzzer": "Fuzzing and input testing",
        "intrusive": "Potentially harmful scripts",
        "malware": "Malware detection",
        "safe": "Safe, non-intrusive scripts",
        "version": "Version detection enhancement",
        "vuln": "Vulnerability detection",
    }
    
    for cat in NSECategory:
        desc = category_descriptions.get(cat.value, "")
        table.add_row(cat.value, desc)
    
    console.print(table)


def _script_info(script_name: str, verbose: bool = False):
    """Show information about a specific script."""
    try:
        from spectrescan.core.nse_engine import NSEEngine
        
        engine = NSEEngine()
        engine.load_scripts()  # Load all scripts from directory
        script = engine.get_script(script_name)
        
        if not script:
            console.print(f"[red]Error:[/red] Script '{script_name}' not found")
            console.print("\nUse 'spectrescan script list' to see available scripts")
            sys.exit(1)
        
        # Display script info
        console.print(Panel(f"[bold cyan]{script.name}[/bold cyan]", title="NSE Script"))
        
        console.print(f"\n[bold]Description:[/bold]")
        console.print(f"  {script.description}")
        
        console.print(f"\n[bold]Categories:[/bold]")
        console.print(f"  {', '.join(c.value for c in script.categories)}")
        
        if script.author:
            console.print(f"\n[bold]Author:[/bold]")
            console.print(f"  {script.author}")
        
        if script.license:
            console.print(f"\n[bold]License:[/bold]")
            console.print(f"  {script.license}")
        
        if script.dependencies:
            console.print(f"\n[bold]Dependencies:[/bold]")
            for dep in script.dependencies:
                console.print(f"  - {dep}")
        
        console.print(f"\n[bold]Path:[/bold]")
        console.print(f"  {script.path}")
        
        if not engine.lua_available:
            console.print("\n[yellow]Note:[/yellow] Lua runtime not available. Install with: pip install lupa")
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


async def _script_run(script_name: str, target: str, port: Optional[int], 
                      args: dict, verbose: bool = False):
    """Run an NSE script against a target."""
    try:
        from spectrescan.core.nse_engine import NSEEngine, NSEHostInfo, NSEPortInfo, format_nse_results
        
        engine = NSEEngine()
        engine.load_scripts()  # Load all scripts from directory
        
        if not engine.lua_available:
            console.print("[red]Error:[/red] Lua runtime not available")
            console.print("Install with: [cyan]pip install lupa[/cyan]")
            sys.exit(1)
        
        # Get script info first
        script = engine.get_script(script_name)
        if not script:
            console.print(f"[red]Error:[/red] Script '{script_name}' not found")
            sys.exit(1)
        
        console.print(f"[cyan]Running script:[/cyan] {script_name}")
        console.print(f"[cyan]Target:[/cyan] {target}" + (f":{port}" if port else ""))
        
        if args:
            console.print(f"[cyan]Arguments:[/cyan] {args}")
        
        console.print()
        
        # Create host/port info
        host = NSEHostInfo(ip=target)
        port_info = NSEPortInfo(number=port or 0, protocol="tcp", state="open") if port else None
        
        # Run the script
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Executing script...", total=None)
            result = await engine.run_script(script_name, host, port_info, args)
            progress.update(task, completed=True)
        
        # Display results
        if result.success:
            console.print("[green]Script completed successfully[/green]\n")
            
            if result.output:
                console.print("[bold]Output:[/bold]")
                # Format output nicely - pass as list, not dict
                formatted = format_nse_results([result])
                console.print(formatted)
            else:
                console.print("[yellow]No output returned[/yellow]")
        else:
            console.print(f"[red]Script failed:[/red] {result.error}")
            sys.exit(1)
        
        if verbose and result.execution_time:
            console.print(f"\n[dim]Execution time: {result.execution_time:.2f}s[/dim]")
    
    except Exception as e:
        console.print(f"[red]Error running script:[/red] {e}")
        sys.exit(1)


@app.command(name="api")
def api_server(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (development mode)"),
    workers: int = typer.Option(1, "--workers", "-w", help="Number of worker processes"),
    cors_origins: Optional[str] = typer.Option(None, "--cors", help="Comma-separated CORS origins (default: all)"),
    create_key: bool = typer.Option(False, "--create-key", help="Create initial API key and exit"),
    key_name: str = typer.Option("default", "--key-name", help="Name for the initial API key"),
):
    """
    Start the REST API server.
    
    The API server provides HTTP endpoints for scan operations, profile management,
    history access, and WebSocket support for real-time updates.
    
    Examples:
    
      # Start server on default port 8000
      spectrescan api
      
      # Start on custom port
      spectrescan api --port 9000
      
      # Start with auto-reload for development
      spectrescan api --reload
      
      # Create an API key before starting
      spectrescan api --create-key --key-name "my-app"
      
      # Restrict CORS origins
      spectrescan api --cors "http://localhost:3000,https://myapp.com"
    
    API Documentation:
      After starting, visit http://localhost:8000/docs for Swagger UI
      or http://localhost:8000/redoc for ReDoc documentation.
    
    Authentication:
      Use X-API-Key header with an API key, or Authorization: Bearer <token>
      with a JWT token obtained from POST /auth/token.
    """
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]Error:[/red] uvicorn is required for the API server.\n"
            "Install with: [cyan]pip install uvicorn[standard][/cyan]"
        )
        sys.exit(1)
    
    # Check FastAPI availability
    try:
        from spectrescan.api.main import create_app, FASTAPI_AVAILABLE
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI not available")
    except ImportError:
        console.print(
            "[red]Error:[/red] FastAPI is required for the API server.\n"
            "Install with: [cyan]pip install fastapi uvicorn[standard][/cyan]"
        )
        sys.exit(1)
    
    # Create initial API key if requested
    if create_key:
        from spectrescan.api.auth import APIKeyAuth
        
        auth = APIKeyAuth()
        api_key, key_obj = auth.create_key(
            name=key_name,
            scopes=["*"],  # Full access for initial key
        )
        
        console.print("\n[bold green]API Key Created Successfully[/bold green]\n")
        console.print(f"[yellow]Key ID:[/yellow] {key_obj.key_id}")
        console.print(f"[yellow]Name:[/yellow] {key_obj.name}")
        console.print(f"[yellow]Scopes:[/yellow] {', '.join(key_obj.scopes)}")
        console.print(f"\n[bold cyan]API Key (save this - shown only once!):[/bold cyan]")
        console.print(f"[bold white]{api_key}[/bold white]\n")
        console.print("[dim]Use this key in the X-API-Key header for API requests.[/dim]")
        return
    
    print_logo()
    
    # Parse CORS origins
    origins = None
    if cors_origins:
        origins = [o.strip() for o in cors_origins.split(",")]
    
    console.print("\n[bold cyan]Starting SpectreScan REST API Server...[/bold cyan]\n")
    console.print(f"[green]Host:[/green] {host}")
    console.print(f"[green]Port:[/green] {port}")
    console.print(f"[green]Workers:[/green] {workers}")
    console.print(f"[green]Auto-reload:[/green] {'Yes' if reload else 'No'}")
    console.print(f"[green]CORS Origins:[/green] {origins if origins else 'All (*)'}")
    console.print(f"\n[cyan]API Documentation:[/cyan] http://{host if host != '0.0.0.0' else 'localhost'}:{port}/docs")
    console.print(f"[cyan]ReDoc:[/cyan] http://{host if host != '0.0.0.0' else 'localhost'}:{port}/redoc")
    console.print(f"[cyan]Health Check:[/cyan] http://{host if host != '0.0.0.0' else 'localhost'}:{port}/health\n")
    
    # Create app with settings
    if origins:
        # Need to pass config to create_app
        app_instance = create_app(cors_origins=origins)
    else:
        app_instance = create_app()
    
    # Run server
    uvicorn.run(
        app_instance,
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,
        access_log=True,
    )


@app.command(name="web")
def web_dashboard(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind to"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind to"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug mode"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Don't open browser automatically"),
):
    """
    Start the Web Dashboard UI server.
    
    The web dashboard provides a modern browser-based interface for SpectreScan
    with real-time scan monitoring, interactive results visualization, and
    network topology graphs.
    
    Features:
      - Real-time scan progress via WebSocket
      - Interactive results filtering and sorting
      - Network topology visualization
      - User authentication with role-based access
      - Dark/light theme support
      - Mobile-responsive design
    
    Examples:
    
      # Start web dashboard on default port 8080
      spectrescan web
      
      # Start on custom port
      spectrescan web --port 9000
      
      # Start without opening browser
      spectrescan web --no-browser
      
      # Enable debug mode
      spectrescan web --debug
    
    Default Login:
      Username: admin
      Password: admin
      (Change this immediately in production!)
    """
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]Error:[/red] uvicorn is required for the web dashboard.\n"
            "Install with: [cyan]pip install uvicorn[standard][/cyan]"
        )
        sys.exit(1)
    
    # Check FastAPI availability
    try:
        from spectrescan.web.app import create_web_app, FASTAPI_AVAILABLE
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI not available")
    except ImportError:
        console.print(
            "[red]Error:[/red] FastAPI is required for the web dashboard.\n"
            "Install with: [cyan]pip install fastapi uvicorn[standard][/cyan]"
        )
        sys.exit(1)
    
    print_logo()
    
    console.print("\n[bold cyan]Starting SpectreScan Web Dashboard...[/bold cyan]\n")
    console.print(f"[green]Host:[/green] {host}")
    console.print(f"[green]Port:[/green] {port}")
    console.print(f"[green]Debug:[/green] {'Yes' if debug else 'No'}")
    
    display_host = "localhost" if host == "0.0.0.0" else host
    dashboard_url = f"http://{display_host}:{port}"
    
    console.print(f"\n[cyan]Dashboard:[/cyan] {dashboard_url}")
    console.print(f"[cyan]Login:[/cyan] {dashboard_url}/login")
    console.print(f"[cyan]Health:[/cyan] {dashboard_url}/health")
    console.print(f"\n[yellow]Default credentials: admin / admin[/yellow]\n")
    
    # Open browser automatically
    if not no_browser:
        import webbrowser
        import threading
        
        def open_browser():
            import time
            time.sleep(1.5)  # Wait for server to start
            webbrowser.open(dashboard_url)
        
        threading.Thread(target=open_browser, daemon=True).start()
    
    # Create and run dashboard
    dashboard = create_web_app(host=host, port=port, debug=debug)
    dashboard.run()


@app.command(name="profile")
def manage_profiles(
    action: str = typer.Argument(..., help="Action: list, save, load, delete, export, import"),
    name: Optional[str] = typer.Argument(None, help="Profile name"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="File path for export/import"),
):
    """
    Manage scan profiles.
    
    Examples:
    
      spectrescan profile list
      
      spectrescan profile load "Quick Scan"
      
      spectrescan profile delete "Old Scan"
      
      spectrescan profile export "My Profile" --file profile.json
      
      spectrescan profile import --file profile.json
    """
    manager = ProfileManager()
    
    if action == "list":
        profiles = manager.list_profiles()
        if not profiles:
            console.print("[yellow]No profiles found[/yellow]")
            return
        
        table = Table(title="Scan Profiles", show_header=True, header_style="bold cyan")
        table.add_column("Profile Name", style="cyan")
        table.add_column("Description", style="white")
        
        for profile_name in profiles:
            try:
                profile = manager.load_profile(profile_name)
                table.add_row(profile_name, profile.description)
            except:
                table.add_row(profile_name, "[red]Error loading profile[/red]")
        
        console.print(table)
    
    elif action == "load":
        if not name:
            console.print("[red]Error:[/red] Profile name required", style="bold")
            sys.exit(1)
        
        try:
            profile = manager.load_profile(name)
            console.print(f"\n[bold cyan]Profile:[/bold cyan] {profile.name}")
            console.print(f"[bold]Description:[/bold] {profile.description}")
            console.print(f"[bold]Ports:[/bold] {len(profile.ports)} ports")
            console.print(f"[bold]Scan Types:[/bold] {', '.join(profile.scan_types)}")
            console.print(f"[bold]Threads:[/bold] {profile.threads}")
            console.print(f"[bold]Timeout:[/bold] {profile.timeout}s")
            console.print(f"[bold]Service Detection:[/bold] {profile.enable_service_detection}")
            console.print(f"[bold]OS Detection:[/bold] {profile.enable_os_detection}")
            console.print(f"[bold]Banner Grabbing:[/bold] {profile.enable_banner_grabbing}")
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Profile '{name}' not found", style="bold")
            sys.exit(1)
    
    elif action == "delete":
        if not name:
            console.print("[red]Error:[/red] Profile name required", style="bold")
            sys.exit(1)
        
        try:
            manager.delete_profile(name)
            console.print(f"[green]✓[/green] Profile '{name}' deleted")
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Profile '{name}' not found", style="bold")
            sys.exit(1)
    
    elif action == "export":
        if not name or not file:
            console.print("[red]Error:[/red] Profile name and --file required", style="bold")
            sys.exit(1)
        
        try:
            manager.export_profile(name, file)
            console.print(f"[green]✓[/green] Profile exported to {file}")
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Profile '{name}' not found", style="bold")
            sys.exit(1)
    
    elif action == "import":
        if not file:
            console.print("[red]Error:[/red] --file required for import", style="bold")
            sys.exit(1)
        
        try:
            profile = manager.import_profile(file)
            console.print(f"[green]✓[/green] Profile '{profile.name}' imported")
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Import file not found", style="bold")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Error:[/red] Failed to import: {e}", style="bold")
            sys.exit(1)
    
    else:
        console.print(f"[red]Error:[/red] Unknown action '{action}'", style="bold")
        console.print("Valid actions: list, load, delete, export, import")
        sys.exit(1)


@app.command(name="history")
def manage_history(
    action: str = typer.Argument(..., help="Action: list, show, delete, clear, search, stats"),
    scan_id: Optional[str] = typer.Argument(None, help="Scan ID or search query"),
    limit: int = typer.Option(10, "--limit", "-n", help="Number of entries to show"),
    target: Optional[str] = typer.Option(None, "--target", help="Filter by target"),
    scan_type: Optional[str] = typer.Option(None, "--scan-type", help="Filter by scan type"),
):
    """
    Manage scan history.
    
    Examples:
    
      spectrescan history list
      
      spectrescan history list --limit 20 --target 192.168.1.1
      
      spectrescan history show abc123def456
      
      spectrescan history search "example.com"
      
      spectrescan history stats
      
      spectrescan history clear
    """
    manager = HistoryManager()
    
    if action == "list":
        entries = manager.list_entries(limit=limit, target_filter=target, scan_type_filter=scan_type)
        
        if not entries:
            console.print("[yellow]No history entries found[/yellow]")
            return
        
        table = Table(title="Scan History", show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Target", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Ports", justify="right")
        table.add_column("Open", justify="right", style="green")
        table.add_column("Duration", justify="right")
        table.add_column("Timestamp", style="dim")
        
        for entry in entries:
            from datetime import datetime
            timestamp = datetime.fromisoformat(entry.timestamp).strftime("%Y-%m-%d %H:%M")
            
            table.add_row(
                entry.id[:12],
                entry.target[:30],
                entry.scan_type,
                str(entry.total_ports),
                str(entry.open_ports),
                f"{entry.duration:.1f}s",
                timestamp
            )
        
        console.print(table)
    
    elif action == "show":
        if not scan_id:
            console.print("[red]Error:[/red] Scan ID required", style="bold")
            sys.exit(1)
        
        entry = manager.get_entry(scan_id)
        if not entry:
            console.print(f"[red]Error:[/red] Scan '{scan_id}' not found", style="bold")
            sys.exit(1)
        
        console.print(f"\n[bold cyan]Scan ID:[/bold cyan] {entry.id}")
        console.print(f"[bold]Target:[/bold] {entry.target}")
        console.print(f"[bold]Scan Type:[/bold] {entry.scan_type}")
        console.print(f"[bold]Timestamp:[/bold] {entry.timestamp}")
        console.print(f"[bold]Duration:[/bold] {entry.duration:.2f}s")
        console.print(f"[bold]Total Ports:[/bold] {entry.total_ports}")
        console.print(f"[bold]Open Ports:[/bold] {entry.open_ports}")
        console.print(f"[bold]Closed Ports:[/bold] {entry.closed_ports}")
        console.print(f"[bold]Filtered Ports:[/bold] {entry.filtered_ports}")
        if entry.results_file:
            console.print(f"[bold]Results File:[/bold] {entry.results_file}")
    
    elif action == "delete":
        if not scan_id:
            console.print("[red]Error:[/red] Scan ID required", style="bold")
            sys.exit(1)
        
        if manager.delete_entry(scan_id):
            console.print(f"[green]✓[/green] Scan '{scan_id}' deleted")
        else:
            console.print(f"[red]Error:[/red] Scan '{scan_id}' not found", style="bold")
            sys.exit(1)
    
    elif action == "clear":
        confirm = typer.confirm("Are you sure you want to clear all history?")
        if confirm:
            manager.clear_history()
            console.print("[green]✓[/green] History cleared")
        else:
            console.print("Cancelled")
    
    elif action == "search":
        if not scan_id:  # Using scan_id parameter as search query
            console.print("[red]Error:[/red] Search query required", style="bold")
            sys.exit(1)
        
        results = manager.search_history(scan_id)
        
        if not results:
            console.print(f"[yellow]No results found for '{scan_id}'[/yellow]")
            return
        
        table = Table(title=f"Search Results: '{scan_id}'", show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan")
        table.add_column("Target", style="white")
        table.add_column("Type", style="yellow")
        table.add_column("Open", justify="right", style="green")
        table.add_column("Timestamp", style="dim")
        
        for entry in results[:limit]:
            from datetime import datetime
            timestamp = datetime.fromisoformat(entry.timestamp).strftime("%Y-%m-%d %H:%M")
            
            table.add_row(
                entry.id[:12],
                entry.target[:30],
                entry.scan_type,
                str(entry.open_ports),
                timestamp
            )
        
        console.print(table)
    
    elif action == "stats":
        stats = manager.get_statistics()
        
        panel_content = f"""[bold]Total Scans:[/bold] {stats['total_scans']}
[bold]Total Ports Scanned:[/bold] {stats['total_ports_scanned']:,}
[bold]Total Open Ports Found:[/bold] {stats['total_open_ports']:,}
[bold]Total Scan Time:[/bold] {stats['total_duration']:.2f}s

[bold]Scan Types:[/bold]
"""
        for scan_type, count in stats['scan_types'].items():
            panel_content += f"  • {scan_type}: {count}\n"
        
        if stats['most_scanned_target']:
            panel_content += f"\n[bold]Most Scanned Target:[/bold] {stats['most_scanned_target']}"
        
        panel = Panel(panel_content, title="[bold cyan]Scan History Statistics[/bold cyan]", border_style="cyan")
        console.print(panel)
    
    else:
        console.print(f"[red]Error:[/red] Unknown action '{action}'", style="bold")
        console.print("Valid actions: list, show, delete, clear, search, stats")
        sys.exit(1)


@app.command(name="compare")
def compare_scans(
    scan1_id: str = typer.Argument(..., help="First scan ID (older scan)"),
    scan2_id: str = typer.Argument(..., help="Second scan ID (newer scan)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Compare recent scans for this target"),
    report_format: str = typer.Option("text", "--format", "-f", help="Report format (text, html, json)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save comparison report to file"),
):
    """
    Compare two scans to identify differences.
    
    Examples:
    
      spectrescan compare abc123def456 def456ghi789
      
      spectrescan compare --target 192.168.1.1
      
      spectrescan compare abc123 def456 --format html --output comparison.html
    """
    comparer = ScanComparer()
    
    try:
        if target:
            # Compare recent scans for target
            comparison = comparer.compare_by_target(target)
            if not comparison:
                console.print(f"[yellow]Not enough scans found for target '{target}'[/yellow]")
                console.print("Need at least 2 scans for the same target.")
                sys.exit(1)
        else:
            # Compare specific scans
            comparison = comparer.compare_scans(scan1_id, scan2_id)
        
        # Save report if requested
        if output:
            from spectrescan.reports import generate_comparison_report
            generate_comparison_report(comparison, output, format=report_format)
            console.print(f"[green]✓[/green] Comparison report saved to: {output}")
        
        # Display comparison (always show text version in terminal)
        report = comparer.format_comparison_text(comparison)
        console.print(report)
        
        # Summary panel
        if comparison.total_changes > 0:
            summary = f"[bold]Total Changes:[/bold] {comparison.total_changes}\n"
            summary += f"[green]Newly Opened:[/green] {len(comparison.newly_opened)}\n"
            summary += f"[red]Newly Closed:[/red] {len(comparison.newly_closed)}\n"
            summary += f"[yellow]Newly Filtered:[/yellow] {len(comparison.newly_filtered)}\n"
            summary += f"[cyan]Service Changes:[/cyan] {len(comparison.service_changed)}\n"
            
            panel = Panel(summary, title="[bold cyan]Comparison Summary[/bold cyan]", border_style="cyan")
            console.print(panel)
        else:
            console.print("[green]✓[/green] No changes detected between scans")
    
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}", style="bold")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] Failed to compare scans: {e}", style="bold")
        sys.exit(1)


@app.command(name="resume")
def resume_scan(
    checkpoint_id: str = typer.Argument(..., help="Checkpoint ID or file path"),
    threads: Optional[int] = typer.Option(None, "--threads", "-t", help="Override thread count"),
    timeout: Optional[float] = typer.Option(None, "--timeout", help="Override timeout"),
    json_output: Optional[Path] = typer.Option(None, "--json", "-j", help="Save results to JSON"),
    html_output: Optional[Path] = typer.Option(None, "--html", help="Save HTML report"),
):
    """
    Resume an interrupted scan from a checkpoint.
    
    Examples:
    
      spectrescan resume abc123def456
      
      spectrescan resume abc123 --threads 200
      
      spectrescan resume checkpoint.json --json results.json
    """
    from spectrescan.core.checkpoint import (
        CheckpointManager, CheckpointState, can_resume_scan, get_resume_summary
    )
    
    manager = CheckpointManager()
    
    try:
        checkpoint = manager.load_checkpoint(checkpoint_id)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Checkpoint '{checkpoint_id}' not found")
        sys.exit(1)
    
    if not can_resume_scan(checkpoint):
        console.print(f"[yellow]Cannot resume scan - state is '{checkpoint.state.value}'[/yellow]")
        console.print("Only running, paused, or interrupted scans can be resumed.")
        sys.exit(1)
    
    # Show resume summary
    summary = get_resume_summary(checkpoint)
    
    console.print("\n[bold cyan]Resuming Scan[/bold cyan]\n")
    console.print(f"[bold]Checkpoint ID:[/bold] {summary['checkpoint_id']}")
    console.print(f"[bold]Scan Type:[/bold] {summary['scan_type']}")
    console.print(f"[bold]Remaining Targets:[/bold] {summary['remaining_targets']} / {summary['total_targets']}")
    console.print(f"[bold]Remaining Ports:[/bold] {summary['remaining_ports']} / {summary['total_ports']}")
    console.print(f"[bold]Results Collected:[/bold] {summary['results_collected']}")
    console.print(f"[bold]Elapsed Time:[/bold] {summary['elapsed_time']:.1f}s")
    console.print("")
    
    # Get remaining work
    remaining_targets = checkpoint.get_remaining_targets()
    if not remaining_targets:
        console.print("[green]Scan already complete - no remaining work[/green]")
        return
    
    # Override settings if provided
    scan_threads = threads or checkpoint.threads
    scan_timeout = timeout or checkpoint.timeout
    
    # Create scanner
    scanner = PortScanner(
        threads=scan_threads,
        timeout=scan_timeout,
        rate_limit=checkpoint.rate_limit,
        randomize=checkpoint.randomize,
    )
    
    # Resume scanning
    checkpoint.state = CheckpointState.RUNNING
    all_results = list(checkpoint.results)  # Include existing results
    
    print_logo()
    console.print(f"\n[bold cyan]Resuming scan of {len(remaining_targets)} target(s)...[/bold cyan]\n")
    
    try:
        for target in remaining_targets:
            remaining_ports = checkpoint.get_remaining_ports(target)
            if not remaining_ports:
                checkpoint.mark_target_complete(target)
                continue
            
            checkpoint.progress.current_target = target
            console.print(f"[cyan]Scanning:[/cyan] {target} ({len(remaining_ports)} ports remaining)")
            
            results = scanner.scan(target, remaining_ports, callback=result_callback)
            
            for result in results:
                result_dict = {
                    "host": result.host,
                    "port": result.port,
                    "state": result.state,
                    "service": result.service,
                    "banner": result.banner,
                    "protocol": result.protocol,
                }
                checkpoint.add_result(result_dict)
                all_results.append(result_dict)
            
            checkpoint.mark_target_complete(target)
            manager.save_checkpoint()
        
        # Mark complete
        manager.mark_complete()
        console.print("\n[green]✓[/green] Scan resumed and completed successfully!")
        
        # Save outputs
        if json_output:
            import json
            with open(json_output, "w") as f:
                json.dump(all_results, f, indent=2)
            console.print(f"[green]✓[/green] Results saved to: {json_output}")
        
        if html_output:
            # Convert dicts to ScanResult objects
            scan_results = [
                ScanResult(
                    host=r["host"],
                    port=r["port"],
                    state=r["state"],
                    service=r.get("service"),
                    banner=r.get("banner"),
                    protocol=r.get("protocol", "tcp"),
                )
                for r in all_results
            ]
            generate_html_report(scan_results, html_output, {})
            console.print(f"[green]✓[/green] HTML report saved to: {html_output}")
    
    except KeyboardInterrupt:
        manager.mark_interrupted()
        console.print("\n[yellow]Scan interrupted - checkpoint saved[/yellow]")
        console.print(f"Resume with: spectrescan resume {checkpoint.checkpoint_id}")
        sys.exit(130)
    except Exception as e:
        manager.mark_failed(str(e))
        console.print(f"\n[red]Scan failed:[/red] {e}")
        console.print(f"Resume with: spectrescan resume {checkpoint.checkpoint_id}")
        sys.exit(1)


@app.command(name="checkpoint")
def manage_checkpoints(
    action: str = typer.Argument(..., help="Action: list, show, delete, cleanup"),
    checkpoint_id: Optional[str] = typer.Argument(None, help="Checkpoint ID"),
    force: bool = typer.Option(False, "--force", "-f", help="Force delete running checkpoints"),
    days: int = typer.Option(7, "--days", "-d", help="Days to keep for cleanup"),
):
    """
    Manage scan checkpoints.
    
    Examples:
    
      spectrescan checkpoint list
      
      spectrescan checkpoint show abc123def456
      
      spectrescan checkpoint delete abc123
      
      spectrescan checkpoint cleanup --days 7
    """
    from spectrescan.core.checkpoint import CheckpointManager, CheckpointState
    
    manager = CheckpointManager()
    
    if action == "list":
        checkpoints = manager.list_checkpoints()
        
        if not checkpoints:
            console.print("[yellow]No checkpoints found[/yellow]")
            return
        
        table = Table(title="Scan Checkpoints", show_header=True, header_style="bold cyan")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("State", style="white")
        table.add_column("Targets", justify="right")
        table.add_column("Ports", justify="right")
        table.add_column("Progress", justify="right")
        table.add_column("Type", style="yellow")
        table.add_column("Updated", style="dim")
        
        for cp in checkpoints:
            # Color state
            state = cp["state"]
            if state == "completed":
                state_str = "[green]completed[/green]"
            elif state == "running":
                state_str = "[cyan]running[/cyan]"
            elif state == "interrupted":
                state_str = "[yellow]interrupted[/yellow]"
            elif state == "failed":
                state_str = "[red]failed[/red]"
            else:
                state_str = state
            
            from datetime import datetime
            updated = datetime.fromisoformat(cp["updated_at"]).strftime("%Y-%m-%d %H:%M") if cp["updated_at"] else ""
            
            table.add_row(
                cp["id"][:12],
                state_str,
                str(cp["target_count"]),
                str(cp["port_count"]),
                f"{cp['progress_percent']:.1f}%",
                cp["scan_type"],
                updated
            )
        
        console.print(table)
    
    elif action == "show":
        if not checkpoint_id:
            console.print("[red]Error:[/red] Checkpoint ID required")
            sys.exit(1)
        
        try:
            cp = manager.load_checkpoint(checkpoint_id)
            from spectrescan.core.checkpoint import get_resume_summary
            summary = get_resume_summary(cp)
            
            console.print(f"\n[bold cyan]Checkpoint Details[/bold cyan]\n")
            console.print(f"[bold]ID:[/bold] {summary['checkpoint_id']}")
            console.print(f"[bold]State:[/bold] {summary['state']}")
            console.print(f"[bold]Scan Type:[/bold] {summary['scan_type']}")
            console.print(f"[bold]Total Targets:[/bold] {summary['total_targets']}")
            console.print(f"[bold]Remaining Targets:[/bold] {summary['remaining_targets']}")
            console.print(f"[bold]Total Ports:[/bold] {summary['total_ports']}")
            console.print(f"[bold]Completed Ports:[/bold] {summary['completed_ports']}")
            console.print(f"[bold]Remaining Ports:[/bold] {summary['remaining_ports']}")
            console.print(f"[bold]Results Collected:[/bold] {summary['results_collected']}")
            console.print(f"[bold]Errors:[/bold] {summary['errors_encountered']}")
            console.print(f"[bold]Elapsed Time:[/bold] {summary['elapsed_time']:.1f}s")
            console.print(f"[bold]Created:[/bold] {summary['created_at']}")
            console.print(f"[bold]Last Update:[/bold] {summary['last_update']}")
            
            if cp.targets:
                console.print(f"\n[bold]Targets:[/bold]")
                for t in cp.targets[:5]:
                    status = "[green]done[/green]" if t in cp.completed_targets else "[cyan]pending[/cyan]"
                    console.print(f"  • {t} {status}")
                if len(cp.targets) > 5:
                    console.print(f"  ... and {len(cp.targets) - 5} more")
        
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Checkpoint '{checkpoint_id}' not found")
            sys.exit(1)
    
    elif action == "delete":
        if not checkpoint_id:
            console.print("[red]Error:[/red] Checkpoint ID required")
            sys.exit(1)
        
        deleted = manager.delete_checkpoint(checkpoint_id, force=force)
        if deleted:
            console.print(f"[green]✓[/green] Checkpoint '{checkpoint_id}' deleted")
        else:
            if not force:
                console.print(f"[yellow]Cannot delete running checkpoint. Use --force to override.[/yellow]")
            else:
                console.print(f"[red]Error:[/red] Checkpoint '{checkpoint_id}' not found")
            sys.exit(1)
    
    elif action == "cleanup":
        deleted = manager.cleanup_completed(keep_days=days)
        console.print(f"[green]✓[/green] Cleaned up {deleted} old checkpoint(s)")
    
    else:
        console.print(f"[red]Error:[/red] Unknown action '{action}'")
        console.print("Valid actions: list, show, delete, cleanup")
        sys.exit(1)


@app.command(name="config")
def manage_config(
    action: str = typer.Argument(..., help="Action: show, init, get, set, validate"),
    key: Optional[str] = typer.Argument(None, help="Config key (e.g., scan.threads)"),
    value: Optional[str] = typer.Argument(None, help="Value to set"),
    section: Optional[str] = typer.Option(None, "--section", "-s", help="Show specific section"),
    file_path: Optional[Path] = typer.Option(None, "--file", "-f", help="Config file path"),
    project: bool = typer.Option(False, "--project", "-p", help="Create/use project-level config"),
):
    """
    Manage SpectreScan configuration.
    
    Configuration priority (highest to lowest):
      1. CLI arguments
      2. Environment variables (SPECTRESCAN_*)
      3. Project config (.spectrescan.toml)
      4. User config (~/.spectrescan/config.toml)
      5. Built-in defaults
    
    Examples:
    
      spectrescan config show
      
      spectrescan config show --section scan
      
      spectrescan config init
      
      spectrescan config get scan.threads
      
      spectrescan config set scan.threads 200
      
      spectrescan config validate
    """
    from spectrescan.core.config import ConfigManager, ConfigError, SpectrescanConfig
    
    manager = ConfigManager()
    
    if action == "show":
        try:
            manager.load()
            output = manager.show_config(section=section)
            
            # Show loaded sources
            sources = manager.get_loaded_sources()
            console.print(f"[dim]Loaded from: {', '.join(sources)}[/dim]\n")
            
            console.print(output)
        except ConfigError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    elif action == "init":
        config_path = file_path
        if not config_path:
            if project:
                config_path = Path.cwd() / ".spectrescan.toml"
            else:
                config_path = manager.user_config_path
        
        try:
            path = manager.init_config(path=config_path)
            console.print(f"[green]✓[/green] Configuration file created: {path}")
            console.print("\nEdit the file to customize your settings.")
        except ConfigError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    elif action == "get":
        if not key:
            console.print("[red]Error:[/red] Key required (e.g., scan.threads)")
            sys.exit(1)
        
        try:
            manager.load()
            value_result = manager.get_value(key)
            console.print(f"{key} = {value_result}")
        except (ConfigError, KeyError) as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    elif action == "set":
        if not key or value is None:
            console.print("[red]Error:[/red] Key and value required")
            sys.exit(1)
        
        try:
            manager.load()
            manager.set_value(key, value)
            manager.save_user_config()
            console.print(f"[green]✓[/green] Set {key} = {value}")
        except (ConfigError, KeyError, ValueError) as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    elif action == "validate":
        try:
            manager.load()
            errors = manager.validate()
            
            if errors:
                console.print("[red]Configuration validation failed:[/red]\n")
                for error in errors:
                    console.print(f"  • {error}")
                sys.exit(1)
            else:
                console.print("[green]✓[/green] Configuration is valid")
                sources = manager.get_loaded_sources()
                console.print(f"[dim]Loaded from: {', '.join(sources)}[/dim]")
        except ConfigError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    else:
        console.print(f"[red]Error:[/red] Unknown action '{action}'")
        console.print("Valid actions: show, init, get, set, validate")
        sys.exit(1)


@app.command(name="completion")
def completion_cmd(
    action: str = typer.Argument(..., help="Action: install, show, bash, zsh, powershell, fish"),
    shell: Optional[str] = typer.Argument(None, help="Shell type (for install/show actions)"),
):
    """
    Shell completion utilities.
    
    Examples:
    
      # Show completion script for bash
      spectrescan completion bash
      
      # Show completion script for your shell
      spectrescan completion show bash
      
      # Install completion for bash
      spectrescan completion install bash
      
      # Install completion for PowerShell
      spectrescan completion install powershell
      
      # Show installation instructions
      spectrescan completion install --help
    """
    from spectrescan.cli.completions import (
        get_completion_script,
        install_completion,
        get_install_instructions,
        SUPPORTED_SHELLS
    )
    
    action = action.lower()
    
    # Direct shell name generates completion script
    if action in SUPPORTED_SHELLS:
        script = get_completion_script(action)
        print(script)
        return
    
    if action == "show":
        if not shell:
            console.print("[red]Error:[/red] Please specify a shell type")
            console.print(f"Supported shells: {', '.join(SUPPORTED_SHELLS)}")
            sys.exit(1)
        
        if shell.lower() not in SUPPORTED_SHELLS:
            console.print(f"[red]Error:[/red] Unsupported shell: {shell}")
            console.print(f"Supported shells: {', '.join(SUPPORTED_SHELLS)}")
            sys.exit(1)
        
        script = get_completion_script(shell)
        print(script)
    
    elif action == "install":
        if not shell:
            # Show available shells and instructions
            console.print("[bold cyan]Shell Completion Installation[/bold cyan]\n")
            console.print(f"Supported shells: {', '.join(SUPPORTED_SHELLS)}\n")
            console.print("Usage:")
            console.print("  spectrescan completion install bash")
            console.print("  spectrescan completion install zsh")
            console.print("  spectrescan completion install powershell")
            console.print("  spectrescan completion install fish")
            return
        
        if shell.lower() not in SUPPORTED_SHELLS:
            console.print(f"[red]Error:[/red] Unsupported shell: {shell}")
            console.print(f"Supported shells: {', '.join(SUPPORTED_SHELLS)}")
            sys.exit(1)
        
        console.print(f"[cyan]Installing completion for {shell}...[/cyan]")
        success, message = install_completion(shell)
        
        if success:
            console.print(f"[green]Success![/green] {message}")
        else:
            console.print(f"[red]Error:[/red] {message}")
            sys.exit(1)
    
    elif action == "instructions":
        if not shell:
            # Show all instructions
            for sh in SUPPORTED_SHELLS:
                console.print(get_install_instructions(sh))
                console.print("-" * 60)
        else:
            console.print(get_install_instructions(shell))
    
    else:
        console.print(f"[red]Error:[/red] Unknown action '{action}'")
        console.print("Valid actions: install, show, bash, zsh, powershell, fish, instructions")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# DISTRIBUTED SCANNING COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════


@app.command(name="cluster")
def cluster_command(
    action: str = typer.Argument(..., help="Action: init, status, scan, workers, add-worker, remove-worker, stop"),
    target: Optional[str] = typer.Argument(None, help="Target for scan action"),
    
    # Cluster options
    workers: int = typer.Option(2, "--workers", "-w", help="Number of workers for init/scale"),
    queue_type: str = typer.Option("memory", "--queue", help="Queue type: memory or redis"),
    redis_host: str = typer.Option("localhost", "--redis-host", help="Redis host"),
    redis_port: int = typer.Option(6379, "--redis-port", help="Redis port"),
    
    # Scan options
    ports: Optional[str] = typer.Option(None, "-p", "--ports", help="Port specification"),
    scan_type: str = typer.Option("tcp", "--type", help="Scan type: tcp, syn, udp, async"),
    timeout: float = typer.Option(3600, "--timeout", help="Scan timeout in seconds"),
    
    # Worker options
    worker_id: Optional[str] = typer.Option(None, "--worker-id", help="Worker ID for remove action"),
    capacity: int = typer.Option(4, "--capacity", help="Worker capacity"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Worker tags (comma-separated)"),
    
    # Output options
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output file for results"),
    output_format: str = typer.Option("json", "--format", help="Output format: json, csv"),
):
    """
    Distributed scanning cluster management.
    
    Actions:
        init        - Initialize and start a cluster with workers
        status      - Show cluster status
        scan        - Submit a distributed scan
        workers     - List all workers
        add-worker  - Add a local worker
        remove-worker - Remove a worker
        stop        - Stop the cluster
    
    Examples:
        spectrescan cluster init --workers 4
        spectrescan cluster status
        spectrescan cluster scan 192.168.1.0/24 -p 1-1000
        spectrescan cluster workers
        spectrescan cluster add-worker --capacity 8
        spectrescan cluster stop
    """
    import asyncio
    
    try:
        asyncio.run(_cluster_action(
            action=action,
            target=target,
            workers=workers,
            queue_type=queue_type,
            redis_host=redis_host,
            redis_port=redis_port,
            ports=ports,
            scan_type=scan_type,
            timeout=timeout,
            worker_id=worker_id,
            capacity=capacity,
            tags=tags,
            output=output,
            output_format=output_format
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


# Global cluster instance for persistence across commands
_cluster_instance = None


async def _cluster_action(
    action: str,
    target: Optional[str],
    workers: int,
    queue_type: str,
    redis_host: str,
    redis_port: int,
    ports: Optional[str],
    scan_type: str,
    timeout: float,
    worker_id: Optional[str],
    capacity: int,
    tags: Optional[str],
    output: Optional[Path],
    output_format: str
):
    """Execute cluster action."""
    global _cluster_instance
    
    from spectrescan.distributed.cluster import ClusterManager, ClusterConfig, create_cluster
    from spectrescan.distributed.models import TaskPriority
    from spectrescan.core.utils import parse_ports, parse_target
    
    if action == "init":
        # Initialize cluster
        console.print("[cyan]Initializing distributed scanning cluster...[/cyan]")
        
        # Build queue config
        queue_config = {}
        if queue_type == "redis":
            queue_config = {
                "host": redis_host,
                "port": redis_port
            }
        
        config = ClusterConfig(
            queue_type=queue_type,
            queue_config=queue_config
        )
        
        _cluster_instance = ClusterManager(config=config)
        
        if not await _cluster_instance.start():
            console.print("[red]Failed to start cluster[/red]")
            return
        
        # Add workers
        for i in range(workers):
            worker_tags = tags.split(",") if tags else []
            wid = await _cluster_instance.add_local_worker(
                capacity=capacity,
                tags=worker_tags
            )
            if wid:
                console.print(f"  [green]Added worker {wid}[/green]")
        
        status = _cluster_instance.get_cluster_status()
        console.print(f"\n[green]Cluster initialized![/green]")
        console.print(f"  Cluster ID: {status.cluster_id}")
        console.print(f"  Workers: {status.total_workers}")
        console.print(f"  Total capacity: {status.total_capacity} concurrent tasks")
        console.print("\n[dim]Use 'spectrescan cluster scan <target>' to submit scans[/dim]")
        
        # Keep running
        console.print("\n[cyan]Cluster running. Press Ctrl+C to stop.[/cyan]")
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await _cluster_instance.stop()
            console.print("[yellow]Cluster stopped[/yellow]")
    
    elif action == "status":
        # Show cluster status
        if not _cluster_instance or not _cluster_instance.is_running:
            console.print("[yellow]No cluster running. Use 'spectrescan cluster init' to start.[/yellow]")
            return
        
        status = _cluster_instance.get_cluster_status()
        
        table = Table(title="Cluster Status", show_header=False)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Cluster ID", status.cluster_id)
        table.add_row("Master ID", status.master_id)
        table.add_row("Total Workers", str(status.total_workers))
        table.add_row("Active Workers", str(status.active_workers))
        table.add_row("Idle Workers", str(status.idle_workers))
        table.add_row("Total Capacity", str(status.total_capacity))
        table.add_row("Available Capacity", str(status.available_capacity))
        table.add_row("Pending Tasks", str(status.pending_tasks))
        table.add_row("Running Tasks", str(status.running_tasks))
        table.add_row("Completed Tasks", str(status.completed_tasks))
        table.add_row("Failed Tasks", str(status.failed_tasks))
        table.add_row("Uptime", f"{status.uptime_seconds:.1f}s")
        
        console.print(table)
    
    elif action == "scan":
        # Submit distributed scan
        if not target:
            console.print("[red]Error:[/red] Target required for scan")
            return
        
        if not _cluster_instance or not _cluster_instance.is_running:
            # Create temporary cluster
            console.print("[cyan]Starting temporary cluster...[/cyan]")
            _cluster_instance = await create_cluster(workers=workers, queue_type=queue_type)
        
        # Parse targets
        target_list = parse_target(target)
        if not target_list:
            console.print(f"[red]Error:[/red] Invalid target: {target}")
            return
        
        # Parse ports
        port_list = parse_ports(ports) if ports else list(range(1, 1001))
        
        console.print(f"[cyan]Submitting distributed scan...[/cyan]")
        console.print(f"  Targets: {len(target_list)}")
        console.print(f"  Ports: {len(port_list)}")
        console.print(f"  Scan type: {scan_type}")
        
        task_id = await _cluster_instance.submit_scan(
            targets=target_list,
            ports=port_list,
            scan_type=scan_type,
            priority=TaskPriority.NORMAL
        )
        
        if not task_id:
            console.print("[red]Failed to submit scan[/red]")
            return
        
        console.print(f"  Task ID: {task_id}")
        console.print("\n[cyan]Waiting for scan completion...[/cyan]")
        
        # Wait with progress updates
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            
            while True:
                status = await _cluster_instance.get_scan_status(task_id)
                if not status:
                    break
                
                subtasks = status.get("subtasks", {})
                progress.update(
                    task,
                    description=f"Scanning... {subtasks.get('completed', 0)}/{subtasks.get('total', 0)} subtasks"
                )
                
                if status.get("status") in ("completed", "failed", "cancelled"):
                    break
                
                await asyncio.sleep(0.5)
        
        # Get results
        results = await _cluster_instance.get_scan_results(task_id)
        
        # Count open ports
        open_ports = [r for r in results if r.get("state") == "open"]
        
        console.print(f"\n[green]Scan completed![/green]")
        console.print(f"  Total results: {len(results)}")
        console.print(f"  Open ports: {len(open_ports)}")
        
        # Show open ports
        if open_ports:
            table = Table(title="Open Ports")
            table.add_column("Host", style="cyan")
            table.add_column("Port", style="green")
            table.add_column("Service", style="yellow")
            
            for result in open_ports[:50]:  # Limit to 50 for display
                table.add_row(
                    result.get("host", ""),
                    str(result.get("port", "")),
                    result.get("service", "unknown")
                )
            
            if len(open_ports) > 50:
                console.print(f"[dim](Showing first 50 of {len(open_ports)} open ports)[/dim]")
            
            console.print(table)
        
        # Save results
        if output:
            output_path = await _cluster_instance.save_results(task_id, output_format)
            if output_path:
                console.print(f"Results saved to: {output_path}")
    
    elif action == "workers":
        # List workers
        if not _cluster_instance or not _cluster_instance.is_running:
            console.print("[yellow]No cluster running[/yellow]")
            return
        
        workers_list = _cluster_instance.get_workers()
        
        if not workers_list:
            console.print("[yellow]No workers registered[/yellow]")
            return
        
        table = Table(title=f"Cluster Workers ({len(workers_list)} total)")
        table.add_column("Worker ID", style="cyan")
        table.add_column("Host", style="white")
        table.add_column("Status", style="green")
        table.add_column("Tasks", style="yellow")
        table.add_column("Capacity", style="blue")
        table.add_column("CPU", style="magenta")
        table.add_column("Memory", style="magenta")
        
        for w in workers_list:
            status_color = {
                "idle": "green",
                "busy": "yellow",
                "offline": "red",
                "error": "red"
            }.get(w.status.value, "white")
            
            table.add_row(
                w.worker_id,
                f"{w.ip_address}:{w.port}",
                f"[{status_color}]{w.status.value}[/{status_color}]",
                str(w.current_tasks),
                str(w.capacity),
                f"{w.cpu_usage:.1f}%",
                f"{w.memory_usage:.1f}%"
            )
        
        console.print(table)
    
    elif action == "add-worker":
        # Add a worker
        if not _cluster_instance or not _cluster_instance.is_running:
            console.print("[yellow]No cluster running[/yellow]")
            return
        
        worker_tags = tags.split(",") if tags else []
        wid = await _cluster_instance.add_local_worker(
            capacity=capacity,
            tags=worker_tags
        )
        
        if wid:
            console.print(f"[green]Added worker {wid}[/green]")
        else:
            console.print("[red]Failed to add worker[/red]")
    
    elif action == "remove-worker":
        # Remove a worker
        if not _cluster_instance or not _cluster_instance.is_running:
            console.print("[yellow]No cluster running[/yellow]")
            return
        
        if not worker_id:
            console.print("[red]Error:[/red] --worker-id required")
            return
        
        if await _cluster_instance.remove_local_worker(worker_id):
            console.print(f"[green]Removed worker {worker_id}[/green]")
        else:
            console.print(f"[red]Worker {worker_id} not found[/red]")
    
    elif action == "stop":
        # Stop cluster
        if not _cluster_instance:
            console.print("[yellow]No cluster running[/yellow]")
            return
        
        await _cluster_instance.stop()
        _cluster_instance = None
        console.print("[green]Cluster stopped[/green]")
    
    else:
        console.print(f"[red]Unknown action:[/red] {action}")
        console.print("Valid actions: init, status, scan, workers, add-worker, remove-worker, stop")


# =============================================================================
# Schedule Command
# =============================================================================

@app.command(name="schedule")
def schedule_command(
    action: str = typer.Argument(..., help="Action: list, add, remove, pause, resume, run, status, history"),
    schedule_id: Optional[str] = typer.Argument(None, help="Schedule ID (for remove, pause, resume, run, history)"),
    # Add schedule options
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Schedule name"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Scan target"),
    ports: str = typer.Option("1-1000", "--ports", "-p", help="Port specification"),
    schedule_type: str = typer.Option("once", "--type", help="Schedule type: once, cron, interval, daily, weekly"),
    cron: Optional[str] = typer.Option(None, "--cron", help="Cron expression (e.g., '0 2 * * *')"),
    interval: Optional[str] = typer.Option(None, "--interval", "-i", help="Interval (e.g., '30m', '2h', '1d')"),
    at_time: Optional[str] = typer.Option(None, "--at", help="Run at time (HH:MM for daily/weekly)"),
    days: Optional[str] = typer.Option(None, "--days", help="Days of week for weekly (e.g., 'mon,wed,fri')"),
    scan_type: str = typer.Option("tcp", "--scan-type", help="Scan type: tcp, syn, udp, async"),
    profile: Optional[str] = typer.Option(None, "--profile", help="Use scan profile"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Schedule description"),
    # Hook options
    pre_hook: Optional[str] = typer.Option(None, "--pre-hook", help="Command to run before scan"),
    post_hook: Optional[str] = typer.Option(None, "--post-hook", help="Command to run after scan"),
    # Daemon options
    daemon: bool = typer.Option(False, "--daemon", help="Run scheduler as daemon (for 'run' action)"),
    check_interval: int = typer.Option(60, "--check-interval", help="Scheduler check interval in seconds"),
    # Display options
    limit: int = typer.Option(20, "--limit", "-l", help="Limit number of results"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show verbose output"),
):
    """
    Manage scheduled scans and run the scheduler daemon.
    
    SpectreScan supports automated scan scheduling with cron-like expressions,
    one-time scheduled scans, recurring patterns, and scan chaining.
    
    Examples:
    
      # List all scheduled scans
      spectrescan schedule list
      
      # Add a one-time scan scheduled for 2 AM
      spectrescan schedule add --name "Nightly Scan" --target 192.168.1.0/24 --at "02:00" --type once
      
      # Add a daily recurring scan
      spectrescan schedule add --name "Daily Check" --target 192.168.1.1 --type daily --at "09:00"
      
      # Add a cron-based schedule (every day at 3 AM)
      spectrescan schedule add --name "Cron Scan" --target 10.0.0.1 --type cron --cron "0 3 * * *"
      
      # Add interval-based scan (every 2 hours)
      spectrescan schedule add --name "Hourly Check" --target server.local --type interval --interval "2h"
      
      # Add weekly scan on specific days
      spectrescan schedule add --name "Weekend Scan" --target 192.168.1.0/24 --type weekly --days "sat,sun" --at "01:00"
      
      # Add scan with hooks
      spectrescan schedule add --name "Hooked Scan" --target 192.168.1.1 --pre-hook "echo Starting" --post-hook "notify.sh"
      
      # View schedule details
      spectrescan schedule status <schedule_id>
      
      # Pause a schedule
      spectrescan schedule pause <schedule_id>
      
      # Resume a paused schedule
      spectrescan schedule resume <schedule_id>
      
      # Manually trigger a scheduled scan
      spectrescan schedule run <schedule_id>
      
      # View run history for a schedule
      spectrescan schedule history <schedule_id>
      
      # Start the scheduler daemon
      spectrescan schedule run --daemon
      
      # Remove a schedule
      spectrescan schedule remove <schedule_id>
    
    Schedule Types:
      - once: One-time scheduled scan
      - daily: Run every day at specified time
      - weekly: Run on specific days of the week
      - interval: Run every N minutes/hours/days
      - cron: Cron expression for complex schedules
    
    Cron Shortcuts:
      @hourly   = "0 * * * *"
      @daily    = "0 0 * * *"
      @weekly   = "0 0 * * 0"
      @monthly  = "0 0 1 * *"
    """
    import asyncio
    
    if action == "list":
        _schedule_list(limit, verbose)
    
    elif action == "add":
        _schedule_add(
            name=name,
            target=target,
            ports=ports,
            schedule_type=schedule_type,
            cron_expr=cron,
            interval_str=interval,
            at_time=at_time,
            days=days,
            scan_type=scan_type,
            profile_name=profile,
            description=description,
            pre_hook=pre_hook,
            post_hook=post_hook,
            verbose=verbose,
        )
    
    elif action == "remove":
        if not schedule_id:
            console.print("[red]Error:[/red] Schedule ID required for 'remove' action")
            sys.exit(1)
        _schedule_remove(schedule_id)
    
    elif action == "pause":
        if not schedule_id:
            console.print("[red]Error:[/red] Schedule ID required for 'pause' action")
            sys.exit(1)
        _schedule_pause(schedule_id)
    
    elif action == "resume":
        if not schedule_id:
            console.print("[red]Error:[/red] Schedule ID required for 'resume' action")
            sys.exit(1)
        _schedule_resume(schedule_id)
    
    elif action == "status":
        _schedule_status(schedule_id, verbose)
    
    elif action == "history":
        _schedule_history(schedule_id, limit)
    
    elif action == "run":
        if daemon:
            asyncio.run(_schedule_daemon(check_interval))
        elif schedule_id:
            asyncio.run(_schedule_run_now(schedule_id))
        else:
            console.print("[red]Error:[/red] Either --daemon or schedule_id required for 'run' action")
            sys.exit(1)
    
    else:
        console.print(f"[red]Error:[/red] Unknown action '{action}'")
        console.print("Valid actions: list, add, remove, pause, resume, run, status, history")
        sys.exit(1)


def _schedule_list(limit: int = 20, verbose: bool = False):
    """List all scheduled scans."""
    from spectrescan.core.scheduler import ScanScheduler, ScheduleStatus, format_next_run
    
    scheduler = ScanScheduler()
    schedules = scheduler.list_schedules(limit=limit)
    
    if not schedules:
        console.print("[yellow]No scheduled scans found[/yellow]")
        console.print("\nTo add a schedule, use:")
        console.print("  [cyan]spectrescan schedule add --name 'My Scan' --target 192.168.1.1 --type daily --at '02:00'[/cyan]")
        return
    
    table = Table(
        title="Scheduled Scans",
        show_header=True,
        header_style="bold cyan"
    )
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Target")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Next Run")
    table.add_column("Runs", justify="right")
    
    for s in schedules:
        status_color = {
            ScheduleStatus.PENDING: "green",
            ScheduleStatus.RUNNING: "yellow",
            ScheduleStatus.PAUSED: "dim",
            ScheduleStatus.FAILED: "red",
            ScheduleStatus.COMPLETED: "blue",
            ScheduleStatus.CANCELLED: "dim",
        }.get(s.status, "white")
        
        table.add_row(
            s.schedule_id[:8],
            s.name,
            s.target[:20] + ("..." if len(s.target) > 20 else ""),
            s.schedule_type.value,
            f"[{status_color}]{s.status.value}[/{status_color}]",
            format_next_run(s.next_run),
            f"{s.success_count}/{s.run_count}",
        )
    
    console.print(table)
    
    if verbose:
        # Show statistics
        stats = scheduler.get_statistics()
        console.print("\n[bold]Statistics:[/bold]")
        console.print(f"  Total schedules: {stats['total_schedules']}")
        console.print(f"  Active: {stats['active_schedules']}")
        console.print(f"  Paused: {stats['paused_schedules']}")
        console.print(f"  Total runs: {stats['total_runs']}")
        console.print(f"  Success rate: {stats['successful_runs']}/{stats['total_runs']}")


def _schedule_add(
    name: Optional[str],
    target: Optional[str],
    ports: str,
    schedule_type: str,
    cron_expr: Optional[str],
    interval_str: Optional[str],
    at_time: Optional[str],
    days: Optional[str],
    scan_type: str,
    profile_name: Optional[str],
    description: Optional[str],
    pre_hook: Optional[str],
    post_hook: Optional[str],
    verbose: bool,
):
    """Add a new scheduled scan."""
    from spectrescan.core.scheduler import (
        ScanScheduler, ScheduleType, HookType,
        parse_cron_shorthand, parse_interval, DAYS_OF_WEEK
    )
    from datetime import datetime, timedelta
    
    if not name:
        console.print("[red]Error:[/red] --name is required")
        sys.exit(1)
    
    if not target:
        console.print("[red]Error:[/red] --target is required")
        sys.exit(1)
    
    scheduler = ScanScheduler()
    
    # Parse schedule type
    try:
        stype = ScheduleType(schedule_type.lower())
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid schedule type '{schedule_type}'")
        console.print("Valid types: once, cron, interval, daily, weekly, monthly")
        sys.exit(1)
    
    # Parse time
    run_at = None
    if at_time:
        try:
            hour, minute = map(int, at_time.split(":"))
            run_at = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
            if run_at <= datetime.now():
                run_at += timedelta(days=1)
        except ValueError:
            console.print(f"[red]Error:[/red] Invalid time format '{at_time}'. Use HH:MM")
            sys.exit(1)
    
    # Parse cron expression
    cron_expression = None
    if cron_expr:
        cron_expression = parse_cron_shorthand(cron_expr)
    
    # Parse interval
    interval_minutes = None
    if interval_str:
        try:
            interval_minutes = parse_interval(interval_str)
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}")
            sys.exit(1)
    
    # Parse days of week
    days_of_week = []
    if days:
        for day in days.lower().split(","):
            day = day.strip()
            if day in DAYS_OF_WEEK:
                days_of_week.append(DAYS_OF_WEEK[day])
            else:
                console.print(f"[red]Error:[/red] Invalid day '{day}'")
                console.print("Valid days: mon, tue, wed, thu, fri, sat, sun")
                sys.exit(1)
    
    # Validate required options for each type
    if stype == ScheduleType.CRON and not cron_expression:
        console.print("[red]Error:[/red] --cron is required for cron schedule type")
        sys.exit(1)
    
    if stype == ScheduleType.INTERVAL and not interval_minutes:
        console.print("[red]Error:[/red] --interval is required for interval schedule type")
        sys.exit(1)
    
    if stype in (ScheduleType.DAILY, ScheduleType.WEEKLY) and not at_time:
        console.print(f"[red]Error:[/red] --at is required for {stype.value} schedule type")
        sys.exit(1)
    
    if stype == ScheduleType.WEEKLY and not days_of_week:
        console.print("[red]Error:[/red] --days is required for weekly schedule type")
        sys.exit(1)
    
    # Create schedule
    try:
        schedule = scheduler.create_schedule(
            name=name,
            target=target,
            ports=ports,
            schedule_type=stype,
            cron_expression=cron_expression,
            interval_minutes=interval_minutes,
            run_at=run_at,
            days_of_week=days_of_week,
            scan_type=scan_type,
            profile_name=profile_name,
            description=description,
        )
        
        # Add hooks
        if pre_hook:
            scheduler.add_hook(schedule.schedule_id, HookType.PRE_SCAN, pre_hook)
        if post_hook:
            scheduler.add_hook(schedule.schedule_id, HookType.POST_SCAN, post_hook)
        
        console.print(f"\n[green]Schedule created successfully![/green]")
        console.print(f"[bold]ID:[/bold] {schedule.schedule_id}")
        console.print(f"[bold]Name:[/bold] {schedule.name}")
        console.print(f"[bold]Target:[/bold] {schedule.target}")
        console.print(f"[bold]Type:[/bold] {schedule.schedule_type.value}")
        
        from spectrescan.core.scheduler import format_next_run
        console.print(f"[bold]Next Run:[/bold] {format_next_run(schedule.next_run)}")
        
        if verbose:
            console.print(f"\n[dim]Ports: {schedule.ports}[/dim]")
            console.print(f"[dim]Scan Type: {schedule.scan_type}[/dim]")
            if schedule.cron_expression:
                console.print(f"[dim]Cron: {schedule.cron_expression}[/dim]")
            if schedule.interval_minutes:
                console.print(f"[dim]Interval: {schedule.interval_minutes} minutes[/dim]")
    
    except Exception as e:
        console.print(f"[red]Error creating schedule:[/red] {e}")
        sys.exit(1)


def _schedule_remove(schedule_id: str):
    """Remove a scheduled scan."""
    from spectrescan.core.scheduler import ScanScheduler
    
    scheduler = ScanScheduler()
    
    # Try to find schedule with partial ID
    schedules = scheduler.list_schedules()
    matching = [s for s in schedules if s.schedule_id.startswith(schedule_id)]
    
    if not matching:
        console.print(f"[red]Error:[/red] Schedule '{schedule_id}' not found")
        sys.exit(1)
    
    if len(matching) > 1:
        console.print(f"[red]Error:[/red] Multiple schedules match '{schedule_id}'")
        for s in matching:
            console.print(f"  - {s.schedule_id}: {s.name}")
        sys.exit(1)
    
    schedule = matching[0]
    
    if scheduler.delete_schedule(schedule.schedule_id):
        console.print(f"[green]Removed schedule:[/green] {schedule.name} ({schedule.schedule_id})")
    else:
        console.print(f"[red]Error:[/red] Failed to remove schedule")
        sys.exit(1)


def _schedule_pause(schedule_id: str):
    """Pause a scheduled scan."""
    from spectrescan.core.scheduler import ScanScheduler
    
    scheduler = ScanScheduler()
    schedules = scheduler.list_schedules()
    matching = [s for s in schedules if s.schedule_id.startswith(schedule_id)]
    
    if not matching:
        console.print(f"[red]Error:[/red] Schedule '{schedule_id}' not found")
        sys.exit(1)
    
    schedule = matching[0]
    
    if scheduler.pause_schedule(schedule.schedule_id):
        console.print(f"[green]Paused schedule:[/green] {schedule.name}")
    else:
        console.print(f"[red]Error:[/red] Failed to pause schedule")


def _schedule_resume(schedule_id: str):
    """Resume a paused schedule."""
    from spectrescan.core.scheduler import ScanScheduler
    
    scheduler = ScanScheduler()
    schedules = scheduler.list_schedules()
    matching = [s for s in schedules if s.schedule_id.startswith(schedule_id)]
    
    if not matching:
        console.print(f"[red]Error:[/red] Schedule '{schedule_id}' not found")
        sys.exit(1)
    
    schedule = matching[0]
    
    if scheduler.resume_schedule(schedule.schedule_id):
        console.print(f"[green]Resumed schedule:[/green] {schedule.name}")
    else:
        console.print(f"[red]Error:[/red] Failed to resume schedule")


def _schedule_status(schedule_id: Optional[str], verbose: bool):
    """Show schedule status or statistics."""
    from spectrescan.core.scheduler import ScanScheduler, format_next_run
    
    scheduler = ScanScheduler()
    
    if schedule_id:
        # Show specific schedule details
        schedules = scheduler.list_schedules()
        matching = [s for s in schedules if s.schedule_id.startswith(schedule_id)]
        
        if not matching:
            console.print(f"[red]Error:[/red] Schedule '{schedule_id}' not found")
            sys.exit(1)
        
        s = matching[0]
        
        console.print(f"\n[bold cyan]Schedule Details[/bold cyan]")
        console.print(f"[bold]ID:[/bold] {s.schedule_id}")
        console.print(f"[bold]Name:[/bold] {s.name}")
        console.print(f"[bold]Target:[/bold] {s.target}")
        console.print(f"[bold]Ports:[/bold] {s.ports}")
        console.print(f"[bold]Scan Type:[/bold] {s.scan_type}")
        console.print(f"[bold]Schedule Type:[/bold] {s.schedule_type.value}")
        console.print(f"[bold]Status:[/bold] {s.status.value}")
        console.print(f"[bold]Created:[/bold] {s.created_at.strftime('%Y-%m-%d %H:%M') if s.created_at else 'N/A'}")
        console.print(f"[bold]Last Run:[/bold] {s.last_run.strftime('%Y-%m-%d %H:%M') if s.last_run else 'Never'}")
        console.print(f"[bold]Next Run:[/bold] {format_next_run(s.next_run)}")
        console.print(f"[bold]Run Count:[/bold] {s.run_count}")
        console.print(f"[bold]Success/Failure:[/bold] {s.success_count}/{s.failure_count}")
        
        if s.cron_expression:
            console.print(f"[bold]Cron:[/bold] {s.cron_expression}")
        if s.interval_minutes:
            console.print(f"[bold]Interval:[/bold] {s.interval_minutes} minutes")
        if s.days_of_week:
            day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            console.print(f"[bold]Days:[/bold] {', '.join(day_names[d] for d in s.days_of_week)}")
        
        if s.hooks:
            console.print(f"\n[bold]Hooks:[/bold]")
            for hook in s.hooks:
                console.print(f"  - {hook.hook_type.value}: {hook.action}")
        
        if s.conditions:
            console.print(f"\n[bold]Conditions:[/bold]")
            for cond in s.conditions:
                console.print(f"  - {cond.condition_type.value}")
        
        if s.chain_next:
            console.print(f"\n[bold]Chain Next:[/bold] {s.chain_next}")
        
        if s.description:
            console.print(f"\n[bold]Description:[/bold] {s.description}")
    
    else:
        # Show overall statistics
        stats = scheduler.get_statistics()
        
        console.print("\n[bold cyan]Scheduler Statistics[/bold cyan]\n")
        console.print(f"[bold]Total Schedules:[/bold] {stats['total_schedules']}")
        console.print(f"[bold]Active:[/bold] {stats['active_schedules']}")
        console.print(f"[bold]Paused:[/bold] {stats['paused_schedules']}")
        console.print(f"\n[bold]Total Runs:[/bold] {stats['total_runs']}")
        console.print(f"[bold]Successful:[/bold] {stats['successful_runs']}")
        console.print(f"[bold]Failed:[/bold] {stats['failed_runs']}")
        console.print(f"[bold]Total Open Ports Found:[/bold] {stats['total_open_ports_found']}")
        console.print(f"[bold]Avg Duration:[/bold] {stats['avg_duration_seconds']:.1f}s")


def _schedule_history(schedule_id: Optional[str], limit: int):
    """Show run history."""
    from spectrescan.core.scheduler import ScanScheduler
    
    scheduler = ScanScheduler()
    
    # Resolve partial ID
    full_id = None
    if schedule_id:
        schedules = scheduler.list_schedules()
        matching = [s for s in schedules if s.schedule_id.startswith(schedule_id)]
        if matching:
            full_id = matching[0].schedule_id
    
    history = scheduler.get_run_history(schedule_id=full_id, limit=limit)
    
    if not history:
        console.print("[yellow]No run history found[/yellow]")
        return
    
    table = Table(
        title="Run History",
        show_header=True,
        header_style="bold cyan"
    )
    table.add_column("Run ID", style="dim")
    table.add_column("Schedule", style="dim")
    table.add_column("Started")
    table.add_column("Duration")
    table.add_column("Status")
    table.add_column("Open Ports", justify="right")
    
    for r in history:
        status_color = "green" if r.success else "red"
        status_text = "Success" if r.success else "Failed"
        
        table.add_row(
            r.run_id[:8],
            r.schedule_id[:8],
            r.started_at.strftime("%Y-%m-%d %H:%M"),
            f"{r.duration_seconds:.1f}s",
            f"[{status_color}]{status_text}[/{status_color}]",
            str(r.open_ports),
        )
    
    console.print(table)


async def _schedule_daemon(check_interval: int):
    """Run the scheduler daemon."""
    from spectrescan.core.scheduler import ScanScheduler
    import signal
    
    scheduler = ScanScheduler(check_interval=check_interval)
    
    # Set up signal handlers
    stop_event = asyncio.Event()
    
    def handle_signal(sig):
        console.print(f"\n[yellow]Received signal {sig}, shutting down...[/yellow]")
        stop_event.set()
    
    # Register signal handlers
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda s=sig: handle_signal(s))
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass
    
    console.print("\n[bold cyan]Starting SpectreScan Scheduler Daemon[/bold cyan]\n")
    console.print(f"[green]Check Interval:[/green] {check_interval}s")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    
    # Define callbacks
    def on_scan_start(schedule, result):
        console.print(f"[cyan]Starting scan:[/cyan] {schedule.name} -> {schedule.target}")
    
    def on_scan_complete(schedule, result):
        if result.success:
            console.print(f"[green]Completed:[/green] {schedule.name} - {result.open_ports} open ports")
        else:
            console.print(f"[red]Failed:[/red] {schedule.name} - {result.error_message}")
    
    def on_scan_error(schedule, result):
        console.print(f"[red]Error in {schedule.name}:[/red] {result.error_message}")
    
    scheduler.set_callbacks(
        on_start=on_scan_start,
        on_complete=on_scan_complete,
        on_error=on_scan_error,
    )
    
    # Start scheduler
    await scheduler.start()
    
    # Wait for stop signal
    try:
        await stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await scheduler.stop()
        console.print("[green]Scheduler stopped[/green]")


async def _schedule_run_now(schedule_id: str):
    """Manually trigger a scheduled scan."""
    from spectrescan.core.scheduler import ScanScheduler
    
    scheduler = ScanScheduler()
    
    # Resolve partial ID
    schedules = scheduler.list_schedules()
    matching = [s for s in schedules if s.schedule_id.startswith(schedule_id)]
    
    if not matching:
        console.print(f"[red]Error:[/red] Schedule '{schedule_id}' not found")
        sys.exit(1)
    
    schedule = matching[0]
    
    console.print(f"[cyan]Manually triggering:[/cyan] {schedule.name}")
    console.print(f"[dim]Target: {schedule.target}[/dim]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running scan...", total=None)
        
        result = await scheduler.run_now(schedule.schedule_id)
        
        progress.update(task, completed=True)
    
    if result:
        if result.success:
            console.print(f"\n[green]Scan completed successfully![/green]")
            console.print(f"[bold]Open Ports:[/bold] {result.open_ports}")
            console.print(f"[bold]Closed Ports:[/bold] {result.closed_ports}")
            console.print(f"[bold]Filtered Ports:[/bold] {result.filtered_ports}")
            console.print(f"[bold]Duration:[/bold] {result.duration_seconds:.1f}s")
            if result.results_file:
                console.print(f"[bold]Results:[/bold] {result.results_file}")
        else:
            console.print(f"\n[red]Scan failed:[/red] {result.error_message}")
    else:
        console.print("[red]Error:[/red] No result returned")


# Register VulnDB commands
from spectrescan.cli import vulndb_commands
app.add_typer(vulndb_commands.app, name="vulndb", help="Manage custom vulnerability database")

# Register Template commands
from spectrescan.cli import template_commands
app.add_typer(template_commands.app, name="template", help="Manage report templates")

# Register Performance commands
from spectrescan.cli import perf_commands
app.add_typer(perf_commands.app, name="perf", help="Performance profiling and benchmarking tools")


def main():
    """Main entry point."""
    import sys
    
    # If no command provided but there's a target-like argument, inject 'scan'
    if len(sys.argv) > 1 and not sys.argv[1] in ['scan', 'presets', 'version', 'gui', 'tui', 'profile', 'history', 'compare', 'ssl', 'cve', 'dns', 'api', 'resume', 'checkpoint', 'config', 'completion', 'script', 'cluster', 'web', 'schedule', 'vulndb', 'template', 'perf', '--help', '-h']:
        # Check if first arg looks like a target (IP, hostname, or flag)
        first_arg = sys.argv[1]
        if not first_arg.startswith('--') or first_arg in ['--gui', '--tui']:
            # Inject 'scan' command
            if first_arg == '--gui':
                sys.argv[1:2] = ['gui']
            elif first_arg == '--tui':
                sys.argv[1:2] = ['tui']
            else:
                sys.argv.insert(1, 'scan')
    
    app()


if __name__ == "__main__":
    main()
