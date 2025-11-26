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
    threads: int = typer.Option(100, "--threads", "-T", help="Number of threads"),
    timeout: float = typer.Option(2.0, "--timeout", help="Timeout in seconds"),
    rate_limit: Optional[int] = typer.Option(None, "--rate-limit", help="Rate limit (packets/sec)"),
    
    # Features
    service_detection: bool = typer.Option(True, "--service-detection/--no-service-detection", help="Enable service detection"),
    os_detection: bool = typer.Option(False, "--os-detection", help="Enable OS detection"),
    banner_grab: bool = typer.Option(True, "--banner-grab/--no-banner-grab", help="Enable banner grabbing"),
    randomize: bool = typer.Option(False, "--randomize", help="Randomize scan order"),
    
    # Output
    json_output: Optional[Path] = typer.Option(None, "--json", help="Save JSON output"),
    csv_output: Optional[Path] = typer.Option(None, "--csv", help="Save CSV output"),
    xml_output: Optional[Path] = typer.Option(None, "--xml", help="Save XML output"),
    html_output: Optional[Path] = typer.Option(None, "--html", help="Save HTML report"),
    pdf_output: Optional[Path] = typer.Option(None, "--pdf", help="Save PDF report with charts"),
    executive_summary: Optional[Path] = typer.Option(None, "--exec-summary", help="Save executive summary"),
    
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
    
    # Parse ports
    if ports:
        try:
            port_list = parse_ports(ports)
            config.ports = port_list
        except ValueError as e:
            console.print(f"[red]Error:[/red] {e}", style="bold")
            sys.exit(1)
    
    # Display scan info
    if not quiet:
        info_table = Table(show_header=False, box=None)
        info_table.add_row("Target:", f"[cyan]{target}[/cyan]")
        info_table.add_row("Ports:", f"{len(config.ports)}")
        info_table.add_row("Scan Type:", f"{', '.join(config.scan_types).upper()}")
        info_table.add_row("Threads:", f"{config.threads}")
        info_table.add_row("Timeout:", f"{config.timeout}s")
        
        console.print(Panel(info_table, title="[bold]Scan Configuration[/bold]", border_style="blue"))
        console.print()
    
    # Create scanner
    scanner = PortScanner(config)
    
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


@app.command(name="presets")
def list_scan_presets():
    """List available scan presets."""
    print_logo()
    console.print(list_presets())


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


def main():
    """Main entry point."""
    import sys
    
    # If no command provided but there's a target-like argument, inject 'scan'
    if len(sys.argv) > 1 and not sys.argv[1] in ['scan', 'presets', 'version', 'gui', 'tui', 'profile', 'history', 'compare', '--help', '-h']:
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
