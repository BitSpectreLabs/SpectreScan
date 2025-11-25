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
from spectrescan.core.utils import parse_ports, get_common_ports, ScanResult
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
    target: str = typer.Argument(..., help="Target IP, hostname, CIDR, or range"),
    ports: Optional[str] = typer.Option(None, "-p", "--ports", help="Port specification (e.g., 1-1000, 80,443)"),
    
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
    """
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


def main():
    """Main entry point."""
    import sys
    
    # If no command provided but there's a target-like argument, inject 'scan'
    if len(sys.argv) > 1 and not sys.argv[1] in ['scan', 'presets', 'version', 'gui', 'tui', '--help', '-h']:
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
