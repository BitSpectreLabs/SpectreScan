"""
SpectreScan CLI - Vulnerability Database Commands
by BitSpectreLabs
"""

import typer
import json
import csv
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from spectrescan.core.vulndb import VulnerabilityDatabase, Vulnerability

app = typer.Typer(help="Manage custom vulnerability database")
console = Console()

def get_db() -> VulnerabilityDatabase:
    """Get database instance."""
    return VulnerabilityDatabase()

@app.command("init")
def init_db():
    """Initialize the vulnerability database."""
    db = get_db()
    console.print(f"[green]Vulnerability database initialized at {db.db_path}[/green]")

@app.command("list")
def list_vulns(
    limit: int = typer.Option(50, help="Limit number of results"),
    show_all: bool = typer.Option(False, "--all", help="Show all vulnerabilities")
):
    """List vulnerabilities in the database."""
    db = get_db()
    vulns = db.get_all_vulnerabilities()
    
    if not vulns:
        console.print("[yellow]Database is empty.[/yellow]")
        return

    if not show_all:
        vulns = vulns[:limit]

    table = Table(title=f"Vulnerabilities ({len(vulns)})")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="magenta")
    table.add_column("Product", style="green")
    table.add_column("Version Range", style="yellow")

    for v in vulns:
        table.add_row(v.id, v.title, v.severity, v.affected_product, v.affected_version_range)

    console.print(table)

@app.command("search")
def search_vulns(query: str):
    """Search for vulnerabilities."""
    db = get_db()
    results = db.search_vulnerabilities(query)
    
    if not results:
        console.print(f"[yellow]No vulnerabilities found matching '{query}'.[/yellow]")
        return

    table = Table(title=f"Search Results for '{query}'")
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Severity", style="magenta")
    table.add_column("Product", style="green")

    for v in results:
        table.add_row(v.id, v.title, v.severity, v.affected_product)

    console.print(table)

@app.command("add")
def add_vuln(
    id: str = typer.Option(..., prompt=True, help="Vulnerability ID (e.g. CVE-2023-1234)"),
    title: str = typer.Option(..., prompt=True, help="Title"),
    description: str = typer.Option(..., prompt=True, help="Description"),
    severity: str = typer.Option(..., prompt=True, help="Severity (Critical, High, Medium, Low)"),
    cvss: float = typer.Option(..., prompt=True, help="CVSS Score (0.0 - 10.0)"),
    product: str = typer.Option(..., prompt=True, help="Affected Product Regex (e.g. Apache.*)"),
    version: str = typer.Option(..., prompt=True, help="Affected Version Range (e.g. < 2.4.49)"),
    remediation: str = typer.Option("", help="Remediation steps"),
    refs: str = typer.Option("", help="Reference URLs (comma separated)")
):
    """Add a new vulnerability manually."""
    db = get_db()
    
    # Parse refs
    ref_list = [r.strip() for r in refs.split(',')] if refs else []
    ref_json = json.dumps(ref_list)

    vuln = Vulnerability(
        id=id,
        title=title,
        description=description,
        severity=severity,
        cvss_score=cvss,
        affected_product=product,
        affected_version_range=version,
        remediation=remediation,
        reference_urls=ref_json
    )

    if db.add_vulnerability(vuln):
        console.print(f"[green]Successfully added vulnerability {id}[/green]")
    else:
        console.print(f"[red]Failed to add vulnerability {id}[/red]")

@app.command("import")
def import_vulns(
    file: Path = typer.Argument(..., help="JSON or CSV file to import", exists=True)
):
    """Import vulnerabilities from a file."""
    db = get_db()
    count = 0
    
    if file.suffix.lower() == '.json':
        count = db.import_from_json(file)
    elif file.suffix.lower() == '.csv':
        count = db.import_from_csv(file)
    else:
        console.print("[red]Unsupported file format. Use .json or .csv[/red]")
        return

    console.print(f"[green]Successfully imported {count} vulnerabilities.[/green]")

@app.command("export")
def export_vulns(
    file: Path = typer.Argument(..., help="Output JSON file")
):
    """Export all vulnerabilities to JSON."""
    db = get_db()
    if db.export_to_json(file):
        console.print(f"[green]Successfully exported database to {file}[/green]")
    else:
        console.print("[red]Export failed.[/red]")

@app.command("delete")
def delete_vuln(
    id: str = typer.Argument(..., help="ID of vulnerability to delete")
):
    """Delete a vulnerability."""
    db = get_db()
    if db.delete_vulnerability(id):
        console.print(f"[green]Deleted vulnerability {id}[/green]")
    else:
        console.print(f"[red]Failed to delete {id} (not found?)[/red]")
