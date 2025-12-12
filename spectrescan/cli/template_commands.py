"""
SpectreScan CLI - Template Management Commands
by BitSpectreLabs
"""

import typer
from pathlib import Path
from typing import Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from spectrescan.reports.templates import (
    TemplateManager, TemplateMetadata, CompanyBranding, TemplateValidator
)

app = typer.Typer(help="Manage report templates")
console = Console()

def get_manager() -> TemplateManager:
    """Get template manager instance."""
    return TemplateManager()

@app.command("list")
def list_templates(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category"),
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="Filter by tags (comma-separated)")
):
    """List all available templates."""
    manager = get_manager()
    
    # Parse tags
    tag_list = [t.strip() for t in tags.split(',')] if tags else None
    
    # Search templates
    results = manager.search_templates(category=category, tags=tag_list)
    
    if not results and not category and not tags:
        # Show all templates
        templates = manager.list_templates()
        if not templates:
            console.print("[yellow]No templates found.[/yellow]")
            console.print("[dim]Create default templates with: spectrescan template init[/dim]")
            return
        
        table = Table(title="Available Templates")
        table.add_column("Name", style="cyan")
        table.add_column("Format", style="green")
        
        for template in templates:
            suffix = Path(template).suffix[1:].upper()
            table.add_row(template, suffix)
        
        console.print(table)
    elif results:
        table = Table(title=f"Templates ({len(results)})")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="yellow")
        table.add_column("Author", style="green")
        table.add_column("Category", style="magenta")
        table.add_column("Format", style="blue")
        
        for name, metadata in results:
            table.add_row(
                name,
                metadata.version,
                metadata.author,
                metadata.category,
                metadata.format
            )
        
        console.print(table)
    else:
        console.print(f"[yellow]No templates found matching filters.[/yellow]")

@app.command("init")
def init_templates():
    """Create default template examples."""
    from spectrescan.reports.templates import create_default_templates
    
    create_default_templates()
    console.print("[green]Default templates created successfully![/green]")
    console.print(f"[dim]Location: {get_manager().templates_dir}[/dim]")

@app.command("info")
def template_info(name: str):
    """Show detailed information about a template."""
    manager = get_manager()
    
    template_path = manager.get_template_path(name)
    if not template_path:
        console.print(f"[red]Template '{name}' not found.[/red]")
        raise typer.Exit(1)
    
    # Get metadata
    metadata = manager.get_metadata(name)
    
    # Validate template
    is_valid, error, variables = manager.validate_template(name)
    
    # Display info
    info_text = f"""[bold cyan]{name}[/bold cyan]

[bold]Location:[/bold] {template_path}
[bold]Valid:[/bold] {'✓ Yes' if is_valid else '✗ No'}
"""
    
    if error:
        info_text += f"[bold red]Error:[/bold red] {error}\n"
    
    if metadata:
        info_text += f"""
[bold]Version:[/bold] {metadata.version}
[bold]Author:[/bold] {metadata.author}
[bold]Category:[/bold] {metadata.category}
[bold]Format:[/bold] {metadata.format}
[bold]License:[/bold] {metadata.license}
[bold]Tags:[/bold] {', '.join(metadata.tags)}

[bold]Description:[/bold]
{metadata.description}
"""
    
    if variables:
        info_text += f"\n[bold]Variables Used:[/bold]\n"
        info_text += "\n".join(f"  • {var}" for var in variables)
    
    panel = Panel(info_text, title="Template Information", border_style="cyan")
    console.print(panel)

@app.command("validate")
def validate_template(name: str):
    """Validate template syntax."""
    manager = get_manager()
    
    is_valid, error, variables = manager.validate_template(name)
    
    if is_valid:
        console.print(f"[green]✓ Template '{name}' is valid![/green]")
        if variables:
            console.print(f"\n[bold]Variables used:[/bold] {', '.join(variables)}")
    else:
        console.print(f"[red]✗ Template '{name}' is invalid:[/red]")
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1)

@app.command("create")
def create_template(
    name: str = typer.Argument(..., help="Template filename"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", help="Import from file", exists=True),
    content: Optional[str] = typer.Option(None, "--content", "-c", help="Template content"),
    
    # Metadata
    version: str = typer.Option("1.0.0", "--version", help="Template version"),
    author: str = typer.Option("", "--author", help="Author name"),
    description: str = typer.Option("", "--description", "-d", help="Template description"),
    category: str = typer.Option("general", "--category", help="Template category"),
    tags: str = typer.Option("", "--tags", "-t", help="Tags (comma-separated)"),
    format: str = typer.Option("html", "--format", help="Output format"),
):
    """Create a new template."""
    manager = get_manager()
    
    # Get content
    if file:
        template_content = file.read_text(encoding='utf-8')
    elif content:
        template_content = content
    else:
        console.print("[red]Error:[/red] Either --file or --content must be provided")
        raise typer.Exit(1)
    
    # Validate syntax
    is_valid, error = TemplateValidator.validate_syntax(template_content)
    if not is_valid:
        console.print(f"[red]Template validation failed:[/red] {error}")
        raise typer.Exit(1)
    
    # Create template
    try:
        manager.create_template(name, template_content, overwrite=True)
        
        # Add metadata if provided
        if author or description or tags:
            tag_list = [t.strip() for t in tags.split(',')] if tags else []
            metadata = TemplateMetadata(
                name=name,
                version=version,
                author=author or "Unknown",
                description=description or "No description",
                category=category,
                tags=tag_list,
                format=format
            )
            manager.set_metadata(name, metadata)
        
        console.print(f"[green]Template '{name}' created successfully![/green]")
    except Exception as e:
        console.print(f"[red]Error creating template:[/red] {e}")
        raise typer.Exit(1)

@app.command("delete")
def delete_template(name: str):
    """Delete a template."""
    manager = get_manager()
    
    if manager.delete_template(name):
        console.print(f"[green]Template '{name}' deleted.[/green]")
    else:
        console.print(f"[red]Template '{name}' not found.[/red]")

@app.command("export")
def export_template(
    name: str = typer.Argument(..., help="Template name to export"),
    output: Path = typer.Argument(..., help="Output .zip file")
):
    """Export template with metadata."""
    manager = get_manager()
    
    try:
        manager.export_template(name, output)
        console.print(f"[green]Template exported to {output}[/green]")
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

@app.command("import")
def import_template(file: Path = typer.Argument(..., help="Template .zip file", exists=True)):
    """Import template from file."""
    manager = get_manager()
    
    try:
        name = manager.import_template(file)
        console.print(f"[green]Template '{name}' imported successfully![/green]")
    except Exception as e:
        console.print(f"[red]Import failed:[/red] {e}")
        raise typer.Exit(1)

@app.command("categories")
def list_categories():
    """List all template categories."""
    manager = get_manager()
    categories = manager.list_categories()
    
    if not categories:
        console.print("[yellow]No categories found.[/yellow]")
        return
    
    table = Table(title="Template Categories")
    table.add_column("Category", style="cyan")
    
    for cat in categories:
        table.add_row(cat)
    
    console.print(table)

@app.command("search")
def search_templates(
    query: str = typer.Argument(..., help="Search query"),
    category: Optional[str] = typer.Option(None, "--category", "-c"),
    tags: Optional[str] = typer.Option(None, "--tags", "-t")
):
    """Search templates."""
    manager = get_manager()
    
    tag_list = [t.strip() for t in tags.split(',')] if tags else None
    results = manager.search_templates(query=query, category=category, tags=tag_list)
    
    if not results:
        console.print(f"[yellow]No templates found matching '{query}'[/yellow]")
        return
    
    table = Table(title=f"Search Results ({len(results)})")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Category", style="magenta")
    
    for name, metadata in results:
        table.add_row(name, metadata.description[:50] + "...", metadata.category)
    
    console.print(table)
