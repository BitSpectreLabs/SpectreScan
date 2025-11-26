"""
Chart Generation Module for SpectreScan
by BitSpectreLabs
"""

from typing import List, Dict, Optional, Tuple, TYPE_CHECKING
from pathlib import Path
from collections import Counter
from spectrescan.core.utils import ScanResult

if TYPE_CHECKING:
    from reportlab.graphics.shapes import Drawing

try:
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.lib import colors
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def create_port_distribution_chart(
    results: List[ScanResult],
    width: int = 400,
    height: int = 300
) -> Optional["Drawing"]:
    """
    Create pie chart showing distribution of port states.
    
    Args:
        results: List of scan results
        width: Chart width
        height: Chart height
        
    Returns:
        Drawing object or None if reportlab not available
    """
    if not REPORTLAB_AVAILABLE:
        return None
    
    # Count states
    states = Counter(r.state for r in results)
    
    drawing = Drawing(width, height)
    pie = Pie()
    pie.x = width // 3
    pie.y = height // 4
    pie.width = min(width, height) // 2
    pie.height = min(width, height) // 2
    
    # Data
    pie.data = [
        states.get('open', 0),
        states.get('closed', 0),
        states.get('filtered', 0)
    ]
    
    pie.labels = [
        f"Open ({states.get('open', 0)})",
        f"Closed ({states.get('closed', 0)})",
        f"Filtered ({states.get('filtered', 0)})"
    ]
    
    # Colors
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = colors.HexColor('#10B981')  # Green
    pie.slices[1].fillColor = colors.HexColor('#EF4444')  # Red
    pie.slices[2].fillColor = colors.HexColor('#F59E0B')  # Yellow
    
    drawing.add(pie)
    return drawing


def create_service_distribution_chart(
    results: List[ScanResult],
    width: int = 500,
    height: int = 400,
    top_n: int = 10
) -> Optional["Drawing"]:
    """
    Create horizontal bar chart showing top services.
    
    Args:
        results: List of scan results
        width: Chart width
        height: Chart height
        top_n: Number of top services to show
        
    Returns:
        Drawing object or None if reportlab not available
    """
    if not REPORTLAB_AVAILABLE:
        return None
    
    # Get open ports only
    open_results = [r for r in results if r.state == 'open']
    
    # Count services
    services = Counter(r.service or 'unknown' for r in open_results)
    top_services = services.most_common(top_n)
    
    if not top_services:
        return None
    
    drawing = Drawing(width, height)
    chart = HorizontalBarChart()
    chart.x = 100
    chart.y = 50
    chart.width = width - 150
    chart.height = height - 100
    
    # Data
    chart.data = [[count for _, count in top_services]]
    chart.categoryAxis.categoryNames = [name for name, _ in top_services]
    
    # Styling
    chart.bars[0].fillColor = colors.HexColor('#6B46C1')
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(count for _, count in top_services) * 1.2
    chart.categoryAxis.labels.fontSize = 9
    chart.valueAxis.labels.fontSize = 9
    
    drawing.add(chart)
    return drawing


def create_port_range_distribution_chart(
    results: List[ScanResult],
    width: int = 500,
    height: int = 300
) -> Optional["Drawing"]:
    """
    Create bar chart showing port distribution by range.
    
    Args:
        results: List of scan results
        width: Chart width
        height: Chart height
        
    Returns:
        Drawing object or None if reportlab not available
    """
    if not REPORTLAB_AVAILABLE:
        return None
    
    # Define port ranges
    ranges = [
        ("Well-Known\n(1-1023)", 1, 1023),
        ("Registered\n(1024-49151)", 1024, 49151),
        ("Dynamic\n(49152-65535)", 49152, 65535)
    ]
    
    # Count open ports in each range
    open_results = [r for r in results if r.state == 'open']
    range_counts = []
    
    for label, start, end in ranges:
        count = len([r for r in open_results if start <= r.port <= end])
        range_counts.append(count)
    
    if sum(range_counts) == 0:
        return None
    
    drawing = Drawing(width, height)
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 50
    chart.width = width - 100
    chart.height = height - 100
    
    # Data
    chart.data = [range_counts]
    chart.categoryAxis.categoryNames = [label for label, _, _ in ranges]
    
    # Styling
    chart.bars[0].fillColor = colors.HexColor('#3B82F6')
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(range_counts) * 1.2 if range_counts else 10
    chart.categoryAxis.labels.fontSize = 9
    chart.valueAxis.labels.fontSize = 9
    
    drawing.add(chart)
    return drawing


def create_risk_comparison_chart(
    scan_summaries: List[Dict],
    width: int = 500,
    height: int = 300
) -> Optional["Drawing"]:
    """
    Create line chart comparing risk scores over time.
    
    Args:
        scan_summaries: List of scan summary dicts with risk_score
        width: Chart width
        height: Chart height
        
    Returns:
        Drawing object or None if reportlab not available
    """
    if not REPORTLAB_AVAILABLE:
        return None
    
    if len(scan_summaries) < 2:
        return None
    
    drawing = Drawing(width, height)
    chart = HorizontalLineChart()
    chart.x = 50
    chart.y = 50
    chart.width = width - 100
    chart.height = height - 100
    
    # Data
    risk_scores = [s.get('risk_score', 0) for s in scan_summaries]
    chart.data = [risk_scores]
    
    # Styling
    chart.lines[0].strokeColor = colors.HexColor('#EF4444')
    chart.lines[0].strokeWidth = 2
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = 100
    chart.categoryAxis.categoryNames = [
        f"Scan {i+1}" for i in range(len(scan_summaries))
    ]
    
    drawing.add(chart)
    return drawing


def save_chart_as_pdf(drawing: "Drawing", output_path: Path) -> None:
    """
    Save a chart drawing as PDF.
    
    Args:
        drawing: ReportLab Drawing object
        output_path: Output PDF file path
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for PDF chart generation")
    
    renderPDF.drawToFile(drawing, str(output_path))


def save_chart_as_png(drawing: "Drawing", output_path: Path, dpi: int = 150) -> None:
    """
    Save a chart drawing as PNG (requires PIL/Pillow).
    
    Args:
        drawing: ReportLab Drawing object
        output_path: Output PNG file path
        dpi: Resolution in dots per inch
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for chart generation")
    
    try:
        from reportlab.graphics import renderPM
        renderPM.drawToFile(drawing, str(output_path), fmt='PNG', dpi=dpi)
    except ImportError:
        raise ImportError(
            "PIL/Pillow is required for PNG export. "
            "Install it with: pip install pillow"
        )


def generate_all_charts(
    results: List[ScanResult],
    output_dir: Path,
    format: str = 'pdf'
) -> List[Path]:
    """
    Generate all available charts and save to directory.
    
    Args:
        results: List of scan results
        output_dir: Output directory for charts
        format: Output format ('pdf' or 'png')
        
    Returns:
        List of paths to generated chart files
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError("ReportLab is required for chart generation")
    
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_files = []
    
    # Port distribution chart
    port_dist = create_port_distribution_chart(results)
    if port_dist:
        path = output_dir / f"port_distribution.{format}"
        if format == 'pdf':
            save_chart_as_pdf(port_dist, path)
        else:
            save_chart_as_png(port_dist, path)
        generated_files.append(path)
    
    # Service distribution chart
    service_dist = create_service_distribution_chart(results)
    if service_dist:
        path = output_dir / f"service_distribution.{format}"
        if format == 'pdf':
            save_chart_as_pdf(service_dist, path)
        else:
            save_chart_as_png(service_dist, path)
        generated_files.append(path)
    
    # Port range distribution chart
    port_range = create_port_range_distribution_chart(results)
    if port_range:
        path = output_dir / f"port_range_distribution.{format}"
        if format == 'pdf':
            save_chart_as_pdf(port_range, path)
        else:
            save_chart_as_png(port_range, path)
        generated_files.append(path)
    
    return generated_files


def get_ascii_chart(
    results: List[ScanResult],
    chart_type: str = 'port_distribution'
) -> str:
    """
    Generate simple ASCII chart for terminal display.
    
    Args:
        results: List of scan results
        chart_type: Type of chart ('port_distribution', 'service_distribution')
        
    Returns:
        ASCII art chart as string
    """
    if chart_type == 'port_distribution':
        return _ascii_port_distribution(results)
    elif chart_type == 'service_distribution':
        return _ascii_service_distribution(results)
    else:
        return "Unsupported chart type"


def _ascii_port_distribution(results: List[ScanResult]) -> str:
    """Generate ASCII bar chart for port distribution."""
    states = Counter(r.state for r in results)
    
    max_count = max(states.values()) if states else 1
    max_bar_width = 40
    
    lines = []
    lines.append("Port Status Distribution:")
    lines.append("─" * 50)
    
    for state in ['open', 'closed', 'filtered']:
        count = states.get(state, 0)
        bar_width = int((count / max_count) * max_bar_width) if max_count > 0 else 0
        bar = "█" * bar_width
        lines.append(f"{state:10} │{bar} {count}")
    
    lines.append("─" * 50)
    
    return "\n".join(lines)


def _ascii_service_distribution(results: List[ScanResult], top_n: int = 10) -> str:
    """Generate ASCII bar chart for service distribution."""
    open_results = [r for r in results if r.state == 'open']
    services = Counter(r.service or 'unknown' for r in open_results)
    top_services = services.most_common(top_n)
    
    if not top_services:
        return "No services detected"
    
    max_count = max(count for _, count in top_services)
    max_bar_width = 30
    
    lines = []
    lines.append(f"Top {len(top_services)} Services:")
    lines.append("─" * 50)
    
    for service, count in top_services:
        bar_width = int((count / max_count) * max_bar_width)
        bar = "█" * bar_width
        lines.append(f"{service[:15]:15} │{bar} {count}")
    
    lines.append("─" * 50)
    
    return "\n".join(lines)
