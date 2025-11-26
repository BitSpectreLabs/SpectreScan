"""
Comparison Report Generator for SpectreScan
by BitSpectreLabs
"""

from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime
from spectrescan.core.comparison import ScanComparison, PortDifference


def generate_comparison_report(
    comparison: ScanComparison,
    output_path: Path,
    format: str = 'text'
) -> None:
    """
    Generate a detailed comparison report.
    
    Args:
        comparison: ScanComparison object with diff data
        output_path: Output file path
        format: Report format ('text', 'html', 'json')
    """
    if format == 'text':
        _generate_text_comparison(comparison, output_path)
    elif format == 'html':
        _generate_html_comparison(comparison, output_path)
    elif format == 'json':
        _generate_json_comparison(comparison, output_path)
    else:
        raise ValueError(f"Unsupported format: {format}")


def _generate_text_comparison(comparison: ScanComparison, output_path: Path) -> None:
    """Generate text-based comparison report."""
    from spectrescan.core.comparison import ScanComparer
    
    comparer = ScanComparer()
    text = comparer.format_comparison_text(comparison)
    
    output_path.write_text(text, encoding='utf-8')


def _generate_json_comparison(comparison: ScanComparison, output_path: Path) -> None:
    """Generate JSON comparison report."""
    import json
    
    report = {
        "report_type": "scan_comparison",
        "generated_at": datetime.now().isoformat(),
        "tool": "SpectreScan",
        "vendor": "BitSpectreLabs",
        "comparison": {
            "scan1": {
                "id": comparison.scan1_id,
                "target": comparison.scan1_target,
                "timestamp": comparison.scan1_timestamp,
                "open_ports": comparison.scan1_open_count
            },
            "scan2": {
                "id": comparison.scan2_id,
                "target": comparison.scan2_target,
                "timestamp": comparison.scan2_timestamp,
                "open_ports": comparison.scan2_open_count
            },
            "changes": {
                "total": comparison.total_changes,
                "open_port_difference": comparison.open_diff,
                "newly_opened": _serialize_port_differences(comparison.newly_opened),
                "newly_closed": _serialize_port_differences(comparison.newly_closed),
                "newly_filtered": _serialize_port_differences(comparison.newly_filtered),
                "service_changed": _serialize_port_differences(comparison.service_changed)
            }
        }
    }
    
    output_path.write_text(json.dumps(report, indent=2), encoding='utf-8')


def _generate_html_comparison(comparison: ScanComparison, output_path: Path) -> None:
    """Generate HTML comparison report with styling."""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpectreScan Comparison Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .header p {{
            font-size: 1rem;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 2rem;
        }}
        
        .scan-info {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }}
        
        .scan-card {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1.5rem;
            border-left: 4px solid #667eea;
        }}
        
        .scan-card h3 {{
            color: #667eea;
            margin-bottom: 1rem;
        }}
        
        .scan-card p {{
            margin: 0.5rem 0;
            color: #555;
        }}
        
        .summary {{
            background: #f0f4ff;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            border-left: 4px solid #10b981;
        }}
        
        .summary h2 {{
            color: #667eea;
            margin-bottom: 1rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .stat {{
            text-align: center;
            padding: 1rem;
            background: white;
            border-radius: 8px;
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }}
        
        .changes-section {{
            margin-bottom: 2rem;
        }}
        
        .changes-section h2 {{
            color: #667eea;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid #e0e0e0;
        }}
        
        .change-category {{
            margin-bottom: 1.5rem;
        }}
        
        .change-category h3 {{
            color: #555;
            margin-bottom: 0.75rem;
            font-size: 1.1rem;
        }}
        
        .change-category.opened h3 {{ color: #10b981; }}
        .change-category.closed h3 {{ color: #ef4444; }}
        .change-category.filtered h3 {{ color: #f59e0b; }}
        .change-category.changed h3 {{ color: #3b82f6; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }}
        
        thead {{
            background: #667eea;
            color: white;
        }}
        
        th, td {{
            padding: 1rem;
            text-align: left;
        }}
        
        tbody tr:nth-child(even) {{
            background: #f8f9fa;
        }}
        
        tbody tr:hover {{
            background: #e9ecef;
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: bold;
        }}
        
        .badge.opened {{ background: #d1fae5; color: #065f46; }}
        .badge.closed {{ background: #fee2e2; color: #991b1b; }}
        .badge.filtered {{ background: #fef3c7; color: #92400e; }}
        .badge.changed {{ background: #dbeafe; color: #1e40af; }}
        
        .footer {{
            background: #f8f9fa;
            padding: 1.5rem;
            text-align: center;
            color: #666;
            border-top: 1px solid #e0e0e0;
        }}
        
        .no-changes {{
            text-align: center;
            padding: 2rem;
            color: #10b981;
            font-size: 1.2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Scan Comparison Report</h1>
            <p>SpectreScan by BitSpectreLabs</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            <div class="scan-info">
                <div class="scan-card">
                    <h3>📊 Scan 1 (Baseline)</h3>
                    <p><strong>ID:</strong> {comparison.scan1_id[:12]}...</p>
                    <p><strong>Target:</strong> {comparison.scan1_target}</p>
                    <p><strong>Timestamp:</strong> {comparison.scan1_timestamp}</p>
                    <p><strong>Open Ports:</strong> {comparison.scan1_open_count}</p>
                </div>
                
                <div class="scan-card">
                    <h3>📊 Scan 2 (Current)</h3>
                    <p><strong>ID:</strong> {comparison.scan2_id[:12]}...</p>
                    <p><strong>Target:</strong> {comparison.scan2_target}</p>
                    <p><strong>Timestamp:</strong> {comparison.scan2_timestamp}</p>
                    <p><strong>Open Ports:</strong> {comparison.scan2_open_count}</p>
                </div>
            </div>
            
            <div class="summary">
                <h2>📈 Change Summary</h2>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value">{comparison.total_changes}</div>
                        <div class="stat-label">Total Changes</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{comparison.open_diff:+d}</div>
                        <div class="stat-label">Open Port Difference</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{len(comparison.newly_opened)}</div>
                        <div class="stat-label">Newly Opened</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{len(comparison.newly_closed)}</div>
                        <div class="stat-label">Newly Closed</div>
                    </div>
                </div>
            </div>
"""
    
    if comparison.total_changes == 0:
        html += """
            <div class="no-changes">
                ✅ No changes detected between scans
            </div>
"""
    else:
        html += """
            <div class="changes-section">
                <h2>🔄 Detailed Changes</h2>
"""
        
        # Newly opened ports
        if comparison.newly_opened:
            html += f"""
                <div class="change-category opened">
                    <h3>✅ Newly Opened Ports ({len(comparison.newly_opened)})</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Protocol</th>
                                <th>Previous State</th>
                                <th>Current State</th>
                                <th>Service</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for diff in comparison.newly_opened:
                html += f"""
                            <tr>
                                <td><strong>{diff.port}</strong></td>
                                <td>{diff.protocol}</td>
                                <td><span class="badge closed">{diff.old_state}</span></td>
                                <td><span class="badge opened">{diff.new_state}</span></td>
                                <td>{diff.service_new or 'unknown'}</td>
                            </tr>
"""
            html += """
                        </tbody>
                    </table>
                </div>
"""
        
        # Newly closed ports
        if comparison.newly_closed:
            html += f"""
                <div class="change-category closed">
                    <h3>❌ Newly Closed Ports ({len(comparison.newly_closed)})</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Protocol</th>
                                <th>Previous State</th>
                                <th>Current State</th>
                                <th>Service (was)</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for diff in comparison.newly_closed:
                html += f"""
                            <tr>
                                <td><strong>{diff.port}</strong></td>
                                <td>{diff.protocol}</td>
                                <td><span class="badge opened">{diff.old_state}</span></td>
                                <td><span class="badge closed">{diff.new_state}</span></td>
                                <td>{diff.service_old or 'unknown'}</td>
                            </tr>
"""
            html += """
                        </tbody>
                    </table>
                </div>
"""
        
        # Newly filtered ports
        if comparison.newly_filtered:
            html += f"""
                <div class="change-category filtered">
                    <h3>⚠️ Newly Filtered Ports ({len(comparison.newly_filtered)})</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Protocol</th>
                                <th>Previous State</th>
                                <th>Current State</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for diff in comparison.newly_filtered:
                html += f"""
                            <tr>
                                <td><strong>{diff.port}</strong></td>
                                <td>{diff.protocol}</td>
                                <td><span class="badge">{diff.old_state}</span></td>
                                <td><span class="badge filtered">{diff.new_state}</span></td>
                            </tr>
"""
            html += """
                        </tbody>
                    </table>
                </div>
"""
        
        # Service changes
        if comparison.service_changed:
            html += f"""
                <div class="change-category changed">
                    <h3>🔄 Service Changes ({len(comparison.service_changed)})</h3>
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Protocol</th>
                                <th>Previous Service</th>
                                <th>Current Service</th>
                            </tr>
                        </thead>
                        <tbody>
"""
            for diff in comparison.service_changed:
                html += f"""
                            <tr>
                                <td><strong>{diff.port}</strong></td>
                                <td>{diff.protocol}</td>
                                <td>{diff.service_old or 'unknown'}</td>
                                <td><span class="badge changed">{diff.service_new or 'unknown'}</span></td>
                            </tr>
"""
            html += """
                        </tbody>
                    </table>
                </div>
"""
        
        html += """
            </div>
"""
    
    html += """
        </div>
        
        <div class="footer">
            <p><strong>SpectreScan</strong> - Professional Network Security Tools</p>
            <p>© 2025 BitSpectreLabs. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""
    
    output_path.write_text(html, encoding='utf-8')


def _serialize_port_differences(differences: List[PortDifference]) -> List[Dict]:
    """Serialize PortDifference objects to dictionaries."""
    return [
        {
            "port": diff.port,
            "protocol": diff.protocol,
            "old_state": diff.old_state,
            "new_state": diff.new_state,
            "service_old": diff.service_old,
            "service_new": diff.service_new
        }
        for diff in differences
    ]
