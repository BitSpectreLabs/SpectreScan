"""
HTML report generation for SpectreScan
by BitSpectreLabs
"""

from typing import List, Dict, Optional
from pathlib import Path
from spectrescan.core.utils import ScanResult, HostInfo, get_timestamp


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpectreScan Report - {timestamp}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2b2b3c 100%);
            color: #e0e0e0;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #2b2b3c;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #00ffff 0%, #0066cc 100%);
            padding: 30px;
            text-align: center;
            color: #1e1e2e;
        }}
        
        .header .logo {{
            max-width: 120px;
            height: auto;
            margin-bottom: 15px;
            filter: drop-shadow(0 4px 6px rgba(0, 0, 0, 0.3));
        }}
        
        .header h1 {{
            font-size: 3em;
            margin-bottom: 10px;
            font-weight: 700;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .section {{
            margin-bottom: 30px;
            background: #1e1e2e;
            border-radius: 8px;
            padding: 20px;
            border-left: 4px solid #00ffff;
        }}
        
        .section h2 {{
            color: #00ffff;
            margin-bottom: 15px;
            font-size: 1.8em;
            border-bottom: 2px solid #00ffff;
            padding-bottom: 10px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        
        .summary-card {{
            background: #2b2b3c;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 2px solid #444;
            transition: transform 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            border-color: #00ffff;
        }}
        
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #00ffff;
            margin-bottom: 5px;
        }}
        
        .summary-card .label {{
            font-size: 1em;
            color: #aaa;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .open {{ color: #00ff00; }}
        .closed {{ color: #ff6666; }}
        .filtered {{ color: #ffaa00; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #2b2b3c;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        thead {{
            background: #00ffff;
            color: #1e1e2e;
        }}
        
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #444;
        }}
        
        th {{
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
        }}
        
        tr:hover {{
            background: #333344;
        }}
        
        tbody tr:last-child td {{
            border-bottom: none;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .badge-open {{
            background: #00ff0033;
            color: #00ff00;
            border: 1px solid #00ff00;
        }}
        
        .badge-closed {{
            background: #ff000033;
            color: #ff6666;
            border: 1px solid #ff6666;
        }}
        
        .badge-filtered {{
            background: #ffaa0033;
            color: #ffaa00;
            border: 1px solid #ffaa00;
        }}
        
        .footer {{
            background: #1e1e2e;
            padding: 20px;
            text-align: center;
            border-top: 3px solid #00ffff;
            color: #aaa;
        }}
        
        .footer strong {{
            color: #00ffff;
        }}
        
        .chart-container {{
            background: #2b2b3c;
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
        }}
        
        .bar {{
            height: 30px;
            background: #00ffff;
            border-radius: 5px;
            margin: 10px 0;
            position: relative;
            transition: width 0.3s;
        }}
        
        .bar-label {{
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: #1e1e2e;
            font-weight: bold;
        }}
        
        .host-info {{
            background: #2b2b3c;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #00ffff;
        }}
        
        .no-results {{
            text-align: center;
            padding: 40px;
            color: #888;
            font-size: 1.2em;
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {logo_img}
            <h1>🔍 SpectreScan</h1>
            <p>Professional Port Scanning Report</p>
            <p style="font-size: 0.9em; margin-top: 10px;">by BitSpectreLabs</p>
        </div>
        
        <div class="content">
            <!-- Scan Information -->
            <div class="section">
                <h2>📋 Scan Information</h2>
                <p><strong>Generated:</strong> {timestamp}</p>
                <p><strong>Tool:</strong> SpectreScan by BitSpectreLabs</p>
                {scan_info}
            </div>
            
            <!-- Summary Statistics -->
            <div class="section">
                <h2>📊 Summary Statistics</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <div class="value">{total_ports}</div>
                        <div class="label">Total Ports</div>
                    </div>
                    <div class="summary-card">
                        <div class="value open">{open_ports}</div>
                        <div class="label">Open Ports</div>
                    </div>
                    <div class="summary-card">
                        <div class="value closed">{closed_ports}</div>
                        <div class="label">Closed Ports</div>
                    </div>
                    <div class="summary-card">
                        <div class="value filtered">{filtered_ports}</div>
                        <div class="label">Filtered Ports</div>
                    </div>
                    <div class="summary-card">
                        <div class="value">{hosts_scanned}</div>
                        <div class="label">Hosts Scanned</div>
                    </div>
                    <div class="summary-card">
                        <div class="value">{scan_duration}</div>
                        <div class="label">Duration</div>
                    </div>
                </div>
            </div>
            
            {host_info_section}
            
            <!-- Open Ports -->
            <div class="section">
                <h2>🔓 Open Ports</h2>
                {open_ports_table}
            </div>
            
            <!-- All Results -->
            <div class="section">
                <h2>📝 All Scan Results</h2>
                {all_results_table}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by <strong>SpectreScan</strong> - Professional Port Scanner</p>
            <p>© {year} <strong>BitSpectreLabs</strong> | Open Source Security Tools</p>
        </div>
    </div>
</body>
</html>
"""


def generate_html_report(
    results: List[ScanResult],
    output_path: Path,
    summary: Optional[Dict] = None,
    host_info: Optional[Dict[str, HostInfo]] = None
) -> None:
    """
    Generate HTML report with styling and branding.
    
    Args:
        results: List of scan results
        output_path: Output file path
        summary: Optional scan summary
        host_info: Optional host information
    """
    from datetime import datetime
    import base64
    
    timestamp = get_timestamp()
    year = datetime.now().year
    
    # Try to embed logo as base64
    logo_img = ""
    try:
        logo_path = Path(__file__).parent.parent / "assets" / "logo.png"
        if logo_path.exists():
            with open(logo_path, "rb") as f:
                logo_data = base64.b64encode(f.read()).decode('utf-8')
                logo_img = f'<img src="data:image/png;base64,{logo_data}" alt="SpectreScan Logo" class="logo">'
    except Exception:
        # If logo can't be loaded, continue without it
        pass
    
    # Extract summary data
    if summary:
        total_ports = summary.get('total_ports', 0)
        open_ports = summary.get('open_ports', 0)
        closed_ports = summary.get('closed_ports', 0)
        filtered_ports = summary.get('filtered_ports', 0)
        hosts_scanned = summary.get('hosts_scanned', 0)
        scan_duration = summary.get('scan_duration', 'N/A')
        
        scan_info = f"""
                <p><strong>Start Time:</strong> {summary.get('start_time', 'N/A')}</p>
                <p><strong>End Time:</strong> {summary.get('end_time', 'N/A')}</p>
        """
    else:
        total_ports = len(results)
        open_ports = len([r for r in results if r.state == "open"])
        closed_ports = len([r for r in results if r.state == "closed"])
        filtered_ports = len([r for r in results if "filtered" in r.state])
        hosts_scanned = len(set(r.host for r in results))
        scan_duration = "N/A"
        scan_info = ""
    
    # Generate open ports table
    open_results = [r for r in results if r.state == "open"]
    
    if open_results:
        open_ports_table = """
                <table>
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for result in open_results:
            service = result.service or "unknown"
            banner = result.banner[:100] + "..." if result.banner and len(result.banner) > 100 else (result.banner or "")
            banner = banner.replace('<', '&lt;').replace('>', '&gt;')
            
            open_ports_table += f"""
                        <tr>
                            <td>{result.host}</td>
                            <td><strong>{result.port}</strong></td>
                            <td>{result.protocol.upper()}</td>
                            <td>{service}</td>
                            <td><code>{banner}</code></td>
                        </tr>
            """
        
        open_ports_table += """
                    </tbody>
                </table>
        """
    else:
        open_ports_table = '<div class="no-results">No open ports found</div>'
    
    # Generate all results table
    if results:
        all_results_table = """
                <table>
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for result in results:
            service = result.service or "unknown"
            banner = result.banner[:80] + "..." if result.banner and len(result.banner) > 80 else (result.banner or "")
            banner = banner.replace('<', '&lt;').replace('>', '&gt;')
            
            # Badge class based on state
            if result.state == "open":
                badge_class = "badge-open"
            elif result.state == "closed":
                badge_class = "badge-closed"
            else:
                badge_class = "badge-filtered"
            
            all_results_table += f"""
                        <tr>
                            <td>{result.host}</td>
                            <td>{result.port}</td>
                            <td>{result.protocol.upper()}</td>
                            <td><span class="badge {badge_class}">{result.state}</span></td>
                            <td>{service}</td>
                            <td><code>{banner}</code></td>
                        </tr>
            """
        
        all_results_table += """
                    </tbody>
                </table>
        """
    else:
        all_results_table = '<div class="no-results">No results available</div>'
    
    # Generate host info section
    host_info_section = ""
    if host_info:
        host_info_section = """
            <div class="section">
                <h2>🖥️ Host Information</h2>
        """
        
        for ip, info in host_info.items():
            hostname = info.hostname or "N/A"
            os_guess = info.os_guess or "Unknown"
            ttl = info.ttl or "N/A"
            
            host_info_section += f"""
                <div class="host-info">
                    <p><strong>IP:</strong> {ip}</p>
                    <p><strong>Hostname:</strong> {hostname}</p>
                    <p><strong>OS Guess:</strong> {os_guess}</p>
                    <p><strong>TTL:</strong> {ttl}</p>
                </div>
            """
        
        host_info_section += """
            </div>
        """
    
    # Generate HTML
    html = HTML_TEMPLATE.format(
        timestamp=timestamp,
        year=year,
        logo_img=logo_img,
        scan_info=scan_info,
        total_ports=total_ports,
        open_ports=open_ports,
        closed_ports=closed_ports,
        filtered_ports=filtered_ports,
        hosts_scanned=hosts_scanned,
        scan_duration=scan_duration,
        host_info_section=host_info_section,
        open_ports_table=open_ports_table,
        all_results_table=all_results_table
    )
    
    # Write to file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
