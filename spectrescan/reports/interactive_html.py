"""
Interactive HTML Report Generator for SpectreScan
by BitSpectreLabs
"""

from typing import List, Dict, Optional
from pathlib import Path
from datetime import datetime
from spectrescan.core.utils import ScanResult, HostInfo


def generate_interactive_html_report(
    results: List[ScanResult],
    output_path: Path,
    summary: Optional[Dict] = None,
    host_info: Optional[Dict[str, HostInfo]] = None
) -> None:
    """
    Generate interactive HTML report with JavaScript features.
    
    Features:
    - Live search/filter
    - Sortable columns
    - Expandable port details
    - State filtering (open/closed/filtered)
    - Copy to clipboard
    - Dark mode toggle
    
    Args:
        results: List of scan results
        summary: Optional scan summary
        host_info: Optional host information
        output_path: Output file path
    """
    # Prepare data
    open_ports = [r for r in results if r.state == 'open']
    closed_ports = [r for r in results if r.state == 'closed']
    filtered_ports = [r for r in results if r.state == 'filtered']
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SpectreScan Interactive Report</title>
    <style>
        :root {{
            --primary-color: #6B46C1;
            --bg-color: #ffffff;
            --text-color: #1a202c;
            --border-color: #e2e8f0;
            --card-bg: #f7fafc;
            --hover-bg: #edf2f7;
        }}
        
        [data-theme="dark"] {{
            --bg-color: #1a202c;
            --text-color: #f7fafc;
            --border-color: #2d3748;
            --card-bg: #2d3748;
            --hover-bg: #4a5568;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            padding: 20px;
            transition: background 0.3s, color 0.3s;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 30px;
            padding: 30px;
            background: linear-gradient(135deg, var(--primary-color), #805AD5);
            color: white;
            border-radius: 10px;
        }}
        
        .header h1 {{
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        
        .controls {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 12px 20px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            font-size: 16px;
            background: var(--bg-color);
            color: var(--text-color);
        }}
        
        .filter-buttons {{
            display: flex;
            gap: 10px;
        }}
        
        .filter-btn {{
            padding: 10px 20px;
            border: 2px solid var(--border-color);
            border-radius: 8px;
            background: var(--card-bg);
            color: var(--text-color);
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }}
        
        .filter-btn:hover {{
            background: var(--hover-bg);
        }}
        
        .filter-btn.active {{
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }}
        
        .theme-toggle {{
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            background: var(--primary-color);
            color: white;
            cursor: pointer;
            font-size: 14px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
            text-align: center;
        }}
        
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            color: var(--primary-color);
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            color: var(--text-color);
            opacity: 0.7;
        }}
        
        .results-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 10px;
            overflow: hidden;
        }}
        
        .results-table th {{
            background: var(--primary-color);
            color: white;
            padding: 15px;
            text-align: left;
            cursor: pointer;
            user-select: none;
        }}
        
        .results-table th:hover {{
            background: #805AD5;
        }}
        
        .results-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .results-table tr:hover {{
            background: var(--hover-bg);
        }}
        
        .state-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .state-open {{
            background: #48BB78;
            color: white;
        }}
        
        .state-closed {{
            background: #F56565;
            color: white;
        }}
        
        .state-filtered {{
            background: #ED8936;
            color: white;
        }}
        
        .details-btn {{
            padding: 5px 15px;
            border: none;
            border-radius: 5px;
            background: var(--primary-color);
            color: white;
            cursor: pointer;
            font-size: 0.85em;
        }}
        
        .details {{
            display: none;
            padding: 15px;
            background: var(--bg-color);
            border-radius: 5px;
            margin-top: 10px;
        }}
        
        .details.show {{
            display: block;
        }}
        
        .copy-btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 5px;
            background: #4299E1;
            color: white;
            cursor: pointer;
            font-size: 0.9em;
            margin-top: 10px;
        }}
        
        .hidden {{
            display: none !important;
        }}
        
        .no-results {{
            text-align: center;
            padding: 40px;
            font-size: 1.2em;
            color: var(--text-color);
            opacity: 0.6;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 SpectreScan Interactive Report</h1>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p style="font-size: 0.9em; margin-top: 10px;">by BitSpectreLabs</p>
    </div>
    
    <div class="controls">
        <input type="text" class="search-box" id="searchBox" placeholder="Search ports, services, banners...">
        
        <div class="filter-buttons">
            <button class="filter-btn active" data-filter="all">All ({len(results)})</button>
            <button class="filter-btn" data-filter="open">Open ({len(open_ports)})</button>
            <button class="filter-btn" data-filter="closed">Closed ({len(closed_ports)})</button>
            <button class="filter-btn" data-filter="filtered">Filtered ({len(filtered_ports)})</button>
        </div>
        
        <button class="theme-toggle" id="themeToggle">🌙 Dark Mode</button>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{summary.get('total_scanned', len(results)) if summary else len(results)}</div>
            <div class="stat-label">Total Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(open_ports)}</div>
            <div class="stat-label">Open Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(closed_ports)}</div>
            <div class="stat-label">Closed Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{len(filtered_ports)}</div>
            <div class="stat-label">Filtered Ports</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{summary.get('scan_time', 'N/A') if summary else 'N/A'}</div>
            <div class="stat-label">Scan Time (s)</div>
        </div>
    </div>
    
    <table class="results-table" id="resultsTable">
        <thead>
            <tr>
                <th data-sort="host">Host</th>
                <th data-sort="port">Port</th>
                <th data-sort="protocol">Protocol</th>
                <th data-sort="state">State</th>
                <th data-sort="service">Service</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="resultsBody">
"""
    
    # Add table rows
    for result in results:
        state_class = f"state-{result.state}"
        banner_info = result.banner.replace('<', '&lt;').replace('>', '&gt;') if result.banner else 'No banner captured'
        
        html += f"""
            <tr data-state="{result.state}" data-searchtext="{result.host} {result.port} {result.protocol} {result.state} {result.service or ''} {result.banner or ''}">
                <td>{result.host}</td>
                <td>{result.port}</td>
                <td>{result.protocol.upper()}</td>
                <td><span class="state-badge {state_class}">{result.state}</span></td>
                <td>{result.service or '-'}</td>
                <td>
                    <button class="details-btn" onclick="toggleDetails(this)">Details</button>
                    <div class="details">
                        <strong>Port:</strong> {result.port}/{result.protocol}<br>
                        <strong>State:</strong> {result.state}<br>
                        <strong>Service:</strong> {result.service or 'Unknown'}<br>
                        <strong>Banner:</strong><br>
                        <pre>{banner_info}</pre>
                        <button class="copy-btn" onclick="copyToClipboard('{result.host}:{result.port}')">Copy Address</button>
                    </div>
                </td>
            </tr>
"""
    
    html += """
        </tbody>
    </table>
    
    <div class="no-results hidden" id="noResults">
        No results found matching your filters.
    </div>
    
    <script>
        // Search functionality
        const searchBox = document.getElementById('searchBox');
        const resultsBody = document.getElementById('resultsBody');
        const noResults = document.getElementById('noResults');
        const filterButtons = document.querySelectorAll('.filter-btn');
        let currentFilter = 'all';
        
        searchBox.addEventListener('input', filterResults);
        
        filterButtons.forEach(btn => {
            btn.addEventListener('click', function() {
                filterButtons.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                currentFilter = this.dataset.filter;
                filterResults();
            });
        });
        
        function filterResults() {
            const searchTerm = searchBox.value.toLowerCase();
            const rows = resultsBody.querySelectorAll('tr');
            let visibleCount = 0;
            
            rows.forEach(row => {
                const searchText = row.dataset.searchtext.toLowerCase();
                const state = row.dataset.state;
                
                const matchesSearch = searchText.includes(searchTerm);
                const matchesFilter = currentFilter === 'all' || state === currentFilter;
                
                if (matchesSearch && matchesFilter) {
                    row.classList.remove('hidden');
                    visibleCount++;
                } else {
                    row.classList.add('hidden');
                }
            });
            
            if (visibleCount === 0) {
                document.querySelector('.results-table').style.display = 'none';
                noResults.classList.remove('hidden');
            } else {
                document.querySelector('.results-table').style.display = 'table';
                noResults.classList.add('hidden');
            }
        }
        
        // Sort functionality
        const headers = document.querySelectorAll('.results-table th[data-sort]');
        let sortDirection = {};
        
        headers.forEach(header => {
            sortDirection[header.dataset.sort] = 1;
            
            header.addEventListener('click', function() {
                const column = this.dataset.sort;
                const rows = Array.from(resultsBody.querySelectorAll('tr'));
                
                rows.sort((a, b) => {
                    let aVal, bVal;
                    
                    if (column === 'port') {
                        aVal = parseInt(a.children[1].textContent);
                        bVal = parseInt(b.children[1].textContent);
                    } else {
                        const colIndex = Array.from(this.parentNode.children).indexOf(this);
                        aVal = a.children[colIndex].textContent.toLowerCase();
                        bVal = b.children[colIndex].textContent.toLowerCase();
                    }
                    
                    if (aVal < bVal) return -1 * sortDirection[column];
                    if (aVal > bVal) return 1 * sortDirection[column];
                    return 0;
                });
                
                sortDirection[column] *= -1;
                
                rows.forEach(row => resultsBody.appendChild(row));
            });
        });
        
        // Toggle details
        function toggleDetails(btn) {
            const details = btn.nextElementSibling;
            details.classList.toggle('show');
            btn.textContent = details.classList.contains('show') ? 'Hide' : 'Details';
        }
        
        // Copy to clipboard
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('Copied to clipboard: ' + text);
            });
        }
        
        // Dark mode toggle
        const themeToggle = document.getElementById('themeToggle');
        const html = document.documentElement;
        
        // Load saved theme
        if (localStorage.getItem('theme') === 'dark') {
            html.setAttribute('data-theme', 'dark');
            themeToggle.textContent = '☀️ Light Mode';
        }
        
        themeToggle.addEventListener('click', function() {
            const currentTheme = html.getAttribute('data-theme');
            
            if (currentTheme === 'dark') {
                html.removeAttribute('data-theme');
                themeToggle.textContent = '🌙 Dark Mode';
                localStorage.setItem('theme', 'light');
            } else {
                html.setAttribute('data-theme', 'dark');
                themeToggle.textContent = '☀️ Light Mode';
                localStorage.setItem('theme', 'dark');
            }
        });
    </script>
</body>
</html>
"""
    
    # Write file
    output_path.write_text(html, encoding='utf-8')
