"""
Nmap-Compatible Output Format
Generate greppable and XML output formats compatible with Nmap.

Author: BitSpectreLabs
License: MIT
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
import xml.etree.ElementTree as ET
from xml.dom import minidom

logger = logging.getLogger(__name__)


class NmapOutputFormatter:
    """
    Generate Nmap-compatible output formats.
    Supports: greppable (.gnmap), XML (.xml), normal (.nmap)
    """
    
    def __init__(self):
        """Initialize formatter."""
        pass
    
    def generate_greppable(
        self,
        results: List[Any],
        output_path: Path,
        scan_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Generate greppable output format (.gnmap).
        
        Format:
        # Nmap scan initiated at [timestamp]
        Host: [host] ([hostname]) Status: Up
        Host: [host] ([hostname]) Ports: [port/state/protocol/owner/service/rpc/version]
        
        Args:
            results: List of scan results
            output_path: Output file path
            scan_info: Scan metadata
        """
        lines = []
        
        # Header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"# SpectreScan greppable output format")
        lines.append(f"# Nmap-compatible scan initiated at {timestamp}")
        
        if scan_info:
            lines.append(f"# Scan type: {scan_info.get('type', 'unknown')}")
            lines.append(f"# Target: {scan_info.get('target', 'unknown')}")
        
        lines.append("")
        
        # Group results by host
        host_results = {}
        for result in results:
            host = getattr(result, 'host', 'unknown')
            if host not in host_results:
                host_results[host] = []
            host_results[host].append(result)
        
        # Generate output for each host
        for host, ports in host_results.items():
            # Host status line
            hostname = self._get_hostname(host)
            lines.append(f"Host: {host}\t({hostname})\tStatus: Up")
            
            # Ports line
            port_strings = []
            for result in ports:
                port = getattr(result, 'port', 0)
                state = getattr(result, 'state', 'unknown')
                protocol = getattr(result, 'protocol', 'tcp').lower()
                service = getattr(result, 'service', '')
                
                # Format: port/state/protocol/owner/service/sunrpcinfo/version
                port_str = f"{port}/{state}/{protocol}///{service}//"
                port_strings.append(port_str)
            
            if port_strings:
                ports_line = f"Host: {host}\t({hostname})\tPorts: {', '.join(port_strings)}"
                lines.append(ports_line)
        
        # Footer
        lines.append(f"# SpectreScan done at {timestamp}")
        lines.append("")
        
        # Write to file
        output_path.write_text('\n'.join(lines))
        logger.info(f"Greppable output written to {output_path}")
    
    def generate_xml(
        self,
        results: List[Any],
        output_path: Path,
        scan_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Generate XML output format (.xml).
        
        Nmap-compatible XML structure:
        <nmaprun>
          <scaninfo type="..." protocol="..." />
          <host>
            <address addr="..." addrtype="ipv4" />
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open" />
                <service name="http" product="nginx" version="1.18.0" />
              </port>
            </ports>
          </host>
        </nmaprun>
        
        Args:
            results: List of scan results
            output_path: Output file path
            scan_info: Scan metadata
        """
        # Create root element
        root = ET.Element('nmaprun')
        root.set('scanner', 'spectrescan')
        root.set('start', str(int(datetime.now().timestamp())))
        root.set('version', '1.2.0')
        
        # Scan info
        if scan_info:
            scaninfo = ET.SubElement(root, 'scaninfo')
            scaninfo.set('type', scan_info.get('type', 'syn'))
            scaninfo.set('protocol', scan_info.get('protocol', 'tcp'))
            scaninfo.set('numservices', str(len(results)))
        
        # Group results by host
        host_results = {}
        for result in results:
            host = getattr(result, 'host', 'unknown')
            if host not in host_results:
                host_results[host] = []
            host_results[host].append(result)
        
        # Generate host elements
        for host_addr, ports in host_results.items():
            host_elem = ET.SubElement(root, 'host')
            
            # Status
            status = ET.SubElement(host_elem, 'status')
            status.set('state', 'up')
            status.set('reason', 'user-set')
            
            # Address
            address = ET.SubElement(host_elem, 'address')
            address.set('addr', host_addr)
            address.set('addrtype', 'ipv4')
            
            # Ports
            ports_elem = ET.SubElement(host_elem, 'ports')
            
            for result in ports:
                port_elem = ET.SubElement(ports_elem, 'port')
                port_elem.set('protocol', getattr(result, 'protocol', 'tcp').lower())
                port_elem.set('portid', str(getattr(result, 'port', 0)))
                
                # State
                state_elem = ET.SubElement(port_elem, 'state')
                state_elem.set('state', getattr(result, 'state', 'unknown'))
                
                # Service
                service = getattr(result, 'service', None)
                if service:
                    service_elem = ET.SubElement(port_elem, 'service')
                    service_elem.set('name', service)
                    
                    product = getattr(result, 'product', None)
                    if product:
                        service_elem.set('product', product)
                    
                    version = getattr(result, 'version', None)
                    if version:
                        service_elem.set('version', version)
                    
                    # CPE
                    cpe_list = getattr(result, 'cpe', [])
                    if cpe_list:
                        for cpe_str in cpe_list:
                            cpe_elem = ET.SubElement(service_elem, 'cpe')
                            cpe_elem.text = cpe_str
        
        # Format XML with proper indentation
        xml_string = self._prettify_xml(root)
        
        # Write to file
        output_path.write_text(xml_string)
        logger.info(f"XML output written to {output_path}")
    
    def generate_normal(
        self,
        results: List[Any],
        output_path: Path,
        scan_info: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Generate normal text output format (.nmap).
        
        Format similar to Nmap's default output:
        Starting SpectreScan at [timestamp]
        Scan report for [host]
        PORT     STATE  SERVICE  VERSION
        80/tcp   open   http     nginx 1.18.0
        
        Args:
            results: List of scan results
            output_path: Output file path
            scan_info: Scan metadata
        """
        lines = []
        
        # Header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"Starting SpectreScan at {timestamp}")
        
        if scan_info:
            lines.append(f"Scan type: {scan_info.get('type', 'syn')}")
            lines.append(f"Target specification: {scan_info.get('target', 'unknown')}")
        
        lines.append("")
        
        # Group results by host
        host_results = {}
        for result in results:
            host = getattr(result, 'host', 'unknown')
            if host not in host_results:
                host_results[host] = []
            host_results[host].append(result)
        
        # Generate output for each host
        for host, ports in host_results.items():
            hostname = self._get_hostname(host)
            lines.append(f"Scan report for {host}")
            if hostname != host:
                lines.append(f"Host is up ({hostname})")
            else:
                lines.append("Host is up")
            
            lines.append("")
            lines.append("PORT       STATE     SERVICE      VERSION")
            
            for result in ports:
                port = getattr(result, 'port', 0)
                protocol = getattr(result, 'protocol', 'tcp').lower()
                state = getattr(result, 'state', 'unknown')
                service = getattr(result, 'service', '')
                
                # Build version string
                version_parts = []
                product = getattr(result, 'product', None)
                if product:
                    version_parts.append(product)
                
                version = getattr(result, 'version', None)
                if version:
                    version_parts.append(version)
                
                version_str = ' '.join(version_parts) if version_parts else ''
                
                # Format line
                port_str = f"{port}/{protocol}"
                line = f"{port_str:<10} {state:<9} {service:<12} {version_str}"
                lines.append(line)
            
            lines.append("")
        
        # Footer
        lines.append(f"SpectreScan done at {timestamp}")
        lines.append("")
        
        # Write to file
        output_path.write_text('\n'.join(lines))
        logger.info(f"Normal output written to {output_path}")
    
    def _get_hostname(self, host: str) -> str:
        """Get hostname for IP (placeholder)."""
        # In production, this would do reverse DNS lookup
        return host
    
    def _prettify_xml(self, elem: ET.Element) -> str:
        """Return a pretty-printed XML string."""
        rough_string = ET.tostring(elem, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")


def auto_detect_format(output_path: Path) -> str:
    """
    Auto-detect output format from file extension.
    
    Args:
        output_path: Output file path
    
    Returns:
        Format type: "greppable", "xml", or "normal"
    """
    suffix = output_path.suffix.lower()
    
    if suffix == '.gnmap':
        return 'greppable'
    elif suffix == '.xml':
        return 'xml'
    elif suffix == '.nmap':
        return 'normal'
    else:
        # Default to normal
        return 'normal'
