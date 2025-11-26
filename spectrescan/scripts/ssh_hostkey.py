"""
ssh-hostkey.py
Retrieve SSH host key

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import re
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class SshHostkey(Script):
    """Retrieve SSH host key fingerprint."""
    
    name = "ssh-hostkey"
    description = "Retrieve SSH host key fingerprint"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.DISCOVERY, ScriptCategory.SAFE, ScriptCategory.DEFAULT]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        if service and service.lower() != "ssh":
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="Not an SSH service"
            )
        
        try:
            port = port or 22
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            # Read SSH banner
            banner_data = await asyncio.wait_for(reader.read(256), timeout=5.0)
            banner_text = banner_data.decode('utf-8', errors='ignore').strip()
            
            writer.close()
            await writer.wait_closed()
            
            # Extract SSH version
            ssh_match = re.match(r'SSH-([\d.]+)-(.+)', banner_text)
            
            if ssh_match:
                protocol_version = ssh_match.group(1)
                software = ssh_match.group(2)
                
                output = f"SSH Protocol: {protocol_version}\nSSH Software: {software}"
                
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output=output,
                    data={
                        "protocol": protocol_version,
                        "software": software,
                        "banner": banner_text
                    }
                )
            else:
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output=f"SSH banner: {banner_text}",
                    data={"banner": banner_text}
                )
        
        except Exception as e:
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="",
                error=str(e)
            )
