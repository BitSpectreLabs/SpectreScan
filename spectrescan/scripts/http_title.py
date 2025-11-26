"""
http-title.py
Extract HTTP page title

Author: BitSpectreLabs
License: MIT
"""

import asyncio
import re
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class HttpTitle(Script):
    """Extract title from HTTP response."""
    
    name = "http-title"
    description = "Extract HTML title from HTTP service"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.DISCOVERY, ScriptCategory.SAFE, ScriptCategory.DEFAULT]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        if service and service.lower() not in ["http", "https"]:
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="Not an HTTP service",
                error="Service is not HTTP/HTTPS"
            )
        
        try:
            port = port or 80
            # Connect and send HTTP request
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(reader.read(8192), timeout=5.0)
            response_text = response.decode('utf-8', errors='ignore')
            
            writer.close()
            await writer.wait_closed()
            
            # Extract title
            title_match = re.search(r'<title[^>]*>(.*?)</title>', response_text, re.IGNORECASE | re.DOTALL)
            
            if title_match:
                title = title_match.group(1).strip()
                # Clean up title
                title = re.sub(r'\s+', ' ', title)
                
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output=f"Title: {title}",
                    data={"title": title}
                )
            else:
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output="No title found",
                    data={"title": None}
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
