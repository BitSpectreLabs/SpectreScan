"""
ftp-anon.py
Check for anonymous FTP access

Author: BitSpectreLabs
License: MIT
"""

import asyncio
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class FtpAnon(Script):
    """Check if anonymous FTP login is allowed."""
    
    name = "ftp-anon"
    description = "Check for anonymous FTP access"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.AUTH, ScriptCategory.SAFE, ScriptCategory.DEFAULT]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        if service and service.lower() != "ftp":
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="Not an FTP service"
            )
        
        try:
            port = port or 21
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            # Read welcome banner
            welcome = await asyncio.wait_for(reader.read(512), timeout=5.0)
            
            # Try anonymous login
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            user_response = await asyncio.wait_for(reader.read(512), timeout=5.0)
            
            writer.write(b"PASS anonymous@example.com\r\n")
            await writer.drain()
            pass_response = await asyncio.wait_for(reader.read(512), timeout=5.0)
            
            writer.close()
            await writer.wait_closed()
            
            # Check if login successful
            pass_text = pass_response.decode('utf-8', errors='ignore')
            
            if pass_text.startswith('230'):
                # Anonymous login successful
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output="Anonymous FTP login allowed!\nSecurity Risk: Unauthenticated access permitted",
                    data={"anonymous_allowed": True, "risk": "high"}
                )
            else:
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output="Anonymous FTP login not allowed",
                    data={"anonymous_allowed": False}
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
