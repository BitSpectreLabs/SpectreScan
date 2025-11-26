"""
smtp-commands.py
Enumerate SMTP commands

Author: BitSpectreLabs
License: MIT
"""

import asyncio
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class SmtpCommands(Script):
    """Enumerate supported SMTP commands."""
    
    name = "smtp-commands"
    description = "Enumerate SMTP commands (HELP)"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.DISCOVERY, ScriptCategory.SAFE]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        if service and service.lower() != "smtp":
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="Not an SMTP service"
            )
        
        try:
            port = port or 25
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            # Read greeting
            await asyncio.wait_for(reader.read(512), timeout=5.0)
            
            # Send EHLO
            writer.write(f"EHLO scanner.local\r\n".encode())
            await writer.drain()
            ehlo_response = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            
            # Send HELP
            writer.write(b"HELP\r\n")
            await writer.drain()
            help_response = await asyncio.wait_for(reader.read(2048), timeout=5.0)
            
            writer.write(b"QUIT\r\n")
            await writer.drain()
            
            writer.close()
            await writer.wait_closed()
            
            # Parse responses
            ehlo_text = ehlo_response.decode('utf-8', errors='ignore')
            help_text = help_response.decode('utf-8', errors='ignore')
            
            commands = []
            output_lines = []
            
            # Extract commands from EHLO
            for line in ehlo_text.split('\r\n'):
                if line.startswith('250-') or line.startswith('250 '):
                    cmd = line[4:].strip()
                    if cmd and cmd not in commands:
                        commands.append(cmd)
                        output_lines.append(f"  {cmd}")
            
            output = "SMTP Commands:\n" + "\n".join(output_lines)
            
            # Check for dangerous commands
            dangerous = [cmd for cmd in commands if any(d in cmd.upper() for d in ['EXPN', 'VRFY', 'ETRN'])]
            if dangerous:
                output += f"\n\nWarning: Potentially dangerous commands enabled: {', '.join(dangerous)}"
            
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=True,
                output=output,
                data={"commands": commands, "dangerous": dangerous}
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
