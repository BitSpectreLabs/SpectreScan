"""
mysql-info.py
Enumerate MySQL server information

Author: BitSpectreLabs
License: MIT
"""

import asyncio
from spectrescan.core.scripting_engine import Script, ScriptResult, ScriptCategory


class MysqlInfo(Script):
    """Retrieve MySQL server information."""
    
    name = "mysql-info"
    description = "Enumerate MySQL server version and details"
    author = "BitSpectreLabs"
    categories = [ScriptCategory.DISCOVERY, ScriptCategory.SAFE, ScriptCategory.VERSION]
    
    async def run(self, host, port=None, service=None, banner=None, **kwargs):
        """Execute the script."""
        if service and service.lower() not in ["mysql", "mariadb"]:
            return ScriptResult(
                script_name=self.name,
                host=host,
                port=port,
                success=False,
                output="Not a MySQL/MariaDB service"
            )
        
        try:
            port = port or 3306
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=10.0
            )
            
            # Read greeting packet
            greeting = await asyncio.wait_for(reader.read(512), timeout=5.0)
            
            writer.close()
            await writer.wait_closed()
            
            if len(greeting) > 5:
                # Parse MySQL greeting packet
                protocol_version = greeting[4]
                
                # Extract version string (null-terminated)
                version_end = greeting.index(b'\x00', 5)
                version = greeting[5:version_end].decode('utf-8', errors='ignore')
                
                output = f"Protocol version: {protocol_version}\nServer version: {version}"
                
                # Detect MariaDB vs MySQL
                is_mariadb = "mariadb" in version.lower()
                if is_mariadb:
                    output += "\nDatabase: MariaDB"
                else:
                    output += "\nDatabase: MySQL"
                
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=True,
                    output=output,
                    data={
                        "protocol": protocol_version,
                        "version": version,
                        "type": "MariaDB" if is_mariadb else "MySQL"
                    }
                )
            else:
                return ScriptResult(
                    script_name=self.name,
                    host=host,
                    port=port,
                    success=False,
                    output="Invalid MySQL greeting packet"
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
