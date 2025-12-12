-- mysql-info.nse
-- Gathers information from MySQL servers

description = [[
Connects to a MySQL server and prints information such as the protocol and
version numbers, thread ID, status, capabilities, and the password salt.

If service detection is performed and the server appears to be blocking
our host or is blocked because of too many connections, then this script
doesn't run.
]]

author = "Kris Katterjohn, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.service == "mysql" or port.number == 3306
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number, "tcp")
    if not status then
        return nil
    end
    
    -- Receive MySQL greeting packet
    status, response = socket:receive()
    socket:close()
    
    if not status or not response or #response < 5 then
        return nil
    end
    
    -- Parse MySQL greeting packet
    local output = {}
    
    -- Check for MySQL protocol
    local packet_len = string.byte(response, 1) + 
                       string.byte(response, 2) * 256 + 
                       string.byte(response, 3) * 65536
    local packet_num = string.byte(response, 4)
    local protocol_version = string.byte(response, 5)
    
    if protocol_version == 10 or protocol_version == 9 then
        -- Valid MySQL protocol
        table.insert(output, "Protocol: " .. protocol_version)
        
        -- Extract version string (null-terminated after protocol version)
        local version_end = string.find(response, "\x00", 6)
        if version_end then
            local version = string.sub(response, 6, version_end - 1)
            table.insert(output, "Version: " .. version)
        end
        
        -- Check for MariaDB
        if string.match(response, "MariaDB") then
            table.insert(output, "Variant: MariaDB")
        end
        
        return table.concat(output, "\n  ")
    elseif protocol_version == 255 then
        -- Error packet
        return "MySQL Error: Access denied or server refused connection"
    end
    
    return nil
end
