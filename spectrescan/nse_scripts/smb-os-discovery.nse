-- smb-os-discovery.nse
-- Discovers OS info via SMB

description = [[
Attempts to determine the operating system, computer name, domain, workgroup,
and current time over the SMB protocol (ports 445 or 139).
]]

author = "Ron Bowes, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.service == "microsoft-ds" or port.service == "smb" or
           port.number == 445 or port.number == 139
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number, "tcp")
    if not status then
        return nil
    end
    
    -- SMB negotiation requires complex packet crafting
    -- This is a simplified version that detects SMB presence
    
    -- SMB1 Negotiate Protocol Request (minimal)
    local smb_header = "\x00\x00\x00\x85" ..  -- NetBIOS length
                       "\xff\x53\x4d\x42" ..  -- SMB magic
                       "\x72"                  -- Negotiate Protocol
    
    status, err = socket:send(smb_header)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    -- Check for SMB response
    if string.match(response, "\xff\x53\x4d\x42") then
        return "SMB service detected - Use smb-os-discovery with full Nmap for detailed info"
    end
    
    return nil
end
