-- smtp-commands.nse
-- Lists SMTP commands supported by the server

description = [[
Attempts to use EHLO and HELP to gather the Extended SMTP commands
supported by a server.
]]

author = "Jasey DePriest, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.service == "smtp" or port.number == 25 or 
           port.number == 465 or port.number == 587
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number, "tcp")
    if not status then
        return nil
    end
    
    -- Receive banner
    status, banner = socket:receive()
    if not status then
        socket:close()
        return nil
    end
    
    -- Check for 220 greeting
    if not string.match(banner, "^220") then
        socket:close()
        return nil
    end
    
    local output = {}
    table.insert(output, "Banner: " .. string.match(banner, "220%s*([^\r\n]+)"))
    
    -- Send EHLO
    status, err = socket:send("EHLO spectrescan.local\r\n")
    if not status then
        socket:close()
        return table.concat(output, "\n  ")
    end
    
    status, response = socket:receive()
    if status and response then
        -- Parse EHLO response
        local commands = {}
        for line in string.gmatch(response, "250[%- ]([^\r\n]+)") do
            table.insert(commands, line)
        end
        
        if #commands > 0 then
            table.insert(output, "Commands: " .. table.concat(commands, ", "))
        end
        
        -- Check for STARTTLS
        if string.match(response, "STARTTLS") then
            table.insert(output, "STARTTLS: Supported")
        end
        
        -- Check for AUTH methods
        local auth = string.match(response, "AUTH%s+([^\r\n]+)")
        if auth then
            table.insert(output, "AUTH methods: " .. auth)
        end
    end
    
    -- Send QUIT
    socket:send("QUIT\r\n")
    socket:close()
    
    if #output > 0 then
        return table.concat(output, "\n  ")
    end
    
    return nil
end
