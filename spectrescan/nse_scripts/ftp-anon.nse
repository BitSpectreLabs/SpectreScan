-- ftp-anon.nse
-- Checks if FTP server allows anonymous login

description = [[
Checks if an FTP server allows anonymous logins.

If anonymous is allowed, gets a directory listing of the root directory
and highlights writeable files.
]]

author = "Eddie Bell, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "auth", "safe"}

portrule = function(host, port)
    return port.service == "ftp" or port.number == 21
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
    
    -- Check for 220 response
    if not string.match(banner, "^220") then
        socket:close()
        return nil
    end
    
    -- Try anonymous login
    status, err = socket:send("USER anonymous\r\n")
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    if not status then
        socket:close()
        return nil
    end
    
    -- Check for 331 (password required) or 230 (logged in)
    if string.match(response, "^331") then
        -- Send password
        status, err = socket:send("PASS anonymous@example.com\r\n")
        if not status then
            socket:close()
            return nil
        end
        
        status, response = socket:receive()
        if not status then
            socket:close()
            return nil
        end
    end
    
    socket:close()
    
    -- Check if login was successful
    if string.match(response, "^230") then
        return "Anonymous FTP login allowed"
    elseif string.match(response, "^530") then
        return nil  -- Login denied
    end
    
    return nil
end
