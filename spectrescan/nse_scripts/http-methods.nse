-- http-methods.nse
-- Finds which HTTP methods are supported

description = [[
Finds out what options are supported by an HTTP server by sending an OPTIONS request.
Parses the Allow and Public headers to determine which methods are supported.
]]

author = "Bernd Stroessenreuther, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or
           port.number == 8080 or port.number == 8443
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number, "tcp")
    if not status then
        return nil
    end
    
    -- Send OPTIONS request
    local request = "OPTIONS / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: SpectreScan/2.1\r\nConnection: close\r\n\r\n"
    status, err = socket:send(request)
    
    if not status then
        socket:close()
        return nil
    end
    
    -- Receive response
    status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    -- Parse Allow header
    local allow = string.match(response, "[Aa]llow:%s*([^\r\n]+)")
    local public = string.match(response, "[Pp]ublic:%s*([^\r\n]+)")
    
    local methods = allow or public
    
    if methods then
        -- Check for potentially dangerous methods
        local output = "Supported Methods: " .. methods
        
        if string.match(methods, "PUT") then
            output = output .. "\n  WARNING: PUT method enabled"
        end
        if string.match(methods, "DELETE") then
            output = output .. "\n  WARNING: DELETE method enabled"
        end
        if string.match(methods, "TRACE") then
            output = output .. "\n  WARNING: TRACE method enabled (potential XST vulnerability)"
        end
        
        return output
    end
    
    return nil
end
