-- http-headers.nse
-- Shows HTTP headers from the response

description = [[
Performs a HEAD request for the root folder ("/") of a web server and displays the HTTP headers returned.
]]

author = "Ron Bowes, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

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
    
    -- Send HEAD request
    local request = "HEAD / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: SpectreScan/2.1\r\nConnection: close\r\n\r\n"
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
    
    -- Parse headers
    local output = {}
    local header_end = string.find(response, "\r\n\r\n")
    
    if header_end then
        local headers_str = string.sub(response, 1, header_end)
        
        for line in string.gmatch(headers_str, "[^\r\n]+") do
            table.insert(output, line)
        end
    end
    
    if #output > 0 then
        return table.concat(output, "\n  ")
    end
    
    return nil
end
