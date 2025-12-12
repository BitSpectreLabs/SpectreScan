-- http-title.nse
-- Nmap compatible script to fetch HTTP page title

description = [[
Shows the title of the default page of a web server.

The script will follow up to 5 HTTP redirects, using the URL
from the Location header.
]]

author = "Diman Todorov, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or
           port.number == 8080 or port.number == 8443
end

action = function(host, port)
    local socket = nmap.new_socket()
    local status, err = socket:connect(host.ip, port.number, "tcp")
    
    if not status then
        return nil
    end
    
    -- Send HTTP request
    local request = "GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\nUser-Agent: SpectreScan/2.1\r\nConnection: close\r\n\r\n"
    status, err = socket:send(request)
    
    if not status then
        socket:close()
        return nil
    end
    
    -- Receive response
    status, response = socket:receive()
    socket:close()
    
    if not status then
        return nil
    end
    
    -- Extract title
    local title = string.match(response, "<[Tt][Ii][Tt][Ll][Ee]>([^<]+)</[Tt][Ii][Tt][Ll][Ee]>")
    
    if title then
        -- Clean up whitespace
        title = string.gsub(title, "^%s+", "")
        title = string.gsub(title, "%s+$", "")
        title = string.gsub(title, "%s+", " ")
        
        if #title > 65 then
            title = string.sub(title, 1, 62) .. "..."
        end
        
        return title
    end
    
    return nil
end
