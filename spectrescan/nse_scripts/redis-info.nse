-- redis-info.nse
-- Gathers information from a Redis server

description = [[
Retrieves information (such as version number and architecture) from a Redis key-value store.
]]

author = "Patrik Karlsson, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.service == "redis" or port.number == 6379
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number, "tcp")
    if not status then
        return nil
    end
    
    -- Send INFO command (RESP protocol)
    status, err = socket:send("*1\r\n$4\r\nINFO\r\n")
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
    
    -- Check for error (authentication required)
    if string.match(response, "%-NOAUTH") then
        return "Redis: Authentication required"
    end
    
    if string.match(response, "%-ERR") then
        return nil
    end
    
    -- Parse INFO response
    local output = {}
    
    local version = string.match(response, "redis_version:([^\r\n]+)")
    if version then
        table.insert(output, "Version: " .. version)
    end
    
    local os = string.match(response, "os:([^\r\n]+)")
    if os then
        table.insert(output, "OS: " .. os)
    end
    
    local arch = string.match(response, "arch_bits:([^\r\n]+)")
    if arch then
        table.insert(output, "Architecture: " .. arch .. "-bit")
    end
    
    local mode = string.match(response, "redis_mode:([^\r\n]+)")
    if mode then
        table.insert(output, "Mode: " .. mode)
    end
    
    local clients = string.match(response, "connected_clients:([^\r\n]+)")
    if clients then
        table.insert(output, "Connected clients: " .. clients)
    end
    
    local memory = string.match(response, "used_memory_human:([^\r\n]+)")
    if memory then
        table.insert(output, "Memory used: " .. memory)
    end
    
    if #output > 0 then
        return table.concat(output, "\n  ")
    end
    
    return nil
end
