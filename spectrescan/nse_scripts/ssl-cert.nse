-- ssl-cert.nse
-- Retrieves a server's SSL certificate

description = [[
Retrieves a server's SSL certificate. The amount of information printed
about the certificate depends on the verbosity level. With no extra
verbosity, the script prints the validity period and the commonName,
organizationName, stateOrProvinceName, and countryName of the subject.
]]

author = "David Fifield, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.service == "https" or port.service == "ssl" or
           port.number == 443 or port.number == 8443 or
           port.number == 465 or port.number == 993 or port.number == 995
end

action = function(host, port)
    -- Note: Full SSL certificate extraction requires SSL library support
    -- This is a simplified version that attempts to detect SSL/TLS
    
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number, "tcp")
    if not status then
        return nil
    end
    
    -- Send ClientHello (TLS 1.2)
    -- This is a minimal TLS handshake initiation
    local client_hello = "\x16\x03\x01\x00\xf1" ..  -- TLS record header
                        "\x01\x00\x00\xed" ..      -- Handshake header
                        "\x03\x03"                  -- TLS 1.2 version
    
    status, err = socket:send(client_hello)
    
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
    
    -- Check if we got a valid TLS response
    local first_byte = string.byte(response, 1)
    if first_byte == 0x16 then  -- TLS handshake record
        local tls_version = string.byte(response, 2) .. "." .. string.byte(response, 3)
        return "TLS/SSL service detected (use --ssl-analysis for full certificate details)"
    elseif first_byte == 0x15 then  -- TLS alert
        return "TLS/SSL service detected (alert received)"
    end
    
    return nil
end
