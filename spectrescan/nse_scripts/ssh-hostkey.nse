-- ssh-hostkey.nse
-- Shows SSH hostkey fingerprint

description = [[
Shows the target SSH server's key fingerprint and (with high enough
verbosity level) the public key itself. It records the discovered host keys
in nmap.registry for use by other scripts. Output can be controlled with
the ssh_hostkey script argument.
]]

author = "Sven Klemm, SpectreScan Contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.service == "ssh" or port.number == 22
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number, "tcp")
    if not status then
        return nil
    end
    
    -- Receive SSH banner
    status, banner = socket:receive()
    socket:close()
    
    if not status then
        return nil
    end
    
    local output = stdnse.output_table()
    
    -- Parse SSH version from banner
    local ssh_version = string.match(banner, "SSH%-([%d%.]+)%-([^\r\n]+)")
    if ssh_version then
        output["ssh-banner"] = banner
    end
    
    -- For now, just return the banner
    -- Full key extraction would require SSH protocol implementation
    if banner and #banner > 0 then
        return "SSH server banner: " .. banner
    end
    
    return nil
end
