--[[


]]
local iputils = require('iputils')
local util    = require("util")
local realip =  util.get_client_ip()
require("iop")
Ip2Region = require("ip2region")

ip2region = nil
ip2region_file = io.open("/www/server/nginx/x-waf/ip2region.db", "r")
if ip2region_file then
    io.close(ip2region_file)
    ip2region = Ip2Region.new("/www/server/nginx/x-waf/ip2region.db")
end
function parse_ipinfo(ip)
    local ipinfo = {'0', '0', '0', '0'}
    if ip2region then
        local data = ip2region:memorySearch(ip)
        local country = nil
        local region = nil
        local city = nil
        local isp = nil
        local tmp = {}
        if data and data.region then
            string.gsub(data.region, "[^|]+", function(w) table.insert(tmp, w) end )
            for key, value in pairs(tmp) do
                if key == 1 and value ~= '0' then
                    country = value
                end
                if key == 3 and value ~= '0' then
                    region = value
                end
                if key == 4 and value ~= '0' then
                    city = value
                end
                if key == 5 and value ~= '0' then
                    isp = value
                end
            end
            ipinfo = {country, region, city, isp}
        end
    end
    return ipinfo
end


--[站点控制]--
has_domain = false
domain_table = {}
domain_file = io.open("/www/vhosts/.domain_list", "r")
if domain_file then
    for domain_line in domain_file:lines() do
        if string.find(domain_line, ".") then
            table.insert(domain_table, domain_line)
            has_domain = true
        end
    end
    io.close(domain_file)
end

function parse_domain()
    local servername = ngx.var.server_name
    local hostname = ngx.var.http_host
    local domain = nil

    local a = string.match(ngx.var.request, "%s+.*%s+")
    if a then
        local b = string.match(a, "^%s*https*://(.+)")
        if b then
            local c = string.find(b, "/")
            if c then
                domain = string.sub(b, 1, c-1)
            end
        end
    end

    if domain then
        return domain
    elseif hostname then
        local idx,_ = string.find(hostname, ":")
        if idx and idx > 1 then
            hostname = string.sub(hostname, 1, idx-1)
        end
        return hostname
    elseif servername then
        return servername
    else
        return "localhost"
    end
end

function invalid_domain()
    local invalid = true
    local servername = parse_domain()

    if servername == 'localhost' then
        return false
    end

    for k, v in pairs(domain_table) do
        local tmp1 = string.gsub(v, "-", "_")
        local tmp2 = string.gsub(servername, "-", "_")
        if string.find(tmp1, tmp2) then
            invalid = false
            break
        end
    end

    return invalid
end


--[站点控制]--
if has_domain then
    return 
end


-- 主流厂商CDN/蜘蛛IP
local in_open  = iputils.ip_in_cidrs(realip, iputils.parse_cidrs(ip_open_list))
if in_open then
    return 
end


-- ip地址信息
local suspected = parse_ipinfo(realip)
-- ngx.say(suspected)


-- waf
waf.check()

