--[[


]]
local iputils = require('iputils')
local util    = require("util")
local realip =  util.get_client_ip()
require("iop")



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

-- 过滤ftp数据处理
local config = require("config")
if config.config_white_url_check == "on" then
    local URL_WHITE_RULES = waf.get_rule('whiteUrl.rule')
    local REQ_URI = ngx.var.request_uri
    if URL_WHITE_RULES ~= nil then
        for _, rule in pairs(URL_WHITE_RULES) do
            if rule ~= "" and string.find(REQ_URI, rule) then
                return true
            end
        end
    end
end



-- waf
waf.check()

