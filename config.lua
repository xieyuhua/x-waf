--[[

]]

-- WAF config file, enable = "on", disable = "off"

local _M = {
    -- waf status
    config_waf_enable = "on",
    -- log dir
    config_log_dir = "/www/wwwlogs/waf/",
    -- rule setting
    config_rule_dir = "/www/server/nginx/x-waf/rules",
    -- enable/disable white url
    config_white_url_check = "on",
    -- enable/disable white ip
    config_white_ip_check = "on",
    -- enable/disable block ip
    config_black_ip_check = "on",
    -- enable/disable url filtering
    config_url_check = "on",
    -- enalbe/disable url args filtering
    config_url_args_check = "on",
    -- enable/disable user agent filtering
    config_user_agent_check = "on",
    -- enable/disable cookie deny filtering
    config_cookie_check = "on",
    -- enable/disable cc filtering
    config_cc_check = "on",
    -- cc rate the xxx of xxx seconds
    config_cc_rate = "300/60",
    -- enable/disable cc filtering
    config_ipcc_check = 'on',
    -- ipcc rate the xxx of xxx seconds，#########ip请求，100次，否则就封禁2小时
    config_ipcc_rate = "120/7200",
    -- enable/disable post filtering
    config_post_check = "on",
    -- config waf output redirect/html/jinghuashuiyue
    config_waf_model = "html",
    -- if config_waf_output ,setting url
    config_waf_redirect_url = "",
    config_expire_time = 600,
    config_output_html = [[
    <html>
    <head>
    <meta charset="UTF-8">
    <title>网站防火墙</title>
    </head>
      <body>
        <div>
      <div class="table">
        <div>
          <div class="cell">
            您的IP为: %s
          </div>
          <div class="cell">
             <p class="t1">您的请求带有不合法参数，已被网站管理员设置拦截%s次！</p>
          </div>
        </div>
      </div>
    </div>
      </body>
    </html>
    ]],

}

return _M
