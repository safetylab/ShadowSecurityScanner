-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"

description = [[
Exploits CVE-2014-3704, an SQL injection in Drupal 7 that allows an attacker to
add an administrator account.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"intrusive", "exploit", "vuln"}

portrule = shortport.http

action = function(host, port)
  local response = http.post(host, port, "/user/login", nil, nil, {name = payload})
  if response.status == 302 then
    return "vulnerable"
  end
end
