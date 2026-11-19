-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local http = require "http"
local shortport = require "shortport"
local string = require "string"

description = [[
Requests a well known backup path and reports it when the server returns the
file instead of an error page.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"safe", "vuln"}

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/wp-config.php.bak")
  if response.status ~= 200 then return end
  if not string.find(response.body, "DB_PASSWORD", 1, true) then return end
  if string.find(response.body, "Not Found", 1, true) then return end
  return "Backup of wp-config.php is downloadable"
end
