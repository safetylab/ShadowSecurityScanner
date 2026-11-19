-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local http = require "http"
local shortport = require "shortport"
local string = require "string"

description = [[
Fetches a login form, extracts the CSRF token and replays it against the status
endpoint.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local first = http.get(host, port, "/login")
  local token = string.match(first.body, 'value="([a-f0-9]+)"')
  if not token then return end
  local second = http.get(host, port, "/api/status?csrf=" .. token)
  if string.find(second.body, '"ok"', 1, true) then
    return "status endpoint reachable"
  end
end
