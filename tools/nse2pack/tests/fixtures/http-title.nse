-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local http = require "http"
local shortport = require "shortport"
local string = require "string"

description = [[
Shows the title of the default page of a web server and flags a balanced tag
pair, which has no equivalent outside Lua patterns.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"default", "discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  local title = string.match(response.body, "%b<>")
  if not title then return end
  return title
end
