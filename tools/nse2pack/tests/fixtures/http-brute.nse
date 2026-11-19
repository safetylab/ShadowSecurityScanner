-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local brute = require "brute"
local http = require "http"
local shortport = require "shortport"

description = [[
Performs brute force password auditing against http basic authentication.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"intrusive", "brute"}

portrule = shortport.http

action = function(host, port)
  local engine = brute.Engine:new(Driver, host, port)
  return engine:start()
end
