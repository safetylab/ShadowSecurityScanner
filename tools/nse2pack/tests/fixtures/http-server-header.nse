-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Reads the Server header of an HTTP response and records the product and version
it advertises.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"version"}

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response.header["server"] then return end
  local ver = response.header["server"]:match("nginx/([%d%.]+)")
  port.version.product = "nginx"
  port.version.version = ver
  nmap.set_port_version(host, port)
end
