-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local comm = require "comm"
local shortport = require "shortport"
local string = require "string"

description = [[
Sends an SNMP GetRequest for sysDescr with the public community string and
reports whether the agent answers it.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local payload = "\048\038\002\001\000\004\006public\160\025"
  local status, response = comm.exchange(host, port, payload)
  if not status then return end
  if not string.match(response, "public") then return end
  return "SNMP agent answers the public community"
end
