-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Retrieves information from a listening acarsd daemon. Acarsd decodes ACARS
(Aircraft Communication Addressing and Reporting System) data in real time.
The information retrieved includes the daemon version, API version,
administrator e-mail address and listening frequency.
]]

---
-- @usage nmap -p 2202 --script acarsd-info <target>

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service (2202, "acarsd", {"tcp"})

action = function( host, port )
  local status, data = comm.get_banner(host, port, {timeout=5000})
  if not status then return end
  if not string.match(data, "acarsd") then return end
  if string.match(data, "Authorization needed") then return end
  local ver = string.match(data, "<Version>([^<]+)</Version>")
  port.version.product = "acarsd"
  port.version.version = ver
  nmap.set_port_version(host, port)
  return stdnse.format_output(true, data)
end
