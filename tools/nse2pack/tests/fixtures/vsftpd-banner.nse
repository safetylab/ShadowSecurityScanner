-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Grabs the FTP greeting and extracts the vsftpd version from it.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"version", "safe"}

portrule = shortport.port_or_service({21, 990}, {"ftp", "ftps"}, "tcp")

action = function(host, port)
  local status, banner = comm.get_banner(host, port)
  if not status then return end
  if not string.match(banner, "^220.-vsftpd") then return end
  port.version.product = "vsftpd"
  port.version.version = string.match(banner, "vsftpd ([%d%.]+)")
  nmap.set_port_version(host, port)
end
