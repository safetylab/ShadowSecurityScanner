-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local smb = require "smb"
local stdnse = require "stdnse"

description = [[
Attempts to determine the operating system over the SMB protocol by starting a
session with the remote host.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"default", "discovery", "safe"}

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)
  local status, result = smb.get_os(host)
  if not status then return end
  return stdnse.format_output(true, result)
end
