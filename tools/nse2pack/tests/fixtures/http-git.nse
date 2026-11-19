-- Synthetic fixture for the nse2pack test suite. Written from scratch to
-- model the shape of a real NSE script; not copied from Nmap, and not
-- covered by the Nmap Public Source License.
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks for a Git repository found in a website's document root and reports the
repository metadata it exposes.
]]

author = "nse2pack test fixture"
license = "MIT, with the nse2pack test suite"
categories = {"default", "safe", "vuln"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  for _, path in ipairs({"/.git/config", "/.git/HEAD", "/.svn/entries"}) do
    local response = http.get(host, port, path)
    if string.find(response.body, "[core]", 1, true) then
      out.repository = "exposed"
    end
  end
  return out
end
