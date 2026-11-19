"""Reading NSE: the sense of conditions, exchange shapes, version extraction."""

import unittest

from nse2pack.build import KIND_EXPLOIT, KIND_LOGIC, KIND_PATTERN, KIND_ROUTING, convert
from nse2pack.parser import parse_text

HEAD = '''
local comm = require "comm"
local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[One sentence of description. And a second one.]]
author = "Tests"
license = "Same as Nmap"
categories = {%s}

portrule = %s

action = function(host, port)
%s
end
'''


def build(body, categories='"safe"', portrule="shortport.http"):
    text = HEAD % (categories, portrule, body)
    return convert(parse_text(text, "fixture"))


class TestPolarity(unittest.TestCase):
    """`if not X then return end` requires X; `if X then return end` forbids X."""

    def test_guard_with_not_means_required(self):
        result = build('''
  local r = http.get(host, port, "/x")
  if not string.find(r.body, "SECRET-MARKER", 1, true) then return end
  return "found"
''')
        expect = result.checks[0]["steps"][0]["expect"]
        self.assertEqual(expect["body_all"], ["SECRET-MARKER"])
        self.assertNotIn("not", expect)

    def test_guard_without_not_means_forbidden(self):
        result = build('''
  local r = http.get(host, port, "/x")
  if not string.find(r.body, "SECRET-MARKER", 1, true) then return end
  if string.find(r.body, "Not Found", 1, true) then return end
  return "found"
''')
        expect = result.checks[0]["steps"][0]["expect"]
        self.assertEqual(expect["body_all"], ["SECRET-MARKER"])
        self.assertEqual(expect["not"]["body_any"], ["Not Found"])

    def test_returning_a_value_is_not_a_guard(self):
        # `if X then return <value> end` is the reporting branch: sense is not inverted.
        result = build('''
  local r = http.get(host, port, "/x")
  if string.find(r.body, "SECRET-MARKER", 1, true) then
    return "reported"
  end
''')
        expect = result.checks[0]["steps"][0]["expect"]
        self.assertEqual(expect["body_all"], ["SECRET-MARKER"])
        self.assertNotIn("not", expect)

    def test_nil_comparison_matches_not(self):
        result = build('''
  local r = http.get(host, port, "/x")
  if string.match(r.body, "SECRET%-MARKER") == nil then return end
  return "found"
''')
        expect = result.checks[0]["steps"][0]["expect"]
        self.assertEqual(expect["re"], ["SECRET-MARKER"])
        self.assertNotIn("not", expect)


class TestStatus(unittest.TestCase):
    def test_not_equal_in_a_guard_requires_the_status(self):
        result = build('''
  local r = http.get(host, port, "/x")
  if r.status ~= 200 then return end
  if not string.find(r.body, "SECRET-MARKER", 1, true) then return end
  return "found"
''')
        self.assertEqual(result.checks[0]["steps"][0]["expect"]["status"], [200])

    def test_forbidden_status_is_dropped_rather_than_inverted(self):
        result = build('''
  local r = http.get(host, port, "/x")
  if r.status == 404 then return end
  if not string.find(r.body, "SECRET-MARKER", 1, true) then return end
  return "found"
''')
        self.assertNotIn("status", result.checks[0]["steps"][0]["expect"])


class TestShapes(unittest.TestCase):
    def test_banner_and_version(self):
        result = build('''
  local status, banner = comm.get_banner(host, port)
  if not status then return end
  if not string.match(banner, "^220.-myftpd") then return end
  port.version.product = "myftpd"
  port.version.version = string.match(banner, "myftpd ([%d%.]+)")
  nmap.set_port_version(host, port)
''', categories='"version"', portrule='shortport.port_or_service(21, "ftp", "tcp")')
        check = result.checks[0]
        self.assertEqual(check["match"], {"service": "ftp", "ports": [21],
                                          "any_port_open": [21]})
        self.assertEqual(check["steps"][0]["tcp"]["send_b64"], "")
        self.assertEqual(check["detect"], {"product": "myftpd",
                                           "version": {"from": "body",
                                                       "re": "myftpd ([0-9.]+)"}})

    def test_payload_from_a_local_variable(self):
        result = build('''
  local payload = "\\080\\073\\078\\071"
  local status, response = comm.exchange(host, port, payload)
  if not status then return end
  if not string.match(response, "PONG-MARKER") then return end
  return "answered"
''', portrule='shortport.port_or_service(7788, "demosvc", "tcp")')
        self.assertEqual(result.checks[0]["steps"][0]["tcp"]["send_b64"], "UElORw==")

    def test_path_list_becomes_paths(self):
        result = build('''
  for _, path in ipairs({"/.git/config", "/.svn/entries"}) do
    local r = http.get(host, port, path)
    if string.find(r.body, "VERSION-CONTROL-MARKER", 1, true) then
      return "exposed"
    end
  end
''')
        self.assertEqual(result.checks[0]["steps"][0]["http"]["paths"],
                         ["/.git/config", "/.svn/entries"])

    def test_two_dependent_requests_become_capture(self):
        result = build('''
  local first = http.get(host, port, "/login")
  local token = string.match(first.body, 'value="([a-f0-9]+)"')
  if not token then return end
  local second = http.get(host, port, "/api/status?csrf=" .. token)
  if string.find(second.body, '"ok"', 1, true) then
    return "reachable"
  end
''')
        steps = result.checks[0]["steps"]
        self.assertEqual(len(steps), 2)
        self.assertEqual(steps[0]["capture"], [{"as": "token",
                                                "re": 'value="([a-f0-9]+)"'}])
        self.assertEqual(steps[1]["http"]["path"], "/api/status?csrf={{token}}")

    def test_header_presence_and_absence(self):
        present = build('''
  local r = http.get(host, port, "/")
  if not r.header["x-powered-by"] then return end
  return "header is present"
''')
        self.assertEqual(present.checks[0]["steps"][0]["expect"]["header"],
                         [{"name": "x-powered-by"}])

        absent = build('''
  local r = http.get(host, port, "/")
  if not r.header["x-frame-options"] then
    return "header is missing"
  end
''')
        self.assertEqual(absent.checks[0]["steps"][0]["expect"]["header"],
                         [{"name": "x-frame-options", "absent": True}])

    def test_header_test_and_detect_from_header(self):
        result = build('''
  local r = http.get(host, port, "/")
  if not r.header["server"] then return end
  port.version.product = "nginx"
  port.version.version = r.header["server"]:match("nginx/([%d%.]+)")
  nmap.set_port_version(host, port)
''', categories='"version"')
        check = result.checks[0]
        self.assertEqual(check["steps"][0]["expect"]["header"],
                         [{"name": "server", "re": "nginx/([0-9.]+)"}])
        self.assertEqual(check["detect"]["version"],
                         {"from": "header", "header": "server", "re": "nginx/([0-9.]+)"})


class TestRefusals(unittest.TestCase):
    def _kind(self, result):
        return result.skips[0].kind

    def test_brute_category(self):
        result = build('return "x"', categories='"brute"')
        self.assertEqual(self._kind(result), KIND_EXPLOIT)

    def test_state_changing_request(self):
        result = build('''
  local r = http.post(host, port, "/login", nil, nil, {u = "x"})
  if r.status == 302 then return "vulnerable" end
''')
        self.assertEqual(self._kind(result), KIND_EXPLOIT)

    def test_hostrule_only(self):
        text = HEAD % ('"safe"', "shortport.http", 'return "x"')
        text = text.replace("portrule =", "hostrule =")
        result = convert(parse_text(text, "fixture"))
        self.assertEqual(result.skips[0].kind, KIND_ROUTING)

    def test_untranslatable_pattern(self):
        result = build('''
  local r = http.get(host, port, "/")
  local title = string.match(r.body, "%b<>")
  if not title then return end
  return title
''')
        self.assertEqual(self._kind(result), KIND_PATTERN)

    def test_computed_path(self):
        result = build('''
  local path = build_path(host)
  local r = http.get(host, port, path)
  if not string.find(r.body, "SECRET-MARKER", 1, true) then return end
  return "found"
''')
        self.assertEqual(self._kind(result), KIND_LOGIC)
        self.assertTrue(result.skips[0].script_candidate)


class TestQuality(unittest.TestCase):
    def test_short_lone_marker_is_refused(self):
        result = build('''
  local r = http.get(host, port, "/x")
  if not string.find(r.body, "login", 1, true) then return end
  return "found"
''')
        self.assertEqual(result.checks, [])
        self.assertIn("shorter than", result.skips[0].reason)

    def test_product_anchor_rescues_a_short_marker(self):
        # A short piece of evidence over http is fine only with a product anchor.
        result = build('''
  local r = http.get(host, port, "/")
  if not string.match(r.body, "nginx") then return end
  port.version.product = "nginx"
''', categories='"version"')
        self.assertEqual(result.checks[0]["steps"][0]["expect"].get("require_ci"),
                         ["nginx"])

    def test_byte_transport_on_a_known_port_is_specific_enough(self):
        # A byte exchange on a specific port is already narrow: the §8 rule about
        # "a bare substring on any 200 page" does not apply to it.
        result = build('''
  local status, banner = comm.get_banner(host, port)
  if not string.match(banner, "acarsd") then return end
  port.version.product = "acarsd"
''', categories='"version"', portrule='shortport.port_or_service(2202, "acarsd", "tcp")')
        self.assertEqual(result.checks[0]["detect"]["product"], "acarsd")
        self.assertEqual(result.checks[0]["steps"][0]["expect"]["re"], ["acarsd"])

    def test_verified_is_never_claimed(self):
        result = build('''
  local r = http.get(host, port, "/x")
  if not string.find(r.body, "SECRET-MARKER", 1, true) then return end
  return "found"
''')
        self.assertNotIn("verified", result.checks[0]["finding"])
