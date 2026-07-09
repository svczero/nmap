local nmap = require "nmap"
local string = require "string"
local table = require "table"

description = [[
Emits a one-line JSON summary of a host's open TCP/UDP ports for feeding into
other tooling. Reads only what Nmap already collected (nmap.get_ports) and sends
no traffic of its own. Fields Nmap did not determine are null; run with -sV to
fill in product and version.
]]

---
-- @usage nmap -sV --script recon-summary -p <ports> <target>
--
-- @output
-- Host script results:
-- |_recon-summary: {"ip":"127.0.0.1","hostname":null,"ports":[{"number":8099,"protocol":"tcp","state":"open","service":"http","product":"SimpleHTTPServer","version":"0.6"}]}

author = "svczero"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

local JSON_ESCAPES = {
  ['"'] = '\\"', ['\\'] = '\\\\', ['\b'] = '\\b', ['\f'] = '\\f',
  ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t',
}
local function json_escape(s)
  return (tostring(s):gsub('[%c\\"]', function(c)
    return JSON_ESCAPES[c] or string.format('\\u%04x', c:byte())
  end))
end

-- quoted JSON string, or null for nil/empty
local function jstr(v)
  if v == nil or v == "" then
    return "null"
  end
  return '"' .. json_escape(v) .. '"'
end

hostrule = function(host)
  return host ~= nil
end

action = function(host)
  local ports = {}

  for _, proto in ipairs({ "tcp", "udp" }) do
    local port = nil
    while true do
      port = nmap.get_ports(host, port, proto, "open")
      if not port then
        break
      end
      local ver = port.version or {}
      ports[#ports + 1] = string.format(
        '{"number":%d,"protocol":%s,"state":%s,"service":%s,"product":%s,"version":%s}',
        port.number,
        jstr(port.protocol),
        jstr(port.state),
        jstr(port.service or ver.name),
        jstr(ver.product),
        jstr(ver.version))
    end
  end

  local hostname = host.targetname
  if hostname == "" then
    hostname = nil
  end

  return string.format('{"ip":%s,"hostname":%s,"ports":[%s]}',
    jstr(host.ip), jstr(hostname), table.concat(ports, ","))
end
