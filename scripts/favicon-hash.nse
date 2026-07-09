local base64 = require "base64"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Computes the Shodan-style favicon hash of /favicon.ico so results can be pivoted
in Shodan/Censys/ZoomEye with an http.favicon.hash:<int> query.

Matches Shodan's method: base64 the raw icon using Python's base64.encodebytes
layout (76-char lines, trailing newline), MurmurHash3 x86 32-bit over that text,
signed 32-bit result. Only GET /favicon.ico is sent; a non-200 or empty body
reports nothing, and a body over nmap's http size limit is reported but not
hashed. Pass --script-args favicon-hash.selftest=1 to check the hash engine
offline.
]]

---
-- @usage nmap --script favicon-hash -p 80,443 <target>
-- @usage nmap --script favicon-hash --script-args favicon-hash.selftest=1
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_favicon-hash: -1846453327  (shodan: http.favicon.hash:-1846453327)
--
-- @args favicon-hash.selftest run the offline hash-engine check instead of scanning

author = "svczero"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local UINT32 = 0xFFFFFFFF

local function rotl32(x, r)
  x = x & UINT32
  return ((x << r) | (x >> (32 - r))) & UINT32
end

-- low 32 bits of a*b, done in 16-bit halves to stay inside Lua's 63-bit int
local function mul32(a, b)
  a = a & UINT32
  b = b & UINT32
  local a_lo = a & 0xFFFF
  local a_hi = a >> 16
  local lo = a_lo * b
  local hi = (a_hi * b) & 0xFFFF
  return (lo + (hi << 16)) & UINT32
end

-- MurmurHash3 x86_32, unsigned result
local function murmur3_x86_32(data, seed)
  local c1 = 0xCC9E2D51
  local c2 = 0x1B873593
  local len = #data
  local h1 = (seed or 0) & UINT32
  local nblocks = len // 4

  for b = 0, nblocks - 1 do
    local p = b * 4 + 1
    local b0, b1, b2, b3 = data:byte(p, p + 3)
    local k1 = (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) & UINT32
    k1 = mul32(k1, c1)
    k1 = rotl32(k1, 15)
    k1 = mul32(k1, c2)
    h1 = h1 ~ k1
    h1 = rotl32(h1, 13)
    h1 = (mul32(h1, 5) + 0xE6546B64) & UINT32
  end

  local tail = nblocks * 4 + 1
  local rem = len & 3
  local k1 = 0
  if rem == 3 then
    k1 = k1 ~ (data:byte(tail + 2) << 16)
  end
  if rem >= 2 then
    k1 = k1 ~ (data:byte(tail + 1) << 8)
  end
  if rem >= 1 then
    k1 = k1 ~ data:byte(tail)
    k1 = mul32(k1 & UINT32, c1)
    k1 = rotl32(k1, 15)
    k1 = mul32(k1, c2)
    h1 = h1 ~ k1
  end

  h1 = (h1 ~ len) & UINT32
  h1 = h1 ~ (h1 >> 16)
  h1 = mul32(h1, 0x85EBCA6B)
  h1 = h1 ~ (h1 >> 13)
  h1 = mul32(h1, 0xC2B2AE35)
  h1 = h1 ~ (h1 >> 16)
  return h1 & UINT32
end

-- unsigned -> signed, matching Python's mmh3.hash
local function to_signed32(u)
  u = u & UINT32
  if u >= 0x80000000 then
    return u - 0x100000000
  end
  return u
end

-- base64.encodebytes layout: 76-char lines plus a trailing newline
local function encodebytes(raw)
  local b64 = base64.enc(raw)
  local parts = {}
  local n = #b64
  local i = 1
  while i <= n do
    parts[#parts + 1] = b64:sub(i, i + 75)
    parts[#parts + 1] = "\n"
    i = i + 76
  end
  return table.concat(parts)
end

local function shodan_favicon_hash(raw)
  return to_signed32(murmur3_x86_32(encodebytes(raw), 0))
end

local function run_selftest()
  local fails = {}
  local function check(name, got, want)
    if got ~= want then
      fails[#fails + 1] = string.format("%s: got %s want %s",
        name, tostring(got), tostring(want))
    end
  end

  -- SMHasher verification constant for MurmurHash3 x86_32
  local hashes = {}
  for i = 0, 255 do
    local key = {}
    for j = 0, i - 1 do
      key[#key + 1] = string.char(j & 0xFF)
    end
    local h = murmur3_x86_32(table.concat(key), 256 - i)
    hashes[#hashes + 1] = string.char(h & 0xFF, (h >> 8) & 0xFF,
      (h >> 16) & 0xFF, (h >> 24) & 0xFF)
  end
  check("smhasher", murmur3_x86_32(table.concat(hashes), 0), 0xB0F57EE3)

  -- mmh3.hash vectors (signed)
  check("mmh3('')", to_signed32(murmur3_x86_32("", 0)), 0)
  check("mmh3('foo')", to_signed32(murmur3_x86_32("foo", 0)), -156908512)
  check("mmh3('foo',42)", to_signed32(murmur3_x86_32("foo", 42)), -1322301282)

  -- full pipeline vectors from the python oracle
  local range256 = {}
  for i = 0, 255 do range256[#range256 + 1] = string.char(i) end
  check("shodan('hello')", shodan_favicon_hash("hello"), 1155597304)
  check("shodan('A'*100)", shodan_favicon_hash(string.rep("A", 100)), -1846453327)
  check("shodan(0..255)", shodan_favicon_hash(table.concat(range256)), -757223386)

  local eb = encodebytes(table.concat(range256))
  if eb:sub(-1) ~= "\n" then
    fails[#fails + 1] = "encodebytes: missing trailing newline"
  end
  for line in (eb):gmatch("([^\n]*)\n") do
    if #line > 76 then
      fails[#fails + 1] = "encodebytes: line exceeds 76 chars"
      break
    end
  end

  if #fails == 0 then
    return "selftest PASS (smhasher 0xB0F57EE3, mmh3 + shodan vectors)"
  end
  return "selftest FAIL\n  " .. table.concat(fails, "\n  ")
end

prerule = function()
  return stdnse.get_script_args("favicon-hash.selftest") ~= nil
end

portrule = shortport.http

local function scan_action(host, port)
  local resp = http.get(host, port, "/favicon.ico")
  if not resp or resp.status ~= 200 then
    return nil
  end
  if resp.truncated then
    return "favicon body truncated; hash not computed"
  end
  local body = resp.body
  if not body or #body == 0 then
    return nil
  end
  local h = shodan_favicon_hash(body)
  return string.format("%d  (shodan: http.favicon.hash:%d)", h, h)
end

action = function(host, port)
  if host == nil and port == nil then
    return run_selftest()
  end
  return scan_action(host, port)
end
