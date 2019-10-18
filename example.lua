#!/usr/bin/env lua
-- This file can by run with lua or with testy.lua.
--
-- Module usage examples see below in ptest_*() functions.

local pkey    = require "openssl.pkey"
local x509    = require "openssl.x509"
local name    = require "openssl.x509.name"
local altname = require "openssl.x509.altname"
local x509    = require 'openssl.x509'
local jwt     = require "luajwtossl"

local log = print

local function t2s(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. t2s(v) .. ','
      end

      return s .. '} '
   else
      return tostring(o)
   end
end

local function readfile(filename)
   local fd,err = io.open(filename, "rb");
   if not fd then
      return nil,"Failed to open "..filename..": "..tostring(err);
   end
   local content,err = fd:read("*all");
   if not content then
      err = "Failed to read from "..filename..": "..tostring(err)
   end
   fd:close();
   return content, err
end


local function gen_test_rsa_cert()
   -- make self-signed certificate
   local key = pkey.new{ type = "rsa"}
   local dn = name.new ()
   dn:add("C", "US")
   dn:add("ST", "California")
   dn:add("L", "San Francisco ")
   dn:add("O", "Acme , Inc")
   dn:add("CN", "acme.inc")
   -- build our certificate
   local crt = x509.new ()
   crt:setVersion (3)
   crt:setSerial (42)
   crt:setSubject (dn)
   crt:setIssuer(crt: getSubject())
   local issued , expires = crt:getLifetime ()
   crt:setLifetime(issued , expires + 600) -- good for 600 seconds
   crt:setBasicConstraints { CA = true , pathLen = 2 }
   crt:setBasicConstraintsCritical (true)
   crt: setPublicKey (key)
   crt:sign(key)
   return tostring(crt), crt:toPEM("DER"), key:toPEM("privateKey"), key:toPEM("publicKey")
end


local hmac_key = "example_key"
local rsa_cert, rsa_cert_der, rsa_priv_key, rsa_pub_key = gen_test_rsa_cert()

local claim = {
   iss = "12345678",
   nbf = os.time(),
   exp = os.time() + 3600,
}

-- test for HMAC digest based tokens
local function ptest_hmac_jwt(alg, extra)
   log("alg=".. tostring(alg))
   local token, err = jwt.encode(claim, hmac_key, alg, extra)
   log("Token:", token)
   assert(token, err)
   assert(err == nil)
   local validate = true -- validate exp and nbf (default: true)
   local decoded, err = jwt.decode(token, hmac_key, validate)
   assert(decoded)
   assert(err == nil)
   log("Claim:", t2s(decoded) )
   return true
end


local function ptest_rsa_jwt(alg, extra)
   log("alg=".. tostring(alg))
   assert(rsa_cert)
   assert(rsa_priv_key)
   assert(rsa_pub_key)

   local keystr = rsa_priv_key
   assert(keystr)
   log ("KEYSTR=" .. keystr)
   local token, err = jwt.encode(claim, keystr, alg, extra)
   log("Token:", token)
   assert(token, err)
   assert(err == nil)

   local validate = false -- validate exp and nbf (default: true)
   log("decode w/o validation")
   local decoded0, err = jwt.decode(token, nil, validate)
   assert(decoded0, err)
   assert(err == nil)
   log("Claim:", t2s(decoded) )

   validate = true
   log("decode using cert in PEM format")
   local decoded, err = jwt.decode(token, tostring(rsa_cert), validate)
   assert(decoded, err)
   assert(err == nil)
   log("Claim:", t2s(decoded) )

   log("decode using public key in PEM format")
   local decoded, err = jwt.decode(token, tostring(rsa_pub_key), validate)
   assert(decoded, err)
   assert(err == nil)
   log("Claim:", t2s(decoded) )

   log("decode corrupted token (wrong signature), must fail")
   local decoded, err = jwt.decode(token .. "M" , tostring(rsa_pub_key), validate)
   assert("not decoded", "verify should have failed")
   assert(err == "Invalid signature", err)
   
   return token
end

local function test_hmac_jwt_all_alg ()
   local algs = { 'HS256', 'HS384', 'HS512' }
   for  _,alg in ipairs(algs) do
	  assert(ptest_hmac_jwt(alg))
   end
end

local function test_rsa_jwt_all_alg ()
   for  _,alg in ipairs{ 'RS256', 'RS384', 'RS512' } do
	  token = assert(ptest_rsa_jwt(alg))
   end
end

-- FIXME: should not be here
local base64 = require("base64")
local function b64_decode(input)
   --   input = input:gsub('\n', ''):gsub(' ', '')
   local reminder = #input % 4
   if reminder > 0 then
      local padlen = 4 - reminder
      input = input .. string.rep('=', padlen)
   end
   input = input:gsub('-','+'):gsub('_','/')
   return base64.decode(input)
end


local function get_header(token)
   local cjson = require("cjson")
   print("TOKEN="..token)
   local part = b64_decode(token:sub(1,token:find(".",1,true) - 1))
   print("PART="..part)
   return  cjson.decode(part)
end

local function test_rsa_jwt_header ()
   local extra = { header = {typ = "JWT", bar="baz", alg="junk", x5t="" }}
   token = assert(ptest_rsa_jwt("RS256", extra))
   header = get_header(token)
   assert(header.bar == "baz")
   assert(header.x5t == nil)
end


local function test_rsa_jwt_header_preset_x5t ()
   local extra = { header = {typ = "JWT", bar="baz", alg="junk", x5t="fooo" }}
   token = assert(ptest_rsa_jwt("RS256", extra))
   header = get_header(token)
   assert(header.bar == "baz")
   assert(header.x5t == "fooo")
end

local function test_rsa_jwt_header_compute_x5t ()
   local extra = { header = {typ = "JWT", bar="baz", alg="junk", x5t="" },
				   certs = { rsa_cert } }
   token = assert(ptest_rsa_jwt("RS256", extra))
   header = get_header(token)
   assert(header.bar == "baz")
   assert(header.x5t)
   assert(header.x5t ~= "")
end


if pcall(debug.getlocal, 4, 1) then
   -- we'running with test framework, disable logging
   log = function (x) end
else
   -- we're at top level, try to run explicitly with logging
   test_hmac_jwt_all_alg()
   test_rsa_jwt_all_alg()
   test_rsa_jwt_header()
   test_rsa_jwt_header_preset_x5t()
   test_rsa_jwt_header_compute_x5t()
end
