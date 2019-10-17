#!/usr/bin/env lua

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

-- 
local jwt = require "luajwtossl"

local key = "example_key"

local claim = {
   iss = "12345678",
   nbf = os.time(),
   exp = os.time() + 3600,
}

-- test for HMAC digest based tokens
local function ptest_hmac_jwt(alg)
   log("alg=".. tostring(alg))
   local token, err = jwt.encode(claim, key, alg)
   log("Token:", token)
   assert(token)
   local validate = true -- validate exp and nbf (default: true)
   local decoded, err = jwt.decode(token, key, validate)
   assert(decoded)
   assert(err == nil)
   log("Claim:", t2s(decoded) )
   return true
end

local function test_hmac_jwt_all_alg ()
   local algs = { 'HS256', 'HS384', 'HS512' }
   local alg
   for  i,alg in ipairs(algs) do
	  assert(ptest_hmac_jwt(alg))
   end
end


if pcall(debug.getlocal, 4, 1) then
   -- we'running with test framework, disable logging
   log = function (x) end
else
   -- we're at top level, try to run explicitly with logging
   test_hmac_jwt_all_alg()
end
