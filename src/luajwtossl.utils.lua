-- luajwtosssl  utilities package
local base64 = require 'base64'
local hmac   = require 'openssl.hmac'
local pkey   = require 'openssl.pkey'
local x509   = require 'openssl.x509'
local digest = require 'openssl.digest'

local function mkosslobj(fun, str, format)
   local result, value =  pcall( function ()
	 return fun(str, format)
   end)
   if result then
      return value, nil
   else
      return nil, value
   end
end

local function extract_x509_cert(str)
   return mkosslobj(x509.new, str, "*")
end

local function extract_privkey(str)
   return  mkosslobj(pkey.new, str, "*")
end

local function extract_pubkey(str)
   local pubkey = mkosslobj(pkey.new, str, "*")
   if not pubkey then
      local crt = extract_x509_cert(str);
      if crt then
		 pubkey = crt:getPublicKey()
      end
   end
   return pubkey
end

local function mkdigest(data, alg)
   local md  = digest.new(alg)
   assert(md, "failed to create " .. alg .. " message digest")
   md = md:update(data)
   -- Note: Do not call md:final here!!
   -- final() is not idempotent and is being
   -- called implicitly while performing signature
   -- or verification
   return md
end

local function cert_to_der( str )
   local cert = extract_x509_cert(str)
   if cert then
	  return cert:tostring("DER")
   else
	  return nil
   end
end

local function b64urlencode(input)
   local result = base64.encode(input)
   result = result:gsub('+','-'):gsub('/','_'):gsub('=','')
   return result
end

local function b64urldecode(input)
   --   input = input:gsub('\n', ''):gsub(' ', '')
   local reminder = #input % 4
   if reminder > 0 then
      local padlen = 4 - reminder
      input = input .. string.rep('=', padlen)
   end
   input = input:gsub('-','+'):gsub('_','/')
   return base64.decode(input)
end

local function tokenize(str, div, len)
   local result, pos = {}, 0
   for st, sp in function() return str:find(div, pos, true) end do
      result[#result + 1] = str:sub(pos, st-1)
      pos = sp + 1
      len = len - 1
      if len <= 1 then
         break
      end
   end
   result[#result + 1] = str:sub(pos)
   return result
end

return {
   b64urldecode = b64urldecode,
   b64urlencode = b64urlencode,
   cert_to_der = cert_to_der,
   extract_privkey = extract_privkey,
   extract_pubkey = extract_pubkey,
   extract_x509_cert = extract_x509_cert,
   mkdigest = mkdigest,
   mkosslobj = mkosslobj,
   tokenize = tokenize
}

