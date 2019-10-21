local cjson  = require 'cjson'
local base64 = require 'base64'
local hmac   = require 'openssl.hmac'
local pkey   = require 'openssl.pkey'
local x509   = require 'openssl.x509'
local digest = require 'openssl.digest'
local utl    = require 'luajwtossl.utils'

local function mk_hmac_sign_fun(alg)
   local fun = function (data, key)
      local hd = hmac.new(key , alg)
      hd:update(data)
      return hd:final()
   end
   return fun
end

local function mk_hmac_verify_fun(alg)
   local fun = function (data, key)
      local hd = hmac.new(key , alg)
      hd:update(data)
      return hd:final()
   end
   return fun
end

local function mk_pubkey_sign_fun(alg)
   return function (data, key)
	  local priv = utl.extract_privkey(key)
	  assert(priv, "failed to get private key from provided argument:" ..
				"must be private key in pem or in der format")
	  local md  = utl.mkdigest(data, alg)
	  local signature = priv:sign(md)
	  return signature
   end
end

local function mk_pubkey_verify_fun(alg)
   return function(data, signature, key)
	  local pubkey = utl.extract_pubkey(key)
	  assert(pubkey, "failed to get public key from provided argument:" ..
				"must be public key or x509 certificate in pem or der formats")
	  local md  = utl.mkdigest(data, alg)
	  return  pubkey:verify(signature, md)
   end
end

local alg_sign = {
   ['HS256'] = mk_hmac_sign_fun('sha256'),
   ['HS384'] = mk_hmac_sign_fun('sha384'),
   ['HS512'] = mk_hmac_sign_fun('sha512'),
   ['RS256'] = mk_pubkey_sign_fun('sha256'),
   ['RS384'] = mk_pubkey_sign_fun('sha384'),
   ['RS512'] = mk_pubkey_sign_fun('sha512'),
   ['none' ] = function (data, key) return "" end
}

local alg_verify = {
   ['HS256'] = function(data, signature, key) return signature == alg_sign['HS256'](data, key) end,
   ['HS384'] = function(data, signature, key) return signature == alg_sign['HS384'](data, key) end,
   ['HS512'] = function(data, signature, key) return signature == alg_sign['HS512'](data, key) end,
   ['RS256'] = mk_pubkey_verify_fun('sha256'),
   ['RS384'] = mk_pubkey_verify_fun('sha384'),
   ['RS512'] = mk_pubkey_verify_fun('sha512'),
   ['none' ] = function(data, signature, key) return signature == "" end
}

local function mk_cert_hash_fun(digest_alg)
   return function (extra, alg)
	  if not extra or not extra.certs or #(extra.certs) == 0 or extra.certs[1] == nil then 
		 return nil
	  end
	  -- FIXME: error handling
	  local der = utl.cert_to_der(extra.certs[1]);
	  if der then
		 local md = utl.mkdigest(der, digest_alg)
		 return utl.b64urlencode(md:final())
	  else
		 return nil
	  end
   end
end

local function mk_x5c(extra, alg)
   local x5c = {}
   if not extra or not extra.certs then
	  return nil
   end
   for i, cert in ipairs(extra.certs) do
	  local der = utl.cert_to_der(cert)
	  -- FIXME: error handling
	  -- NOTE: the RFC requires plane base64 here 
	  x5c[i] = base64.encode(der)
   end
   return (#x5c > 0 and x5c ) or nil
end


local header_field_func = {
   ['x5t'] = mk_cert_hash_fun("sha1"),
   ['x5t#S256'] = mk_cert_hash_fun("sha256"),
   ['x5c'] = mk_x5c
}

local function mkheader(extra, alg)
   local header
   if extra and extra.header then
	  if not type(extra.header) == "table" then
		 return nil, "extra.header parameter must be a table"
	  end
	  header = {}
	  for k,v in pairs(extra.header) do
		 if v ~= "" then
			header[k] = v
		 elseif header_field_func[k] then
			local val = header_field_func[k](extra, alg)
			if (val) then
			   header[k] = val
			end
		 end
	  end
	  header.alg = alg
   else
	  header = { typ='JWT', alg=alg }
   end
   return header
end

local function get_keystr(alg, header, key)
   if type(key) == "string" then
	  return key, nil
   end
   if type(key) == "function" then
	  local is_ok, keystr, err =	 pcall(function() return key(alg, header) end)
	  if is_ok then
		 if keystr then
			if type(keystr)=='string' then
			   return keystr, nil
			else
			   return nil, "Key fetch function returned invalid key of type "..type(keystr)
			end
		 else
			return nil, "Key fetch function returned error: "..tostring(err)
		 end
	  else
		 return nil, "Key fetch function failed: "..tostring(keystr)
	  end
   end
   if alg == 'none' then
	  return "",nil
   end
   return nil, "Invalid key argument, must be string or function"
end

-- the following functions are exported

local function encode(data, key, alg, extra)
   alg = alg or "HS256" 
   if type(data) ~= 'table' then return nil, "Argument #1 must be table" end
   if alg ~= 'none' and type(key) ~= 'string' then return nil, "Argument #2 must be string" end
   if extra and type(extra) ~= 'table' then return nil, "Argument #4 must be nil or table" end


   if not alg_sign[alg] then
      return nil, "Algorithm not supported"
   end

   local header,err  = mkheader(extra, alg)
   if not header then
	  return nil, err
   end
   
   local segments = {
      utl.b64urlencode(cjson.encode(header)),
      utl.b64urlencode(cjson.encode(data))
   }

   local signing_input = table.concat(segments, ".")

   local signature = alg_sign[alg](signing_input, key)

   segments[#segments+1] = utl.b64urlencode(signature)

   return table.concat(segments, ".")
end

-- Parse JWT token
-- @param  JWT token - in case of failure the parts that has been
--                     successfully parsed get returned anyway
-- @return err - error message, nil on success
--         header body signature - decoded from base64
--         h64    b64  sig64     - those not decoded decoded
local function parse(data)
   local parts = utl.tokenize(data, '.', 3)
   local headerb64, bodyb64, sigb64 = parts[1], parts[2], parts[3]
   local err, ok, header, body, sig
   
   if #parts == 3 then
		 ok, header, body, sig = pcall(function ()
			   return cjson.decode(utl.b64urldecode(headerb64)), 
			   cjson.decode(utl.b64urldecode(bodyb64)),
			   utl.b64urldecode(sigb64)
		 end)
		 if not ok then
			err = "invalid json"
		 end		 
   else
	  err = "token must contain three parts"
   end
   
   return err,  header, body, sig,  headerb64, bodyb64, sigb64
end   
   

function decode(data, key, verify)
   if key and verify == nil then verify = true end
   if type(data) ~= 'string' then return nil, "Argument #1 must be string" end

   local err, header, body, sig, headerb64, bodyb64, sigb64 = parse(data)
   if err then
      return nil, "JWT token parse error: " .. err
   end

   if verify then

      if not header.typ or header.typ ~= "JWT" then
         return nil, "Invalid typ"
      end

      if not header.alg or type(header.alg) ~= "string" then
         return nil, "Invalid alg"
      end

	  local keystr, err = get_keystr(header.alg, header, key)
	  if err then
		 return nil, err
	  end

      if body.exp and type(body.exp) ~= "number" then
         return nil, "exp must be number"
      end

      if body.nbf and type(body.nbf) ~= "number" then
         return nil, "nbf must be number"
      end

      if not alg_verify[header.alg] then
         return nil, "Algorithm not supported"
      end

      if not alg_verify[header.alg](headerb64 .. "." .. bodyb64, sig, keystr) then
         return nil, "Invalid signature"
      end

      if body.exp and os.time() >= body.exp then
         return nil, "Not acceptable by exp"
      end

      if body.nbf and os.time() < body.nbf then
         return nil, "Not acceptable by nbf"
      end
   end

   return body
end

return {
   decode = decode,
   encode = encode,
   parse = parse
}
