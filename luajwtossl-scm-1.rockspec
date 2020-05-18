package = "luajwtossl"
version = "scm-1"

source = {
	url = "https://github.com/exaring/luajwtossl/archive/master.zip",
	dir = "luajwtossl-master"
}

description = {
	summary = "JSON Web Tokens for Lua",
	detailed = "Very fast and compatible with pyjwt, php-jwt, ruby-jwt, node-jwt-simple and others",
	homepage = "git@github.com:exaring/luajwtossl.git",
	license = "MIT <http://opensource.org/licenses/MIT>"
}

-- FIXME: try lower versions of lua and luaossl
-- FIXME: downgraded to lua-cjson 2.1.0-1
--        2.1.0.6-1 needs lua_objlen (is is said
--        that is lua needs to be built with  -DLUA_COMPAT_5_1 for later
--        versions to work )
dependencies = {
	"lua >= 5.1",
	"luaossl >= 20190731-0",
	"lua-cjson = 2.1.0-1",	
	"lbase64 >= 20120807-3"
}

build = {
	type = "builtin",
	modules = {
		luajwtossl = "src/luajwtossl.lua",
		['luajwtossl.utils'] = "src/luajwtossl.utils.lua"
	}
}
