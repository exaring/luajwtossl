package = "luajwtossl"
version = "0.1"

source = {
	url = "git@github.com:dudinea/luajwt.git",
	tag = "luajwtossl-0.1"
}

description = {
	summary = "JSON Web Tokens for Lua",
	detailed = "Very fast and compatible with pyjwt, php-jwt, ruby-jwt, node-jwt-simple and others",
	homepage = "git@github.com:dudinea/luajwt.git",
	license = "MIT <http://opensource.org/licenses/MIT>"
}

-- FIXME: try lower versions of lua and luaossl
dependencies = {
	"lua >= 5.3",
	"luaossl >= 20190731-0",
	"lua-cjson >= 2.1.0",
	"lbase64 >= 20120807-3"
}

build = {
	type = "builtin",
	modules = {
		luajwtossl = "luajwtossl.lua"
	}
}
