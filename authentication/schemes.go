package authentication

import (
	"github.com/ogen-go/ogen"
)

type SecuritySchemeOpt func(map[string]*ogen.SecurityScheme)
type SecuritySchemeType string

const (
	SchemeJwt    SecuritySchemeType = "JwtAuth"
	SchemeApiKey SecuritySchemeType = "ApiKeyAuth"
	SchemeCookie SecuritySchemeType = "CookieAuth"
)
