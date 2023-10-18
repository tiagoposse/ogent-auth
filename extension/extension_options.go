package extension

import (
	"github.com/ogen-go/ogen"
	authz "github.com/tiagoposse/go-auth/authorization"
	"github.com/tiagoposse/ogent-auth/authentication"
	"github.com/tiagoposse/ogent-auth/authorization"
)


type MutatorSchemeOpt func(*ogen.Spec, map[string][]authentication.SecuritySchemeType)

func WithJwtSecurity() AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		a.schemes = append(a.schemes, authentication.SchemeJwt)
		a.authenticationOpts = append(a.authenticationOpts, authentication.WithJwtSecurity())
	}
}

func WithApiKeySecurity() AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		a.schemes = append(a.schemes, authentication.SchemeApiKey)
		a.authenticationOpts = append(a.authenticationOpts, authentication.WithApiKeySecurity())
	}
}

func WithCookieSecurity() AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		a.schemes = append(a.schemes, authentication.SchemeCookie)
		a.authenticationOpts = append(a.authenticationOpts, authentication.WithCookieSecurity())
	}
}

func WithCustomAuthentication(m map[string][]authentication.SecuritySchemeType) AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		a.authenticationOpts = append(a.authenticationOpts, authentication.WithCustomOperations(m))
	}
}

func WithGlobalAuthentication(anns ...authentication.AuthenticationAnnotation) AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		for _, ann := range anns {
			a.globalAuthenticationAnnotation = a.globalAuthenticationAnnotation.Merge(ann)
		}
	}
}

func WithDefaultGlobalAuthentication() AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		WithGlobalAuthentication(authentication.WithAllSecurityMethods(a.schemes...))(a)
	}
}

func WithCustomOperation(op string, schemes []authentication.SecuritySchemeType, scopes authz.Scopes) AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		WithCustomScopes(map[string]authz.Scopes{op: scopes})(a)
		WithCustomAuthentication(map[string][]authentication.SecuritySchemeType{op: schemes})(a)
	}
}


func WithGlobalScopes(anns ...authorization.AuthorizationAnnotation) AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		for _, ann := range anns {
			a.globalAuthorizationAnnotation = a.globalAuthorizationAnnotation.Merge(ann)
		}
	}	
}

func WithCustomScopes(m map[string]authz.Scopes) AuthExtensionOpt {
	return func(a *OgentAuthExtension) {
		a.scopeMutations = append(a.scopeMutations, func(scopes map[string]authz.Scopes) {
			for k, v := range m {
				scopes[k] = v
			}
		})
	}
}
