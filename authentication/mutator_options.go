package authentication

import (
	"github.com/ogen-go/ogen"
	"github.com/ogen-go/ogen/jsonschema"
)

type MutatorSchemeOpt func(*ogen.Spec, map[string][]SecuritySchemeType)

func WithJwtSecurity() MutatorSchemeOpt {
	return func(spec *ogen.Spec, _ map[string][]SecuritySchemeType) {
		ensureComponents(spec)
		spec.Components.SecuritySchemes[string(SchemeJwt)] = &ogen.SecurityScheme{
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "jwt",
		}
	}
}

func WithApiKeySecurity() MutatorSchemeOpt {
	return func(spec *ogen.Spec, _ map[string][]SecuritySchemeType) {
		ensureComponents(spec)
		spec.Components.SecuritySchemes[string(SchemeApiKey)] = &ogen.SecurityScheme{
			Name: "x-api-key",
			In:   "header",
			Type: "apiKey",
		}
	}
}

func WithCookieSecurity() MutatorSchemeOpt {
	return func(spec *ogen.Spec, _ map[string][]SecuritySchemeType) {
		ensureComponents(spec)
		spec.Components.SecuritySchemes[string(SchemeCookie)] = &ogen.SecurityScheme{
			Name: "Authorization",
			In:   "cookie",
			Type: "apiKey",
			Common: jsonschema.OpenAPICommon{
				Extensions: jsonschema.Extensions{
					"x-ogen-custom-security": {},
				},
			},
		}
	}
}

func WithSecuritySchemes(schemes map[string]*ogen.SecurityScheme) MutatorSchemeOpt {
	return func(spec *ogen.Spec, _ map[string][]SecuritySchemeType) {
		ensureComponents(spec)
		for k, v := range schemes {
			spec.Components.SecuritySchemes[k] = v
		}
	}
}

func WithCustomOperations(m map[string][]SecuritySchemeType) MutatorSchemeOpt {
	return func(_ *ogen.Spec, mapping map[string][]SecuritySchemeType) {
		for k, v := range m {
			mapping[k] = v
		}
	}
}

func WithSpec(givenSpec *ogen.Spec) MutatorSchemeOpt {
	return func(spec *ogen.Spec, _ map[string][]SecuritySchemeType) {
		*spec = *givenSpec
	}
}

func ensureComponents(spec *ogen.Spec) {
	if spec.Components == nil {
		spec.Components = &ogen.Components{}
	}
	
	if spec.Components.SecuritySchemes == nil {
		spec.Components.SecuritySchemes = make(map[string]*ogen.SecurityScheme)
	}
}
