package extension

import (
	_ "embed"
	"html/template"
	"os"
	"path/filepath"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
	"github.com/ogen-go/ogen"
	"github.com/tiagoposse/ogent-auth/authentication"
	"github.com/tiagoposse/ogent-auth/authorization"
)

//go:embed handler.tmpl
var handlerTmpl string

type OgentAuthExtension struct {
	entc.DefaultExtension
	schemes                        []authentication.SecuritySchemeType
	authenticationOpts             []authentication.MutatorSchemeOpt
	scopeMutations                 []authorization.ScopeMutator
	globalAuthorizationAnnotation  authorization.AuthorizationAnnotation
	globalAuthenticationAnnotation authentication.AuthenticationAnnotation
}

type AuthExtensionOpt func(a *OgentAuthExtension)

func NewOgentAuthExtension(opts ...AuthExtensionOpt) *OgentAuthExtension {
	ext := &OgentAuthExtension{
		schemes:                       make([]authentication.SecuritySchemeType, 0),
		authenticationOpts:            make([]authentication.MutatorSchemeOpt, 0),
		globalAuthorizationAnnotation: authorization.AuthorizationAnnotation{},
		scopeMutations:                make([]authorization.ScopeMutator, 0),
	}

	for _, opt := range opts {
		opt(ext)
	}

	return ext
}

func (ae *OgentAuthExtension) Hooks() []gen.Hook {
	return []gen.Hook{
		ae.generate(),
	}
}

// DisallowTypeName ensures there is no ent.Schema with the given name in the graph.
func (a *OgentAuthExtension) generate() gen.Hook {
	return func(next gen.Generator) gen.Generator {
		return gen.GenerateFunc(func(graph *gen.Graph) error {
			err := next.Generate(graph)
			if err != nil {
				return err
			}

			graph.Annotations[a.globalAuthorizationAnnotation.Name()] = a.globalAuthorizationAnnotation

			spec := ogen.NewSpec()
			spec.Components = &ogen.Components{SecuritySchemes: make(map[string]*ogen.SecurityScheme)}

			for _, opt := range a.authenticationOpts {
				opt(spec, make(map[string][]authentication.SecuritySchemeType))
			}

			scopes := authorization.ExtractGraphScopes(graph)
			for _, sm := range a.scopeMutations {
				sm(scopes)
			}

			if err := os.MkdirAll(filepath.Join(graph.Target, "ogentauth"), os.ModePerm); err != nil {
				return err
			}

			data := map[string]any{
				"Scopes":          scopes,
				"Package":         graph.Config.Package,
				"SecuritySchemes": spec.Components.SecuritySchemes,
			}
			if err := executeTemplate(
				"handler",
				handlerTmpl,
				filepath.Join(graph.Target, "ogentauth", "handler.go"),
				data,
			); err != nil {
				return err
			}

			return nil
		})
	}
}

func executeTemplate(name, tmpl, target string, params map[string]any) error {
	t, err := template.New(name).Parse(tmpl)
	if err != nil {
		return err
	}

	f, err := os.Create(target)
	if err != nil {
		return err
	}

	err = t.Execute(f, params)
	if err != nil {
		return err
	}

	return nil
}

func (a *OgentAuthExtension) SecurityMutation() func(graph *gen.Graph, spec *ogen.Spec) error {
	return func(graph *gen.Graph, spec *ogen.Spec) error {
		graph.Annotations[a.globalAuthenticationAnnotation.Name()] = a.globalAuthenticationAnnotation
		return authentication.SecurityMutation(a.authenticationOpts...)(graph, spec)
	}
}
