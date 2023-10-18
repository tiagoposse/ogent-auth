package authorization

import (
	"encoding/json"

	"entgo.io/ent/schema"
	authz "github.com/tiagoposse/go-auth/authorization"
)

// AuthorizationAnnotation provides security annotations for the ent graph
type AuthorizationAnnotation struct {
	CreateScopes          authz.Scopes
	DeleteScopes          authz.Scopes
	UpdateScopes          authz.Scopes
	ReadScopes            authz.Scopes
	ListScopes            authz.Scopes
}

func (AuthorizationAnnotation) Name() string {
	return "OgentAuthAuthorization"
}

// Merge implements ent.Merger interface.
func (a AuthorizationAnnotation) Merge(o schema.Annotation) AuthorizationAnnotation {
	var ant AuthorizationAnnotation
	switch o := o.(type) {
	case AuthorizationAnnotation:
		ant = o
	case *AuthorizationAnnotation:
		if o != nil {
			ant = *o
		}
	default:
		return a
	}

	if ant.CreateScopes != nil {
		a.CreateScopes = ant.CreateScopes
	}

	if ant.DeleteScopes != nil {
		a.DeleteScopes = ant.DeleteScopes
	}

	if ant.ListScopes != nil {
		a.ListScopes = ant.ListScopes
	}

	if ant.ReadScopes != nil {
		a.ReadScopes = ant.ReadScopes
	}

	if ant.UpdateScopes != nil {
		a.UpdateScopes = ant.UpdateScopes
	}

	return a
}

// Decode from ent.
func (a *AuthorizationAnnotation) Decode(o interface{}) error {
	buf, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, a)
}
