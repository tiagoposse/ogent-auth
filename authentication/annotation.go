package authentication

import (
	"encoding/json"

	"entgo.io/ent/schema"
	"github.com/ogen-go/ogen"
)

// AuthenticationAnnotation provides security annotations for the ent graph and nodes
type AuthenticationAnnotation struct {
	// only applicable as a graph annotation and must be provided
	SecuritySchemes       map[string]*ogen.SecurityScheme
	CreateSecurityMethods []SecuritySchemeType
	ListSecurityMethods   []SecuritySchemeType
	DeleteSecurityMethods []SecuritySchemeType
	UpdateSecurityMethods []SecuritySchemeType
	ReadSecurityMethods   []SecuritySchemeType
}

func (AuthenticationAnnotation) Name() string {
	return "OgentAuthAuthentication"
}

// Merge implements ent.Merger interface.
func (a AuthenticationAnnotation) Merge(o schema.Annotation) AuthenticationAnnotation {
	var ant AuthenticationAnnotation
	switch o := o.(type) {
	case AuthenticationAnnotation:
		ant = o
	case *AuthenticationAnnotation:
		if o != nil {
			ant = *o
		}
	default:
		return a
	}

	if ant.SecuritySchemes != nil {
		if a.SecuritySchemes == nil {
			a.SecuritySchemes = make(map[string]*ogen.SecurityScheme)
		}

		for k, v := range ant.SecuritySchemes {
			a.SecuritySchemes[k] = v
		}
	}

	if ant.CreateSecurityMethods != nil {
		a.CreateSecurityMethods = ant.CreateSecurityMethods
	}

	if ant.DeleteSecurityMethods != nil {
		a.DeleteSecurityMethods = ant.DeleteSecurityMethods
	}

	if ant.ListSecurityMethods != nil {
		a.ListSecurityMethods = ant.ListSecurityMethods
	}

	if ant.ReadSecurityMethods != nil {
		a.ReadSecurityMethods = ant.ReadSecurityMethods
	}

	if ant.UpdateSecurityMethods != nil {
		a.UpdateSecurityMethods = ant.UpdateSecurityMethods
	}

	return a
}

// Decode from ent.
func (a *AuthenticationAnnotation) Decode(o interface{}) error {
	buf, err := json.Marshal(o)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, a)
}
