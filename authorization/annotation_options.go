package authorization

import (
	authz "github.com/tiagoposse/go-auth/authorization"
)

// WithCreateScopes adds authorization scopes to a create operation
func WithCreateScopes(ss ...authz.Scope) AuthorizationAnnotation {
	return AuthorizationAnnotation{
		CreateScopes: ss,
	}
}

// WithDeleteScopes adds authorization scopes to a delete operation
func WithDeleteScopes(ss ...authz.Scope) AuthorizationAnnotation {
	return AuthorizationAnnotation{
		DeleteScopes: ss,
	}
}

// WithUpdateScopes adds authorization scopes to an update operation
func WithUpdateScopes(ss ...authz.Scope) AuthorizationAnnotation {
	return AuthorizationAnnotation{
		UpdateScopes: ss,
	}
}

// WithListScopes adds authorization scopes to a list operation
func WithListScopes(ss ...authz.Scope) AuthorizationAnnotation {
	return AuthorizationAnnotation{
		ListScopes: ss,
	}
}

// WithAllScopes adds authorization scopes to all operation
func WithAllScopes(ss ...authz.Scope) AuthorizationAnnotation {
	return AuthorizationAnnotation{
		ListScopes:   ss,
		CreateScopes: ss,
		ReadScopes:   ss,
		DeleteScopes: ss,
		UpdateScopes: ss,
	}
}

// WithReadScopes adds authorization scopes to a read operation
func WithReadScopes(ss ...authz.Scope) AuthorizationAnnotation {
	return AuthorizationAnnotation{
		ReadScopes: ss,
	}
}
