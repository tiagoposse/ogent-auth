package authentication

// WithCreateSecurityMethods adds authorization scopes to a create operation
func WithCreateSecurityMethods(ss ...SecuritySchemeType) AuthenticationAnnotation {
	return AuthenticationAnnotation{
		CreateSecurityMethods: ss,
	}
}

// WithDeleteSecurityMethods adds authorization scopes to a delete operation
func WithDeleteSecurityMethods(ss ...SecuritySchemeType) AuthenticationAnnotation {
	return AuthenticationAnnotation{
		DeleteSecurityMethods: ss,
	}
}

// WithUpdateSecurityMethods adds authorization scopes to an update operation
func WithUpdateSecurityMethods(ss ...SecuritySchemeType) AuthenticationAnnotation {
	return AuthenticationAnnotation{
		UpdateSecurityMethods: ss,
	}
}

// WithListSecurityMethods adds authorization scopes to a list operation
func WithListSecurityMethods(ss ...SecuritySchemeType) AuthenticationAnnotation {
	return AuthenticationAnnotation{
		ListSecurityMethods: ss,
	}
}

// WithAllSecurityMethods adds authorization scopes to all operation
func WithAllSecurityMethods(ss ...SecuritySchemeType) AuthenticationAnnotation {
	return AuthenticationAnnotation{
		ListSecurityMethods:   ss,
		CreateSecurityMethods: ss,
		ReadSecurityMethods:   ss,
		DeleteSecurityMethods: ss,
		UpdateSecurityMethods: ss,
	}
}

// WithReadSecurityMethods adds authorization scopes to a read operation
func WithReadSecurityMethods(ss ...SecuritySchemeType) AuthenticationAnnotation {
	return AuthenticationAnnotation{
		ReadSecurityMethods: ss,
	}
}
