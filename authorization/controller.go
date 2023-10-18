package authorization

// import (
// 	"context"

// 	authz "github.com/tiagoposse/go-auth/authorization"
// 	"github.com/tiagoposse/go-auth/sessions"
// )

// type IApiKeyAuth interface{
// 	GetAPIKey() string
// }

// type ITokenAuth interface{
// 	GetToken() string
// }

// type IAuthTokenValidator interface {
//   ValidateApiKeyAuth(context.Context, string) (authz.ScopedSession, error)
//   ValidateCookieAuth(context.Context, string) (authz.ScopedSession, error)

//   CreateSessionToken(ctx context.Context, item any) (string, error)
//   ValidateSessionToken(ctx context.Context, token string) (authz.ScopedSession, error)
// }

// type AuthorizationHandler struct {
//   *authz.AuthzController
//   IAuthTokenValidator
// }

// func NewAuthorizationHandler(val IAuthTokenValidator, scopes map[string]authz.Scopes) *AuthorizationHandler {
// 	ctrl := authz.NewAuthzController(scopes)

//   return &AuthorizationHandler{
//     AuthzController: ctrl,
//     IAuthTokenValidator: val,
//   }
// }

// func (h *AuthorizationHandler) HandleApiKeyAuth(c context.Context, operationName string, t IApiKeyAuth) (context.Context, error) {
//   session, err := h.ValidateApiKeyAuth(c, t.GetAPIKey())
// 	if err != nil {
// 		return c, err
// 	}

//   ctx := context.WithValue(c, sessions.ContextSessionKey{}, session)
//   if h.ValidateScopes(ctx, operationName, session.GetScopes()); err != nil {
//     return ctx, nil
//   }

// 	return ctx, nil
// }

// func (h *AuthorizationHandler) HandleCookieAuth(c context.Context, operationName string, t IApiKeyAuth) (context.Context, error) {
//   session, err := h.ValidateCookieAuth(c, t.GetAPIKey())
// 	if err != nil {
// 		return c, err
// 	}

//   ctx := context.WithValue(c, sessions.ContextSessionKey{}, session)
//   if h.ValidateScopes(ctx, operationName, session.GetScopes()); err != nil {
//     return ctx, nil
//   }

// 	return ctx, nil
// }
