// Package auth provides the core authentication and authorization logic,
// including OIDC integration with Dex, platform token issuance/verification,
// API key management, user management, and an Envoy external authorization check service.
// This file specifically implements the HTTP API layer using the Echo framework,
// defining routes and handlers for interacting with the auth service.
package auth

import (
	"context"
	"crypto/rsa"
	"crypto/sha512"
	_ "embed" // Keep if needed for email templates etc.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	// Correct import path for Dex v2 API
	dexApi "github.com/dexidp/dex/api/v2" // Ensure this exact path is used

	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/uuid"
	api2 "github.com/opengovern/og-util/pkg/api" // Assuming this is the correct path for Role type
	"github.com/opengovern/og-util/pkg/httpserver"
	"github.com/opengovern/opensecurity/services/auth/db" // Local DB package (imports interface now too)
	"github.com/opengovern/opensecurity/services/auth/utils"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes" // For gRPC status codes

	// Use v5 if that's standard in your project, otherwise v4
	"github.com/golang-jwt/jwt" // Or jwt "github.com/golang-jwt/jwt/v5"

	"github.com/labstack/echo/v4"
	"github.com/opengovern/opensecurity/services/auth/api" // Local API definitions
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DexClaims struct defines the expected claims structure parsed from an OIDC ID Token
// issued by the Dex identity provider. It includes standard OIDC claims and embeds
// jwt.StandardClaims for common JWT fields.
type DexClaims struct {
	Email           string                 `json:"email"`
	EmailVerified   bool                   `json:"email_verified"`
	Groups          []string               `json:"groups"` // Groups claim from Dex/upstream IdP
	Name            string                 `json:"name"`
	FederatedClaims map[string]interface{} `json:"federated_claims,omitempty"` // Optional federated claims
	jwt.StandardClaims
}

// httpRoutes holds dependencies needed by the HTTP API handlers.
// It includes logging, cryptographic keys, the database interface,
// reference to the core auth server logic, and configured Dex client details.
type httpRoutes struct {
	logger             *zap.Logger          // Structured logger instance.
	platformPrivateKey *rsa.PrivateKey      // Private key used for signing platform JWTs and API Keys.
	platformKeyID      string               // Key ID ('kid') associated with the platform keys.
	db                 db.DatabaseInterface // Interface for database operations (allows mocking).
	authServer         *Server              // Reference to the core server logic (e.g., for Dex gRPC client, public key).
	// Effective Dex client IDs and names (determined during startup in cmd.go)
	dexPublicClientID    string
	dexPublicClientName  string
	dexPrivateClientID   string
	dexPrivateClientName string
}

// Register sets up the HTTP routes, middleware, and handlers for the auth service API
// within the provided Echo web server instance. It implements the httpserver.Routes interface.
func (r *httpRoutes) Register(e *echo.Echo) {
	// API versioning group
	v1 := e.Group("/api/v1")

	// --- Public / Semi-public endpoints ---
	v1.GET("/check", r.Check)  // For Envoy auth checks
	v1.POST("/token", r.Token) // For OAuth/OIDC code exchange

	// --- User Management Endpoints ---
	v1.GET("/users", httpserver.AuthorizeHandler(r.GetUsers, api2.EditorRole))
	v1.GET("/user/:id", httpserver.AuthorizeHandler(r.GetUserDetails, api2.EditorRole))
	v1.GET("/me", httpserver.AuthorizeHandler(r.GetMe, api2.ViewerRole))
	v1.POST("/user", httpserver.AuthorizeHandler(r.CreateUser, api2.EditorRole))
	v1.PUT("/user", httpserver.AuthorizeHandler(r.UpdateUser, api2.EditorRole))
	v1.GET("/user/password/check", httpserver.AuthorizeHandler(r.CheckUserPasswordChangeRequired, api2.ViewerRole))
	v1.POST("/user/password/reset", httpserver.AuthorizeHandler(r.ResetUserPassword, api2.ViewerRole))
	v1.DELETE("/user/:id", httpserver.AuthorizeHandler(r.DeleteUser, api2.AdminRole))
	v1.PUT("/user/:id/enable", httpserver.AuthorizeHandler(r.EnableUserHandler, api2.AdminRole))
	v1.PUT("/user/:id/disable", httpserver.AuthorizeHandler(r.DisableUserHandler, api2.AdminRole))

	// --- API Key Management Endpoints ---
	v1.POST("/keys", httpserver.AuthorizeHandler(r.CreateAPIKey, api2.AdminRole))
	v1.GET("/keys", httpserver.AuthorizeHandler(r.ListAPIKeys, api2.AdminRole))
	v1.DELETE("/key/:id", httpserver.AuthorizeHandler(r.DeleteAPIKey, api2.AdminRole))
	v1.PUT("/key/:id", httpserver.AuthorizeHandler(r.EditAPIKey, api2.AdminRole))

	// --- Connector Management Endpoints ---
	v1.GET("/connectors", httpserver.AuthorizeHandler(r.GetConnectors, api2.AdminRole))
	v1.GET("/connectors/supported-connector-types", httpserver.AuthorizeHandler(r.GetSupportedType, api2.AdminRole))
	v1.GET("/connector/:type", httpserver.AuthorizeHandler(r.GetConnectors, api2.AdminRole)) // Filters by type
	v1.POST("/connector", httpserver.AuthorizeHandler(r.CreateConnector, api2.AdminRole))
	v1.POST("/connector/auth0", httpserver.AuthorizeHandler(r.CreateAuth0Connector, api2.AdminRole))
	v1.PUT("/connector", httpserver.AuthorizeHandler(r.UpdateConnector, api2.AdminRole))
	v1.DELETE("/connector/:id", httpserver.AuthorizeHandler(r.DeleteConnector, api2.AdminRole)) // ID is Dex Connector ID string
}

// bindValidate is a helper function to bind the request body (typically JSON)
// into the provided struct pointer `i` and then validate the struct using
// the Echo instance's configured validator.
func bindValidate(ctx echo.Context, i interface{}) error {
	if err := ctx.Bind(i); err != nil {
		return fmt.Errorf("failed to bind request: %w", err)
	}
	if err := ctx.Validate(i); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	return nil
}

// Check godoc
// @Summary Perform Authorization Check (Envoy)
// @Description Endpoint typically called by Envoy External Authorization filter. Verifies Bearer token, checks user status/permissions.
// @Tags auth
// @Success 200 {string} string "OK (Authorization granted)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/check [get]
// Check handles Envoy's Check request by reconstructing the Envoy request attributes,
// calling the core gRPC Check logic in the authServer, and translating the gRPC response
// back into an appropriate HTTP response for Envoy (typically 200 OK with headers on allow,
// or 401/403 on deny).
func (r *httpRoutes) Check(ctx echo.Context) error {
	// 1. Build the Envoy CheckRequest
	httpReq := ctx.Request()
	orig := httpReq.Header.Get(HeaderOrigURI)
	fullPath := httpReq.URL.RequestURI()
	if orig != "" {
		if u, err := url.Parse(orig); err == nil {
			fullPath = u.RequestURI()
		}
	}

	req := &envoyauth.CheckRequest{
		Attributes: &envoyauth.AttributeContext{
			Request: &envoyauth.AttributeContext_Request{
				Http: &envoyauth.AttributeContext_HttpRequest{
					Method: httpReq.Header.Get(HeaderOrigMethod), // may be blank
					Path:   fullPath,
					Host:   httpReq.Host,
					Scheme: httpReq.URL.Scheme,
					Headers: func() map[string]string {
						m := make(map[string]string, len(httpReq.Header))
						for k, vs := range httpReq.Header {
							if len(vs) > 0 {
								m[k] = vs[0]
							} else {
								m[k] = ""
							}
						}
						// also copy request-ID if you use it downstream
						if rid := httpReq.Header.Get(HeaderRequestID); rid != "" {
							m[HeaderRequestID] = rid
						}
						return m
					}(),
				},
			},
		},
	}

	// 2. Call your authServer
	res, err := r.authServer.Check(ctx.Request().Context(), req)
	if err != nil {
		r.logger.Error("authServer.Check failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "authorization error")
	}

	// 3. Map gRPC code → HTTP
	switch codes.Code(res.Status.Code) {
	case codes.OK:
		// fallthrough to header injection
	case codes.Unauthenticated:
		return echo.NewHTTPError(http.StatusUnauthorized, res.Status.Message)
	case codes.PermissionDenied:
		return echo.NewHTTPError(http.StatusForbidden, res.Status.Message)
	default:
		return echo.NewHTTPError(http.StatusInternalServerError, res.Status.Message)
	}

	// 4. Inject any OkResponse headers
	if ok := res.GetOkResponse(); ok != nil {
		for _, he := range ok.GetHeaders() {
			if h := he.GetHeader(); h != nil {
				ctx.Response().Header().Set(h.Key, h.Value)
			}
		}
	}

	return ctx.NoContent(http.StatusOK)
}

// Token godoc
// @Summary Exchange OIDC Code for Platform Token
// @Description Handles the OIDC authorization code flow callback. Exchanges the provided code with Dex for an OIDC token set, verifies the ID token, looks up the user locally, enriches claims with local role/IDs, and issues a new platform-specific JWT signed by this service. Includes a self-verification step after signing.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body api.GetTokenRequest true "Authorization Code and Callback URL"
// @Success 200 {object} map[string]interface{} "Original Dex token response with 'access_token' replaced by platform JWT"
// @Failure 400 {object} echo.HTTPError "Bad Request (Missing code/callback, invalid request format)"
// @Failure 401 {object} echo.HTTPError "Unauthorized (Failed to verify token from Dex)"
// @Failure 403 {object} echo.HTTPError "Forbidden (User authenticated with Dex but not found locally or inactive)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, token signing/verification error, config error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Failed to communicate with Dex)"
// @Router /auth/api/v1/token [post]
// Token handles the OIDC authorization code exchange.
func (r *httpRoutes) Token(ctx echo.Context) error {
	var req api.GetTokenRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	domain := os.Getenv("DEX_AUTH_DOMAIN")
	if domain == "" {
		r.logger.Error("DEX_AUTH_DOMAIN not set")
		return echo.NewHTTPError(http.StatusInternalServerError, "identity provider misconfigured")
	}
	tokenURL := fmt.Sprintf("%s/token", strings.TrimRight(domain, "/"))

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", req.Code)
	data.Set("redirect_uri", req.CallBackUrl)
	data.Set("client_id", r.dexPublicClientID)
	data.Set("client_secret", "")

	httpReq, err := http.NewRequestWithContext(ctx.Request().Context(),
		http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		r.logger.Error("building token request failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to create request")
	}
	httpReq.Header.Set(HeaderContentType, MIMEFormURLEncoded)
	httpReq.Header.Set(HeaderAccept, MIMEApplicationJSON)

	client := &http.Client{Timeout: DefaultHTTPTimeout}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		r.logger.Error("token exchange failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "identity provider unreachable")
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		r.logger.Error("token exchange error",
			zap.Int("status", httpResp.StatusCode),
			zap.String("body", string(body)))
		return echo.NewHTTPError(http.StatusBadGateway, "token exchange failed")
	}

	var tok map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&tok); err != nil {
		r.logger.Error("decoding token response failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid identity response")
	}

	// pick id_token first, fallback to access_token
	raw := ""
	if idt, ok := tok["id_token"].(string); ok && idt != "" {
		raw = idt
	} else if at, ok := tok["access_token"].(string); ok {
		raw = at
	}
	if raw == "" {
		r.logger.Error("no token to verify", zap.Any("resp", tok))
		return echo.NewHTTPError(http.StatusBadRequest, "no token in response")
	}

	// verify with Dex
	dv, err := r.authServer.dexVerifier.Verify(ctx.Request().Context(), raw)
	if err != nil {
		r.logger.Warn("Dex token verification failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid identity token")
	}

	var claimsRaw json.RawMessage
	if err := dv.Claims(&claimsRaw); err != nil {
		r.logger.Error("extracting claims failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid identity token")
	}
	var c DexClaims
	if err := json.Unmarshal(claimsRaw, &c); err != nil {
		r.logger.Error("unmarshalling claims failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid identity token")
	}

	// lookup local user
	user, err := r.db.GetUserByEmail(ctx.Request().Context(), c.Email)
	if errors.Is(err, gorm.ErrRecordNotFound) || user == nil {
		r.logger.Warn("user not found", zap.String("email", c.Email))
		return echo.NewHTTPError(http.StatusForbidden, "user not registered")
	} else if err != nil {
		r.logger.Error("DB lookup failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "database error")
	}
	if !user.IsActive {
		r.logger.Warn("inactive user login", zap.String("email", user.Email))
		return echo.NewHTTPError(http.StatusForbidden, "user inactive")
	}

	// enrich & sign
	c.Groups = append(c.Groups, string(user.Role))
	c.Name = user.Username
	c.Subject = user.ExternalId
	c.Id = uuid.NewString()
	c.Issuer = JWTIssuerPlatform
	c.Audience = JWTAudienceClient

	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, c).
		SignedString(r.platformPrivateKey)
	if err != nil {
		r.logger.Error("JWT signing failed", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "token generation error")
	}

	// self-verify
	if pt, verr := jwt.ParseWithClaims(signed, &DexClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected alg %v", t.Header["alg"])
		}
		return r.authServer.platformPublicKey, nil
	}); verr != nil || !pt.Valid {
		r.logger.Error("new token self-verification failed", zap.Error(verr))
		return echo.NewHTTPError(http.StatusInternalServerError, "token validation error")
	}

	tok["access_token"] = signed
	r.logger.Info("token exchange successful", zap.String("email", c.Email))
	return ctx.JSON(http.StatusOK, tok)
}

// mapsKeys is a helper to get map keys for logging without exposing values.
func mapsKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// GetUsers godoc
// @Summary List Users
// @Description Retrieves a list of registered users. Requires Editor role.
// @Security BearerToken
// @Tags users
// @Produce json
// @Success 200 {array} api.GetUsersResponse "List of users"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/users [get]
// GetUsers handles requests to list all users stored in the local database.
func (r *httpRoutes) GetUsers(ctx echo.Context) error {
	users, err := r.db.GetUsers(ctx.Request().Context())
	if err != nil {
		r.logger.Error("Failed to get users from DB", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve users")
	}
	resp := make([]api.GetUsersResponse, 0, len(users))
	for _, u := range users {
		tempResp := api.GetUsersResponse{ID: u.ID, UserName: u.Username, Email: u.Email, EmailVerified: u.EmailVerified, ExternalId: u.ExternalId, RoleName: u.Role, CreatedAt: u.CreatedAt, IsActive: u.IsActive, ConnectorId: u.ConnectorId, FullName: u.FullName}
		if !u.LastLogin.IsZero() {
			tempResp.LastActivity = &u.LastLogin
		}
		resp = append(resp, tempResp)
	}
	return ctx.JSON(http.StatusOK, resp)
}

// GetUserDetails godoc
// @Summary Get User Details by ID
// @Description Retrieves details for a specific user by their internal database ID. Requires Editor role.
// @Security BearerToken
// @Tags users
// @Produce json
// @Param id path int true "User Database ID" format(uint) example(123)
// @Success 200 {object} api.GetUserResponse "User details"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid ID format)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "User Not Found"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/user/{id} [get]
// GetUserDetails handles requests to fetch details for a single user by database ID.
func (r *httpRoutes) GetUserDetails(ctx echo.Context) error {
	userIDParam := ctx.Param("id")
	userID, err := strconv.ParseUint(userIDParam, 10, 32)
	if err != nil {
		r.logger.Warn("Invalid user ID format in GetUserDetails", zap.String("idParam", userIDParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID format")
	}
	user, err := r.db.GetUser(ctx.Request().Context(), strconv.FormatUint(userID, 10))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to get user details from DB", zap.Uint64("userID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user details")
	}
	if user == nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	resp := api.GetUserResponse{ID: user.ID, UserName: user.Username, Email: user.Email, EmailVerified: user.EmailVerified, CreatedAt: user.CreatedAt, Blocked: !user.IsActive, RoleName: user.Role}
	if !user.LastLogin.IsZero() {
		resp.LastActivity = &user.LastLogin
	}
	return ctx.JSON(http.StatusOK, resp)
}

// GetMe godoc
// @Summary Get Current User Details
// @Description Retrieves details for the currently authenticated user making the request (based on the validated token). Requires Viewer role.
// @Security BearerToken
// @Tags users
// @Produce json
// @Success 200 {object} api.GetMeResponse "Current user details"
// @Failure 401 {object} echo.HTTPError "Unauthorized (Token missing or invalid)"
// @Failure 404 {object} echo.HTTPError "User Not Found (User from token not in DB)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/me [get]
// GetMe handles requests for the calling user's own details.
func (r *httpRoutes) GetMe(ctx echo.Context) error {
	userID := httpserver.GetUserID(ctx)
	if userID == "" {
		r.logger.Error("UserID missing from context in GetMe handler")
		return echo.NewHTTPError(http.StatusUnauthorized, "User ID not found in request context")
	}
	dbUser, err := r.db.GetUserByExternalID(ctx.Request().Context(), userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			r.logger.Warn("User from token context not found in DB", zap.String("externalID", userID))
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to get current user from DB", zap.String("externalID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user data")
	}
	if dbUser == nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	resp := api.GetMeResponse{ID: dbUser.ID, UserName: dbUser.Username, Email: dbUser.Email, EmailVerified: dbUser.EmailVerified, CreatedAt: dbUser.CreatedAt, Blocked: !dbUser.IsActive, Role: string(dbUser.Role), MemberSince: dbUser.CreatedAt, ConnectorId: dbUser.ConnectorId}
	if !dbUser.LastLogin.IsZero() {
		resp.LastLogin = &dbUser.LastLogin
		resp.LastActivity = &dbUser.LastLogin
	}
	return ctx.JSON(http.StatusOK, resp)
}

// CreateAPIKey godoc
// @Summary Create Platform API Key
// @Description Creates a new long-lived API key (JWT) associated with the requesting user, granting specified permissions (role). Requires Admin role to create keys. The returned token should be stored securely by the client.
// @Security BearerToken
// @Tags keys
// @Accept json
// @Produce json
// @Param request body api.CreateAPIKeyRequest true "API Key Name and Role"
// @Success 201 {object} api.CreateAPIKeyResponse "API Key details including the generated token"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 409 {object} echo.HTTPError "Conflict (API key limit reached)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, token signing error)"
// @Failure 503 {object} echo.HTTPError "Service Unavailable (Platform key signing disabled)"
// @Router /auth/api/v1/keys [post]
// CreateAPIKey generates a new platform API key (JWT format) for the requesting user.
func (r *httpRoutes) CreateAPIKey(ctx echo.Context) error {
	userID := httpserver.GetUserID(ctx)
	var req api.CreateAPIKeyRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	usr, err := utils.GetUser(ctx.Request().Context(), userID, r.db)
	if err != nil || usr == nil {
		r.logger.Error("Failed to get creator user details for API key", zap.String("userID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user details")
	}
	currentKeyCount, err := r.db.CountApiKeysForUser(ctx.Request().Context(), userID)
	if err != nil {
		r.logger.Error("Failed to count user API keys", zap.String("userID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to count API keys")
	}
	if currentKeyCount >= MaxAPIKeysPerUser {
		r.logger.Warn("API key limit reached for user", zap.String("userID", userID), zap.Int64("limit", MaxAPIKeysPerUser))
		return echo.NewHTTPError(http.StatusConflict, fmt.Sprintf("Maximum number of %d API keys for user reached", MaxAPIKeysPerUser))
	} // Use constant
	jti := uuid.NewString()
	apiKeyClaims := &jwt.StandardClaims{Issuer: JWTIssuerPlatform, Subject: userID, Audience: JWTAudienceAPI, ExpiresAt: 0, IssuedAt: jwt.TimeFunc().Unix(), Id: jti} // Use constants
	if r.platformPrivateKey == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "Platform API key signing is disabled")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, apiKeyClaims)
	if r.platformKeyID != "" {
		token.Header["kid"] = r.platformKeyID
		r.logger.Debug("Adding kid to API Key JWT header", zap.String("kid", r.platformKeyID))
	} else {
		r.logger.Warn("Platform Key ID (kid) is not configured. API Key JWT header will not contain kid.")
	}
	signedToken, err := token.SignedString(r.platformPrivateKey)
	if err != nil {
		r.logger.Error("Failed to sign API key token", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create API key token")
	}
	masked := fmt.Sprintf("%s...%s", signedToken[:min(DefaultAPIKeyMaskLenStart, len(signedToken))], signedToken[max(0, len(signedToken)-DefaultAPIKeyMaskLenEnd):])
	hash := sha512.New()
	_, err = hash.Write([]byte(signedToken))
	if err != nil {
		r.logger.Error("Failed to hash API key token", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to hash API key")
	} // Use constants
	keyHash := hex.EncodeToString(hash.Sum(nil))
	r.logger.Info("Creating API Key DB entry", zap.String("name", req.Name), zap.String("role", string(req.Role)))
	apikey := db.ApiKey{Name: req.Name, Role: req.Role, CreatorUserID: userID, IsActive: true, MaskedKey: masked, KeyHash: keyHash}
	err = r.db.AddApiKey(ctx.Request().Context(), &apikey)
	if err != nil {
		r.logger.Error("Failed to add API Key to db", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save API key")
	}
	r.logger.Info("Successfully created and stored API Key", zap.Uint("apiKeyID", apikey.ID), zap.String("name", apikey.Name))
	return ctx.JSON(http.StatusCreated, api.CreateAPIKeyResponse{ID: apikey.ID, Name: apikey.Name, Active: apikey.IsActive, CreatedAt: apikey.CreatedAt, RoleName: apikey.Role, Token: signedToken})
}

// DeleteAPIKey godoc
// @Summary Delete Platform API Key
// @Description Deletes a platform API key by its internal database ID. Requires Admin role.
// @Security BearerToken
// @Tags keys
// @Produce json
// @Param id path int true "API Key Database ID" format(uint64) example(5)
// @Success 202 {string} string "Accepted (Deletion initiated)"
// @Success 204 {string} string "No Content (Deletion successful)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid ID format)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "Not Found (API Key with ID not found)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/key/{id} [delete]
// DeleteAPIKey handles requests to delete an API key record from the database.
func (r *httpRoutes) DeleteAPIKey(ctx echo.Context) error {
	idParam := ctx.Param("id")
	apiKeyID, err := strconv.ParseUint(idParam, 10, 64)
	if err != nil {
		r.logger.Warn("Invalid API Key ID format in DeleteAPIKey", zap.String("idParam", idParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid API Key ID format")
	}
	err = r.db.DeleteAPIKey(ctx.Request().Context(), apiKeyID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "API Key not found")
		}
		r.logger.Error("Failed to delete API Key", zap.Uint64("apiKeyID", apiKeyID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete API Key")
	}
	r.logger.Info("Deleted API Key", zap.Uint64("apiKeyID", apiKeyID))
	return ctx.NoContent(http.StatusAccepted)
}

// EditAPIKey godoc
// @Summary Update Platform API Key
// @Description Updates the status (active/inactive) and/or role of an existing platform API key by its internal database ID. Requires Admin role.
// @Security BearerToken
// @Tags keys
// @Accept json
// @Produce json
// @Param id path int true "API Key Database ID" format(uint64) example(5)
// @Param request body api.EditAPIKeyRequest true "Fields to update (Role, IsActive)"
// @Success 202 {string} string "Accepted (Update successful)"
// @Success 204 {string} string "No Content (Update successful)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input or ID format)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "Not Found (API Key with ID not found)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/key/{id} [put]
// EditAPIKey handles requests to modify the role or active status of an API key record.
func (r *httpRoutes) EditAPIKey(ctx echo.Context) error {
	idParam := ctx.Param("id")
	var req api.EditAPIKeyRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	err := r.db.UpdateAPIKey(ctx.Request().Context(), idParam, req.IsActive, req.Role)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "API Key not found")
		}
		r.logger.Error("Failed to update API Key", zap.String("apiKeyID", idParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update API Key")
	}
	r.logger.Info("Updated API Key", zap.String("apiKeyID", idParam), zap.Bool("isActive", req.IsActive), zap.String("role", string(req.Role)))
	return ctx.NoContent(http.StatusAccepted)
}

// ListAPIKeys godoc
// @Summary List Platform API Keys
// @Description Retrieves a list of platform API keys created by the currently authenticated user. Requires Admin role.
// @Security BearerToken
// @Tags keys
// @Produce json
// @Success 200 {array} api.APIKeyResponse "List of API keys created by the user"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/keys [get]
// ListAPIKeys retrieves metadata for API keys created by the requesting user.
func (r *httpRoutes) ListAPIKeys(ctx echo.Context) error {
	requestingUserID := httpserver.GetUserID(ctx)
	keys, err := r.db.ListApiKeysForUser(ctx.Request().Context(), requestingUserID)
	if err != nil {
		r.logger.Error("Failed to list API keys for user", zap.String("userID", requestingUserID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve API keys")
	}
	resp := make([]api.APIKeyResponse, 0, len(keys))
	for _, key := range keys {
		resp = append(resp, api.APIKeyResponse{ID: key.ID, CreatedAt: key.CreatedAt, UpdatedAt: key.UpdatedAt, Name: key.Name, RoleName: key.Role, CreatorUserID: key.CreatorUserID, Active: key.IsActive, MaskedKey: key.MaskedKey})
	}
	return ctx.JSON(http.StatusOK, resp)
}

// CreateUser godoc
// @Summary Create User
// @Description Creates a new user (either local with password or linked to an external connector). Requires Editor role. The first user created automatically becomes an Admin.
// @Security BearerToken
// @Tags users
// @Accept json
// @Produce json
// @Param request body api.CreateUserRequest true "User details (email, role, optional password, connector)"
// @Success 201 {string} string "Created"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input, missing email)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 409 {object} echo.HTTPError "Conflict (Email already exists)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, password hashing error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex for password creation)"
// @Router /auth/api/v1/user [post]
// CreateUser handles requests to create a new user.
func (r *httpRoutes) CreateUser(ctx echo.Context) error {
	var req api.CreateUserRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	err := r.DoCreateUser(ctx.Request().Context(), req)
	if err != nil {
		return err
	}
	r.logger.Info("User created successfully request processed", zap.String("email", req.EmailAddress))
	return ctx.NoContent(http.StatusCreated)
}

// DoCreateUser contains the core logic for creating a user.
func (r *httpRoutes) DoCreateUser(ctx context.Context, req api.CreateUserRequest) error {
	if req.EmailAddress == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email address is required")
	}
	email := strings.ToLower(strings.TrimSpace(req.EmailAddress))
	existingUser, err := r.db.GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		r.logger.Error("Failed to check existing user by email", zap.String("email", email), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check user existence")
	}
	if existingUser != nil {
		r.logger.Warn("Attempt to create user with existing email", zap.String("email", email))
		return echo.NewHTTPError(http.StatusConflict, "Email address already in use")
	}
	count, err := r.db.GetUsersCount(ctx)
	if err != nil {
		r.logger.Error("Failed to get users count", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get users count")
	}
	isAdminBootstrap := count == 0
	role := api2.ViewerRole
	if req.Role != nil {
		role = *req.Role
	}
	if isAdminBootstrap {
		r.logger.Info("Creating first user, assigning Admin role", zap.String("email", email))
		role = api2.AdminRole
	} else if req.Role == nil {
		r.logger.Info("No role specified for new user, defaulting to Viewer", zap.String("email", email))
	}
	connectorType := req.ConnectorId
	externalID := ""
	requirePasswordChange := true
	if req.Password != nil && *req.Password != "" {
		connectorType = ConnectorLocal
		externalID = fmt.Sprintf("%s|%s", ConnectorLocal, email)
		r.logger.Info("Creating local user with password", zap.String("email", email), zap.String("externalId", externalID))
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			r.logger.Error("Failed to hash user password", zap.String("email", email), zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process password")
		}
		dexReq := &dexApi.CreatePasswordReq{Password: &dexApi.Password{UserId: externalID, Email: email, Hash: hashedPassword, Username: email}}
		resp, err := r.authServer.dexClient.CreatePassword(ctx, dexReq)
		if err != nil {
			r.logger.Error("Failed to create dex password", zap.String("email", email), zap.Error(err))
			return echo.NewHTTPError(http.StatusBadGateway, "Failed to create user identity with provider")
		}
		if resp.AlreadyExists {
			r.logger.Warn("Dex password entry already exists for new user, attempting update", zap.String("email", email))
			updateReq := &dexApi.UpdatePasswordReq{Email: email, NewHash: hashedPassword, NewUsername: email}
			_, err = r.authServer.dexClient.UpdatePassword(ctx, updateReq)
			if err != nil {
				r.logger.Error("Failed to update potentially existing dex password", zap.String("email", email), zap.Error(err))
				return echo.NewHTTPError(http.StatusBadGateway, "Failed to update user identity with provider")
			}
		}
		requirePasswordChange = false
	} else {
		if connectorType == "" || connectorType == ConnectorLocal {
			connectorType = ConnectorLocal
			externalID = fmt.Sprintf("%s|%s", ConnectorLocal, email)
			r.logger.Info("Creating local user without initial password", zap.String("email", email))
		} else {
			externalID = fmt.Sprintf("%s|%s", connectorType, email)
			r.logger.Info("Creating user linked to external connector", zap.String("email", email), zap.String("connector", connectorType))
			requirePasswordChange = false
		}
	}
	if isAdminBootstrap {
		requirePasswordChange = false
	}
	newUser := &db.User{Email: email, Username: email, FullName: email, Role: role, EmailVerified: false, ConnectorId: connectorType, ExternalId: externalID, RequirePasswordChange: requirePasswordChange, IsActive: true}
	err = r.db.CreateUser(ctx, newUser)
	if err != nil {
		r.logger.Error("Failed to create user in local database", zap.String("email", email), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save user data")
	}
	return nil
}

// UpdateUser godoc
// @Summary Update User
// @Description Updates an existing user's details (Role, Status, Username, Fullname, Connector, Password for local users). Requires Editor role. User identified by email in request body.
// @Security BearerToken
// @Tags users
// @Accept json
// @Produce json
// @Param request body api.UpdateUserRequest true "User details to update (must include email_address)"
// @Success 200 {string} string "OK (User updated)"
// @Success 204 {string} string "No Content (User updated)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input, missing email, password for non-local user)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "User Not Found"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, password hashing error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex for password update)"
// @Router /auth/api/v1/user [put]
// UpdateUser handles requests to modify an existing user.
func (r *httpRoutes) UpdateUser(ctx echo.Context) error {
	var req api.UpdateUserRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.EmailAddress == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email address is required to identify user")
	}
	email := strings.ToLower(strings.TrimSpace(req.EmailAddress))
	user, err := r.db.GetUserByEmail(ctx.Request().Context(), email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to get user for update", zap.String("email", email), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user")
	}
	if user == nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	if req.Password != nil && *req.Password != "" {
		if user.ConnectorId != ConnectorLocal {
			r.logger.Warn("Attempt to set password for non-local user", zap.String("email", email), zap.String("connector", user.ConnectorId))
			return echo.NewHTTPError(http.StatusBadRequest, "Cannot set password for user linked to external connector")
		}
		r.logger.Info("Updating password for local user", zap.String("email", email))
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			r.logger.Error("Failed to hash updated password", zap.String("email", email), zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process password")
		}
		dexUpdateReq := &dexApi.UpdatePasswordReq{Email: email, NewHash: hashedPassword, NewUsername: email}
		resp, err := r.authServer.dexClient.UpdatePassword(ctx.Request().Context(), dexUpdateReq)
		if err != nil {
			r.logger.Error("Failed to update dex password", zap.String("email", email), zap.Error(err))
			return echo.NewHTTPError(http.StatusBadGateway, "Failed to update user identity with provider")
		}
		if resp.NotFound {
			r.logger.Warn("Dex password entry not found during update, attempting creation", zap.String("email", email))
			dexCreateReq := &dexApi.CreatePasswordReq{Password: &dexApi.Password{UserId: user.ExternalId, Email: email, Hash: hashedPassword, Username: email}}
			_, err = r.authServer.dexClient.CreatePassword(ctx.Request().Context(), dexCreateReq)
			if err != nil {
				r.logger.Error("Failed to create dex password during update fallback", zap.String("email", email), zap.Error(err))
				return echo.NewHTTPError(http.StatusBadGateway, "Failed to create user identity with provider")
			}
		}
		err = r.db.UserPasswordUpdate(ctx.Request().Context(), user.ID)
		if err != nil {
			r.logger.Error("Failed to mark user password as updated in db", zap.Uint("userID", user.ID), zap.Error(err))
		}
	}
	updateNeeded := false
	if req.Role != nil && user.Role != *req.Role {
		user.Role = *req.Role
		updateNeeded = true
	}
	if user.IsActive != req.IsActive {
		user.IsActive = req.IsActive
		updateNeeded = true
	}
	if req.UserName != "" && user.Username != req.UserName {
		user.Username = req.UserName
		updateNeeded = true
	}
	if req.FullName != "" && user.FullName != req.FullName {
		user.FullName = req.FullName
		updateNeeded = true
	}
	if req.ConnectorId != "" && user.ConnectorId != req.ConnectorId {
		user.ConnectorId = req.ConnectorId
		user.ExternalId = fmt.Sprintf("%s|%s", req.ConnectorId, user.Email)
		r.logger.Warn("User connector changed", zap.String("email", email), zap.String("oldConnector", user.ConnectorId), zap.String("newConnector", req.ConnectorId))
		updateNeeded = true
	}
	if updateNeeded {
		r.logger.Info("Updating user details in database", zap.String("email", email))
		err = r.db.UpdateUser(ctx.Request().Context(), user)
		if err != nil {
			r.logger.Error("Failed to update user in database", zap.String("email", email), zap.Error(err))
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update user data")
		}
	} else {
		r.logger.Info("No user details needed updating", zap.String("email", email))
	}
	return ctx.NoContent(http.StatusOK)
}

// DeleteUser godoc
// @Summary Delete User
// @Description Deletes a user by their internal database ID. Requires Admin role. Cannot delete the initial admin (ID 1). Also attempts to delete associated Dex password entry for local users.
// @Security BearerToken
// @Tags users
// @Produce json
// @Param id path int true "User Database ID to delete" format(uint) example(123)
// @Success 202 {string} string "Accepted (Deletion process initiated)"
// @Success 204 {string} string "No Content (Deletion successful)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid ID format, attempt to delete ID 1)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "User Not Found"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex for password deletion)"
// @Router /auth/api/v1/user/{id} [delete]
// DeleteUser handles requests to delete a user by their database ID.
func (r *httpRoutes) DeleteUser(ctx echo.Context) error {
	idParam := ctx.Param("id")
	userID, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		r.logger.Warn("Invalid user ID format in DeleteUser", zap.String("idParam", idParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID format")
	}
	err = r.DoDeleteUser(ctx.Request().Context(), uint(userID))
	if err != nil {
		return err
	}
	r.logger.Info("User deleted successfully", zap.Uint("userID", uint(userID)))
	return ctx.NoContent(http.StatusAccepted)
}

// DoDeleteUser contains the core logic for deleting a user (DB and Dex cleanup).
func (r *httpRoutes) DoDeleteUser(ctx context.Context, userID uint) error {
	user, err := r.db.GetUser(ctx, strconv.FormatUint(uint64(userID), 10))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to get user for deletion", zap.Uint("userID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user before deletion")
	}
	if user == nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	if user.ID == 1 {
		r.logger.Warn("Attempt to delete the first user (ID 1)", zap.String("email", user.Email))
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete the initial administrator user")
	}
	if user.ConnectorId == ConnectorLocal {
		r.logger.Info("Deleting Dex password entry for local user", zap.String("email", user.Email))
		dexReq := &dexApi.DeletePasswordReq{Email: user.Email}
		resp, err := r.authServer.dexClient.DeletePassword(ctx, dexReq)
		if err != nil {
			r.logger.Error("Failed to remove dex password during user deletion", zap.String("email", user.Email), zap.Error(err))
			return echo.NewHTTPError(http.StatusBadGateway, "Failed to remove user identity from provider")
		}
		if resp.NotFound {
			r.logger.Warn("Dex password entry not found during deletion, proceeding", zap.String("email", user.Email))
		}
	}
	err = r.db.DeleteUser(ctx, user.ID)
	if err != nil {
		r.logger.Error("Failed to delete user from local database", zap.Uint("userID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete user data")
	}
	return nil
}

// CheckUserPasswordChangeRequired godoc
// @Summary Check if Password Change is Required
// @Description Checks if the currently authenticated user is required to change their password (typically for new local users). Requires Viewer role.
// @Security BearerToken
// @Tags users
// @Produce plain
// @Success 200 {string} string "CHANGE_REQUIRED or CHANGE_NOT_REQUIRED"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 404 {object} echo.HTTPError "User Not Found"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/user/password/check [get]
// CheckUserPasswordChangeRequired checks the database flag for the current user.
func (r *httpRoutes) CheckUserPasswordChangeRequired(ctx echo.Context) error {
	userId := httpserver.GetUserID(ctx)
	if userId == "" {
		r.logger.Error("UserID missing from context in CheckUserPasswordChangeRequired")
		return echo.NewHTTPError(http.StatusUnauthorized, "User ID not found in request context")
	}
	user, err := r.db.GetUserByExternalID(ctx.Request().Context(), userId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to get user for password check", zap.String("externalID", userId), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user data")
	}
	if user == nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	if user.RequirePasswordChange {
		return ctx.String(http.StatusOK, PasswordChangeRequired)
	} else {
		return ctx.String(http.StatusOK, PasswordChangeNotRequired)
	} // Use constants
}

// ResetUserPassword godoc
// @Summary Reset Current User's Password
// @Description Allows the currently authenticated user to reset their own password for local accounts. Requires Viewer role. Verifies current password before updating.
// @Security BearerToken
// @Tags users
// @Accept json
// @Produce json
// @Param request body api.ResetUserPasswordRequest true "Current and new password"
// @Success 202 {string} string "Accepted (Password reset successful)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input, non-local user, same password)"
// @Failure 401 {object} echo.HTTPError "Unauthorized (Incorrect current password)"
// @Failure 404 {object} echo.HTTPError "Not Found (User not found)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (Hashing error, DB error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex)"
// @Router /auth/api/v1/user/password/reset [post]
// ResetUserPassword allows authenticated users to change their own password if it's a local account.
func (r *httpRoutes) ResetUserPassword(ctx echo.Context) error {
	userId := httpserver.GetUserID(ctx)
	if userId == "" {
		r.logger.Error("UserID missing from context in ResetUserPassword")
		return echo.NewHTTPError(http.StatusUnauthorized, "User ID not found in request context")
	}
	user, err := r.db.GetUserByExternalID(ctx.Request().Context(), userId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to get user for password reset", zap.String("externalID", userId), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user data")
	}
	if user == nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}
	if user.ConnectorId != ConnectorLocal {
		r.logger.Warn("Password reset attempt for non-local user", zap.String("externalID", userId), zap.String("connector", user.ConnectorId))
		return echo.NewHTTPError(http.StatusBadRequest, "Password reset only available for local accounts")
	} // Use constant
	var req api.ResetUserPasswordRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Current and new passwords are required")
	}
	if req.CurrentPassword == req.NewPassword {
		return echo.NewHTTPError(http.StatusBadRequest, "New password must be different from the current password")
	}
	dexVerifyReq := &dexApi.VerifyPasswordReq{Email: user.Email, Password: req.CurrentPassword}
	resp, err := r.authServer.dexClient.VerifyPassword(ctx.Request().Context(), dexVerifyReq)
	if err != nil {
		r.logger.Error("Failed to verify current password with Dex", zap.String("email", user.Email), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to verify current password")
	}
	if resp.NotFound {
		r.logger.Error("Dex password entry not found for existing local user during verification", zap.String("email", user.Email))
		return echo.NewHTTPError(http.StatusInternalServerError, "User identity inconsistency")
	}
	if !resp.Verified {
		r.logger.Info("Incorrect current password provided during reset", zap.String("email", user.Email))
		return echo.NewHTTPError(http.StatusUnauthorized, "Incorrect current password")
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		r.logger.Error("Failed to hash new password", zap.String("email", user.Email), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process new password")
	}
	passwordUpdateReq := &dexApi.UpdatePasswordReq{Email: user.Email, NewHash: hashedPassword, NewUsername: user.Username}
	passwordUpdateResp, err := r.authServer.dexClient.UpdatePassword(ctx.Request().Context(), passwordUpdateReq)
	if err != nil {
		r.logger.Error("Failed to update dex password during reset", zap.String("email", user.Email), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to update password with identity provider")
	}
	if passwordUpdateResp.NotFound {
		r.logger.Error("Dex password entry not found for existing local user during update", zap.String("email", user.Email))
		return echo.NewHTTPError(http.StatusInternalServerError, "User identity inconsistency")
	}
	err = r.db.UserPasswordUpdate(ctx.Request().Context(), user.ID)
	if err != nil {
		r.logger.Error("Failed to mark user password as updated in db after reset", zap.Uint("userID", user.ID), zap.Error(err))
	}
	r.logger.Info("User successfully reset password", zap.String("email", user.Email))
	return ctx.NoContent(http.StatusAccepted)
}

// EnableUserHandler godoc
// @Summary Enable User Account
// @Description Marks a user account as active. Requires Admin role. Cannot enable the initial admin (ID 1).
// @Security BearerToken
// @Tags users
// @Produce json
// @Param id path int true "User Database ID to enable" format(uint) example(123)
// @Success 204 {string} string "No Content (User enabled successfully)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid ID format, attempt to modify ID 1)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "User Not Found"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/user/{id}/enable [put]
// EnableUserHandler handles requests to mark a user account as active (is_active=true).
func (r *httpRoutes) EnableUserHandler(ctx echo.Context) error {
	idParam := ctx.Param("id")
	userID, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		r.logger.Warn("Invalid user ID format in EnableUserHandler", zap.String("idParam", idParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID format")
	}
	if userID == 1 {
		r.logger.Warn("Attempt to modify activation status for user ID 1", zap.Uint64("userID", userID))
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot modify activation status for the initial administrator user")
	}
	err = r.db.EnableUser(ctx.Request().Context(), uint(userID))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to enable user in database", zap.Uint64("userID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to enable user")
	}
	r.logger.Info("User enabled successfully", zap.Uint64("userID", userID))
	return ctx.NoContent(http.StatusNoContent)
}

// DisableUserHandler godoc
// @Summary Disable User Account
// @Description Marks a user account as inactive (is_active=false). Requires Admin role. Cannot disable the initial admin (ID 1).
// @Security BearerToken
// @Tags users
// @Produce json
// @Param id path int true "User Database ID to disable" format(uint) example(123)
// @Success 204 {string} string "No Content (User disabled successfully)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid ID format, attempt to disable ID 1)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "User Not Found"
// @Failure 500 {object} echo.HTTPError "Internal Server Error"
// @Router /auth/api/v1/user/{id}/disable [put]
// DisableUserHandler handles requests to mark a user account as inactive (is_active=false).
func (r *httpRoutes) DisableUserHandler(ctx echo.Context) error {
	idParam := ctx.Param("id")
	userID, err := strconv.ParseUint(idParam, 10, 32)
	if err != nil {
		r.logger.Warn("Invalid user ID format in DisableUserHandler", zap.String("idParam", idParam), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid user ID format")
	}
	if userID == 1 {
		r.logger.Warn("Attempt to disable user ID 1", zap.Uint64("userID", userID))
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot disable the initial administrator user")
	}
	err = r.db.DisableUser(ctx.Request().Context(), uint(userID))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "User not found")
		}
		r.logger.Error("Failed to disable user in database", zap.Uint64("userID", userID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to disable user")
	}
	r.logger.Info("User disabled successfully", zap.Uint64("userID", userID))
	return ctx.NoContent(http.StatusNoContent)
}

// GetConnectors godoc
// @Summary List Dex Connectors
// @Description Retrieves a list of configured identity provider connectors from Dex, augmented with local metadata. Requires Admin role. Optionally filters by connector type if provided in the path.
// @Security BearerToken
// @Tags connectors
// @Produce json
// @Param type path string false "Connector Type Filter (e.g., 'oidc')"
// @Success 200 {array} api.GetConnectorsResponse "List of connectors"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex)"
// @Router /auth/api/v1/connectors [get]
// @Router /auth/api/v1/connector/{type} [get]
// GetConnectors lists configured Dex connectors, optionally filtered by type.
func (r *httpRoutes) GetConnectors(ctx echo.Context) error {
	connectorTypeFilter := ctx.Param("type")
	if connectorTypeFilter != "" {
		r.logger.Info("Filtering connectors by type", zap.String("type", connectorTypeFilter))
	}
	req := &dexApi.ListConnectorReq{}
	respDex, err := r.authServer.dexClient.ListConnectors(ctx.Request().Context(), req)
	if err != nil {
		r.logger.Error("Failed to list connectors from Dex", zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to retrieve connector list from provider")
	}
	connectorsFromDex := respDex.Connectors
	resp := make([]api.GetConnectorsResponse, 0, len(connectorsFromDex))
	for _, dexConnector := range connectorsFromDex {
		if dexConnector.Id == ConnectorLocal {
			continue
		}
		if connectorTypeFilter != "" && !strings.EqualFold(connectorTypeFilter, dexConnector.Type) {
			continue
		}
		localConnector, err := r.db.GetConnectorByConnectorID(ctx.Request().Context(), dexConnector.Id)
		if err != nil {
			r.logger.Warn("Failed to get local DB record for Dex connector", zap.String("connectorID", dexConnector.Id), zap.Error(err))
			continue
		}
		if localConnector == nil {
			r.logger.Warn("Connector exists in Dex but not in local DB", zap.String("connectorID", dexConnector.Id))
			continue
		}
		info := api.GetConnectorsResponse{ID: localConnector.ID, ConnectorID: dexConnector.Id, Type: dexConnector.Type, Name: dexConnector.Name, SubType: localConnector.ConnectorSubType, UserCount: localConnector.UserCount, CreatedAt: localConnector.CreatedAt, LastUpdate: localConnector.LastUpdate}
		if strings.EqualFold(dexConnector.Type, ConnectorOIDC) && len(dexConnector.Config) > 0 {
			var oidcConfig struct {
				Issuer   string `json:"issuer"`
				ClientID string `json:"clientID"`
			}
			err := json.Unmarshal(dexConnector.Config, &oidcConfig)
			if err != nil {
				r.logger.Warn("Failed to unmarshal OIDC config for connector", zap.String("connectorID", dexConnector.Id), zap.Error(err))
			} else {
				info.Issuer = oidcConfig.Issuer
				info.ClientID = oidcConfig.ClientID
			}
		}
		resp = append(resp, info)
	} // Use constants
	return ctx.JSON(http.StatusOK, resp)
}

// GetSupportedType godoc
// @Summary Get Supported Connector Types
// @Description Returns a list of connector types and subtypes currently supported for creation via the API. Requires Admin role. Reads data from configuration within the 'utils' package.
// @Security BearerToken
// @Tags connectors
// @Produce json
// @Success 200 {array} api.GetSupportedConnectorTypeResponse "List of supported connector types and subtypes"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (Configuration mismatch)"
// @Router /auth/api/v1/connectors/supported-connector-types [get]
// GetSupportedType returns a list of connector types and subtypes that can be created.
func (r *httpRoutes) GetSupportedType(ctx echo.Context) error {
	supportedConnectors := utils.SupportedConnectors
	supportedNames := utils.SupportedConnectorsNames
	responseList := make([]api.GetSupportedConnectorTypeResponse, 0, len(supportedConnectors))
	if subTypes, ok := supportedConnectors[ConnectorOIDC]; ok {
		subTypeNames := supportedNames[ConnectorOIDC]
		if len(subTypes) != len(subTypeNames) {
			r.logger.Error("Mismatch between supported OIDC subtypes and names in utils config")
		}
		apiSubTypes := make([]api.ConnectorSubTypes, 0, len(subTypes))
		for i, subTypeID := range subTypes {
			name := subTypeID
			if i < len(subTypeNames) {
				name = subTypeNames[i]
			}
			apiSubTypes = append(apiSubTypes, api.ConnectorSubTypes{ID: subTypeID, Name: name})
		}
		responseList = append(responseList, api.GetSupportedConnectorTypeResponse{ConnectorType: ConnectorOIDC, SubTypes: apiSubTypes})
	} // Use constant
	return ctx.JSON(http.StatusOK, responseList)
}

// CreateConnector godoc
// @Summary Create Dex Connector
// @Description Creates a new identity provider connector configuration in Dex (e.g., OIDC). Requires Admin role. Restarts Dex pod upon success.
// @Security BearerToken
// @Tags connectors
// @Accept json
// @Produce json
// @Param request body api.CreateConnectorRequest true "Connector Configuration"
// @Success 201 {object} map[string]interface{} "Details of the created connector metadata"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input, unsupported type/subtype)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 409 {object} echo.HTTPError "Conflict (Connector ID already exists)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, K8s interaction error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex)"
// @Router /auth/api/v1/connector [post]
// CreateConnector handles creating a new Dex connector configuration.
func (r *httpRoutes) CreateConnector(ctx echo.Context) error {
	var req api.CreateConnectorRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	dexUtilReq := utils.CreateConnectorRequest{ConnectorType: req.ConnectorType, ConnectorSubType: req.ConnectorSubType, Issuer: req.Issuer, TenantID: req.TenantID, ClientID: req.ClientID, ClientSecret: req.ClientSecret, ID: req.ID, Name: req.Name}
	dexAPICreator := utils.GetConnectorCreator(strings.ToLower(dexUtilReq.ConnectorType))
	if dexAPICreator == nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unsupported connector type: %s", dexUtilReq.ConnectorType))
	}
	dexAPIReq, err := dexAPICreator(dexUtilReq)
	if err != nil {
		r.logger.Warn("Failed to prepare Dex connector creation request", zap.Error(err), zap.Any("request", req))
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Failed to create connector request: %s", err.Error()))
	}
	r.logger.Info("Creating Dex connector", zap.String("id", dexAPIReq.Connector.Id), zap.String("type", dexAPIReq.Connector.Type), zap.String("name", dexAPIReq.Connector.Name))
	res, err := r.authServer.dexClient.CreateConnector(ctx.Request().Context(), dexAPIReq)
	if err != nil {
		r.logger.Error("Failed to create Dex connector via gRPC", zap.String("id", dexAPIReq.Connector.Id), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to create connector with identity provider")
	}
	if res.AlreadyExists {
		r.logger.Warn("Attempt to create Dex connector that already exists", zap.String("id", dexAPIReq.Connector.Id))
		return echo.NewHTTPError(http.StatusConflict, "Connector with this ID already exists")
	}
	localConnector := &db.Connector{ConnectorID: dexAPIReq.Connector.Id, ConnectorType: dexAPIReq.Connector.Type, ConnectorSubType: req.ConnectorSubType, LastUpdate: time.Now()}
	err = r.db.CreateConnector(ctx.Request().Context(), localConnector)
	if err != nil {
		r.logger.Error("Failed to create local DB record for new connector", zap.String("connectorID", dexAPIReq.Connector.Id), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save connector metadata locally after creation")
	}
	r.logger.Info("Restarting Dex pod to apply connector changes", zap.String("connectorID", dexAPIReq.Connector.Id))
	err = utils.RestartDexPod()
	if err != nil {
		r.logger.Error("Failed to restart Dex pod after connector creation", zap.String("connectorID", dexAPIReq.Connector.Id), zap.Error(err))
	}
	r.logger.Info("Successfully created connector", zap.String("id", dexAPIReq.Connector.Id))
	return ctx.JSON(http.StatusCreated, map[string]interface{}{"id": localConnector.ID, "connector_id": localConnector.ConnectorID, "type": localConnector.ConnectorType, "sub_type": localConnector.ConnectorSubType, "created_at": localConnector.CreatedAt})
}

// CreateAuth0Connector godoc
// @Summary Create Auth0 Dex Connector
// @Description Specialized endpoint to create an Auth0 OIDC connector in Dex and update necessary Dex OAuth clients. Requires Admin role. Restarts Dex pod upon success.
// @Security BearerToken
// @Tags connectors
// @Accept json
// @Produce json
// @Param request body api.CreateAuth0ConnectorRequest true "Auth0 Connector Configuration (including Dex client URIs)"
// @Success 201 {object} map[string]interface{} "Details of the created connector metadata"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 409 {object} echo.HTTPError "Conflict (Connector ID 'auth0' already exists)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, K8s interaction error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex)"
// @Router /auth/api/v1/connector/auth0 [post]
// CreateAuth0Connector handles the specific workflow for adding Auth0 as a connector.
func (r *httpRoutes) CreateAuth0Connector(ctx echo.Context) error {
	var req api.CreateAuth0ConnectorRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	dexUtilReq := utils.CreateAuth0ConnectorRequest{Issuer: req.Issuer, ClientID: req.ClientID, ClientSecret: req.ClientSecret, Domain: req.Domain}
	dexAPIReq, err := utils.CreateAuth0Connector(dexUtilReq)
	if err != nil {
		r.logger.Warn("Failed to prepare Dex Auth0 connector creation request", zap.Error(err), zap.Any("request", req))
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Failed to create Auth0 connector request: %s", err.Error()))
	}
	publicUris := req.PublicURIS
	if len(publicUris) > 0 {
		err = r.ensureDexClient(r.dexPublicClientID, r.dexPublicClientName, publicUris, true)
		if err != nil {
			return err
		}
	} // Use configured ID/Name
	privateUris := req.PrivateURIS
	if len(privateUris) > 0 {
		err = r.ensureDexClient(r.dexPrivateClientID, r.dexPrivateClientName, privateUris, false)
		if err != nil {
			return err
		}
	} // Use configured ID/Name
	r.logger.Info("Creating Dex Auth0 connector", zap.String("id", dexAPIReq.Connector.Id), zap.String("name", dexAPIReq.Connector.Name))
	res, err := r.authServer.dexClient.CreateConnector(ctx.Request().Context(), dexAPIReq)
	if err != nil {
		r.logger.Error("Failed to create Dex Auth0 connector via gRPC", zap.String("id", dexAPIReq.Connector.Id), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to create connector with identity provider")
	}
	if res.AlreadyExists {
		r.logger.Warn("Attempt to create Dex Auth0 connector that already exists", zap.String("id", dexAPIReq.Connector.Id))
		return echo.NewHTTPError(http.StatusConflict, "Connector with ID 'auth0' already exists")
	}
	localConnector := &db.Connector{ConnectorID: dexAPIReq.Connector.Id, ConnectorType: ConnectorOIDC, ConnectorSubType: ConnectorAuth0, LastUpdate: time.Now()}
	err = r.db.CreateConnector(ctx.Request().Context(), localConnector)
	if err != nil {
		r.logger.Error("Failed to create local DB record for Auth0 connector", zap.String("connectorID", dexAPIReq.Connector.Id), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save connector metadata locally after creation")
	} // Use constants
	r.logger.Info("Restarting Dex pod to apply Auth0 connector changes", zap.String("connectorID", dexAPIReq.Connector.Id))
	err = utils.RestartDexPod()
	if err != nil {
		r.logger.Error("Failed to restart Dex pod after Auth0 connector creation", zap.Error(err))
	}
	r.logger.Info("Successfully created Auth0 connector", zap.String("id", dexAPIReq.Connector.Id))
	return ctx.JSON(http.StatusCreated, map[string]interface{}{"id": localConnector.ID, "connector_id": localConnector.ConnectorID, "type": localConnector.ConnectorType, "sub_type": localConnector.ConnectorSubType, "created_at": localConnector.CreatedAt})
}

// ensureDexClient is a helper to create or update Dex OAuth clients via gRPC.
func (r *httpRoutes) ensureDexClient(id, name string, redirectUris []string, isPublic bool) error {
	ctx := context.TODO()
	clientResp, _ := r.authServer.dexClient.GetClient(ctx, &dexApi.GetClientReq{Id: id}) // Ignore GetClient error for now
	if clientResp != nil && clientResp.Client != nil {
		r.logger.Info("Updating Dex OAuth client", zap.String("id", id), zap.Strings("redirectUris", redirectUris))
		updateReq := dexApi.UpdateClientReq{Id: id, Name: name, RedirectUris: redirectUris}
		_, err := r.authServer.dexClient.UpdateClient(ctx, &updateReq)
		if err != nil {
			r.logger.Error("Failed to update Dex OAuth client", zap.String("id", id), zap.Error(err))
			return echo.NewHTTPError(http.StatusBadGateway, fmt.Sprintf("Failed to update OAuth client '%s'", id))
		}
	} else {
		r.logger.Info("Creating Dex OAuth client", zap.String("id", id), zap.Strings("redirectUris", redirectUris), zap.Bool("public", isPublic))
		createReq := dexApi.CreateClientReq{Client: &dexApi.Client{Id: id, Name: name, RedirectUris: redirectUris, Public: isPublic}}
		if !isPublic {
			createReq.Client.Secret = os.Getenv(EnvDexPrivateClientSecret)
			if createReq.Client.Secret == "" {
				createReq.Client.Secret = DefaultDexPrivateClientSecret
				r.logger.Warn("DEX_PRIVATE_CLIENT_SECRET not set, using insecure default secret for private client", zap.String("clientId", id))
			}
		}
		_, err := r.authServer.dexClient.CreateClient(ctx, &createReq)
		if err != nil {
			r.logger.Error("Failed to create Dex OAuth client", zap.String("id", id), zap.Error(err))
			return echo.NewHTTPError(http.StatusBadGateway, fmt.Sprintf("Failed to create OAuth client '%s'", id))
		}
	} // Use constants
	return nil
}

// UpdateConnector godoc
// @Summary Update Dex Connector
// @Description Updates the configuration of an existing Dex identity provider connector. Requires Admin role. Restarts Dex pod upon success.
// @Security BearerToken
// @Tags connectors
// @Accept json
// @Produce json
// @Param request body api.UpdateConnectorRequest true "Connector Configuration Update (must include local DB 'id' and Dex 'connector_id')"
// @Success 202 {string} string "Accepted (Update successful)"
// @Success 204 {string} string "No Content (Update successful)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Invalid input, missing IDs)"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "Not Found (Connector not found in Dex or local DB)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, K8s interaction error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex)"
// @Router /auth/api/v1/connector [put]
// UpdateConnector handles updating an existing Dex connector configuration.
func (r *httpRoutes) UpdateConnector(ctx echo.Context) error {
	var req api.UpdateConnectorRequest
	if err := bindValidate(ctx, &req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	if req.ID == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Local database connector ID is required for update")
	}
	if req.ConnectorID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Dex connector_id is required in the request body for update")
	}
	dexUtilReq := utils.UpdateConnectorRequest{ID: req.ConnectorID, ConnectorType: req.ConnectorType, ConnectorSubType: req.ConnectorSubType, Issuer: req.Issuer, TenantID: req.TenantID, ClientID: req.ClientID, ClientSecret: req.ClientSecret}
	dexAPIReq, err := utils.UpdateOIDCConnector(dexUtilReq)
	if err != nil {
		r.logger.Warn("Failed to prepare Dex connector update request", zap.Error(err), zap.Any("request", req))
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Failed to create connector update request: %s", err.Error()))
	}
	r.logger.Info("Updating Dex connector", zap.String("id", dexAPIReq.Id))
	res, err := r.authServer.dexClient.UpdateConnector(ctx.Request().Context(), dexAPIReq)
	if err != nil {
		r.logger.Error("Failed to update Dex connector via gRPC", zap.String("id", dexAPIReq.Id), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to update connector with identity provider")
	}
	if res.NotFound {
		r.logger.Warn("Attempt to update Dex connector that does not exist", zap.String("id", dexAPIReq.Id))
		return echo.NewHTTPError(http.StatusNotFound, "Connector not found in identity provider")
	}
	localConnectorUpdate := &db.Connector{Model: gorm.Model{ID: req.ID}, ConnectorID: req.ConnectorID, ConnectorType: req.ConnectorType, ConnectorSubType: req.ConnectorSubType, LastUpdate: time.Now()}
	err = r.db.UpdateConnector(ctx.Request().Context(), localConnectorUpdate)
	if err != nil {
		r.logger.Error("Failed to update local DB record for connector", zap.Uint("localID", req.ID), zap.String("connectorID", req.ConnectorID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save connector metadata locally after update")
	}
	r.logger.Info("Restarting Dex pod to apply connector changes", zap.String("connectorID", req.ConnectorID))
	err = utils.RestartDexPod()
	if err != nil {
		r.logger.Error("Failed to restart Dex pod after connector update", zap.String("connectorID", req.ConnectorID), zap.Error(err))
	}
	r.logger.Info("Successfully updated connector", zap.String("id", req.ConnectorID))
	return ctx.NoContent(http.StatusAccepted)
}

// DeleteConnector godoc
// @Summary Delete Dex Connector
// @Description Deletes an identity provider connector configuration from Dex and associated local metadata. Requires Admin role. Cannot delete 'local' connector. Restarts Dex pod upon success.
// @Security BearerToken
// @Tags connectors
// @Produce json
// @Param id path string true "Dex Connector ID to delete (e.g., 'oidc-google')" example(oidc-google)
// @Success 202 {string} string "Accepted (Deletion initiated)"
// @Success 204 {string} string "No Content (Deletion successful)"
// @Failure 400 {object} echo.HTTPError "Bad Request (Missing ID, attempt to delete 'local')"
// @Failure 401 {object} echo.HTTPError "Unauthorized"
// @Failure 403 {object} echo.HTTPError "Forbidden (Insufficient role)"
// @Failure 404 {object} echo.HTTPError "Not Found (Connector not found in Dex - deletion still proceeds locally)"
// @Failure 500 {object} echo.HTTPError "Internal Server Error (DB error, K8s interaction error)"
// @Failure 502 {object} echo.HTTPError "Bad Gateway (Error communicating with Dex)"
// @Router /auth/api/v1/connector/{id} [delete]
// DeleteConnector handles deleting a Dex connector configuration and its corresponding local metadata.
func (r *httpRoutes) DeleteConnector(ctx echo.Context) error {
	connectorID := ctx.Param("id")
	if connectorID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Connector ID is required in path")
	}
	if connectorID == ConnectorLocal {
		return echo.NewHTTPError(http.StatusBadRequest, "Cannot delete the built-in 'local' connector")
	} // Use constant
	r.logger.Info("Deleting Dex connector", zap.String("id", connectorID))
	dexReq := &dexApi.DeleteConnectorReq{Id: connectorID}
	resp, err := r.authServer.dexClient.DeleteConnector(ctx.Request().Context(), dexReq)
	if err != nil {
		r.logger.Error("Failed to delete Dex connector via gRPC", zap.String("id", connectorID), zap.Error(err))
		return echo.NewHTTPError(http.StatusBadGateway, "Failed to delete connector with identity provider")
	}
	if resp.NotFound {
		r.logger.Warn("Attempt to delete Dex connector that does not exist", zap.String("id", connectorID))
	}
	err = r.db.DeleteConnector(ctx.Request().Context(), connectorID)
	if err != nil {
		r.logger.Error("Failed to delete local DB record for connector after Dex deletion", zap.String("connectorID", connectorID), zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete connector metadata locally")
	}
	r.logger.Info("Restarting Dex pod to apply connector changes", zap.String("connectorID", connectorID))
	err = utils.RestartDexPod()
	if err != nil {
		r.logger.Error("Failed to restart Dex pod after connector deletion", zap.String("connectorID", connectorID), zap.Error(err))
	}
	r.logger.Info("Successfully deleted connector", zap.String("id", connectorID))
	return ctx.NoContent(http.StatusAccepted)
}

// min is a helper for masking tokens.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max is a helper for masking tokens.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
