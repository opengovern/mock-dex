// Package auth provides the core authentication and authorization logic.
// This file defines constants used throughout the auth service package.
package auth

import "time"

// Environment variable names used for configuration.
const (
	// Dex related env vars
	EnvDexAuthDomain            = "DEX_AUTH_DOMAIN"
	EnvDexAuthPublicClientID    = "DEX_AUTH_PUBLIC_CLIENT_ID" // For OIDC verification audience
	EnvDexGrpcAddress           = "DEX_GRPC_ADDR"
	EnvDexGrpcTlsCertPath       = "DEX_GRPC_TLS_CERT_PATH"
	EnvDexGrpcTlsKeyPath        = "DEX_GRPC_TLS_KEY_PATH"
	EnvDexGrpcTlsCaPath         = "DEX_GRPC_TLS_CA_PATH"
	EnvDexPublicClientRedirect  = "DEX_PUBLIC_CLIENT_REDIRECT_URIS"
	EnvDexPrivateClientRedirect = "DEX_PRIVATE_CLIENT_REDIRECT_URIS"
	EnvDexPublicClientIDOver    = "DEX_PUBLIC_CLIENT_ID_OVERRIDE"    // Optional override
	EnvDexPublicClientNameOver  = "DEX_PUBLIC_CLIENT_NAME_OVERRIDE"  // Optional override
	EnvDexPrivateClientIDOver   = "DEX_PRIVATE_CLIENT_ID_OVERRIDE"   // Optional override
	EnvDexPrivateClientNameOver = "DEX_PRIVATE_CLIENT_NAME_OVERRIDE" // Optional override
	EnvDexPrivateClientSecret   = "DEX_PRIVATE_CLIENT_SECRET"        // Mandatory if private client used

	// HTTP Server env vars
	EnvHttpServerAddress = "HTTP_ADDRESS"

	// Platform Key env vars
	EnvPlatformHost       = "PLATFORM_HOST"
	EnvPlatformKeyEnabled = "PLATFORM_KEY_ENABLED"
	EnvPlatformPublicKey  = "PLATFORM_PUBLIC_KEY"
	EnvPlatformPrivateKey = "PLATFORM_PRIVATE_KEY"

	// Kubernetes env vars
	EnvNamespace = "NAMESPACE" // Used by RestartDexPod
)

// Default values for Dex OAuth Clients if not overridden by environment variables.
const (
	DefaultDexPublicClientID      = "public-client"
	DefaultDexPublicClientName    = "Public Client"
	DefaultDexPrivateClientID     = "private-client"
	DefaultDexPrivateClientName   = "Private Client"
	DefaultDexPrivateClientSecret = "secret" // Insecure default
)

// Constants for JWT claim values issued by this platform.
const (
	JWTIssuerPlatform = "platform-auth-service" // Issuer for platform-generated tokens
	JWTAudienceClient = "platform-client"       // Audience for tokens used by frontends/clients
	JWTAudienceAPI    = "platform-api"          // Audience for API keys used by services
)

// Constants for connector types and IDs.
const (
	ConnectorLocal = "local"
	ConnectorOIDC  = "oidc"
	ConnectorAuth0 = "auth0" // Specific ID for Auth0 connector
)

// Constants for HTTP header names and MIME types.
const (
	HeaderOrigURI       = "x-original-uri"
	HeaderOrigMethod    = "x-original-method"
	HeaderRequestID     = "x-request-id"
	HeaderContentType   = "Content-Type"
	HeaderAccept        = "Accept"
	MIMEFormURLEncoded  = "application/x-www-form-urlencoded"
	MIMEApplicationJSON = "application/json"
)

// Constants for password change status responses.
const (
	PasswordChangeRequired    = "CHANGE_REQUIRED"
	PasswordChangeNotRequired = "CHANGE_NOT_REQUIRED"
)

// Constants for numeric literals and configurations.
const (
	DefaultHTTPTimeout        = 10 * time.Second // Timeout for external HTTP calls (e.g., Dex token endpoint)
	DefaultGRPCClientTimeout  = 5 * time.Second  // Example timeout for gRPC calls
	MaxAPIKeysPerUser         = 5                // Limit on active API keys per user
	DefaultAPIKeyMaskLenStart = 10               // Length of prefix to show for masked API keys
	DefaultAPIKeyMaskLenEnd   = 10               // Length of suffix to show for masked API keys
	MinPasswordLength         = 8                // Example minimum password length
	LoginUpdateInterval       = 15 * time.Minute // Interval after which last login is updated
	UpdateLoopTickInterval    = 1 * time.Minute  // How often the login update loop runs
	UpdateLoginChanBuffer     = 100000           // Buffer size for the async login update channel
	RSAKeyBitSize             = 2048             // Bit size for generated RSA keys
)

// Constants for database configuration keys.
const (
	DBConfigKeyPublicKey  = "public_key"
	DBConfigKeyPrivateKey = "private_key"
)
