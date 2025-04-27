// Package auth provides the core authentication and authorization logic,
// including OIDC integration with Dex, platform token issuance/verification,
// API key management, user management, and an Envoy external authorization check service.
// This file, cmd.go, defines the command structure (using Cobra) and the main
// startup sequence for the auth service executable.
package auth

import (
	"context"
	"crypto" // For crypto.SHA256
	"crypto/rand"
	"crypto/rsa" // For crypto.SHA256 hash
	"crypto/tls" // Needed for TLS config
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors" // For errors.Is
	"fmt"
	"log"      // Use standard log for fatal startup errors before zap is ready
	"net/http" // For http.ErrServerClosed and OIDC client
	"os"
	"os/signal" // For signal handling
	"strconv"   // For strconv.ParseBool, Atoi
	"strings"
	"syscall" // For signal handling

	// For OIDC client timeout
	dexApi "github.com/dexidp/dex/api/v2"
	config2 "github.com/opengovern/og-util/pkg/config" // Assumes this pkg exists and has ReadFromEnv
	"github.com/opengovern/og-util/pkg/httpserver"
	"github.com/opengovern/og-util/pkg/postgres"
	"github.com/opengovern/opensecurity/services/auth/db" // Local DB package
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"          // For TLS credentials
	"google.golang.org/grpc/credentials/insecure" // For insecure fallback

	// Use v4 as confirmed working by 'go get'
	jose "github.com/go-jose/go-jose/v4"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Environment variables read at startup to configure the service, using constants for names.
var (
	dexAuthDomain                = os.Getenv(EnvDexAuthDomain)
	dexAuthPublicClientID        = os.Getenv(EnvDexAuthPublicClientID)
	dexGrpcAddress               = os.Getenv(EnvDexGrpcAddress)
	dexGrpcTlsCertPath           = os.Getenv(EnvDexGrpcTlsCertPath)
	dexGrpcTlsKeyPath            = os.Getenv(EnvDexGrpcTlsKeyPath)
	dexGrpcTlsCaPath             = os.Getenv(EnvDexGrpcTlsCaPath)
	dexPublicClientRedirectUris  = os.Getenv(EnvDexPublicClientRedirect)
	dexPrivateClientRedirectUris = os.Getenv(EnvDexPrivateClientRedirect)
	dexPublicClientIDOverride    = os.Getenv(EnvDexPublicClientIDOver)
	dexPublicClientNameOverride  = os.Getenv(EnvDexPublicClientNameOver)
	dexPrivateClientIDOverride   = os.Getenv(EnvDexPrivateClientIDOver)
	dexPrivateClientNameOverride = os.Getenv(EnvDexPrivateClientNameOver)
	dexPrivateClientSecret       = os.Getenv(EnvDexPrivateClientSecret)
	httpServerAddress            = os.Getenv(EnvHttpServerAddress)
	platformHost                 = os.Getenv(EnvPlatformHost)
	platformKeyEnabledStr        = os.Getenv(EnvPlatformKeyEnabled)
	platformPublicKeyStr         = os.Getenv(EnvPlatformPublicKey)
	platformPrivateKeyStr        = os.Getenv(EnvPlatformPrivateKey)

	// Package-level variables to hold the effective Dex client IDs and names after checking overrides.
	effectiveDexPublicClientID    string
	effectiveDexPublicClientName  string
	effectiveDexPrivateClientID   string
	effectiveDexPrivateClientName string
)

// calculateKeyID computes the JWK thumbprint (SHA256, Base64URL encoded) for the given public key.
// This thumbprint is used as the 'kid' (Key ID) in platform-issued JWT headers, allowing
// verifiers to identify the correct public key used for signing.
func calculateKeyID(pub *rsa.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	thumbprintBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("failed to calculate JWK thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(thumbprintBytes)
	return kid, nil
}

// Command creates the Cobra command structure for the auth service executable.
// This allows the main package (`cmd/auth-service/main.go`) to simply execute this command,
// benefiting from Cobra's context handling and integration with OS signals for graceful shutdown.
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth-service",
		Short: "Starts the OpenSecurity authentication and authorization service",
		Long: `Initializes dependencies (database, Dex connection, keys)
and starts the HTTP server handling authentication logic and APIs.
Listens for OS signals (Interrupt, SIGTERM) for graceful shutdown.`,
		SilenceUsage: true, // Prevent usage printing on RunE error return
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create a root context that listens for OS interrupt signals.
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop() // Ensure the stop function is called to release signal resources.

			// Execute the main service startup logic.
			err := start(ctx)

			// Handle different shutdown scenarios for clean exit codes.
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("ERROR: Service failed: %v\n", err)
				return err // Return error for Cobra to handle non-zero exit code.
			}
			if errors.Is(err, context.Canceled) {
				log.Println("Service shutdown requested via signal.")
			}
			log.Println("Service shutdown complete.")
			return nil // Return nil on clean shutdown or context cancellation (exit code 0).
		},
	}
	return cmd
}

// ServerConfig holds configuration read from the environment via og-util/config.
// It primarily contains PostgreSQL connection details.
type ServerConfig struct {
	PostgreSQL config2.Postgres // Assumes config2.Postgres has Port as string
}

// start initializes all components (logger, config, db, keys, clients)
// and runs the main service logic (HTTP server, background tasks).
// It accepts a context that can be cancelled (e.g., by OS signals) for graceful shutdown.
func start(ctx context.Context) error {
	// --- Logger Setup ---
	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("CRITICAL: Failed to initialize Zap logger: %v", err)
		return err
	}
	defer func() { _ = logger.Sync() }()
	logger = logger.Named("auth-service")
	logger.Info("Auth service starting...")

	// --- Configuration Reading & Validation ---
	var conf ServerConfig
	config2.ReadFromEnv(&conf, nil) // Panics on internal errors
	logger.Info("Configuration loaded from environment")
	// Validate essential configurations read directly from environment or via config struct.
	if dexAuthDomain == "" || dexAuthPublicClientID == "" || dexGrpcAddress == "" {
		return fmt.Errorf("required Dex configuration missing (%s, %s, %s)", EnvDexAuthDomain, EnvDexAuthPublicClientID, EnvDexGrpcAddress)
	}
	if httpServerAddress == "" {
		return fmt.Errorf("required HTTP server address missing (%s)", EnvHttpServerAddress)
	}
	if conf.PostgreSQL.Host == "" || conf.PostgreSQL.Port == "" || conf.PostgreSQL.Username == "" || conf.PostgreSQL.DB == "" {
		return fmt.Errorf("incomplete PostgreSQL configuration provided (host, port, user, db required)")
	}
	if _, err := strconv.Atoi(conf.PostgreSQL.Port); err != nil {
		return fmt.Errorf("invalid PostgreSQL port number '%s': must be a number", conf.PostgreSQL.Port)
	}

	// --- Determine Effective Dex Client IDs/Names ---
	// Use override from env var if set, otherwise use the default constant.
	effectiveDexPublicClientID = DefaultDexPublicClientID
	if dexPublicClientIDOverride != "" {
		effectiveDexPublicClientID = dexPublicClientIDOverride
		logger.Info("Overriding Dex public client ID from environment", zap.String("envVar", EnvDexPublicClientIDOver), zap.String("id", effectiveDexPublicClientID))
	}
	effectiveDexPublicClientName = DefaultDexPublicClientName
	if dexPublicClientNameOverride != "" {
		effectiveDexPublicClientName = dexPublicClientNameOverride
		logger.Info("Overriding Dex public client name from environment", zap.String("envVar", EnvDexPublicClientNameOver), zap.String("name", effectiveDexPublicClientName))
	}
	effectiveDexPrivateClientID = DefaultDexPrivateClientID
	if dexPrivateClientIDOverride != "" {
		effectiveDexPrivateClientID = dexPrivateClientIDOverride
		logger.Info("Overriding Dex private client ID from environment", zap.String("envVar", EnvDexPrivateClientIDOver), zap.String("id", effectiveDexPrivateClientID))
	}
	effectiveDexPrivateClientName = DefaultDexPrivateClientName
	if dexPrivateClientNameOverride != "" {
		effectiveDexPrivateClientName = dexPrivateClientNameOverride
		logger.Info("Overriding Dex private client name from environment", zap.String("envVar", EnvDexPrivateClientNameOver), zap.String("name", effectiveDexPrivateClientName))
	}
	// Handle private client secret (use default if env var is missing)
	if dexPrivateClientSecret == "" {
		dexPrivateClientSecret = DefaultDexPrivateClientSecret
		logger.Warn("DEX_PRIVATE_CLIENT_SECRET not set, using insecure default secret for private client")
	}
	logger.Info("Effective Dex client IDs/Names determined", zap.String("publicId", effectiveDexPublicClientID), zap.String("publicName", effectiveDexPublicClientName), zap.String("privateId", effectiveDexPrivateClientID), zap.String("privateName", effectiveDexPrivateClientName))

	logger.Info("Configuration validated")

	// --- OIDC Verifier Setup ---
	dexVerifier, err := newDexOidcVerifier(ctx, dexAuthDomain, dexAuthPublicClientID)
	if err != nil {
		return fmt.Errorf("failed to create OIDC dex verifier: %w", err)
	}
	logger.Info("Instantiated Open ID Connect verifier", zap.String("issuer", dexAuthDomain))

	// --- Database Setup ---
	pgCfg := postgres.Config{Host: conf.PostgreSQL.Host, Port: conf.PostgreSQL.Port, User: conf.PostgreSQL.Username, Passwd: conf.PostgreSQL.Password, DB: conf.PostgreSQL.DB, SSLMode: conf.PostgreSQL.SSLMode}
	orm, err := postgres.NewClient(&pgCfg, logger.Named("postgres"))
	if err != nil {
		return fmt.Errorf("failed to create postgres client: %w", err)
	}
	sqlDB, err := orm.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB from GORM: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	adb := db.Database{Orm: orm}
	logger.Info("Connected to the postgres database", zap.String("db_name", conf.PostgreSQL.DB))
	if err := adb.Initialize(); err != nil {
		return fmt.Errorf("database migration/initialization error: %w", err)
	}
	logger.Info("Database initialized successfully")

	// --- Platform Key Loading/Generation ---
	if platformKeyEnabledStr == "" {
		platformKeyEnabledStr = "false"
	}
	platformKeyEnabled, err := strconv.ParseBool(platformKeyEnabledStr)
	if err != nil {
		return fmt.Errorf("invalid PLATFORM_KEY_ENABLED value [%s]: %w", platformKeyEnabledStr, err)
	}
	var platformPublicKey *rsa.PublicKey
	var platformPrivateKey *rsa.PrivateKey
	var platformKeyID string
	if platformKeyEnabled {
		logger.Info("Loading platform keys from environment variables.")
		if platformPublicKeyStr == "" || platformPrivateKeyStr == "" {
			return fmt.Errorf("PLATFORM_KEY_ENABLED=true but PLATFORM_PUBLIC_KEY or PLATFORM_PRIVATE_KEY is missing")
		}
		pubBytes, err := base64.StdEncoding.DecodeString(platformPublicKeyStr)
		if err != nil {
			return fmt.Errorf("failed to base64 decode PLATFORM_PUBLIC_KEY: %w", err)
		}
		pubBlock, _ := pem.Decode(pubBytes)
		if pubBlock == nil {
			return fmt.Errorf("failed to pem decode PLATFORM_PUBLIC_KEY")
		}
		pubParsed, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key from env: %w", err)
		}
		var ok bool
		platformPublicKey, ok = pubParsed.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("key parsed from PLATFORM_PUBLIC_KEY is not an RSA public key")
		}
		privBytes, err := base64.StdEncoding.DecodeString(platformPrivateKeyStr)
		if err != nil {
			return fmt.Errorf("failed to base64 decode PLATFORM_PRIVATE_KEY: %w", err)
		}
		privBlock, _ := pem.Decode(privBytes)
		if privBlock == nil {
			return fmt.Errorf("failed to pem decode PLATFORM_PRIVATE_KEY")
		}
		privParsed, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key (PKCS8) from env: %w", err)
		}
		platformPrivateKey, ok = privParsed.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("key parsed from PLATFORM_PRIVATE_KEY is not an RSA private key")
		}
	} else {
		logger.Info("Attempting to load/generate platform keys from/to database.")
		keyPair, err := adb.GetKeyPair(ctx)
		if err != nil {
			return fmt.Errorf("failed to query key pair from db: %w", err)
		}
		if len(keyPair) == 0 {
			logger.Info("No keys found in database, generating new platform RSA key pair.")
			platformPrivateKey, err = rsa.GenerateKey(rand.Reader, RSAKeyBitSize)
			if err != nil {
				return fmt.Errorf("error generating RSA key: %w", err)
			}
			platformPublicKey = &platformPrivateKey.PublicKey
			bPub, errPub := x509.MarshalPKIXPublicKey(platformPublicKey)
			if errPub != nil {
				return fmt.Errorf("failed to marshal generated public key: %w", errPub)
			}
			bpPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: bPub})
			strPub := base64.StdEncoding.EncodeToString(bpPub)
			errDbPub := adb.AddConfiguration(ctx, &db.Configuration{Key: DBConfigKeyPublicKey, Value: strPub})
			if errDbPub != nil {
				return fmt.Errorf("failed to save generated public key to db: %w", errDbPub)
			}
			bPri, errPri := x509.MarshalPKCS8PrivateKey(platformPrivateKey)
			if errPri != nil {
				return fmt.Errorf("failed to marshal generated private key (PKCS8): %w", errPri)
			}
			bpPri := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: bPri})
			strPri := base64.StdEncoding.EncodeToString(bpPri)
			errDbPri := adb.AddConfiguration(ctx, &db.Configuration{Key: DBConfigKeyPrivateKey, Value: strPri})
			if errDbPri != nil {
				return fmt.Errorf("failed to save generated private key to db: %w", errDbPri)
			}
			logger.Info("Saved generated key pair to database.")
		} else {
			logger.Info("Loading platform key pair from database.")
			var pubFound, privFound bool
			for _, k := range keyPair {
				keyBytes, err := base64.StdEncoding.DecodeString(k.Value)
				if err != nil {
					return fmt.Errorf("failed to base64 decode key '%s' from db: %w", k.Key, err)
				}
				block, _ := pem.Decode(keyBytes)
				if block == nil {
					return fmt.Errorf("failed to pem decode key '%s' from db", k.Key)
				}
				if k.Key == DBConfigKeyPublicKey {
					pubParsed, err := x509.ParsePKIXPublicKey(block.Bytes)
					if err != nil {
						return fmt.Errorf("failed to parse public key from db: %w", err)
					}
					var ok bool
					platformPublicKey, ok = pubParsed.(*rsa.PublicKey)
					if !ok {
						return fmt.Errorf("public key from db is not RSA")
					}
					pubFound = true
				} else if k.Key == DBConfigKeyPrivateKey {
					privParsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
					if err != nil {
						return fmt.Errorf("failed to parse private key (PKCS8) from db: %w", err)
					}
					var ok bool
					platformPrivateKey, ok = privParsed.(*rsa.PrivateKey)
					if !ok {
						return fmt.Errorf("private key from db is not RSA")
					}
					privFound = true
				}
			}
			if !pubFound || !privFound {
				return fmt.Errorf("could not find both public and private keys in db configuration")
			}
		}
	}

	if platformPublicKey == nil {
		return fmt.Errorf("platform public key was not loaded or generated")
	}
	platformKeyID, err = calculateKeyID(platformPublicKey)
	if err != nil {
		logger.Error("Failed to calculate Key ID from platform public key", zap.Error(err))
		return fmt.Errorf("failed to derive platform key ID: %w", err)
	}
	logger.Info("Derived platform Key ID (kid) for JWTs", zap.String("kid", platformKeyID))
	if platformPrivateKey == nil || platformKeyID == "" {
		return fmt.Errorf("platform private key or key ID could not be initialized")
	}

	// --- Dex Client Setup ---
	dexClient, conn, err := newDexClient(logger, dexGrpcAddress)
	if err != nil {
		logger.Error("Failed to create dex client", zap.Error(err))
		return err
	}
	defer func() {
		logger.Info("Closing Dex gRPC client connection...")
		if closeErr := conn.Close(); closeErr != nil {
			logger.Warn("Error closing Dex gRPC client connection", zap.Error(closeErr))
		}
	}()
	if err = ensureDexClients(ctx, logger, dexClient); err != nil {
		logger.Error("Failed to ensure dex clients", zap.Error(err))
		return err
	}
	logger.Info("Dex gRPC client connected and clients ensured")

	// --- Instantiate Servers ---
	// Pass pointer (&adb) which satisfies db.DatabaseInterface
	// !!! This assignment requires methods in db/db.go to be updated for context/interface !!!
	authServer := &Server{
		host: platformHost, platformPublicKey: platformPublicKey, platformKeyID: platformKeyID,
		dexVerifier: dexVerifier, dexClient: dexClient, logger: logger.Named("authServer"),
		db:          &adb,                                   // Assign pointer to concrete struct to interface field
		updateLogin: make(chan User, UpdateLoginChanBuffer), // Use constant
	}
	go authServer.UpdateLastLoginLoop()

	errorsChan := make(chan error, 1)

	go func() {
		// !!! This assignment requires methods in db/db.go to be updated for context/interface !!!
		httpRoutes := httpRoutes{
			logger: logger.Named("httpRoutes"), platformPrivateKey: platformPrivateKey,
			platformKeyID: platformKeyID, db: &adb, // Assign pointer to concrete struct to interface field
			authServer: authServer,
			// Pass effective client IDs/Names
			dexPublicClientID:    effectiveDexPublicClientID,
			dexPublicClientName:  effectiveDexPublicClientName,
			dexPrivateClientID:   effectiveDexPrivateClientID,
			dexPrivateClientName: effectiveDexPrivateClientName,
		}
		logger.Info("Starting HTTP server", zap.String("address", httpServerAddress))
		serverErr := httpserver.RegisterAndStart(ctx, logger, httpServerAddress, &httpRoutes)
		if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
			errorsChan <- fmt.Errorf("http server error: %w", serverErr)
		} else {
			logger.Info("HTTP server shut down.")
			close(errorsChan)
		}
	}()

	// --- Wait for Shutdown Signal or Error ---
	logger.Info("Auth service started successfully. Waiting for shutdown signal...")
	select {
	case err, ok := <-errorsChan:
		if ok && err != nil {
			logger.Error("Service failed", zap.Error(err))
			if errors.Is(err, http.ErrServerClosed) {
				logger.Info("HTTP server closed normally.")
				return nil
			}
			return err
		}
		logger.Info("Errors channel closed, service stopped gracefully.")
		return nil
	case <-ctx.Done():
		logger.Info("Service shutting down due to context cancellation signal...")
		return ctx.Err()
	}
}

// --- Helper Functions ---

// newServerCredentials loads TLS credentials from specified file paths.
// Used for establishing secure gRPC connections (e.g., to Dex).
// certPath/keyPath are for the client's certificate (for mTLS). caPath is for verifying the server.
func newServerCredentials(certPath string, keyPath string, caPath string) (credentials.TransportCredentials, error) {
	var clientCert tls.Certificate
	var err error
	if certPath != "" && keyPath != "" {
		clientCert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client TLS key pair (cert: %s, key: %s): %w", certPath, keyPath, err)
		}
	}
	// Correctly handle both return values from SystemCertPool
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("Warning: Failed to load system certificate pool: %v. Using empty pool.", err)
		caCertPool = x509.NewCertPool()
	}
	if caPath != "" {
		caBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate %s: %w", caPath, err)
		}
		if !caCertPool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append CA certs from %s", caPath)
		}
	}
	tlsConfig := &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12}
	if clientCert.Certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}
	return credentials.NewTLS(tlsConfig), nil
}

// newDexOidcVerifier creates a verifier for OIDC ID Tokens issued by Dex.
// It uses the provided context for HTTP requests during OIDC discovery.
func newDexOidcVerifier(ctx context.Context, domain, clientId string) (*oidc.IDTokenVerifier, error) {
	httpClient := &http.Client{Timeout: DefaultHTTPTimeout} // Use constant
	providerCtx := oidc.ClientContext(ctx, httpClient)
	// IMPORTANT: For production Dex using HTTPS, remove the InsecureIssuerURLContext wrapper.
	provider, err := oidc.NewProvider(oidc.InsecureIssuerURLContext(providerCtx, domain), domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for %s: %w", domain, err)
	}
	// Return a verifier configured for the provider and client ID. Standard checks are enabled.
	return provider.Verifier(&oidc.Config{ClientID: clientId}), nil
}

// newDexClient creates a gRPC client connection to the Dex API server.
// It conditionally uses TLS based on environment variables DEX_GRPC_TLS_*.
// Returns the Dex API client, the underlying gRPC connection (for closing), and an error.
func newDexClient(logger *zap.Logger, hostAndPort string) (dexApi.DexClient, *grpc.ClientConn, error) {
	var opts []grpc.DialOption // gRPC dialing options.

	// Check if TLS environment variables are set, indicating a secure connection is desired.
	if dexGrpcTlsCertPath != "" && dexGrpcTlsKeyPath != "" || dexGrpcTlsCaPath != "" {
		logger.Info("Attempting to establish Dex gRPC connection using TLS", zap.String("certPath", dexGrpcTlsCertPath), zap.String("keyPath", dexGrpcTlsKeyPath), zap.String("caPath", dexGrpcTlsCaPath))
		creds, err := newServerCredentials(dexGrpcTlsCertPath, dexGrpcTlsKeyPath, dexGrpcTlsCaPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load TLS credentials for Dex gRPC client: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
		logger.Info("Using TLS for Dex gRPC connection.")
	} else {
		// Fallback to insecure connection if no TLS paths are provided.
		logger.Warn("Using insecure credentials for Dex gRPC connection. Set DEX_GRPC_TLS_*_PATH for TLS.", zap.String("address", hostAndPort))
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Establish the gRPC connection with the determined options.
	conn, err := grpc.NewClient(hostAndPort, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial dex grpc server at %s: %w", hostAndPort, err)
	}
	return dexApi.NewDexClient(conn), conn, nil
}

// ensureDexClients verifies that the required Dex OAuth2 clients exist and are configured.
// It uses the 'effectiveDex*' package-level variables determined during startup.
func ensureDexClients(ctx context.Context, logger *zap.Logger, dexClient dexApi.DexClient) error {
	// --- Ensure Public Client ---
	publicUrisList := strings.Split(strings.TrimSpace(dexPublicClientRedirectUris), ",")
	var validPublicUris []string
	for _, uri := range publicUrisList {
		if trimmed := strings.TrimSpace(uri); trimmed != "" {
			validPublicUris = append(validPublicUris, trimmed)
		}
	}
	if len(validPublicUris) == 0 {
		logger.Warn("DEX_PUBLIC_CLIENT_REDIRECT_URIS is not set or empty, skipping public client setup.")
	} else {
		// Use effective ID and Name determined during startup
		clientID := effectiveDexPublicClientID
		clientName := effectiveDexPublicClientName
		clientResp, err := dexClient.GetClient(ctx, &dexApi.GetClientReq{Id: clientID})
		if err != nil && !strings.Contains(err.Error(), "not found") {
			logger.Error("Failed to get dex public client", zap.String("clientID", clientID), zap.Error(err))
			return fmt.Errorf("failed to get dex public client '%s': %w", clientID, err)
		}
		logger.Info("Ensuring Dex public client exists/is updated", zap.String("clientID", clientID), zap.Strings("redirectURIs", validPublicUris))
		if clientResp != nil && clientResp.Client != nil {
			req := dexApi.UpdateClientReq{Id: clientID, Name: clientName, RedirectUris: validPublicUris}
			_, err := dexClient.UpdateClient(ctx, &req)
			if err != nil {
				logger.Error("Failed to update dex public client", zap.String("clientID", clientID), zap.Error(err))
				return fmt.Errorf("failed to update dex public client '%s': %w", clientID, err)
			}
			logger.Info("Updated existing Dex public client.", zap.String("clientID", clientID))
		} else {
			req := dexApi.CreateClientReq{Client: &dexApi.Client{Id: clientID, Name: clientName, RedirectUris: validPublicUris, Public: true}}
			_, err := dexClient.CreateClient(ctx, &req)
			if err != nil {
				logger.Error("Failed to create dex public client", zap.String("clientID", clientID), zap.Error(err))
				return fmt.Errorf("failed to create dex public client '%s': %w", clientID, err)
			}
			logger.Info("Created new Dex public client.", zap.String("clientID", clientID))
		}
	}

	// --- Ensure Private Client ---
	privateUrisList := strings.Split(strings.TrimSpace(dexPrivateClientRedirectUris), ",")
	var validPrivateUris []string
	for _, uri := range privateUrisList {
		if trimmed := strings.TrimSpace(uri); trimmed != "" {
			validPrivateUris = append(validPrivateUris, trimmed)
		}
	}
	if len(validPrivateUris) == 0 {
		logger.Warn("DEX_PRIVATE_CLIENT_REDIRECT_URIS is not set or empty, skipping private client setup.")
	} else {
		// Use effective ID and Name determined during startup
		clientID := effectiveDexPrivateClientID
		clientName := effectiveDexPrivateClientName
		clientResp, err := dexClient.GetClient(ctx, &dexApi.GetClientReq{Id: clientID})
		if err != nil && !strings.Contains(err.Error(), "not found") {
			logger.Error("Failed to get dex private client", zap.String("clientID", clientID), zap.Error(err))
			return fmt.Errorf("failed to get dex private client '%s': %w", clientID, err)
		}
		logger.Info("Ensuring Dex private client exists/is updated", zap.String("clientID", clientID), zap.Strings("redirectURIs", validPrivateUris))
		if clientResp != nil && clientResp.Client != nil {
			req := dexApi.UpdateClientReq{Id: clientID, Name: clientName, RedirectUris: validPrivateUris}
			_, err := dexClient.UpdateClient(ctx, &req)
			if err != nil {
				logger.Error("Failed to update dex private client", zap.String("clientID", clientID), zap.Error(err))
				return fmt.Errorf("failed to update dex private client '%s': %w", clientID, err)
			}
			logger.Info("Updated existing Dex private client.", zap.String("clientID", clientID))
		} else {
			// Use the secret read from env (with default)
			req := dexApi.CreateClientReq{Client: &dexApi.Client{Id: clientID, Name: clientName, RedirectUris: validPrivateUris, Secret: dexPrivateClientSecret}}
			_, err := dexClient.CreateClient(ctx, &req)
			if err != nil {
				logger.Error("Failed to create dex private client", zap.String("clientID", clientID), zap.Error(err))
				return fmt.Errorf("failed to create dex private client '%s': %w", clientID, err)
			}
			logger.Info("Created new Dex private client.", zap.String("clientID", clientID))
		}
	}
	return nil
}
