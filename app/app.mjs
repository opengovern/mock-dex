// app.mjs (ESM-only – Docker Compose ready, reads .env.compose)
// ────────────────────────────────────────────────────────────
// Purpose: Sample Node.js Express app using Passport.js for OIDC authentication against Dex.
// Designed to run in Docker Compose, loading config from '.env.compose'.
// Includes fixes for path prefixes, displays OIDC tokens after login (for debugging),
// and logs the calculated login route on home page load.
// Ensure your package.json contains: "type": "module"
// Dependencies: express, express-session, passport, passport-openidconnect, dotenv
// ────────────────────────────────────────────────────────────

import dotenv from 'dotenv';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as OpenIDConnectStrategy } from 'passport-openidconnect';
import path from 'path'; // Needed for path joining
import { fileURLToPath, URL } from 'url'; // Needed for __dirname in ESM and URL parsing

// Helper for __dirname in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Docker Compose Adaptation: Load .env.compose ---
const envPath = path.resolve(__dirname, '.env.compose');
console.log(`[${new Date().toISOString()}] Attempting to load environment variables from: ${envPath}`);
const dotenvResult = dotenv.config({ path: envPath });

if (dotenvResult.error) {
  console.warn(`[${new Date().toISOString()}] ⚠️ Warning: Could not load ${envPath}. Relying on system environment variables. Error: ${dotenvResult.error.message}`);
} else {
  console.log(`[${new Date().toISOString()}] ✅ Successfully loaded environment variables from ${envPath}`);
}
// ----------------------------------------------------

const app = express();

// --- Trust Proxy Setting ---
// Important for running behind a reverse proxy (like Nginx) that handles TLS.
// Allows correct detection of secure connection (https) for cookies.
app.set('trust proxy', 1);
// ---------------------------

// --- JWT Decoding Helper ---
/**
 * Decodes the payload of a JWT (without verifying the signature).
 * Handles Base64Url decoding.
 * WARNING: This is for informational purposes only. Do NOT trust this data
 * in security-sensitive contexts without proper signature verification.
 * @param {string} token The JWT string.
 * @returns {object|null} The decoded payload object, or null if decoding fails.
 */
function decodeJwtPayload(token) {
  if (!token || typeof token !== 'string') return null;
  try {
    const payloadBase64Url = token.split('.')[1];
    if (!payloadBase64Url) return null;
    let payloadBase64 = payloadBase64Url.replace(/-/g, '+').replace(/_/g, '/');
    switch (payloadBase64.length % 4) { // Add padding if needed
      case 0: break;
      case 2: payloadBase64 += '=='; break;
      case 3: payloadBase64 += '='; break;
      default: throw new Error('Invalid base64url string length.');
    }
    const payloadJson = Buffer.from(payloadBase64, 'base64').toString('utf8');
    return JSON.parse(payloadJson);
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Failed to decode JWT payload:`, error.message);
    return null;
  }
}
// ------------------------

// ────────────────────────────────────────────────────────────
// Load & validate environment variables from process.env
// ────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT, 10) || 3000;
const DEX_ISSUER = process.env.DEX_ISSUER; // e.g., http://localhost/dex
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const APP_BASE_URL = process.env.APP_BASE_URL; // e.g., http://localhost/app
const SESSION_SECRET = process.env.SESSION_SECRET;
const SESSION_MAX_AGE = parseInt(process.env.SESSION_MAX_AGE_MS, 10) || 3600000;

// Validate essential configuration
if (!DEX_ISSUER || !CLIENT_ID || !CLIENT_SECRET || !APP_BASE_URL || !SESSION_SECRET) {
  console.error(`[${new Date().toISOString()}] ❌ Fatal Error: Missing one or more required environment variables.`);
  console.error('   Required: DEX_ISSUER, CLIENT_ID, CLIENT_SECRET, APP_BASE_URL, SESSION_SECRET');
  // ... (rest of validation logging) ...
  process.exit(1);
}

// --- Calculate Base Path from APP_BASE_URL ---
let APP_PATH_PREFIX = '';
try {
    const baseUrlObj = new URL(APP_BASE_URL);
    APP_PATH_PREFIX = baseUrlObj.pathname.replace(/\/$/, ''); // Get path, remove trailing slash
    if (APP_PATH_PREFIX === '/') APP_PATH_PREFIX = ''; // Handle root base URL correctly
} catch (e) {
    console.error(`[${new Date().toISOString()}] ❌ Invalid APP_BASE_URL format: ${APP_BASE_URL}. Could not determine path prefix.`);
    process.exit(1);
}
console.log(`[${new Date().toISOString()}] Derived application path prefix: '${APP_PATH_PREFIX}'`);
// ------------------------------------------

// Define constants
const REDIRECT_PATH = '/auth/callback'; // Path relative to app's base
const REDIRECT_URI = `${APP_BASE_URL.replace(/\/$/, '')}${REDIRECT_PATH}`; // Absolute URI for OIDC
const SCOPES = ['email', 'profile', 'groups', 'offline_access']; // offline_access for refresh token

// Define application-internal route paths using the prefix
const LOGIN_ROUTE = `${APP_PATH_PREFIX}/login`;
const LOGOUT_ROUTE = `${APP_PATH_PREFIX}/logout`;
const PROFILE_ROUTE = `${APP_PATH_PREFIX}/profile`;
const CALLBACK_ROUTE = `${APP_PATH_PREFIX}${REDIRECT_PATH}`;
const LOGIN_ERROR_ROUTE = `${APP_PATH_PREFIX}/login/error`;
const HOME_ROUTE = APP_PATH_PREFIX || '/';

// ────────────────────────────────────────────────────────────
// Session middleware & Passport initialization
// ────────────────────────────────────────────────────────────

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: 'auto', // Use secure cookies if connection is HTTPS (requires 'trust proxy')
    httpOnly: true, // Helps mitigate XSS
    maxAge: SESSION_MAX_AGE,
    path: HOME_ROUTE || '/', // Cookie path should match the app's base path
    sameSite: 'lax', // Recommended for security against CSRF
  },
}));

app.use(passport.initialize());
app.use(passport.session()); // Depends on express-session

// ────────────────────────────────────────────────────────────
// Passport OpenID Connect Strategy Configuration
// ────────────────────────────────────────────────────────────

passport.use('oidc', new OpenIDConnectStrategy({
    // --- Provider Details ---
    issuer:           DEX_ISSUER,
    authorizationURL: `${DEX_ISSUER}/auth`,
    tokenURL:         `${DEX_ISSUER}/token`,
    userInfoURL:      `${DEX_ISSUER}/userinfo`,
    // --- Client Details ---
    clientID:         CLIENT_ID,
    clientSecret:     CLIENT_SECRET,
    callbackURL:      REDIRECT_URI, // Absolute URL where provider redirects back
    // --- OIDC Options ---
    scope:            SCOPES.join(' '),
    passReqToCallback: false,
    skipUserProfile:  false, // Fetch profile from userinfo endpoint
    // pkce: true, // Usually default & recommended
    // nonce: true, // Usually default & recommended
  },
  // --- Verify Callback ---
  // Called after successful token exchange. Provides profile and tokens.
  (issuer, profile, context, id_token, access_token, refresh_token, done) => {
    console.log(`[${new Date().toISOString()}] ✅ OIDC Verify Callback: User profile received from issuer: ${issuer}`);

    // Construct the object to be stored in the session and attached to req.user
    const userSessionData = {
      profile: profile,         // Claims from userinfo endpoint
      id_token: id_token,       // Raw ID Token JWT
      access_token: access_token, // Raw Access Token
      refresh_token: refresh_token // Raw Refresh Token (only if offline_access granted)
    };

    // Pass this object to Passport to be serialized into the session
    return done(null, userSessionData);
  }
));

// --- Passport Session Handling ---
// How to store the user object in the session
passport.serializeUser((userSessionData, done) => {
  const userId = userSessionData?.profile?.id ?? userSessionData?.profile?.displayName ?? '[Unknown User]';
  console.log(`[${new Date().toISOString()}] Serializing user data for session: ${userId}`);
  done(null, userSessionData); // Store the entire collected object
});

// How to retrieve the user object from the session
passport.deserializeUser((userSessionData, done) => {
  const userId = userSessionData?.profile?.id ?? userSessionData?.profile?.displayName ?? '[Unknown User]';
  console.log(`[${new Date().toISOString()}] Deserializing user data from session: ${userId}`);
  done(null, userSessionData); // The retrieved object becomes req.user
});

// Middleware to make user available in templates via res.locals
app.use((req, res, next) => {
  res.locals.user = req.user; // Contains { profile, id_token, ... }
  next();
});

// ────────────────────────────────────────────────────────────
// Application Routes
// ────────────────────────────────────────────────────────────

// --- Home Page ---
// Serve at the root of the application prefix (e.g., /app/ or /)
app.get(HOME_ROUTE, (req, res) => {
  // --- Added Logging Here ---
  console.log(`[${new Date().toISOString()}] Request received for home route: ${req.originalUrl}`);
  console.log(`[Debug] LOGIN_ROUTE value available in this handler: ${LOGIN_ROUTE}`);
  // ------------------------

  if (req.isAuthenticated()) { // Check if user is logged in
    const profile = req.user.profile;
    const idToken = req.user.id_token;
    const accessToken = req.user.access_token;
    const refreshToken = req.user.refresh_token;
    const decodedIdTokenPayload = decodeJwtPayload(idToken); // Decode ID token for display

    const userEmail = profile?.emails?.[0]?.value ?? profile?._json?.email ?? 'N/A';
    const displayName = profile?.displayName ?? userEmail;
    const userId = profile?.id ?? 'N/A';

    console.log(`[${new Date().toISOString()}] [Debug] Rendering logged-in view for user: ${displayName}`);

    // WARNING: Displaying tokens in HTML is a security risk in production. For DEBUGGING ONLY.
    res.send(`
      <!DOCTYPE html><html lang="en">
      <head><meta charset="UTF-8"><title>App Home</title>
      <style>
        body { font-family: sans-serif; line-height: 1.5; padding: 15px; }
        pre { background-color:#f0f0f0; padding:10px; border:1px solid #ccc; overflow-x:auto; word-wrap:break-word; white-space: pre-wrap; margin-top: 5px;}
        textarea { width: 95%; min-height: 60px; font-family: monospace; margin-top: 5px; padding: 5px; border: 1px solid #ccc; }
        hr { margin: 20px 0; border: 0; border-top: 1px solid #eee; }
        h2, h3 { margin-top: 20px; margin-bottom: 5px; border-bottom: 1px solid #eee; padding-bottom: 5px; }
        .warning { color: #d8000c; background-color: #ffdddd; border: 1px solid #d8000c; padding: 10px; margin-top: 15px;}
      </style>
      </head><body>
      <h1>Hello, ${displayName}!</h1><p>You are logged in.</p>
      <p>OIDC Subject ID: ${userId}</p><p>Email: ${userEmail}</p><hr>
      <p><a href="${PROFILE_ROUTE}">View Full Profile Object</a> | <a href="${LOGOUT_ROUTE}">Log out</a></p>
      <hr>

      <div class="warning"><strong>Security Warning:</strong> Displaying tokens below is for demonstration/debugging ONLY and should NOT be done in a production application.</div>

      <h2>Access Token</h2>
      <p>Used to access protected APIs (if any). Usually opaque.</p>
      <textarea readonly>${accessToken || 'N/A'}</textarea>

      ${refreshToken ? `<h2>Refresh Token</h2><p>Used to get new tokens (requires 'offline_access'). Keep this VERY secure.</p><textarea readonly>${refreshToken}</textarea>` : ''}

      <h2>ID Token (JWT)</h2>
      <p>Contains identity claims about the user, signed by Dex.</p>
      <textarea readonly>${idToken || 'N/A'}</textarea>

      <h2>Decoded ID Token Payload</h2>
      <p>Claims inside the ID Token (signature NOT verified by this display).</p>
      <pre>${decodedIdTokenPayload ? JSON.stringify(decodedIdTokenPayload, null, 2) : 'Could not decode ID Token.'}</pre>

      <hr>
      <h3>Debug Info: Full req.user Object (from session)</h3>
      <pre>${JSON.stringify(req.user, null, 2)}</pre>

      </body></html>`);
  } else {
    // User is not logged in
    console.log(`[${new Date().toISOString()}] [Debug] User not authenticated. Rendering welcome page with login link href="${LOGIN_ROUTE}"`);
    res.send(`
      <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Welcome</title></head><body>
      <h1>Welcome!</h1><p>Please log in to continue.</p>
      <p><a href="${LOGIN_ROUTE}">Log in with Dex</a></p>
      </body></html>`);
  }
});

// --- Login Route ---
// Initiates the OIDC flow via Passport middleware
app.get(LOGIN_ROUTE, passport.authenticate('oidc'));

// --- OIDC Callback Route ---
// Handles the redirect from Dex after authentication attempt
app.get(CALLBACK_ROUTE,
  passport.authenticate('oidc', {
    successRedirect: HOME_ROUTE, // Redirect to app home on success
    failureRedirect: LOGIN_ERROR_ROUTE, // Redirect to error page on failure
    failureMessage: true // Store error info in session flash/messages
  })
);

// --- Profile Page (Protected) ---
// Displays the user profile claims specifically
app.get(PROFILE_ROUTE, (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`
      <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Your Profile</title></head><body>
      <h1>Your Profile Data (from Userinfo)</h1>
      <p>This is the 'profile' part of req.user:</p>
      <pre style="background-color:#f0f0f0;padding:10px;border:1px solid #ccc;overflow-x:auto;">${JSON.stringify(req.user?.profile, null, 2)}</pre>
      <hr><p><a href="${HOME_ROUTE}">Home</a> | <a href="${LOGOUT_ROUTE}">Log out</a></p>
      </body></html>`);
  } else {
    res.redirect(LOGIN_ROUTE); // Redirect unauthenticated users to login
  }
});

// --- Logout Route ---
app.get(LOGOUT_ROUTE, (req, res, next) => {
  const userName = req.user?.profile?.displayName || 'User';
  console.log(`[${new Date().toISOString()}] Processing logout request for ${userName}...`);
  req.logout((err) => { // Use passport's req.logout()
    if (err) {
      console.error(`[${new Date().toISOString()}] Error during req.logout():`, err);
      return next(err); // Pass error to Express error handler
    }
    // After logout, destroy the session and clear the cookie
    req.session.destroy((destroyErr) => {
        if (destroyErr) {
            console.error(`[${new Date().toISOString()}] Error destroying session after logout:`, destroyErr);
            // Still try to clear cookie and redirect
        }
        console.log(`[${new Date().toISOString()}] Clearing session cookie 'connect.sid' for ${userName}...`);
        res.clearCookie('connect.sid', { path: HOME_ROUTE || '/' }); // Match cookie path
        console.log(`[${new Date().toISOString()}] ${userName} logged out successfully. Redirecting to app home.`);
        res.redirect(HOME_ROUTE); // Redirect to application's home page
    });
  });
});

// --- Login Error Route ---
// Displays authentication failures
app.get(LOGIN_ERROR_ROUTE, (req, res) => {
    const messages = req.session.messages || [];
    const errorMsg = messages.length > 0 ? messages[messages.length - 1] : 'Unknown authentication error.';
    console.warn(`[${new Date().toISOString()}] Login failure page displayed. Last error: ${errorMsg}`);
    res.status(401).send(`
      <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Login Error</title></head><body>
      <h1>Authentication Error</h1><p>Could not complete the login process.</p>
      ${messages.length > 0 ? `<p><b>Details:</b> ${messages.join('<br>')}</p>` : ''}<hr>
      <p><a href="${HOME_ROUTE}">Home</a> | <a href="${LOGIN_ROUTE}">Try Login Again</a></p>
      </body></html>`);
    // Important: Clear the messages from session after displaying them
    if (req.session.messages) { delete req.session.messages; }
});

// ────────────────────────────────────────────────────────────
// Basic Error Handling Middleware (Place near the end)
// ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Unhandled Error on ${req.method} ${req.originalUrl}:`, err.stack || err);
  if (!res.headersSent) {
    res.status(500).send('Internal Server Error');
  } else {
    next(err);
  }
});

// ────────────────────────────────────────────────────────────
// Start the Express Server
// ────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Server ready and listening on internal port ${PORT}`);
  console.log(`   Container Time (UTC): ${new Date().toISOString()}`); // Use ISO format for clarity
  console.log(`   Node Environment:     ${process.env.NODE_ENV || 'not set'}`);
  console.log(`\n🔗 Network Configuration (from environment):`);
  console.log(`   App Base URL:         ${APP_BASE_URL} (Browser access URL, prefix: '${APP_PATH_PREFIX}')`);
  console.log(`   App Redirect URI:     ${REDIRECT_URI}`);
  console.log(`   OIDC Provider Issuer: ${DEX_ISSUER}`);
  console.log(`\n🔑 Client Credentials & Scopes:`);
  console.log(`   Client ID:            ${CLIENT_ID}`);
  console.log(`   Client Secret:        ${CLIENT_SECRET ? '[Loaded]' : '[MISSING!]'}`);
  console.log(`   Requested Scopes:     openid ${SCOPES.join(' ')}`);
  console.log(`\n🔒 Session Configuration:`);
  console.log(`   Session Secret:       ${SESSION_SECRET ? '[Loaded]' : '[MISSING - FATAL!]'}`);
  console.log(`   Session Max Age:      ${SESSION_MAX_AGE / 1000 / 60} minutes`);
  console.log(`   Cookie Secure:        'auto' (Depends on trusted connection)`);
  console.log(`   Cookie Path:          '${HOME_ROUTE || '/'}'`);
  console.log(`   Cookie SameSite:      'lax'`);

  console.warn(`\n⚠️ Crucial: Ensure Dex client config for '${CLIENT_ID}' includes '${REDIRECT_URI}' exactly in 'redirectURIs'.`);
  console.warn(`⚠️ Crucial: Ensure Nginx proxies requests to '${APP_PATH_PREFIX || '/'}' and its subpaths correctly to this app.`);
  if (!APP_BASE_URL.startsWith('https')) {
    console.warn("⚠️ Warning: APP_BASE_URL is not HTTPS. Secure cookies disabled unless behind a trusted proxy setting 'X-Forwarded-Proto'.");
  }
  if (process.env.NODE_ENV !== 'production') {
      console.warn("⚠️ Warning: NODE_ENV is not 'production'. Ensure production hardening for deployment.");
  } else {
      console.info("✅ Production mode detected.")
  }
});