package org.example;

// =============================================================
// STAGE 4 — Level 3: Architectural Upgrades
// Builds on all Level 1 improvements. Adds:
//
//   1. Router
//      Centralised route registry mapping (method + path pattern)
//      to handlers. Supports path parameters (/users/{id}).
//      Automatically returns 404 for unknown paths and 405 when
//      the path exists but the method doesn't match.
//
//   2. HTTPS / TLS
//      Switches from HttpServer to HttpsServer. Loads a keys0tore
//      (self-signed certificate) and wraps the server in SSLContext.
//      Basic Auth credentials are no longer transmitted in plaintext.
//
//   3. JWT Authentication
//      Replaces Basic Auth. A POST /login endpoint exchanges
//      username + password for a signed JWT token (HS256).
//      All protected routes verify the token via JwtFilter.
//      Tokens expire after 1 hour. No session state on the server.
//
// Architecture:
//
//   HTTPS Request
//         │
//         ▼
//    [TLS Layer]       ← decrypts the connection
//         │
//         ▼
//      [Router]        ← matches path/method, extracts {params}
//         │
//         ▼
//    [JwtFilter]       ← verifies token signature + expiry
//         │              /login is exempt from this filter
//         ▼
//     [Handler]        ← only sees valid authenticated requests
//
// Setup (one-time):
//   keytool -genkeypair -alias server -keyalg RSA -keysize 2048  \
//           -validity 365 -keystore keystore.jks                 \
//           -storepass changeit -keypass changeit                \
//           -dname "CN=localhost"
//
// Environment variables required:
//   APP_USER=admin
//   APP_PASS=secret
//   JWT_SECRET=a-long-random-string-at-least-32-chars
//   KEYSTORE_PASS=changeit          (matches keytool -storepass)
//
// Run:
//   javac -cp .:gson-2.10.1.jar ServerArchitecture.java
//   java  -cp .:gson-2.10.1.jar org.example.ServerArchitecture
//
// Test:
//   # 1. Get a token
//   TOKEN=$(curl -sk -X POST https://localhost:8443/login \
//     -H "Content-Type: application/json"                \
//     -d '{"username":"admin","password":"secret"}'      \
//     | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
//
//   # 2. Use the token
//   curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8443/hello
//   curl -sk -H "Authorization: Bearer $TOKEN" "https://localhost:8443/greet?name=Alice"
//   curl -sk -H "Authorization: Bearer $TOKEN" -X POST https://localhost:8443/echo \
//        -d '{"key":"value"}'
//   curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8443/users/42
// =============================================================

import com.google.gson.Gson;
import com.sun.net.httpserver.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.*;
import java.util.regex.*;

public class ServerArchitecture {

    private static final Logger log  = Logger.getLogger(ServerArchitecture.class.getName());
    private static final int    PORT = 8443;   // standard HTTPS port range for dev

    static final int  MAX_BODY_BYTES = 10_000;
    static final Gson GSON           = new Gson();

    public static void main(String[] args) {

        // --- Load required environment variables ---
        String appUser      = requireEnv("APP_USER");
        String appPass      = requireEnv("APP_PASS");
        String jwtSecret    = requireEnv("JWT_SECRET");
        String keystorePass = requireEnv("KEYSTORE_PASS");

        try {
            // -------------------------------------------------------
            // IMPROVEMENT 2: HTTPS — swap HttpServer for HttpsServer
            //
            // HttpsServer is the TLS-capable sibling of HttpServer.
            // It needs an SSLContext which holds the server certificate
            // (loaded from a JKS keystore file on disk).
            // -------------------------------------------------------
            HttpsServer server = HttpsServer.create(new InetSocketAddress(PORT), 0);
            server.setHttpsConfigurator(buildHttpsConfigurator(keystorePass));

            ExecutorService pool = Executors.newCachedThreadPool();
            server.setExecutor(pool);

            // -------------------------------------------------------
            // IMPROVEMENT 1: Router
            //
            // Instead of registering each route directly on the server
            // we create a Router, register handlers on it, and attach
            // it as a single catch-all context on "/".
            // The Router handles 404 and 405 internally.
            // -------------------------------------------------------
            JwtFilter  jwt    = new JwtFilter(jwtSecret);
            Router     router = new Router();

            // Public route — no JWT filter
            router.add("POST", "/login", new LoginHandler(appUser, appPass, jwtSecret));

            // Protected routes — JWT filter applied
            router.add("GET",  "/hello",        jwt.wrap(new HelloHandler()));
            router.add("GET",  "/greet",         jwt.wrap(new GreetHandler()));
            router.add("POST", "/echo",          jwt.wrap(new EchoHandler()));
            router.add("GET",  "/users/{id}",    jwt.wrap(new UserHandler()));   // path param demo

            // Attach the router as the single handler for all paths
            server.createContext("/", router);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log.info("Shutting down...");
                server.stop(2);
                pool.shutdown();
            }));

            server.start();
            log.info("HTTPS server running on https://localhost:" + PORT);

        } catch (Exception e) {
            log.log(Level.SEVERE, "Server could not start", e);
        }
    }

    // ===========================================================
    //  IMPROVEMENT 2 (HTTPS): Build SSLContext from a JKS keystore
    //
    //  A KeyStore is Java's container for certificates and keys.
    //  KeyManagerFactory loads our certificate from it.
    //  SSLContext is the TLS engine — it uses the KeyManager
    //  to prove the server's identity to connecting clients.
    //
    //  The keystore file (keystore.jks) must be in the working
    //  directory. Generate it once with the keytool command at
    //  the top of this file.
    // ===========================================================

    private static HttpsConfigurator buildHttpsConfigurator(String keystorePass)
            throws Exception {

        char[] password = keystorePass.toCharArray();

        // Load the JKS keystore from disk
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream in = new FileInputStream("keystore.jks")) {
            ks.load(in, password);
        }

        // KeyManager holds the server's certificate and private key
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password);

        // Build the SSLContext using TLS protocol
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        return new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLContext ctx    = getSSLContext();
                SSLParameters sslParams = ctx.getDefaultSSLParameters();
                params.setSSLParameters(sslParams);
            }
        };
    }

    // ===========================================================
    //  IMPROVEMENT 1: Router
    //
    //  Implements HttpHandler so it can be attached as a single
    //  context on "/". All requests pass through it.
    //
    //  Route matching works in two steps:
    //    1. Path matching  — does the request path match a pattern?
    //                        e.g. "/users/42" matches "/users/{id}"
    //    2. Method matching — does the method match the route?
    //                        path match + wrong method → 405
    //                        no path match at all       → 404
    //
    //  Path parameters ({id}, {name}, etc.) are extracted and
    //  stored in the exchange's attribute map for handlers to read.
    // ===========================================================

    static class Router implements HttpHandler {

        private static final Logger log = Logger.getLogger(Router.class.getName());

        // Holds one registered route entry
        private record Route(String method, Pattern pattern,
                             List<String> paramNames, HttpHandler handler) {}

        private final List<Route> routes = new ArrayList<>();

        // Register a route. Path segments wrapped in {} become parameters.
        // e.g. "/users/{id}/posts/{postId}"
        void add(String method, String pathTemplate, HttpHandler handler) {
            List<String> paramNames = new ArrayList<>();

            // Convert template to a regex:
            //   /users/{id}  →  /users/([^/]+)
            String regex = Arrays.stream(pathTemplate.split("/"))
                    .map(segment -> {
                        if (segment.startsWith("{") && segment.endsWith("}")) {
                            paramNames.add(segment.substring(1, segment.length() - 1));
                            return "([^/]+)";      // capture group for the param value
                        }
                        return Pattern.quote(segment);  // literal segment
                    })
                    .reduce((a, b) -> a + "/" + b)
                    .orElse("");

            routes.add(new Route(method.toUpperCase(),
                    Pattern.compile("^" + regex + "$"),
                    paramNames, handler));

            log.info("Route registered: " + method.toUpperCase() + " " + pathTemplate);
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {

            String requestPath   = exchange.getRequestURI().getPath();
            String requestMethod = exchange.getRequestMethod().toUpperCase();

            boolean pathFound = false;

            for (Route route : routes) {
                Matcher matcher = route.pattern().matcher(requestPath);

                if (matcher.matches()) {
                    pathFound = true;   // at least one route matches this path

                    if (!route.method().equals(requestMethod)) {
                        continue;       // path matches but wrong method — keep looking
                    }

                    // Extract path parameters and store them for the handler
                    Map<String, String> pathParams = new HashMap<>();
                    for (int i = 0; i < route.paramNames().size(); i++) {
                        pathParams.put(route.paramNames().get(i), matcher.group(i + 1));
                    }
                    exchange.setAttribute("pathParams", pathParams);

                    // Delegate to the matched handler
                    route.handler().handle(exchange);
                    return;
                }
            }

            // Path was found but no method matched → 405
            if (pathFound) {
                log.warning("405 — method not allowed: " + requestMethod + " " + requestPath);
                sendResponse(exchange, 405, "application/json",
                        GSON.toJson(Map.of("error", "Method Not Allowed")),
                        CachePolicy.NO_STORE);
                return;
            }

            // No path matched at all → 404
            log.warning("404 — no route for: " + requestMethod + " " + requestPath);
            sendResponse(exchange, 404, "application/json",
                    GSON.toJson(Map.of("error", "Not Found")),
                    CachePolicy.NO_STORE);
        }
    }

    // ===========================================================
    //  IMPROVEMENT 3: JWT — Minimal HS256 Implementation
    //
    //  JSON Web Token structure:  header.payload.signature
    //
    //  header  = Base64Url({ "alg":"HS256", "typ":"JWT" })
    //  payload = Base64Url({ "sub":"admin", "exp":1234567890 })
    //  signature = HMAC-SHA256(header + "." + payload, secret)
    //
    //  To verify: re-compute the signature from the received
    //  header+payload, compare with the signature in the token.
    //  If they match, the payload has not been tampered with.
    //  Then check the "exp" claim to ensure the token hasn't expired.
    //
    //  This is a minimal implementation for learning purposes.
    //  In production use a library like java-jwt or jjwt.
    // ===========================================================

    static class Jwt {

        private static final long EXPIRY_SECONDS = 3600; // 1 hour

        // --- Token issuance ---

        static String issue(String subject, String secret) throws Exception {
            String header  = base64url("""
                    {"alg":"HS256","typ":"JWT"}""");
            String payload = base64url(
                    "{\"sub\":\"" + subject + "\","
                            + "\"exp\":" + (Instant.now().getEpochSecond() + EXPIRY_SECONDS) + "}");

            String headerPayload = header + "." + payload;
            String signature     = sign(headerPayload, secret);
            return headerPayload + "." + signature;
        }

        // --- Token verification — returns the subject (username) or throws ---

        static String verify(String token, String secret) throws Exception {
            String[] parts = token.split("\\.");
            if (parts.length != 3) throw new IllegalArgumentException("Malformed token");

            // Re-compute signature and compare (constant-time via MessageDigest)
            String expectedSig = sign(parts[0] + "." + parts[1], secret);
            if (!MessageDigest.isEqual(
                    expectedSig.getBytes(StandardCharsets.UTF_8),
                    parts[2].getBytes(StandardCharsets.UTF_8))) {
                throw new SecurityException("Invalid token signature");
            }

            // Decode payload JSON and check expiry
            String payloadJson = new String(
                    Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

            @SuppressWarnings("unchecked")
            Map<String, Object> claims = GSON.fromJson(payloadJson, Map.class);

            double exp = (Double) claims.get("exp");
            if (Instant.now().getEpochSecond() > (long) exp) {
                throw new SecurityException("Token has expired");
            }

            return (String) claims.get("sub");
        }

        // --- Helpers ---

        private static String sign(String data, String secret) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        }

        private static String base64url(String json) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(json.getBytes(StandardCharsets.UTF_8));
        }
    }

    // ===========================================================
    //  IMPROVEMENT 3: JWT Filter
    //
    //  Checks every request for a valid Bearer token:
    //    Authorization: Bearer <token>
    //
    //  If valid: extracts the username, stores it as an exchange
    //  attribute so handlers can read who is logged in, then
    //  passes to the next handler.
    //
    //  If invalid or missing: returns 401 immediately.
    //
    //  wrap() returns an anonymous HttpHandler that applies the
    //  filter inline, so public routes (like /login) are simply
    //  registered without calling wrap() — they are never filtered.
    // ===========================================================

    static class JwtFilter {

        private static final Logger log = Logger.getLogger(JwtFilter.class.getName());
        private final String secret;

        JwtFilter(String secret) { this.secret = secret; }

        // Returns a new handler that JWT-checks before delegating
        HttpHandler wrap(HttpHandler inner) {
            return exchange -> {
                String authHeader = exchange.getRequestHeaders().getFirst("Authorization");

                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    log.warning("Missing or malformed Authorization header on "
                            + exchange.getRequestURI());
                    rejectUnauthorized(exchange, "Missing Bearer token");
                    return;
                }

                String token = authHeader.substring("Bearer ".length()).trim();

                try {
                    String username = Jwt.verify(token, secret);
                    // Store username so handlers can access it
                    exchange.setAttribute("authenticatedUser", username);
                    log.info("JWT valid for user: " + username
                            + " → " + exchange.getRequestURI());
                    inner.handle(exchange);     // pass to the real handler

                } catch (SecurityException e) {
                    log.warning("JWT rejected: " + e.getMessage()
                            + " on " + exchange.getRequestURI());
                    rejectUnauthorized(exchange, e.getMessage());
                } catch (Exception e) {
                    log.log(Level.WARNING, "JWT verification error", e);
                    rejectUnauthorized(exchange, "Invalid token");
                }
            };
        }

        private void rejectUnauthorized(HttpExchange exchange, String reason) throws IOException {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer realm=\"SecureApp\"");
            byte[] body = GSON.toJson(Map.of("error", "Unauthorized", "reason", reason))
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
        }
    }

    // ===========================================================
    //  HANDLER 0 (NEW): POST /login
    //
    //  Public endpoint — not wrapped by JwtFilter.
    //  Accepts JSON body: { "username": "...", "password": "..." }
    //  Validates against APP_USER / APP_PASS.
    //  On success: issues a JWT and returns it.
    //  On failure: returns 401.
    //
    //  This is the only place in the system where a password
    //  is ever checked. After this, everything uses tokens.
    // ===========================================================

    static class LoginHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(LoginHandler.class.getName());
        private final String validUser;
        private final String validPass;
        private final String jwtSecret;

        LoginHandler(String user, String pass, String secret) {
            this.validUser  = user;
            this.validPass  = pass;
            this.jwtSecret  = secret;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("POST /login from " + exchange.getRemoteAddress());
            try {
                byte[] bodyBytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES);
                String bodyJson  = new String(bodyBytes, StandardCharsets.UTF_8);

                @SuppressWarnings("unchecked")
                Map<String, String> creds = GSON.fromJson(bodyJson, Map.class);

                String username = creds.getOrDefault("username", "");
                String password = creds.getOrDefault("password", "");

                if (!username.equals(validUser) || !password.equals(validPass)) {
                    log.warning("Failed login attempt for user: " + username);
                    sendResponse(exchange, 401, "application/json",
                            GSON.toJson(Map.of("error", "Invalid credentials")),
                            CachePolicy.NO_STORE);
                    return;
                }

                String token = Jwt.issue(username, jwtSecret);
                log.info("Issued JWT for user: " + username);

                sendResponse(exchange, 200, "application/json",
                        GSON.toJson(Map.of("token", token, "expiresIn", "3600s")),
                        CachePolicy.NO_STORE);

            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in LoginHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")),
                        CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER 1: GET /hello  (unchanged logic, logger fixed)
    // ===========================================================

    static class HelloHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(HelloHandler.class.getName());

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("GET /hello");
            try {
                String user = (String) exchange.getAttribute("authenticatedUser");
                sendResponse(exchange, 200, "text/plain",
                        "Hello, " + user + "! You are authenticated.",
                        CachePolicy.PRIVATE);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in HelloHandler", e);
                sendResponse(exchange, 500, "text/plain",
                        "500 Internal Server Error", CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER 2: GET /greet?name=Alice
    // ===========================================================

    static class GreetHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(GreetHandler.class.getName());

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("GET /greet");
            try {
                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
                String name = params.getOrDefault("name", "Stranger");

                Map<String, String> response = new HashMap<>();
                response.put("message", "Hello, " + name + "!");
                response.put("status", "ok");

                sendResponse(exchange, 200, "application/json",
                        GSON.toJson(response), CachePolicy.PUBLIC);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in GreetHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")),
                        CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER 3: POST /echo
    // ===========================================================

    static class EchoHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(EchoHandler.class.getName());

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("POST /echo");
            try {
                String contentLengthHeader =
                        exchange.getRequestHeaders().getFirst("Content-Length");
                long contentLength = contentLengthHeader != null
                        ? Long.parseLong(contentLengthHeader) : -1;

                if (contentLength > MAX_BODY_BYTES) {
                    sendResponse(exchange, 413, "application/json",
                            GSON.toJson(Map.of("error", "Payload too large")),
                            CachePolicy.NO_STORE);
                    return;
                }

                byte[] bodyBytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
                if (bodyBytes.length > MAX_BODY_BYTES) {
                    sendResponse(exchange, 413, "application/json",
                            GSON.toJson(Map.of("error", "Payload too large")),
                            CachePolicy.NO_STORE);
                    return;
                }

                String body = new String(bodyBytes, StandardCharsets.UTF_8);
                Map<String, Object> responseMap = new HashMap<>();
                responseMap.put("echo", body.isEmpty() ? "(empty)" : body);

                sendResponse(exchange, 200, "application/json",
                        GSON.toJson(responseMap), CachePolicy.NO_STORE);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in EchoHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")),
                        CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER 4 (NEW): GET /users/{id}
    //
    //  Demonstrates reading a path parameter extracted by the Router.
    //  exchange.getAttribute("pathParams") returns the map the Router
    //  populated when it matched /users/{id} against the request path.
    // ===========================================================

    static class UserHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(UserHandler.class.getName());

        @Override
        @SuppressWarnings("unchecked")
        public void handle(HttpExchange exchange) throws IOException {
            log.info("GET /users/{id}");
            try {
                // Read the path parameter the Router extracted
                Map<String, String> pathParams =
                        (Map<String, String>) exchange.getAttribute("pathParams");
                String userId = pathParams.getOrDefault("id", "unknown");

                // In a real app this is where you'd query a database
                Map<String, String> response = new HashMap<>();
                response.put("userId", userId);
                response.put("note", "Real app would fetch user " + userId + " from a database");

                sendResponse(exchange, 200, "application/json",
                        GSON.toJson(response), CachePolicy.PRIVATE);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in UserHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")),
                        CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  Cache Policy Enum (unchanged)
    // ===========================================================

    enum CachePolicy {
        PUBLIC  ("public, max-age=3600"),
        PRIVATE ("private, max-age=600"),
        NO_STORE("no-store");

        final String headerValue;
        CachePolicy(String headerValue) { this.headerValue = headerValue; }
    }

    // ===========================================================
    //  Shared Utilities
    // ===========================================================

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            log.severe(name + " environment variable is not set. Refusing to start.");
            System.exit(1);
        }
        return value;
    }

    static void sendResponse(HttpExchange exchange, int status,
                             String contentType, String body,
                             CachePolicy cache) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",  contentType + "; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", cache.headerValue);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) { out.write(bytes); }
    }

    static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null || query.isEmpty()) return result;
        for (String param : query.split("&")) {
            String[] parts = param.split("=", 2);
            try {
                String key   = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                String value = parts.length == 2
                        ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
                result.put(key, value);
            } catch (IllegalArgumentException e) {
                log.warning("Skipping malformed query param: " + parts[0]);
            }
        }
        return result;
    }
}