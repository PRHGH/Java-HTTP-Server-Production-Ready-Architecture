package org.example;

// =============================================================
// PRODUCTION-READY HTTP SERVER ARCHITECTURE (FINAL)
//
// CORE ARCHITECTURE
//
//   Request → [AuthFilter] → [MethodFilter] → [Handler] → Response
//                │               │
//                │               └── Rejects invalid HTTP methods (405)
//                └── Rejects unauthenticated requests (401)
//
// Filters implement a Chain of Responsibility pattern.
// Each filter decides whether to pass the request forward.
//
// -------------------------------------------------------------
// INCLUDED FEATURES
//
// 1. Basic Authentication (AuthFilter)
//    - Uses HTTP Basic Auth header
//    - Credentials loaded from environment variables
//      (APP_USER / APP_PASS)
//    - Server fails fast if missing
//
// 2. Method Enforcement (MethodFilter)
//    - Centralised HTTP method validation (GET, POST)
//    - Removes duplicate logic from handlers
//
// 3. Cache-Control Policies
//    - PUBLIC   → cacheable by CDN/proxies
//    - PRIVATE  → browser-only caching
//    - NO_STORE → never cached (sensitive data)
//
// 4. Safe JSON Handling (Gson)
//    - Prevents malformed JSON from string concatenation
//    - Automatically escapes special characters
//
// 5. URL Query Decoding
//    - Proper handling of encoded params (?name=John%20Doe)
//
// 6. Request Size Protection
//    - POST body limit (10 KB)
//    - Prevents memory abuse / DoS risks
//
// 7. Thread Pool (ExecutorService)
//    - Cached pool for I/O-bound concurrency
//
// 8. Graceful Shutdown
//    - Allows in-flight requests to complete
//
// 9. Centralised Routing
//    - registerRoute() keeps main() clean and extensible
//
// -------------------------------------------------------------
// HOW TO RUN
//cc
// export APP_USER=admin
// export APP_PASS=secret
//
// javac -cp .:gson-2.10.1.jar ServerArchitecture.java
// java  -cp .:gson-2.10.1.jar org.example.ServerArchitecture
//
// -------------------------------------------------------------
// TESTING
//
// curl -u admin:secret http://localhost:8000/hello
// curl -u admin:secret "http://localhost:8000/greet?name=John%20Doe"
// curl -u admin:secret -X POST http://localhost:8000/echo -d '{"key":"val"}'
//
// =============================================================

import com.google.gson.Gson;
import com.sun.net.httpserver.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerArchitecture {

    private static final Logger log = Logger.getLogger(ServerArchitecture.class.getName());
    private static final int PORT = 8000;

    // Maximum allowed request body size (10 KB)
    // Protects server from large payload attacks
    static final int MAX_BODY_BYTES = 10_000;

    // Shared Gson instance (thread-safe for serialization)
    static final Gson GSON = new Gson();

    public static void main(String[] args) {

        // ------------------------------------------------------
        // Load credentials from environment variables
        // Fail fast if not provided (secure default)
        // ------------------------------------------------------
        String appUser = System.getenv("APP_USER");
        String appPass = System.getenv("APP_PASS");

        if (appUser == null || appUser.isBlank()) {
            log.severe("APP_USER environment variable is not set.");
            System.exit(1);
        }
        if (appPass == null || appPass.isBlank()) {
            log.severe("APP_PASS environment variable is not set.");
            System.exit(1);
        }

        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

            // Thread pool for concurrent request handling
            ExecutorService pool = Executors.newCachedThreadPool();
            server.setExecutor(pool);

            // Filters applied in order: Auth → Method
            AuthFilter auth = new AuthFilter(appUser, appPass);

            registerRoute(server, "/hello", new HelloHandler(), auth, new MethodFilter("GET"));
            registerRoute(server, "/greet", new GreetHandler(), auth, new MethodFilter("GET"));
            registerRoute(server, "/echo",  new EchoHandler(),  auth, new MethodFilter("POST"));

            // Graceful shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log.info("Shutting down server...");
                server.stop(2);
                pool.shutdown();
                log.info("Server stopped.");
            }));

            server.start();
            log.info("Server running on http://localhost:" + PORT);

        } catch (IOException e) {
            log.log(Level.SEVERE, "Server could not start", e);
        }
    }

    // Registers a route and attaches filters in execution order
    private static void registerRoute(HttpServer server, String path,
                                      HttpHandler handler, Filter... filters) {
        HttpContext ctx = server.createContext(path, handler);
        for (Filter f : filters) {
            ctx.getFilters().add(f);
        }
        log.info("Registered route: " + path);
    }

    // ===========================================================
    // FILTER: Basic Authentication
    //
    // Validates "Authorization: Basic <base64>" header
    // Rejects unauthenticated requests with 401
    // ===========================================================

    static class AuthFilter extends Filter {

        private final String expectedUsername;
        private final String expectedPassword;

        AuthFilter(String username, String password) {
            this.expectedUsername = username;
            this.expectedPassword = password;
        }

        @Override
        public String description() {
            return "HTTP Basic Authentication Filter";
        }

        @Override
        public void doFilter(HttpExchange exchange, Chain chain) throws IOException {

            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");

            if (authHeader == null || !authHeader.startsWith("Basic")) {
                rejectUnauthorized(exchange);
                return;
            }

            try {
                String decoded = new String(
                        Base64.getDecoder().decode(authHeader.substring(6)),
                        StandardCharsets.UTF_8);

                String[] parts = decoded.split(":", 2);

                if (parts.length != 2 ||
                        !parts[0].equals(expectedUsername) ||
                        !parts[1].equals(expectedPassword)) {
                    rejectUnauthorized(exchange);
                    return;
                }

                chain.doFilter(exchange);

            } catch (IllegalArgumentException e) {
                rejectUnauthorized(exchange);
            }
        }

        private void rejectUnauthorized(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"SecureApp\"");
            byte[] body = "401 Unauthorized".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    // ===========================================================
    // FILTER: HTTP Method Enforcement
    //
    // Ensures only allowed HTTP methods reach the handler
    // Eliminates duplicate checks inside handlers
    // ===========================================================

    static class MethodFilter extends Filter {

        private final String allowedMethod;

        MethodFilter(String allowedMethod) {
            this.allowedMethod = allowedMethod.toUpperCase();
        }

        @Override
        public String description() {
            return "HTTP Method Filter";
        }

        @Override
        public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
            if (!exchange.getRequestMethod().equalsIgnoreCase(allowedMethod)) {
                exchange.getResponseHeaders().set("Allow", allowedMethod);
                byte[] body = ("405 Method Not Allowed — use " + allowedMethod)
                        .getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(405, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
                return;
            }
            chain.doFilter(exchange);
        }
    }

    // ===========================================================
    // HANDLER: /hello (GET)
    //
    // Returns plain text
    // Cache: PRIVATE (user-specific response)
    // ===========================================================

    static class HelloHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            sendResponse(exchange, 200, "text/plain",
                    "Hello! You are authenticated.", CachePolicy.PRIVATE);
        }
    }

    // ===========================================================
    // HANDLER: /greet (GET)
    //
    // Returns JSON greeting
    // Cache: PUBLIC (safe to cache)
    // ===========================================================

    static class GreetHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
            String name = params.getOrDefault("name", "Stranger");

            sendResponse(exchange, 200, "application/json",
                    GSON.toJson(Map.of("message", "Hello, " + name + "!", "status", "ok")),
                    CachePolicy.PUBLIC);
        }
    }

    // ===========================================================
    // HANDLER: /echo (POST)
    //
    // Echoes request body safely
    // Cache: NO_STORE (sensitive data)
    // ===========================================================

    static class EchoHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {

            long contentLength = Optional.ofNullable(
                            exchange.getRequestHeaders().getFirst("Content-Length"))
                    .map(Long::parseLong).orElse(-1L);

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

            sendResponse(exchange, 200, "application/json",
                    GSON.toJson(Map.of("echo", body.isEmpty() ? "(empty)" : body)),
                    CachePolicy.NO_STORE);
        }
    }

    enum CachePolicy {
        PUBLIC("public, max-age=3600"),
        PRIVATE("private, max-age=600"),
        NO_STORE("no-store");

        final String headerValue;
        CachePolicy(String v) { this.headerValue = v; }
    }

    // Shared response builder
    static void sendResponse(HttpExchange exchange, int status,
                             String contentType, String body,
                             CachePolicy cache) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Cache-Control", cache.headerValue);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    // Parses and URL-decodes query parameters
    static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null) return result;

        for (String param : query.split("&")) {
            String[] parts = param.split("=", 2);
            try {
                String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
                String value = parts.length == 2
                        ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8)
                        : "";
                result.put(key, value);
            } catch (IllegalArgumentException ignored) {}
        }
        return result;
    }
}