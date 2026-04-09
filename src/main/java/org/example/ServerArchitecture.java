package org.example;

// =============================================================
// PRODUCTION-READY HTTP SERVER (FINAL)
// =============================================================
//
// ARCHITECTURE
//
//   Request → [RequestLogger] → [AuthFilter] → [MethodFilter] → [Handler] → Response
//                │                 │
//                │                 └── Rejects invalid HTTP methods (405)
//                └── Rejects unauthenticated requests (401)
//
//   Filters implement a Chain of Responsibility pattern.
//   Each filter decides whether to pass the request forward.
//
// FEATURES
//
// 1. Basic Authentication (AuthFilter)
//    - HTTP Basic Auth using APP_USER / APP_PASS from environment
//    - Server fails fast if missing
//
// 2. Method Enforcement (MethodFilter)
//    - Centralised HTTP method validation (GET, POST)
//    - Reduces duplicate checks in handlers
//
// 3. Request Logging (RequestLogger)
//    - Logs method, path, elapsed time (ms), request number
//    - Increments shared AtomicLong REQUEST_COUNTER
//
// 4. Status Endpoint (/status, no auth)
//    - Returns JSON with uptime, total requests, and port
//    - Cache: NO_STORE
//
// 5. Static File Serving (/files, auth required)
//    - Serves files from ./public
//    - Path traversal prevention (normalizes paths, checks startsWith root)
//    - Detects MIME type via Files.probeContentType
//    - Cache: PUBLIC
//
// 6. Handlers (/hello, /greet, /echo)
//    - /hello: plain text, Cache: PRIVATE
//    - /greet: JSON greeting, Cache: PUBLIC
//    - /echo: echoes POST body, Cache: NO_STORE
//
// 7. Safe JSON handling with Gson
//
// 8. URL query decoding
//
// 9. Request size protection (10 KB limit)
//
// 10. Thread pool for concurrency
//
// 11. Graceful shutdown
//
// RUNNING
//   export APP_USER=admin
//   export APP_PASS=secret
//   mkdir public && echo "Hello from file" > public/hello.txt
//   javac -cp .:gson-2.10.1.jar ServerArchitecture.java
//   java -cp .:gson-2.10.1.jar org.example.ServerArchitecture
//
// TESTING
//   curl http://localhost:8000/status
//   curl -u admin:secret http://localhost:8000/hello
//   curl -u admin:secret "http://localhost:8000/greet?name=John%20Doe"
//   curl -u admin:secret -X POST http://localhost:8000/echo -d '{"key":"val"}'
//   curl -u admin:secret http://localhost:8000/files/hello.txt
// =============================================================

import com.google.gson.Gson;
import com.sun.net.httpserver.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerArchitecture {

    private static final Logger log = Logger.getLogger(ServerArchitecture.class.getName());
    private static final int PORT = 8000;
    static final int MAX_BODY_BYTES = 10_000;  // Protects server from large payload attacks
    static final Gson GSON = new Gson();

    // ----------------------------------------------------------
    // Shared server state
    // ----------------------------------------------------------
    static final Instant SERVER_START = Instant.now(); // For uptime calculation
    static final AtomicLong REQUEST_COUNTER = new AtomicLong(0); // Thread-safe request counter

    // Root directory for static file serving
    static final Path FILES_ROOT = Paths.get("public").toAbsolutePath().normalize();

    public static void main(String[] args) {

        // Load credentials from environment variables
        String appUser = System.getenv("APP_USER");
        String appPass = System.getenv("APP_PASS");

        if (appUser == null || appUser.isBlank()) {
            log.severe("APP_USER environment variable is not set. Refusing to start.");
            System.exit(1);
        }
        if (appPass == null || appPass.isBlank()) {
            log.severe("APP_PASS environment variable is not set. Refusing to start.");
            System.exit(1);
        }

        // Ensure the public files directory exists
        if (!Files.exists(FILES_ROOT)) {
            log.warning("Static files directory not found: " + FILES_ROOT + " — creating it now.");
            try { Files.createDirectories(FILES_ROOT); }
            catch (IOException e) {
                log.log(Level.SEVERE, "Could not create public directory", e);
                System.exit(1);
            }
        }

        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
            ExecutorService pool = Executors.newCachedThreadPool();
            server.setExecutor(pool);

            AuthFilter auth = new AuthFilter(appUser, appPass);
            RequestLogger logger = new RequestLogger();

            // Route registrations
            registerRoute(server, "/status", new StatusHandler(), logger);
            registerRoute(server, "/hello", new HelloHandler(), logger, auth, new MethodFilter("GET"));
            registerRoute(server, "/greet", new GreetHandler(), logger, auth, new MethodFilter("GET"));
            registerRoute(server, "/echo",  new EchoHandler(), logger, auth, new MethodFilter("POST"));
            registerRoute(server, "/files/", new FilesHandler(), logger, auth, new MethodFilter("GET"));

            // Graceful shutdown
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log.info("Shutting down server...");
                server.stop(2);
                pool.shutdown();
                log.info("Server stopped. Total requests served: " + REQUEST_COUNTER.get());
            }));

            server.start();
            log.info("Server running on http://localhost:" + PORT);
            log.info("Static files served from: " + FILES_ROOT);

        } catch (IOException e) {
            log.log(Level.SEVERE, "Server could not start", e);
        }
    }

    // Register a route and attach filters in order
    private static void registerRoute(HttpServer server, String path,
                                      HttpHandler handler, Filter... filters) {
        HttpContext ctx = server.createContext(path, handler);
        for (Filter f : filters) ctx.getFilters().add(f);
        log.info("Registered route: " + path);
    }

    // ===========================================================
    // FILTER: Request Logger
    // Logs method, path, elapsed time, request number
    // ===========================================================
    static class RequestLogger extends Filter {
        private static final Logger log = Logger.getLogger(RequestLogger.class.getName());

        @Override
        public String description() {
            return "Request Logger — logs every request with timing";
        }

        @Override
        public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
            long requestNumber = REQUEST_COUNTER.incrementAndGet();
            long startNanos = System.nanoTime();
            String method = exchange.getRequestMethod();
            String path   = exchange.getRequestURI().toString();

            chain.doFilter(exchange);

            long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000;
            log.info(String.format("[#%d] %s %s completed in %dms",
                    requestNumber, method, path, elapsedMs));
        }
    }

    // ===========================================================
    // FILTER: Basic Authentication
    // ===========================================================
    static class AuthFilter extends Filter {
        private final String expectedUsername;
        private final String expectedPassword;

        AuthFilter(String username, String password) {
            this.expectedUsername = username;
            this.expectedPassword = password;
        }

        @Override
        public String description() { return "HTTP Basic Authentication Filter"; }

        @Override
        public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
            String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
            if (authHeader == null || !authHeader.startsWith("Basic")) {
                rejectUnauthorized(exchange);
                return;
            }

            try {
                String decoded = new String(Base64.getDecoder()
                        .decode(authHeader.substring("Basic ".length())), StandardCharsets.UTF_8);
                String[] parts = decoded.split(":", 2);

                if (parts.length != 2
                        || !parts[0].equals(expectedUsername)
                        || !parts[1].equals(expectedPassword)) {
                    rejectUnauthorized(exchange);
                    return;
                }
                chain.doFilter(exchange);

            } catch (IllegalArgumentException e) { rejectUnauthorized(exchange); }
        }

        private void rejectUnauthorized(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"SecureApp\"");
            byte[] body = "401 Unauthorized".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
        }
    }

    // ===========================================================
    // FILTER: HTTP Method Enforcement
    // ===========================================================
    static class MethodFilter extends Filter {
        private final String allowedMethod;
        MethodFilter(String allowedMethod) { this.allowedMethod = allowedMethod.toUpperCase(); }

        @Override
        public String description() { return "HTTP Method Filter — allows: " + allowedMethod; }

        @Override
        public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
            String method = exchange.getRequestMethod().toUpperCase();
            if (!method.equals(allowedMethod)) {
                exchange.getResponseHeaders().set("Allow", allowedMethod);
                byte[] body = ("405 Method Not Allowed — use " + allowedMethod)
                        .getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(405, body.length);
                try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                return;
            }
            chain.doFilter(exchange);
        }
    }

    // ===========================================================
    // HANDLER: GET /status — health check, no auth
    // ===========================================================
    static class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            long uptimeSeconds = Duration.between(SERVER_START, Instant.now()).getSeconds();
            Map<String, Object> status = Map.of(
                    "status", "ok",
                    "uptime_seconds", uptimeSeconds,
                    "total_requests", REQUEST_COUNTER.get(),
                    "port", PORT
            );
            sendResponse(exchange, 200, "application/json", GSON.toJson(status), CachePolicy.NO_STORE);
        }
    }

    // ===========================================================
    // HANDLER: GET /files/{filename} — static files, auth
    // ===========================================================
    static class FilesHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String filename = URLDecoder.decode(exchange.getRequestURI()
                    .getPath().replaceFirst("^/files/", ""), StandardCharsets.UTF_8);

            if (filename.isBlank()) {
                sendResponse(exchange, 400, "application/json",
                        GSON.toJson(Map.of("error", "No filename specified")),
                        CachePolicy.NO_STORE);
                return;
            }

            Path requestedPath = FILES_ROOT.resolve(filename).normalize();
            if (!requestedPath.startsWith(FILES_ROOT)) {
                sendResponse(exchange, 403, "application/json",
                        GSON.toJson(Map.of("error", "Forbidden")),
                        CachePolicy.NO_STORE);
                return;
            }

            if (!Files.exists(requestedPath) || !Files.isRegularFile(requestedPath)) {
                sendResponse(exchange, 404, "application/json",
                        GSON.toJson(Map.of("error", "File not found: " + filename)),
                        CachePolicy.NO_STORE);
                return;
            }

            String mimeType = Optional.ofNullable(Files.probeContentType(requestedPath))
                    .orElse("application/octet-stream");
            byte[] fileBytes = Files.readAllBytes(requestedPath);

            exchange.getResponseHeaders().set("Content-Type", mimeType);
            exchange.getResponseHeaders().set("Cache-Control", CachePolicy.PUBLIC.headerValue);
            exchange.sendResponseHeaders(200, fileBytes.length);
            try (OutputStream out = exchange.getResponseBody()) { out.write(fileBytes); }
        }
    }

    // ===========================================================
    // HANDLER: /hello, /greet, /echo — as before with proper caching
    // ===========================================================
    static class HelloHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            sendResponse(exchange, 200, "text/plain",
                    "Hello! You are authenticated.", CachePolicy.PRIVATE);
        }
    }

    static class GreetHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());
            String name = params.getOrDefault("name", "Stranger");
            Map<String, String> resp = Map.of("message", "Hello, " + name + "!", "status", "ok");
            sendResponse(exchange, 200, "application/json", GSON.toJson(resp), CachePolicy.PUBLIC);
        }
    }

    static class EchoHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
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

    // ===========================================================
    // ENUM: Cache Policy
    // ===========================================================
    enum CachePolicy {
        PUBLIC("public, max-age=3600"),
        PRIVATE("private, max-age=600"),
        NO_STORE("no-store");
        final String headerValue;
        CachePolicy(String v) { this.headerValue = v; }
    }

    // ===========================================================
    // UTILS
    // ===========================================================
    static void sendResponse(HttpExchange exchange, int status,
                             String contentType, String body, CachePolicy cache) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType + "; charset=UTF-8");
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
                        ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8)
                        : "";
                result.put(key, value);
            } catch (IllegalArgumentException ignored) {}
        }
        return result;
    }
}