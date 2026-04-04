package org.example;

// =============================================================
// Production-Ready Architecture
// The final, most complete version. Adds:
//
//   1. BasicAuth Filter  — intercepts ALL requests before
//      they reach any handler (Chain of Responsibility pattern).
//      Checks the "Authorization: Basic <base64>" header.
//
//   2. Cache-Control Headers — demonstrates the caching concepts
//      from Week 3: private, public, no-store.
//
//   3. Router pattern — centralised context registration keeps
//      main() clean and makes adding routes easy.
//
//   4. Graceful shutdown — shuts down the thread pool properly.
//
// Architecture :
//
//   Request → [AuthFilter] → [Handler] → Response
//                  ↑ rejects with 401 if credentials wrong
//
// To test with curl:
//   curl -u admin:secret http://localhost:8000/hello
//   curl -u admin:secret "http://localhost:8000/greet?name=Alice"
//   curl -u admin:secret -X POST http://localhost:8000/echo -d '{"key":"val"}'
// =============================================================

import com.sun.net.httpserver.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServerArchitecture {

    private static final Logger Log = Logger.getLogger(ServerArchitecture.class.getName());
    private static final int PORT = 8000;

    public static void main(String[] args) {

        try{
            HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

            // --- Thread pool: cached for I/O-bound work ---
            ExecutorService pool = Executors.newCachedThreadPool();
            server.setExecutor(pool);

            // --- Register routes and attach the Auth filter to each context ---
            AuthFilter auth = new AuthFilter("admin", "secret");
            registerRoute(server, "/hello", new HelloHandler(), auth);
            registerRoute(server, "/greet", new GreetHandler(), auth);
            registerRoute(server, "/echo", new EchoHandler(), auth);

            // Graceful shutdown hook on Ctrl+C
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                Log.info("Shutting down server...");
                server.stop(2); // allow 2s for in-flight requests to finish
                pool.shutdown();
                Log.info("Server stopped");
            }));

            server.start();
            Log.info("Server running on http:/localhost:" + PORT);
            Log.info("Credentials required - username: admin password: secret");
        }
        catch(IOException e) {
            Log.log(Level.SEVERE, "Sever could not start", e);
        }
    }

    // Registers a context and attaches a filter to it
    private static void registerRoute(HttpServer server, String path, HttpHandler handler, Filter filter) {
        HttpContext ctx = server.createContext(path, handler);
        ctx.getFilters().add(filter);
        Log.info("Registered route: " + path);
    }

    // ===========================================================
    //  FILTER: Basic Authentication
    //  Runs BEFORE the handler. Returns 401 if credentials fail.
    //  Week 3: "Each request must be self-descriptive, containing
    //           all necessary authentication."
    // ===========================================================

    static class AuthFilter extends Filter {

        private static final Logger Log = Logger.getLogger(AuthFilter.class.getName());
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
            // No credentials provided at all
            if(authHeader == null || !authHeader.startsWith("Basic")) {

                Log.warning("Unathorized request (no credentials): " + exchange.getRequestURI() + " from " + exchange.getRemoteAddress());
                rejectUnauthorized(exchange);
                return; // do NOT call chain.doFilter — block the request here
            }

            try {
                // Decode Base64: "Basic YWRtaW46c2VjcmV0" -> "admin:secret"
                String base64 = authHeader.substring("Basic ".length());
                String decoded = new String(Base64.getDecoder().decode(base64),
                        StandardCharsets.UTF_8);
                String[] parts = decoded.split(":", 2);

                if(parts.length != 2
                        || !parts[0].equals(expectedUsername)
                        || !parts[1].equals(expectedPassword)) {
                    Log.warning("Bad credentials for user: " + (parts.length > 0 ? parts[0] : "?") + " on " + exchange.getRequestURI());
                    rejectUnauthorized(exchange);
                    return;
                }

                // Credentials valid — pass request to the actual handler
                Log.info("Authenticated user: " + parts[0] + " accessing " + exchange.getRequestURI());
                chain.doFilter(exchange);

            }catch(IllegalArgumentException e) {
                // Base64 decoding failed (malformed header)
                Log.log(Level.WARNING, "Malformed Authorization header", e);
                rejectUnauthorized(exchange);
            }

        }

        private void rejectUnauthorized(HttpExchange exchange) throws IOException {
            // WWW-Authenticate header tells the browser to show a login prompt
            exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"SecureApp\"");
            byte[] body = "401 Unauthorized".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            OutputStream out = exchange.getResponseBody();
            out.write(body);
            out.close();
        }
    }

    // ===========================================================
    //  HANDLER 1: GET /hello
    //  Returns plain text. Uses "private" cache-control (user data).
    // ===========================================================

    static class HelloHandler implements HttpHandler {

        private static final Logger Log = Logger.getLogger(HelloHandler.class.getName());

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Log.info("GET /hello");
            try {
                if(!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendResponse(exchange, 405, "text/plain", "405 Method Not Allowed", CachePolicy.NO_STORE);
                    return;
                }
                // private: only the user's browser may cache, not shared proxies
                sendResponse(exchange, 200, "text/plain", "Hello! You are authenticated.", CachePolicy.PRIVATE);

            }catch(Exception e) {
                Log.log(Level.SEVERE, "Error in HelloHandler", e);
                sendResponse(exchange,500,"text/plain", "500 Internal Server Error", CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER 2: GET /greet?name=Alice
    //  Returns JSON. Public cacheable (no user-specific data).
    // ===========================================================

    static class GreetHandler implements HttpHandler {

        private static final Logger Log = Logger.getLogger(GreetHandler.class.getName());

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Log.info("GET /greet");

            try {
                if(!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}", CachePolicy.NO_STORE);
                    return;
                }

                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());

                String name = params.getOrDefault("name", "Stranger");

                String json = "{\"message\":\"Hello, " + name + "!\",\"status\":\"ok\"}";

                // public: a shared CDN/proxy may cache this (non-sensitive data)
                sendResponse(exchange, 200, "application/json", json, CachePolicy.PUBLIC);
            }
            catch(Exception e) {
                Log.log(Level.SEVERE, "Error in GreetHandler", e);
                sendResponse(exchange, 500, "application/json", "{\"error\":\"Internal Server Error\"}", CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER 3: POST /echo
    //  Reads the request body and echoes it back as JSON.
    //  no-store: body may contain sensitive input, never cache.
    // ===========================================================

    static class EchoHandler implements HttpHandler {
        private static final Logger Log = Logger.getLogger(EchoHandler.class.getName());

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Log.info("POST /echo");
            try {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    sendResponse(exchange, 405, "application/json",
                            "{\"error\":\"Method Not Allowed — use POST\"}",
                            CachePolicy.NO_STORE);
                    return;
                }

                // Read the full request body
                InputStream in = exchange.getRequestBody();
                String body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                Log.info("Echo received body: " + body);

                String json = "{\"echo\":" + (body.isEmpty() ? "\"(empty)\"" : body) + "}";

                // no-store: banking / sensitive POST data must never be cached
                sendResponse(exchange, 200, "application/json", json, CachePolicy.NO_STORE);

            } catch (Exception e) {
                Log.log(Level.SEVERE, "Error in EchoHandler", e);
                sendResponse(exchange, 500, "application/json",
                        "{\"error\":\"Internal Server Error\"}", CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  Cache Policy Enum (Week 3: Cache-Control header values)
    // ===========================================================

    enum CachePolicy {
        PUBLIC("public, max-age=3600"),     // shared proxy/CDN cachable (1 hour)
        PRIVATE("private, max-age=600"),    // Browser-only cache (10 min)
        NO_STORE("no-store");               // Never Cache (sensitive data)

        final String headerValue;

        CachePolicy(String headerValue) {
            this.headerValue = headerValue;
        }
    }

    // ===========================================================
    //  Shared Utilities
    // ===========================================================

    static void sendResponse(HttpExchange exchange, int status, String contentType, String body, CachePolicy cache) throws IOException {

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type",contentType + "; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", cache.headerValue);
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream out = exchange.getResponseBody();
        out.write(bytes);
        out.close();
    }

    static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();

        if(query == null || query.isEmpty()) return result;
        for(String param : query.split("&")) {
            String[] parts = param.split("=", 2);
            result.put(parts[0], parts.length == 2 ? parts[1] : "");
        }
        return result;
    }

}