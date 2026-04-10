package org.example;

// =============================================================
// STAGE 4 — Level 4: Production Concepts
// Builds on all Level 3 architecture. Adds:
//
//   1. SQLite Persistence Layer
//      UserRepository wraps all database access via JDBC.
//      Handlers never touch SQL directly — they call the repo.
//      Passwords hashed with bcrypt (jBCrypt library).
//      DB file (users.db) created and seeded automatically.
//
//   2. Rate Limiting
//      RateLimitFilter runs first on every request.
//      Tracks requests per IP in a sliding 60-second window.
//      Exceeding 60 req/min returns 429 Too Many Requests.
//      Uses ConcurrentHashMap + AtomicInteger for thread safety.
//      A background thread prunes stale IP entries every minute.
//
// Full route table:
//   POST /login              → public, issues JWT
//   GET  /hello              → JWT required
//   GET  /greet?name=X       → JWT required
//   POST /echo               → JWT required
//   GET  /users/{id}         → JWT required, fetches from DB
//   POST /users              → JWT required, creates user in DB
//   DELETE /users/{id}       → JWT required, deletes from DB
//
// Architecture:
//
//   HTTPS Request
//         │
//         ▼
//   [RateLimitFilter]   ← NEW: 429 if IP exceeds 60 req/min
//         │
//         ▼
//      [Router]         ← matches path/method, extracts {params}
//         │
//         ▼
//    [JwtFilter]        ← verifies token
//         │
//         ▼
//     [Handler]         ← business logic
//         │
//         ▼
//  [UserRepository]     ← NEW: all SQL lives here
//         │
//         ▼
//      [SQLite]         ← NEW: users.db on disk
//
// Dependencies (place jars in lib/):
//   gson-2.10.1.jar       https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/
//   sqlite-jdbc-3.45.jar  https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.45.3.0/
//   jbcrypt-0.4.jar       https://repo1.maven.org/maven2/org/mindrot/jbcrypt/0.4/
//
// Environment variables:
//   APP_USER=admin
//   APP_PASS=secret        (bcrypt-hashed and stored in DB on first run)
//   JWT_SECRET=<32+ char random string>
//   KEYSTORE_PASS=changeit
//
// Build and run (without Docker):
//   javac -cp "lib/*" -d out src/org/example/ServerArchitecture.java
//   java  -cp "lib/*:out" org.example.ServerArchitecture
//
// Build and run (with Docker — see Dockerfile):
//   docker build -t java-server .
//   docker run -p 8443:8443 \
//     -e APP_USER=admin -e APP_PASS=secret \
//     -e JWT_SECRET=supersecretkey123456789012345678 \
//     -e KEYSTORE_PASS=changeit \
//     java-server
//
// Test:
//   TOKEN=$(curl -sk -X POST https://localhost:8443/login \
//     -H "Content-Type: application/json"               \
//     -d '{"username":"admin","password":"secret"}'     \
//     | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
//
//   curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8443/users/1
//   curl -sk -H "Authorization: Bearer $TOKEN" -X POST https://localhost:8443/users \
//        -H "Content-Type: application/json" \
//        -d '{"username":"alice","password":"pass123"}'
//   curl -sk -H "Authorization: Bearer $TOKEN" -X DELETE https://localhost:8443/users/2
// =============================================================

import com.google.gson.Gson;
import com.sun.net.httpserver.*;
import com.sun.net.httpserver.Filter;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.*;
import java.util.regex.*;

public class ServerArchitecture {

    private static final Logger log  = Logger.getLogger(ServerArchitecture.class.getName());
    private static final int    PORT = 8443;

    static final int  MAX_BODY_BYTES = 10_000;
    static final Gson GSON           = new Gson();

    public static void main(String[] args) {

        String appUser      = requireEnv("APP_USER");
        String appPass      = requireEnv("APP_PASS");
        String jwtSecret    = requireEnv("JWT_SECRET");
        String keystorePass = requireEnv("KEYSTORE_PASS");

        try {
            // ---------------------------------------------------
            // LEVEL 4: Initialise the database and seed the admin
            // user on first run. This happens before the server
            // starts — if the DB can't be set up, we fail fast.
            // ---------------------------------------------------
            UserRepository userRepo = new UserRepository("users.db");
            userRepo.initialise(appUser, appPass);

            HttpsServer server = HttpsServer.create(new InetSocketAddress(PORT), 0);
            server.setHttpsConfigurator(buildHttpsConfigurator(keystorePass));

            ExecutorService pool = Executors.newCachedThreadPool();
            server.setExecutor(pool);

            JwtFilter jwt    = new JwtFilter(jwtSecret);
            Router    router = new Router();

            // Public
            router.add("POST",   "/login",       new LoginHandler(userRepo, jwtSecret));

            // Protected — JWT wrapped
            router.add("GET",    "/hello",        jwt.wrap(new HelloHandler()));
            router.add("GET",    "/greet",        jwt.wrap(new GreetHandler()));
            router.add("POST",   "/echo",         jwt.wrap(new EchoHandler()));
            router.add("GET",    "/users/{id}",   jwt.wrap(new GetUserHandler(userRepo)));
            router.add("POST",   "/users",        jwt.wrap(new CreateUserHandler(userRepo)));
            router.add("DELETE", "/users/{id}",   jwt.wrap(new DeleteUserHandler(userRepo)));

            // ---------------------------------------------------
            // LEVEL 4: Attach the RateLimitFilter as a context
            // filter on "/". It runs before the Router for every
            // single request regardless of path or auth status.
            // ---------------------------------------------------
            RateLimitFilter rateLimiter = new RateLimitFilter(60, 60);
            HttpContext rootContext = server.createContext("/", router);
            rootContext.getFilters().add(rateLimiter);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                log.info("Shutting down...");
                server.stop(2);
                pool.shutdown();
                rateLimiter.shutdown();
                userRepo.close();
            }));

            server.start();
            log.info("HTTPS server running on https://localhost:" + PORT);

        } catch (Exception e) {
            log.log(Level.SEVERE, "Server could not start", e);
        }
    }

    // ===========================================================
    //  LEVEL 4 — ADDITION 1: UserRepository (Persistence Layer)
    //
    //  The Repository pattern keeps all SQL in one class.
    //  Handlers call methods like userRepo.findById(id) and never
    //  write a SQL string themselves. Benefits:
    //    - If you switch databases, change one class not ten handlers
    //    - SQL logic is testable in isolation
    //    - Handlers stay readable — no SQL strings cluttering them
    //
    //  JDBC (Java Database Connectivity) is the standard Java API
    //  for relational databases. The same code works for SQLite,
    //  PostgreSQL, MySQL — only the JDBC URL and driver jar change.
    //
    //  Passwords are stored as bcrypt hashes, never plaintext.
    //  BCrypt.hashpw() produces a new random salt every time so
    //  two identical passwords produce different hash strings.
    //  BCrypt.checkpw() verifies a plaintext password against a hash.
    // ===========================================================

    static class UserRepository {

        private static final Logger log = Logger.getLogger(UserRepository.class.getName());

        // Represents a row from the users table
        record User(int id, String username, String passwordHash, String createdAt) {}

        private final Connection conn;

        UserRepository(String dbPath) throws SQLException {
            // sqlite:// URL tells JDBC to use SQLite. The file is created
            // automatically if it doesn't exist.
            conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            log.info("Connected to SQLite database: " + dbPath);
        }

        // Create the users table if it doesn't exist, and seed the admin user.
        // Called once at startup — safe to call on every restart (IF NOT EXISTS).
        void initialise(String adminUsername, String adminPassword) throws SQLException {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        username     TEXT    NOT NULL UNIQUE,
                        password_hash TEXT   NOT NULL,
                        created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
                    )
                """);
            }
            log.info("Users table ready.");

            // Only insert admin if they don't already exist
            if (findByUsername(adminUsername).isEmpty()) {
                // BCrypt.hashpw() hashes the password with a random salt.
                // The salt is embedded in the resulting string — no need to
                // store it separately.
                String hash = BCrypt.hashpw(adminPassword, BCrypt.gensalt());
                create(adminUsername, hash);
                log.info("Admin user '" + adminUsername + "' seeded into database.");
            } else {
                log.info("Admin user already exists — skipping seed.");
            }
        }

        // Find a user by their numeric ID. Returns Optional — empty if not found.
        Optional<User> findById(int id) throws SQLException {
            // PreparedStatement prevents SQL injection — the ? is a parameter
            // placeholder, never concatenated directly into the SQL string.
            String sql = "SELECT id, username, password_hash, created_at FROM users WHERE id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, id);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    return Optional.of(new User(
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getString("password_hash"),
                            rs.getString("created_at")));
                }
            }
            return Optional.empty();
        }

        // Find a user by username. Used during login to validate credentials.
        Optional<User> findByUsername(String username) throws SQLException {
            String sql = "SELECT id, username, password_hash, created_at FROM users WHERE username = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    return Optional.of(new User(
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getString("password_hash"),
                            rs.getString("created_at")));
                }
            }
            return Optional.empty();
        }

        // Insert a new user. Password must already be bcrypt-hashed by the caller.
        User create(String username, String passwordHash) throws SQLException {
            String sql = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
            try (PreparedStatement ps = conn.prepareStatement(sql,
                    Statement.RETURN_GENERATED_KEYS)) {
                ps.setString(1, username);
                ps.setString(2, passwordHash);
                ps.executeUpdate();

                // RETURN_GENERATED_KEYS lets us read back the auto-generated ID
                ResultSet keys = ps.getGeneratedKeys();
                keys.next();
                int newId = keys.getInt(1);
                log.info("Created user: " + username + " (id=" + newId + ")");
                return findById(newId).orElseThrow();
            }
        }

        // Delete a user by ID. Returns true if a row was actually deleted.
        boolean delete(int id) throws SQLException {
            String sql = "DELETE FROM users WHERE id = ?";
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setInt(1, id);
                int affected = ps.executeUpdate();
                return affected > 0;
            }
        }

        void close() {
            try { conn.close(); } catch (SQLException e) {
                log.log(Level.WARNING, "Error closing DB connection", e);
            }
        }
    }

    // ===========================================================
    //  LEVEL 4 — ADDITION 2: RateLimitFilter
    //
    //  Tracks how many requests each IP address has made within
    //  a rolling time window. Rejects excess requests with 429.
    //
    //  Data structure:
    //    ConcurrentHashMap<String, RequestWindow>
    //      key   = client IP address string
    //      value = window tracking request count + window start time
    //
    //  ConcurrentHashMap is used instead of HashMap because multiple
    //  threads handle requests simultaneously. A plain HashMap would
    //  produce corrupt state under concurrent writes.
    //
    //  AtomicInteger is used for the request counter inside each
    //  window — it provides thread-safe increment without locks.
    //
    //  A ScheduledExecutorService runs a cleanup task every minute
    //  to remove entries for IPs that haven't sent requests recently,
    //  preventing the map from growing indefinitely.
    //
    //  constructor params:
    //    maxRequests  — how many requests allowed per window
    //    windowSeconds — how long the window is in seconds
    // ===========================================================

    static class RateLimitFilter extends Filter {

        private static final Logger log = Logger.getLogger(RateLimitFilter.class.getName());

        // Inner class to track one IP's request window
        private static class RequestWindow {
            final AtomicInteger count     = new AtomicInteger(0);
            volatile long       windowStart = Instant.now().getEpochSecond();
        }

        private final int maxRequests;
        private final long windowSeconds;
        private final ConcurrentHashMap<String, RequestWindow> windows = new ConcurrentHashMap<>();
        private final ScheduledExecutorService cleaner = Executors.newSingleThreadScheduledExecutor();

        RateLimitFilter(int maxRequests, long windowSeconds) {
            this.maxRequests   = maxRequests;
            this.windowSeconds = windowSeconds;

            // Prune stale entries every minute so the map doesn't grow forever.
            // An entry is stale if it hasn't been active for more than one window.
            cleaner.scheduleAtFixedRate(() -> {
                long now = Instant.now().getEpochSecond();
                windows.entrySet().removeIf(e ->
                        (now - e.getValue().windowStart) > windowSeconds * 2);
                log.fine("Rate limiter pruned stale entries. Active IPs: " + windows.size());
            }, 1, 1, TimeUnit.MINUTES);
        }

        @Override
        public String description() { return "Rate Limit Filter"; }

        @Override
        public void doFilter(HttpExchange exchange, Filter.Chain chain) throws IOException {

            // Extract the client IP from the remote address
            String ip = exchange.getRemoteAddress().getAddress().getHostAddress();
            long   now = Instant.now().getEpochSecond();

            // computeIfAbsent is atomic — safe under concurrent access.
            // Gets existing window or creates a new one for this IP.
            RequestWindow window = windows.computeIfAbsent(ip, k -> new RequestWindow());

            // If the window has expired, reset it
            // synchronized on the window object to prevent two threads
            // both seeing an expired window and both resetting it
            synchronized (window) {
                if ((now - window.windowStart) >= windowSeconds) {
                    window.windowStart = now;
                    window.count.set(0);
                }
            }

            int requestCount = window.count.incrementAndGet();

            if (requestCount > maxRequests) {
                log.warning("Rate limit exceeded for IP: " + ip
                        + " (" + requestCount + " requests in window)");

                // Retry-After header tells the client how many seconds to wait
                long retryAfter = windowSeconds - (now - window.windowStart);
                exchange.getResponseHeaders().set("Retry-After", String.valueOf(retryAfter));

                byte[] body = GSON.toJson(Map.of(
                        "error",      "Too Many Requests",
                        "retryAfter", retryAfter + "s"
                )).getBytes(StandardCharsets.UTF_8);

                exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
                exchange.sendResponseHeaders(429, body.length);
                try (OutputStream out = exchange.getResponseBody()) { out.write(body); }
                return; // do NOT call chain.doFilter — block the request
            }

            chain.doFilter(exchange); // within limit — proceed
        }

        void shutdown() { cleaner.shutdownNow(); }
    }

    // ===========================================================
    //  HANDLER: POST /login (updated to use UserRepository)
    //
    //  Now looks up the user from the database instead of comparing
    //  against hardcoded env var strings.
    //  BCrypt.checkpw() verifies the submitted password against
    //  the stored hash — it never decrypts (bcrypt is one-way).
    // ===========================================================

    static class LoginHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(LoginHandler.class.getName());
        private final UserRepository userRepo;
        private final String         jwtSecret;

        LoginHandler(UserRepository userRepo, String jwtSecret) {
            this.userRepo  = userRepo;
            this.jwtSecret = jwtSecret;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("POST /login from " + exchange.getRemoteAddress());
            try {
                byte[] bodyBytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES);
                @SuppressWarnings("unchecked")
                Map<String, String> creds = GSON.fromJson(
                        new String(bodyBytes, StandardCharsets.UTF_8), Map.class);

                String username = creds.getOrDefault("username", "");
                String password = creds.getOrDefault("password", "");

                Optional<UserRepository.User> userOpt = userRepo.findByUsername(username);

                // BCrypt.checkpw() does the comparison — never compare hashes with .equals()
                if (userOpt.isEmpty() || !BCrypt.checkpw(password, userOpt.get().passwordHash())) {
                    log.warning("Failed login attempt for: " + username);
                    sendResponse(exchange, 401, "application/json",
                            GSON.toJson(Map.of("error", "Invalid credentials")),
                            CachePolicy.NO_STORE);
                    return;
                }

                String token = Jwt.issue(username, jwtSecret);
                log.info("JWT issued for: " + username);
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
    //  HANDLER: GET /users/{id}  — fetches a user from the DB
    // ===========================================================

    static class GetUserHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(GetUserHandler.class.getName());
        private final UserRepository userRepo;

        GetUserHandler(UserRepository userRepo) { this.userRepo = userRepo; }

        @Override
        @SuppressWarnings("unchecked")
        public void handle(HttpExchange exchange) throws IOException {
            log.info("GET /users/{id}");
            try {
                Map<String, String> pathParams =
                        (Map<String, String>) exchange.getAttribute("pathParams");
                int id = Integer.parseInt(pathParams.getOrDefault("id", "0"));

                Optional<UserRepository.User> userOpt = userRepo.findById(id);

                if (userOpt.isEmpty()) {
                    sendResponse(exchange, 404, "application/json",
                            GSON.toJson(Map.of("error", "User not found")),
                            CachePolicy.NO_STORE);
                    return;
                }

                UserRepository.User user = userOpt.get();
                // Never return the password hash in an API response
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("id",        user.id());
                response.put("username",  user.username());
                response.put("createdAt", user.createdAt());

                sendResponse(exchange, 200, "application/json",
                        GSON.toJson(response), CachePolicy.PRIVATE);

            } catch (NumberFormatException e) {
                sendResponse(exchange, 400, "application/json",
                        GSON.toJson(Map.of("error", "Invalid user ID")),
                        CachePolicy.NO_STORE);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in GetUserHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")),
                        CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER: POST /users  — creates a new user
    //
    //  Accepts { "username": "...", "password": "..." }.
    //  Hashes the password with bcrypt before storing.
    //  Returns 409 Conflict if username already exists.
    // ===========================================================

    static class CreateUserHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(CreateUserHandler.class.getName());
        private final UserRepository userRepo;

        CreateUserHandler(UserRepository userRepo) { this.userRepo = userRepo; }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("POST /users");
            try {
                byte[] bodyBytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES);
                @SuppressWarnings("unchecked")
                Map<String, String> body = GSON.fromJson(
                        new String(bodyBytes, StandardCharsets.UTF_8), Map.class);

                String username = body.getOrDefault("username", "").trim();
                String password = body.getOrDefault("password", "").trim();

                if (username.isEmpty() || password.isEmpty()) {
                    sendResponse(exchange, 400, "application/json",
                            GSON.toJson(Map.of("error", "username and password are required")),
                            CachePolicy.NO_STORE);
                    return;
                }

                // Hash the password before it ever touches the database
                String hash = BCrypt.hashpw(password, BCrypt.gensalt());

                try {
                    UserRepository.User created = userRepo.create(username, hash);
                    Map<String, Object> response = new LinkedHashMap<>();
                    response.put("id",       created.id());
                    response.put("username", created.username());
                    sendResponse(exchange, 201, "application/json",
                            GSON.toJson(response), CachePolicy.NO_STORE);
                } catch (SQLException e) {
                    // SQLite UNIQUE constraint violation error code is 19
                    if (e.getErrorCode() == 19) {
                        sendResponse(exchange, 409, "application/json",
                                GSON.toJson(Map.of("error", "Username already exists")),
                                CachePolicy.NO_STORE);
                    } else {
                        throw e;
                    }
                }

            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in CreateUserHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")),
                        CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  HANDLER: DELETE /users/{id}  — removes a user from the DB
    // ===========================================================

    static class DeleteUserHandler implements HttpHandler {

        private static final Logger log = Logger.getLogger(DeleteUserHandler.class.getName());
        private final UserRepository userRepo;

        DeleteUserHandler(UserRepository userRepo) { this.userRepo = userRepo; }

        @Override
        @SuppressWarnings("unchecked")
        public void handle(HttpExchange exchange) throws IOException {
            log.info("DELETE /users/{id}");
            try {
                Map<String, String> pathParams =
                        (Map<String, String>) exchange.getAttribute("pathParams");
                int id = Integer.parseInt(pathParams.getOrDefault("id", "0"));

                boolean deleted = userRepo.delete(id);
                if (!deleted) {
                    sendResponse(exchange, 404, "application/json",
                            GSON.toJson(Map.of("error", "User not found")),
                            CachePolicy.NO_STORE);
                    return;
                }

                // 204 No Content — success, nothing to return
                exchange.sendResponseHeaders(204, -1);

            } catch (NumberFormatException e) {
                sendResponse(exchange, 400, "application/json",
                        GSON.toJson(Map.of("error", "Invalid user ID")),
                        CachePolicy.NO_STORE);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in DeleteUserHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")),
                        CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  Existing handlers — HelloHandler, GreetHandler, EchoHandler
    //  (unchanged from Level 3)
    // ===========================================================

    static class HelloHandler implements HttpHandler {
        private static final Logger log = Logger.getLogger(HelloHandler.class.getName());
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("GET /hello");
            try {
                String user = (String) exchange.getAttribute("authenticatedUser");
                sendResponse(exchange, 200, "text/plain",
                        "Hello, " + user + "! You are authenticated.", CachePolicy.PRIVATE);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in HelloHandler", e);
                sendResponse(exchange, 500, "text/plain",
                        "500 Internal Server Error", CachePolicy.NO_STORE);
            }
        }
    }

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

    static class EchoHandler implements HttpHandler {
        private static final Logger log = Logger.getLogger(EchoHandler.class.getName());
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            log.info("POST /echo");
            try {
                String clHeader = exchange.getRequestHeaders().getFirst("Content-Length");
                long cl = clHeader != null ? Long.parseLong(clHeader) : -1;
                if (cl > MAX_BODY_BYTES) {
                    sendResponse(exchange, 413, "application/json",
                            GSON.toJson(Map.of("error", "Payload too large")), CachePolicy.NO_STORE);
                    return;
                }
                byte[] bodyBytes = exchange.getRequestBody().readNBytes(MAX_BODY_BYTES + 1);
                if (bodyBytes.length > MAX_BODY_BYTES) {
                    sendResponse(exchange, 413, "application/json",
                            GSON.toJson(Map.of("error", "Payload too large")), CachePolicy.NO_STORE);
                    return;
                }
                String body = new String(bodyBytes, StandardCharsets.UTF_8);
                Map<String, Object> resp = new HashMap<>();
                resp.put("echo", body.isEmpty() ? "(empty)" : body);
                sendResponse(exchange, 200, "application/json",
                        GSON.toJson(resp), CachePolicy.NO_STORE);
            } catch (Exception e) {
                log.log(Level.SEVERE, "Error in EchoHandler", e);
                sendResponse(exchange, 500, "application/json",
                        GSON.toJson(Map.of("error", "Internal Server Error")), CachePolicy.NO_STORE);
            }
        }
    }

    // ===========================================================
    //  Router, JwtFilter, Jwt — unchanged from Level 3
    // ===========================================================

    static class Router implements HttpHandler {
        private static final Logger log = Logger.getLogger(Router.class.getName());
        private record Route(String method, Pattern pattern,
                             List<String> paramNames, HttpHandler handler) {}
        private final List<Route> routes = new ArrayList<>();

        void add(String method, String pathTemplate, HttpHandler handler) {
            List<String> paramNames = new ArrayList<>();
            String regex = Arrays.stream(pathTemplate.split("/"))
                    .map(segment -> {
                        if (segment.startsWith("{") && segment.endsWith("}")) {
                            paramNames.add(segment.substring(1, segment.length() - 1));
                            return "([^/]+)";
                        }
                        return Pattern.quote(segment);
                    })
                    .reduce((a, b) -> a + "/" + b).orElse("");
            routes.add(new Route(method.toUpperCase(),
                    Pattern.compile("^" + regex + "$"), paramNames, handler));
            log.info("Route: " + method.toUpperCase() + " " + pathTemplate);
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path   = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase();
            boolean pathFound = false;
            for (Route route : routes) {
                Matcher m = route.pattern().matcher(path);
                if (m.matches()) {
                    pathFound = true;
                    if (!route.method().equals(method)) continue;
                    Map<String, String> pp = new HashMap<>();
                    for (int i = 0; i < route.paramNames().size(); i++)
                        pp.put(route.paramNames().get(i), m.group(i + 1));
                    exchange.setAttribute("pathParams", pp);
                    route.handler().handle(exchange);
                    return;
                }
            }
            if (pathFound) {
                sendResponse(exchange, 405, "application/json",
                        GSON.toJson(Map.of("error", "Method Not Allowed")), CachePolicy.NO_STORE);
            } else {
                sendResponse(exchange, 404, "application/json",
                        GSON.toJson(Map.of("error", "Not Found")), CachePolicy.NO_STORE);
            }
        }
    }

    static class JwtFilter {
        private static final Logger log = Logger.getLogger(JwtFilter.class.getName());
        private final String secret;
        JwtFilter(String secret) { this.secret = secret; }

        HttpHandler wrap(HttpHandler inner) {
            return exchange -> {
                String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
                if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                    rejectUnauthorized(exchange, "Missing Bearer token"); return;
                }
                try {
                    String username = Jwt.verify(authHeader.substring("Bearer ".length()).trim(), secret);
                    exchange.setAttribute("authenticatedUser", username);
                    inner.handle(exchange);
                } catch (SecurityException e) {
                    rejectUnauthorized(exchange, e.getMessage());
                } catch (Exception e) {
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

    static class Jwt {
        private static final long EXPIRY_SECONDS = 3600;

        static String issue(String subject, String secret) throws Exception {
            String header  = b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
            String payload = b64url("{\"sub\":\"" + subject + "\","
                    + "\"exp\":" + (Instant.now().getEpochSecond() + EXPIRY_SECONDS) + "}");
            String hp = header + "." + payload;
            return hp + "." + sign(hp, secret);
        }

        static String verify(String token, String secret) throws Exception {
            String[] p = token.split("\\.");
            if (p.length != 3) throw new IllegalArgumentException("Malformed token");
            if (!MessageDigest.isEqual(sign(p[0] + "." + p[1], secret).getBytes(StandardCharsets.UTF_8),
                    p[2].getBytes(StandardCharsets.UTF_8)))
                throw new SecurityException("Invalid token signature");
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = GSON.fromJson(
                    new String(Base64.getUrlDecoder().decode(p[1]), StandardCharsets.UTF_8), Map.class);
            if (Instant.now().getEpochSecond() > ((Double) claims.get("exp")).longValue())
                throw new SecurityException("Token has expired");
            return (String) claims.get("sub");
        }

        private static String sign(String data, String secret) throws Exception {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        }

        private static String b64url(String json) {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(json.getBytes(StandardCharsets.UTF_8));
        }
    }

    // ===========================================================
    //  Cache Policy, shared utilities — unchanged
    // ===========================================================

    enum CachePolicy {
        PUBLIC("public, max-age=3600"), PRIVATE("private, max-age=600"), NO_STORE("no-store");
        final String headerValue;
        CachePolicy(String h) { this.headerValue = h; }
    }

    private static String requireEnv(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            log.severe(name + " env var not set. Refusing to start.");
            System.exit(1);
        }
        return v;
    }

    static void sendResponse(HttpExchange exchange, int status, String contentType,
                             String body, CachePolicy cache) throws IOException {
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
                result.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                        parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
            } catch (IllegalArgumentException e) {
                log.warning("Skipping malformed query param: " + parts[0]);
            }
        }
        return result;
    }

    private static HttpsConfigurator buildHttpsConfigurator(String keystorePass) throws Exception {
        char[] password = keystorePass.toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream in = new FileInputStream("keystore.jks")) { ks.load(in, password); }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password);
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(kmf.getKeyManagers(), null, null);
        return new HttpsConfigurator(ssl) {
            @Override
            public void configure(HttpsParameters p) {
                p.setSSLParameters(getSSLContext().getDefaultSSLParameters());
            }
        };
    }
}