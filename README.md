# Java HTTP Server — Built from First Principles

> A production-grade HTTP server built in pure Java with no frameworks — demonstrating authentication, routing, caching, persistence, rate limiting, and containerisation from scratch.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Learning Outcomes](#learning-outcomes)
- [Project Structure](#project-structure)
- [Challenges & Next Steps](#challenges--next-steps)
- [Credits & References](#credits--references)

---

## Overview

This project implements a fully functional HTTP server using **only the Java standard library and a handful of small libraries**, exposing every concept that frameworks normally abstract away.

The project evolved through four deliberate levels, each adding one layer of real-world complexity:

| Level | What was added |
|-------|----------------|
| Original | HTTP server, Basic Auth, Cache-Control headers, thread pool |
| Level 1 | Environment config, URL decoding, body size limits, Gson, method routing |
| Level 2 | Health check endpoint, request logging middleware, static file serving |
| Level 3 | Router with path parameters, HTTPS/TLS, JWT authentication |
| Level 4 | SQLite persistence, bcrypt password hashing, rate limiting, Docker |

**Why build this?** To understand what Spring Boot, Express, and Django are actually doing under the hood

**Key technologies:** Java 21, Gson, SQLite (JDBC), jBCrypt, Docker.

---

## Features

### Authentication & Security
- HTTP Basic Authentication with Base64 decoding (original)
- JWT (JSON Web Token) authentication with HS256 signing and expiry (Level 3)
- bcrypt password hashing — passwords never stored or compared in plaintext (Level 4)
- HTTPS/TLS via `HttpsServer` and a JKS keystore (Level 3)
- Constant-time signature comparison to prevent timing attacks (Level 3)

### Request Pipeline
- Chain of Responsibility filter pattern — auth and method enforcement before handlers run
- Centralised Router with path parameter support — `/users/{id}` style routing (Level 3)
- `MethodFilter` — centralised HTTP method enforcement, 405 returned automatically
- `RateLimitFilter` — per-IP sliding window rate limiting, 429 with `Retry-After` header (Level 4)

### Endpoints
- `POST /login` — exchanges credentials for a JWT token (Level 3)
- `GET /hello` — authenticated greeting, `private` cache policy
- `GET /greet?name=Alice` — JSON greeting with URL-decoded query params, `public` cache policy
- `POST /echo` — echoes request body as JSON with payload size enforcement
- `GET /users/{id}` — fetches a user from the database (Level 4)
- `POST /users` — creates a new user with bcrypt-hashed password (Level 4)
- `DELETE /users/{id}` — removes a user, returns 204 No Content (Level 4)

### Infrastructure
- Thread pool concurrency — `CachedThreadPool` for I/O-bound request handling
- Graceful shutdown — JVM shutdown hook gives in-flight requests 2 seconds to complete
- Per-class loggers — every log line identifies its source class automatically
- SQLite persistence via JDBC — `UserRepository` pattern keeps all SQL in one place (Level 4)
- Docker multi-stage build — compiles in JDK image, runs in smaller JRE image (Level 4)
- Health check — `HEALTHCHECK` instruction in Dockerfile for container self-healing (Level 4)

---

## Installation

### Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Java JDK | 21+ | Compile and run the server |
| Docker | Any recent | Run containerised (optional) |
| `keytool` | Bundled with JDK | Generate the TLS certificate |
| `curl` | Any | Test endpoints from the terminal |

### Dependency JARs

Download these into a `lib/` directory in the project root:

| Library | Version | Download |
|---------|---------|----------|
| `gson` | 2.10.1 | [Maven Central](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.10.1/) |
| `sqlite-jdbc` | 3.45.3 | [Maven Central](https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.45.3.0/) |
| `jbcrypt` | 0.4 | [Maven Central](https://repo1.maven.org/maven2/org/mindrot/jbcrypt/0.4/) |

### 1. Clone the repository

```bash
git clone https://github.com/username/java-http-server.git
cd java-http-server
```

### 2. Generate a TLS certificate (one-time setup)

```bash
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 \
        -validity 365 -keystore keystore.jks              \
        -storepass changeit -keypass changeit              \
        -dname "CN=localhost"
```

This creates `keystore.jks` in the project root. Keep this file out of version control.

### 3. Set environment variables

```bash
export APP_USER=admin
export APP_PASS=secret
export JWT_SECRET=a-long-random-secret-string-at-least-32-chars
export KEYSTORE_PASS=changeit
```

### 4. Compile

```bash
mkdir -p out
javac -cp "lib/*" -d out src/org/example/ServerArchitecture.java
```

### 5. Run

```bash
java -cp "lib/*:out" org.example.ServerArchitecture
```

The server starts on `https://localhost:8443`.

### Alternative: Run with Docker

```bash
# Build the image
docker build -t java-server .

# Run the container
docker run -p 8443:8443 \
  -e APP_USER=admin \
  -e APP_PASS=secret \
  -e JWT_SECRET=supersecretkey123456789012345678 \
  -e KEYSTORE_PASS=changeit \
  -v $(pwd)/keystore.jks:/app/keystore.jks:ro \
  -v java-server-data:/app/data \
  java-server
```

The `-v $(pwd)/keystore.jks` flag mounts the certificate without baking it into the image. The `-v java-server-data:/app/data` flag persists the SQLite database across container restarts.

---

## Usage

### Step 1 — Get a JWT token

```bash
TOKEN=$(curl -sk -X POST https://localhost:8443/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo $TOKEN
```

Expected response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": "3600s"
}
```

### Step 2 — Call protected endpoints

```bash
# Plain greeting
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/hello

# JSON greeting with URL-encoded name
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost:8443/greet?name=John%20Doe"

# Echo a request body
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X POST https://localhost:8443/echo \
  -H "Content-Type: application/json" \
  -d '{"message": "hello server"}'

# Fetch a user from the database
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/users/1

# Create a new user
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X POST https://localhost:8443/users \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"pass123"}'

# Delete a user
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X DELETE https://localhost:8443/users/2
```

### Testing error responses

```bash
# Wrong password → 401
curl -sk -X POST https://localhost:8443/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong"}'

# No token → 401
curl -sk https://localhost:8443/hello

# Wrong HTTP method → 405
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X DELETE https://localhost:8443/hello

# Unknown path → 404
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/unknown

# Duplicate username → 409
curl -sk -H "Authorization: Bearer $TOKEN" \
  -X POST https://localhost:8443/users \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"anything"}'
```

### HTTP status codes used in this project

| Code | Meaning | When returned |
|------|---------|---------------|
| 200 | OK | Successful GET or POST |
| 201 | Created | New user successfully created |
| 204 | No Content | Successful DELETE |
| 400 | Bad Request | Missing required fields |
| 401 | Unauthorized | Missing, invalid, or expired token |
| 404 | Not Found | Unknown route or user ID not in DB |
| 405 | Method Not Allowed | Wrong HTTP method for the route |
| 409 | Conflict | Username already exists |
| 413 | Payload Too Large | POST body exceeds 10 KB limit |
| 429 | Too Many Requests | IP exceeded 60 requests per minute |
| 500 | Internal Server Error | Unhandled exception in a handler |

---

## Learning Outcomes

### HTTP & Networking
- How the HTTP request/response cycle works at the protocol level — headers, body, status codes
- What `Content-Type`, `Cache-Control`, `Authorization`, `WWW-Authenticate`, `Allow`, and `Retry-After` headers do and when to set them
- The difference between `public`, `private`, and `no-store` cache policies and why they matter
- Why Basic Auth over plain HTTP is insecure — Base64 is encoding, not encryption
- What HTTPS actually does — TLS encrypts the transport layer, not the data itself

### Java
- How `com.sun.net.httpserver` works — `HttpServer`, `HttpHandler`, `Filter`, `HttpExchange`
- Thread pools — `CachedThreadPool` vs `FixedThreadPool`, and why I/O-bound workloads suit cached pools
- `InputStream`/`OutputStream` — why servers read and write bytes, not strings
- Concurrency primitives — `AtomicInteger`, `AtomicLong`, `ConcurrentHashMap`, and why plain `HashMap` is unsafe under concurrent writes
- Check-then-act race conditions and how `synchronized` blocks solve them
- `java.time.Instant` for timestamps and elapsed time measurement
- `java.nio.Files` for modern file I/O
- `try-with-resources` — how `AutoCloseable` guarantees stream closure even on exception
- Java `record` types — what they auto-generate and when to use them
- Regular expressions — `Pattern`, `Matcher`, and capture groups for path parameter extraction
- JDBC API — `Connection`, `PreparedStatement`, `ResultSet` — and why the same code works across databases

### Security
- JWT structure — header, payload, signature, Base64Url encoding, expiry claims
- HMAC-SHA256 — what a MAC is, how it proves data integrity without encryption
- Timing attacks — why `==` comparison leaks information and why constant-time `MessageDigest.isEqual()` is required
- SQL injection — how `PreparedStatement` placeholders make it structurally impossible
- bcrypt — why it's the right choice for passwords: one-way, salted, deliberately slow
- Path traversal attacks — how `../../etc/passwd` style requests exploit naive file servers
- Rate limiting as resilience — sliding windows, `Retry-After`, and the `429` status code

### Design Patterns & Principles
- **Chain of Responsibility** — filter pipeline where each layer either passes or blocks
- **Decorator Pattern** — `JwtFilter.wrap()` adds behaviour without changing the wrapped handler
- **Repository Pattern** — `UserRepository` isolates all SQL, making handlers and data access independently changeable
- **Strategy Pattern** — `CachePolicy` enum encapsulates varying cache behaviour behind a common interface
- **Single Responsibility Principle** — every class does exactly one job
- **DRY** — `sendResponse()` and `parseQuery()` eliminate repeated boilerplate
- **Fail Fast** — invalid requests rejected at the earliest possible point, minimum wasted processing
- **Externalized Configuration** — credentials and secrets in environment variables, never in source code

### Infrastructure & DevOps
- Docker — images vs containers, layers, `FROM`, `COPY`, `RUN`, `CMD`, `EXPOSE`
- Multi-stage Docker builds — why separating compile and runtime stages reduces image size
- Docker volumes — why container filesystems are ephemeral and how volumes persist data
- Environment variable injection — `-e` flags vs `ENV` in Dockerfile, why secrets never belong in images
- TLS certificate management — `keytool`, JKS keystores, `KeyManagerFactory`, `SSLContext`
- Health checks — what `HEALTHCHECK` does and why production containers need them

---

## Project Structure

```
java-http-server/
│
├── src/
│   └── org/example/
│       └── ServerArchitecture.java     # Entire server — all classes in one file
│           ├── main()                  # Server setup, route registration, shutdown hook
│           ├── UserRepository          # All database access (JDBC + SQLite)
│           ├── RateLimitFilter         # Per-IP sliding window rate limiting
│           ├── Router                  # Path pattern matching, 404/405 handling
│           ├── JwtFilter               # JWT verification, wraps protected handlers
│           ├── Jwt                     # HS256 token issue and verify (manual impl)
│           ├── LoginHandler            # POST /login — credential check, token issue
│           ├── HelloHandler            # GET /hello
│           ├── GreetHandler            # GET /greet?name=X
│           ├── EchoHandler             # POST /echo
│           ├── GetUserHandler          # GET /users/{id}
│           ├── CreateUserHandler       # POST /users
│           ├── DeleteUserHandler       # DELETE /users/{id}
│           ├── CachePolicy             # Cache-Control enum (PUBLIC, PRIVATE, NO_STORE)
│           └── Utilities               # sendResponse(), parseQuery(), requireEnv()
│
├── lib/                                # External JAR dependencies (not committed)
│   ├── gson-2.10.1.jar
│   ├── sqlite-jdbc-3.45.3.0.jar
│   └── jbcrypt-0.4.jar
│
├── out/                                # Compiled .class files (not committed)
│
├── data/                               # Runtime database (not committed)
│   └── users.db                        # SQLite database, created on first run
│
├── keystore.jks                        # TLS certificate (not committed — contains private key)
├── Dockerfile                          # Multi-stage build: JDK compile → JRE runtime
├── .gitignore
└── README.md
```

### What to add to `.gitignore`

```
# Compiled output
out/

# Runtime data
data/
*.db

# TLS certificate — contains private key, never commit
keystore.jks

# Dependencies — download separately
lib/

# IDE files
.idea/
*.iml
.vscode/
```

---

## Challenges & Next Steps

### Challenges Faced

**1. Basic Auth is not encryption**
The original server sent credentials as `Authorization: Basic YWRtaW46c2VjcmV0` — just Base64. Anyone watching the network can decode this in one command. The solution was HTTPS (Level 3), which encrypts the transport layer so credentials are never transmitted in plaintext. The lesson: security must be layered. Fixing authentication without fixing the transport layer only partially solves the problem.

**2. String-concatenated JSON breaks silently**
The original `GreetHandler` built JSON by hand: `"{\"message\":\"Hello, " + name + "!\"}"`. This produces invalid JSON if `name` contains a quote or backslash — and it fails silently, returning broken output rather than an error. The fix was Gson (Level 1), which escapes all special characters automatically. The lesson: never build structured formats (JSON, XML, SQL) by string concatenation.

**3. The logger name bug**
`HelloHandler` declared `private static final Logger log` (lowercase) but called `Log` (uppercase — the outer class logger). A one-character typo that doesn't crash, doesn't fail to compile, but silently routes all `HelloHandler` log lines through `ServerArchitecture`'s logger. Caught only by inspecting log output carefully. The lesson: subtle bugs often produce wrong output rather than errors.

**4. Race condition in the rate limiter**
A rate limiter needs to check if a window has expired AND reset it atomically. With multiple threads, two could both see an expired window and both reset it — doubling the allowed request count. Solved with `synchronized (window)` around the check-then-reset block. The lesson: concurrent code requires thinking about what happens when two threads execute the same lines simultaneously.

**5. Clients can lie about body size**
The `Content-Length` header declares how many bytes the body contains — but clients can omit it or lie. A malicious client could send no `Content-Length` and stream gigabytes. Fixed with a two-phase check: reject declared-too-large before reading, and use `readNBytes(MAX + 1)` to cap actual reading. The lesson: never trust client-supplied metadata without independent verification.

**6. TLS configuration complexity**
`HttpsServer` requires `KeyStore` → `KeyManagerFactory` → `SSLContext` → `HttpsConfigurator` — four classes working together. None of them is obvious in isolation. The solution was encapsulating all of it in `buildHttpsConfigurator()` so `main()` stays readable, and adding detailed comments explaining what each layer does.

---

### Next Steps

**Unit testing** — handlers are currently static inner classes, which makes them hard to test in isolation. Refactoring to top-level classes and writing JUnit tests for `parseQuery()`, `UserRepository`, and each handler would immediately improve confidence in correctness. This is the single highest-value next step.

**Refresh tokens** — JWT tokens currently expire after one hour and cannot be renewed without logging in again. A `/refresh` endpoint that exchanges a valid (non-expired) token for a new one is standard practice in real applications.

**Multiple users and roles** — the database has users but no concept of roles (admin vs regular user). Adding a `role` column and checking it in `JwtFilter` would introduce role-based access control (RBAC) — a fundamental authorisation concept.

**PostgreSQL migration** — because all SQL is in `UserRepository` and uses standard JDBC, switching from SQLite to PostgreSQL is a matter of changing the JDBC URL and driver jar. Actually doing this migration demonstrates the power of the Repository pattern.

**Rebuild in Spring Boot** — now that every piece of the server has been built by hand, rebuilding the same thing in Spring Boot reveals exactly what the framework provides: `@RestController` is a Handler, `OncePerRequestFilter` is a Filter, `JpaRepository` is a Repository. The framework stops being magic and becomes familiar patterns with a different syntax.

**Frontend** — adding a simple HTML/JavaScript frontend that calls these endpoints would complete the full-stack picture — login form, token storage in memory, fetch calls with Bearer headers.

---

## Credits & References

### Documentation
- [Java HttpServer documentation](https://docs.oracle.com/en/java/docs/api/jdk.httpserver/com/sun/net/httpserver/HttpServer.html)
- [JWT specification — RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [HTTP Basic Auth — RFC 7617](https://datatracker.ietf.org/doc/html/rfc7617)
- [HTTP Caching — RFC 9111](https://datatracker.ietf.org/doc/html/rfc9111)
- [SQLite JDBC driver (Xerial)](https://github.com/xerial/sqlite-jdbc)
- [jBCrypt](https://www.mindrot.org/projects/jBCrypt/)
- [Gson](https://github.com/google/gson)

### Concepts
- [OWASP Top 10](https://owasp.org/www-project-top-ten/) — SQL injection, path traversal
- [The 12-Factor App](https://12factor.net/) — externalized configuration
- [Docker multi-stage builds](https://docs.docker.com/build/building/multi-stage/)
- [MDN HTTP documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP) — headers, status codes, caching

### Tools
- [eclipse-temurin](https://hub.docker.com/_/eclipse-temurin) — JDK/JRE Docker base images
- [keytool](https://docs.oracle.com/en/java/docs/technotes/tools/unix/keytool.html) — TLS certificate generation
