# Java HTTP Server — Production-Ready Architecture

> A framework-free HTTP server built in pure Java, demonstrating authentication, caching, routing, and concurrency from first principles.

---

## Overview

This project builds a fully functional HTTP server using **only the Java standard library**, no frameworks, no external dependencies to expose those mechanics directly.

It is structured as a learning reference for core backend and software engineering concepts:

- HTTP request/response lifecycle
- Basic Authentication (RFC 7617)
- Cache-Control header strategies
- Thread pool concurrency
- Chain of Responsibility pattern
- Graceful shutdown

---

## Architecture

```
Incoming Request
      │
      ▼
 [AuthFilter]        ← checks Authorization header
      │                 rejects with 401 if credentials invalid
      ▼
  [Handler]          ← HelloHandler / GreetHandler / EchoHandler
      │
      ▼
   Response          ← with appropriate Cache-Control headers
```

Every request passes through the `AuthFilter` before reaching any handler. If credentials are missing or wrong, the request is rejected immediately and the handler never runs.

---

## Endpoints

| Method | Path | Description | Cache Policy |
|--------|------|-------------|--------------|
| `GET` | `/hello` | Returns a plain text greeting | `private, max-age=600` |
| `GET` | `/greet?name=Alice` | Returns a personalised JSON greeting | `public, max-age=3600` |
| `POST` | `/echo` | Echoes the request body back as JSON | `no-store` |

All endpoints require HTTP Basic Authentication.

**Default credentials**
```
Username: admin
Password: secret
```

---

## Getting Started

### Prerequisites

- Java 11 or higher
- No build tool required (no Maven, no Gradle)

### Run

```bash
# Compile
javac ServerArchitecture.java

# Run
java org.example.ServerArchitecture
```

The server starts on `http://localhost:8000`.

### Test with curl

```bash
# Plain text greeting
curl -u admin:secret http://localhost:8000/hello

# Personalised JSON response
curl -u admin:secret "http://localhost:8000/greet?name=Alice"

# Echo a JSON body
curl -u admin:secret -X POST http://localhost:8000/echo \
     -H "Content-Type: application/json" \
     -d '{"key": "value"}'

# Test auth rejection
curl -u admin:wrong http://localhost:8000/hello
# → 401 Unauthorized
```

---

## Key Concepts

### Basic Authentication
The `AuthFilter` decodes the `Authorization: Basic <base64>` header on every request, extracts the username and password, and either forwards the request to the handler or returns a `401` with a `WWW-Authenticate` header that prompts browsers to show a login dialog.

### Cache-Control Strategies
Three policies are defined as an enum and applied per-endpoint based on data sensitivity:

| Policy | Header | Use Case |
|--------|--------|----------|
| `PUBLIC` | `public, max-age=3600` | Generic data — CDN/proxy cacheable |
| `PRIVATE` | `private, max-age=600` | User-specific data — browser only |
| `NO_STORE` | `no-store` | Sensitive data — never stored |

### Thread Pool
A `CachedThreadPool` handles concurrency - each incoming request gets its own thread, and idle threads are reused rather than destroyed. This is appropriate for I/O-bound workloads like HTTP handling.

### Graceful Shutdown
A JVM shutdown hook fires on `Ctrl+C`, giving in-flight requests 2 seconds to complete before the server closes and the thread pool terminates.

---

## Design Principles Applied

| Principle | Where |
|-----------|-------|
| Single Responsibility | Each class has exactly one job |
| Chain of Responsibility | `AuthFilter` is fully decoupled from handlers |
| DRY | `sendResponse()` and `parseQuery()` shared across all handlers |
| Open/Closed | New routes added via `registerRoute()` without modifying existing code |
| Fail Fast | Auth rejection happens at the earliest possible point |

---

## Known Limitations

These are intentional simplifications for clarity, not oversights:

- **Hardcoded credentials** - should be loaded from environment variables in production
- **String-built JSON** - a library like Gson or Jackson should be used for safety
- **No URL decoding** - query params with encoded characters (e.g. `%20`) are not decoded
- **No input size limit** - POST body size is unbounded
- **Static inner classes** - limits unit testability; handlers should be top-level classes

---

## Project Structure

```
src/
└── main/
    └── java/
        └── org/example/
            └── ServerArchitecture.java
                ├── main()              — server setup, route registration, shutdown hook
                ├── AuthFilter          — Basic Auth filter (Chain of Responsibility)
                ├── HelloHandler        — GET /hello
                ├── GreetHandler        — GET /greet
                ├── EchoHandler         — POST /echo
                ├── CachePolicy         — Cache-Control enum
                └── Utilities           — sendResponse(), parseQuery()
```

---

## Technologies

| Technology | Purpose |
|------------|---------|
| Java (JDK 11+) | Language |
| `com.sun.net.httpserver` | Built-in Java HTTP server API |
| `java.util.concurrent` | Thread pool management |
| `java.util.Base64` | Basic Auth header decoding |
| `java.util.logging` | Per-class logging |

No external dependencies.

---

## License

MIT
