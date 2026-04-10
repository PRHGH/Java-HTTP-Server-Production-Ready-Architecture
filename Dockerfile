# =========================
# Stage 1: Build
# =========================
FROM maven:3.9.9-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy everything first (simpler + avoids confusion)
COPY . .

# Build project
RUN mvn clean package -DskipTests

# Show output (for debugging)
RUN ls -l target

# =========================
# Stage 2: Runtime
# =========================
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copy ANY jar produced
COPY --from=builder /build/target/*-shaded.jar app.jar

COPY keystore.jks keystore.jks

EXPOSE 8443

CMD ["java", "-jar", "app.jar"]