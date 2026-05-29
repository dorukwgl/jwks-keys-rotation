#
# JWKS Server — build & run with Liberica hardened JRE
# ======================================================
# Build:   docker build -t jwks .
# Run:     docker run -p 41518:41518 -v ./data/jwks:/var/lib/jwks jwks
#

# ── Stage 1: Build ────────────────────────────────────────────────────────────
# Uses Maven with Eclipse Temurin JDK 25 to compile the Micronaut fat JAR
FROM maven:3.9-eclipse-temurin-25 AS builder

WORKDIR /build

# Copy project files
COPY pom.xml .
COPY src src

# Build the application JAR (AOT is disabled by default)
RUN mvn package -DskipTests

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Liberica hardened JRE 25 — CDS enabled, non-root user, glibc
# Minimal attack surface, production-hardened JVM runtime
FROM bellsoft/hardened-liberica-runtime-container:jre-25-cds-nonroot-glibc

WORKDIR /app

# Copy the fat JAR from the builder stage
COPY --from=builder /build/target/jwks-0.1.jar app.jar

# Application port
EXPOSE 41518

# Container-aware heap sizing — let the JVM adapt to container memory limits
# CDS is already enabled in the base image for faster startup
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75.0"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
