# Dockerfile for the Go Auth Service (Revised for Robustness)
# Location: ./auth/Dockerfile
# Build context is the parent directory './auth'

# --- Stage 1: Build ---
# Use a Go version compatible with your go.mod file (e.g., >= 1.24)
FROM golang:1.24-alpine AS builder

# Set the working directory inside the build container
WORKDIR /app

# Copy go.mod and go.sum from the './src' directory in the build context
# Ensure './auth/src/go.mod' contains the 'replace' directive:
# replace github.com/opengovern/opensecurity/services/auth => ./auth
COPY src/go.mod src/go.sum ./

# Download dependencies (respects the 'replace' directive)
RUN go mod download
# Tidy ensures consistency and processes the replace directive fully
RUN go mod tidy

# Copy the *entire content* of the './src' directory from the build context
# This includes main.go, the 'auth' subdirectory (your fork), etc.
COPY src/ ./

# Build the Go application from the WORKDIR (/app, where main.go is)
# Output the binary to '/app/go-auth-server' (a non-conflicting name)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/go-auth-server .

# --- Stage 2: Run ---
# Use a minimal base image like Alpine for the final container
FROM alpine:latest

WORKDIR /app

# Copy only the compiled binary from the 'builder' stage using its specific name
COPY --from=builder /app/go-auth-server /app/go-auth-server

# Copy any necessary runtime files (configs, templates, static assets) if needed.
# Adjust the source path if they are within the 'src' directory in the context.
# Example: If you have './src/config.prod.yml' needed at runtime:
# COPY --from=builder /app/config.prod.yml ./config.yml

# Expose the internal port the Go application listens on (e.g., 8000)
EXPOSE 8000

# Set the entrypoint to run the compiled binary using its specific name
ENTRYPOINT ["/app/go-auth-server"]