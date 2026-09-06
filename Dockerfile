# ==============================================================================
# Build Stage — assembles a custom Caddy binary with the Hansestack plugin
# baked in via xcaddy.
# ==============================================================================
# BUILDPLATFORM = platform of the build host (e.g. linux/arm64 on Apple Silicon)
# TARGETPLATFORM / TARGETARCH / TARGETOS = platform we're building FOR
FROM --platform=$BUILDPLATFORM caddy:2-builder-alpine AS builder

WORKDIR /build

# Copy the plugin source so that xcaddy can build against the working tree
# instead of a published tag. This is the correct approach for local/CI
# builds; replace the "--with ...=." line below with a pinned version
# (e.g. --with github.com/hansestack/caddy-hansestack@vX.Y.Z) once the
# plugin is tagged and published.
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} xcaddy build \
    --with github.com/hansestack/caddy-hansestack=.

# ==============================================================================
# Final Stage
# ==============================================================================
FROM --platform=$TARGETPLATFORM caddy:2-alpine

COPY --from=builder /build/caddy /usr/bin/caddy

# The official caddy:2-alpine image already ships ca-certificates, tzdata,
# a working entrypoint and CMD that reads /etc/caddy/Caddyfile — no further
# customization is required here.
