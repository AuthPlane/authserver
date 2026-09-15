# Build stage
#
# --platform=$BUILDPLATFORM runs the compiler natively and cross-compiles for
# the image's target platform, which BuildKit supplies as TARGETARCH. Without
# it the build stage itself runs emulated on a cross-arch host.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETARCH

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# GOARCH follows the image's target platform. It was hardcoded to amd64,
# which on an arm64 host produced an x86-64 binary inside an arm64-tagged
# image; Docker Desktop then ran it under Rosetta, where the Go runtime hits
# spurious "unaligned arguments" fatal errors under load. The published
# multi-arch images are built by build/Dockerfile.goreleaser and were never
# affected; this file is the local, quickstart, kind and CI-scan path.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev}" \
    -o /app/authserver \
    ./cmd/authserver

# Create empty data directories owned by nonroot (UID 65534).
RUN mkdir -p /data/keys && chown -R 65534:65534 /data

# Final stage — distroless, non-root
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/authserver /authserver
COPY --from=builder --chown=nonroot:nonroot /data /data

USER nonroot:nonroot
WORKDIR /data

EXPOSE 9000 9001

ENTRYPOINT ["/authserver"]
CMD ["serve"]
