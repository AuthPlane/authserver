# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
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
