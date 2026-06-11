# Multi-stage build: compile the Go binary in a builder image, then ship it
# in a distroless image so the runtime container has no shell, no package
# manager, and a minimal attack surface.

FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache the module download as its own layer.
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
# CGO_ENABLED=0 produces a statically linked binary so distroless/static works.
RUN CGO_ENABLED=0 go build -o /out/mcp-server ./

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/mcp-server /usr/local/bin/mcp-server

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/mcp-server"]
