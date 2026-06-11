# Multi-stage build for the tier-04 agent: compile the Go binary in a builder
# image, then ship it in a distroless image so the runtime container has no
# shell, no package manager, and a minimal attack surface.
#
# In practice the tier-04 agent typically runs on the host via `go run ./`
# (the verify script does exactly this) so the operator can hand-edit
# subject_token / scopes between runs. This Dockerfile is the reference
# packaging for when you ship the same agent as a long-running MCP server
# component.

FROM golang:1.25-alpine AS builder

WORKDIR /src

# Cache the module download as its own layer.
COPY go.mod ./
RUN go mod download

COPY main.go ./
# CGO_ENABLED=0 produces a statically linked binary so distroless/static works.
RUN CGO_ENABLED=0 go build -o /out/broker-agent ./

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/broker-agent /usr/local/bin/broker-agent

ENTRYPOINT ["/usr/local/bin/broker-agent"]
