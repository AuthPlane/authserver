FROM golang:1.27-alpine AS builder

WORKDIR /src

COPY go.mod go.sum* ./
RUN go mod download

COPY main.go ./
RUN CGO_ENABLED=0 go build -o /out/mcp-server ./

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/mcp-server /usr/local/bin/mcp-server

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/mcp-server"]
