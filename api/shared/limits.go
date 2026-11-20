package shared

import (
	"cmp"
	"log/slog"
	"net/http"
	"slices"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
)

// MaxRequestHeaderBytes caps the request line plus all request headers on the
// public and admin listeners. Without a cap Go's default of 1 MB applies, and
// every header the server parses as a JWS (a DPoP proof, a bearer token) is
// attacker-sized input to the JOSE library before any authentication has
// happened.
//
// RequestHeaderLimit enforces it inside the middleware chain, so a rejection
// is logged, traced and counted in the HTTP server metrics with status 431
// like any other response. 32 KiB matches nginx's default header budget
// (large_client_header_buffers 4 x 8 KiB). Real traffic sits far below it: a
// DPoP proof with a 4096-bit RSA key is about 2.3 KB, an access token a few
// KB, and the session cookie well under 1 KB.
//
// This is a hard-coded constant on purpose. Making it configurable is a
// contract change (a new config key and env var) and belongs to a minor
// release, not a patch.
const MaxRequestHeaderBytes = 32 << 10

// ServerMaxHeaderBytes is http.Server.MaxHeaderBytes on both listeners: the
// backstop for headers too large to read at all. net/http answers those with
// 431 itself, before any handler runs, so they reach no AuthPlane log or
// metric; Go adds 4 KiB of slack, so that happens above about 68 KiB.
// Setting the backstop at twice MaxRequestHeaderBytes keeps the requests that
// common proxies pass on (Envoy and Istio allow 60 KiB, cloud load balancers
// about 64 KB) inside the range RequestHeaderLimit sees and reports.
const ServerMaxHeaderBytes = 2 * MaxRequestHeaderBytes

// The rejection warning is built from caller-chosen fields; these bound
// what one request can write into the log.
const (
	maxLoggedPathBytes       = 256
	maxLoggedHeaderNameBytes = 64
)

// requestHeaderLimitBody matches the body net/http writes for its own 431,
// so a client sees the same response whichever layer rejected it.
const requestHeaderLimitBody = "431 Request Header Fields Too Large"

// RequestHeaderLimit rejects a request whose request line and headers add up
// to more than MaxRequestHeaderBytes with 431, before any handler reads them.
// It logs a warning with the size and the largest header names (never their
// values) and marks the request span. Place it inside the logging, metrics
// and tracing middleware, so the 431 is recorded like other responses.
func RequestHeaderLimit(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			size := RequestHeaderBytes(r)
			if size <= MaxRequestHeaderBytes {
				next.ServeHTTP(w, r)
				return
			}
			largest := largestHeaders(r, 3)
			if logger != nil {
				logger.WarnContext(r.Context(), "request headers too large",
					"header_bytes", size,
					"limit_bytes", MaxRequestHeaderBytes,
					"method", observability.MethodLabel(r.Method),
					"path", observability.TruncateForLog(r.URL.Path, maxLoggedPathBytes),
					"path_bytes", len(r.URL.Path),
					"largest_headers", largest,
				)
			}
			span := trace.SpanFromContext(r.Context())
			span.AddEvent("request headers too large", trace.WithAttributes(
				attribute.Int("http.request.header_bytes", size),
				attribute.Int("http.request.header_limit_bytes", MaxRequestHeaderBytes),
			))
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
			_, _ = w.Write([]byte(requestHeaderLimitBody))
		})
	}
}

// RequestHeaderBytes approximates the size of the request line and header
// block as sent in HTTP/1.1 ("Name: value\r\n" per value, Host included).
// For HTTP/2 it is the same sum over the decoded header fields.
func RequestHeaderBytes(r *http.Request) int {
	n := len(r.Method) + 1 + len(r.RequestURI) + 1 + len(r.Proto) + 2
	if r.Host != "" {
		n += len("Host: ") + len(r.Host) + 2
	}
	for name, values := range r.Header {
		for _, v := range values {
			n += len(name) + 2 + len(v) + 2
		}
	}
	return n + 2
}

// largestHeaders returns "Name=bytes" for the k largest header names.
func largestHeaders(r *http.Request, k int) []string {
	type hs struct {
		name string
		size int
	}
	sizes := make([]hs, 0, len(r.Header))
	for name, values := range r.Header {
		total := 0
		for _, v := range values {
			total += len(name) + 2 + len(v) + 2
		}
		sizes = append(sizes, hs{name, total})
	}
	slices.SortFunc(sizes, func(a, b hs) int {
		return cmp.Or(cmp.Compare(b.size, a.size), cmp.Compare(a.name, b.name))
	})
	out := make([]string, 0, k)
	for _, s := range sizes[:min(k, len(sizes))] {
		out = append(out, observability.TruncateForLog(s.name, maxLoggedHeaderNameBytes)+"="+strconv.Itoa(s.size))
	}
	return out
}
