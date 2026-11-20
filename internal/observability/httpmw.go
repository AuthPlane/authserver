package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// HTTPMiddleware provides observability middleware for HTTP handlers.
type HTTPMiddleware struct {
	logger  *slog.Logger
	tracer  trace.Tracer
	metrics *Metrics
}

// NewHTTPMiddleware creates a new HTTP observability middleware.
func NewHTTPMiddleware(p *Provider) *HTTPMiddleware {
	return &HTTPMiddleware{
		logger:  p.Logger,
		tracer:  p.Tracer,
		metrics: p.Metrics,
	}
}

// responseWriter wraps http.ResponseWriter to capture status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	statusCode    int
	written       int64
	headerWritten bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

// WriteHeader implements http.ResponseWriter.
func (rw *responseWriter) WriteHeader(code int) {
	if !rw.headerWritten {
		rw.statusCode = code
		rw.headerWritten = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		rw.headerWritten = true
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.written += int64(n)
	return n, err
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController compatibility.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// RequestID returns middleware that generates a unique request ID,
// stores it in context along with the caller's IP, adds X-Request-ID header,
// and creates a child logger.
func (m *HTTPMiddleware) RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get("X-Request-ID")
			if !validRequestID(reqID) {
				reqID = generateRequestID()
			}

			ctx := WithRequestID(r.Context(), reqID)
			ctx = WithClientIP(ctx, RemoteIP(r))
			childLogger := m.logger.With("request_id", reqID)
			ctx = WithLogger(ctx, childLogger)

			w.Header().Set("X-Request-ID", reqID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Tracing returns middleware that extracts propagated trace context
// and creates a server span for each request.
func (m *HTTPMiddleware) Tracing() func(http.Handler) http.Handler {
	propagator := otel.GetTextMapPropagator()
	if propagator == nil {
		propagator = propagation.TraceContext{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx, routes := withRouteHolder(ctx)

			// The route is known only after the mux has run, so the span
			// starts named by method alone and is renamed below. Naming it by
			// the raw path would give every distinct path its own span name,
			// which span-metrics pipelines turn into metric series.
			method := MethodLabel(r.Method)
			ctx, span := m.tracer.Start(ctx, method,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.method", method),
					attribute.String("http.url", TruncateForLog(r.URL.Path, maxLoggedPathBytes)),
				),
			)
			defer span.End()

			rw := newResponseWriter(w)
			inner := r.WithContext(ctx)

			// Deferred so a panicking handler still ends a span with its route
			// and a 500 (Recover, outside this middleware, writes that 500).
			completed := false
			defer func() {
				status := rw.statusCode
				if !completed {
					status = http.StatusInternalServerError
				}
				route := routes.route(inner)
				if route != unmatchedRoute {
					span.SetName(spanName(method, route))
				}
				span.SetAttributes(
					attribute.String("http.route", route),
					attribute.Int("http.status_code", status),
					attribute.Int64("http.response_size", rw.written),
				)
				// A 5xx is the server failing, so the span carries an error
				// status and shows up in trace-backend error filters and
				// service-map error rates. 4xx is the caller's fault and stays
				// Unset.
				if status >= 500 {
					span.SetStatus(codes.Error, http.StatusText(status))
				}
			}()
			next.ServeHTTP(rw, inner)
			completed = true
		})
	}
}

// Metrics returns middleware that records HTTP request count and latency.
func (m *HTTPMiddleware) Metrics() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := newResponseWriter(w)
			ctx, routes := withRouteHolder(r.Context())
			inner := r.WithContext(ctx)

			// Deferred so a panicking handler is still counted, as a 500,
			// and HTTPServerErrorRatio sees it.
			completed := false
			defer func() {
				status := rw.statusCode
				if !completed {
					status = http.StatusInternalServerError
				}
				// Hand the pattern the mux set on inner to an outer Tracing,
				// whose own request copy never sees it.
				routes.fill(inner)
				attrs := otelmetric.WithAttributes(
					attribute.String("http.method", MethodLabel(r.Method)),
					attribute.String("http.route", routes.route(inner)),
					attribute.Int("http.status_code", status),
				)
				m.metrics.HTTPRequestsTotal.Add(r.Context(), 1, attrs)
				m.metrics.HTTPRequestDuration.Record(r.Context(), time.Since(start).Seconds(), attrs)
			}()
			next.ServeHTTP(rw, inner)
			completed = true
		})
	}
}

// Logging returns middleware that logs every HTTP request with structured fields.
func (m *HTTPMiddleware) Logging() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := newResponseWriter(w)

			next.ServeHTTP(rw, r)

			duration := time.Since(start)

			level := slog.LevelInfo
			if rw.statusCode >= 500 {
				level = slog.LevelError
			} else if rw.statusCode >= 400 {
				level = slog.LevelWarn
			}

			logger := LoggerFromContext(r.Context(), m.logger)
			logger.Log(r.Context(), level, "http request",
				"method", MethodLabel(r.Method),
				"path", TruncateForLog(r.URL.Path, maxLoggedPathBytes),
				"status", rw.statusCode,
				"duration_ms", duration.Milliseconds(),
				"bytes", rw.written,
				"remote_addr", r.RemoteAddr,
				"user_agent", TruncateForLog(r.UserAgent(), maxLoggedUserAgentBytes),
			)
		})
	}
}

// Recover returns middleware that recovers from panics, logs the error, and returns 500.
func (m *HTTPMiddleware) Recover() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger := LoggerFromContext(r.Context(), m.logger)
					logger.ErrorContext(r.Context(), "panic recovered",
						"panic", fmt.Sprintf("%v", rec),
						"method", MethodLabel(r.Method),
						"path", TruncateForLog(r.URL.Path, maxLoggedPathBytes),
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// unmatchedRoute is the route label of a request no mux pattern matched: an
// unknown path (404) or one rejected before routing (431, 429). A raw path
// here would let any caller mint metric series at will.
const unmatchedRoute = "unmatched"

// routeHolder carries the matched mux pattern back up to Tracing and Metrics.
// The mux sets Pattern on the request it is handed, so a middleware between
// the observability chain and the mux that replaces the request (r.WithContext)
// would otherwise hide the route; RecordRoute writes it here instead.
//
// The pattern is atomic because a ChainBuilder may run the mux on another
// goroutine (http.TimeoutHandler) that can still be writing after the
// middleware has returned.
type routeHolder struct{ pattern atomic.Pointer[string] }

type routeHolderKey struct{}

// withRouteHolder returns ctx carrying a routeHolder, reusing one an outer
// middleware already added so Tracing and Metrics share it.
func withRouteHolder(ctx context.Context) (context.Context, *routeHolder) {
	if h, ok := ctx.Value(routeHolderKey{}).(*routeHolder); ok {
		return ctx, h
	}
	h := &routeHolder{}
	return context.WithValue(ctx, routeHolderKey{}, h), h
}

// route returns the matched pattern for the low-cardinality http.route
// label: the one RecordRoute saw, else the one the mux set on the request
// passed down, else unmatchedRoute.
func (h *routeHolder) route(passed *http.Request) string {
	if p := h.pattern.Load(); p != nil {
		return *p
	}
	if passed.Pattern != "" {
		return passed.Pattern
	}
	return unmatchedRoute
}

// fill records the pattern the mux set on passed, unless one is recorded.
func (h *routeHolder) fill(passed *http.Request) {
	if passed.Pattern != "" {
		pattern := passed.Pattern
		h.pattern.CompareAndSwap(nil, &pattern)
	}
}

// RecordRoute wraps the server's mux so the pattern it matched reaches the
// observability middleware however the request was replaced on the way down.
func RecordRoute(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r)
		if h, ok := r.Context().Value(routeHolderKey{}).(*routeHolder); ok {
			h.fill(r)
		}
	})
}

// spanName is "METHOD route", without repeating the method when the mux
// pattern already starts with it ("GET /healthz").
func spanName(method, route string) string {
	if strings.HasPrefix(route, method+" ") {
		return route
	}
	return method + " " + route
}

// otherMethod is the label for any method outside the standard set, as in the
// OpenTelemetry HTTP conventions. net/http accepts any token as a method, so
// using it raw would let a caller mint metric series and span names.
const otherMethod = "_OTHER"

// MethodLabel returns r.Method if it is a standard HTTP method, else "_OTHER".
// Use it wherever the method reaches a metric label, span or log line.
func MethodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return method
	default:
		return otherMethod
	}
}

// Caller-controlled request fields are cut to these sizes in logs and span
// attributes, so one request cannot write tens of KB into either.
const (
	maxLoggedPathBytes      = 256
	maxLoggedUserAgentBytes = 256
	maxRequestIDBytes       = 128
)

// TruncateForLog cuts s to at most n bytes, marking the cut with "...".
func TruncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Back up to a rune boundary so the cut never splits a UTF-8 sequence.
	cut := n
	for cut > 0 && cut > n-utf8.UTFMax && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// validRequestID reports whether an inbound X-Request-ID may be adopted: at
// most maxRequestIDBytes of printable ASCII other than space, '"' and '\'.
// That keeps the IDs proxies send (UUIDs, "uuid#counter", base64) while
// anything longer or odd is replaced by a generated ID, because the value is
// echoed and bound to every log line.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDBytes {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !requestIDByte(id[i]) {
			return false
		}
	}
	return true
}

// RemoteIP returns the IP of the connection the request arrived on.
// It reads RemoteAddr only; X-Forwarded-For is ignored so a caller cannot
// choose the address the server attributes it to.
func RemoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// generateRequestID creates a hex-encoded random request ID.
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

func requestIDByte(c byte) bool {
	return c > ' ' && c < 0x7f && c != '"' && c != '\\'
}
