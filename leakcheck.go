// Package caddyhansestack implements the official Hansestack Enterprise
// Caddy plugin: a k-anonymity password leak-check middleware that inspects
// login requests, asks the Hansestack Leak-Check API whether the submitted
// password appears in a known breach corpus, and enriches the request or
// response with the result — without requiring any change to the backend
// application.
//
// # Fail-Open
//
// The Hansestack Leak-Check API is a supplementary security signal, never a
// single point of failure. The underlying hansestack-go client already fails
// open by default (timeouts, rate limiting, and upstream faults are reported
// as "not leaked" with a nil error). This middleware additionally treats any
// non-nil error defensively as "safe, proceed": it is only ever reachable if
// the library were reconfigured to fail closed, which this plugin never
// does. A request is only ever blocked in mode "block", and only when the
// API affirmatively reports leaked == true.
package caddyhansestack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hansestack/hansestack-go/leakcheck"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
)

func init() {
	caddy.RegisterModule(Middleware{})
}

// Supported operation modes for the middleware. See the Caddyfile docs in
// README.md for a full description of each mode's semantics.
const (
	ModeEnrichRequest  = "enrich_request"
	ModeEnrichResponse = "enrich_response"
	ModeBlock          = "block"
)

// Defaults mirrored 1:1 in caddyfile.go and used whenever the Caddyfile (or
// JSON config) omits the corresponding field.
const (
	defaultMode          = ModeEnrichRequest
	defaultPasswordField = "password"
	defaultHeaderLeaked  = "X-Hansestack-Leaked"
	defaultHeaderCount   = "X-Hansestack-Leak-Count"
	defaultBlockStatus   = http.StatusUnauthorized

	// maxBodyBytes bounds how much of the request body the middleware will
	// ever read while looking for the password field. This protects against
	// memory-exhaustion / slow-body DoS attempts; it does not affect the
	// bytes forwarded to the backend, since the original (limited) body is
	// restored verbatim regardless of whether the limit was hit.
	maxBodyBytes = 1 << 20 // 1 MiB
)

// passwordChecker is the subset of *leakcheck.Client this middleware depends
// on. It exists so that leakcheck_test.go can substitute a fake without
// spinning up a real HTTP server behind the unexported base-URL override of
// the hansestack-go client.
type passwordChecker interface {
	CheckPassword(ctx context.Context, password string) (leaked bool, count int, err error)
}

// Middleware implements the "hansestack leakcheck" Caddyfile directive as a
// Caddy HTTP middleware module (http.handlers.hansestack).
type Middleware struct {
	// APIKey is the Hansestack API key used to authenticate against the
	// Leak-Check API. Required.
	APIKey string `json:"api_key,omitempty"`

	// Mode selects one of "enrich_request", "enrich_response", or "block".
	// Defaults to "enrich_request".
	Mode string `json:"mode,omitempty"`

	// PasswordField is the JSON key or form field name that carries the
	// plaintext password in the request body. Defaults to "password".
	PasswordField string `json:"password_field,omitempty"`

	// HeaderLeaked is the response/request header name set to "true" or
	// "false" once the check has completed. Defaults to
	// "X-Hansestack-Leaked".
	HeaderLeaked string `json:"header_leaked,omitempty"`

	// HeaderCount is the response/request header name set to the number of
	// breaches the password was found in. Defaults to
	// "X-Hansestack-Leak-Count".
	HeaderCount string `json:"header_count,omitempty"`

	// BlockStatus is the HTTP status code written when mode is "block" and
	// a leak is confirmed. Defaults to 401.
	BlockStatus int `json:"block_status,omitempty"`

	logger  *zap.Logger
	checker passwordChecker
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hansestack",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision sets up the middleware: it applies defaults, wires up the
// zap logger provided by Caddy, bridges it into the slog.Logger required by
// hansestack-go, and constructs the Leak-Check API client.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	if m.Mode == "" {
		m.Mode = defaultMode
	}
	if m.PasswordField == "" {
		m.PasswordField = defaultPasswordField
	}
	if m.HeaderLeaked == "" {
		m.HeaderLeaked = defaultHeaderLeaked
	}
	if m.HeaderCount == "" {
		m.HeaderCount = defaultHeaderCount
	}
	if m.BlockStatus == 0 {
		m.BlockStatus = defaultBlockStatus
	}

	// Bridge Caddy's native *zap.Logger into the *slog.Logger expected by
	// hansestack-go, so that library-internal WARN/ERROR diagnostics (rate
	// limiting, timeouts, bad API keys, ...) show up in Caddy's own log
	// output instead of being discarded.
	slogLogger := slog.New(zapslog.NewHandler(m.logger.Core(), zapslog.WithName("hansestack.leakcheck")))

	m.checker = leakcheck.NewClient(m.APIKey, leakcheck.WithLogger(slogLogger))

	return nil
}

// Validate ensures the configuration is usable.
func (m *Middleware) Validate() error {
	if m.APIKey == "" {
		return fmt.Errorf("hansestack: api_key must be set")
	}

	switch m.Mode {
	case ModeEnrichRequest, ModeEnrichResponse, ModeBlock:
	default:
		return fmt.Errorf("hansestack: invalid mode %q (must be one of %q, %q, %q)",
			m.Mode, ModeEnrichRequest, ModeEnrichResponse, ModeBlock)
	}

	if m.BlockStatus < 100 || m.BlockStatus > 599 {
		return fmt.Errorf("hansestack: invalid block_status %d", m.BlockStatus)
	}

	return nil
}

// leakResult carries the outcome of a single CheckPassword call between the
// modes below and the goroutine used by enrich_response.
type leakResult struct {
	leaked bool
	count  int
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	password, found, err := extractPassword(r, m.PasswordField)
	if err != nil {
		// Malformed body, unsupported content type, oversized payload, or no
		// password field present: never block the request on account of
		// this. Log for operators and let the backend handle it as it would
		// without this plugin installed.
		m.logger.Warn("hansestack: could not extract password from request, skipping check",
			zap.Error(err),
			zap.String("path", r.URL.Path),
		)
		return next.ServeHTTP(w, r)
	}
	if !found {
		return next.ServeHTTP(w, r)
	}

	switch m.Mode {
	case ModeBlock:
		return m.serveBlock(w, r, next, password)
	case ModeEnrichResponse:
		return m.serveEnrichResponse(w, r, next, password)
	default: // ModeEnrichRequest
		return m.serveEnrichRequest(w, r, next, password)
	}
}

// check performs the leak lookup and always fails open: any error returned
// by the checker is logged and treated as "not leaked", exactly as mandated
// by the hansestack-go fail-open contract. The request's context is passed
// through unmodified.
func (m *Middleware) check(r *http.Request, password string) leakResult {
	leaked, count, err := m.checker.CheckPassword(r.Context(), password)
	if err != nil {
		// Only reachable if the client were configured with WithFailClose,
		// which this middleware never does. Handled defensively anyway per
		// the hansestack-go integration contract: log and proceed as if the
		// password were not leaked. Never turn this into a 5xx.
		m.logger.Error("hansestack: leak check failed, failing open",
			zap.Error(err),
			zap.String("path", r.URL.Path),
		)

		return leakResult{leaked: false, count: 0}
	}

	return leakResult{leaked: leaked, count: count}
}

// setHeaders writes the enrichment headers into the given header map.
func (m *Middleware) setHeaders(h http.Header, res leakResult) {
	if res.leaked {
		h.Set(m.HeaderLeaked, "true")
	} else {
		h.Set(m.HeaderLeaked, "false")
	}
	h.Set(m.HeaderCount, fmt.Sprintf("%d", res.count))
}

// serveEnrichRequest performs a synchronous check and injects the result as
// request headers before invoking the next handler in the chain.
func (m *Middleware) serveEnrichRequest(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, password string) error {
	res := m.check(r, password)
	m.setHeaders(r.Header, res)

	return next.ServeHTTP(w, r)
}

// serveBlock performs a synchronous check. If, and only if, the API
// affirmatively confirms a leak, the request is short-circuited with
// block_status and a generic JSON error body; the backend is never invoked
// in that case. In every other case (not leaked, or the check failed open)
// the request proceeds unchanged.
func (m *Middleware) serveBlock(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, password string) error {
	res := m.check(r, password)

	if !res.leaked {
		return next.ServeHTTP(w, r)
	}

	m.logger.Info("hansestack: blocking request, password found in known breaches",
		zap.Int("breach_count", res.count),
		zap.String("path", r.URL.Path),
	)

	m.setHeaders(w.Header(), res)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(m.BlockStatus)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":      "password_leaked",
		"message":    "The submitted password was found in a known data breach.",
		"leak_count": res.count,
	})

	return nil
}

// serveEnrichResponse starts the leak check concurrently with the downstream
// handler chain. The response is wrapped so that the first call to
// WriteHeader blocks until the check has completed, at which point the
// enrichment headers are injected into the real response before the
// original status code is written.
func (m *Middleware) serveEnrichResponse(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler, password string) error {
	resultCh := make(chan leakResult, 1)

	go func() {
		resultCh <- m.check(r, password)
	}()

	rw := &enrichingResponseWriter{
		ResponseWriter: w,
		mw:             m,
		resultCh:       resultCh,
	}

	err := next.ServeHTTP(rw, r)

	// If the downstream handler never wrote a response (e.g. it only wrote a
	// body via an implicit 200, or nothing at all), make sure the headers
	// are still applied and the wrapper's bookkeeping is finalized.
	rw.ensureHeadersApplied()

	return err
}

// enrichingResponseWriter wraps http.ResponseWriter so that the Hansestack
// enrichment headers can be injected exactly once, immediately before
// headers are actually sent, blocking only long enough for the concurrent
// leak check (bounded by the Hansestack client's own timeout) to finish.
type enrichingResponseWriter struct {
	http.ResponseWriter

	mw       *Middleware
	resultCh chan leakResult

	once sync.Once
}

// applyResult blocks until the leak-check goroutine has produced a result,
// then writes the enrichment headers. It is safe to call multiple times;
// only the first call has any effect.
func (rw *enrichingResponseWriter) applyResult() {
	rw.once.Do(func() {
		res := <-rw.resultCh
		rw.mw.setHeaders(rw.ResponseWriter.Header(), res)
	})
}

// WriteHeader blocks until the leak-check result is available, applies the
// enrichment headers, and then forwards to the wrapped ResponseWriter.
func (rw *enrichingResponseWriter) WriteHeader(statusCode int) {
	rw.applyResult()
	rw.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures headers (and therefore the enrichment) are applied even if
// the downstream handler calls Write directly without an explicit
// WriteHeader, which implicitly sends a 200 OK.
func (rw *enrichingResponseWriter) Write(b []byte) (int, error) {
	rw.applyResult()
	return rw.ResponseWriter.Write(b)
}

// ensureHeadersApplied is called after the downstream handler has returned,
// to guarantee the headers are applied even for handlers that never call
// Write or WriteHeader at all.
func (rw *enrichingResponseWriter) ensureHeadersApplied() {
	rw.applyResult()
}

// extractPassword reads the request body (bounded to maxBodyBytes),
// extracts the configured password field from a JSON or form-encoded
// payload, and restores r.Body so the real backend can still read it in
// full. It returns found == false (with a nil error) whenever the content
// type is unsupported or the field is simply absent — both are treated as
// "nothing to check", never as a hard failure.
func extractPassword(r *http.Request, field string) (password string, found bool, err error) {
	if r.Body == nil || r.Body == http.NoBody {
		return "", false, nil
	}

	// Read at most maxBodyBytes+1 bytes to decide, without buffering the
	// rest of a possibly much larger body in memory, whether the payload
	// fits within the limit at all.
	prefix, readErr := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if readErr != nil {
		// r.Body is unreadable; restore what we have and give up quietly.
		r.Body = io.NopCloser(bytes.NewReader(prefix))
		return "", false, fmt.Errorf("reading request body: %w", readErr)
	}

	if len(prefix) > maxBodyBytes {
		// Oversized body: never buffer the remainder, and never attempt to
		// parse it. Reassemble the original, untruncated stream (the bytes
		// already read, followed by whatever is left of r.Body) so the real
		// backend still receives the full payload unmodified.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
		return "", false, fmt.Errorf("request body exceeds %d byte limit", maxBodyBytes)
	}

	// The body fit entirely within the limit, so prefix already contains it
	// in full; restore it verbatim for the real backend.
	r.Body = io.NopCloser(bytes.NewReader(prefix))
	bodyBytes := prefix

	contentType := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(contentType)
	if parseErr != nil {
		// No/unparseable Content-Type: not our business, skip silently.
		return "", false, nil
	}

	switch mediaType {
	case "application/json":
		return extractPasswordFromJSON(bodyBytes, field)
	case "application/x-www-form-urlencoded":
		return extractPasswordFromForm(bodyBytes, field)
	default:
		return "", false, nil
	}
}

func extractPasswordFromJSON(body []byte, field string) (string, bool, error) {
	if len(body) == 0 {
		return "", false, nil
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", false, fmt.Errorf("decoding JSON body: %w", err)
	}

	raw, ok := payload[field]
	if !ok {
		return "", false, nil
	}

	password, ok := raw.(string)
	if !ok || password == "" {
		return "", false, nil
	}

	return password, true, nil
}

func extractPasswordFromForm(body []byte, field string) (string, bool, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false, fmt.Errorf("decoding form body: %w", err)
	}

	password := values.Get(field)
	if password == "" {
		return "", false, nil
	}

	return password, true, nil
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
