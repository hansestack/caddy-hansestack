package caddyhansestack

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/hansestack/hansestack-go/leakcheck"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

// fakeChecker is a test double for passwordChecker. It records the last
// context and password it was called with, and returns whatever the test
// configured, optionally with a delay to exercise concurrency.
type fakeChecker struct {
	leaked bool
	count  int
	err    error
	delay  time.Duration

	// outcome overrides the Result.Outcome returned on the success path,
	// e.g. to simulate a fail-open skip (timeout, rate limit, circuit
	// open, ...) that still returns a nil error. Defaults to
	// leakcheck.OutcomeChecked (the zero value, leakcheck.OutcomeUnknown,
	// is never a real outcome, so it is safe to treat as "unset").
	outcome leakcheck.Outcome

	mu       sync.Mutex
	calls    int
	lastCtx  context.Context
	lastPass string
}

func (f *fakeChecker) CheckPassword(ctx context.Context, password string) (leakcheck.Result, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	f.mu.Lock()
	f.calls++
	f.lastCtx = ctx
	f.lastPass = password
	f.mu.Unlock()

	if f.err != nil {
		return leakcheck.Result{}, f.err
	}

	outcome := f.outcome
	if outcome == leakcheck.OutcomeUnknown {
		outcome = leakcheck.OutcomeChecked
	}

	return leakcheck.Result{
		Leaked:  f.leaked,
		Count:   f.count,
		Outcome: outcome,
	}, nil
}

func newTestMiddleware(checker passwordChecker) *Middleware {
	m := &Middleware{
		Mode:          ModeEnrichRequest,
		PasswordField: defaultPasswordField,
		HeaderLeaked:  defaultHeaderLeaked,
		HeaderCount:   defaultHeaderCount,
		BlockStatus:   defaultBlockStatus,
		logger:        zap.NewNop(),
		checker:       checker,
	}
	return m
}

// nextHandler builds a caddyhttp.Handler (the type ServeHTTP's third
// argument requires) from a plain http.HandlerFunc.
func nextHandler(fn http.HandlerFunc) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fn(w, r)
		return nil
	})
}

func jsonRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func formRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// TestExtractPassword table-drives the body-parsing logic: JSON and form
// extraction, the 1 MiB body limit, unsupported content types, and body
// restoration for the downstream handler.
func TestExtractPassword(t *testing.T) {
	tests := []struct {
		name      string
		req       func(t *testing.T) *http.Request
		field     string
		wantPass  string
		wantFound bool
		wantErr   bool
	}{
		{
			name:      "json body with password field",
			req:       func(t *testing.T) *http.Request { return jsonRequest(t, `{"email":"a@b.de","password":"hunter2"}`) },
			field:     "password",
			wantPass:  "hunter2",
			wantFound: true,
		},
		{
			name:      "json body missing password field",
			req:       func(t *testing.T) *http.Request { return jsonRequest(t, `{"email":"a@b.de"}`) },
			field:     "password",
			wantFound: false,
		},
		{
			name:      "json body with empty password",
			req:       func(t *testing.T) *http.Request { return jsonRequest(t, `{"password":""}`) },
			field:     "password",
			wantFound: false,
		},
		{
			name:      "json body with non-string password",
			req:       func(t *testing.T) *http.Request { return jsonRequest(t, `{"password":12345}`) },
			field:     "password",
			wantFound: false,
		},
		{
			name:      "malformed json body fails open",
			req:       func(t *testing.T) *http.Request { return jsonRequest(t, `{not-json`) },
			field:     "password",
			wantFound: false,
			wantErr:   true,
		},
		{
			name:      "form body with password field",
			req:       func(t *testing.T) *http.Request { return formRequest(t, "email=a%40b.de&password=hunter2") },
			field:     "password",
			wantPass:  "hunter2",
			wantFound: true,
		},
		{
			name:      "form body missing password field",
			req:       func(t *testing.T) *http.Request { return formRequest(t, "email=a%40b.de") },
			field:     "password",
			wantFound: false,
		},
		{
			name:      "custom password field name",
			req:       func(t *testing.T) *http.Request { return jsonRequest(t, `{"pwd":"hunter2"}`) },
			field:     "pwd",
			wantPass:  "hunter2",
			wantFound: true,
		},
		{
			name: "unsupported content type is skipped, not an error",
			req: func(t *testing.T) *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`<xml/>`))
				r.Header.Set("Content-Type", "application/xml")
				return r
			},
			field:     "password",
			wantFound: false,
		},
		{
			name: "missing content type is skipped, not an error",
			req: func(t *testing.T) *http.Request {
				return httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"password":"hunter2"}`))
			},
			field:     "password",
			wantFound: false,
		},
		{
			name:      "empty body is skipped, not an error",
			req:       func(t *testing.T) *http.Request { return jsonRequest(t, ``) },
			field:     "password",
			wantFound: false,
		},
		{
			name: "body exceeding 1 MiB limit fails open with error",
			req: func(t *testing.T) *http.Request {
				huge := `{"password":"` + strings.Repeat("a", maxBodyBytes+10) + `"}`
				return jsonRequest(t, huge)
			},
			field:     "password",
			wantFound: false,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.req(t)
			originalBody, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(originalBody))

			pass, found, err := extractPassword(r, tc.field)

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if pass != tc.wantPass {
				t.Fatalf("password = %q, want %q", pass, tc.wantPass)
			}

			// Body must always be restored verbatim for the real backend,
			// regardless of whether parsing succeeded.
			restored, _ := io.ReadAll(r.Body)
			if !bytes.Equal(restored, originalBody) {
				t.Fatalf("body was not restored verbatim: got %d bytes, want %d bytes", len(restored), len(originalBody))
			}
		})
	}
}

// explodingReader panics on any Read call. It is used to assert that
// extractPassword never even attempts to read the body for content types it
// doesn't understand — not "reads and discards", but genuinely never
// touches io.Reader at all.
type explodingReader struct{}

func (explodingReader) Read([]byte) (int, error) {
	panic("body must not be read for an unsupported content type")
}

func (explodingReader) Close() error { return nil }

// TestExtractPassword_UnsupportedContentTypeNeverReadsBody is a regression
// test for multipart/form-data (file uploads) and other unsupported content
// types: the body must never be read at all, not merely "read and
// restored". Large uploads must never be buffered into memory just because
// this plugin sits in front of the endpoint.
func TestExtractPassword_UnsupportedContentTypeNeverReadsBody(t *testing.T) {
	tests := []string{
		"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
		"application/octet-stream",
		"text/plain",
	}

	for _, ct := range tests {
		t.Run(ct, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", nil)
			r.Body = explodingReader{}
			r.Header.Set("Content-Type", ct)

			_, found, err := extractPassword(r, "password")
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if found {
				t.Fatalf("found = true, want false")
			}
			// If extractPassword had called Read, explodingReader would
			// have panicked before we got here.
			if r.Body != (explodingReader{}) {
				t.Fatalf("r.Body was replaced even though it should have been left untouched")
			}
		})
	}
}

// TestExtractPassword_NilBody ensures a request with no body at all does not
// panic and is treated as "nothing to check".
func TestExtractPassword_NilBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	r.Body = nil

	_, found, err := extractPassword(r, "password")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if found {
		t.Fatalf("found = true, want false for nil body")
	}
}

// TestServeHTTP_EnrichRequest verifies the synchronous enrich_request mode:
// the check runs before next.ServeHTTP, and the result is injected into the
// request headers the backend sees.
func TestServeHTTP_EnrichRequest(t *testing.T) {
	tests := []struct {
		name       string
		checker    *fakeChecker
		wantLeaked string
		wantCount  string
	}{
		{
			name:       "not leaked",
			checker:    &fakeChecker{leaked: false, count: 0},
			wantLeaked: "false",
			wantCount:  "0",
		},
		{
			name:       "leaked",
			checker:    &fakeChecker{leaked: true, count: 42},
			wantLeaked: "true",
			wantCount:  "42",
		},
		{
			name:       "checker errors: fails open, reported as not leaked",
			checker:    &fakeChecker{err: errors.New("boom")},
			wantLeaked: "false",
			wantCount:  "0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMiddleware(tc.checker)
			m.Mode = ModeEnrichRequest

			r := jsonRequest(t, `{"password":"hunter2"}`)
			w := httptest.NewRecorder()

			var seenLeaked, seenCount string
			nextCalled := false
			next := nextHandler(func(_ http.ResponseWriter, r *http.Request) {
				nextCalled = true
				seenLeaked = r.Header.Get(defaultHeaderLeaked)
				seenCount = r.Header.Get(defaultHeaderCount)
			})

			if err := m.ServeHTTP(w, r, next); err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}
			if !nextCalled {
				t.Fatal("next handler was not called")
			}
			if seenLeaked != tc.wantLeaked {
				t.Errorf("request header leaked = %q, want %q", seenLeaked, tc.wantLeaked)
			}
			if seenCount != tc.wantCount {
				t.Errorf("request header count = %q, want %q", seenCount, tc.wantCount)
			}
			if tc.checker.calls != 1 {
				t.Errorf("checker called %d times, want 1", tc.checker.calls)
			}
		})
	}
}

// TestServeHTTP_Block verifies mode=block: only a confirmed leak
// short-circuits the chain; everything else (not leaked, or a fail-open
// error) must reach the backend unchanged.
func TestServeHTTP_Block(t *testing.T) {
	t.Run("leaked password is blocked with block_status and next is never called", func(t *testing.T) {
		checker := &fakeChecker{leaked: true, count: 5}
		m := newTestMiddleware(checker)
		m.Mode = ModeBlock
		m.BlockStatus = http.StatusUnauthorized

		r := jsonRequest(t, `{"password":"hunter2"}`)
		w := httptest.NewRecorder()

		nextCalled := false
		next := nextHandler(func(http.ResponseWriter, *http.Request) { nextCalled = true })

		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if nextCalled {
			t.Fatal("next handler must not be called when a leak is confirmed")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
		if got := w.Header().Get(defaultHeaderLeaked); got != "true" {
			t.Errorf("response header leaked = %q, want %q", got, "true")
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q, want JSON", ct)
		}
		if w.Body.Len() == 0 {
			t.Error("expected a JSON error body, got none")
		}
	})

	t.Run("not leaked password reaches the backend", func(t *testing.T) {
		checker := &fakeChecker{leaked: false}
		m := newTestMiddleware(checker)
		m.Mode = ModeBlock

		r := jsonRequest(t, `{"password":"hunter2"}`)
		w := httptest.NewRecorder()

		nextCalled := false
		next := nextHandler(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if !nextCalled {
			t.Fatal("next handler was not called")
		}
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})

	t.Run("checker error fails open: request reaches the backend, never blocked", func(t *testing.T) {
		checker := &fakeChecker{err: errors.New("upstream down")}
		m := newTestMiddleware(checker)
		m.Mode = ModeBlock

		r := jsonRequest(t, `{"password":"hunter2"}`)
		w := httptest.NewRecorder()

		nextCalled := false
		next := nextHandler(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		})

		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if !nextCalled {
			t.Fatal("next handler must be called: a failed check must fail open, never block")
		}
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200 (fail open)", w.Code)
		}
	})
}

// TestServeHTTP_EnrichResponse verifies mode=enrich_response: the check runs
// concurrently with next.ServeHTTP, and the wrapped ResponseWriter's
// WriteHeader blocks until the result is available before applying the
// enrichment headers and forwarding the real status code.
func TestServeHTTP_EnrichResponse(t *testing.T) {
	t.Run("headers are applied before the real status code is written", func(t *testing.T) {
		checker := &fakeChecker{leaked: true, count: 3, delay: 50 * time.Millisecond}
		m := newTestMiddleware(checker)
		m.Mode = ModeEnrichResponse

		r := jsonRequest(t, `{"password":"hunter2"}`)
		w := httptest.NewRecorder()

		next := nextHandler(func(w http.ResponseWriter, _ *http.Request) {
			// Simulate a real backend: write an explicit status, then a body.
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("ok"))
		})

		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}

		if w.Code != http.StatusCreated {
			t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
		}
		if got := w.Header().Get(defaultHeaderLeaked); got != "true" {
			t.Errorf("response header leaked = %q, want %q", got, "true")
		}
		if got := w.Header().Get(defaultHeaderCount); got != "3" {
			t.Errorf("response header count = %q, want %q", got, "3")
		}
		if w.Body.String() != "ok" {
			t.Errorf("body = %q, want %q", w.Body.String(), "ok")
		}
	})

	t.Run("next runs concurrently with the check, not after it", func(t *testing.T) {
		// The check is deliberately slow. In enrich_response, next.ServeHTTP
		// must be invoked immediately rather than waiting for the check.
		delay := 100 * time.Millisecond
		checker := &fakeChecker{leaked: false, delay: delay}
		m := newTestMiddleware(checker)
		m.Mode = ModeEnrichResponse

		r := jsonRequest(t, `{"password":"hunter2"}`)
		w := httptest.NewRecorder()

		var nextInvokedAt time.Duration
		start := time.Now()
		next := nextHandler(func(w http.ResponseWriter, _ *http.Request) {
			nextInvokedAt = time.Since(start)
			w.WriteHeader(http.StatusOK)
		})

		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}

		if nextInvokedAt >= delay {
			t.Errorf("next.ServeHTTP appears to have waited for the check (invoked after %v, check delay %v)", nextInvokedAt, delay)
		}
	})

	t.Run("handler that only calls Write (implicit 200) still gets enriched", func(t *testing.T) {
		checker := &fakeChecker{leaked: false}
		m := newTestMiddleware(checker)
		m.Mode = ModeEnrichResponse

		r := jsonRequest(t, `{"password":"hunter2"}`)
		w := httptest.NewRecorder()

		next := nextHandler(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("implicit-200"))
		})

		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if got := w.Header().Get(defaultHeaderLeaked); got != "false" {
			t.Errorf("response header leaked = %q, want %q", got, "false")
		}
	})

	t.Run("handler that writes nothing at all still gets enriched", func(t *testing.T) {
		checker := &fakeChecker{leaked: true, count: 1}
		m := newTestMiddleware(checker)
		m.Mode = ModeEnrichResponse

		r := jsonRequest(t, `{"password":"hunter2"}`)
		w := httptest.NewRecorder()

		next := nextHandler(func(http.ResponseWriter, *http.Request) {})

		if err := m.ServeHTTP(w, r, next); err != nil {
			t.Fatalf("ServeHTTP returned error: %v", err)
		}
		if got := w.Header().Get(defaultHeaderLeaked); got != "true" {
			t.Errorf("response header leaked = %q, want %q (headers must be applied even without an explicit write)", got, "true")
		}
	})
}

// TestServeHTTP_Observe verifies mode=observe: the check runs synchronously,
// the backend is invoked unchanged, and neither the request nor the
// response is ever modified — no enrichment headers in either direction —
// while the check itself still happens and the backend's status is still
// captured for the responses_total correlation metric (see
// TestServeHTTP_ResponsesTotal for that assertion).
func TestServeHTTP_Observe(t *testing.T) {
	tests := []struct {
		name    string
		checker *fakeChecker
	}{
		{name: "not leaked", checker: &fakeChecker{leaked: false, count: 0}},
		{name: "leaked", checker: &fakeChecker{leaked: true, count: 42}},
		{name: "checker errors: fails open", checker: &fakeChecker{err: errors.New("boom")}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMiddleware(tc.checker)
			m.Mode = ModeObserve

			r := jsonRequest(t, `{"password":"hunter2"}`)
			w := httptest.NewRecorder()

			var seenLeakedReqHeader, seenCountReqHeader string
			nextCalled := false
			next := nextHandler(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				seenLeakedReqHeader = r.Header.Get(defaultHeaderLeaked)
				seenCountReqHeader = r.Header.Get(defaultHeaderCount)
				w.WriteHeader(http.StatusTeapot)
			})

			if err := m.ServeHTTP(w, r, next); err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}
			if !nextCalled {
				t.Fatal("next handler was not called")
			}
			if tc.checker.calls != 1 {
				t.Errorf("checker called %d times, want 1", tc.checker.calls)
			}

			// observe must never inject headers, in either direction.
			if seenLeakedReqHeader != "" {
				t.Errorf("request header leaked = %q, want empty (observe must not modify the request)", seenLeakedReqHeader)
			}
			if seenCountReqHeader != "" {
				t.Errorf("request header count = %q, want empty (observe must not modify the request)", seenCountReqHeader)
			}
			if got := w.Header().Get(defaultHeaderLeaked); got != "" {
				t.Errorf("response header leaked = %q, want empty (observe must not modify the response)", got)
			}
			if got := w.Header().Get(defaultHeaderCount); got != "" {
				t.Errorf("response header count = %q, want empty (observe must not modify the response)", got)
			}

			// The backend's real status must still reach the client
			// unchanged.
			if w.Code != http.StatusTeapot {
				t.Errorf("status = %d, want %d (observe must not alter the response)", w.Code, http.StatusTeapot)
			}
		})
	}
}

// TestServeHTTP_SkippedCheckStillFailsOpen verifies that a check that was
// skipped under fail-open (e.g. timeout, rate limit, circuit open) — which
// hansestack-go reports as Result{Outcome: <skip reason>} with a nil error,
// not leaked == true — is still surfaced as "not leaked" to headers/blocking
// logic, while the skip reason itself is preserved on leakResult.outcome for
// metrics/logging.
func TestServeHTTP_SkippedCheckStillFailsOpen(t *testing.T) {
	checker := &fakeChecker{leaked: false, count: 0, outcome: leakcheck.OutcomeSkippedTimeout}
	m := newTestMiddleware(checker)
	m.Mode = ModeEnrichRequest

	r := jsonRequest(t, `{"password":"hunter2"}`)
	w := httptest.NewRecorder()

	var seenLeaked string
	next := nextHandler(func(_ http.ResponseWriter, r *http.Request) {
		seenLeaked = r.Header.Get(defaultHeaderLeaked)
	})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if seenLeaked != "false" {
		t.Errorf("request header leaked = %q, want %q (a skipped check must fail open)", seenLeaked, "false")
	}

	res := m.check(jsonRequest(t, `{"password":"hunter2"}`), "hunter2")
	if res.outcome != leakcheck.OutcomeSkippedTimeout {
		t.Errorf("leakResult.outcome = %v, want %v", res.outcome, leakcheck.OutcomeSkippedTimeout)
	}
}

// TestServeHTTP_NoPasswordFound verifies that requests without an
// extractable password skip the check entirely and proceed unchanged, for
// every mode.
func TestServeHTTP_NoPasswordFound(t *testing.T) {
	for _, mode := range []string{ModeObserve, ModeEnrichRequest, ModeEnrichResponse, ModeBlock} {
		t.Run(mode, func(t *testing.T) {
			checker := &fakeChecker{leaked: true, count: 99} // must never be consulted
			m := newTestMiddleware(checker)
			m.Mode = mode

			r := jsonRequest(t, `{"email":"a@b.de"}`) // no password field
			w := httptest.NewRecorder()

			nextCalled := false
			next := nextHandler(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			if err := m.ServeHTTP(w, r, next); err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}
			if !nextCalled {
				t.Fatal("next handler must be called when there is no password to check")
			}
			if checker.calls != 0 {
				t.Errorf("checker was called %d times, want 0", checker.calls)
			}
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", w.Code)
			}
		})
	}
}

// TestServeHTTP_ContextPropagation ensures the request's own context is
// passed through to CheckPassword, per the hansestack-go integration
// contract.
func TestServeHTTP_ContextPropagation(t *testing.T) {
	checker := &fakeChecker{leaked: false}
	m := newTestMiddleware(checker)
	m.Mode = ModeEnrichRequest

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")

	r := jsonRequest(t, `{"password":"hunter2"}`).WithContext(ctx)
	w := httptest.NewRecorder()

	next := nextHandler(func(http.ResponseWriter, *http.Request) {})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if checker.lastCtx == nil || checker.lastCtx.Value(ctxKey{}) != "marker" {
		t.Error("CheckPassword was not called with the request's context")
	}
}

// TestServeHTTP_ResponsesTotal is the end-to-end regression test for the
// Indicator-of-Compromise correlation metric: it verifies that every mode
// (observe, enrich_request, enrich_response, block) increments
// hansestack_leakcheck_responses_total with the correct {result,
// status_class} labels, derived from the backend's real (or, for a blocked
// request, the configured block_status) response.
func TestServeHTTP_ResponsesTotal(t *testing.T) {
	tests := []struct {
		name           string
		mode           string
		checker        *fakeChecker
		backendStatus  int // status the fake backend writes; ignored for a blocked leak
		wantResult     string
		wantStatusClas string
	}{
		{
			name:           "observe: not leaked, backend 200",
			mode:           ModeObserve,
			checker:        &fakeChecker{leaked: false},
			backendStatus:  http.StatusOK,
			wantResult:     responseResultNotLeaked,
			wantStatusClas: "2xx",
		},
		{
			name:           "observe: leaked, backend 200 (the core IoC signal)",
			mode:           ModeObserve,
			checker:        &fakeChecker{leaked: true, count: 3},
			backendStatus:  http.StatusOK,
			wantResult:     responseResultLeaked,
			wantStatusClas: "2xx",
		},
		{
			name:           "enrich_request: leaked, backend rejects with 401",
			mode:           ModeEnrichRequest,
			checker:        &fakeChecker{leaked: true, count: 1},
			backendStatus:  http.StatusUnauthorized,
			wantResult:     responseResultLeaked,
			wantStatusClas: "4xx",
		},
		{
			name:           "enrich_response: not leaked, backend 500",
			mode:           ModeEnrichResponse,
			checker:        &fakeChecker{leaked: false},
			backendStatus:  http.StatusInternalServerError,
			wantResult:     responseResultNotLeaked,
			wantStatusClas: "5xx",
		},
		{
			name:           "block: not leaked, passes through to backend 200",
			mode:           ModeBlock,
			checker:        &fakeChecker{leaked: false},
			backendStatus:  http.StatusOK,
			wantResult:     responseResultNotLeaked,
			wantStatusClas: "2xx",
		},
		{
			name:           "block: leaked, short-circuited with block_status, backend never runs",
			mode:           ModeBlock,
			checker:        &fakeChecker{leaked: true, count: 9},
			wantResult:     responseResultLeaked,
			wantStatusClas: "4xx", // defaultBlockStatus is 401
		},
		{
			name:           "skipped check (fail-open) is labeled \"skipped\", not \"not_leaked\"",
			mode:           ModeObserve,
			checker:        &fakeChecker{leaked: false, outcome: leakcheck.OutcomeSkippedTimeout},
			backendStatus:  http.StatusOK,
			wantResult:     responseResultSkipped,
			wantStatusClas: "2xx",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			m := newTestMiddleware(tc.checker)
			m.Mode = tc.mode
			m.metrics = newMetrics(ctx)

			r := jsonRequest(t, `{"password":"hunter2"}`)
			w := httptest.NewRecorder()
			next := nextHandler(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.backendStatus)
			})

			if err := m.ServeHTTP(w, r, next); err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}

			got := testutil.ToFloat64(m.metrics.responsesTotal.WithLabelValues(tc.wantResult, tc.wantStatusClas))
			if got != 1 {
				t.Errorf("responses_total{result=%q, status_class=%q} = %v, want 1",
					tc.wantResult, tc.wantStatusClas, got)
			}
		})
	}
}

// hijackableRecorder is an httptest.ResponseRecorder that also implements
// http.Hijacker, so tests can verify that statusCapturingWriter's Unwrap()
// lets http.ResponseController reach through to it — the exact mechanism
// reverse_proxy relies on for WebSocket/CONNECT upgrades. httptest's own
// ResponseRecorder deliberately does not implement Hijacker, so it cannot be
// used directly for this regression test.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	server, _ := net.Pipe()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

// readerFromRecorder is an httptest.ResponseRecorder that also implements
// io.ReaderFrom, so tests can verify statusCapturingWriter promotes the fast
// streaming path (see caddyhttp.ResponseWriterWrapper.ReadFrom) rather than
// silently falling back to a manual io.Copy.
type readerFromRecorder struct {
	*httptest.ResponseRecorder
	readFromCalled bool
}

func (rf *readerFromRecorder) ReadFrom(r io.Reader) (int64, error) {
	rf.readFromCalled = true
	return io.Copy(rf.ResponseRecorder, r)
}

// TestStatusCapturingWriter_PreservesHijacker is a regression test for the
// classic response-writer-wrapping pitfall: a naive wrapper that only embeds
// http.ResponseWriter (rather than promoting Unwrap) silently breaks
// Hijack(), which reverse_proxy needs for WebSocket/CONNECT upgrades.
func TestStatusCapturingWriter_PreservesHijacker(t *testing.T) {
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	sw := newStatusCapturingWriter(rec)

	conn, _, err := http.NewResponseController(sw).Hijack()
	if err != nil {
		t.Fatalf("Hijack() through statusCapturingWriter failed: %v", err)
	}
	defer conn.Close()

	if !rec.hijacked {
		t.Error("underlying Hijack() was never reached through statusCapturingWriter")
	}
}

// TestStatusCapturingWriter_PreservesReadFrom is a regression test ensuring
// statusCapturingWriter still promotes io.ReaderFrom from the wrapped
// writer, so a streamed reverse-proxy response keeps its zero-copy fast
// path instead of falling back to a manual io.Copy loop.
func TestStatusCapturingWriter_PreservesReadFrom(t *testing.T) {
	rec := &readerFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	sw := newStatusCapturingWriter(rec)

	rf, ok := any(sw).(io.ReaderFrom)
	if !ok {
		t.Fatal("statusCapturingWriter does not implement io.ReaderFrom")
	}

	n, err := rf.ReadFrom(strings.NewReader("streamed-body"))
	if err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if n != int64(len("streamed-body")) {
		t.Errorf("ReadFrom returned n = %d, want %d", n, len("streamed-body"))
	}
	if !rec.readFromCalled {
		t.Error("underlying ReadFrom() was never reached through statusCapturingWriter")
	}
}

// TestStatusCapturingWriter_Status verifies the three ways a status code can
// end up recorded: an explicit WriteHeader call, an implicit 200 from a bare
// Write, and the zero value when nothing was ever written at all.
func TestStatusCapturingWriter_Status(t *testing.T) {
	t.Run("explicit WriteHeader", func(t *testing.T) {
		sw := newStatusCapturingWriter(httptest.NewRecorder())
		sw.WriteHeader(http.StatusCreated)
		if sw.Status() != http.StatusCreated {
			t.Errorf("Status() = %d, want %d", sw.Status(), http.StatusCreated)
		}
	})

	t.Run("implicit 200 via bare Write", func(t *testing.T) {
		sw := newStatusCapturingWriter(httptest.NewRecorder())
		if _, err := sw.Write([]byte("ok")); err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
		if sw.Status() != http.StatusOK {
			t.Errorf("Status() = %d, want %d", sw.Status(), http.StatusOK)
		}
	})

	t.Run("first WriteHeader call wins", func(t *testing.T) {
		sw := newStatusCapturingWriter(httptest.NewRecorder())
		sw.WriteHeader(http.StatusCreated)
		sw.WriteHeader(http.StatusInternalServerError)
		if sw.Status() != http.StatusCreated {
			t.Errorf("Status() = %d, want %d (first WriteHeader call must win)", sw.Status(), http.StatusCreated)
		}
	})

	t.Run("nothing written at all", func(t *testing.T) {
		sw := newStatusCapturingWriter(httptest.NewRecorder())
		if sw.Status() != 0 {
			t.Errorf("Status() = %d, want 0 when nothing was ever written", sw.Status())
		}
	})
}

// TestStatusCapturingWriter_PreservesFlusher is a regression test ensuring
// statusCapturingWriter's embedded caddyhttp.ResponseWriterWrapper still
// lets http.ResponseController reach the wrapped writer's Flush method via
// Unwrap(), rather than silently swallowing flush calls — which would break
// streaming/SSE responses proxied through this middleware. This is exactly
// the http.NewResponseController(...).Flush() pattern reverse_proxy itself
// uses to flush partial chunks of a streamed response as they arrive.
//
// httptest.ResponseRecorder already implements http.Flusher natively (its
// own Flush() method sets the exported Flushed field), so no custom
// test-double type is needed here, unlike the Hijacker/ReadFrom regression
// tests above.
func TestStatusCapturingWriter_PreservesFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := newStatusCapturingWriter(rec)

	if err := http.NewResponseController(sw).Flush(); err != nil {
		t.Fatalf("Flush() through statusCapturingWriter failed: %v", err)
	}

	if !rec.Flushed {
		t.Error("underlying Flush() was never reached through statusCapturingWriter")
	}
}

// TestServeHTTP_PanicStillRecordsResponseMetricAndRepanics verifies, for
// every mode, that a panicking backend does not cause
// hansestack_leakcheck_responses_total to silently drop an observation, and
// that the panic still propagates past ServeHTTP so Caddy's own recovery
// middleware still sees and handles it — this plugin must never swallow a
// downstream panic.
func TestServeHTTP_PanicStillRecordsResponseMetricAndRepanics(t *testing.T) {
	for _, mode := range []string{ModeObserve, ModeEnrichRequest, ModeEnrichResponse, ModeBlock} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			checker := &fakeChecker{leaked: false}
			m := newTestMiddleware(checker)
			m.Mode = mode
			m.metrics = newMetrics(ctx)

			r := jsonRequest(t, `{"password":"hunter2"}`)
			w := httptest.NewRecorder()
			next := nextHandler(func(http.ResponseWriter, *http.Request) {
				panic("simulated backend panic")
			})

			func() {
				defer func() {
					rec := recover()
					if rec == nil {
						t.Fatal("panic did not propagate past ServeHTTP; it must reach Caddy's own recovery middleware")
					}

					// The panic happens before any write in every mode
					// (including block's pass-through branch, since
					// fakeChecker{leaked: false} never short-circuits), so
					// the captured status is always 0 -> "unknown".
					got := testutil.ToFloat64(m.metrics.responsesTotal.WithLabelValues(responseResultNotLeaked, "unknown"))
					if got != 1 {
						t.Errorf("responses_total{result=not_leaked, status_class=unknown} = %v, want 1 (metric must be recorded even on panic)", got)
					}
				}()

				_ = m.ServeHTTP(w, r, next)
			}()
		})
	}
}

// TestUnmarshalCaddyfile exercises the Caddyfile parser against valid and
// invalid configurations.
func TestUnmarshalCaddyfile(t *testing.T) {
	valid := `leakcheck {
		api_key supersecret
		mode block
		password_field pwd
		header_leaked X-Leaked
		header_count X-Count
		block_status 422
	}`

	d := caddyfile.NewTestDispenser(valid)
	d.Next() // position at "leakcheck", mirroring parseCaddyfile's contract
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}

	if m.APIKey != "supersecret" {
		t.Errorf("APIKey = %q, want %q", m.APIKey, "supersecret")
	}
	if m.Mode != "block" {
		t.Errorf("Mode = %q, want %q", m.Mode, "block")
	}
	if m.PasswordField != "pwd" {
		t.Errorf("PasswordField = %q, want %q", m.PasswordField, "pwd")
	}
	if m.HeaderLeaked != "X-Leaked" {
		t.Errorf("HeaderLeaked = %q, want %q", m.HeaderLeaked, "X-Leaked")
	}
	if m.HeaderCount != "X-Count" {
		t.Errorf("HeaderCount = %q, want %q", m.HeaderCount, "X-Count")
	}
	if m.BlockStatus != 422 {
		t.Errorf("BlockStatus = %d, want 422", m.BlockStatus)
	}
}

func TestUnmarshalCaddyfile_Defaults(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if m.APIKey != "supersecret" {
		t.Errorf("APIKey = %q, want %q", m.APIKey, "supersecret")
	}
	// Defaults are applied in Provision, not here; UnmarshalCaddyfile should
	// leave the rest zero-valued.
	if m.Mode != "" {
		t.Errorf("Mode = %q, want empty before Provision", m.Mode)
	}
}

func TestUnmarshalCaddyfile_Timeout(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
		timeout 250ms
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if m.Timeout != "250ms" {
		t.Errorf("Timeout = %q, want %q", m.Timeout, "250ms")
	}
}

func TestUnmarshalCaddyfile_CircuitBreaker(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
		circuit_breaker_threshold 5
		circuit_breaker_cooldown 30s
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if m.CircuitBreakerThreshold != 5 {
		t.Errorf("CircuitBreakerThreshold = %d, want 5", m.CircuitBreakerThreshold)
	}
	if m.CircuitBreakerCooldown != "30s" {
		t.Errorf("CircuitBreakerCooldown = %q, want %q", m.CircuitBreakerCooldown, "30s")
	}
}

func TestUnmarshalCaddyfile_InvalidCircuitBreakerThreshold(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
		circuit_breaker_threshold not-a-number
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected an error for a non-numeric circuit_breaker_threshold")
	}
}

func TestUnmarshalCaddyfile_MaxIdleConns(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
		max_idle_conns 200
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if m.MaxIdleConns != 200 {
		t.Errorf("MaxIdleConns = %d, want 200", m.MaxIdleConns)
	}
}

func TestUnmarshalCaddyfile_InvalidMaxIdleConns(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
		max_idle_conns not-a-number
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected an error for a non-numeric max_idle_conns")
	}
}

func TestUnmarshalCaddyfile_Endpoint(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
		endpoint "http://localhost:8081"
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if m.Endpoint != "http://localhost:8081" {
		t.Errorf("Endpoint = %q, want %q", m.Endpoint, "http://localhost:8081")
	}
}

func TestUnmarshalCaddyfile_UnknownDirective(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		totally_unknown foo
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected an error for an unrecognized subdirective")
	}
}

func TestUnmarshalCaddyfile_InvalidBlockStatus(t *testing.T) {
	d := caddyfile.NewTestDispenser(`leakcheck {
		api_key supersecret
		block_status not-a-number
	}`)
	d.Next()
	m := new(Middleware)
	if err := m.UnmarshalCaddyfile(d); err == nil {
		t.Fatal("expected an error for a non-numeric block_status")
	}
}

// TestValidate exercises the module's Validate lifecycle method.
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		m       *Middleware
		wantErr bool
	}{
		{
			name:    "valid",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401},
			wantErr: false,
		},
		{
			name:    "valid observe mode",
			m:       &Middleware{APIKey: "k", Mode: ModeObserve, BlockStatus: 401},
			wantErr: false,
		},
		{
			name:    "missing api_key is allowed (on-prem/sidecar deployments may run without auth)",
			m:       &Middleware{Mode: ModeEnrichRequest, BlockStatus: 401},
			wantErr: false,
		},
		{
			name:    "invalid mode",
			m:       &Middleware{APIKey: "k", Mode: "bogus", BlockStatus: 401},
			wantErr: true,
		},
		{
			name:    "invalid block_status",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 9999},
			wantErr: true,
		},
		{
			name:    "valid timeout",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401, Timeout: "250ms"},
			wantErr: false,
		},
		{
			name:    "invalid timeout",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401, Timeout: "not-a-duration"},
			wantErr: true,
		},
		{
			name:    "valid circuit breaker config",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401, CircuitBreakerThreshold: 5, CircuitBreakerCooldown: "30s"},
			wantErr: false,
		},
		{
			name:    "negative circuit_breaker_threshold",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401, CircuitBreakerThreshold: -1},
			wantErr: true,
		},
		{
			name:    "invalid circuit_breaker_cooldown",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401, CircuitBreakerThreshold: 5, CircuitBreakerCooldown: "not-a-duration"},
			wantErr: true,
		},
		{
			name:    "valid max_idle_conns",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401, MaxIdleConns: 200},
			wantErr: false,
		},
		{
			name:    "negative max_idle_conns",
			m:       &Middleware{APIKey: "k", Mode: ModeEnrichRequest, BlockStatus: 401, MaxIdleConns: -1},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
