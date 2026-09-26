package caddyhansestack

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/hansestack/hansestack-go/leakcheck"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// newTestContext returns a fresh caddy.Context with its own metrics
// registry, along with a cancel func the test must call to release it.
func newTestContext(t *testing.T) caddy.Context {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	return ctx
}

// TestMetrics_Observe verifies that observing check outcomes increments the
// correctly labeled Prometheus counters, and that a fail-open error also
// increments the dedicated error counter without affecting which result
// label is incremented.
func TestMetrics_Observe(t *testing.T) {
	ctx := newTestContext(t)
	m := newMetrics(ctx)

	m.observe(leakResult{leaked: false, count: 0}, nil)
	m.observe(leakResult{leaked: true, count: 3}, nil)
	m.observe(leakResult{leaked: true, count: 5}, nil)
	// A fail-open result (err != nil) is always reported as "not leaked" by
	// the caller (see Middleware.check), so it also lands in the
	// not_leaked bucket, plus the dedicated error counter.
	m.observe(leakResult{leaked: false, count: 0}, errors.New("boom"))

	if got := testutil.ToFloat64(m.checksTotal.WithLabelValues(resultLeaked)); got != 2 {
		t.Errorf("checksTotal{result=leaked} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.checksTotal.WithLabelValues(resultNotLeaked)); got != 2 {
		t.Errorf("checksTotal{result=not_leaked} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.checkErrorsTotal); got != 1 {
		t.Errorf("checkErrorsTotal = %v, want 1", got)
	}
}

// TestMetrics_Observe_Outcomes verifies that observe() also records the
// reasoning behind each check via check_outcomes_total, labeled by
// leakcheck.Outcome — the signal that distinguishes a genuine "checked, not
// leaked" from a fail-open skip (timeout, rate limit, circuit open, ...).
func TestMetrics_Observe_Outcomes(t *testing.T) {
	ctx := newTestContext(t)
	m := newMetrics(ctx)

	m.observe(leakResult{leaked: false, count: 0, outcome: leakcheck.OutcomeChecked}, nil)
	m.observe(leakResult{leaked: true, count: 3, outcome: leakcheck.OutcomeChecked}, nil)
	m.observe(leakResult{leaked: false, count: 0, outcome: leakcheck.OutcomeSkippedTimeout}, nil)
	m.observe(leakResult{leaked: false, count: 0, outcome: leakcheck.OutcomeSkippedRateLimited}, nil)
	m.observe(leakResult{leaked: false, count: 0, outcome: leakcheck.OutcomeSkippedCircuitOpen}, nil)
	m.observe(leakResult{leaked: false, count: 0, outcome: leakcheck.OutcomeSkippedError}, errors.New("boom"))

	cases := []struct {
		outcome leakcheck.Outcome
		want    float64
	}{
		{leakcheck.OutcomeChecked, 2},
		{leakcheck.OutcomeSkippedTimeout, 1},
		{leakcheck.OutcomeSkippedRateLimited, 1},
		{leakcheck.OutcomeSkippedCircuitOpen, 1},
		{leakcheck.OutcomeSkippedError, 1},
	}

	for _, tc := range cases {
		if got := testutil.ToFloat64(m.checkOutcomesTotal.WithLabelValues(tc.outcome.String())); got != tc.want {
			t.Errorf("checkOutcomesTotal{outcome=%s} = %v, want %v", tc.outcome, got, tc.want)
		}
	}
}

// TestMetrics_NilReceiverIsSafe ensures a nil *metrics (e.g. if
// registration were ever skipped) never panics when observed.
func TestMetrics_NilReceiverIsSafe(t *testing.T) {
	var m *metrics
	m.observe(leakResult{leaked: true, count: 1}, nil) // must not panic
}

// TestMetrics_DuplicateRegistrationIsReused verifies that provisioning a
// second set of collectors against the same registry (as happens with
// multiple "hansestack leakcheck" blocks in one Caddyfile) reuses the
// existing collectors instead of panicking or silently going blind.
func TestMetrics_DuplicateRegistrationIsReused(t *testing.T) {
	ctx := newTestContext(t)

	first := newMetrics(ctx)
	second := newMetrics(ctx)

	first.observe(leakResult{leaked: true, count: 1}, nil)
	second.observe(leakResult{leaked: true, count: 1}, nil)

	// Both handles must refer to the same underlying collector, so both
	// increments are visible regardless of which handle is read from.
	if got := testutil.ToFloat64(first.checksTotal.WithLabelValues(resultLeaked)); got != 2 {
		t.Errorf("first.checksTotal{result=leaked} = %v, want 2 (collectors should be shared)", got)
	}
	if got := testutil.ToFloat64(second.checksTotal.WithLabelValues(resultLeaked)); got != 2 {
		t.Errorf("second.checksTotal{result=leaked} = %v, want 2 (collectors should be shared)", got)
	}
}

// TestStatusClass verifies the HTTP status code bucketing used to keep
// responsesTotal's cardinality bounded regardless of what the backend
// returns.
func TestStatusClass(t *testing.T) {
	tests := []struct {
		statusCode int
		want       string
	}{
		{100, "1xx"},
		{199, "1xx"},
		{200, "2xx"},
		{204, "2xx"},
		{299, "2xx"},
		{300, "3xx"},
		{301, "3xx"},
		{399, "3xx"},
		{400, "4xx"},
		{401, "4xx"},
		{404, "4xx"},
		{499, "4xx"},
		{500, "5xx"},
		{502, "5xx"},
		{599, "5xx"},
		{0, "unknown"},   // nothing was ever written (e.g. hijacked connection)
		{99, "unknown"},  // below the valid HTTP status range
		{600, "unknown"}, // above the valid HTTP status range
		{-1, "unknown"},  // defensively guard against a nonsensical negative code
	}

	for _, tc := range tests {
		if got := statusClass(tc.statusCode); got != tc.want {
			t.Errorf("statusClass(%d) = %q, want %q", tc.statusCode, got, tc.want)
		}
	}
}

// TestResponseResult verifies that a skipped check (any outcome other than
// leakcheck.OutcomeChecked) is always classified as "skipped" for
// responsesTotal, regardless of the neutral leaked/not-leaked value it
// carries under fail-open — conflating the two would defeat the purpose of
// the correlation metric.
func TestResponseResult(t *testing.T) {
	tests := []struct {
		name string
		res  leakResult
		want string
	}{
		{
			name: "checked, not leaked",
			res:  leakResult{leaked: false, outcome: leakcheck.OutcomeChecked},
			want: responseResultNotLeaked,
		},
		{
			name: "checked, leaked",
			res:  leakResult{leaked: true, outcome: leakcheck.OutcomeChecked},
			want: responseResultLeaked,
		},
		{
			name: "skipped (timeout), neutral leaked=false must not read as not_leaked",
			res:  leakResult{leaked: false, outcome: leakcheck.OutcomeSkippedTimeout},
			want: responseResultSkipped,
		},
		{
			name: "skipped (rate limited)",
			res:  leakResult{leaked: false, outcome: leakcheck.OutcomeSkippedRateLimited},
			want: responseResultSkipped,
		},
		{
			name: "skipped (circuit open)",
			res:  leakResult{leaked: false, outcome: leakcheck.OutcomeSkippedCircuitOpen},
			want: responseResultSkipped,
		},
		{
			name: "skipped (error)",
			res:  leakResult{leaked: false, outcome: leakcheck.OutcomeSkippedError},
			want: responseResultSkipped,
		},
		{
			name: "skipped (canceled)",
			res:  leakResult{leaked: false, outcome: leakcheck.OutcomeSkippedCanceled},
			want: responseResultSkipped,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := responseResult(tc.res); got != tc.want {
				t.Errorf("responseResult(%+v) = %q, want %q", tc.res, got, tc.want)
			}
		})
	}
}

// TestMetrics_ObserveResponse verifies observeResponse increments
// responsesTotal with the correct {result, status_class} label combination,
// independently of the existing observe()/checksTotal path.
func TestMetrics_ObserveResponse(t *testing.T) {
	ctx := newTestContext(t)
	m := newMetrics(ctx)

	m.observeResponse(leakResult{leaked: true, outcome: leakcheck.OutcomeChecked}, http.StatusOK)
	m.observeResponse(leakResult{leaked: false, outcome: leakcheck.OutcomeChecked}, http.StatusUnauthorized)
	m.observeResponse(leakResult{leaked: false, outcome: leakcheck.OutcomeSkippedTimeout}, http.StatusOK)
	m.observeResponse(leakResult{leaked: true, outcome: leakcheck.OutcomeChecked}, http.StatusOK)

	cases := []struct {
		result      string
		statusClass string
		want        float64
	}{
		{responseResultLeaked, "2xx", 2},
		{responseResultNotLeaked, "4xx", 1},
		{responseResultSkipped, "2xx", 1},
	}

	for _, tc := range cases {
		if got := testutil.ToFloat64(m.responsesTotal.WithLabelValues(tc.result, tc.statusClass)); got != tc.want {
			t.Errorf("responsesTotal{result=%s, status_class=%s} = %v, want %v", tc.result, tc.statusClass, got, tc.want)
		}
	}
}

// TestMetrics_ObserveResponse_NilReceiverIsSafe ensures a nil *metrics never
// panics when observeResponse is called, mirroring the existing
// TestMetrics_NilReceiverIsSafe guarantee for observe().
func TestMetrics_ObserveResponse_NilReceiverIsSafe(t *testing.T) {
	var m *metrics
	m.observeResponse(leakResult{leaked: true}, http.StatusOK) // must not panic
}

// TestMiddleware_MetricsIntegration verifies end-to-end that ServeHTTP
// increments the shared metrics through Middleware.check, across modes.
func TestMiddleware_MetricsIntegration(t *testing.T) {
	ctx := newTestContext(t)
	m := newMetrics(ctx)

	mw := newTestMiddleware(&fakeChecker{leaked: true, count: 7})
	mw.Mode = ModeEnrichRequest
	mw.metrics = m

	r := jsonRequest(t, `{"password":"hunter2"}`)
	w := httptest.NewRecorder()
	next := nextHandler(func(http.ResponseWriter, *http.Request) {})

	if err := mw.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if got := testutil.ToFloat64(m.checksTotal.WithLabelValues(resultLeaked)); got != 1 {
		t.Errorf("checksTotal{result=leaked} = %v, want 1", got)
	}
}
