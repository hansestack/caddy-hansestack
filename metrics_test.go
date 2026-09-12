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
