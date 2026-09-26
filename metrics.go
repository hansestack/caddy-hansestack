package caddyhansestack

import (
	"errors"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
)

// Metric names use a dedicated "hansestack_leakcheck" namespace/subsystem
// rather than Caddy's own "caddy_*" convention. These are a distinct
// product signal — the outcome of calls to the Hansestack Leak-Check API —
// not an HTTP-server-level metric, so operators should be able to recognize
// and dashboard them independently of caddy_http_* metrics.
const (
	metricsNamespace = "hansestack"
	metricsSubsystem = "leakcheck"
)

// resultLabel values for the "result" label on checksTotal.
const (
	resultLeaked    = "leaked"
	resultNotLeaked = "not_leaked"
)

// responseResultLabel values for the "result" label on responsesTotal. This
// is a coarser vocabulary than checksTotal's: it collapses every fail-open
// skip reason (timeout, rate limit, circuit open, error, canceled) into a
// single "skipped" bucket, since responsesTotal's purpose is IoC
// correlation ("did a leaked-password login succeed anyway?"), not root-
// causing why a check didn't run — that remains checkOutcomesTotal's job.
const (
	responseResultLeaked    = "leaked"
	responseResultNotLeaked = "not_leaked"
	responseResultSkipped   = "skipped"
)

// statusClass buckets an HTTP status code into its class ("2xx", "4xx",
// ...) for use as a bounded-cardinality Prometheus label. Exact status
// codes are deliberately never used as a label value: a backend (especially
// one reached via reverse_proxy to an arbitrary upstream) can emit any of
// dozens of distinct codes, and an attacker who can influence the backend's
// response can influence the code too. Bucketing by class keeps
// responsesTotal's cardinality fixed regardless of what the backend does,
// while still answering the IoC question that matters: did the request
// ultimately succeed (2xx), redirect (3xx), get rejected (4xx), or fail
// (5xx)?
//
// statusCode == 0 (no response was ever written, e.g. a hijacked
// connection or a request that never reached a next.ServeHTTP call) and any
// value outside the valid HTTP status range are reported as "unknown"
// rather than silently misclassified.
func statusClass(statusCode int) string {
	switch {
	case statusCode >= 100 && statusCode < 200:
		return "1xx"
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500 && statusCode < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

// metrics holds the Prometheus collectors this middleware reports. A single
// set is shared by all Middleware instances provisioned from the same
// caddy.Context (e.g. multiple "hansestack leakcheck" blocks in one
// Caddyfile), since Prometheus collectors must be registered exactly once
// per process/registry.
type metrics struct {
	// checksTotal counts every completed leak check, labeled by whether the
	// password was found leaked. It is incremented regardless of whether
	// the check actually reached the API or was skipped under fail-open
	// (see checkOutcomesTotal for that distinction); a skipped check is
	// always reported here as "not_leaked", per the fail-open contract.
	checksTotal *prometheus.CounterVec

	// checkOutcomesTotal counts every completed leak check labeled by
	// leakcheck.Outcome (e.g. "checked", "skipped_timeout",
	// "skipped_rate_limited", "skipped_circuit_open", "skipped_error",
	// "skipped_canceled"). This is the reasoning behind checksTotal: under
	// fail-open, a skipped check and a clean miss are indistinguishable in
	// checksTotal alone, but here they carry different outcome labels, so
	// operators can tell "confirmed not leaked" apart from "the check
	// didn't run, and here is why".
	checkOutcomesTotal *prometheus.CounterVec

	// checkErrorsTotal counts checks that fell back to the fail-open path
	// because the underlying client returned an error. In the default
	// (fail-open) client configuration this should stay at zero; a nonzero
	// rate signals a misconfiguration (e.g. a bad API key) that deserves
	// operator attention, even though end users were never affected.
	checkErrorsTotal prometheus.Counter

	// responsesTotal is the dedicated Indicator-of-Compromise correlation
	// counter: it pairs the leak-check result with the *backend's own*
	// final HTTP response status class, e.g.
	// responses_total{result="leaked", status_class="2xx"} means a request
	// carrying a breached password nonetheless reached the backend and got
	// a successful response — the strongest, most actionable signal this
	// plugin can offer an operator watching a dashboard.
	//
	// Deliberately kept separate from checksTotal rather than adding
	// status_class as an extra label there: checksTotal is incremented the
	// moment the leak check itself completes, a point that in some modes
	// (observe, enrich_response) is temporally decoupled from — or
	// concurrent with — the backend actually producing a response.
	// responsesTotal is only ever incremented once the backend's status is
	// known, so its absence or delay (e.g. a hijacked connection, a
	// panicking backend) never affects the always-reliable checksTotal.
	//
	// The "result" label uses the coarser responseResult* vocabulary
	// ("leaked", "not_leaked", "skipped") rather than checksTotal's two-
	// value one, and "status_class" is bucketed ("2xx", "4xx", ...) rather
	// than the exact status code, to keep cardinality strictly bounded
	// regardless of what the backend returns.
	responsesTotal *prometheus.CounterVec
}

// newMetrics registers this plugin's Prometheus collectors against ctx's
// metrics registry. If they are already registered (e.g. because another
// "hansestack leakcheck" block in the same Caddyfile provisioned first),
// the existing collectors are reused instead of panicking or erroring out.
// Registration is designed to never fail: metrics are an observability
// nice-to-have, never a reason to abort a config load.
func newMetrics(ctx caddy.Context) *metrics {
	registry := ctx.GetMetricsRegistry()

	checksTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "checks_total",
		Help:      "Total number of passwords checked against the Hansestack Leak-Check API, labeled by result.",
	}, []string{"result"})

	checkOutcomesTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "check_outcomes_total",
		Help:      "Total number of leak checks, labeled by outcome (checked, skipped_timeout, skipped_rate_limited, skipped_circuit_open, skipped_error, skipped_canceled): the reasoning behind whether a check actually reached the API.",
	}, []string{"outcome"})

	checkErrorsTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "check_errors_total",
		Help:      "Total number of leak checks that fell back to fail-open because the Hansestack API client returned an error.",
	})

	responsesTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "responses_total",
		Help:      "Indicator-of-Compromise correlation counter: total number of requests labeled by leak-check result (leaked, not_leaked, skipped) and the backend's final HTTP response status class (2xx, 3xx, 4xx, 5xx). Status codes are bucketed by class to keep cardinality bounded.",
	}, []string{"result", "status_class"})

	return &metrics{
		checksTotal:        mustRegisterOrReuseVec(registry, checksTotal),
		checkOutcomesTotal: mustRegisterOrReuseVec(registry, checkOutcomesTotal),
		checkErrorsTotal:   mustRegisterOrReuseCounter(registry, checkErrorsTotal),
		responsesTotal:     mustRegisterOrReuseVec(registry, responsesTotal),
	}
}

// mustRegisterOrReuseVec registers cv, or returns the already-registered
// collector of the same name if a duplicate registration is detected.
func mustRegisterOrReuseVec(registry *prometheus.Registry, cv *prometheus.CounterVec) *prometheus.CounterVec {
	if err := registry.Register(cv); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
		// Any other registration error (e.g. a genuine metric name
		// collision with an unrelated collector) is not something this
		// plugin can recover from sensibly; fall back to an unregistered
		// collector so the middleware still functions (metrics simply
		// won't be scraped) rather than failing the whole config load.
		return cv
	}

	return cv
}

// mustRegisterOrReuseCounter is the prometheus.Counter analogue of
// mustRegisterOrReuseVec.
func mustRegisterOrReuseCounter(registry *prometheus.Registry, c prometheus.Counter) prometheus.Counter {
	if err := registry.Register(c); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			if existing, ok := alreadyRegistered.ExistingCollector.(prometheus.Counter); ok {
				return existing
			}
		}
		return c
	}

	return c
}

// observe records the outcome of a single completed check.
func (m *metrics) observe(res leakResult, err error) {
	if m == nil {
		return
	}

	if err != nil {
		m.checkErrorsTotal.Inc()
	}

	if res.leaked {
		m.checksTotal.WithLabelValues(resultLeaked).Inc()
	} else {
		m.checksTotal.WithLabelValues(resultNotLeaked).Inc()
	}

	m.checkOutcomesTotal.WithLabelValues(res.outcome.String()).Inc()
}

// responseResult classifies res into the coarse vocabulary used by
// responsesTotal's "result" label. A check that was skipped under fail-open
// (any outcome other than leakcheck.OutcomeChecked) is reported as
// "skipped" here, regardless of the neutral res.leaked value it carries —
// conflating a genuine "confirmed not leaked" with "the check never ran"
// would defeat the whole purpose of this correlation metric.
func responseResult(res leakResult) string {
	if !res.outcome.Checked() {
		return responseResultSkipped
	}
	if res.leaked {
		return responseResultLeaked
	}
	return responseResultNotLeaked
}

// observeResponse records the Indicator-of-Compromise correlation signal:
// the leak-check result paired with the backend's final HTTP response
// status, once that status is known. Unlike observe, this is called from
// the request pipeline only after next.ServeHTTP has produced (or failed to
// produce) a status code, which may be well after — or, in concurrent
// modes, independently of — the check itself completing.
//
// statusCode is bucketed via statusClass before being used as a label value
// to keep cardinality bounded; see statusClass for why exact codes are
// never used here.
func (m *metrics) observeResponse(res leakResult, statusCode int) {
	if m == nil {
		return
	}

	m.responsesTotal.WithLabelValues(responseResult(res), statusClass(statusCode)).Inc()
}
