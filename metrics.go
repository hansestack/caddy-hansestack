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

// metrics holds the Prometheus collectors this middleware reports. A single
// set is shared by all Middleware instances provisioned from the same
// caddy.Context (e.g. multiple "hansestack leakcheck" blocks in one
// Caddyfile), since Prometheus collectors must be registered exactly once
// per process/registry.
type metrics struct {
	// checksTotal counts every completed leak check, labeled by outcome.
	// It is only incremented once the Hansestack API (or the fail-open
	// path) has produced a definitive leaked/not-leaked result.
	checksTotal *prometheus.CounterVec

	// checkErrorsTotal counts checks that fell back to the fail-open path
	// because the underlying client returned an error. In the default
	// (fail-open) client configuration this should stay at zero; a nonzero
	// rate signals a misconfiguration (e.g. a bad API key) that deserves
	// operator attention, even though end users were never affected.
	checkErrorsTotal prometheus.Counter
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

	checkErrorsTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Subsystem: metricsSubsystem,
		Name:      "check_errors_total",
		Help:      "Total number of leak checks that fell back to fail-open because the Hansestack API client returned an error.",
	})

	return &metrics{
		checksTotal:      mustRegisterOrReuseVec(registry, checksTotal),
		checkErrorsTotal: mustRegisterOrReuseCounter(registry, checkErrorsTotal),
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
}
