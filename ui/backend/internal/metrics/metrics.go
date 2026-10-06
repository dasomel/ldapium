// Package metrics is the UI backend's Prometheus surface (change package
// api-error-envelope, D218-9/D218-11): process-scope series only, on a private
// Registry, behind the narrow Recorder interface so the rest of the code never
// imports the Prometheus client and the library can be swapped.
//
// Every label value is normalised to a closed set before it reaches a series
// (REQ-009): a route is a registered Echo pattern or "unmatched", a method one
// of five or "other", an API error code one the caller registered, and so on.
// Nothing user-controlled (path text, uid, DN, IP, error text) can become a
// label, so cardinality has a fixed ceiling and a scrape carries no secrets.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DefaultBuckets are the histogram upper bounds (seconds) for HTTP and LDAP
// latency.
var DefaultBuckets = prometheus.DefBuckets

const (
	other     = "other"
	unmatched = "unmatched"
)

// Recorder is everything the rest of the process may report. Nop satisfies it
// when metrics are off.
type Recorder interface {
	// ObserveHTTP records one finished request. route is the Echo route
	// pattern (c.Path()), never the request path.
	ObserveHTTP(route, method string, status int, d time.Duration)
	// InFlight adds delta (+1 on start, -1 on finish) to the in-flight gauge.
	InFlight(delta int)
	// APIError counts one error envelope by its stable code.
	APIError(code string)
	// LoginFailure counts one failed login by a closed reason.
	LoginFailure(reason string)
	// ObserveLDAP records one directory operation: op is bind, search, ping or
	// write; result is ok, invalid_credentials or error.
	ObserveLDAP(op, result string, d time.Duration)
}

// Nop discards everything.
type Nop struct{}

func (Nop) ObserveHTTP(string, string, int, time.Duration) {}
func (Nop) InFlight(int)                                   {}
func (Nop) APIError(string)                                {}
func (Nop) LoginFailure(string)                            {}
func (Nop) ObserveLDAP(string, string, time.Duration)      {}

// Options configures the closed label sets and the live gauge source.
type Options struct {
	// Routes are the registered Echo route patterns; any other route label is
	// reported as "unmatched".
	Routes []string
	// Codes are the API error codes the process can emit; any other is "other".
	Codes []string
	// Sessions reports the live session count for ldapium_ui_sessions_active.
	Sessions func() int
}

// Registry implements Recorder on a private prometheus.Registry.
type Registry struct {
	reg       *prometheus.Registry
	routes    map[string]struct{}
	codes     map[string]struct{}
	requests  *prometheus.CounterVec
	duration  *prometheus.HistogramVec
	inFlight  prometheus.Gauge
	apiErrors *prometheus.CounterVec
	logins    *prometheus.CounterVec
	ldapOps   *prometheus.CounterVec
	ldapDur   *prometheus.HistogramVec
}

var (
	methods = map[string]struct{}{"GET": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {}}
	reasons = map[string]struct{}{"invalid_credentials": {}, "rate_limited": {}, "malformed": {}, "upstream": {}}
	ldapOps = map[string]struct{}{"bind": {}, "search": {}, "ping": {}, "write": {}}
	results = map[string]struct{}{"ok": {}, "invalid_credentials": {}, "error": {}}
)

// New builds a Registry with the Go and process collectors and the
// ldapium_ui_* series of D218-9.
func New(o Options) *Registry {
	r := &Registry{
		reg:    prometheus.NewRegistry(),
		routes: set(o.Routes),
		codes:  set(o.Codes),
	}
	r.requests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ldapium_ui_http_requests_total", Help: "HTTP requests handled, by route pattern, method and status class.",
	}, []string{"route", "method", "code_class"})
	r.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ldapium_ui_http_request_duration_seconds", Help: "HTTP request latency, by route pattern and method.", Buckets: DefaultBuckets,
	}, []string{"route", "method"})
	r.inFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ldapium_ui_http_requests_in_flight", Help: "HTTP requests currently being served.",
	})
	r.apiErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ldapium_ui_api_errors_total", Help: "Error envelopes returned by /api, by stable error code.",
	}, []string{"code"})
	r.logins = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ldapium_ui_login_failures_total", Help: "Failed logins, by reason.",
	}, []string{"reason"})
	r.ldapOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ldapium_ui_ldap_operations_total", Help: "Directory operations issued by the UI backend, by operation and result.",
	}, []string{"op", "result"})
	r.ldapDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "ldapium_ui_ldap_operation_duration_seconds", Help: "Directory operation latency, by operation.", Buckets: DefaultBuckets,
	}, []string{"op"})

	r.reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		r.requests, r.duration, r.inFlight, r.apiErrors, r.logins, r.ldapOps, r.ldapDur)
	if o.Sessions != nil {
		r.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "ldapium_ui_sessions_active", Help: "Live sessions held by this process.",
		}, func() float64 { return float64(o.Sessions()) }))
	}
	return r
}

// Handler serves the Prometheus text exposition of this registry.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

func (r *Registry) ObserveHTTP(route, method string, status int, d time.Duration) {
	if _, ok := r.routes[route]; !ok {
		route = unmatched
	}
	method = pick(methods, method)
	r.requests.WithLabelValues(route, method, statusClass(status)).Inc()
	r.duration.WithLabelValues(route, method).Observe(d.Seconds())
}

func (r *Registry) InFlight(delta int) { r.inFlight.Add(float64(delta)) }

func (r *Registry) APIError(code string) {
	r.apiErrors.WithLabelValues(pick(r.codes, code)).Inc()
}

func (r *Registry) LoginFailure(reason string) {
	r.logins.WithLabelValues(pick(reasons, reason)).Inc()
}

func (r *Registry) ObserveLDAP(op, result string, d time.Duration) {
	op = pick(ldapOps, op)
	r.ldapOps.WithLabelValues(op, pick(results, result)).Inc()
	r.ldapDur.WithLabelValues(op).Observe(d.Seconds())
}

func set(values []string) map[string]struct{} {
	m := make(map[string]struct{}, len(values))
	for _, v := range values {
		m[v] = struct{}{}
	}
	return m
}

func pick(allowed map[string]struct{}, v string) string {
	if _, ok := allowed[v]; ok {
		return v
	}
	return other
}

func statusClass(status int) string {
	if status < 100 || status > 599 {
		return other
	}
	return strconv.Itoa(status/100) + "xx"
}
