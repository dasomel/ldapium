package main

import (
	"net/http"
	"time"
)

// newMetricsServer builds the optional second listener that serves the process
// metrics (D218-10). It returns nil when addr is empty, which is the default:
// no METRICS_ADDR, no listener, and the public port never serves /metrics.
// There is no authentication here by Prometheus convention; keeping the port
// reachable only by the scraper (loopback, a ClusterIP Service behind a
// NetworkPolicy) is the operator's boundary.
func newMetricsServer(addr string, metrics http.Handler) *http.Server {
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	// "GET /metrics" matches that exact path only (also HEAD), so every other
	// path is a plain 404 and other methods on /metrics are 405 with Allow.
	mux.Handle("GET /metrics", metrics)
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
}
