package main

import (
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
)

const (
	// defaultShutdownGrace is the wait for in-flight requests when machine
	// authentication is off; it is also the floor when it is on.
	defaultShutdownGrace = 10 * time.Second
	// machineAuthPhase mirrors httpapi.machineAuthTimeout (2*FetchTimeout): a
	// request accepted just before SIGTERM can spend this long authenticating
	// before its MACHINE_REQUEST_TIMEOUT execution step even starts.
	machineAuthPhase = 2 * machineauth.FetchTimeout
	// shutdownGraceMargin is added on top so a request that starts its
	// execution step right at the deadline can still write its response
	// before the server closes connections.
	shutdownGraceMargin = 5 * time.Second
	// maxShutdownGrace bounds the derived value. MACHINE_REQUEST_TIMEOUT is
	// already capped at 5m by config, so this is a defensive ceiling that
	// equals the chart's largest terminationGracePeriodSeconds (300+15): a
	// larger wait could never complete inside the pod's grace period anyway.
	maxShutdownGrace = 5*time.Minute + machineAuthPhase + shutdownGraceMargin
)

// shutdownGrace derives the graceful-shutdown wait from configuration (#280,
// D7). Machine auth off keeps the historical 10 s. On, in-flight machine
// requests (up to requestTimeout) must be able to finish when a replica is
// replaced for an emergency block, so the wait is
// max(10s, authPhase+requestTimeout+margin), clamped to maxShutdownGrace.
//
// D1: the chart's terminationGracePeriodSeconds is max(30, timeout+15), which is
// always >= this value; keep the two in step. Cost: a stuck request can delay
// pod exit by up to the grace. Escape hatch: Kubernetes SIGKILLs at its own
// grace period regardless.
func shutdownGrace(machineEnabled bool, requestTimeout time.Duration) time.Duration {
	if !machineEnabled {
		return defaultShutdownGrace
	}
	grace := machineAuthPhase + requestTimeout + shutdownGraceMargin
	if grace < defaultShutdownGrace {
		grace = defaultShutdownGrace
	}
	if grace > maxShutdownGrace {
		grace = maxShutdownGrace
	}
	return grace
}
