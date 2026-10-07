package main

import (
	"testing"
	"time"
)

func TestShutdownGrace(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		timeout time.Duration
		want    time.Duration
	}{
		{"machine off ignores timeout", false, 120 * time.Second, 10 * time.Second},
		{"machine off zero timeout", false, 0, 10 * time.Second},
		{"machine on min timeout adds auth phase and margin", true, 1 * time.Second, 16 * time.Second},
		{"machine on default 10s timeout", true, 10 * time.Second, 25 * time.Second},
		{"machine on 60s timeout", true, 60 * time.Second, 75 * time.Second},
		{"machine on config max 5m", true, 5 * time.Minute, 315 * time.Second},
		{"machine on above bound is clamped", true, 10 * time.Minute, 315 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shutdownGrace(tc.enabled, tc.timeout); got != tc.want {
				t.Fatalf("shutdownGrace(%v, %v) = %v, want %v", tc.enabled, tc.timeout, got, tc.want)
			}
		})
	}
}
