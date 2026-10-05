package backup

import (
	"fmt"
	"regexp"
	"time"
)

type Policy struct {
	Enabled         bool     `json:"enabled"`
	IntervalMinutes int      `json:"interval_minutes"`
	KeepDays        int      `json:"keep_days"`
	KeepCount       int      `json:"keep_count"`
	Destinations    []string `json:"destinations"`
}
type Policies struct {
	Revision uint64 `json:"revision"`
	Data     Policy `json:"data"`
	Logs     Policy `json:"logs"`
}
type Destination struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}
type State struct {
	LocalVerified    bool      `json:"local_verified"`
	LastLocalSuccess time.Time `json:"last_local_success"`
	Status           string    `json:"status"`
	LastAttempt      time.Time `json:"last_attempt"`
	LastSuccess      time.Time `json:"last_success"`
	NextRun          time.Time `json:"next_run"`
	RunID            string    `json:"run_id"`
	PolicyRevision   uint64    `json:"policy_revision"`
}
type Storage struct {
	Bytes       int64 `json:"bytes"`
	Copies      int   `json:"copies"`
	LatestBytes int64 `json:"latest_bytes"`
}
type View struct {
	Connections   []PublicConnection `json:"connections"`
	Storage       map[string]Storage `json:"storage"`
	Policies      Policies           `json:"policies"`
	Destinations  []Destination      `json:"destinations"`
	States        map[string]State   `json:"states"`
	Running       bool               `json:"running"`
	LogsAvailable bool               `json:"logs_available"`
}

var safeID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func validate(p Policy, destinations []Destination) error {
	if p.IntervalMinutes < 1 || p.IntervalMinutes > 525600 || p.KeepDays < 1 || p.KeepDays > 3650 || p.KeepCount < 1 || p.KeepCount > 10000 {
		return fmt.Errorf("invalid interval or retention bounds")
	}
	if len(p.Destinations) == 0 || len(p.Destinations) > 20 {
		return fmt.Errorf("select 1–20 registered destinations")
	}
	seen := map[string]bool{}
	for _, id := range p.Destinations {
		found := false
		for _, d := range destinations {
			if d.ID == id {
				found = true
			}
		}
		if !found || seen[id] {
			return fmt.Errorf("unknown or duplicate destination")
		}
		seen[id] = true
	}
	if !seen["local"] {
		return fmt.Errorf("local backup destination is required")
	}
	return nil
}
func defaultPolicies() Policies {
	return Policies{Data: Policy{IntervalMinutes: 1440, KeepDays: 30, KeepCount: 30, Destinations: []string{"local"}}, Logs: Policy{IntervalMinutes: 60, KeepDays: 7, KeepCount: 168, Destinations: []string{"local"}}}
}
