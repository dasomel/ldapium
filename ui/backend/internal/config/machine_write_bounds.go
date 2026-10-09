package config

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/dasomel/ldapium/ui/backend/internal/idempotency"
)

var writeBoundsBER = regexp.MustCompile(`=\s*#`)

// D8/D22/D23: client-specific bounds are parsed only behind the write switch.
// JSON maps preserve DN commas/escapes. Cost: explicit client inventory and
// bounded DN counts; escape hatch: disable writes, never ignore invalid bounds.
func loadMachineWriteBounds(getenv func(string) string, cfg Config, m MachineConfig, w *MachineWriteConfig) error {
	var err error
	if w.AuditTargetDNPlaintext, err = boolEnv(getenv, "MACHINE_WRITE_AUDIT_TARGET_DN_PLAINTEXT", false); err != nil {
		return err
	}
	if w.Subtrees, err = parseMachineWriteDNMap(getenv("MACHINE_WRITE_SUBTREES"), m.Clients); err != nil {
		return fmt.Errorf("MACHINE_WRITE_SUBTREES: %w", err)
	}
	if w.Groups, err = parseMachineWriteDNMap(getenv("MACHINE_WRITE_GROUPS"), m.Clients); err != nil {
		return fmt.Errorf("MACHINE_WRITE_GROUPS: %w", err)
	}
	raw := strings.TrimSpace(getenv("MACHINE_WRITE_PRIVILEGED_GROUPS"))
	if len(raw) > 64<<10 {
		return fmt.Errorf("MACHINE_WRITE_PRIVILEGED_GROUPS exceeds 64 KiB")
	}
	if raw != "" {
		dec := json.NewDecoder(strings.NewReader(raw))
		if dec.Decode(&w.PrivilegedGroups) != nil || w.PrivilegedGroups == nil {
			return fmt.Errorf("MACHINE_WRITE_PRIVILEGED_GROUPS requires a JSON DN array")
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return fmt.Errorf("MACHINE_WRITE_PRIVILEGED_GROUPS has trailing data")
		}
	}
	if len(w.PrivilegedGroups) > 64 {
		return fmt.Errorf("MACHINE_WRITE_PRIVILEGED_GROUPS exceeds 64 DNs")
	}
	base, err := canonicalWriteBoundDN(cfg.BaseDN)
	if err != nil {
		return fmt.Errorf("machine write base requires canonical naming types")
	}
	eligible := 0
	for _, dns := range w.Subtrees {
		if len(dns) > 0 {
			eligible++
		}
		for _, raw := range dns {
			dn, _ := canonicalWriteBoundDN(raw)
			if !base.EqualFold(dn) && !base.AncestorOfFold(dn) {
				return fmt.Errorf("MACHINE_WRITE_SUBTREES entry is outside LDAP_BASE_DN")
			}
		}
	}
	for _, raw := range w.PrivilegedGroups {
		if _, err := canonicalWriteBoundDN(raw); err != nil {
			return fmt.Errorf("MACHINE_WRITE_PRIVILEGED_GROUPS has a noncanonical DN")
		}
	}
	for client, dns := range w.Groups {
		for _, raw := range dns {
			group, _ := canonicalWriteBoundDN(raw)
			inside := false
			for _, subtree := range w.Subtrees[client] {
				bound, _ := canonicalWriteBoundDN(subtree)
				inside = inside || bound.AncestorOfFold(group)
			}
			if !inside {
				return fmt.Errorf("MACHINE_WRITE_GROUPS entry must be strictly within its client's write subtree")
			}
			for _, denied := range w.PrivilegedGroups {
				privileged, _ := canonicalWriteBoundDN(denied)
				if privileged.EqualFold(group) || privileged.AncestorOfFold(group) {
					return fmt.Errorf("MACHINE_WRITE_GROUPS contains a privileged group")
				}
			}
		}
	}
	// The store uses these defaults (newIdempotency), so every bounded writing
	// client can fill its own quota without exhausting another client's share.
	if eligible > idempotency.DefaultMaxRecords/idempotency.DefaultMaxPerSubject {
		return fmt.Errorf("machine write clients exceed the idempotency subject quota capacity")
	}
	n := machineInts{getenv: getenv}
	w.RateLimitRPS = n.get("MACHINE_WRITE_RATE_LIMIT_RPS", 1, 1, 1000)
	w.RateLimitBurst = n.get("MACHINE_WRITE_RATE_LIMIT_BURST", 1, 1, 1000)
	w.MaxConcurrency = n.get("MACHINE_WRITE_MAX_CONCURRENCY", 2, 1, 64)
	return n.err
}

func canonicalWriteBoundDN(raw string) (*ldap.DN, error) {
	if len(raw) > 4096 || writeBoundsBER.MatchString(raw) {
		return nil, fmt.Errorf("requires a canonical DN")
	}
	dn, err := ldap.ParseDN(raw)
	if err != nil || !writeIdentityDNUnambiguous(dn) {
		return nil, fmt.Errorf("requires a canonical DN")
	}
	return dn, nil
}

func parseMachineWriteDNMap(raw string, clients []MachineClient) (map[string][]string, error) {
	result := map[string][]string{}
	if strings.TrimSpace(raw) == "" {
		return result, nil
	}
	if len(raw) > 64<<10 {
		return nil, fmt.Errorf("JSON map exceeds 64 KiB")
	}
	allowed := map[string]bool{}
	for _, client := range clients {
		allowed[client.ID] = true
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("requires a JSON client-to-DN-array map")
	}
	total := 0
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid client map")
		}
		client, ok := token.(string)
		if !ok || !allowed[client] {
			return nil, fmt.Errorf("client is not in MACHINE_ALLOWED_CLIENTS")
		}
		if _, duplicate := result[client]; duplicate {
			return nil, fmt.Errorf("duplicate client entry")
		}
		var dns []string
		if dec.Decode(&dns) != nil || dns == nil || len(dns) > 64 {
			return nil, fmt.Errorf("client requires a JSON array of at most 64 DNs")
		}
		total += len(dns)
		if total > 1024 {
			return nil, fmt.Errorf("DN map exceeds 1024 entries")
		}
		for _, raw := range dns {
			if _, err := canonicalWriteBoundDN(raw); err != nil {
				return nil, err
			}
		}
		result[client] = dns
	}
	token, err = dec.Token()
	if err != nil || token != json.Delim('}') {
		return nil, fmt.Errorf("invalid client map")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return result, nil
}
