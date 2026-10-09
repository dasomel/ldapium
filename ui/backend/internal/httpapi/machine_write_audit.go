package httpapi

import (
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// D6/Q4: write metadata is appended to the existing single machine_access
// line, with target/key fingerprints by default. No body, tag, token or secret
// value is retained. Cost: fingerprints do not reveal the target; escape hatch:
// opt into a validated plaintext target DN explicitly in operator config.
// T-013 must set this state before route middleware/early write rejections.
type machineWriteAuditFields struct {
	TargetFingerprint      string `json:"target_dn_fingerprint,omitempty"`
	TargetDN               string `json:"target_dn,omitempty"`
	IfMatch                bool   `json:"if_match"`
	Idempotent             bool   `json:"idempotent"`
	IdempotencyFingerprint string `json:"idempotency_key_fingerprint,omitempty"`
	LDAPResult             *int   `json:"ldap_result,omitempty"`
	Replayed               bool   `json:"replayed"`
}

func (s *machineAuditState) setWrite(target, key string, ifMatch, plaintext bool) {
	if s == nil {
		return
	}
	fields := &machineWriteAuditFields{IfMatch: ifMatch, Idempotent: key != ""}
	if target != "" {
		fields.TargetFingerprint = fingerprintIdentity(target)
	}
	if key != "" {
		fields.IdempotencyFingerprint = fingerprintIdentity(key)
	}
	if plaintext && len(target) <= 4096 && !strings.ContainsAny(target, "\r\n\x00") {
		if dn, err := ldap.ParseDN(target); err == nil && len(dn.RDNs) > 0 {
			fields.TargetDN = target
		}
	}
	s.write = fields
}

func (s *machineAuditState) setWriteResult(code int, replayed bool) {
	if s == nil || s.write == nil {
		return
	}
	s.write.Replayed = replayed
	s.write.LDAPResult = nil
	if code >= 0 && code <= 255 {
		value := code
		s.write.LDAPResult = &value
	}
}
