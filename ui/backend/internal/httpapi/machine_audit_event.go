package httpapi

// machineEvent is the structured record. token_fingerprint and subject_fingerprint
// are omitted when empty; bind_dn only appears when the request reached the
// directory identity.
type machineEvent struct {
	TargetFingerprint      string `json:"target_dn_fingerprint,omitempty"`
	TargetDN               string `json:"target_dn,omitempty"`
	IfMatch                *bool  `json:"if_match,omitempty"`
	Idempotent             *bool  `json:"idempotent,omitempty"`
	IdempotencyFingerprint string `json:"idempotency_key_fingerprint,omitempty"`
	LDAPResult             *int   `json:"ldap_result,omitempty"`
	Replayed               *bool  `json:"replayed,omitempty"`

	Event              string `json:"event"`
	Provider           string `json:"provider"`
	Actor              string `json:"actor"`
	RequestID          string `json:"request_id"`
	Operation          string `json:"operation"`
	Method             string `json:"method"`
	Status             int    `json:"status"`
	Result             string `json:"result"`
	Reason             string `json:"reason"`
	TokenFingerprint   string `json:"token_fingerprint,omitempty"`
	SubjectFingerprint string `json:"subject_fingerprint,omitempty"`
	BindDN             string `json:"bind_dn,omitempty"`
}

// machineEventInput is everything buildMachineEvent decides from. Nothing in
// it is a token or a raw error.
type machineEventInput struct {
	RequestID   string
	Method      string
	Status      int
	EnvelopeErr string // the response's error-envelope code, "" on success
	Reason      string
	Actor       string
	SubjectFP   string
	Operation   string
	BindDN      string
	TokenFP     string
	Write       *machineWriteAuditFields
}
