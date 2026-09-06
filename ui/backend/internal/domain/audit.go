package domain

// AuditEvent represents an identity audit event matching the canonical
// envelope documented in docs/audit-event-schema.md.
type AuditEvent struct {
	SchemaVersion string   `json:"schemaVersion"`
	Source        string   `json:"source"`
	Seq           int      `json:"seq"`
	Time          *string  `json:"time"`
	Actor         string   `json:"actor"`
	Target        *string  `json:"target"`
	Op            string   `json:"op"`
	Result        string   `json:"result"`
	ObjectId      *string  `json:"objectId"`
	CorrelationId string   `json:"correlationId"`
	Privileged    bool     `json:"privileged"`
	Raw           AuditRaw `json:"raw"`
}

// AuditRaw holds source-specific raw fields emitted by cn=accesslog,
// with attribute names only in ChangedAttrs (never values or passwords)
// and search filters redacted.
type AuditRaw struct {
	ReqSession   string   `json:"reqSession,omitempty"`
	ReqType      string   `json:"reqType,omitempty"`
	ReqDN        string   `json:"reqDN,omitempty"`
	ReqAuthzID   string   `json:"reqAuthzID,omitempty"`
	ReqResult    string   `json:"reqResult,omitempty"`
	ReqStart     string   `json:"reqStart,omitempty"`
	ReqEnd       string   `json:"reqEnd,omitempty"`
	ChangedAttrs []string `json:"changedAttrs,omitempty"`
	Filter       string   `json:"filter,omitempty"`
}
