package domain

// MonitorStats is a curated view of slapd's cn=Monitor subtree (back_monitor,
// enabled by default — see image/ldifs/01-cn-config.ldif). It exists for the
// admin UI's health view: a status snapshot, not the full monitor tree
// (which also carries live connection lists and per-listener detail nobody
// browsing a health page needs).
type MonitorStats struct {
	ConnectionsCurrent int `json:"connectionsCurrent"`
	ConnectionsTotal   int `json:"connectionsTotal"`
	ConnectionsMaxFDs  int `json:"connectionsMaxFds"`

	Operations []OperationCounter `json:"operations"`

	BytesSent   int64 `json:"bytesSent"`
	EntriesSent int64 `json:"entriesSent"`

	ThreadsMax        int `json:"threadsMax"`
	ThreadsMaxPending int `json:"threadsMaxPending"`
	ThreadsActive     int `json:"threadsActive"`

	WaitersRead   int   `json:"waitersRead"`
	WaitersWrite  int   `json:"waitersWrite"`
	UptimeSeconds int64 `json:"uptimeSeconds"`

	ReplicationCSNs []ReplicationCSN `json:"replicationCsns,omitempty"`

	// Database* describe the primary data database (the one whose
	// namingContexts matches the deployment's configured base DN), not
	// cn=config or cn=Monitor's own internal database entries.
	DatabasePagesUsed int64 `json:"databasePagesUsed"`
	DatabasePagesMax  int64 `json:"databasePagesMax"`
	DatabasePagesFree int64 `json:"databasePagesFree"`
	DatabaseEntries   int64 `json:"databaseEntries"`

	RecentLogs []AuditEvent `json:"recentLogs,omitempty"`
}

// ReplicationCSN describes the replication state for one provider node
// reported via contextCSN on the base DN.
type ReplicationCSN struct {
	ServerID  string `json:"serverId"`
	CSN       string `json:"csn"`
	Timestamp string `json:"timestamp,omitempty"`
}

// OperationCounter is slapd's initiated/completed count for one LDAP
// operation type (Bind, Search, Add, ...). Completed can lag Initiated
// under load or, sustained, indicate operations that never finish.
type OperationCounter struct {
	Name      string `json:"name"`
	Initiated int64  `json:"initiated"`
	Completed int64  `json:"completed"`
}
