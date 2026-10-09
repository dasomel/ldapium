package httpapi

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestMachineWriteAuditSingleLineMetadata(t *testing.T) {
	const target = "uid=target,dc=example,dc=org"
	const secret = "SENTINEL-KEY-TOKEN-PASSWORD"
	for _, tc := range []struct {
		status, ldap int
		replay       bool
	}{{428, -1, false}, {412, 122, false}, {403, 50, false}, {204, 0, false}, {204, -1, true}} {
		state := &machineAuditState{}
		state.setWrite(target, secret, true, false)
		state.setWriteResult(tc.ldap, tc.replay)
		event := buildMachineEvent(machineEventInput{Status: tc.status, Actor: "machine-a", Operation: "patchUser", Write: state.write})
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var decoded machineEvent
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if strings.Contains(text, secret) || strings.Contains(text, target) || strings.Contains(text, "\n") {
			t.Fatalf("raw value/newline exposed: %s", text)
		}
		if event.TargetFingerprint == "" || event.IdempotencyFingerprint == "" || event.Idempotent == nil || !*event.Idempotent || event.IfMatch == nil || !*event.IfMatch || event.Replayed == nil || *event.Replayed != tc.replay {
			t.Fatalf("missing write metadata: %s", text)
		}
		if (event.LDAPResult == nil) != (tc.ldap < 0) {
			t.Fatal("unknown LDAP result fabricated")
		}
	}
}

func TestMachineWriteAuditPlaintextOptInAndReadCompatibility(t *testing.T) {
	state := &machineAuditState{}
	state.setWrite("uid=target,dc=example,dc=org", "", false, true)
	event := buildMachineEvent(machineEventInput{Status: 428, Write: state.write})
	if event.TargetDN == "" || event.IfMatch == nil || *event.IfMatch || event.Idempotent == nil || *event.Idempotent {
		t.Fatal("plaintext/header flags")
	}
	raw, _ := json.Marshal(event)
	if !strings.Contains(string(raw), `"if_match":false`) || !strings.Contains(string(raw), `"idempotent":false`) {
		t.Fatal("missing false flags on write")
	}
	state.setWrite("uid=target\nsecret,dc=example,dc=org", "", false, true)
	if state.write.TargetDN != "" {
		t.Fatal("unvalidated plaintext target logged")
	}
	read, _ := json.Marshal(buildMachineEvent(machineEventInput{Status: 200, Method: "GET"}))
	for _, field := range []string{"if_match", "idempotent", "replayed", "target_dn", "ldap_result"} {
		if strings.Contains(string(read), field) {
			t.Fatalf("read event gained %s", field)
		}
	}
}

func TestMachineWriteAuditEmitsOneLogLine(t *testing.T) {
	old := log.Writer()
	var output bytes.Buffer
	log.SetOutput(&output)
	defer log.SetOutput(old)
	state := &machineAuditState{}
	state.setWrite("uid=target,dc=example,dc=org", "SENTINEL-SECRET", true, false)
	logMachineEvent(buildMachineEvent(machineEventInput{Status: 412, Write: state.write}))
	if strings.Count(output.String(), "\n") != 1 || strings.Contains(output.String(), "SENTINEL-SECRET") {
		t.Fatalf("invalid audit line: %q", output.String())
	}
}
