package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/labstack/echo/v4"

	"github.com/dasomel/ldapium/ui/backend/internal/domain"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/machineauth"
	"github.com/dasomel/ldapium/ui/backend/internal/validate"
)

// The machine write pipeline (machine-write-scope T-012, T-014, T-016..T-019).
// ONE path, in this EXACT security order; each step fails closed with its own
// audit outcome and nothing opens an LDAP connection before step 8:
//
//	1  verify token + revocation check          machineAuth.serve (existing hook, before this)
//	2  operation lookup + scope ceiling         D7, REQ-003: scope must be in THIS client's ceiling
//	3  write limiter admission                  D8d, REQ-008: own budget, 1 per client, global slots;
//	                                            the read budget is neither spent nor consulted;
//	                                            released by defer on return, panic, cancel, timeout
//	4  body/param parse + strict DN checks      D20/B2 strict descendant (parent only for create),
//	                                            D26/B5 canonical form (no OID types, odd whitespace)
//	5  revocations subtree, protected DNs,      D19/B1 + D22/B4 (group allowlist; privileged groups
//	   group allowlist                          are in the protected set)
//	6  If-Match: one concrete strong tag        D21/B3 -> 428 if_match_required
//	7  AUTHORIZATION COMPLETE. Only now: require Idempotency-Key (428), derive the idempotency
//	   subject (D9: issuer+client) and begin the record (D23). Every request, a replay included,
//	   has already passed steps 2-6, so a replay after a revoked scope or ceiling answers 403 and
//	   never the stored 2xx, and nothing about a stored key is observable to an unauthorized caller.
//	8  bind DN by compartment (data -> W_data, lock -> W_lock; never M, never an administrator),
//	   then the M pre-read of the target (entryDN/entryUUID against the protected entries and the
//	   objectClass assertion, D26/D19e) through writeIdentityChecker
//	9  execute with the per-request deadline and the machine-write assertion marker, using the
//	   existing handlers and normalisation; generatedPassword cannot occur (closed body, D16)
//	10 one audit line with the write fields on EVERY path (machineAuditMiddleware owns the line,
//	   including early returns and panic; this file only fills the write fields)
//	11 errors map through the existing envelope: 412 revision_conflict, 403, 409, 503
//
// Cost: steps 4-6 run before the idempotency lookup, so a retry costs a parse and a
// policy evaluation (no LDAP). Escape hatch: MACHINE_WRITE_ENABLED=false.

// machineIdempotencyDoneKey tells the route-level idempotent() wrapper that this
// request already began its record at step 7.
const machineIdempotencyDoneKey = "machine_idempotency_done"

// writeIdentityChecker is the M pre-read (ldapclient.WriteIdentityReader in
// production); tests inject a fake because the real one dials a server.
type writeIdentityChecker interface {
	Check(ctx context.Context, target, requiredClass string) error
	// CheckNotPrivileged refuses a target that is a member of a privileged group.
	CheckNotPrivileged(ctx context.Context, target string) error
}

type machineWritePipeline struct {
	s     *Server
	m     *machineAuth
	ops   map[string]machineWriteOp
	exec  *machineExecutor
	ident writeIdentityChecker
	// hook is nil in production; tests record the stage order or panic at a stage.
	hook func(stage string)
}

// newMachineWritePipeline returns nil when the write runtime is off, so with
// MACHINE_WRITE_ENABLED unset no table is consulted at all. The opened table is
// machineWriteOps (nine operations, T-013/T-014) unless a test injects its own through machineDeps.
func (s *Server) newMachineWritePipeline(dialer ldapclient.Dialer) (*machineWritePipeline, error) {
	rt := s.machineWrite
	if rt == nil {
		return nil, nil
	}
	opened := machineWriteOps
	var ident writeIdentityChecker = rt.identity
	if d := s.machineTest; d != nil {
		if d.writeOps != nil {
			opened = d.writeOps
		}
		if d.writeIdentity != nil {
			ident = d.writeIdentity
		}
	}
	ops, err := resolveMachineWriteOps(opened)
	if err != nil {
		return nil, err
	}
	return &machineWritePipeline{s: s, m: s.machine, ops: ops, exec: newMachineExecutor(s.cfg.Machine, dialer), ident: ident}, nil
}

func (w *machineWritePipeline) lookup(method, route string) (machineWriteOp, bool) {
	op, ok := w.ops[method+" "+route]
	return op, ok
}

func (w *machineWritePipeline) stage(name string) {
	if w.hook != nil {
		w.hook(name)
	}
}

// writeDN is one DN the request names. parent allows the subtree root itself
// (create parent only); class is the objectClass an existing entry must have.
type writeDN struct {
	raw    string
	parent bool
	class  string
}

// wreq is one request through the pipeline.
type wreq struct {
	w       *machineWritePipeline
	c       echo.Context
	p       *machineauth.Principal
	op      machineWriteOp
	st      *machineAuditState
	next    echo.HandlerFunc
	pol     machineWritePolicy
	dns     []writeDN
	csn     string
	release func()
}

func (w *machineWritePipeline) serve(c echo.Context, p *machineauth.Principal, op machineWriteOp, next echo.HandlerFunc) error {
	st := auditStateOf(c)
	st.setOperation(op.ID)
	st.setWrite(machineWriteInput{Scope: op.Scope, Compartment: op.Compartment, TargetKind: op.Kind})
	r := &wreq{w: w, c: c, p: p, op: op, st: st, next: next}
	defer func() {
		if r.release != nil {
			r.release()
		}
	}()
	if err := r.authorize(); err != nil {
		return err
	}
	err := r.step7Idempotency()
	r.classify(err)
	return err
}

// authorize runs steps 2-6.
func (r *wreq) authorize() error {
	for _, step := range []func() error{r.step2Scope, r.step3Admit, r.step4Parse, r.step5Denylist, r.step6IfMatch} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func (r *wreq) setOutcome(o string) {
	if r.st != nil && r.st.write != nil {
		r.st.write.Outcome = o
	}
}

func (r *wreq) deny(reason, outcome, code, msg string) error {
	r.st.setReason(reason)
	r.setOutcome(outcome)
	return apiErr(http.StatusForbidden, code, msg)
}

func (r *wreq) reject(status int, code, msg string) error {
	r.st.setReason(reasonRequestRejected)
	r.setOutcome(outcomeRejected)
	return apiErr(status, code, msg)
}

// step2Scope: the write scope must be in this client's ceiling and in the token,
// and the client must have a write subtree at all (D8a: empty means no writes).
func (r *wreq) step2Scope() error {
	r.w.stage("scope")
	_, hasPolicy := r.w.s.machineWrite.policies[r.p.ClientID]
	if !hasPolicy || !scopeAllows(r.w.m.ceilings[r.p.ClientID], r.p.Scopes, r.op.Scope) {
		return r.deny(reasonScope, outcomeDeniedGuard, codeScopeDenied, "insufficient scope")
	}
	return nil
}

// step3Admit takes the write budget, the client's single write slot and a
// global write slot. The release is registered by serve's defer.
func (r *wreq) step3Admit() error {
	r.w.stage("limiter")
	release, retry, err := r.w.s.machineWrite.limiter.acquire(r.c.Request().Context(), r.p.ClientID)
	switch {
	case err == nil:
		r.release = release
		return nil
	case errors.Is(err, errMachineWriteRate):
		r.st.forceReason(reasonRate)
		r.setOutcome(outcomeRejected)
		return rateLimited(r.c, retry, "client write budget exhausted")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		r.st.setReason(reasonCanceled)
	default:
		r.st.setReason(reasonCapacity)
	}
	r.setOutcome(outcomeRejected)
	r.c.Response().Header().Set(echo.HeaderRetryAfter, "1")
	return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine write concurrency limit reached")
}

// step4Parse reads the body and parameters (closed sets only) and applies the
// pre-connect DN checks: canonical form (D26) and the strict ceiling (D20).
func (r *wreq) step4Parse() error {
	r.w.stage("parse")
	pol, ok := r.w.s.machineWrite.policies[r.p.ClientID]
	if !ok {
		return r.deny(reasonScope, outcomeDeniedGuard, codeScopeDenied, "no write subtree for this client")
	}
	r.pol = pol
	req := r.c.Request()
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxIdempotencyRequestBody+1))
	if err != nil || len(raw) > maxIdempotencyRequestBody {
		return r.reject(http.StatusBadRequest, codeInvalidRequest, "request body too large or unreadable")
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	if r.dns, err = r.parseDNs(raw); err != nil {
		return r.reject(http.StatusBadRequest, codeInvalidRequest, err.Error())
	}
	if r.st.write != nil {
		r.st.write.TargetDN = r.dns[0].raw
	}
	for _, d := range r.dns {
		if _, ok := machineWriteDN(d.raw); !ok {
			return r.deny(reasonScope, outcomeDeniedGuard, codeScopeDenied, msgWriteDNRefused)
		}
		if !pol.withinCeiling(d.raw, d.parent) {
			return r.deny(reasonScope, outcomeDeniedGuard, codeScopeDenied, msgWriteDNRefused)
		}
	}
	return nil
}

const msgWriteDNRefused = "dn is not permitted for this machine client"

// parseDNs extracts the DNs of the request. The first entry is the audit target.
func (r *wreq) parseDNs(raw []byte) ([]writeDN, error) {
	req := r.c.Request()
	var get func(name string) (string, bool)
	allowed := map[string]bool{}
	switch r.op.Shape {
	case shapeCreate:
		allowed["uid"] = r.op.Kind != "group"
		allowed["cn"] = r.op.Kind == "group"
	case shapeTarget:
		allowed["dn"] = true
	case shapeMembership:
		allowed["groupDn"], allowed["memberDn"] = true, true
	}
	if r.op.InQuery {
		if len(bytes.TrimSpace(raw)) != 0 {
			return nil, errors.New("this operation takes no request body")
		}
		q := req.URL.Query()
		for k, v := range q {
			if !allowed[k] || len(v) != 1 {
				return nil, errors.New("unexpected query parameter")
			}
		}
		get = func(name string) (string, bool) { v := q[name]; return strings.Join(v, ""), len(v) == 1 }
	} else {
		if len(req.URL.Query()) != 0 {
			return nil, errors.New("this operation takes no query parameters")
		}
		if !machineWriteBodyAllowed(r.op.ID, raw) {
			return nil, errors.New("request body is not a permitted machine write body")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, errors.New("invalid request body")
		}
		get = bodyString(fields)
	}
	need := func(name string) (string, error) {
		v, ok := get(name)
		if !ok || v == "" {
			return "", errors.New(name + " is required")
		}
		return v, nil
	}
	switch r.op.Shape {
	case shapeCreate:
		if r.op.Kind == "group" {
			cn, err := need("cn")
			if err != nil {
				return nil, err
			}
			return groupCreateDNs(cn, r.w.s.cfg.GroupCreateBase)
		}
		uid, err := need("uid")
		if err != nil {
			return nil, err
		}
		if err := validate.UID(uid); err != nil {
			return nil, err
		}
		base := r.w.s.cfg.UserCreateBase
		return []writeDN{{raw: "uid=" + uid + "," + base}, {raw: base, parent: true}}, nil
	case shapeTarget:
		dn, err := need("dn")
		if err != nil {
			return nil, err
		}
		return []writeDN{{raw: dn, class: r.op.Class}}, nil
	default:
		group, err := need("groupDn")
		if err != nil {
			return nil, err
		}
		member, err := need("memberDn")
		if err != nil {
			return nil, err
		}
		return []writeDN{{raw: group, class: r.op.Class}, {raw: member, class: r.op.MemberClass}}, nil
	}
}

// groupCreateDNs is the create shape of a group: cn under GroupCreateBase (the
// parent, which may equal a ceiling root). The DN the guards judge must be the
// DN the directory will create, so a cn that does not parse back as exactly one
// plain RDN value (comma, escape, multi-valued or BER spelling) is refused.
func groupCreateDNs(cn, base string) ([]writeDN, error) {
	if err := validate.CN(cn); err != nil {
		return nil, err
	}
	raw := "cn=" + cn + "," + base
	dn, err := ldap.ParseDN(raw)
	if err != nil || len(dn.RDNs) < 2 || len(dn.RDNs[0].Attributes) != 1 || dn.RDNs[0].Attributes[0].Value != cn {
		return nil, errors.New("cn is not permitted for a machine-created group")
	}
	return []writeDN{{raw: raw}, {raw: base, parent: true}}, nil
}

func bodyString(fields map[string]json.RawMessage) func(string) (string, bool) {
	return func(name string) (string, bool) {
		var s string
		v, ok := fields[name]
		return s, ok && json.Unmarshal(v, &s) == nil && s != ""
	}
}

// step5Denylist: revocation subtree and protected identities for every DN
// (parent included), then the writable-group allowlist for membership (D22).
func (r *wreq) step5Denylist() error {
	r.w.stage("denylist")
	for _, d := range r.dns {
		if err := r.w.s.revocationWriteGuard(d.raw); err != nil || r.pol.isProtected(d.raw) {
			return r.deny(reasonScope, outcomeDeniedProtected, codeScopeDenied, msgWriteDNRefused)
		}
	}
	// D379-4: a created group is not on the list, so patch/delete/member changes
	// on it stay refused until the operator lists its exact DN.
	if r.op.Kind == "group" && r.op.Shape != shapeCreate && !r.pol.groupListed(r.dns[0].raw) {
		return r.deny(reasonScope, outcomeDeniedGuard, codeScopeDenied, "group is not writable for this machine client")
	}
	return nil
}

// step6IfMatch: modifications need exactly one concrete strong entryCSN tag.
func (r *wreq) step6IfMatch() error {
	r.w.stage("ifmatch")
	if r.st.write != nil {
		r.st.write.IfMatch = len(r.c.Request().Header.Values("If-Match")) > 0
	}
	if !r.op.IfMatch {
		return nil
	}
	csn, err := machineIfMatch(r.c)
	if err != nil {
		r.st.setReason(reasonRequestRejected)
		if he, ok := err.(*echo.HTTPError); ok && he.Code == http.StatusPreconditionRequired {
			r.setOutcome(outcomePreconditionFailed)
		} else {
			r.setOutcome(outcomeRejected)
		}
		return err
	}
	r.csn = csn
	return nil
}

// step7Idempotency: authorization is complete. The principal key is set only
// here, so nothing before this point can derive an idempotency subject.
func (r *wreq) step7Idempotency() error {
	r.w.stage("idempotency")
	if len(r.c.Request().Header.Values(headerIdempotencyKey)) == 0 {
		return r.reject(http.StatusPreconditionRequired, codeIdempotencyKeyRequired, "Idempotency-Key is required for machine writes")
	}
	if r.w.s.idem == nil {
		r.st.setReason(reasonUpstream)
		r.setOutcome(outcomeRejected)
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine write idempotency is unavailable")
	}
	r.c.Set(machinePrincipalKey, r.p)
	subject, err := machineIdempotencySubject(r.c, r.w.s.cfg.Machine.IssuerURL, "")
	if err != nil {
		return err
	}
	if r.st.write != nil {
		r.st.write.Subject = subject
	}
	return r.w.s.idempotent(r.execute, false)(r.c)
}

// execute is steps 8 and 9; it runs inside the idempotency record, so a replay
// never reaches it and a refusal before the write releases the key.
func (r *wreq) execute(c echo.Context) error {
	r.w.stage("execute")
	// Nothing has been sent to the directory yet, so a failure here is definitive
	// and must not burn the key as outcome_unknown.
	markDefinitive(c)
	id, ok := writeBindIdentity(r.w.s.cfg.Machine.Write, r.op.Compartment)
	if !ok {
		r.st.setReason(reasonBindFailed)
		r.setOutcome(outcomeRejected)
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine write identity is not configured")
	}
	seed := r.w.s.cfg.Machine.Write.GroupSeedDN
	if r.op.ID == "createGroup" && seed == "" {
		r.st.setReason(reasonUpstream)
		r.setOutcome(outcomeRejected)
		return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine group seed is not configured")
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), r.w.exec.timeout)
	defer cancel()
	for _, d := range r.dns {
		if d.class == "" {
			continue
		}
		if err := r.w.ident.Check(ctx, d.raw, d.class); err != nil {
			return r.identityRefusal(err)
		}
	}
	// D379-8 (REQ-007): a member of a privileged group is never locked by a
	// machine. This is an M read of the target's memberOf, before the W bind.
	if r.op.ID == "lockUser" {
		if err := r.w.ident.CheckNotPrivileged(ctx, r.dns[0].raw); err != nil {
			return r.identityRefusal(err)
		}
	}
	// runAs derives its own timeout from the request context: handing it ours
	// keeps the M pre-read and the write inside ONE MACHINE_REQUEST_TIMEOUT
	// (emergency-block and shutdown-grace bounds), not two back to back.
	c.SetRequest(c.Request().WithContext(ctx))
	return r.w.exec.runAs(c, r.p, id.BindDN, id.BindPassword, func(c echo.Context) error {
		c.Set(definitiveKey, false) // from here on a 5xx may hide an applied write
		c.Set(machineIdempotencyDoneKey, true)
		ctx := ldapclient.WithMachineWriteConstraints(c.Request().Context())
		if r.op.ID == "createGroup" {
			ctx = ldapclient.WithMachineGroupSeed(ctx, seed)
		}
		c.SetRequest(c.Request().WithContext(ctx))
		return r.next(c)
	})
}

// identityRefusal maps an M pre-read failure to the response of step 8.
func (r *wreq) identityRefusal(err error) error {
	if errors.Is(err, domain.ErrPermissionDenied) || errors.Is(err, domain.ErrInvalidInput) {
		return r.deny(reasonScope, outcomeDeniedProtected, codeScopeDenied, "target is not permitted for machine writes")
	}
	if errors.Is(err, domain.ErrNotFound) {
		// Only a genuine noSuchObject for the target reaches here; the
		// scope/protected guards above already ran, so existence outside
		// the client's subtree is never disclosed.
		r.st.setReason(reasonRequestRejected)
		r.setOutcome(outcomeTargetNotFound)
		return apiErr(http.StatusNotFound, codeNotFound, domain.ErrNotFound.Error())
	}
	r.st.setReason(reasonUpstream)
	r.setOutcome(outcomeRejected)
	return apiErr(http.StatusServiceUnavailable, codeUnavailable, "machine write identity check unavailable")
}

// classify names the audit outcome of a request that got past step 6, unless a
// step already named it. The audit wrapper writes the line itself.
func (r *wreq) classify(err error) {
	if r.st.write == nil || r.st.write.Outcome != "" {
		return
	}
	status := r.c.Response().Status
	var he *echo.HTTPError
	if errors.As(err, &he) {
		status = he.Code
	}
	code, _ := r.c.Get(envelopeCodeKey).(string)
	switch {
	case r.c.Response().Header().Get(headerIdempotentReplayed) == "true":
		r.setOutcome(outcomeReplayed)
	case status >= 200 && status < 300:
		r.setOutcome(outcomeApplied)
	case code == codeIdempotencyOutcomeUnknown:
		r.setOutcome(outcomeOutcomeUnknown)
	case status == http.StatusPreconditionFailed:
		r.setOutcome(outcomePreconditionFailed)
	case r.st.bindDN != "":
		r.setOutcome(outcomeLDAPRefused)
	default:
		r.setOutcome(outcomeRejected)
	}
}
