#!/usr/bin/env python3
"""Live proof of the v2c password step (#379, T-024; AC-009, AC-010, AC-010c; E-10, E-13, E-17).

docs/changes/machine-write-scope-v2, against real slapd. setPassword is still closed in production
(T-026), so the application side is the `live`-tagged Go test TestCredSecretLive
(ui/backend/internal/httpapi/machine_write_cred_live_test.go): the real HTTP pipeline, real dialer,
real M pre-reads, real T-028 premise checker and limiter, with the TEST-ONLY table that adds the
setPassword catalog row (as the unit tests do). It runs inside the slapd container against
ldap://127.0.0.1, as the T-028 proof does.

Per configuration, one fresh container built with the T-028 proof's setup (guide 4.2/4.3, 8.2-8.5,
8.8: reader, canaries in two cred subtrees):

  accepted  accesslog `writes reads bind`, no auditlog: what the chart and T-028 accept
  auditlog  the same plus LDAP_AUDIT_ENABLED=true: what the chart refuses (D379-14 (a))

The Go test runs every path: success, replay, 422, 409, If-Match 400, no key 428, oldPassword 400,
short 400, other client's tag 403, slapd policy refusal (E-10: pending pwdMinLength raised above the
value), a privileged member 403, an LDAP ACL refusal (50), the Q14 stuck state, two requests at once
(E-17 app path: same client five rounds, another client once), the production 1 rps budget (429).
Then this script scans, for the one-time plaintext sentinels (and their base64 forms) and for hash
patterns: every response status/header/body and every server log line (UI audit included), the Go
test's own output, the slapd container log (auditlog stdout in the auditlog configuration), and
cn=accesslog reqMod/reqOld read as the accesslog rootdn and as M (with the M opt-in installed for
that read; the T-028 premise must then refuse to start). A configuration in which a hash shows up
must be one the chart or T-028 refuses (asserted). Last, E-10 by direct W_cred: a pre-hashed 2-char
value through a plain Modify is refused (pwdCheckQuality 2), after the scans because a refused plain
Modify leaves the attempted hash in accesslog (F-8).

Mutation self-test (LDAPIUM_T024_MUTATE builds the Go test from a patched copy):
  log-password             setPassword logs the request's password                      -> must FAIL (scan)
  log-short                the too-short refusal logs the 11-character value             -> must FAIL (scan)
  drop-serialization       per-client write concurrency (D8d) raised AND the per-target
                           lock (T-023) admitting everything                             -> must FAIL (E-17 app path)
  drop-client-concurrency  only the per-client concurrency raised: the T-023 lock alone
                           must still give exactly one success (layer check)             -> must PASS
  drop-target-lock         only the T-023 lock removed: the per-client concurrency
                           alone gives the 429 (T024-F2)                                  -> must PASS

Run (docker, go, helm): python3 scripts/test/test-machine-write-cred-secret-live.py
Override LDAPIUM_IMAGE / LDAPIUM_TEST_PREFIX / LDAPIUM_T024_CONFIGS (accepted,auditlog).
"""
import base64
import hashlib
import importlib.util
import os
import pathlib
import re
import secrets
import shutil
import sys
import tempfile
import time

repo_root = pathlib.Path(__file__).resolve().parents[2]
mutation = os.environ.get('LDAPIUM_T024_MUTATE', '')
MUTATIONS = ('log-password', 'log-short', 'drop-serialization', 'drop-client-concurrency', 'drop-target-lock')
if mutation not in ('',) + MUTATIONS:
  raise SystemExit('LDAPIUM_T024_MUTATE must be one of ' + ', '.join(MUTATIONS))
os.environ.setdefault('LDAPIUM_TEST_PREFIX', 'ldapium-t024-')
_spec = importlib.util.spec_from_file_location('cpre', repo_root / 'scripts/test/test-machine-write-cred-premise-live.py')
pre = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pre)       # its main() does not run; it sets accesslog `writes reads bind`
acl = pre.acl
check, require, mask, run, lcode = acl.check, acl.require, acl.mask, acl.run, acl.lcode
configs = os.environ.get('LDAPIUM_T024_CONFIGS', 'accepted' if mutation else 'accepted,auditlog').split(',')

HASH_RE = re.compile(r'\{(SSHA(256|384|512)?|ARGON2|CRYPT|PBKDF2[^}]*|SHA(256|384|512)?|S?MD5)\}', re.I)
HASH_B64 = ('userPassword::', 'e1NTSEF9', 'e1NTSEEy', 'e1NTSEEz', 'e1NTSEE1', 'e0FSR09OMn0', 'e0NSWVBUfQ', 'e1BCS0RGMi', 'e1NIQX0', 'e1NIQTI', 'e01ENX0', 'e1NNRDV9')
SHORTEST = 11  # the shortest value the Go test sends (MACHINE_WRITE_CRED_MIN_LENGTH - 1)
# ldapclient canaryHashedProbe: {SSHA} of the public 2-character 'zz' with the public salt 'ldapium!'
PROBE_HASH = '{SSHA}' + base64.b64encode(hashlib.sha1(b'zzldapium!').digest() + b'ldapium!').decode()
SENTINELS = ['Aa1-' + secrets.token_hex(14) for _ in range(60)]   # 32 characters each, one-time, never printed
acl.passwords.update({f't024-{i}': s for i, s in enumerate(SENTINELS)})  # mask() hides them in any printed text

_audit = {'on': False}
_run_al = acl.run


def _run_with_audit(cmd, *a, **kw):
  if cmd[:3] == ['docker', 'run', '-d'] and _audit['on']:
    cmd = cmd[:3] + ['-e', 'LDAP_AUDIT_ENABLED=true'] + cmd[3:]
  return _run_al(cmd, *a, **kw)


acl.run = _run_with_audit


def b64_forms(value):
  """The value's base64 spelling at each of the three byte alignments: the encoding of the value behind
  0, 1 or 2 filler bytes, minus the 4 characters at each end the neighbours can change."""
  return [base64.b64encode(b'\0' * shift + value.encode()).decode()[4:-4] for shift in range(3)]


def scan(text):
  """(plaintext sentinel hits, base64 sentinel hits, hash hits) in text; never returns a value.
  The Go test sends whole sentinels and 11-character prefixes of them (the short-value refusal), so every
  form is searched at the shortest length sent: the 11-character prefix (which every whole value contains)
  and the base64 spellings of both lengths."""
  plain = sum(text.count(s[:SHORTEST]) for s in SENTINELS)
  b64 = sum(text.count(f) for s in SENTINELS for v in (s, s[:SHORTEST]) for f in b64_forms(v))
  hashes = len(HASH_RE.findall(text)) + sum(text.count(p) for p in HASH_B64)
  return plain, b64, hashes


def allow_probe(text, canaries):
  """T024-F1 (maintainer 2026-10-14): T-028 check 5's pre-hashed probe is the PUBLIC constant PROBE_HASH
  (ldapclient canaryHashedProbe); its refused plain Modify leaves it in accesslog (F-8). Exactly that one
  string is allowlisted, and only in entries that are that probe (reqType modify, W_cred, a pending canary,
  reqResult 19). Returns (text without the allowlisted occurrences, their count, entries holding it elsewhere)."""
  pending = {c.split('|')[2].lower() for c in canaries}
  keep, allowed, stray = [], 0, 0
  for entry in text.split('\n\n'):
    n = entry.count(PROBE_HASH)
    if n:
      meta = dict((l.split(': ', 1) + [''])[:2] for l in entry.splitlines() if l.split(':')[0] in ('reqType', 'reqDN', 'reqAuthzID', 'reqResult'))
      if (meta.get('reqType') == 'modify' and meta.get('reqResult') == '19' and meta.get('reqDN', '').lower() in pending
          and meta.get('reqAuthzID', '').lower() == acl.wc_dn.lower()):
        allowed += n
        entry = entry.replace(PROBE_HASH, '<allowlisted check-5 probe>')
      else:
        stray += 1
    keep.append(entry)
  return '\n\n'.join(keep), allowed, stray


def build_binary():
  arch = run(['docker', 'info', '--format', '{{.Architecture}}']).stdout.strip()
  goarch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
  src = repo_root / 'ui/backend'
  work = tempfile.mkdtemp(prefix='t024-src-')
  acl.tmp_dirs.append(work)
  if mutation:
    shutil.copytree(src, work + '/backend', ignore=shutil.ignore_patterns('dist', 'node_modules'))
    src = pathlib.Path(work + '/backend')
    patches = []
    if mutation == 'log-password':
      patches.append(('internal/httpapi/machine_write_pipeline.go',
                      r'(func \(r \*wreq\) setPassword\(c echo\.Context, id config\.MachineWriteIdentity\) error \{\n)',
                      r'\1\tlog.Printf("machine_set_password debug value=%s", r.password)\n'))
    if mutation == 'log-short':
      patches.append(('internal/httpapi/machine_write_pipeline.go',
                      r'(\t\treturn errors\.New\("password is shorter than the machine write minimum length"\))',
                      r'\t\tlog.Printf("machine_set_password short value=%s", pw)\n\1'))
    if mutation in ('drop-serialization', 'drop-target-lock'):
      patches.append(('internal/httpapi/machine_write_cred_limiter.go', r'(func \(l \*credLimiter\) lock\(uuid string\) \(func\(\), error\) \{\n)',
                      r'\1\tif true {\n\t\treturn func() {}, nil\n\t}\n'))
    if mutation in ('drop-serialization', 'drop-client-concurrency'):
      patches.append(('internal/httpapi/machine_write_limiter.go', r'newClientBudget\(rps, burst, 1, clients, now\)', 'newClientBudget(rps, burst, 100, clients, now)'))
    n = 0
    for rel, pat, rep in patches:
      f = src / rel
      text, k = re.subn(pat, rep, f.read_text())
      f.write_text(text)
      n += k == 1
    n = 1 if n == len(patches) else 0
    require(n == 1, f'mutation {mutation} did not apply')
  out = work + '/t024-test'
  env = dict(os.environ, GOOS='linux', GOARCH=goarch, CGO_ENABLED='0')
  res = run(['go', 'test', '-tags=live', '-c', '-o', out, './internal/httpapi'], env=env, cwd=str(src), timeout=900)
  require(res.returncode == 0, 'go test -c: ' + res.stderr[-600:])
  return out


def go(node, canaries, test, extra=None):
  env = {'LDAPIUM_CRED_SECRET_LIVE': '1', 'T_BASE': acl.base_dn, 'T_M_DN': acl.machine_dn, 'T_WDATA_DN': acl.wd_dn, 'T_WLOCK_DN': acl.wl_dn,
         'T_WCRED_DN': acl.wc_dn, 'T_READER_DN': pre.reader_dn, 'T_CEIL': acl.managed, 'T_CRED': pre.sub_a + ';' + pre.sub_b,
         'T_CREATE_BASE': pre.sub_a, 'T_PRIV': acl.priv, 'T_PENDING': acl.pending_pol, 'T_CANARIES': ';'.join(canaries),
         'T_CAPTURE': '/tmp/.t024-capture'}
  env.update(extra or {})
  cmd = ['docker', 'exec']
  for k, v in env.items():
    cmd += ['-e', f'{k}={v}']
  res = run(cmd + [node.container, '/tmp/.t024-test', '-test.run', f'^{test}$', '-test.v', '-test.timeout', '300s'], timeout=360)
  return res.stdout + res.stderr + f'\n(exit {res.returncode})\n'


def slapd_now(node):
  return node.sh('date -u +%Y%m%d%H%M%SZ').stdout.strip()


def accesslog(node, who, since=None):
  flt = f'(reqStart>={since})' if since else '(objectClass=*)'
  args = ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=accesslog', '-s', 'sub', flt, 'reqType', 'reqDN', 'reqAuthzID', 'reqResult', 'reqMod', 'reqOld']
  if who == 'alog-admin':
    res = run(['docker', 'exec', '-i', node.container, 'ldapsearch', '-x', '-H', acl.ldap_uri, '-D', 'cn=admin,cn=accesslog',
               '-y', '/tmp/.pw-admin'] + args)
  else:
    res = node.tool(who, 'ldapsearch', args)
  return res.stdout, len(acl.dn_set(res.stdout))


def prove(node_key, label, binary):
  _audit['on'] = label == 'auditlog'
  print(f'=== configuration {label}: accesslog `writes reads bind`, auditlog {"ON" if _audit["on"] else "off"} ===', flush=True)
  node = acl.Node(node_key)
  canaries = pre.setup(node)
  require(run(['docker', 'cp', binary, node.container + ':/tmp/.t024-test']).returncode == 0, 'docker cp the test')
  node.put('/tmp/.t024-sentinels', '\n'.join(SENTINELS) + '\n')
  time.sleep(1.2)  # reqStart has second precision: t0 must be later than the setup's last write
  t0 = slapd_now(node)
  out = go(node, canaries, 'TestCredSecretLive')
  for m in re.finditer(r'^T024 (PASS|FAIL) (.*)$', out, re.M):
    check(m.group(1) == 'PASS', f'[{label}] {m.group(2)}')
  for m in re.finditer(r'^T024 OBS (.*)$', out, re.M):
    print(f'OBS [{label}] {m.group(1)}', flush=True)
  check(re.search(r'^(ok|PASS)\b', out, re.M) is not None and '(exit 0)' in out,
        f'[{label}] the Go test ran to the end and passed (exit 0)' + ('' if '(exit 0)' in out else ': ' + mask(out)[-600:]))
  check(len(re.findall(r'^T024 (PASS|FAIL) ', out, re.M)) >= 40, f'[{label}] the Go test reported its checks')

  rows = []  # (path, plain, b64, hashes)
  # 1. HTTP responses (status, headers, body) and the server's own log (UI audit lines included)
  local = tempfile.mkdtemp(prefix='t024-cap-')
  acl.tmp_dirs.append(local)
  require(run(['docker', 'cp', node.container + ':/tmp/.t024-capture', local + '/capture']).returncode == 0, 'copy the capture')
  capture = pathlib.Path(local, 'capture').read_text()
  check(capture.count('### ') >= 40 and '"event":"machine_access"' in capture, f'[{label}] the capture holds the responses and the audit lines')
  rows.append(('HTTP responses + headers, UI log + audit', capture))
  rows.append(('Go test output (stdout/stderr)', out))
  # 2. the slapd container log (auditlog stdout when on)
  logs = run(['docker', 'logs', node.container])
  rows.append(('slapd docker logs' + (' (auditlog stdout)' if _audit['on'] else ''), logs.stdout + logs.stderr))
  # 3. accesslog as its rootdn: everything written during the Go test, and the whole log for sentinels
  since, n_since = accesslog(node, 'alog-admin', t0)
  whole, n_whole = accesslog(node, 'alog-admin')
  check(n_since > 0 and acl.attr_values(since, 'reqType') and re.search(r'^reqMod: employeeType:-', since, re.M | re.I) is not None,
        f'[{label}] control: accesslog recorded the Go test\'s writes ({n_since} entries, the W_cred cleanup Modify among them)')
  pre_hashes = scan(whole)[2] - scan(since)[2]
  check(pre_hashes > 0, f'[{label}] control: the hash scan finds the seed\'s plain userPassword Adds before the test ({pre_hashes} hits)')
  since_other, n_probe, stray = allow_probe(since, canaries)
  check(n_probe >= 2 and stray == 0, f'[{label}] T024-F1: the allowlisted public check-5 probe constant appears {n_probe} times, only in the probe entries ({stray} elsewhere)')
  rows.append(('accesslog reqMod/reqOld, accesslog rootdn, written during the test, the probe constant allowlisted', since_other))
  rows.append(('accesslog reqMod/reqOld, accesslog rootdn, whole log: sentinels only', whole))
  # 4. accesslog as M: the shipped ACL, then the M opt-in (f/accesslog-optin.ldif) for the read
  m_text, m_n = accesslog(node, 'machine')
  check(m_n == 0, f'[{label}] M reads no accesslog entry under the shipped accesslog ACL')
  alog_db = re.search(r'^dn: (.*)$', node.cfgtool('ldapsearch', ['-LLL', '-b', 'cn=config', '(olcSuffix=cn=accesslog)', 'dn']).stdout, re.M).group(1)
  pre.insert_rule(node, 0, f'to * by dn.exact="{acl.machine_dn}" read by * break', alog_db)
  try:
    m_text, m_n = accesslog(node, 'machine', t0)
    check(m_n > 0, f'[{label}] with the M opt-in M reads the test\'s accesslog entries ({m_n})')
    m_other, m_probe, m_stray = allow_probe(m_text, canaries)
    check(m_probe == n_probe and m_stray == 0, f'[{label}] M with the opt-in sees the same {m_probe} allowlisted probe constants (T024-F1)')
    rows.append(('accesslog reqMod/reqOld, M with the opt-in, written during the test, the probe constant allowlisted', m_other))
    p = go(node, canaries, 'TestCredSecretPremiseLive')
    check(re.search(r'^PREMISE check=accesslog_children_readable start=refused$', p, re.M) is not None,
          f'[{label}] the M opt-in configuration is one T-028 refuses: check 6 accesslog_children_readable, the server does not start')
  finally:
    pre.delete_rule(node, 0, alog_db)

  print(f'--- [{label}] E-13 scan (plaintext sentinel / base64 sentinel / hash pattern hits) ---', flush=True)
  for path, text in rows:
    plain, b64, hashes = scan(text)
    sentinels_only = 'sentinels only' in path
    print(f'SCAN [{label}] {path}: plaintext {plain}, base64 {b64}, hash {"(not counted)" if sentinels_only else hashes}', flush=True)
    check(plain == 0 and b64 == 0, f'[{label}] {path}: 0 plaintext and base64 sentinels')
    if sentinels_only:
      continue
    if path.startswith('slapd docker logs') and _audit['on']:
      check(hashes > 0, f'[{label}] {path}: the auditlog carries password hashes ({hashes}) -> this configuration must be refused')
    else:
      check(hashes == 0, f'[{label}] {path}: 0 hash patterns')
      if hashes:  # name where, never the value
        for entry in text.split('\n\n'):
          if HASH_RE.search(entry) or any(p in entry for p in HASH_B64):
            meta = [l for l in entry.splitlines() if l.split(':')[0] in ('reqType', 'reqDN', 'reqAuthzID', 'reqResult')]
            print('  hash in: ' + mask(' | '.join(meta) or entry.splitlines()[0][:24]), flush=True)
  if _audit['on']:
    chart = run(['bash', str(repo_root / 'scripts/test/test-chart-machine-write.sh')], cwd=str(repo_root), timeout=600)
    for want in ('cred next to audit.enabled (auditlog writes password hashes)', 'cred next to audit.enabled, even with write off'):
      check(f'PASS: {want}' in chart.stdout, f'[{label}] D379-14 (a): the chart refuses to render "{want}"')

  print(f'--- [{label}] E-10 by direct W_cred, after the scans (F-8) ---', flush=True)
  dn = f'uid=t024-direct,{pre.sub_a}'
  mark = 'ldapium-credential-pending:' + secrets.token_hex(8)
  res = node.tool('wdata', 'ldapadd', [], acl.person(dn, 't024-direct', f'employeeType: {mark}\npwdPolicySubentry: {acl.pending_pol}\n').replace('changetype: add\n', ''))
  require(res.returncode == 0, 'W_data pending Add: ' + mask(res.stderr))
  weak = secrets.token_hex(1)
  hashed = node.sh('slappasswd -h {SSHA} -T /dev/stdin', weak).stdout.strip()
  rc = lcode(node.tool('wcred', 'ldapmodify', [], f'dn: {dn}\nchangetype: modify\nreplace: userPassword\nuserPassword: {hashed}\n'))
  check(rc == 19, f'[{label}] E-10 (F-6 closed): W_cred plain Modify with a pre-hashed 2-char value -> 19 under the pending policy (got {rc})')
  short = '/tmp/.t024-short'
  node.put(short, 'Aa1-' + secrets.token_hex(3))
  rc = lcode(node.tool('wcred', 'ldappasswd', ['-T', short, dn]))
  check(rc == 19, f'[{label}] E-10: W_cred Password Modify with a 10-character value -> 19 (pending pwdMinLength 12; got {rc})')
  node.stop()


def main():
  print(f'Run {acl.name_prefix}: image {acl.ldap_image}, configurations {configs}, mutation={mutation or "none"}', flush=True)
  require(run(['docker', 'version', '--format', 'ok']).returncode == 0, 'docker is not available')
  binary = build_binary()
  for label in configs:
    require(label in ('accepted', 'auditlog'), 'unknown configuration ' + label)
    prove('n0', label, binary)


if __name__ == '__main__':
  code = 0
  try:
    main()
  except Exception as e:
    print('ERROR: ' + mask(e), flush=True)
    import traceback
    traceback.print_exc()
    code = 1
  print(f'RESULT: {acl.passed} checks passed, {len(acl.failed)} failed, mutation={mutation or "none"}, {time.monotonic() - acl.start_time:.0f}s', flush=True)
  for f in acl.failed:
    print('  FAILED: ' + f, flush=True)
  sys.exit(1 if acl.failed or code else 0)
