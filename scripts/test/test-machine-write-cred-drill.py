#!/usr/bin/env python3
"""Per-compartment emergency block drill of the v2c password compartment (#379, T-025; AC-011, REQ-017).

docs/changes/machine-write-scope-v2, against real slapd, the sibling of test-machine-write-drill.py (the
v2a W_data drill). setPassword is still closed in production (T-026), so the application side is the
`live`-tagged Go test TestCredDrillLive (ui/backend/internal/httpapi/machine_write_cred_drill_live_test.go):
the real HTTP pipeline, real dialer, real M pre-reads, real T-028 premise checker, with the TEST-ONLY table
that adds the setPassword catalog row (as the T-024 proof does). It runs inside the slapd container against
ldap://127.0.0.1 through a TCP proxy that can hold one LDAP message. A "replica" is one in-process server
(own IdP and issuer); a "redeploy" is a new server from a changed config. No Kubernetes rollout is involved.

One fresh container built with the T-028 proof's setup (guide 4.2/4.3, 8.2-8.5, 8.8: reader, canaries in two
cred subtrees; accesslog `writes reads bind`). The Go test measures and asserts:

  * AC-011 (c): MACHINE_REQUEST_TIMEOUT is the bound of a stalled in-flight setPassword (10 s and 4 s, the
    proxy holds the Password Modify), with and without a W_cred rotation during the stall; an already-bound
    write completes after the rotation and its cleanup cannot (cleanup=failed, a stuck entry)
  * Revision 8: while W_cred is rotated the stuck sweep finds the entry and cannot clean it, a new replica
    refuses to start (sweep_stuck_at_startup), and the MANUAL PROCEDURE (M search, administrator Modify)
    clears it; then the rotated Secret rolls out
  * AC-011 (b): W_cred rotation -> the next setPassword on every replica 503 bind_failed, the old credential
    refused by slapd, W_data/W_lock/M unaffected, the premise cycle, the lockout trap, restore by rollout
  * AC-011 (a): MACHINE_WRITE_CRED_ENABLED=false redeploy -> setPassword refused with zero W_cred binds, other
    compartments unaffected, credentialPending refused, and the same account served again with the flag on

This driver adds the slapd side: the accesslog's failed W_cred binds against the application's count.

Mutation self-test (LDAPIUM_T025_MUTATE; the first two build the Go test from a patched copy of the source):
  timeout-ignored   the request timeout is tripled in the write pipeline and the executor     -> must FAIL
  cred-flag-ignored the W_cred identity no longer depends on MACHINE_WRITE_CRED_ENABLED       -> must FAIL
  rotate-noop       the drill's W_cred rotation is skipped                                    -> must FAIL
  runbook-noop      the manual procedure's administrator Modify is skipped                    -> must FAIL

Run (docker, go): LDAPIUM_IMAGE=ldapium:t025 python3 scripts/test/test-machine-write-cred-drill.py
Override LDAPIUM_IMAGE / LDAPIUM_TEST_PREFIX.
"""
import importlib.util
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time

repo_root = pathlib.Path(__file__).resolve().parents[2]
mutation = os.environ.get('LDAPIUM_T025_MUTATE', '')
MUTATIONS = ('timeout-ignored', 'cred-flag-ignored', 'rotate-noop', 'runbook-noop')
if mutation not in ('',) + MUTATIONS:
  raise SystemExit('LDAPIUM_T025_MUTATE must be one of ' + ', '.join(MUTATIONS))
os.environ.setdefault('LDAPIUM_TEST_PREFIX', 'ldapium-t025-')
_spec = importlib.util.spec_from_file_location('cpre', repo_root / 'scripts/test/test-machine-write-cred-premise-live.py')
pre = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pre)       # its main() does not run; it sets accesslog `writes reads bind`
acl = pre.acl
check, require, mask, run = acl.check, acl.require, acl.mask, acl.run


def build_binary():
  arch = run(['docker', 'info', '--format', '{{.Architecture}}']).stdout.strip()
  goarch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
  src = repo_root / 'ui/backend'
  work = tempfile.mkdtemp(prefix='t025-src-')
  acl.tmp_dirs.append(work)
  if mutation in ('timeout-ignored', 'cred-flag-ignored'):
    shutil.copytree(src, work + '/backend', ignore=shutil.ignore_patterns('dist', 'node_modules'))
    src = pathlib.Path(work + '/backend')
    patches = []
    if mutation == 'timeout-ignored':
      patches.append(('internal/httpapi/machine_write_pipeline.go', r'r\.deadline = time\.Now\(\)\.Add\(r\.w\.exec\.timeout\)',
                      'r.deadline = time.Now().Add(r.w.exec.timeout * 3)'))
      patches.append(('internal/httpapi/machine_exec.go', r'context\.WithTimeout\(c\.Request\(\)\.Context\(\), x\.timeout\)',
                      'context.WithTimeout(c.Request().Context(), x.timeout*3)'))
    else:
      patches.append(('internal/httpapi/machine_write_ops.go', r'if w\.CredEnabled && w\.Cred\.BindDN != "" \{', 'if w.Cred.BindDN != "" {'))
    for rel, pat, rep in patches:
      f = src / rel
      text, k = re.subn(pat, rep, f.read_text())
      require(k == 1, f'mutation {mutation} did not apply to {rel}')
      f.write_text(text)
  out = work + '/t025-test'
  env = dict(os.environ, GOOS='linux', GOARCH=goarch, CGO_ENABLED='0')
  res = run(['go', 'test', '-tags=live', '-c', '-o', out, './internal/httpapi'], env=env, cwd=str(src), timeout=900)
  require(res.returncode == 0, 'go test -c: ' + res.stderr[-600:])
  return out


def go(node, canaries):
  env = {'LDAPIUM_CRED_DRILL_LIVE': '1', 'T_BASE': acl.base_dn, 'T_M_DN': acl.machine_dn, 'T_WDATA_DN': acl.wd_dn, 'T_WLOCK_DN': acl.wl_dn,
         'T_WCRED_DN': acl.wc_dn, 'T_READER_DN': pre.reader_dn, 'T_CEIL': acl.managed, 'T_CRED': pre.sub_a + ';' + pre.sub_b,
         'T_CREATE_BASE': pre.sub_a, 'T_PRIV': acl.priv, 'T_PENDING': acl.pending_pol, 'T_CANARIES': ';'.join(canaries),
         'T_CAPTURE': '/tmp/.t025-capture', 'LDAPIUM_T025_MUTATE': mutation}
  cmd = ['docker', 'exec']
  for k, v in env.items():
    cmd += ['-e', f'{k}={v}']
  res = run(cmd + [node.container, '/tmp/.t025-test', '-test.run', '^TestCredDrillLive$', '-test.v', '-test.timeout', '400s'], timeout=460)
  return res.stdout + res.stderr + f'\n(exit {res.returncode})\n'


def main():
  print(f'Run {acl.name_prefix}: image {acl.ldap_image}, mutation={mutation or "none"}', flush=True)
  require(run(['docker', 'version', '--format', 'ok']).returncode == 0, 'docker is not available')
  binary = build_binary()
  node = acl.Node('n0')
  canaries = pre.setup(node)
  require(run(['docker', 'cp', binary, node.container + ':/tmp/.t025-test']).returncode == 0, 'docker cp the test')
  time.sleep(1.2)  # reqStart has second precision
  t0 = node.sh('date -u +%Y%m%d%H%M%SZ').stdout.strip()
  out = go(node, canaries)
  for m in re.finditer(r'^T025 (PASS|FAIL) (.*)$', out, re.M):
    check(m.group(1) == 'PASS', m.group(2))
  for m in re.finditer(r'^T025 OBS (.*)$', out, re.M):
    print(f'OBS {m.group(1)}', flush=True)
  check(re.search(r'^(ok|PASS)\b', out, re.M) is not None and '(exit 0)' in out,
        'the Go test ran to the end and passed (exit 0)' + ('' if '(exit 0)' in out else ': ' + mask(out)[-800:]))
  check(len(re.findall(r'^T025 (PASS|FAIL) ', out, re.M)) >= 40, 'the Go test reported its checks')
  # the slapd side: failed W_cred binds at the directory, since the test started
  res = run(['docker', 'exec', '-i', node.container, 'ldapsearch', '-x', '-H', acl.ldap_uri, '-D', 'cn=admin,cn=accesslog', '-y', '/tmp/.pw-admin',
             '-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=accesslog', '-s', 'sub',
             f'(&(reqType=bind)(reqDN={acl.wc_dn})(reqResult=49)(reqStart>={t0}))', 'reqDN'])
  failed = len(acl.dn_set(res.stdout)) if res.returncode == 0 else -1
  seen = [int(m.group(1)) for m in re.finditer(r'failed W_cred binds on replica 1 so far: (\d+)', out)]
  print(f'OBS slapd accesslog: {failed} failed W_cred binds (reqResult 49) during the drill; the application counted {seen} on replica 1', flush=True)
  check(failed >= 0 and seen and failed >= seen[0] >= 1, 'slapd saw at least as many failed W_cred binds as the application counted on replica 1 (>= 1)')
  node.stop()


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
