#!/usr/bin/env python3
"""E-22 / R-4 / AC-010b: the check -> write window of machine setPassword (#417 (c), docs/changes/machine-write-scope-v2).

The sibling of test-machine-write-cred-drill.py: the same fixture (T-028 proof setup), the same `live`-tagged Go
package, a different test, TestCredE22Live (ui/backend/internal/httpapi/machine_write_cred_e22_live_test.go). Inside the
slapd container, through the drill's TCP proxy, the Go test HOLDS the W_cred Password Modify (after the per-request
premise check passed), inserts a looser userPassword rule for the first cred subtree in front of the W_cred bundle
(cn=config, ldapi as the administrator), releases, then records: the held request; the NEXT request; how long the REAL
60 s ticker of the premise gate takes to close the password operation (insert phases spread over the tick period);
the window (check returned -> request finished); and a request held past MACHINE_REQUEST_TIMEOUT. The rule is removed
after every run. A fresh container per run. Not wired into CI.

Run (docker, go): LDAPIUM_IMAGE=ldapium:e2e python3 scripts/test/test-machine-write-cred-e22-live.py
Override LDAPIUM_IMAGE / LDAPIUM_TEST_PREFIX; T_E22_RUNS (default 5) sets the repeat count (about 1 minute per run).
"""
import importlib.util
import os
import pathlib
import re
import sys
import time

repo_root = pathlib.Path(__file__).resolve().parents[2]
os.environ.setdefault('LDAPIUM_TEST_PREFIX', 'ldapium-e22-')
_spec = importlib.util.spec_from_file_location('cdrill', repo_root / 'scripts/test/test-machine-write-cred-drill.py')
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)     # its main() does not run
pre, acl = drill.pre, drill.acl
check, require, mask, run = acl.check, acl.require, acl.mask, acl.run
runs = int(os.environ.get('T_E22_RUNS', '5'))


def go(node, canaries, at):
  env = {'LDAPIUM_CRED_E22_LIVE': '1', 'T_BASE': acl.base_dn, 'T_M_DN': acl.machine_dn, 'T_WDATA_DN': acl.wd_dn, 'T_WLOCK_DN': acl.wl_dn,
         'T_WCRED_DN': acl.wc_dn, 'T_READER_DN': pre.reader_dn, 'T_CEIL': acl.managed, 'T_CRED': pre.sub_a + ';' + pre.sub_b,
         'T_CREATE_BASE': pre.sub_a, 'T_PRIV': acl.priv, 'T_PENDING': acl.pending_pol, 'T_CANARIES': ';'.join(canaries),
         'T_CAPTURE': '/tmp/.e22-capture', 'T_WCRED_POLICY': pre.wcred_policy,
         'T_CFG_URI': acl.ldapi_uri, 'T_CFG_DN': acl.cfg_dn, 'T_MAIN_DB': pre.MAIN, 'T_LOOSE_AT': str(at),
         'T_LOOSE_RULE': f'to dn.subtree="{pre.sub_a}" attrs=userPassword by users write', 'T_E22_RUNS': str(runs)}
  cmd = ['docker', 'exec']
  for k, v in env.items():
    cmd += ['-e', f'{k}={v}']
  res = run(cmd + [node.container, '/tmp/.t025-test', '-test.run', '^TestCredE22Live$', '-test.v', '-test.timeout', f'{runs * 150 + 300}s'],
            timeout=runs * 150 + 360)
  return res.stdout + res.stderr + f'\n(exit {res.returncode})\n'


def main():
  print(f'Run {acl.name_prefix}: image {acl.ldap_image}, runs={runs}', flush=True)
  require(run(['docker', 'version', '--format', 'ok']).returncode == 0, 'docker is not available')
  binary = drill.build_binary()
  node = acl.Node('n0')
  canaries = pre.setup(node)
  require(run(['docker', 'cp', binary, node.container + ':/tmp/.t025-test']).returncode == 0, 'docker cp the test')
  at = pre.cred_at(node)      # the loose rule goes directly in front of the W_cred bundle
  rules0 = pre.rules(node)
  time.sleep(1.2)
  out = go(node, canaries, at)
  for m in re.finditer(r'^E22 (PASS|FAIL) (.*)$', out, re.M):
    check(m.group(1) == 'PASS', m.group(2))
  for m in re.finditer(r'^E22 OBS (.*)$', out, re.M):
    print(f'OBS {m.group(1)}', flush=True)
  check(re.search(r'^(ok|PASS)\b', out, re.M) is not None and '(exit 0)' in out,
        'the Go test ran to the end and passed (exit 0)' + ('' if '(exit 0)' in out else ': ' + mask(out)[-800:]))
  check(pre.rules(node) == rules0, 'the olcAccess rules are exactly as before the run (the loose rule was removed)')
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
  print(f'RESULT: {acl.passed} checks passed, {len(acl.failed)} failed, {time.monotonic() - acl.start_time:.0f}s', flush=True)
  for f in acl.failed:
    print('  FAILED: ' + f, flush=True)
  sys.exit(1 if acl.failed or code else 0)
