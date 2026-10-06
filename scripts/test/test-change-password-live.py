#!/usr/bin/env python3
"""Live verification of self-service change-password failure against real LDAP & UI containers.

Exercises the real browser UI (Playwright) against a live stack and asserts the status
code, error envelope code, screen text and UI log for each password change rejection.
Image tags come from LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE (default ldapium:e2e, ldapium-ui:e2e);
LDAPIUM_CP_PREFIX renames the throwaway docker objects.
"""
import http.cookiejar
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
root = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + root
prefix = os.environ.get('LDAPIUM_CP_PREFIX', 'ldapium-cp-') + uuid.uuid4().hex[:8]
network = prefix + '-net'
volumes = [prefix + '-cfg', prefix + '-data']
ldap_name = prefix + '-ldap'
ui_name = prefix + '-ui'
containers = []
created_volumes = []
network_created = False
frontend_dir = pathlib.Path(__file__).resolve().parents[2] / 'ui' / 'frontend'
pw_file = '/tmp/.admin-pw'

admin_password = 'Admin-' + uuid.uuid4().hex[:12] + '!'
user_password = 'Current-Pass-123!'
user_dn = 'uid=cpuser,ou=people,' + root

def run_cmd(args, **kwargs):
  return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()

def check(condition, message):
  if not condition:
    raise AssertionError(message)
  print('ok:', message)

def cleanup():
  # Only objects this run created: a name collision never removes someone else's container.
  # Names are registered before `docker run`, so a container created but never started
  # (exit 125, state `created`) is still removed; absent objects are tolerated.
  for c in containers:
    subprocess.run(['docker', 'rm', '-fv', c], capture_output=True)
  for v in created_volumes:
    subprocess.run(['docker', 'volume', 'rm', v], capture_output=True)
  if network_created:
    subprocess.run(['docker', 'network', 'rm', network], capture_output=True)

try:
  print('Creating docker network %s...' % network)
  run_cmd(['docker', 'network', 'create', network])
  network_created = True
  for v in volumes:
    created_volumes.append(v)
    run_cmd(['docker', 'volume', 'create', v])

  print('Starting LDAP container (%s)...' % ldap_image)
  containers.append(ldap_name)
  run_cmd(['docker', 'run', '-d', '--name', ldap_name, '--network', network,
           '--network-alias', 'ldap-host',
           '-e', 'LDAP_ROOT_DN=' + root,
           '-e', 'LDAP_ADMIN_PASSWORD',
           '-e', 'LDAP_PPM_MIN_CLASSES=3',
           '-v', volumes[0] + ':/etc/openldap/slapd.d',
           '-v', volumes[1] + ':/var/lib/openldap/data',
           ldap_image],
          env={**os.environ, 'LDAP_ADMIN_PASSWORD': admin_password})

  # The admin password reaches the tools via a 0600 file inside the disposable container
  # (written from its own environment), so it never rides in a tool's argv.
  run_cmd(['docker', 'exec', ldap_name, 'sh', '-c', 'umask 077; printf %s "$LDAP_ADMIN_PASSWORD" > ' + pw_file])

  # Wait for LDAP to accept admin bind
  ldap_ready = False
  for _ in range(60):
    res = subprocess.run(['docker', 'exec', ldap_name, 'sh', '-c',
                          'ldapwhoami -x -H ldap://127.0.0.1 -D "$0" -y ' + pw_file, admin_dn],
                         capture_output=True, text=True)
    if res.returncode == 0:
      ldap_ready = True
      break
    time.sleep(1)
  if not ldap_ready:
    raise RuntimeError('LDAP container failed to start')

  # Scaffold ou=people, ou=groups, and cpuser
  ldif = (
      f"dn: ou=people,{root}\nobjectClass: organizationalUnit\nou: people\n\n"
      f"dn: ou=groups,{root}\nobjectClass: organizationalUnit\nou: groups\n\n"
      f"dn: {user_dn}\nobjectClass: inetOrgPerson\nuid: cpuser\ncn: CP User\nsn: User\n"
      f"userPassword: {user_password}\n"
  )
  res = subprocess.run(['docker', 'exec', '-i', ldap_name, 'sh', '-c',
                        'ldapadd -x -H ldap://127.0.0.1 -D "$0" -y ' + pw_file, admin_dn],
                       input=ldif, capture_output=True, text=True)
  if res.returncode != 0:
    raise RuntimeError(f"Scaffold failed: {res.stderr}")

  print('Starting UI container (%s)...' % ui_image)
  containers.append(ui_name)
  run_cmd(['docker', 'run', '-d', '--name', ui_name, '--network', network,
           '-p', '127.0.0.1::8080',
           '--tmpfs', '/tmp:rw,mode=1777',
           '-e', 'LDAP_URL=ldap://ldap-host:389',
           '-e', 'LDAP_BASE_DN=' + root,
           '-e', 'LDAP_USER_CREATE_BASE=ou=people,' + root,
           '-e', 'LDAP_GROUP_CREATE_BASE=ou=groups,' + root,
           '-e', 'COOKIE_SECURE=false',
           ui_image])

  ui_port = run_cmd(['docker', 'port', ui_name, '8080/tcp']).splitlines()[0].rsplit(':', 1)[1]
  base_url = f"http://127.0.0.1:{ui_port}"

  # Wait for UI
  ui_ready = False
  for _ in range(60):
    try:
      with urllib.request.urlopen(f"{base_url}/api/auth/config", timeout=1) as resp:
        if resp.status == 200:
          ui_ready = True
          break
    except Exception:
      time.sleep(1)
  if not ui_ready:
    raise RuntimeError('UI container failed to start')

  print(f"UI is ready at {base_url}. Running browser verification...")

  # Write and run Node Playwright runner
  node_script = f"""
import {{ chromium }} from '@playwright/test';

async function main() {{
  const browser = await chromium.launch({{ headless: true }});
  const page = await browser.newPage({{ locale: 'en-US' }});

  console.log('Navigating to login page...');
  await page.goto('{base_url}/login');
  await page.locator('#identity').fill('{user_dn}');
  await page.locator('#password').fill('{user_password}');
  const loginPromise = page.waitForResponse((res) => res.url().includes('/api/login') && res.request().method() === 'POST');
  await page.getByRole('button', {{ name: 'Sign in' }}).click();
  const loginResp = await loginPromise;
  console.log('Login HTTP status:', loginResp.status(), await loginResp.text());

  // Wait for login redirection to /tree
  await page.waitForURL('**/tree', {{ timeout: 10000 }});
  console.log('Logged in successfully. Navigating to /change-password...');
  await page.goto('{base_url}/change-password');
  await page.waitForSelector('#current-password');

  async function testScenario(name, currentPw, newPw, confirmPw) {{
    console.log(`\\n--- Testing scenario: ${{name}} ---`);
    await page.locator('#current-password').fill(currentPw);
    await page.locator('#new-password').fill(newPw);
    await page.locator('#confirm-password').fill(confirmPw);

    // Capture the API response
    const responsePromise = page.waitForResponse(
      (res) => res.url().includes('/api/users/password') && res.request().method() === 'POST'
    );
    await page.getByRole('button', {{ name: 'Change password', exact: true }}).click();
    const response = await responsePromise;
    const status = response.status();
    const bodyText = await response.text();
    let bodyJson = null;
    try {{ bodyJson = JSON.parse(bodyText); }} catch (e) {{}}

    // Wait for error text rendered on screen
    const errorLocator = page.locator('div.border-danger\\\\/30');
    await errorLocator.waitFor({{ state: 'visible', timeout: 5000 }});
    const screenText = (await errorLocator.textContent())?.trim();

    console.log(`HTTP Status: ${{status}}`);
    console.log(`API Response Body: ${{bodyText}}`);
    console.log(`Exact Screen Text: "${{screenText}}"`);
    const headerRequestId = response.headers()['x-request-id'] || null;
    return {{ name, status, bodyJson, headerRequestId, screenText }};
  }}

  // Scenario 1: Wrong current password
  const r1 = await testScenario(
    'Wrong Current Password',
    'Wrong-Current-Pass-999!',
    'Valid-New-Pass-456!',
    'Valid-New-Pass-456!'
  );

  // Scenario 2: Weak new password (failing PPM strength checks)
  const r2 = await testScenario(
    'Weak New Password (PPM Strength Check Failure)',
    '{user_password}',
    'aaaaaaaaaaaaaaaa',
    'aaaaaaaaaaaaaaaa'
  );

  // Scenario 3: Unchanged password (same as current password)
  const r3 = await testScenario(
    'Unchanged Password (Same as Current Password)',
    '{user_password}',
    '{user_password}',
    '{user_password}'
  );

  for (const r of [r1, r2, r3]) {{
    console.log('SCENARIO_RESULT: ' + JSON.stringify({{ name: r.name, status: r.status, code: r.bodyJson && r.bodyJson.code, requestId: r.bodyJson && r.bodyJson.requestId, body: r.bodyJson, headerRequestId: r.headerRequestId, screenText: r.screenText }}));
  }}
  await browser.close();
  console.log('\\nAll browser scenarios complete.');
}}

main().catch((err) => {{
  console.error('Browser test failed:', err);
  process.exit(1);
}});
"""

  # A unique file inside the frontend dir (so @playwright/test resolves), never a fixed name.
  fd, script_path = tempfile.mkstemp(prefix='.pw_change_', suffix='.mjs', dir=str(frontend_dir))
  try:
    with os.fdopen(fd, 'w') as f:
      f.write(node_script)
    result = subprocess.run(['node', os.path.basename(script_path)], cwd=str(frontend_dir), capture_output=True, text=True)
  finally:
    os.remove(script_path)
  print(result.stdout)
  if result.returncode != 0:
    print(result.stderr, file=sys.stderr)
    raise RuntimeError('Node runner exited with non-zero code')
  results = [json.loads(l.split(':', 1)[1]) for l in result.stdout.splitlines() if l.startswith('SCENARIO_RESULT: ')]
  check(len(results) == 3, 'three scenarios reported')
  r1, r2, r3 = results
  check(r1['status'] == 500 and r1['code'] == 'internal' and r1['screenText'] == 'internal error',
        'wrong current password: 500, code internal, screen "internal error"')
  check(r2['status'] == 400 and r2['code'] == 'invalid_request' and 'strength checks' in r2['screenText'],
        'weak new password: 400, code invalid_request, policy text visible')
  check(r3['status'] == 400 and r3['code'] == 'invalid_request' and 'not being changed' in r3['screenText'],
        'unchanged password: 400, code invalid_request, policy text visible')

  dn_re = re.compile(r'\b(uid|cn|ou)=[^,\s]+,|dc=', re.I)
  for r, label in ((r1, 'wrong current password'), (r2, 'weak new password'), (r3, 'unchanged password')):
    body = r['body'] or {}
    for key in ('error', 'message', 'code', 'requestId', 'retryable'):
      check(key in body, '%s: envelope has key %s' % (label, key))
    check(body['error'] == body['message'], '%s: error == message' % label)
    check(bool(r['headerRequestId']) and body['requestId'] == r['headerRequestId'],
          '%s: requestId equals X-Request-Id header' % label)
    check(not dn_re.search(str(body['error'])) and not dn_re.search(str(body['message'])),
          '%s: no DN in error/message' % label)
    check(body['retryable'] is False, '%s: retryable is false' % label)

  req_id = r1['requestId']
  check(bool(req_id), 'scenario 1 carries a requestId')
  ui_logs = subprocess.run(['docker', 'logs', ui_name], capture_output=True, text=True)
  check(ui_logs.returncode == 0, 'UI log lookup succeeded')
  lines = [l for l in (ui_logs.stdout + ui_logs.stderr).splitlines() if req_id in l]
  for line in lines:
    print('  LOG:', line)
  check(any('Result Code 53' in l for l in lines), 'UI log for the 500 requestId has "Result Code 53"')

finally:
  print('\nCleaning up containers...')
  cleanup()
  print('Cleanup done.')
