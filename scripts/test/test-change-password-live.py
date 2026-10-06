#!/usr/bin/env python3
"""Live verification of self-service change-password failure against real LDAP & UI containers.

Exercises the real browser UI (Playwright) against a live stack to observe the exact
screen text, status codes, error envelope, and UI logs for password change rejections.
"""
import http.cookiejar
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import uuid

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:lane-249')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:lane-249')
root = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + root
prefix = 'ldapium-cp-249-' + uuid.uuid4().hex[:6]
network = prefix + '-net'
volumes = [prefix + '-cfg', prefix + '-data']
ldap_name = prefix + '-ldap'
ui_name = prefix + '-ui'
containers = []

admin_password = 'Admin-' + uuid.uuid4().hex[:12] + '!'
user_password = 'Current-Pass-123!'
user_dn = 'uid=cpuser,ou=people,' + root

def run_cmd(args, **kwargs):
  return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout.strip()

def cleanup():
  for c in set(containers + [ldap_name, ui_name]):
    subprocess.run(['docker', 'rm', '-f', c], capture_output=True)
  for v in volumes:
    subprocess.run(['docker', 'volume', 'rm', v], capture_output=True)
  subprocess.run(['docker', 'network', 'rm', network], capture_output=True)

try:
  print('Creating docker network %s...' % network)
  run_cmd(['docker', 'network', 'create', network])
  for v in volumes:
    run_cmd(['docker', 'volume', 'create', v])

  print('Starting LDAP container (%s)...' % ldap_image)
  run_cmd(['docker', 'run', '-d', '--name', ldap_name, '--network', network,
           '--network-alias', 'ldap-host',
           '-e', 'LDAP_ROOT_DN=' + root,
           '-e', 'LDAP_ADMIN_PASSWORD',
           '-e', 'LDAP_PPM_MIN_CLASSES=3',
           '-v', volumes[0] + ':/etc/openldap/slapd.d',
           '-v', volumes[1] + ':/var/lib/openldap/data',
           ldap_image],
          env={**os.environ, 'LDAP_ADMIN_PASSWORD': admin_password})
  containers.append(ldap_name)

  # Wait for LDAP to accept admin bind
  ldap_ready = False
  for _ in range(60):
    res = subprocess.run(['docker', 'exec', ldap_name, 'sh', '-c',
                          'ldapwhoami -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn],
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
  )
  res = subprocess.run(['docker', 'exec', '-i', ldap_name, 'sh', '-c',
                        'ldapadd -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn],
                       input=ldif, capture_output=True, text=True)
  if res.returncode != 0:
    raise RuntimeError(f"Scaffold failed: {res.stderr}")

  # Set initial password for cpuser
  res = subprocess.run(['docker', 'exec', '-i', ldap_name, 'sh', '-c',
                        'ldappasswd -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" -s "$1" "$2"',
                        admin_dn, user_password, user_dn],
                       capture_output=True, text=True)
  if res.returncode != 0:
    raise RuntimeError(f"Setting initial password failed: {res.stderr}")

  print('Starting UI container (%s)...' % ui_image)
  run_cmd(['docker', 'run', '-d', '--name', ui_name, '--network', network,
           '-p', '127.0.0.1::8080',
           '--tmpfs', '/tmp:rw,mode=1777',
           '-e', 'LDAP_URL=ldap://ldap-host:389',
           '-e', 'LDAP_BASE_DN=' + root,
           '-e', 'LDAP_USER_CREATE_BASE=ou=people,' + root,
           '-e', 'LDAP_GROUP_CREATE_BASE=ou=groups,' + root,
           '-e', 'COOKIE_SECURE=false',
           ui_image])
  containers.append(ui_name)

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
    return {{ name, status, bodyJson, screenText }};
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

  console.log('SCENARIO_1_REQUEST_ID: ' + (r1.bodyJson && r1.bodyJson.requestId ? r1.bodyJson.requestId : ''));
  await browser.close();
  console.log('\\nAll browser scenarios complete.');
}}

main().catch((err) => {{
  console.error('Browser test failed:', err);
  process.exit(1);
}});
"""

  script_path = 'ui/frontend/pw_change_test.mjs'
  with open(script_path, 'w') as f:
    f.write(node_script)

  req_id = ''
  try:
    result = subprocess.run(['node', 'pw_change_test.mjs'], cwd='ui/frontend', capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
      print(result.stderr, file=sys.stderr)
      raise RuntimeError('Node runner exited with non-zero code')
    for line in result.stdout.splitlines():
      if line.startswith('SCENARIO_1_REQUEST_ID: '):
        req_id = line.split(':', 1)[1].strip()
  finally:
    if os.path.exists(script_path):
      os.remove(script_path)

  print('\nUI container server log for 500 failure:')
  ui_logs = subprocess.run(['docker', 'logs', ui_name], capture_output=True, text=True)
  all_logs = ui_logs.stdout + ui_logs.stderr
  for line in all_logs.splitlines():
    if (req_id and req_id in line) or 'internal error' in line.lower() or 'ldap result' in line.lower():
      print('  LOG:', line)

finally:
  print('\nCleaning up containers...')
  cleanup()
  print('Cleanup done.')
