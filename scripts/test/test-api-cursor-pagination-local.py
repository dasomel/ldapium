#!/usr/bin/env python3
"""Disposable LDAP/UI containers prove cursor pagination end to end (#215).

Builds a directory of LDAPIUM_COUNT users and groups (default 12000, more than
the default olcSizeLimit of 10000) with the awkward cases a keyset order must
survive (mixed case, no uid, duplicate uid values, non-ASCII cn, DNs that
differ only in case), then through the real backend:

  1. traverses /api/users and /api/groups as the ADMIN (rootDN, exempt from the
     size limit) and compares the sequence with an ldapsearch ground truth:
     same entries, zero duplicates, strictly increasing (key, DN);
  2. as a NON-ROOT identity on the default configuration: the legacy listing
     is unchanged (5000 + truncated), cursor mode answers 422
     size_limit_exceeded (never a partial page), and narrowing with q works;
  3. restarts slapd with LDAP_PAGED_TOTAL_LIMIT=unlimited (reconcile on an
     existing volume) and traverses fully as the non-root identity;
  4. checks cursor misuse (re-login, tampering, other resource/q) and that no
     userPassword ever reaches a page;
  5. applies the documented concurrent-change table (a)-(f) between pages;
  6. measures page latency (limit 50/200, admin and non-root), a full
     traversal and the legacy listing;
  7. with a latency-injecting TCP proxy in front of slapd: another request of
     the same session is not starved while a page runs (and IS starved by the
     legacy listing, for contrast), and a page that exceeds the request
     deadline answers 503 scan_timeout and leaves the shared connection healthy.

Image tags come from LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE (default ldapium:e2e,
ldapium-ui:e2e). Docker objects are named with LDAPIUM_PREFIX (default
ldapium-cursor) and removed at the end. Sections 6 and 7 can be skipped with
SKIP_PERF=1 / SKIP_SLOW=1; SLOW_REQUEST_DELAY_MS tunes the proxy for the
timeout test (default 1500).
"""
import base64
import hashlib
import http.cookiejar
import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
proxy_image = os.environ.get('LDAPIUM_PROXY_IMAGE', 'python:3.12-slim')
count = int(os.environ.get('LDAPIUM_COUNT', '12000'))
prefix = os.environ.get('LDAPIUM_PREFIX', 'ldapium-cursor')
root = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + root
people = 'ou=people,' + root
groups_ou = 'ou=groups,' + root
reader_dn = 'uid=reader,' + people
name = '%s-%s' % (prefix, uuid.uuid4().hex[:6])
network = name + '-net'
volumes = [name + '-config', name + '-data']
ldap = name + '-ldap'
ui = name + '-ui'
containers = []
admin_password = uuid.uuid4().hex + uuid.uuid4().hex
reader_password = 'Reader-' + uuid.uuid4().hex[:12] + '!'
fake_hash = '{SSHA}' + base64.b64encode(b'not-a-real-hash-' + uuid.uuid4().bytes).decode()
results = []  # (name, detail) lines printed at the end


def mask(text):
  return str(text).replace(admin_password, '***').replace(reader_password, '***')


def command(args, **kw):
  try:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()
  except subprocess.CalledProcessError as error:
    raise RuntimeError('%s failed (exit %d): %s' % (' '.join(args[:3]), error.returncode, mask(error.stderr).strip())) from None


def check(condition, message):
  if not condition:
    raise AssertionError(message)


def record(label, detail):
  results.append((label, detail))
  print('ok: %s -- %s' % (label, detail), flush=True)


# ---------------------------------------------------------------- directory

def user_entries():
  """Yield (dn, ldif) for every generated user. Deterministic."""
  for i in range(count):
    variant = i % 100
    if variant == 7:
      # no uid attribute at all: sorts first, ordered by DN; DN uses cn
      dn = 'cn=NoUid %05d,%s' % (i, people)
      attrs = ['objectClass: inetOrgPerson', 'cn: NoUid %05d' % i, 'sn: NoUid']
    elif variant == 13:
      # two uid values: the smaller (lowercased) one is the sort key
      dn = 'uid=Multi%05d,%s' % (i, people)
      attrs = ['objectClass: inetOrgPerson', 'uid: Multi%05d' % i, 'uid: aaMulti%05d' % i, 'cn: Multi %05d' % i, 'sn: Multi']
    elif variant == 21:
      # upper-case uid (mixed case against the lower-case majority)
      dn = 'uid=UPPER%05d,%s' % (i, people)
      attrs = ['objectClass: inetOrgPerson', 'uid: UPPER%05d' % i, 'cn: Upper %05d' % i, 'sn: Upper']
    elif variant == 33:
      # same uid value as the previous user but a different DN (cn RDN)
      dn = 'cn=Shared %05d,%s' % (i, people)
      attrs = ['objectClass: inetOrgPerson', 'uid: user%05d' % (i - 1), 'cn: Shared %05d' % i, 'sn: Shared']
    elif variant == 47:
      # non-ASCII in cn/sn/displayName (uid is IA5String and stays ASCII)
      dn = 'uid=user%05d,%s' % (i, people)
      attrs = ['objectClass: inetOrgPerson', 'uid: user%05d' % i, 'cn:: ' + base64.b64encode(('홍길동 %05d' % i).encode()).decode(),
               'sn:: ' + base64.b64encode('홍'.encode()).decode(), 'displayName:: ' + base64.b64encode(('Çédric Ünï %05d' % i).encode()).decode()]
    else:
      dn = 'uid=user%05d,%s' % (i, people)
      attrs = ['objectClass: inetOrgPerson', 'uid: user%05d' % i, 'cn: User %05d' % i, 'sn: User', 'mail: user%05d@example.invalid' % i]
    if i % 250 == 0:
      attrs.append('userPassword: ' + fake_hash)
    yield dn, 'dn: %s\n%s\n\n' % (dn, '\n'.join(attrs))


def group_entries():
  for i in range(count):
    variant = i % 100
    if variant == 5:
      cn = 'Group-%05d' % i
    elif variant == 9:
      cn = 'grp-ünï-%05d' % i
    elif variant == 11:
      cn = 'ZZ-upper-%05d' % i
    else:
      cn = 'group%05d' % i
    enc = cn if cn.isascii() else None
    dn = 'cn=%s,%s' % (cn.replace(',', '\\,'), groups_ou)
    cnline = ('cn: ' + cn) if enc else 'cn:: ' + base64.b64encode(cn.encode()).decode()
    dnline = ('dn: ' + dn) if enc else 'dn:: ' + base64.b64encode(dn.encode()).decode()
    yield dn, '%s\nobjectClass: groupOfNames\n%s\ndescription: generated group %d\nmember: %s\n\n' % (dnline, cnline, i, reader_dn)


def write_ldif(path):
  with open(path, 'w', encoding='utf-8') as f:
    f.write('dn: %s\nobjectClass: organizationalUnit\nou: people\n\n' % people)
    f.write('dn: %s\nobjectClass: organizationalUnit\nou: groups\n\n' % groups_ou)
    for _, text in user_entries():
      f.write(text)
    for _, text in group_entries():
      f.write(text)


def wait_ldap(container):
  for _ in range(90):
    r = subprocess.run(['docker', 'exec', container, 'sh', '-c',
                        'ldapwhoami -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn], capture_output=True, text=True)
    if r.returncode == 0:
      return
    time.sleep(1)
  raise RuntimeError('LDAP server did not accept the admin bind')


def run_ldap(extra_env=None):
  env = ['-e', 'LDAP_ROOT_DN=' + root, '-e', 'LDAP_ADMIN_PASSWORD', '-e', 'LDAP_DB_MAX_SIZE=2147483648']
  for k, v in (extra_env or {}).items():
    env += ['-e', '%s=%s' % (k, v)]
  command(['docker', 'run', '-d', '--name', ldap, '--network', network, '--network-alias', 'cursor-ldap'] + env +
          ['-v', volumes[0] + ':/etc/openldap/slapd.d', '-v', volumes[1] + ':/var/lib/openldap/data', ldap_image],
          env={**os.environ, 'LDAP_ADMIN_PASSWORD': admin_password})
  if ldap not in containers:
    containers.append(ldap)
  wait_ldap(ldap)


def load_directory():
  # First start bootstraps cn=config; then slapadd loads the bulk offline into
  # the same volumes (the way scripts/bench-load.sh does).
  run_ldap()
  command(['docker', 'rm', '-f', ldap])
  with tempfile.NamedTemporaryFile('w', suffix='.ldif', delete=False) as tmp:
    path = tmp.name
  try:
    t = time.time()
    write_ldif(path)
    loader = name + '-loader'
    command(['docker', 'create', '--name', loader, '--user', 'root', '--entrypoint', 'slapadd',
             '-v', volumes[0] + ':/etc/openldap/slapd.d', '-v', volumes[1] + ':/var/lib/openldap/data',
             ldap_image, '-n', '1', '-F', '/etc/openldap/slapd.d', '-l', '/tmp/load.ldif'])
    command(['docker', 'cp', path, loader + ':/tmp/load.ldif'])
    subprocess.run(['docker', 'start', '-a', loader], check=True, capture_output=True)
    command(['docker', 'rm', '-f', loader])
    print('loaded %d users + %d groups in %.1fs' % (count, count, time.time() - t), flush=True)
  finally:
    os.unlink(path)
  run_ldap()
  command(['docker', 'exec', '-i', ldap, 'sh', '-c', 'ldapadd -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn],
          input='dn: %s\nobjectClass: inetOrgPerson\nuid: reader\ncn: Reader\nsn: Reader\n' % reader_dn)
  command(['docker', 'exec', '-i', ldap, 'sh', '-c',
           'ldappasswd -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" -T /dev/stdin "$1"', admin_dn, reader_dn],
          input=reader_password)


def ldap_admin(cmd, ldif=None):
  """Run an LDAP client command in the slapd container as the admin."""
  return command(['docker', 'exec', '-i', ldap, 'sh', '-c', cmd + ' -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn],
                 input=ldif)


def ground_truth(base, filter_, attr, who):
  """Entries visible to `who` as (dn, [attr values]) by paged ldapsearch, plus ldapsearch's own rc."""
  if who == 'admin':
    args = ['docker', 'exec', ldap, 'sh', '-c',
            'ldapsearch -x -LLL -o ldif-wrap=no -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" -b "$1" -E pr=500/noprompt "$2" "$3"', admin_dn, base, filter_, attr]
    r = subprocess.run(args, capture_output=True, text=True)
  else:
    r = subprocess.run(['docker', 'exec', '-i', ldap, 'ldapsearch', '-x', '-LLL', '-o', 'ldif-wrap=no', '-H', 'ldap://127.0.0.1', '-D', reader_dn,
                        '-y', '/dev/stdin', '-b', base, '-E', 'pr=500/noprompt', filter_, attr], input=reader_password, capture_output=True, text=True)
  entries, dn, vals = [], None, []
  for line in r.stdout.splitlines() + ['']:
    if line.startswith('dn:: '):
      dn = base64.b64decode(line[5:]).decode()
    elif line.startswith('dn: '):
      dn = line[4:]
    elif line.startswith(attr + ':: '):
      vals.append(base64.b64decode(line[len(attr) + 3:]).decode())
    elif line.startswith(attr + ': '):
      vals.append(line[len(attr) + 2:])
    elif line == '' and dn is not None:
      entries.append((dn, vals))
      dn, vals = None, []
  return entries, r.returncode


def order_key(dn, vals):
  key = min((v.lower() for v in vals), default='')
  return (key.encode(), dn.lower().encode())


# ----------------------------------------------------------------------- UI

class Api:
  def __init__(self, url):
    self.url = url
    self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

  def call(self, method, path, body=None, timeout=120):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(self.url + path, data, {'Content-Type': 'application/json', 'Origin': self.url}, method=method)
    t = time.perf_counter()
    try:
      with self.opener.open(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode(), resp.headers, time.perf_counter() - t
    except urllib.error.HTTPError as error:
      return error.code, error.read().decode(), error.headers, time.perf_counter() - t

  def login(self, identity, password):
    status, text, _, _ = self.call('POST', '/api/login', {'identity': identity, 'password': password})
    check(status == 200, 'login as %s failed: %d %s' % (identity, status, text[:120]))

  def page(self, resource, **params):
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    status, text, headers, secs = self.call('GET', '/api/%s?%s' % (resource, qs))
    return status, (json.loads(text) if text else {}), headers, secs, text


def start_ui(container, ldap_url, port_label='8080'):
  command(['docker', 'run', '-d', '--name', container, '--network', network, '-p', '127.0.0.1::8080',
           '-e', 'LDAP_URL=' + ldap_url, '-e', 'LDAP_BASE_DN=' + root,
           '-e', 'LDAP_USER_CREATE_BASE=' + people, '-e', 'LDAP_GROUP_CREATE_BASE=' + groups_ou,
           '-e', 'COOKIE_SECURE=false', ui_image])
  containers.append(container)
  port = command(['docker', 'port', container, '8080/tcp']).splitlines()[0].rsplit(':', 1)[1]
  url = 'http://127.0.0.1:' + port
  for _ in range(60):
    try:
      urllib.request.urlopen(url + '/api/auth/config', timeout=1).close()
      return url
    except Exception:
      time.sleep(1)
  raise RuntimeError('UI did not start')


def traverse(api, resource, limit, q=None):
  """Follow nextCursor to the end. Returns (items, per-page seconds, raw bodies)."""
  items, secs, raws, cursor = [], [], [], None
  for _ in range(100000):
    status, body, _, s, text = api.page(resource, limit=limit, q=q, cursor=cursor)
    check(status == 200, 'page failed: %d %s' % (status, text[:300]))
    secs.append(s)
    raws.append(text)
    check(body['truncated'] is False, 'truncated must be false in cursor mode')
    items.extend(body[resource])
    if not body['hasMore']:
      check('nextCursor' not in body, 'last page carries a nextCursor')
      return items, secs, raws
    check(body.get('nextCursor'), 'hasMore without nextCursor')
    cursor = body['nextCursor']
  raise AssertionError('traversal did not terminate')


def pct(values, p):
  s = sorted(values)
  return s[min(len(s) - 1, int(round((len(s) - 1) * p)))]


def verify_traversal(label, items, truth, key_field):
  dns = [i['dn'] for i in items]
  check(len(dns) == len(set(dns)), '%s: %d duplicate DNs' % (label, len(dns) - len(set(dns))))
  expected = sorted(truth, key=lambda e: order_key(e[0], e[1]))
  check([d for d, _ in expected] == dns,
        '%s: sequence differs from ldapsearch ground truth (got %d, want %d; first diff at %s)' % (
            label, len(dns), len(expected),
            next((i for i, (a, b) in enumerate(zip([d for d, _ in expected], dns)) if a != b), min(len(dns), len(expected)))))
  # The attribute values must be the live ones, not just DNs.
  record(label, '%d entries == ldapsearch ground truth, 0 duplicates, strictly increasing (%s, DN)' % (len(dns), key_field))


def no_secrets(label, raws):
  blob = '\n'.join(raws).lower()
  check('userpassword' not in blob and 'ssha' not in blob and fake_hash.lower() not in blob, label + ': a password attribute reached a page')
  record(label, 'no userPassword / hash in %d pages' % len(raws))


# ------------------------------------------------------------------ slow proxy

PROXY_CODE = r'''
import asyncio, os
DELAY = float(os.environ["DELAY_MS"]) / 1000
UP = (os.environ["UP_HOST"], 389)
async def pipe(r, w, delay):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            if delay:
                await asyncio.sleep(delay)
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass
async def handle(cr, cw):
    ur, uw = await asyncio.open_connection(*UP)
    await asyncio.gather(pipe(cr, uw, 0), pipe(ur, cw, DELAY))
async def main():
    s = await asyncio.start_server(handle, "0.0.0.0", 389)
    async with s:
        await s.serve_forever()
asyncio.run(main())
'''


def start_proxy(label, delay_ms):
  cname = '%s-proxy-%s' % (name, label)
  command(['docker', 'run', '-d', '--name', cname, '--network', network, '--network-alias', cname,
           '-e', 'DELAY_MS=%d' % delay_ms, '-e', 'UP_HOST=cursor-ldap', proxy_image, 'python', '-c', PROXY_CODE])
  containers.append(cname)
  time.sleep(1.5)
  return cname


# ------------------------------------------------------------------ scenarios

def scenario_admin(admin):
  for resource, base, flt, attr, field in (('users', people, '(objectClass=inetOrgPerson)', 'uid', 'smallest uid'),
                                           ('groups', groups_ou, '(objectClass=groupOfNames)', 'cn', 'smallest cn')):
    truth, rc = ground_truth(base, flt, attr, 'admin')
    check(rc == 0, 'admin ground truth ldapsearch rc=%d' % rc)
    check(len(truth) >= count, 'ground truth has only %d %s' % (len(truth), resource))
    items, secs, raws = traverse(admin, resource, 200)
    verify_traversal('admin %s traversal (limit=200)' % resource, items, truth, field)
    no_secrets('admin %s pages' % resource, raws)


def scenario_default_nonroot(reader):
  truth, rc = ground_truth(people, '(objectClass=inetOrgPerson)', 'uid', 'reader')
  record('non-root ldapsearch on the default config', 'rc=%d (4=sizeLimitExceeded) after %d entries' % (rc, len(truth)))
  check(rc == 4 and len(truth) == 10000, 'expected rc=4 after exactly 10000 entries, got rc=%d n=%d' % (rc, len(truth)))

  status, text, _, _ = reader.call('GET', '/api/users')
  body = json.loads(text)
  check(status == 200 and set(body) == {'users', 'truncated'} and body['truncated'] is True and len(body['users']) == 5000,
        'legacy listing changed: %d keys=%s n=%s' % (status, sorted(body), len(body.get('users', []))))
  record('non-root legacy GET /api/users (default config)', '200, keys {users,truncated}, 5000 entries, truncated=true (unchanged)')

  status, body, headers, _, text = reader.page('users', limit=50)
  check(status == 422 and body.get('code') == 'size_limit_exceeded' and body.get('retryable') is False, 'expected 422 size_limit_exceeded, got %d %s' % (status, text[:300]))
  check('users' not in body and 'nextCursor' not in body, 'partial page returned with the error')
  check('LDAP_PAGED_TOTAL_LIMIT' in body['message'] and 'q' in body['message'], 'message lacks the remedies')
  record('non-root cursor mode on the default config', '422 size_limit_exceeded, retryable=false, no users/nextCursor in the body, message names q / exempt identity / LDAP_PAGED_TOTAL_LIMIT')

  status, body, _, _, text = reader.page('groups', limit=50)
  check(status == 422 and body.get('code') == 'size_limit_exceeded', 'groups: expected 422, got %d %s' % (status, text[:200]))

  # Narrowing the candidate set below the limit works for the same identity.
  q = 'user0123'
  items, _, _ = traverse(reader, 'users', 50, q=q)
  check(len(items) >= 1 and all(q in json.dumps(i).lower() for i in items), 'q results do not match q')
  record('non-root narrowed by q=%s' % q, '%d entries returned with the same identity that got 422 without q' % len(items))


def scenario_unlimited_nonroot(reader):
  truth, rc = ground_truth(people, '(objectClass=inetOrgPerson)', 'uid', 'reader')
  check(rc == 0, 'ldapsearch as reader still limited after LDAP_PAGED_TOTAL_LIMIT=unlimited (rc=%d)' % rc)
  items, secs, raws = traverse(reader, 'users', 200)
  verify_traversal('non-root users traversal, LDAP_PAGED_TOTAL_LIMIT=unlimited (limit=200)', items, truth, 'smallest uid')
  gtruth, rc = ground_truth(groups_ou, '(objectClass=groupOfNames)', 'cn', 'reader')
  check(rc == 0, 'groups ldapsearch as reader rc=%d' % rc)
  gitems, _, graws = traverse(reader, 'groups', 200)
  verify_traversal('non-root groups traversal, LDAP_PAGED_TOTAL_LIMIT=unlimited (limit=200)', gitems, gtruth, 'smallest cn')
  no_secrets('non-root pages', raws + graws)


def scenario_cursor_misuse(admin_url, admin):
  status, body, _, _, _ = admin.page('users', limit=5)
  cursor = body['nextCursor']
  status, group_body, _, _, _ = admin.page('groups', limit=5)
  gcursor = group_body['nextCursor']

  def expect400(label, resource, **params):
    st, b, _, _, text = admin.page(resource, **params)
    check(st == 400 and b.get('code') == 'cursor_invalid' and b.get('message') == 'invalid cursor' and b.get('retryable') is False,
          '%s: expected 400 cursor_invalid, got %d %s' % (label, st, text[:200]))

  flipped = cursor[:-3] + ('AAA' if not cursor.endswith('AAA') else 'BBB')
  expect400('tampered', 'users', limit=5, cursor=flipped)
  expect400('truncated', 'users', limit=5, cursor=cursor[:len(cursor) // 2])
  expect400('groups cursor on users', 'users', limit=5, cursor=gcursor)
  expect400('users cursor on groups', 'groups', limit=5, cursor=cursor)
  expect400('different q', 'users', limit=5, q='x', cursor=cursor)
  expect400('oversized', 'users', cursor='A' * 3000)

  # A new login of the SAME DN is a new Session.ID: the old cursor must die.
  fresh = Api(admin_url)
  fresh.login(admin_dn, admin_password)
  st, b, _, _, text = fresh.page('users', limit=5, cursor=cursor)
  check(st == 400 and b.get('code') == 'cursor_invalid', 'cursor survived a re-login: %d %s' % (st, text[:200]))
  st, _, _, _, _ = admin.page('users', limit=5, cursor=cursor)
  check(st == 200, 'cursor stopped working on its own session: %d' % st)
  for q, field in (('limit=0', 'limit'), ('limit=201', 'limit'), ('limit=abc', 'limit'), ('sort=mail', 'sort'), ('q=' + 'a' * 65, 'q'), ('q=a%01b', 'q')):
    status, text, _, _ = admin.call('GET', '/api/users?' + q)
    b = json.loads(text)
    check(status == 422 and b.get('code') == 'validation_failed' and field in b['message'], '%s: %d %s' % (q, status, text[:200]))
  record('cursor misuse', 'tamper/truncate/other resource/other q/oversized/re-login -> 400 cursor_invalid; bad limit/sort/q -> 422 validation_failed; same-session cursor still valid')


def scenario_concurrent_changes(admin):
  """AC-003: the documented table, applied between pages of a small controlled traversal."""
  ids = ['zz-conc-%02d' % i for i in range(30)]
  dn = lambda uid: 'uid=%s,%s' % (uid, people)
  ldif = ''.join('dn: %s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: C\n\n' % (dn(u), u, u) for u in ids)
  ldap_admin('ldapadd', ldif)
  counts = {}

  def take(body):
    for u in body['users']:
      counts[u['dn']] = counts.get(u['dn'], 0) + 1

  status, body, _, _, text = admin.page('users', limit=5, q='zz-conc-')
  check(status == 200 and body['hasMore'], 'first page: %d %s' % (status, text[:200]))
  take(body)
  cursor = body['nextCursor']
  first_page = [u['uid'] for u in body['users']]
  check(first_page == ids[:5], 'first page is not c00..c04: %s' % first_page)

  # (a) add before the cursor, (b) add after it, (c) delete unvisited,
  # (d) delete already returned, (e) rename unvisited to a key before the
  # cursor, (f) rename a visited entry to a key after the cursor.
  ldap_admin('ldapadd', 'dn: %s\nobjectClass: inetOrgPerson\nuid: zz-conc-00a\ncn: a\nsn: C\n\n' % dn('zz-conc-00a'))
  ldap_admin('ldapadd', 'dn: %s\nobjectClass: inetOrgPerson\nuid: zz-conc-10a\ncn: b\nsn: C\n\n' % dn('zz-conc-10a'))
  ldap_admin('ldapdelete', dn('zz-conc-12') + '\n')
  ldap_admin('ldapdelete', dn('zz-conc-01') + '\n')
  ldap_admin('ldapmodrdn -r', '%s\nuid=zz-conc-02a\n' % dn('zz-conc-20'))
  ldap_admin('ldapmodrdn -r', '%s\nuid=zz-conc-25a\n' % dn('zz-conc-02'))

  while True:
    status, body, _, _, text = admin.page('users', limit=5, q='zz-conc-', cursor=cursor)
    check(status == 200, 'page failed: %d %s' % (status, text[:200]))
    take(body)
    if not body['hasMore']:
      break
    cursor = body['nextCursor']

  def times(uid):
    return counts.get(dn(uid), 0)

  expected = {
      'untouched entry (c00)': (times('zz-conc-00'), 1),
      'untouched entry (c07)': (times('zz-conc-07'), 1),
      '(a) added before the cursor (zz-conc-00a)': (times('zz-conc-00a'), 0),
      '(b) added after the cursor (zz-conc-10a)': (times('zz-conc-10a'), 1),
      '(c) unvisited, deleted (zz-conc-12)': (times('zz-conc-12'), 0),
      '(d) already returned, then deleted (zz-conc-01)': (times('zz-conc-01'), 1),
      '(e) unvisited, renamed to a key before the cursor (old + new)': (times('zz-conc-20') + times('zz-conc-02a'), 0),
      '(f) visited, renamed to a key after the cursor (old + new)': (times('zz-conc-02') + times('zz-conc-25a'), 2),
  }
  for label, (got, want) in expected.items():
    check(got == want, '%s: returned %d times, documented %d' % (label, got, want))
  stable = [u for u in ids if u not in ('zz-conc-12', 'zz-conc-20', 'zz-conc-02', 'zz-conc-01')]
  check(all(times(u) == 1 for u in stable), 'a stable entry was not returned exactly once: %s' % {u: times(u) for u in stable if times(u) != 1})
  check(all(v <= 1 for dn_, v in counts.items() if 'zz-conc-02' not in dn_ and 'zz-conc-25a' not in dn_), 'an unrelated duplicate appeared')
  record('concurrent changes between pages (a)-(f)', '; '.join('%s=%d' % (k.split(' ')[0], v[0]) for k, v in expected.items() if k.startswith('(')) + ' -- all match the documented table; every stable entry exactly once')
  # cleanup
  for u in ids + ['zz-conc-00a', 'zz-conc-10a', 'zz-conc-02a', 'zz-conc-25a']:
    subprocess.run(['docker', 'exec', '-i', ldap, 'sh', '-c', 'ldapdelete -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD" "$1"', admin_dn, dn(u)], capture_output=True, text=True)


def scenario_etag(admin):
  """#216: cursor pages carry the same ETag as the legacy list and the single read."""
  for resource, q, field in (('users', 'user00042', 'users'), ('groups', 'group00042', 'groups')):
    status, body, _, _, text = admin.page(resource, q=q, limit=5)
    check(status == 200 and body[field], 'etag probe page failed: %d %s' % (status, text[:200]))
    item = body[field][0]
    check(item.get('etag'), '%s cursor page item has no etag: %s' % (resource, item))
    st, _, headers, _ = admin.call('GET', '/api/entry?' + urllib.parse.urlencode({'dn': item['dn']}))
    check(st == 200 and headers.get('ETag') == item['etag'], '%s: page etag %s != GET /api/entry ETag %s' % (resource, item['etag'], headers.get('ETag')))
    st, text, _, _ = admin.call('GET', '/api/%s' % resource)
    legacy = [i for i in json.loads(text)[field] if i['dn'] == item['dn']]
    check(legacy and legacy[0].get('etag') == item['etag'], '%s: legacy list etag differs from the page etag' % resource)
  record('ETag on cursor pages', 'a user and a group: page item etag == GET /api/entry ETag header == legacy list etag')


def scenario_latency(admin, reader):
  lines = []
  for who, api in (('admin', admin), ('non-root', reader)):
    for resource in ('users', 'groups'):
      for limit in (50, 200):
        status, _, _, _, _ = api.page(resource, limit=limit)  # warm-up
        samples = []
        cursor = None
        for _ in range(30):
          status, body, _, secs, text = api.page(resource, limit=limit, cursor=cursor)
          check(status == 200, 'latency page failed: %d %s' % (status, text[:200]))
          samples.append(secs * 1000)
          cursor = body.get('nextCursor')
          if not cursor:
            break
        lines.append('%-8s %-6s limit=%-3d pages=%-2d p50=%6.0fms p95=%6.0fms p99=%6.0fms' % (who, resource, limit, len(samples), pct(samples, .5), pct(samples, .95), pct(samples, .99)))
    t = time.perf_counter()
    items, secs, _ = traverse(api, 'users', 200)
    lines.append('%-8s users  full traversal limit=200: %d entries, %d pages in %.1fs' % (who, len(items), len(secs), time.perf_counter() - t))
    t = time.perf_counter()
    status, _, _, lsecs = api.call('GET', '/api/users')
    lines.append('%-8s legacy GET /api/users (5000 cap): %d in %.0fms' % (who, status, lsecs * 1000))
  for line in lines:
    record('latency @%d entries' % count, line)


def scenario_slow(slow_ms_probe=150):
  """Starvation and cancellation with latency injected between the UI and slapd."""
  proxy = start_proxy('probe', slow_ms_probe)
  url = start_ui(name + '-ui-probe', 'ldap://%s:389' % proxy)
  api = Api(url)
  api.login(admin_dn, admin_password)

  def probe_loop(stop, out):
    while not stop.is_set():
      for path in ('/api/entry?dn=' + urllib.parse.quote(admin_dn), '/api/me'):
        t = time.perf_counter()
        status, _, _, _ = api.call('GET', path)
        out.setdefault(path.split('?')[0], []).append((time.perf_counter() - t) * 1000)
        if status != 200:
          out.setdefault('bad', []).append(status)
      time.sleep(0.05)

  def with_probe(label, request):
    out, stop = {}, threading.Event()
    th = threading.Thread(target=probe_loop, args=(stop, out))
    th.start()
    t = time.perf_counter()
    status, text = request()
    took = time.perf_counter() - t
    stop.set()
    th.join()
    check(status == 200, '%s request failed: %d %s' % (label, status, text[:200]))
    entry, me = out.get('/api/entry', [0]), out.get('/api/me', [0])
    return took, entry, me, out.get('bad', [])

  # baseline probe latency, no load
  base = []
  for _ in range(10):
    t = time.perf_counter()
    api.call('GET', '/api/entry?dn=' + urllib.parse.quote(admin_dn))
    base.append((time.perf_counter() - t) * 1000)
  record('probe baseline /api/entry (LDAP read, proxy %dms/read)' % slow_ms_probe, 'p50=%.0fms max=%.0fms' % (pct(base, .5), max(base)))

  def cursor_request():
    r = api.page('users', limit=200)
    return r[0], r[4]

  took, entry, me, bad = with_probe('cursor page', cursor_request)
  record('same-session probes during ONE slow cursor page (%.1fs)' % took,
         '/api/entry n=%d p50=%.0fms max=%.0fms; /api/me n=%d max=%.0fms; non-200=%s -- bounded by ~one chunk, not the page' % (
             len(entry), pct(entry, .5), max(entry), len(me), max(me), bad))
  check(not bad, 'probes failed during the cursor page: %s' % bad)
  page_max = max(entry)
  check(page_max < took * 1000 * 0.5, 'a same-session read waited %.0fms of a %.0fms page: the connection lock is held across chunks' % (page_max, took * 1000))

  def legacy():
    st, text, _, _ = api.call('GET', '/api/users')
    return st, text
  took_l, entry_l, me_l, bad_l = with_probe('legacy list', legacy)
  record('same-session probes during the LEGACY listing (%.1fs)' % took_l,
         '/api/entry n=%d p50=%.0fms max=%.0fms -- the legacy scan holds the connection for the whole listing (contrast)' % (len(entry_l), pct(entry_l, .5), max(entry_l)))

  # Request deadline and cancellation on the same shared connection.
  delay = int(os.environ.get('SLOW_REQUEST_DELAY_MS', '1500'))
  proxy2 = start_proxy('timeout', delay)
  url2 = start_ui(name + '-ui-timeout', 'ldap://%s:389' % proxy2)
  api2 = Api(url2)
  api2.login(admin_dn, admin_password)
  t = time.perf_counter()
  status, body, headers, secs, text = api2.page('users', limit=200)
  took = time.perf_counter() - t
  check(status == 503 and body.get('code') == 'scan_timeout' and body.get('retryable') is False, 'expected 503 scan_timeout, got %d %s' % (status, text[:300]))
  check(25 < took < 45, 'timeout answered after %.1fs, expected about the 30s request deadline' % took)
  record('request deadline', '503 scan_timeout after %.1fs (30s deadline + at most one in-flight chunk), no users in the body' % took)
  st, _, _, secs2 = api2.call('GET', '/api/entry?dn=' + urllib.parse.quote(admin_dn))
  check(st == 200, 'the shared connection is unusable after a cancelled chunk: %d' % st)
  st2, text2, _, _ = api2.call('GET', '/api/groups?q=%s&limit=5' % urllib.parse.quote('group00042'))
  check(st2 == 200 and json.loads(text2)['groups'], 'a narrow cursor request after the cancelled chunk failed: %d %s' % (st2, text2[:200]))
  record('connection after a cancelled chunk', 'same session: /api/entry 200 in %.0fms, then a q-narrowed cursor request 200 with %d group(s) (SearchAsync cancellation left the shared connection healthy)' % (secs2 * 1000, len(json.loads(text2)['groups'])))

  # The request deadline must also end the WAIT for the connection lock: a slow
  # legacy listing holds it for its whole scan, and a cursor request on that
  # session must still answer at its own 30 s deadline and free its scan slot.
  api3 = Api(url2)
  api3.login(admin_dn, admin_password)
  legacy = []
  holder = threading.Thread(target=lambda: legacy.append(api3.call('GET', '/api/users', timeout=600)[0]))
  holder.start()
  time.sleep(3)
  t = time.perf_counter()
  status, body, headers, secs, text = api3.page('users', limit=50)
  took = time.perf_counter() - t
  check(status == 503 and body.get('code') == 'scan_timeout', 'expected 503 scan_timeout while the lock is held, got %d %s' % (status, text[:300]))
  check(26 < took < 36, 'a cursor request behind a slow legacy listing ended after %.1fs, expected about its 30s deadline' % took)
  legacy_alive = holder.is_alive()
  holder.join()
  record('deadline while WAITING for the connection lock', '503 scan_timeout after %.1fs although a slow legacy listing still held the connection (%s); legacy finished with %s afterwards' % (took, 'still running at that moment' if legacy_alive else 'it had just finished', legacy))
  st3, text3, _, _ = api3.call('GET', '/api/groups?q=%s&limit=5' % urllib.parse.quote('group00042'))
  check(st3 == 200 and json.loads(text3)['groups'], 'the session cannot list after the abandoned lock wait: %d %s' % (st3, text3[:200]))
  record('scan slot and lock after the abandoned wait', 'the same session served a cursor request again (200, %d group(s))' % len(json.loads(text3)['groups']))


def run():
  command(['docker', 'network', 'create', network])
  for volume in volumes:
    command(['docker', 'volume', 'create', volume])
  load_directory()
  url = start_ui(ui, 'ldap://cursor-ldap:389')
  admin, reader = Api(url), Api(url)
  admin.login(admin_dn, admin_password)
  reader.login(reader_dn, reader_password)

  scenario_admin(admin)
  scenario_default_nonroot(reader)
  scenario_concurrent_changes(admin)

  # Reconcile LDAP_PAGED_TOTAL_LIMIT onto the existing volume, then re-login.
  command(['docker', 'rm', '-f', ldap])
  run_ldap({'LDAP_PAGED_TOTAL_LIMIT': 'unlimited'})
  admin, reader = Api(url), Api(url)
  admin.login(admin_dn, admin_password)
  reader.login(reader_dn, reader_password)
  scenario_unlimited_nonroot(reader)
  scenario_cursor_misuse(url, admin)
  scenario_etag(admin)
  if not os.environ.get('SKIP_PERF'):
    scenario_latency(admin, reader)
  if not os.environ.get('SKIP_SLOW'):
    scenario_slow()
  print('\nPASS: %d checks' % len(results))


try:
  run()
except Exception as error:
  print('FAIL: %s: %s' % (type(error).__name__, mask(error)), file=sys.stderr)
  for container in containers:
    logs = subprocess.run(['docker', 'logs', '--tail', '40', container], capture_output=True, text=True)
    print('--- logs %s ---\n%s' % (container, mask(logs.stdout + logs.stderr)), file=sys.stderr)
  sys.exit(1)
finally:
  for container in set(containers + [ldap, ui, name + '-loader']):
    subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
  for volume in volumes:
    subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
  subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
