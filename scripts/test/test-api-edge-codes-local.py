#!/usr/bin/env python3
"""Disposable LDAP/UI containers prove API edge status codes through the real backend (#223).

Covers unlock idempotency, lock/unlock bind behaviour, group member 409/404,
router 404/405 JSON, the /api/v1/meta allowlist and userPassword redaction.
Also pins the error envelope (#218): every checked error carries exactly
{error, message, code, requestId, retryable}, error == message, requestId ==
X-Request-Id, no DN in the body, and a real 5xx (a wrong current password,
LDAP result 53) is redacted with its cause only in the UI log. The password
policy refusals the change-password screen shows are checked end to end,
including that ppm's user DN is stripped. The conditional-write contract of #216 (ETag/If-Match on every protected route,
PATCH, create compensation) runs as a non-root operator. Image tags come from LDAPIUM_IMAGE /
LDAPIUM_UI_IMAGE (default ldapium:e2e, ldapium-ui:e2e); LDAPIUM_EDGE_PREFIX renames the throwaway docker objects.
"""
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ldap_image = os.environ.get('LDAPIUM_IMAGE', 'ldapium:e2e')
ui_image = os.environ.get('LDAPIUM_UI_IMAGE', 'ldapium-ui:e2e')
root = 'dc=example,dc=org'
admin_dn = 'cn=admin,' + root
name = os.environ.get('LDAPIUM_EDGE_PREFIX', 'ldapium-edge-') + uuid.uuid4().hex[:8]
network = name + '-network'
volumes = [name + '-config', name + '-data']
ldap = name + '-ldap'
ui = name + '-ui'
containers = []
# Throwaway values for a disposable stack; the user password is only used
# against this container.
admin_password = uuid.uuid4().hex + uuid.uuid4().hex
user_password = 'Edge-' + uuid.uuid4().hex[:12] + '!'


def mask(text):
  return str(text).replace(admin_password, '***').replace(user_password, '***').replace(ops_password, '***')


def command(args, **kw):
  # No secret rides in argv (docker run gets them through the environment), and
  # a failure is re-raised with the masked stderr only: CalledProcessError's
  # str() would embed the whole argv.
  try:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kw).stdout.strip()
  except subprocess.CalledProcessError as error:
    raise RuntimeError('%s failed (exit %d): %s' % (' '.join(args[:3]), error.returncode, mask(error.stderr).strip())) from None


def check(condition, message):
  if not condition:
    raise AssertionError(message)


def start_ldap():
  command(['docker', 'run', '-d', '--name', ldap, '--network', network, '--network-alias', 'edge-ldap',
           '-e', 'LDAP_ROOT_DN=' + root, '-e', 'LDAP_ADMIN_PASSWORD', '-e', 'LDAP_PPM_MIN_CLASSES=3',
           '-v', volumes[0] + ':/etc/openldap/slapd.d', '-v', volumes[1] + ':/var/lib/openldap/data', ldap_image],
          env={**os.environ, 'LDAP_ADMIN_PASSWORD': admin_password})
  containers.append(ldap)
  for _ in range(60):
    # $LDAP_ADMIN_PASSWORD is expanded inside the container so the password never
    # appears in this process's argv or output.
    result = subprocess.run(['docker', 'exec', ldap, 'sh', '-c',
                             'ldapwhoami -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn],
                            capture_output=True, text=True)
    if result.returncode == 0:
      return
    time.sleep(1)
  raise RuntimeError('LDAP server did not accept the admin bind')


# #229 probe, run in the LDAP container with the admin password on stdin. Exit 0
# with "names= hits= seen=" on success; any probe failure aborts with a distinct
# status (3 pid-1 environ unreadable, 4 mktemp/empty pattern/grep error) so a
# broken probe can never read as "no match". Messages never contain the secret.
# Only PID 1 and its descendants are scanned: `docker exec` and HEALTHCHECK
# processes inherit the container-configured env (the password included) and have
# PPID 0 inside the namespace, so they are not entrypoint-started processes.
PROCESS_ENV_PROBE = r'''
umask 077
f=$(mktemp) || { echo "probe-error: mktemp failed"; exit 4; }
trap 'rm -f "$f"' EXIT HUP INT TERM
cat > "$f"
[ -s "$f" ] || { echo "probe-error: empty pattern file"; exit 4; }
chk() { case $1 in 0) return 0 ;; 1) return 1 ;; *) echo "probe-error: grep status $1"; exit 4 ;; esac; }
rd() { { tr "\0" "\n" < "$1"; } 2>/dev/null; }
[ -r /proc/1/environ ] || { echo "probe-error: /proc/1/environ unreadable"; exit 3; }
d=$(rd /proc/1/environ) || { echo "probe-error: cannot read /proc/1/environ"; exit 3; }
names=0
for v in ADMIN REPLICATION; do
  printf '%s\n' "$d" | grep -q "^LDAP_${v}_PASSWORD="; chk $? && names=$((names+1))
done
desc() {
  q=$1; i=0
  while [ "$i" -lt 64 ]; do
    [ "$q" = 1 ] && return 0
    s=$(cat "/proc/$q/stat" 2>/dev/null) || return 1
    q=$(printf '%s\n' "$s" | sed "s/^.*) [A-Za-z] //; s/ .*//")
    case $q in ''|*[!0-9]*|0) return 1 ;; esac
    i=$((i+1))
  done
  return 1
}
hits=0; seen=0
for p in /proc/[0-9]*; do
  desc "${p#/proc/}" || continue
  for n in environ cmdline; do
    d=$(rd "$p/$n") || continue
    seen=$((seen+1))
    printf '%s\n' "$d" | grep -qFf "$f"; chk $? && hits=$((hits+1))
  done
done
echo "names=$names hits=$hits seen=$seen"
'''


def check_secret_not_in_process_env():
  # The probe runs under `env -u` (docker exec inherits the container env, which
  # would otherwise make the probe itself a false hit) and takes the value on
  # stdin, so it is never in any argv. Output is counts only, never the value.
  result = subprocess.run(['docker', 'exec', '-i', ldap, 'env', '-u', 'LDAP_ADMIN_PASSWORD', '-u', 'LDAP_REPLICATION_PASSWORD',
                           'sh', '-c', PROCESS_ENV_PROBE], input=admin_password, capture_output=True, text=True)
  out = mask(result.stdout).strip()
  check(result.returncode == 0, 'process-env probe failed (exit %d): %s %s' % (result.returncode, out, mask(result.stderr).strip()))
  fields = dict(item.split('=') for item in out.split())
  check(int(fields['seen']) >= 2, 'process probe successfully read too few /proc entries: ' + out)
  check(fields['names'] == '0', 'LDAP_*_PASSWORD still present in /proc/1/environ: ' + out)
  check(fields['hits'] == '0', 'admin password value found in a container process environ/cmdline: ' + out)
  print('ok: admin password absent from every /proc/*/environ and /proc/*/cmdline (' + out + ')')


def scaffold():
  ldif = ''.join('dn: ou=%s,%s\nobjectClass: organizationalUnit\nou: %s\n\n' % (ou, root, ou) for ou in ('people', 'groups'))
  command(['docker', 'exec', '-i', ldap, 'sh', '-c',
           'ldapadd -x -H ldap://127.0.0.1 -D "$0" -w "$LDAP_ADMIN_PASSWORD"', admin_dn], input=ldif)


def start_ui():
  # --tmpfs + APP_PROFILES_*: the profile routes are what produce 422/412/428/415.
  command(['docker', 'run', '-d', '--name', ui, '--network', network, '-p', '127.0.0.1::8080', '--tmpfs', '/tmp:rw,mode=1777',
           '-e', 'APP_PROFILES_PATH=/tmp/profiles.json', '-e', 'APP_PROFILES_ADMIN_DNS=' + admin_dn,
           '-e', 'LDAP_URL=ldap://edge-ldap:389', '-e', 'LDAP_BASE_DN=' + root,
           '-e', 'LDAP_USER_CREATE_BASE=ou=people,' + root, '-e', 'LDAP_GROUP_CREATE_BASE=ou=groups,' + root,
           '-e', 'COOKIE_SECURE=false', ui_image])
  containers.append(ui)
  port = command(['docker', 'port', ui, '8080/tcp']).rsplit(':', 1)[1]
  url = 'http://127.0.0.1:' + port
  for _ in range(60):
    try:
      urllib.request.urlopen(url + '/api/auth/config', timeout=1).close()
      return url
    except Exception:
      time.sleep(1)
  raise RuntimeError('UI did not start')


def bind_ok(dn):
  # -y /dev/stdin keeps the user password out of argv.
  result = subprocess.run(['docker', 'exec', '-i', ldap, 'ldapwhoami', '-x', '-H', 'ldap://127.0.0.1', '-D', dn, '-y', '/dev/stdin'],
                          input=user_password, capture_output=True, text=True)
  return result.returncode == 0

# --- conditional writes (#216 part A): ETag / If-Match, PATCH, create compensation ---------------------------
CSN_ETAG = re.compile(r'^"[0-9]{14}\.[0-9]{6}Z#[0-9A-F]{6}#[0-9A-F]{3}#[0-9A-F]{6}"$')
ops_dn = 'uid=ops,ou=admins,' + root
ops_password = 'Ops-' + uuid.uuid4().hex[:12] + '-Xq'


def ldap_tool(tool, args, input=None, bind=None):
  # An OpenLDAP client tool run inside the LDAP container; the bind password is
  # expanded there from the container's own environment, never put in argv.
  return subprocess.run(['docker', 'exec', '-i', ldap, 'sh', '-c',
                         'tool=$1; bind=$2; shift 2; exec "$tool" -x -H ldap://127.0.0.1 -D "$bind" -w "$LDAP_ADMIN_PASSWORD" "$@"',
                         'sh', tool, bind or admin_dn] + args, input=input, capture_output=True, text=True)


def setup_ops():
  # A NON-root operator with write access to the whole tree. Non-root matters
  # twice: the conditional writes run under ordinary ACL evaluation (not the
  # rootDN bypass), and ppolicy applies to its password operations (the image's
  # pwdSafeModify refuses a non-root initial password, which is how the create
  # compensation is forced below). `by * break` keeps everyone else on the image's own rules.
  ldif = ('dn: ou=admins,%s\nobjectClass: organizationalUnit\nou: admins\n\n'
          'dn: %s\nobjectClass: inetOrgPerson\nuid: ops\ncn: Ops\nsn: Ops\n') % (root, ops_dn)
  result = ldap_tool('ldapadd', [], ldif)
  check(result.returncode == 0, 'ops entry: ' + mask(result.stderr))
  result = ldap_tool('ldappasswd', ['-T', '/dev/stdin', ops_dn], ops_password)
  check(result.returncode == 0, 'ops password: ' + mask(result.stderr))
  acl = ('dn: olcDatabase={1}mdb,cn=config\nchangetype: modify\nadd: olcAccess\n'
         'olcAccess: {0}to dn.subtree="%s" by dn.exact="%s" write by * break\n') % (root, ops_dn)
  result = ldap_tool('ldapmodify', [], acl, bind='cn=admin,cn=config')
  check(result.returncode == 0, 'ops ACL: ' + mask(result.stderr))


def conditional_writes(url, login):
  call = login(ops_dn, ops_password)

  def expect(code, method, path, body=None, what='', headers=None):
    status, text, hdrs = call(method, path, body, headers)
    check(status == code, '%s: %s %s expected %d, got %d (%s)' % (what, method, path, code, status, mask(text)[:300]))
    return text, hdrs

  def entry(dn):
    text, hdrs = expect(200, 'GET', '/api/entry?' + urllib.parse.urlencode({'dn': dn}), None, 'get entry')
    return json.loads(text)['attributes'], hdrs.get('ETag')

  def etag_of(dn):
    return entry(dn)[1]

  def listed(kind, dn):
    text, _ = expect(200, 'GET', '/api/' + kind, None, 'list ' + kind)
    items = json.loads(text)[kind]
    return next(item for item in items if item['dn'] == dn)

  def stale(method, path, body, what, before_dn):
    # A stale tag must answer 412 revision_conflict, carry no DN/filter, and write nothing.
    tag_before = etag_of(before_dn)
    old = expect_tag['stale']
    text, hdrs = expect(412, method, path, body, what + ' with a stale If-Match', {'If-Match': old})
    parsed = envelope(text, hdrs, 'revision_conflict', what + ' 412', forbidden=('dc=example', 'entryCSN', 'assert', 'uid=', 'cn='))
    check(parsed['retryable'] is False, what + ': 412 must not be retryable')
    check(etag_of(before_dn) == tag_before, what + ': a refused write changed the entry (ETag moved)')

  expect_tag = {}

  def stale_tag(dn, bump_body, bump_path='/api/users'):
    # Read a tag, then change the entry unconditionally so that tag is stale.
    expect_tag['stale'] = etag_of(dn)
    expect(204, 'PATCH', bump_path, bump_body(str(uuid.uuid4().hex[:8])), 'bump')

  def user_bump(dn):
    return lambda v: {'dn': dn, 'department': 'd-' + v}

  def group_bump(dn):
    return lambda v: {'dn': dn, 'description': 'g-' + v}

  def mk_user(uid, **extra):
    body = {'uid': uid, 'cn': 'CW ' + uid, 'sn': 'CW'}
    body.update(extra)
    text, _ = expect(201, 'POST', '/api/users', body, 'create ' + uid)
    return json.loads(text)['dn']

  def mk_group(cn):
    text, _ = expect(201, 'POST', '/api/groups', {'cn': cn}, 'create ' + cn)
    return json.loads(text)['dn']

  # 1. etag exposure -----------------------------------------------------------------------------------
  dn = mk_user('cw-a', mail='a@example.org', givenName='A', department='D1', organization='Org')
  attrs, tag = entry(dn)
  check(tag and CSN_ETAG.match(tag), 'GET /api/entry ETag is not a quoted entryCSN: %r' % tag)
  check(not any(k.lower() in ('entrycsn', 'userpassword') for k in attrs), 'entry attributes expose a revision/password attribute: %s' % sorted(attrs))
  check(listed('users', dn).get('etag') == tag, 'user list etag differs from the entry ETag')
  gdn = mk_group('cw-g')
  check(CSN_ETAG.match(listed('groups', gdn).get('etag', '')), 'group list item has no etag')
  text, _ = expect(200, 'GET', '/api/entry?' + urllib.parse.urlencode({'dn': dn}), None, 'entry body')
  check('entryCSN' not in text and 'etag' not in text.lower(), 'revision leaked into the entry JSON body')
  # GET ignores If-Match entirely.
  expect(200, 'GET', '/api/users', None, 'GET with a garbage If-Match', {'If-Match': 'garbage'})

  # 2. stale If-Match: 412 and no write, every protected route ----------------------------------------------
  stale_tag(dn, user_bump(dn))
  stale('PUT', '/api/users', {'dn': dn, 'cn': 'ZZ stale', 'sn': 'ZZ'}, 'user PUT', dn)
  check(entry(dn)[0]['cn'] == ['CW cw-a'], 'stale PUT changed cn')
  stale_tag(dn, user_bump(dn))
  stale('PATCH', '/api/users', {'dn': dn, 'mail': 'stale@example.org'}, 'user PATCH', dn)
  check(entry(dn)[0]['mail'] == ['a@example.org'], 'stale PATCH changed mail')
  stale_tag(dn, user_bump(dn))
  stale('POST', '/api/users/lock', {'dn': dn}, 'user lock', dn)
  check(listed('users', dn)['locked'] is False, 'stale lock locked the user')
  expect(204, 'POST', '/api/users/lock', {'dn': dn}, 'lock')
  stale_tag(dn, user_bump(dn))
  stale('POST', '/api/users/unlock', {'dn': dn}, 'user unlock', dn)
  check(listed('users', dn)['locked'] is True, 'stale unlock unlocked the user')
  expect(204, 'POST', '/api/users/unlock', {'dn': dn}, 'unlock')
  stale_tag(dn, user_bump(dn))
  stale('DELETE', '/api/users?' + urllib.parse.urlencode({'dn': dn}), None, 'user DELETE', dn)

  stale_tag(gdn, group_bump(gdn), '/api/groups')
  stale('PUT', '/api/groups', {'dn': gdn, 'cn': 'cw-g', 'description': 'stale'}, 'group PUT', gdn)
  stale_tag(gdn, group_bump(gdn), '/api/groups')
  stale('PATCH', '/api/groups', {'dn': gdn, 'description': 'stale'}, 'group PATCH', gdn)
  stale_tag(gdn, group_bump(gdn), '/api/groups')
  member = {'groupDn': gdn, 'memberDn': dn}
  stale('POST', '/api/groups/members', member, 'member add', gdn)
  check(dn not in listed('groups', gdn)['members'], 'stale member add added the member')
  expect(204, 'POST', '/api/groups/members', member, 'member add (unconditional)')
  stale_tag(gdn, group_bump(gdn), '/api/groups')
  mq = '/api/groups/members?' + urllib.parse.urlencode(member)
  stale('DELETE', mq, None, 'member remove', gdn)
  check(dn in listed('groups', gdn)['members'], 'stale member remove removed the member')
  stale_tag(gdn, group_bump(gdn), '/api/groups')
  stale('DELETE', '/api/groups?' + urllib.parse.urlencode({'dn': gdn}), None, 'group DELETE', gdn)

  archive = 'ou=archive,' + root
  result = ldap_tool('ldapadd', [], 'dn: %s\nobjectClass: organizationalUnit\nou: archive\n' % archive)
  check(result.returncode == 0, 'archive ou: ' + mask(result.stderr))
  stale_tag(dn, user_bump(dn))
  stale('POST', '/api/entry/move', {'dn': dn, 'newParentDn': archive}, 'entry move', dn)

  # 3. matching If-Match applies, and the ETag moves -------------------------------------------------------
  def matching(method, path, body, what, target):
    before = etag_of(target)
    expect(204, method, path, body, what + ' with the current If-Match', {'If-Match': before})
    after = etag_of(target)
    check(after != before, what + ': ETag did not change after a conditional write')
    return after

  matching('PUT', '/api/users', {'dn': dn, 'cn': 'CW renamed', 'sn': 'CW', 'mail': 'a@example.org'}, 'user PUT', dn)
  check(entry(dn)[0]['cn'] == ['CW renamed'], 'conditional PUT did not apply')
  matching('PATCH', '/api/users', {'dn': dn, 'mail': 'b@example.org'}, 'user PATCH', dn)
  matching('POST', '/api/users/lock', {'dn': dn}, 'user lock', dn)
  matching('POST', '/api/users/unlock', {'dn': dn}, 'user unlock', dn)
  matching('PUT', '/api/groups', {'dn': gdn, 'cn': 'cw-g', 'description': 'cond'}, 'group PUT', gdn)
  matching('PATCH', '/api/groups', {'dn': gdn, 'description': 'cond2'}, 'group PATCH', gdn)
  matching('DELETE', mq, None, 'member remove', gdn)
  matching('POST', '/api/groups/members', member, 'member add', gdn)
  before_move = etag_of(dn)
  expect(204, 'POST', '/api/entry/move', {'dn': dn, 'newParentDn': archive}, 'entry move with the current If-Match', {'If-Match': before_move})
  moved = 'uid=cw-a,' + archive
  check(etag_of(moved), 'moved entry is not readable at its new DN')
  expect(404, 'GET', '/api/entry?' + urllib.parse.urlencode({'dn': dn}), None, 'old DN is gone after the move')
  expect(204, 'DELETE', '/api/users?' + urllib.parse.urlencode({'dn': moved}), None, 'conditional delete',
         {'If-Match': etag_of(moved)})
  expect(404, 'GET', '/api/entry?' + urllib.parse.urlencode({'dn': moved}), None, 'deleted entry is gone')
  expect(204, 'DELETE', '/api/groups?' + urllib.parse.urlencode({'dn': gdn}), None, 'conditional group delete',
         {'If-Match': etag_of(gdn)})

  # 4. malformed / unsupported If-Match: 400, no write ------------------------------------------------------
  dn = mk_user('cw-b', mail='b@example.org')
  tag = etag_of(dn)
  for bad in ('W/' + tag, tag + ', ' + tag, tag.strip('"'), '"not-a-csn"', '"%s)(objectClass=*"' % tag.strip('"')):
    text, hdrs = expect(400, 'PUT', '/api/users', {'dn': dn, 'cn': 'bad', 'sn': 'bad'}, 'malformed If-Match %r' % bad, {'If-Match': bad})
    envelope(text, hdrs, 'invalid_request', 'malformed If-Match 400')
  expect(204, 'PUT', '/api/users', {'dn': dn, 'cn': 'CW cw-b', 'sn': 'CW', 'mail': 'b@example.org'}, 'If-Match * is unconditional', {'If-Match': '*'})
  text, hdrs = expect(400, 'POST', '/api/users/password', {'dn': dn, 'password': 'Never-Echoed-1'}, 'password If-Match', {'If-Match': tag})
  envelope(text, hdrs, 'invalid_request', 'password If-Match 400', forbidden=('Never-Echoed',))
  check(entry(dn)[0]['cn'] == ['CW cw-b'], 'a rejected If-Match changed the entry')

  # 5. exactly one of two concurrent conditional writers wins ----------------------------------------------
  call2 = login(ops_dn, ops_password)
  for round_no in range(15):
    tag = etag_of(dn)
    results = []

    def writer(client, cn):
      body = {'dn': dn, 'cn': cn, 'sn': 'CW', 'mail': 'b@example.org'}
      status, text, _ = client('PUT', '/api/users', body, {'If-Match': tag})
      results.append((status, cn, text))

    threads = [threading.Thread(target=writer, args=(call, 'CW round%d-A' % round_no)),
               threading.Thread(target=writer, args=(call2, 'CW round%d-B' % round_no))]
    for t in threads:
      t.start()
    for t in threads:
      t.join()
    codes = sorted(status for status, _, _ in results)
    check(codes == [204, 412], 'round %d: concurrent same-ETag writers got %s, want exactly one 204 and one 412' % (round_no, codes))
    winner = next(cn for status, cn, _ in results if status == 204)
    check(entry(dn)[0]['cn'] == [winner], 'round %d: surviving cn is not the 204 winner' % round_no)

  # 6. PATCH keeps what it does not mention; PUT still erases ----------------------------------------------
  dn = mk_user('cw-c', mail='c@example.org', givenName='C', department='D2', organization='Org2')
  expect(204, 'PATCH', '/api/users', {'dn': dn, 'mail': 'c2@example.org'}, 'patch mail only')
  attrs, _ = entry(dn)
  check(attrs.get('mail') == ['c2@example.org'] and attrs.get('givenName') == ['C'] and attrs.get('departmentNumber') == ['D2']
        and attrs.get('o') == ['Org2'], 'PATCH of mail disturbed other attributes: %s' % attrs)
  expect(204, 'PATCH', '/api/users', {'dn': dn, 'givenName': None}, 'patch null removes')
  attrs, _ = entry(dn)
  check('givenName' not in attrs and attrs.get('mail') == ['c2@example.org'], 'null did not remove exactly givenName: %s' % attrs)
  for body in ({'dn': dn, 'givenName': ''}, {'dn': dn, 'uid': 'y'}, {'dn': dn}, {'dn': dn, 'password': 'Nope-Nope-1'}, {'dn': dn, 'cn': None}):
    expect(400, 'PATCH', '/api/users', body, 'invalid patch %s' % sorted(k for k in body if k != 'dn'))
  status, _, _ = call('PATCH', '/api/users', {'dn': dn, 'mail': 'x@example.org'}, {'Content-Type': 'text/plain'})
  check(status == 415, 'PATCH with text/plain expected 415, got %d' % status)
  expect(204, 'PUT', '/api/users', {'dn': dn, 'cn': 'CW cw-c', 'sn': 'CW'}, 'PUT baseline')
  attrs, _ = entry(dn)
  check('mail' not in attrs and 'departmentNumber' not in attrs and 'o' not in attrs, 'PUT no longer erases omitted fields: %s' % attrs)

  # 6b. Pinned limitation (docs/api.md): the ETag is the entry's entryCSN, which only moves on writes made TO that
  # entry. refint removing a deleted user from a group's `member` does not move the group's ETag. If a future
  # change makes this bump the CSN, this check fails so docs and tests are updated deliberately.
  victim = mk_user('cw-refint')
  refint_group = mk_group('cw-refint-g')
  expect(204, 'POST', '/api/groups/members', {'groupDn': refint_group, 'memberDn': victim}, 'add soon-deleted member')
  group_tag = etag_of(refint_group)
  expect(204, 'DELETE', '/api/users?' + urllib.parse.urlencode({'dn': victim}), None, 'delete the member user')
  check(victim not in listed('groups', refint_group)['members'], 'refint did not remove the deleted member from the group')
  check(etag_of(refint_group) == group_tag, 'refint now bumps the group ETag: update docs/api.md, llms.txt, CHANGELOG and CHANGE.md deliberately')

  # 7. create compensation: a failed password step leaves no orphan -------------------------------------
  # As a non-root bind, the image's pwdSafeModify refuses an initial password, so the
  # password step fails after the Add succeeded (the rootDN bypasses ppolicy and cannot be made to fail this way).
  status, text, hdrs = call('POST', '/api/users', {'uid': 'cw-new', 'cn': 'CW New', 'sn': 'CW', 'password': 'Forced-Fail-Pw-1x'}, None)
  check(status == 403, 'forced password failure: %d %s' % (status, mask(text)[:300]))
  parsed = envelope(text, hdrs, 'forbidden', 'rolled-back create', forbidden=('Forced-Fail', 'cw-new', 'dc=example'))
  check(parsed['error'].startswith('user not created'), 'rolled-back text does not say the user was not created: ' + parsed['error'])
  expect(404, 'GET', '/api/entry?' + urllib.parse.urlencode({'dn': 'uid=cw-new,ou=people,' + root}), None, 'no orphan after rollback')
  expect(201, 'POST', '/api/users', {'uid': 'cw-new', 'cn': 'CW New', 'sn': 'CW'}, 'same uid can be created afterwards')

  # 8. delete + re-create of the same DN: the old identity assertion fails with 122 ---------------------
  def identity(target):
    result = ldap_tool('ldapsearch', ['-LLL', '-b', target, '-s', 'base', 'entryUUID', 'entryCSN'])
    check(result.returncode == 0, 'identity read: ' + mask(result.stderr))
    fields = dict(line.split(': ', 1) for line in result.stdout.splitlines() if ': ' in line)
    return fields['entryUUID'], fields['entryCSN']

  for i in range(10):
    uid = 'cw-race%d' % i
    target = mk_user(uid)
    uuid0, csn0 = identity(target)
    expect(204, 'DELETE', '/api/users?' + urllib.parse.urlencode({'dn': target}), None, 'delete before re-create')
    mk_user(uid)
    result = ldap_tool('ldapdelete', ['-e', '!assert=(&(entryUUID=%s)(entryCSN=%s))' % (uuid0, csn0), target])
    check(result.returncode == 122, 'old-identity assertion delete rc=%d (want 122): %s' % (result.returncode, mask(result.stderr)))
    check(etag_of(target), 'the re-created entry did not survive the stale-identity delete')
    uuid1, csn1 = identity(target)
    check(uuid1 != uuid0, 're-created entry kept the old entryUUID')

  # 9. slapd honours criticality: an unknown critical control is refused, not ignored ------------------
  dn = mk_user('cw-d')
  before = etag_of(dn)
  mod = 'dn: %s\nchangetype: modify\nreplace: description\ndescription: critical\n' % dn
  result = ldap_tool('ldapmodify', ['-e', '!1.2.3.4.5.6.7.8'], mod)
  check(result.returncode == 12, 'unknown critical control rc=%d (want 12 unavailableCriticalExtension)' % result.returncode)
  check(etag_of(dn) == before, 'a refused critical-control write changed the entry')
  print('ok: conditional writes (ETag/If-Match on every protected route, stale 412 with no write, concurrent writers 1x204+1x412 x15, PATCH merge, create rollback, identity-bound delete 122)')


ENVELOPE_KEYS = {'error', 'message', 'code', 'requestId', 'retryable'}


def envelope(text, headers, code, what, forbidden=()):
  """Assert text is the five-key error envelope with the expected code."""
  body = json.loads(text)
  check(isinstance(body, dict) and set(body) == ENVELOPE_KEYS, '%s: keys %s != %s (%s)' % (what, sorted(body), sorted(ENVELOPE_KEYS), text[:200]))
  check(isinstance(body['error'], str) and body['error'] and body['error'] == body['message'], '%s: error/message differ or empty (%s)' % (what, text[:200]))
  check(body['code'] == code, '%s: code %r, want %r' % (what, body['code'], code))
  check(body['requestId'] and body['requestId'] == headers.get('X-Request-Id'), '%s: requestId %r != X-Request-Id %r' % (what, body['requestId'], headers.get('X-Request-Id')))
  check(isinstance(body['retryable'], bool), '%s: retryable is not a bool' % what)
  for needle in forbidden:
    check(needle not in text, '%s: body contains %r: %s' % (what, needle, text[:300]))
  return body


def run():
  command(['docker', 'network', 'create', network])
  for volume in volumes:
    command(['docker', 'volume', 'create', volume])
  start_ldap()
  check_secret_not_in_process_env()
  scaffold()
  url = start_ui()

  opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

  def call(method, path, body=None, headers=None, who=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url + path, data, {'Content-Type': 'application/json', 'Origin': url, **(headers or {})}, method=method)
    try:
      with (who or opener).open(request) as response:
        return response.status, response.read().decode(), response.headers
    except urllib.error.HTTPError as error:
      return error.code, error.read().decode(), error.headers

  def login_as(identity, password):
    # A separate session (own cookie jar) for the conditional-write section.
    jar = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def session_call(method, path, body=None, headers=None):
      return call(method, path, body, headers, jar)

    status, text, _ = session_call('POST', '/api/login', {'identity': identity, 'password': password})
    check(status == 200, 'login as %s failed: %d %s' % (identity, status, mask(text)[:200]))
    return session_call

  def expect(code, method, path, body=None, what='', headers=None, who=None):
    status, text, headers = call(method, path, body, headers, who)
    check(status == code, '%s: %s %s expected %d, got %d (%s)' % (what, method, path, code, status, text[:200]))
    return text, headers

  expect(200, 'POST', '/api/login', {'identity': admin_dn, 'password': admin_password}, 'admin login')

  text, _ = expect(201, 'POST', '/api/users', {'uid': 'edge-user', 'cn': 'Edge User', 'sn': 'User', 'password': user_password}, 'create user')
  user_dn = json.loads(text)['dn']
  check(user_dn == 'uid=edge-user,ou=people,' + root, 'unexpected user DN ' + user_dn)
  text, _ = expect(201, 'POST', '/api/groups', {'cn': 'edge-group'}, 'create group')
  group_dn = json.loads(text)['dn']
  check(group_dn == 'cn=edge-group,ou=groups,' + root, 'unexpected group DN ' + group_dn)

  member = {'groupDn': group_dn, 'memberDn': user_dn}
  query = '/api/groups/members?' + urllib.parse.urlencode(member)
  expect(204, 'POST', '/api/groups/members', member, 'add member')
  text, headers = expect(409, 'POST', '/api/groups/members', member, 'add duplicate member')
  envelope(text, headers, 'conflict', 'duplicate member 409', forbidden=(user_dn, group_dn, 'member'))
  expect(204, 'DELETE', query, None, 'remove member')
  expect(404, 'DELETE', query, None, 'remove non-member')

  expect(204, 'POST', '/api/users/unlock', {'dn': user_dn}, 'unlock never-locked user')
  check(bind_ok(user_dn), 'user cannot bind before locking')
  expect(204, 'POST', '/api/users/lock', {'dn': user_dn}, 'lock user')
  check(not bind_ok(user_dn), 'locked user could still bind')
  expect(204, 'POST', '/api/users/unlock', {'dn': user_dn}, 'unlock locked user')
  check(bind_ok(user_dn), 'user cannot bind after unlock')
  text, headers = expect(404, 'POST', '/api/users/unlock', {'dn': 'uid=nobody,ou=people,' + root}, 'unlock missing user')
  envelope(text, headers, 'not_found', 'missing user 404', forbidden=('uid=nobody',))

  text, headers = expect(404, 'GET', '/api/no-such-endpoint', None, 'unknown api path')
  envelope(text, headers, 'not_found', 'unknown path 404')
  text, headers = expect(405, 'TRACE', '/api/users', None, 'wrong method')
  check(headers.get('Allow'), 'wrong method response lacks Allow header')
  envelope(text, headers, 'method_not_allowed', 'wrong method 405')

  # #218: the envelope on the other error classes, through the real backend.
  anonymous = urllib.request.build_opener()
  text, headers = expect(401, 'GET', '/api/users', None, 'no session', who=anonymous)
  envelope(text, headers, 'unauthenticated', 'no session 401')
  text, headers = expect(400, 'POST', '/api/users', {'uid': '!bad', 'cn': 'x', 'sn': 'x'}, 'invalid uid')
  body = envelope(text, headers, 'invalid_request', 'validation 400', forbidden=('!bad',))
  check(body['retryable'] is False, 'validation 400 must not be retryable')
  profile = {'id': 'edge-app', 'name': 'Edge', 'client_id': 'edge', 'issuer': 'https://sso.example/realms/company', 'claim_path': 'groups',
             'token_source': 'access_token', 'enforcement': 'native_app', 'scope': 'subtree', 'mappings': [{'keycloak_role': 'admin', 'native_role': 'owner'}]}
  path = '/api/v1/applications/edge-app/integration-profile'
  text, headers = expect(422, 'PUT', path, profile, 'invalid profile scope', headers={'If-Match': '"0"'})
  envelope(text, headers, 'validation_failed', 'validation 422')
  text, headers = expect(428, 'PUT', path, profile, 'missing If-Match')
  envelope(text, headers, 'if_match_required', 'precondition required 428')
  text, headers = expect(403, 'PUT', path, profile, 'foreign origin', headers={'Origin': 'https://evil.example', 'If-Match': '"0"'})
  envelope(text, headers, 'origin_mismatch', 'foreign origin 403')
  profile['scope'] = 'app'
  expect(200, 'PUT', path, profile, 'create profile', headers={'If-Match': '"0"'})
  text, headers = expect(412, 'PUT', path, profile, 'stale revision', headers={'If-Match': '"0"'})
  envelope(text, headers, 'revision_conflict', 'stale revision 412')

  # Password-policy refusals reach the change-password screen as the server
  # sends them: fixed policy text, never the user's DN (ppm puts it in every
  # message). A wrong current password is LDAP 53, which is a redacted 500.
  user_session = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  expect(200, 'POST', '/api/login', {'identity': user_dn, 'password': user_password}, 'user login', who=user_session)
  change = {'dn': user_dn, 'oldPassword': user_password}
  text, headers = expect(400, 'POST', '/api/users/password', {**change, 'password': 'Ab1!'}, 'too short', who=user_session)
  body = envelope(text, headers, 'invalid_request', 'ppolicy quality 400', forbidden=(user_dn, 'dn='))
  check(body['error'] == 'invalid input: Password fails quality checking policy', 'ppolicy text changed: ' + body['error'])
  text, headers = expect(400, 'POST', '/api/users/password', {**change, 'password': 'aaaaaaaaaaaaaaaa'}, 'ppm strength', who=user_session)
  body = envelope(text, headers, 'invalid_request', 'ppm strength 400', forbidden=(user_dn, 'dn=', 'edge-user'))
  check(body['error'] == 'invalid input: Password does not pass required number of strength checks (1 of 3)', 'ppm text: ' + body['error'])
  text, headers = expect(500, 'POST', '/api/users/password', {**change, 'oldPassword': 'Wrong-' + user_password, 'password': 'New-' + user_password}, 'wrong current password', who=user_session)
  body = envelope(text, headers, 'internal', 'LDAP 53 -> 500', forbidden=('LDAP Result', 'Unwilling', 'verify old password', user_dn))
  check(body['error'] == 'internal error' and body['retryable'] is False, '500 body is not the fixed redacted text: ' + text[:200])
  ui_log = subprocess.run(['docker', 'logs', ui], capture_output=True, text=True)
  ui_log = ui_log.stdout + ui_log.stderr
  check(body['requestId'] in ui_log and 'LDAP Result Code 53' in ui_log, 'UI log lacks the unredacted cause under requestId ' + body['requestId'])

  text, _ = expect(200, 'GET', '/api/v1/meta', None, 'meta')
  keys = set(json.loads(text))
  allowed = {'name', 'apiVersion', 'version', 'authMode', 'openapi'}
  check(keys == allowed, '/api/v1/meta keys %s != allowlist %s' % (sorted(keys), sorted(allowed)))

  text, _ = expect(200, 'GET', '/api/entry?' + urllib.parse.urlencode({'dn': user_dn}), None, 'get entry')
  check('userpassword' not in text.lower(), '/api/entry leaked userPassword')
  check(user_password not in text, '/api/entry leaked the user password')

  setup_ops()
  conditional_writes(url, login_as)

  print('PASS: unlock idempotent (204/404), lock->bind fails->unlock->bind works, group member 204/409/404, error envelope on 400/401/403/404/405/409/412/422/428/500 (error==message, requestId==X-Request-Id, no DN), password-policy text without DN, meta allowlist, no userPassword in /api/entry, conditional writes (If-Match/ETag/PATCH/create rollback)')


try:
  run()
except Exception as error:
  print('FAIL: %s: %s' % (type(error).__name__, mask(error)), file=sys.stderr)
  # Containers are removed in finally, so show their logs now, with every
  # secret this script knows scrubbed out.
  for container in containers:
    logs = subprocess.run(['docker', 'logs', '--tail', '60', container], capture_output=True, text=True)
    text = mask(logs.stdout + logs.stderr)
    print('--- logs %s ---\n%s' % (container, text), file=sys.stderr)
  sys.exit(1)
finally:
  for container in set(containers + [ldap, ui]):
    subprocess.run(['docker', 'rm', '-f', container], capture_output=True)
  for volume in volumes:
    subprocess.run(['docker', 'volume', 'rm', volume], capture_output=True)
  subprocess.run(['docker', 'network', 'rm', network], capture_output=True)
