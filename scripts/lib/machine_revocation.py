#!/usr/bin/env python3
"""Operator-only revocation writer; never use the UI API for this subtree."""
import argparse
import base64
import datetime
import hashlib
import re
import secrets
import subprocess
import sys
import time

# D2: ceilings mirror machineauth.Retention; the cross-language test owns drift.
# Cost: conservative retention. Escape hatch: --retention may increase it only.
MAX_TTL = 3600
MAX_SKEW = 60
MAX_REFRESH = 60
MAX_STALE = 600
MIN_RETENTION = MAX_TTL + 3 * MAX_SKEW + MAX_REFRESH + MAX_STALE
MAX_RETENTION = 86400
MAX_VALUE_BYTES = 512


class Error(Exception):
  pass


def single(values):
  if len(values) != 1 or not values[0] or len(values[0].encode()) > MAX_VALUE_BYTES:
    raise Error('attribute must have exactly one bounded, nonempty value')
  if any(c in values[0] for c in '\r\n\x00'):
    raise Error('attribute contains newline or NUL')
  return values[0]


def digest(entries):
  return hashlib.sha256('\n'.join(sorted(single(e.get('cn', [])) for e in entries)).encode()).hexdigest()


def ldif(attrs):
  # All values are encoded: DN metacharacters and non-ASCII cannot inject LDIF.
  return ''.join(k + ':: ' + base64.b64encode(v.encode()).decode() + '\n' for k, v in attrs)


def parse_ldif(data):
  unfolded = re.sub(r'\r?\n ', '', data)
  entries = []
  for block in re.split(r'\r?\n\r?\n', unfolded):
    entry = {}
    for line in block.splitlines():
      if not line or line.startswith('#'):
        continue
      key, sep, value = line.partition(':')
      if not sep or value.startswith('<'):
        raise Error('unsupported LDAP output')
      if value.startswith(':'):
        value = base64.b64decode(value[1:].strip(), validate=True).decode()
      else:
        value = value.lstrip(' ')
      entry.setdefault(key.lower(), []).append(value)
    if entry:
      entries.append(entry)
  return entries


def rdn(value):
  return ''.join('\\%02x' % b if b in b',+"\\<>;=# ' else chr(b)
                 for b in value.encode('ascii'))


def timestamp(value):
  return int(datetime.datetime.strptime(value, '%Y%m%d%H%M%SZ').replace(
    tzinfo=datetime.timezone.utc).timestamp())


class Directory:
  def __init__(self, args):
    self.args = args

  def run(self, tool, extra=(), data=None, allowed=(0,)):
    a = self.args
    cmd = [tool, '-x', '-H', a.uri, '-D', a.bind_dn, '-y', a.password_file,
           '-o', 'nettimeout=5', *extra]
    if a.container:
      cmd = ['docker', 'exec', '-i', a.container, *cmd]
    try:
      p = subprocess.run(cmd, input=data, text=True, capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
      raise Error('LDAP command failed or timed out') from exc
    if p.returncode not in allowed:
      # Never echo LDAP diagnostics: a rejected request can contain identifiers.
      raise Error('LDAP command failed (rc=%d); sentinel was not published' % p.returncode)
    return p

  def search(self):
    p = self.run('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', self.args.base,
      '-s', 'sub', '(objectClass=*)', 'dn', 'objectClass', 'cn', 'ou',
      'serialNumber', 'description', 'createTimestamp', 'modifyTimestamp'])
    rows = parse_ldif(p.stdout)
    base = [e for e in rows if 'organizationalunit' in [v.lower() for v in e.get('objectclass', [])]
            and e.get('dn', [''])[0].lower() == self.args.base.lower()]
    if len(base) != 1 or single(base[0].get('ou', [])) != 'revocations':
      raise Error('revocations container missing or malformed')
    rows.remove(base[0])
    sent = None
    entries = []
    for e in rows:
      cn = single(e.get('cn', []))
      if 'device' not in [v.lower() for v in e.get('objectclass', [])]:
        raise Error('stray non-device entry: refusing writes')
      # D3: direct children only, one cn and ou. Cost: strict format; repair offline.
      expected = 'cn=' + rdn(cn) + ',' + self.args.base
      if single(e.get('dn', [])).lower() != expected.lower():
        raise Error('stray or nested entry: refusing writes')
      single(e.get('ou', []))
      timestamp(single(e.get('createtimestamp', [])))
      if cn == 'sentinel':
        if sent is not None:
          raise Error('duplicate sentinel')
        sent = e
      elif (cn.startswith('jti-') and len(cn) > 4) or (cn.startswith('cutoff-') and len(cn) > 7):
        entries.append(e)
      else:
        raise Error('stray malformed entry: refusing writes')
    if sent:
      gen = single(sent.get('serialnumber', []))
      desc = single(sent.get('description', []))
      match = re.fullmatch(r'entries=(\d+);digest=([0-9a-f]{64});ts=(\d+);ret=(\d+)', desc)
      if not re.fullmatch(r'[1-9]\d*', gen) or int(gen) >= 2**63 - 1 or not match:
        raise Error('malformed sentinel')
      ret = int(match[4])
      if not MIN_RETENTION <= ret <= MAX_RETENTION or single(sent.get('ou', [])) != 'revocations':
        raise Error('invalid sentinel retention or ou')
      self.args.retention = max(self.args.retention, ret)
    return sent, entries

  def add(self, cn, ou, more=()):
    dn = 'cn=' + rdn(cn) + ',' + self.args.base
    data = ldif([('dn', dn), ('objectClass', 'top'), ('objectClass', 'device'),
                 ('cn', cn), ('ou', ou), *more]) + '\n'
    return self.run('ldapadd', data=data, allowed=(0, 68)).returncode

  def delete(self, entry):
    self.run('ldapdelete', [single(entry['dn'])], allowed=(0, 32))

  def prune(self, entries):
    cutoff = int(time.time()) - self.args.retention
    for e in entries:
      if single(e['cn']).startswith('jti-') and timestamp(single(e['createtimestamp'])) < cutoff:
        self.delete(e)

  def publish(self):
    # D7/REQ-013: re-read and recompute after a CAS collision. Writes precede the
    # sentinel; a failed publication is unavailable, never a claimed success.
    for attempt in range(8):
      sent, entries = self.search()
      if not sent:
        raise Error('sentinel missing: run init before enabling revocation')
      self.prune(entries)
      sent, entries = self.search()
      if not sent:
        raise Error('sentinel disappeared')
      ts = int(time.time())  # Only after pruning and the final read.
      # REQ-013: count the set at published ts, even across a second boundary.
      entries = [e for e in entries if not single(e['cn']).startswith('jti-')
                 or timestamp(single(e['createtimestamp'])) >= ts - self.args.retention]
      if len(entries) > self.args.max_entries:
        raise Error('entry cap exceeded; sentinel not published')
      if len(entries) * 5 > self.args.max_entries * 4:
        print('WARN: revocations exceed 80% of the entry cap', file=sys.stderr)
      gen = str(int(single(sent['serialnumber'])) + 1)
      desc = 'entries=%d;digest=%s;ts=%d;ret=%d' % (len(entries), digest(entries), ts, self.args.retention)
      data = ldif([('dn', single(sent['dn']))]) + 'changetype: modify\n'
      for attr, new in [('serialNumber', gen), ('description', desc)]:
        data += 'delete: ' + attr + '\n' + ldif([(attr, single(sent[attr.lower()]))]) + '-\n'
        data += 'add: ' + attr + '\n' + ldif([(attr, new)]) + '-\n'
      p = self.run('ldapmodify', data=data + '\n', allowed=(0, 16))
      if p.returncode == 0:
        print('published generation=%s entries=%d' % (gen, len(entries)))
        return
      print('WARN: sentinel CAS rc=16; rereading and retrying', file=sys.stderr)
      time.sleep(0.02 + secrets.randbelow(30) / 1000)
    raise Error('sentinel CAS retry budget exhausted; rerun heartbeat')


def main():
  p = argparse.ArgumentParser(description=__doc__)
  p.add_argument('command', choices=['init', 'add', 'remove', 'prune', 'heartbeat', 'retention'])
  p.add_argument('--uri', default='ldaps://localhost:636')
  p.add_argument('--base', help='exact ou=revocations,<parent DN>')
  p.add_argument('--bind-dn')
  p.add_argument('--password-file')
  p.add_argument('--container', help='execute LDAP CLI inside this local container')
  p.add_argument('--kind', choices=['jti', 'cutoff'])
  p.add_argument('--id-file', help='jti identifier file (never a bearer token)')
  p.add_argument('--client', help='client id metadata; required for add')
  p.add_argument('--cn', help='exact entry cn for remove; sentinel is forbidden')
  p.add_argument('--retention', type=int, default=MIN_RETENTION)
  p.add_argument('--max-entries', type=int, default=2000)
  a = p.parse_args()
  if not MIN_RETENTION <= a.retention <= MAX_RETENTION or not 1 <= a.max_entries <= 2500:
    raise Error('invalid retention or entry cap')
  if a.command == 'retention':
    print(a.retention)
    return
  if not a.base or not re.fullmatch(r'ou=revocations,.+=.+', a.base, re.I) or any(c in a.base for c in '\r\n\x00'):
    raise Error('--base must be ou=revocations,<parent DN>')
  if not a.bind_dn or not a.password_file:
    raise Error('--bind-dn and --password-file are required')
  d = Directory(a)
  sent, entries = d.search()
  if a.command == 'init':
    if sent or entries:
      raise Error('init requires an empty existing revocations container')
    desc = 'entries=0;digest=%s;ts=%d;ret=%d' % (digest([]), int(time.time()), a.retention)
    if d.add('sentinel', 'revocations', [('serialNumber', '1'), ('description', desc)]) != 0:
      raise Error('sentinel already exists; init refused')
    print('initialized generation=1 entries=0')
    return
  if not sent:
    raise Error('sentinel missing: run init first')
  if a.command == 'add':
    client = single([a.client] if a.client else [])
    if not client.isascii() or not re.fullmatch(r'[A-Za-z0-9_.:-]+', client):
      raise Error('client must be an ASCII identifier')
    if a.kind == 'jti':
      if not a.id_file:
        raise Error('jti requires --id-file')
      with open(a.id_file, encoding='utf-8') as f:
        identifier = single([f.read(MAX_VALUE_BYTES + 1)])
      # D286-13b: Keycloak transient token ids use a colon-prefixed identifier.
      # Keep dots forbidden so a JWT cannot be supplied as an identifier.
      if not re.fullmatch(r'[A-Za-z0-9_:-]+', identifier):
        raise Error('jti must be an identifier, never a JWT or bearer token')
      cn = single(['jti-' + identifier])
    elif a.kind == 'cutoff':
      cn = single(['cutoff-' + client + '-' + secrets.token_hex(8)])
    else:
      raise Error('add requires --kind')
    d.prune(entries)
    sent, entries = d.search()
    if not sent:
      raise Error('sentinel disappeared')
    if len(entries) >= a.max_entries and not any(single(e['cn']) == cn for e in entries):
      raise Error('entry cap reached; run prune or increase the supported cap')
    rc = d.add(cn, client)
    if rc == 68:
      _, current = d.search()
      if a.kind != 'jti' or not any(single(e['cn']) == cn and single(e['ou']) == client for e in current):
        raise Error('existing LDAP entry does not match the exact requested identifier/client')
    if a.kind == 'cutoff':
      for e in entries:
        if single(e['cn']).startswith('cutoff-') and single(e['ou']) == client:
          d.delete(e)  # New cutoff exists before any old cutoff is removed.
  elif a.command == 'remove':
    cn = single([a.cn] if a.cn else [])
    if cn == 'sentinel':
      raise Error('sentinel removal is forbidden')
    for e in entries:
      if single(e['cn']) == cn:
        d.delete(e)
  d.publish()


if __name__ == '__main__':
  try:
    main()
  except (Error, ValueError, UnicodeError, OSError) as exc:
    print('ERROR: machine-revocation: ' + str(exc), file=sys.stderr)
    sys.exit(1)
