"""D59 stable-CSN comparison. Prints counts only; hashes never enter diagnostics."""
import argparse
import base64
import subprocess
import sys

ATTRS = ('userpassword', 'objectclass', 'uid', 'cn', 'sn', 'mail')


def parse_ldif(raw):
  lines = []
  for line in raw.splitlines():
    if line.startswith(b' '):
      if not lines:
        raise ValueError('invalid LDIF continuation')
      lines[-1] += line[1:]
    else:
      lines.append(line)
  rows, row = {}, {}
  for line in lines + [b'']:
    if not line:
      if row:
        dn = row.pop('dn', [])
        if len(dn) != 1 or dn[0] in rows:
          raise ValueError('missing or duplicate DN')
        rows[dn[0]] = {key: tuple(sorted(value)) for key, value in row.items()}
        row = {}
      continue
    if line.startswith(b'#'):
      continue
    key, sep, value = line.partition(b':')
    if not sep:
      raise ValueError('invalid LDIF field')
    key = key.decode('ascii').lower()
    if value.startswith(b':'):
      value = base64.b64decode(value[1:].lstrip(b' '), validate=True)
    elif value.startswith(b'<'):
      raise ValueError('LDIF external references refused')
    else:
      value = value.lstrip(b' ')
    row.setdefault(key, []).append(value)
  return rows


def compare(first, identity, second, attrs=ATTRS):
  # D59: same entryCSN and different contents is a defect, even if another
  # entry changed during the scan. Unstable entries are deferred, never failed.
  for view in (first, identity, second):
    for item in view.values():
      csn = item.get('entrycsn', ())
      if len(csn) != 1 or not csn[0]:
        raise ValueError('entryCSN unavailable to checker')
  failed, pending = 0, 0
  for dn in first.keys() | identity.keys() | second.keys():
    a, v, b = first.get(dn), identity.get(dn), second.get(dn)
    if a is None or b is None or a.get('entrycsn') != b.get('entrycsn'):
      pending += 1
      continue
    if any(a.get(key, ()) != b.get(key, ()) for key in attrs):
      failed += 1
      continue
    if v is not None and v.get('entrycsn') != a.get('entrycsn'):
      pending += 1
      continue
    if v is None or any(a.get(key, ()) != v.get(key, ()) for key in attrs):
      failed += 1
  return failed, pending


def search(args, dn, password):
  command = ['ldapsearch', '-x', '-LLL', '-o', 'ldif-wrap=no', '-H', args.uri,
             '-D', dn, '-y', password, '-b', args.base, '(objectClass=*)',
             'entryCSN', *args.attributes]
  if args.container:
    command = ['docker', 'exec', '-e', 'LDAPTLS_REQCERT=demand',
               '-e', 'LDAPTLS_CACERT=' + args.ca_file, args.container, *command]
  import os
  environment = dict(os.environ, LDAPTLS_REQCERT='demand', LDAPTLS_CACERT=args.ca_file)
  result = subprocess.run(command, capture_output=True, timeout=30, env=environment)
  if result.returncode:
    # Server diagnostics may contain sensitive data: report only operation status.
    raise ValueError('directory read failed (code %d)' % result.returncode)
  return parse_ldif(result.stdout)


def read_password_file(args, path):
  if args.container:
    result = subprocess.run(['docker', 'exec', args.container, 'cat', path],
                            capture_output=True, timeout=5)
    if result.returncode:
      raise ValueError('credential file unreadable')
    return result.stdout
  with open(path, 'rb') as file:
    return file.read()


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--uri', required=True)
  parser.add_argument('--base', required=True)
  parser.add_argument('--admin-dn')
  parser.add_argument('--admin-password-file', required=True)
  parser.add_argument('--identity-password-file')
  parser.add_argument('--config-password-file')
  parser.add_argument('--configuration-only', action='store_true')
  parser.add_argument('--dedicated', action='store_true')
  parser.add_argument('--ca-file', required=True)
  parser.add_argument('--container')
  parser.add_argument('--attributes', nargs='+', default=list(ATTRS))
  args = parser.parse_args()
  if not args.uri.startswith('ldaps://'):
    parser.error('verified LDAPS is required')
  args.attributes = [key.lower() for key in args.attributes]
  if any(key in ('*', '+', 'contextcsn', 'entrycsn') or not key.isalnum()
         for key in args.attributes):
    parser.error('attributes must be an explicit data-attribute list')
  args.admin_dn = args.admin_dn or 'cn=admin,' + args.base
  if not args.configuration_only and not args.identity_password_file:
    parser.error('--identity-password-file required for data visibility')
  if args.configuration_only and not args.config_password_file:
    parser.error('--config-password-file required for configuration inspection')
  if args.dedicated and (not args.config_password_file or not args.identity_password_file):
    parser.error('--dedicated requires config and current identity password files')
  try:
    if args.config_password_file:
      from replication_identity_config import FIELDS, configuration
      from types import SimpleNamespace
      cfg_args = SimpleNamespace(**vars(args))
      cfg_args.base = 'cn=config'
      cfg_args.attributes = FIELDS
      config_rows = search(cfg_args, 'cn=admin,cn=config', args.config_password_file)
      password = None
      if args.dedicated:
        password = read_password_file(args, args.identity_password_file)
        if password == read_password_file(args, args.admin_password_file):
          print('FAIL: replication credential equals administrator credential', file=sys.stderr)
          return 1
      try:
        consumers = configuration(config_rows, args.base, args.dedicated, password)
      except ValueError:
        print('FAIL: identity configuration predicates did not pass', file=sys.stderr)
        return 1
      data_args = SimpleNamespace(**vars(args))
      data_args.attributes = ['authzTo', 'authzFrom']
      delegation = search(data_args, args.admin_dn, args.admin_password_file)
      if not delegation:
        raise ValueError('root view empty')
      if any(item.get('authzto') or item.get('authzfrom') for item in delegation.values()):
        print('FAIL: delegated data authorization is present', file=sys.stderr)
        return 1
      print('PASS: configuration predicates and %d consumer credential fingerprints' % consumers)
      if args.configuration_only:
        return 0
    for attempt in range(5):
      first = search(args, args.admin_dn, args.admin_password_file)
      if not first:
        raise ValueError('empty root view cannot establish evidence')
      visible = search(args, 'cn=replicator,' + args.base, args.identity_password_file)
      second = search(args, args.admin_dn, args.admin_password_file)
      failed, pending = compare(first, visible, second, args.attributes)
      if failed:
        print('FAIL: %d stable entries differ' % failed, file=sys.stderr)
        return 1
      if not pending:
        print('PASS: %d stable entries checked' % len(first))
        return 0
    print('WARN: %d entries remained unstable after 5 reads' % pending)
    return 0
  except (ValueError, OSError, subprocess.TimeoutExpired):
    print('ERROR: directory check could not establish evidence', file=sys.stderr)
    return 2


if __name__ == '__main__':
  sys.exit(main())
