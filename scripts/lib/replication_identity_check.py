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


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--uri', required=True)
  parser.add_argument('--base', required=True)
  parser.add_argument('--admin-dn')
  parser.add_argument('--admin-password-file', required=True)
  parser.add_argument('--identity-password-file', required=True)
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
  try:
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
