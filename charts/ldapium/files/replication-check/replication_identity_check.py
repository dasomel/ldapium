"""D59 stable-CSN comparison. Prints counts only; hashes never enter diagnostics."""
import argparse
import base64
import os
import secrets
import shlex
import subprocess
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlsplit
from replication_uri import valid_uri

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


def endpoint(uri):
  # D68: scheme-less (host, port) so ldaps://n1 and ldaps://N1:636 are one member.
  parsed = urlsplit(uri)
  return (parsed.hostname or '').rstrip('.').lower(), parsed.port or 636


def providers(config_rows):
  # Provider endpoints named by a node's own olcSyncrepl values (D68).
  found = set()
  for row in config_rows.values():
    for value in row.get('olcsyncrepl', ()):
      for part in shlex.split(value.decode()):
        key, sep, item = part.partition('=')
        if sep and key == 'provider':
          if not valid_uri(item):
            raise ValueError('consumer provider is not LDAPS')
          found.add(endpoint(item))
  return found


def missing_members(config_rows, targets):
  # D68: the authoritative member list is outside the directory, but every node
  # records the providers it follows. A provider that is not a checked target is
  # a node whose data this run would silently not compare.
  checked = {endpoint(target) for target in targets}
  return sorted(providers(config_rows) - checked)


def tool(args, command, user=None, stdin=False):
  if args.container:
    prefix = ['docker', 'exec', '-e', 'LDAPTLS_REQCERT=demand',
              '-e', 'LDAPTLS_CACERT=' + args.ca_file]
    if user:
      prefix += ['-u', user]
    if stdin:
      prefix.append('-i')
    command = [*prefix, args.container, *command]
  return command


def tool_run(args, command, data=None, user=None):
  environment = dict(os.environ, LDAPTLS_REQCERT='demand', LDAPTLS_CACERT=args.ca_file)
  result = subprocess.run(tool(args, command, user, data is not None), input=data,
                          capture_output=True, timeout=30, env=environment)
  if result.returncode:
    # Server diagnostics may contain sensitive data: report only operation status.
    raise ValueError('directory operation failed (code %d)' % result.returncode)
  return result.stdout


def slapcat(args):
  # D69: offline read of the node's own database, run as the slapd user so the
  # MDB lock file keeps its owner. Only the compared attributes (and entryCSN)
  # are kept, exactly like the remote view.
  raw = tool_run(args, ['slapcat', '-b', args.base, '-o', 'ldif-wrap=no'], user='ldap')
  keep = {'entrycsn', *args.attributes}
  return {dn: {key: value for key, value in row.items() if key in keep}
          for dn, row in parse_ldif(raw).items()}


def admin_view(args, node_args):
  if args.local and node_args.uri == args.uri:
    return slapcat(node_args)
  return search(node_args, args.admin_dn, args.admin_password_file)


def canary(args, targets):
  # D70: opt-in write. One throwaway entry on the anchor node, no credentials in
  # it, deleted again; every selected node must show it and then lose it.
  dn = 'cn=ridcheck-%s,%s' % (secrets.token_hex(6), args.base)
  ldif = ('dn: %s\nobjectClass: applicationProcess\ncn: %s\n'
          % (dn, dn.split(',')[0][3:])).encode()
  credentials = ['-x', '-H', args.uri, '-D', args.admin_dn, '-y', args.admin_password_file]
  def visible(target, who, password):
    node_args = SimpleNamespace(**vars(args))
    node_args.uri = target
    return dn.encode() in search_one(node_args, who, password, dn)
  def wait(want, who, password):
    deadline = time.monotonic() + args.canary_timeout
    pending = set(targets)
    while pending:
      pending = {t for t in pending if visible(t, who, password) != want}
      if not pending:
        return True
      if time.monotonic() >= deadline:
        return False
      time.sleep(1)
    return True
  tool_run(args, ['ldapadd', *credentials], ldif)
  try:
    arrived = wait(True, args.admin_dn, args.admin_password_file)
    readable = arrived and wait(True, 'cn=replicator,' + args.base, args.identity_password_file)
  finally:
    try:
      tool_run(args, ['ldapdelete', *credentials, dn])
      gone = wait(False, args.admin_dn, args.admin_password_file)
    except (ValueError, subprocess.TimeoutExpired):
      gone = False
  if not gone:
    print('ERROR: canary entry %s could not be removed or its deletion did not replicate; remove it manually' % dn, file=sys.stderr)
    return 2
  if not arrived:
    print('FAIL: canary entry did not replicate to every selected node within %ds' % args.canary_timeout, file=sys.stderr)
    return 1
  if not readable:
    print('FAIL: canary entry replicated but is not readable by the replication identity', file=sys.stderr)
    return 1
  print('PASS: canary entry replicated to %d selected nodes, readable by the identity, and deleted everywhere' % len(targets))
  return 0


def search_one(args, who, password, dn):
  command = ['ldapsearch', '-x', '-LLL', '-o', 'ldif-wrap=no', '-H', args.uri,
             '-D', who, '-y', password, '-b', dn, '-s', 'base', '(objectClass=*)', '1.1']
  try:
    return parse_ldif(tool_run(args, command))
  except ValueError as error:
    # 32 = no such object is the expected answer for a not-yet-replicated or deleted entry.
    if str(error).endswith('(code 32)'):
      return {}
    raise


def search(args, dn, password):
  command = ['ldapsearch', '-x', '-LLL', '-o', 'ldif-wrap=no', '-H', args.uri,
             '-D', dn, '-y', password, '-b', args.base, '(objectClass=*)',
             'entryCSN', *args.attributes]
  return parse_ldif(tool_run(args, command))


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
  parser.add_argument('--peer', action='append', default=[])
  parser.add_argument('--require-converged', action='store_true')
  parser.add_argument('--admin-dn')
  parser.add_argument('--admin-password-file', required=True)
  parser.add_argument('--identity-password-file')
  parser.add_argument('--config-password-file')
  parser.add_argument('--configuration-only', action='store_true')
  parser.add_argument('--dedicated', action='store_true')
  parser.add_argument('--ca-file', required=True)
  parser.add_argument('--container')
  parser.add_argument('--local', action='store_true',
                      help='read the --uri node with slapcat (inside --container, else on this host) instead of an administrator bind')
  parser.add_argument('--canary', action='store_true',
                      help='write, observe on every selected node, and delete one throwaway entry (a directory mutation)')
  parser.add_argument('--canary-timeout', type=int, default=30)
  parser.add_argument('--attributes', nargs='+', default=list(ATTRS))
  args = parser.parse_args()
  targets = list(dict.fromkeys([args.uri, *args.peer]))
  if any(not valid_uri(target) for target in targets):
    parser.error('one pinned verified LDAPS URI is required per target; lists and URI options are refused')
  args.attributes = [key.lower() for key in args.attributes]
  if any(key in ('*', '+', 'contextcsn', 'entrycsn') or not key.isalnum()
         for key in args.attributes):
    parser.error('attributes must be an explicit data-attribute list')
  if args.canary and (args.configuration_only or not 1 <= args.canary_timeout <= 600):
    parser.error('--canary needs the data check and a timeout of 1-600 seconds')
  if args.local and args.configuration_only:
    parser.error('--local reads data; configuration-only does not')
  if args.configuration_only and args.require_converged:
    parser.error('configuration-only cannot establish data convergence')
  args.admin_dn = args.admin_dn or 'cn=admin,' + args.base
  if not args.configuration_only and not args.identity_password_file:
    parser.error('--identity-password-file required for data visibility')
  if args.configuration_only and not args.config_password_file:
    parser.error('--config-password-file required for configuration inspection')
  if args.dedicated and (not args.config_password_file or not args.identity_password_file):
    parser.error('--dedicated requires config and current identity password files')
  try:
    if args.config_password_file:
      for target in targets:
        node_args = SimpleNamespace(**vars(args))
        node_args.uri = target
        from replication_identity_config import FIELDS, configuration
        cfg_args = SimpleNamespace(**vars(node_args))
        cfg_args.base = 'cn=config'
        cfg_args.attributes = FIELDS
        config_rows = search(cfg_args, 'cn=admin,cn=config', args.config_password_file)
        absent = missing_members(config_rows, targets)
        if absent:
          print('FAIL: %d replication provider(s) named in the node configuration are not checked targets' % len(absent), file=sys.stderr)
          return 1
        password = None
        if args.dedicated:
          password = read_password_file(node_args, args.identity_password_file)
          if password == read_password_file(node_args, args.admin_password_file):
            print('FAIL: replication credential equals administrator credential', file=sys.stderr)
            return 1
        try:
          consumers = configuration(config_rows, args.base, args.dedicated, password)
        except ValueError:
          print('FAIL: identity configuration predicates did not pass', file=sys.stderr)
          return 1
        data_args = SimpleNamespace(**vars(node_args))
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
      anchor_first = admin_view(args, args)
      if not anchor_first:
        raise ValueError('empty root view cannot establish evidence')
      failed, pending, node_first_views = 0, 0, []
      for target in targets:
        node_args = SimpleNamespace(**vars(args))
        node_args.uri = target
        first = admin_view(args, node_args)
        if not first:
          raise ValueError('empty peer root view cannot establish evidence')
        visible = search(node_args, 'cn=replicator,' + args.base, args.identity_password_file)
        second = admin_view(args, node_args)
        bad, deferred = compare(first, visible, second, args.attributes)
        failed += bad
        pending += deferred
        node_first_views.append(first)
      anchor_second = admin_view(args, args)
      for view in node_first_views:
        bad, deferred = compare(anchor_first, view, anchor_second, args.attributes)
        failed += bad
        pending += deferred
      if failed:
        print('FAIL: %d stable entry comparisons differ' % failed, file=sys.stderr)
        return 1
      if not pending:
        print('PASS: %d stable entries compared across %d selected nodes' % (len(anchor_first), len(targets)))
        return canary(args, targets) if args.canary else 0
    # D59: strict gates may fail during sustained healthy writes; retry after a
    # quiet interval. Default WARN is diagnostic, never restore/rotation acceptance.
    if args.require_converged:
      print('FAIL: %d comparisons did not converge in 5 passes' % pending, file=sys.stderr)
      return 1
    print('WARN: %d comparisons remained unstable after 5 passes' % pending)
    return canary(args, targets) if args.canary else 0
  except (ValueError, OSError, subprocess.TimeoutExpired):
    print('ERROR: directory check could not establish evidence', file=sys.stderr)
    return 2


if __name__ == '__main__':
  sys.exit(main())
