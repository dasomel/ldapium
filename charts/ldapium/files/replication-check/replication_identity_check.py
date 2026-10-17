"""D59 stable-CSN comparison and D434-2 divergence detector. Attribute values never enter diagnostics."""
import argparse
import base64
import hashlib
import os
import secrets
import shlex
import signal
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


class DirectoryOperationError(ValueError):
  """Raised when a directory subprocess exits non-zero, preserving output."""
  def __init__(self, code, stdout=b'', stderr=b''):
    super().__init__('directory operation failed (code %d)' % code)
    self.code = code
    self.stdout = stdout
    self.stderr = stderr


def tool_run(args, command, data=None, user=None):
  environment = dict(os.environ, LDAPTLS_REQCERT='demand', LDAPTLS_CACERT=args.ca_file)
  result = subprocess.run(tool(args, command, user, data is not None), input=data,
                          capture_output=True, timeout=30, env=environment)
  if result.returncode:
    # Server diagnostics may contain sensitive data: report only operation status.
    raise DirectoryOperationError(result.returncode, result.stdout, result.stderr)
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
  arrived = readable = gone = finished = False
  previous = signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))  # the Job deadline still runs the cleanup
  try:
    try:
      # The add may be applied even when its response is lost, so cleanup is owed from the attempt on.
      tool_run(args, ['ldapadd', *credentials], ldif)
      arrived = wait(True, args.admin_dn, args.admin_password_file)
      readable = arrived and wait(True, 'cn=replicator,' + args.base, args.identity_password_file)
      finished = True
    finally:
      try:
        try:
          tool_run(args, ['ldapdelete', *credentials, dn])
        except ValueError as error:
          if not str(error).endswith('(code 32)'):  # noSuchObject: the add never landed
            raise
        gone = wait(False, args.admin_dn, args.admin_password_file)
      except (ValueError, OSError, subprocess.TimeoutExpired):
        gone = False
      if not (gone and finished):
        print('ERROR: canary entry %s may remain; remove it manually if present' % dn, file=sys.stderr)
  finally:
    signal.signal(signal.SIGTERM, previous)
  if not gone:
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



OPATTRS = frozenset({
    'entrycsn', 'entryuuid', 'hassubordinates', 'subschemasubentry',
    'structuralobjectclass', 'createtimestamp', 'creatorsname',
    'modifytimestamp', 'modifiersname', 'contextcsn'
})


def get_entry_csn(entry):
  if not entry:
    return ()
  for k, v in entry.items():
    if k.lower() == 'entrycsn':
      return v
  return ()


def generalized_time(timestamp):
  return time.strftime('%Y%m%d%H%M%SZ', time.gmtime(timestamp))


def divergence_filter(window_minutes, now_timestamp=None):
  if now_timestamp is None:
    now_timestamp = time.time()
  window_seconds = window_minutes * 60
  gt = generalized_time(now_timestamp - window_seconds)
  # D434-2: modifyTimestamp is not indexed in image/ldifs/01-cn-config.ldif:78 (only entryCSN eq is),
  # so this evaluates entries under the base without an index. Catches modified and newly created
  # entries as well as the #432 defect signature where an entry has no entryCSN / no modifyTimestamp.
  return '(|(modifyTimestamp>=%s)(createTimestamp>=%s)(!(entryCSN=*)))' % (gt, gt)


def canonical_user_attr_hash(entry, opattrs=OPATTRS):
  if entry is None:
    return None
  hasher = hashlib.sha256()
  norm = {k.lower(): v for k, v in entry.items() if k.lower() not in opattrs}
  for key in sorted(norm.keys()):
    hasher.update(key.encode('utf-8'))
    hasher.update(b':')
    for val in sorted(norm[key]):
      hasher.update(str(len(val)).encode('ascii'))
      hasher.update(b':')
      hasher.update(val)
      hasher.update(b';')
    hasher.update(b'|')
  return hasher.hexdigest()


def diff_attributes(entry_a, entry_b, opattrs=OPATTRS):
  if entry_a is None or entry_b is None:
    return []
  map_a = {k.lower(): v for k, v in entry_a.items() if k.lower() not in opattrs}
  map_b = {k.lower(): v for k, v in entry_b.items() if k.lower() not in opattrs}
  diff = set()
  for k in map_a.keys() ^ map_b.keys():
    diff.add(k)
  for k in map_a.keys() & map_b.keys():
    if sorted(map_a[k]) != sorted(map_b[k]):
      diff.add(k)
  return sorted(diff)


def evaluate_entry_divergence(entries_by_target, opattrs=OPATTRS):
  """Evaluates candidate entry divergence across targets.

  Never prints or stores raw attribute values (especially userPassword);
  only exposes target URIs, truncated hashes, CSN status, and differing attribute names.
  """
  missing_targets = [t for t, e in entries_by_target.items() if e is None]
  present_entries = {t: e for t, e in entries_by_target.items() if e is not None}

  if not present_entries:
    return False, {}

  if missing_targets:
    return True, {
        'missing_targets': sorted(missing_targets),
        'lacks_csn_targets': [],
        'hashes': {},
        'csns': {},
        'differing_attrs': [],
    }

  lacks_csn_targets = []
  for t, e in present_entries.items():
    csn = get_entry_csn(e)
    if len(csn) != 1 or not csn[0]:
      lacks_csn_targets.append(t)

  if lacks_csn_targets:
    return True, {
        'missing_targets': [],
        'lacks_csn_targets': sorted(lacks_csn_targets),
        'hashes': {},
        'csns': {},
        'differing_attrs': [],
    }

  hashes = {t: canonical_user_attr_hash(e, opattrs) for t, e in present_entries.items()}
  distinct_hashes = set(hashes.values())

  csns = {t: get_entry_csn(e)[0] for t, e in present_entries.items()}
  distinct_csns = set(csns.values())

  if len(distinct_hashes) > 1:
    differing_attrs = set()
    targets_list = list(present_entries.keys())
    for i in range(len(targets_list)):
      for j in range(i + 1, len(targets_list)):
        differing_attrs.update(
            diff_attributes(present_entries[targets_list[i]],
                            present_entries[targets_list[j]],
                            opattrs)
        )
    return True, {
        'missing_targets': [],
        'lacks_csn_targets': [],
        'hashes': hashes,
        'csns': csns,
        'differing_attrs': sorted(differing_attrs),
    }

  if len(distinct_csns) > 1:
    return True, {
        'missing_targets': [],
        'lacks_csn_targets': [],
        'hashes': hashes,
        'csns': csns,
        'differing_attrs': [],
    }

  return False, {}


def format_divergence_reason(details):
  parts = []
  if details.get('missing_targets'):
    parts.append('missing entry on %s' % ', '.join(details['missing_targets']))
  if details.get('lacks_csn_targets'):
    parts.append('lacks entryCSN on %s' % ', '.join(details['lacks_csn_targets']))
  if len(set(details.get('hashes', {}).values())) > 1:
    attrs = details.get('differing_attrs') or []
    attr_msg = (' differing attributes: %s' % ', '.join(attrs)) if attrs else ''
    hash_summary = ', '.join('%s=%s' % (t, h[:16] if h else 'none')
                             for t, h in sorted(details['hashes'].items()))
    parts.append('user attribute mismatch (%s)%s' % (hash_summary, attr_msg))
  if len(set(details.get('csns', {}).values())) > 1:
    csn_summary = ', '.join('%s=%s' % (t, c.decode('ascii', errors='replace')
                                        if isinstance(c, bytes) else str(c))
                            for t, c in sorted(details['csns'].items()))
    parts.append('entryCSN mismatch (%s)' % csn_summary)
  return '; '.join(parts) if parts else 'unknown divergence'


def read_candidate_entry(args, dn):
  dn_str = dn.decode('utf-8') if isinstance(dn, bytes) else dn
  command = ['ldapsearch', '-x', '-LLL', '-o', 'ldif-wrap=no', '-H', args.uri,
             '-D', args.admin_dn, '-y', args.admin_password_file,
             '-b', dn_str, '-s', 'base', '(objectClass=*)', '*', 'entryCSN']
  try:
    rows = parse_ldif(tool_run(args, command))
    if not rows:
      return None
    for row in rows.values():
      return row
    return None
  except ValueError as error:
    if str(error).endswith('(code 32)'):
      return None
    raise


def paged_results_args(page_size):
  if page_size < 1:
    raise ValueError('page size must be at least 1')
  return ['-E', 'pr=%d/noprompt' % page_size]


def find_candidates(args, targets, filter_str, page_size=500):
  all_dns = set()
  hit_size_limit = False
  for target in targets:
    node_args = SimpleNamespace(**vars(args))
    node_args.uri = target
    command = ['ldapsearch', '-x', '-LLL', '-o', 'ldif-wrap=no',
               *paged_results_args(page_size),
               '-H', target,
               '-D', args.admin_dn, '-y', args.admin_password_file,
               '-b', args.base, filter_str, 'dn']
    try:
      raw = tool_run(node_args, command)
    except DirectoryOperationError as error:
      if error.code == 4:  # LDAP_SIZELIMIT_EXCEEDED
        hit_size_limit = True
        raw = error.stdout
      else:
        raise
    rows = parse_ldif(raw)
    all_dns.update(rows.keys())
  if hit_size_limit:
    print('WARN: divergence candidate search reached server size limit (code 4); checking available candidates', file=sys.stderr)
  return sorted(all_dns)


def run_divergence_check(args, targets):
  flt = divergence_filter(args.divergence_window_minutes)
  page_size = getattr(args, 'divergence_page_size', 500)
  candidates = find_candidates(args, targets, flt, page_size=page_size)
  if not candidates:
    print('PASS: divergence check: 0 candidate entries within %d minutes across %d selected nodes'
          % (args.divergence_window_minutes, len(targets)))
    return 0

  max_candidates = getattr(args, 'divergence_max_candidates', 500)
  total_candidates = len(candidates)
  capped = False
  if total_candidates > max_candidates:
    capped = True
    print('WARN: candidate count %d exceeds cap %d; checking first %d entries deterministically'
          % (total_candidates, max_candidates, max_candidates), file=sys.stderr)
    candidates = candidates[:max_candidates]

  # D434-2 cap: per-candidate per-node read subprocesses bounded by max_candidates * len(targets).
  # Exceeding candidate cap returns rc 0 with WARN: batch modifications should not fail
  # replication check (rc 2) while healthy syncrepl is active; cost: remaining entries uninspected
  # in this run; escape hatch: increase --divergence-max-candidates or inspect WARN logs.
  suspects = {}
  for dn in candidates:
    entries = {}
    for target in targets:
      node_args = SimpleNamespace(**vars(args))
      node_args.uri = target
      entries[target] = read_candidate_entry(node_args, dn)
    diverged, details = evaluate_entry_divergence(entries)
    if diverged:
      suspects[dn] = details

  if suspects:
    if args.divergence_grace_seconds > 0:
      time.sleep(args.divergence_grace_seconds)
    confirmed = {}
    for dn in suspects:
      recheck_entries = {}
      for target in targets:
        node_args = SimpleNamespace(**vars(args))
        node_args.uri = target
        recheck_entries[target] = read_candidate_entry(node_args, dn)
      diverged, details = evaluate_entry_divergence(recheck_entries)
      if diverged:
        confirmed[dn] = details

    if confirmed:
      for dn, details in confirmed.items():
        dn_display = dn.decode('utf-8', errors='replace') if isinstance(dn, bytes) else str(dn)
        print('FAIL: divergence detected for dn="%s": %s'
              % (dn_display, format_divergence_reason(details)), file=sys.stderr)
      print('FAIL: %d entry divergence(s) detected across %d selected nodes'
            % (len(confirmed), len(targets)), file=sys.stderr)
      return 1

  if capped:
    print('PASS: divergence check: %d of %d candidate entries verified across %d selected nodes (capped)'
          % (len(candidates), total_candidates, len(targets)))
  else:
    print('PASS: divergence check: %d candidate entries verified across %d selected nodes'
          % (len(candidates), len(targets)))
  return 0


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
  parser.add_argument('--divergence', action='store_true',
                      help='detect cross-provider state divergence for recently modified entries (#434)')
  parser.add_argument('--divergence-window-minutes', type=int, default=45,
                      help='lookback window in minutes for recent modifications')
  parser.add_argument('--divergence-grace-seconds', type=int, default=5,
                      help='grace period in seconds to wait before re-reading divergent entries')
  parser.add_argument('--divergence-max-candidates', type=int, default=500,
                      help='maximum candidate entries to evaluate across providers')
  parser.add_argument('--divergence-page-size', type=int, default=500,
                      help='page size for paged candidate searches')
  args = parser.parse_args()
  targets = list(dict.fromkeys([args.uri, *args.peer]))
  if any(not valid_uri(target) for target in targets):
    parser.error('one pinned verified LDAPS URI is required per target; lists and URI options are refused')
  args.attributes = [key.lower() for key in args.attributes]
  if any(key in ('*', '+', 'contextcsn', 'entrycsn') or not key.isalnum()
          for key in args.attributes):
    parser.error('attributes must be an explicit data-attribute list')
  if args.divergence:
    if args.configuration_only:
      parser.error('--divergence needs the data check')
    if args.divergence_window_minutes < 1:
      parser.error('--divergence-window-minutes must be at least 1')
    if args.divergence_grace_seconds < 0:
      parser.error('--divergence-grace-seconds must be non-negative')
    if args.divergence_max_candidates < 1:
      parser.error('--divergence-max-candidates must be at least 1')
    if args.divergence_page_size < 1:
      parser.error('--divergence-page-size must be at least 1')
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
    if args.divergence:
      rc = run_divergence_check(args, targets)
      if rc != 0:
        return rc
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
