#!/usr/bin/env python3
"""Fixed backup worker; accepts policy JSON on stdin, secrets only via operator file."""
import argparse
import configparser
import datetime as dt
import gzip
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import uuid

RUN = re.compile(r'^\d{8}T\d{6}Z-[a-f0-9]{12}$')


def command(argv):
  return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)


def validate_remote(target, cfg):
  parser = configparser.ConfigParser(interpolation=None)
  parser.read(cfg['rclone_config'])
  remote = target['remote']
  if not re.fullmatch(r'[A-Za-z0-9_-]+', remote) or not parser.has_section(remote):
    raise ValueError('unknown remote')
  section = parser[remote]
  actual = section.get('type')
  if actual != {'s3': 's3', 'ftp': 'ftp', 'ftps': 'ftp', 'sftp': 'sftp'}[target['type']]:
    raise ValueError('transport mismatch')
  if actual == 'sftp' and not section.get('known_hosts_file'):
    raise ValueError('SSH known_hosts_file required')
  if actual == 'ftp':
    tls = section.get('tls', 'false').lower() == 'true' or section.get('explicit_tls', 'false').lower() == 'true'
    if target['type'] == 'ftps' and not tls:
      raise ValueError('FTPS requires TLS')
    if not tls and not target.get('allow_plaintext', False):
      raise ValueError('plaintext FTP requires operator opt-in')
  prefix = target['prefix']
  if not re.fullmatch(r'[A-Za-z0-9_./-]+', prefix) or any(p in {'', '.', '..'} for p in prefix.split('/')):
    raise ValueError('invalid remote prefix')
  return remote + ':' + prefix


def digest(path):
  hasher = hashlib.sha256()
  with path.open('rb') as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b''):
      hasher.update(block)
  return hasher.hexdigest()


def verify(directory):
  manifest = json.loads((directory / 'complete.json').read_text())
  for name, checksum in manifest['sha256'].items():
    if Path(name).name != name or digest(directory / name) != checksum:
      raise ValueError('backup checksum mismatch')
  return manifest


def prune(root, kind, policy, now, instance_id=None):
  owned = []
  for path in root.iterdir():
    if path.is_symlink() or not path.is_dir() or not RUN.fullmatch(path.name):
      continue
    try:
      manifest = verify(path)
      if (manifest['kind'] != kind or manifest['owner'] != 'ldapium-backup-v1'
          or manifest.get('instance_id') != instance_id or manifest.get('run_id') != path.name):
        continue
      created = dt.datetime.fromisoformat(manifest['created_at'])
      owned.append((created, path))
    except (OSError, ValueError, KeyError):
      continue
  owned.sort(reverse=True)
  for index, (created, path) in enumerate(owned):
    # Always retain newest successful copy, regardless of age/count.
    if index > 0 and (index >= policy['keep_count'] or (now - created).total_seconds() > policy['keep_days'] * 86400):
      shutil.rmtree(path)




def verify_remote(common, base, marker):
  for name, checksum in marker['sha256'].items():
    if Path(name).name != name or not re.fullmatch(r'[a-f0-9]{64}', checksum):
      raise ValueError('invalid remote checksum entry')
    hasher = hashlib.sha256()
    process = subprocess.Popen(common + ['cat', base + '/' + name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
      for block in iter(lambda: process.stdout.read(1024 * 1024), b''):
        hasher.update(block)
      if process.wait(timeout=1800) or hasher.hexdigest() != checksum:
        raise ValueError('remote checksum mismatch')
    finally:
      process.stdout.close()
      if process.poll() is None:
        process.kill(); process.wait()


def owned(marker, cfg, kind, name):
  return (marker.get('owner') == 'ldapium-backup-v1' and marker.get('instance_id') == cfg['instance_id']
    and marker.get('kind') == kind and marker.get('run_id') == name)


def cleanup_remote(common, base, cfg, kind, now):
  listing = command(common + ['lsf', base, '--dirs-only']).stdout.decode().splitlines()
  for entry in listing:
    name = entry.rstrip('/')
    if not RUN.fullmatch(name):
      continue
    try:
      pending = json.loads(command(common + ['cat', base + '/' + name + '/pending.json']).stdout)
      if owned(pending, cfg, kind, name):
        # Only this instance's explicitly marked abandoned uploads are removed.
        files = command(common + ['lsf', base + '/' + name, '--files-only']).stdout.decode().splitlines()
        if 'complete.json' in files:
          # Read errors/corrupt markers never prove absence. Preserve the backup;
          # a verified completed run only needs its stale pending marker removed.
          completed = json.loads(command(common + ['cat', base + '/' + name + '/complete.json']).stdout)
          if owned(completed, cfg, kind, name):
            verify_remote(common, base + '/' + name, completed)
            command(common + ['deletefile', base + '/' + name + '/pending.json'])
          continue
        command(common + ['purge', base + '/' + name])
    except (ValueError, KeyError, subprocess.CalledProcessError):
      continue


def prune_remote(common, base, cfg, kind, policy, now):
  entries = command(common + ['lsf', base, '--dirs-only']).stdout.decode().splitlines()
  owned = []
  for entry in entries:
    name = entry.rstrip('/')
    if not RUN.fullmatch(name):
      continue
    try:
      marker = json.loads(command(common + ['cat', base + '/' + name + '/complete.json']).stdout)
      if (marker.get('owner') != 'ldapium-backup-v1' or marker.get('instance_id') != cfg['instance_id']
          or marker.get('kind') != kind or marker.get('run_id') != name):
        continue
      verify_remote(common, base + '/' + name, marker)
      owned.append((dt.datetime.fromisoformat(marker['created_at']), name))
    except (ValueError, KeyError, subprocess.CalledProcessError):
      continue
  owned.sort(reverse=True)
  for index, (created, name) in enumerate(owned):
    if index > 0 and (index >= policy['keep_count'] or (now - created).total_seconds() > policy['keep_days'] * 86400):
      command(common + ['purge', base + '/' + name])


def run(cfg, kind, policy):
  root = Path(cfg['root']); root.mkdir(parents=True, exist_ok=True, mode=0o700)
  with (root / '.worker.lock').open('a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return locked_run(cfg, kind, policy)


def locked_run(cfg, kind, policy):
  os.umask(0o077)
  if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', cfg['instance_id']):
    raise ValueError('stable instance id required')
  now = dt.datetime.now(dt.timezone.utc)
  root = Path(cfg['root']) / kind
  root.mkdir(parents=True, exist_ok=True, mode=0o700)
  for path in root.glob('.pending-*'):
    if path.is_dir() and not path.is_symlink():
      try:
        owner = json.loads((path / '.owner.json').read_text())
        if owner == {'instance_id': cfg['instance_id'], 'kind': kind}: shutil.rmtree(path)
      except (OSError, ValueError): pass
  run_id = now.strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:12]
  staging = Path(tempfile.mkdtemp(prefix='.pending-', dir=root))
  (staging / '.owner.json').write_text(json.dumps({'instance_id': cfg['instance_id'], 'kind': kind}))
  try:
    if kind == 'data':
      ldap = cfg['ldap']
      bases = [('data', ldap['admin_dn'], ldap['base_dn'])]
      if ldap.get('include_config', True):
        bases.append(('config', ldap.get('config_admin_dn', 'cn=admin,cn=config'), 'cn=config'))
      for name, bind, base in bases:
        args = [cfg.get('ldapsearch', 'ldapsearch'), '-x', '-H', ldap['url'], '-D', bind,
          '-y', ldap['password_file'], '-b', base, '-E', 'pr=500/noprompt', '-o', 'ldif-wrap=no', '-o', 'nettimeout=10']
        if ldap.get('start_tls', False):
          args.append('-ZZ')
        args += ['(objectClass=*)', '*', '+']
        # No LDIF or credentials enter controller output/API. Existing restore
        # sanitizer keeps operational UUID/CSN while dropping generated attributes.
        with tempfile.TemporaryFile(dir=staging) as raw:
          subprocess.run(args, check=True, stdout=raw, stderr=subprocess.PIPE, timeout=1800)
          raw.seek(0)
          with gzip.open(staging / f'{name}-{run_id}.ldif.gz', 'wb') as stream:
            shutil.copyfileobj(raw, stream, 1024 * 1024)
      if cfg.get('metadata_files'):
        with tarfile.open(staging / 'metadata.tar.gz', 'w:gz') as archive:
          for index, value in enumerate(cfg['metadata_files']):
            source = Path(value)
            if source.is_symlink() or not source.is_file():
              raise ValueError('metadata source must be regular non-symlink file')
            archive.add(source, arcname=f'{index}-{source.name}', recursive=False)
      files = sorted(p for p in staging.iterdir() if p.name != '.owner.json')
      (staging / f'manifest-{run_id}.sha256').write_text(''.join(
        digest(path) + '  ' + path.name + '\n' for path in files))
    elif kind == 'logs':
      paths = cfg.get('log_paths', [])
      if not paths:
        raise ValueError('no log sources configured')
      with tarfile.open(staging / 'logs.tar.gz', 'w:gz') as archive:
        for index, value in enumerate(paths):
          source = Path(value)
          if source.is_symlink() or not source.is_file():
            raise ValueError('log source must be a regular non-symlink file')
          archive.add(source, arcname=f'{index}-{source.name}', recursive=False)
    else:
      raise ValueError('invalid kind')
    manifest = {'owner': 'ldapium-backup-v1', 'kind': kind, 'run_id': run_id,
      'created_at': now.isoformat(), 'instance_id': cfg['instance_id'], 'sha256': {p.name: digest(p) for p in staging.iterdir() if p.name != '.owner.json'}}
    (staging / 'complete.json').write_text(json.dumps(manifest))
    verify(staging)
    final = root / run_id
    staging.rename(final)
    (final / '.owner.json').unlink()
    prune(root, kind, policy, now, cfg['instance_id'])
    for identifier in policy['destinations']:
      target = next(t for t in cfg['destinations'] if t['id'] == identifier)
      if target['type'] == 'local':
        continue
      base = validate_remote(target, cfg) + '/' + cfg['instance_id'] + '/' + kind
      destination = base + '/' + run_id
      common = [cfg.get('rclone', 'rclone'), '--config', cfg['rclone_config'], '--retries', '2', '--low-level-retries', '2', '--timeout', '1m', '--contimeout', '10s']
      try:
        cleanup_remote(common, base, cfg, kind, now)
      except subprocess.CalledProcessError:
        pass  # A new destination namespace may not exist yet.
      command(common + ['copyto', str(final / 'complete.json'), destination + '/pending.json'])
      # Commit marker uploaded last; partial remote uploads never have complete.json.
      command(common + ['copy', str(final), destination, '--exclude', 'complete.json'])
      command(common + ['check', str(final), destination, '--exclude', 'complete.json', '--one-way', '--download'])
      command(common + ['copyto', str(final / 'complete.json'), destination + '/complete.json'])
      if json.loads(command(common + ['cat', destination + '/complete.json']).stdout) != manifest:
        raise ValueError('remote completion marker mismatch')
      command(common + ['deletefile', destination + '/pending.json'])
      prune_remote(common, base, cfg, kind, policy, now)
    return {'run_id': run_id, 'kind': kind, 'verified': True, 'local_verified': True, 'destinations': policy['destinations']}
  except Exception as error:
    if 'final' in locals() and final.exists():
      error.backup_result = {'run_id': run_id, 'kind': kind, 'verified': False, 'local_verified': True}
    raise
  finally:
    if staging.exists():
      shutil.rmtree(staging)


def managed_run(cfg, kind, policy):
  connections = policy.get('connections', [])
  if not connections:
    return run(cfg, kind, policy)
  root = Path(cfg['root'])
  root.mkdir(parents=True, exist_ok=True, mode=0o700)
  # D37: write-only credentials arrive over the private worker pipe. Transient
  # rclone configuration and pinned keys never become command-line arguments.
  with tempfile.TemporaryDirectory(prefix='.connections-', dir=root) as temporary:
    private = Path(temporary)
    parser = configparser.ConfigParser(interpolation=None)
    if cfg.get('rclone_config'): parser.read(cfg['rclone_config'])
    merged = dict(cfg)
    merged['destinations'] = list(cfg['destinations'])
    for connection in connections:
      if connection['id'] not in policy['destinations']: continue
      # D38: never overwrite an operator section, even if it uses our prefix.
      remote = 'ldapium-managed-' + uuid.uuid4().hex
      while parser.has_section(remote): remote = 'ldapium-managed-' + uuid.uuid4().hex
      section = {'type': connection['type']}
      if connection['type'] == 's3':
        section.update(provider='Other', access_key_id=connection['access_key'], secret_access_key=connection['secret_key'], region=connection.get('region', ''), force_path_style='true')
        if connection.get('endpoint'): section['endpoint'] = connection['endpoint']
        prefix = connection['bucket'] + '/' + connection['prefix']
      else:
        section.update(type='ftp' if connection['type'] in ('ftp', 'ftps') else 'sftp', host=connection['host'], port=str(connection['port']), user=connection['user'])
        section['pass'] = subprocess.run([cfg.get('rclone', 'rclone'), 'obscure', '-'], input=connection['password']+'\n', text=True, check=True, capture_output=True, timeout=30).stdout.strip()
        prefix = connection['prefix']
        if connection['type'] == 'ftps': section['explicit_tls'] = 'true'
        if connection['type'] == 'sftp':
          keys = private / (remote + '.known_hosts')
          keys.write_text(connection['known_hosts']); keys.chmod(0o600)
          section['known_hosts_file'] = str(keys)
      parser[remote] = section
      merged['destinations'].append({'id': connection['id'], 'name': connection['name'], 'type': connection['type'], 'remote': remote, 'prefix': prefix, 'allow_plaintext': connection.get('allow_plaintext', False)})
    config = private / 'rclone.conf'
    with config.open('w') as stream: parser.write(stream)
    config.chmod(0o600)
    merged['rclone_config'] = str(config)
    return run(merged, kind, policy)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--config', required=True)
  parser.add_argument('--kind', choices=['data', 'logs'], required=True)
  args = parser.parse_args()
  cfg = json.loads(Path(args.config).read_text())
  policy = json.load(__import__('sys').stdin)
  print(json.dumps(managed_run(cfg, args.kind, policy)))


if __name__ == '__main__':
  try:
    main()
  except Exception as error:
    if hasattr(error, 'backup_result'): print(json.dumps(error.backup_result))
    raise SystemExit('backup failed; check operator configuration, source availability and destination access')
