import datetime as dt
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('backup_worker', Path(__file__).parents[2] / 'ui/backend/backup-tools/backup_worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class BackupWorkerTests(unittest.TestCase):
  def test_managed_connections_preserve_operator_sections_and_dotted_bucket(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary)
      config = root / 'operator.conf'
      config.write_text('[ldapium-managed-demo]\ntype=s3\nendpoint=https://operator.example\n')
      cfg = dict(root=str(root), instance_id='test', destinations=[{'id': 'operator', 'type': 's3', 'remote': 'ldapium-managed-demo', 'prefix': 'bucket/backups'}], rclone_config=str(config))
      connection = dict(id='demo', name='Demo', type='s3', access_key='key', secret_key='secret', bucket='backup.example', prefix='backups')
      def inspect(merged, kind, policy, job_id=None):
        parser = worker.configparser.ConfigParser(interpolation=None);parser.read(merged['rclone_config'])
        self.assertEqual(parser['ldapium-managed-demo']['endpoint'], 'https://operator.example')
        target = next(t for t in merged['destinations'] if t['id'] == 'demo')
        self.assertNotEqual(target['remote'], 'ldapium-managed-demo')
        self.assertTrue(worker.validate_remote(target, merged).endswith(':backup.example/backups'))
        return {'verified': True}
      with patch.object(worker, 'run', side_effect=inspect):
        worker.managed_run(cfg, 'logs', dict(destinations=['demo'], connections=[connection]))
      self.assertFalse(list(root.glob('.connections-*')))

  def test_logs_integrity_and_independent_retention(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary);source = root / 'audit.log';source.write_text('audit event')
      cfg = {'root': str(root / 'backups'), 'instance_id': 'test', 'log_paths': [str(source)], 'destinations': [{'id': 'local', 'type': 'local'}]}
      policy = {'keep_count': 1, 'keep_days': 7, 'destinations': ['local']}
      first = worker.run(cfg, 'logs', policy)
      first_dir = root / 'backups/logs' / first['run_id']
      worker.verify(first_dir)
      (root / 'backups/data').mkdir()
      (root / 'backups/data/unrelated').write_text('preserve')
      second = worker.run(cfg, 'logs', policy)
      self.assertFalse(first_dir.exists())
      self.assertTrue((root / 'backups/data/unrelated').exists())
      path = root / 'backups/logs' / second['run_id']
      (path / 'logs.tar.gz').write_text('corrupt')
      with self.assertRaises(ValueError): worker.verify(path)

  def test_symlinks_and_unowned_runs_are_not_backed_up_or_pruned(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary);source = root / 'real';source.write_text('real');link = root / 'link';link.symlink_to(source)
      cfg = {'root': str(root / 'backups'), 'instance_id': 'test', 'log_paths': [str(link)], 'destinations': [{'id': 'local', 'type': 'local'}]}
      with self.assertRaises(ValueError): worker.run(cfg, 'logs', {'keep_count': 1, 'keep_days': 1, 'destinations': ['local']})
      unowned = root / 'backups/logs/20200101T000000Z-aaaaaaaaaaaa';unowned.mkdir();(unowned / 'other').write_text('preserve')
      worker.prune(unowned.parent, 'logs', {'keep_count': 1, 'keep_days': 1}, dt.datetime.now(dt.timezone.utc))
      self.assertTrue(unowned.exists())

  def test_transient_completed_marker_read_never_purges_backup(self):
    name = '20250101T000000Z-aaaaaaaaaaaa'
    cfg = {'instance_id': 'test'}
    marker = {'owner': 'ldapium-backup-v1', 'instance_id': 'test', 'kind': 'logs', 'run_id': name}
    calls = []
    def execute(argv):
      calls.append(argv)
      if argv[0] == 'lsf':
        output = name + '/\n' if '--dirs-only' in argv else 'complete.json\npending.json\n'
        return subprocess.CompletedProcess(argv, 0, stdout=output.encode())
      if argv[0] == 'cat' and argv[1].endswith('pending.json'):
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(marker).encode())
      raise subprocess.CalledProcessError(1, argv)
    with patch.object(worker, 'command', execute):
      worker.cleanup_remote([], 'remote:backups', cfg, 'logs', dt.datetime.now(dt.timezone.utc))
    self.assertFalse(any(argv[0] == 'purge' for argv in calls))

  def test_instance_retention_preserves_other_instance(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary);source = root / 'audit.log';source.write_text('event')
      cfg = {'root': str(root / 'backups'), 'instance_id': 'first', 'log_paths': [str(source)], 'destinations': [{'id': 'local', 'type': 'local'}]}
      policy = {'keep_count': 1, 'keep_days': 1, 'destinations': ['local']}
      first = worker.run(cfg, 'logs', policy)
      cfg['instance_id'] = 'second'
      worker.run(cfg, 'logs', policy);worker.run(cfg, 'logs', policy)
      self.assertTrue((root / 'backups/logs' / first['run_id']).exists())
      self.assertEqual(len(list((root / 'backups/logs').iterdir())), 2)


  JOB = 'job-20261006T150000Z-0123456789ab'

  def logs_cfg(self, root, destinations=None):
    source = root / 'audit.log'; source.write_text('audit event')
    return {'root': str(root / 'backups'), 'instance_id': 'test', 'log_paths': [str(source)],
      'destinations': destinations or [{'id': 'local', 'type': 'local'}]}

  def test_job_id_reaches_manifest_and_result_file_without_breaking_verify(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary); cfg = self.logs_cfg(root)
      result = worker.run(cfg, 'logs', {'keep_count': 5, 'keep_days': 7, 'destinations': ['local']}, self.JOB)
      run_dir = root / 'backups/logs' / result['run_id']
      manifest = worker.verify(run_dir)
      self.assertEqual(manifest['job_id'], self.JOB)
      self.assertEqual(result, {'run_id': result['run_id'], 'kind': 'logs', 'verified': True, 'local_verified': True, 'job_id': self.JOB,
        'destinations': [{'id': 'local', 'status': 'succeeded'}]})
      result_file = root / 'backups/.results' / (self.JOB + '.json')
      self.assertEqual(json.loads(result_file.read_text()), result)
      self.assertEqual(stat.S_IMODE(result_file.stat().st_mode), 0o600)
      self.assertEqual(stat.S_IMODE(result_file.parent.stat().st_mode), 0o700)
      self.assertEqual([p.name for p in result_file.parent.iterdir()], [self.JOB + '.json'])

  def test_without_job_id_nothing_is_written_and_manifest_has_no_job_id(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary); cfg = self.logs_cfg(root)
      result = worker.run(cfg, 'logs', {'keep_count': 5, 'keep_days': 7, 'destinations': ['local']})
      self.assertNotIn('job_id', worker.verify(root / 'backups/logs' / result['run_id']))
      self.assertNotIn('job_id', result)
      self.assertFalse((root / 'backups/.results').exists())

  def remote_cfg(self, root):
    destinations = [{'id': 'local', 'type': 'local'}] + [{'id': name, 'type': 's3', 'remote': 'x', 'prefix': 'p'} for name in ('remote-a', 'remote-b')]
    cfg = self.logs_cfg(root, destinations); cfg['rclone_config'] = str(root / 'rclone.conf')
    return cfg

  def run_with_failing(self, failing_verb, validate_error=None):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary); cfg = self.remote_cfg(root)
      policy = {'keep_count': 5, 'keep_days': 7, 'destinations': ['local', 'remote-a', 'remote-b']}
      calls = []
      def execute(argv):
        calls.append(argv[argv.index('--contimeout') + 2] if '--contimeout' in argv else argv[0])
        if failing_verb in argv:
          raise subprocess.CalledProcessError(1, argv, stderr=b'rclone said SECRET-TOKEN /etc/secret')
        return subprocess.CompletedProcess(argv, 0, stdout=b'')
      patches = [patch.object(worker, 'command', execute), patch.object(worker, 'cleanup_remote', lambda *a: None), patch.object(worker, 'prune_remote', lambda *a: None)]
      patches.append(patch.object(worker, 'validate_remote', side_effect=validate_error) if validate_error else patch.object(worker, 'validate_remote', lambda *a: 'x:p'))
      for item in patches: item.start()
      try:
        with self.assertRaises(Exception) as caught:
          worker.run(cfg, 'logs', policy, self.JOB)
      finally:
        for item in patches: item.stop()
      result_file = json.loads((root / 'backups/.results' / (self.JOB + '.json')).read_text())
      local_copies = [p.name for p in (root / 'backups/logs').iterdir() if not p.name.startswith('.')]
      return caught.exception, result_file, local_copies, calls

  def test_remote_failure_reports_per_destination_results_and_keeps_local_copy(self):
    error, result_file, copies, calls = self.run_with_failing('copy')
    self.assertEqual(error.backup_result, result_file)
    self.assertEqual(result_file['destinations'], [
      {'id': 'local', 'status': 'succeeded'},
      {'id': 'remote-a', 'status': 'failed', 'error_code': 'transfer_failed'},
      {'id': 'remote-b', 'status': 'skipped', 'error_code': 'previous_destination_failed'}])
    self.assertEqual((result_file['verified'], result_file['local_verified'], result_file['job_id']), (False, True, self.JOB))
    self.assertEqual(copies, [result_file['run_id']])
    self.assertNotIn('SECRET-TOKEN', json.dumps(result_file))

  def test_failure_classes_map_to_the_closed_error_codes(self):
    _, verify_result, _, _ = self.run_with_failing('check')
    self.assertEqual(verify_result['destinations'][1], {'id': 'remote-a', 'status': 'failed', 'error_code': 'verify_failed'})
    _, config_result, _, _ = self.run_with_failing('none', validate_error=ValueError('unknown remote'))
    self.assertEqual(config_result['destinations'][1], {'id': 'remote-a', 'status': 'failed', 'error_code': 'config_invalid'})

  def test_sigterm_runs_cleanup_and_leaves_a_result_file(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary); cfg = self.logs_cfg(root)
      previous = signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(128 + signum))
      try:
        with patch.object(worker, 'verify', side_effect=lambda directory: os.kill(os.getpid(), signal.SIGTERM)):
          with self.assertRaises(SystemExit):
            worker.run(cfg, 'logs', {'keep_count': 5, 'keep_days': 7, 'destinations': ['local']}, self.JOB)
      finally:
        signal.signal(signal.SIGTERM, previous)
      self.assertEqual(list((root / 'backups/logs').glob('.pending-*')), [])
      result = json.loads((root / 'backups/.results' / (self.JOB + '.json')).read_text())
      self.assertEqual((result['verified'], result['local_verified'], result['run_id']), (False, False, ''))
      self.assertEqual(result['destinations'], [{'id': 'local', 'status': 'failed'}])

  def test_lock_contention_exits_75_and_writes_nothing(self):
    with tempfile.TemporaryDirectory() as temporary:
      root = Path(temporary); cfg = self.logs_cfg(root)
      (root / 'backups').mkdir()
      with (root / 'backups/.worker.lock').open('a') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaises(SystemExit) as caught:
          worker.run(cfg, 'logs', {'keep_count': 5, 'keep_days': 7, 'destinations': ['local']}, self.JOB)
      self.assertEqual(caught.exception.code, 75)
      self.assertFalse((root / 'backups/.results').exists())
      self.assertFalse((root / 'backups/logs').exists())

  def test_job_id_argument_is_validated(self):
    with self.assertRaises(SystemExit):
      with patch.object(sys, 'argv', ['w', '--config', 'x', '--kind', 'logs', '--job-id', '../../etc/passwd']):
        worker.main()


if __name__ == '__main__': unittest.main()
