import datetime as dt
import importlib.util
import json
from pathlib import Path
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
      def inspect(merged, kind, policy):
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



if __name__ == '__main__': unittest.main()
