import importlib.util
import json
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location('merge_app', Path(__file__).parents[1] / 'integration/merge-app-oidc.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def artifact(adapter, content):
  return {'adapter': adapter, 'status': 'exported', 'filename': 'team-a-argocd-rbac.json', 'content': json.dumps(content)}


class MergeTests(unittest.TestCase):
  def test_grafana_preserves_secret_and_other_sections_idempotently(self):
    fields = dict.fromkeys(module.GRAFANA_FIELDS, 'value')
    fields['enabled'] = True
    fields['role_attribute_strict'] = True
    obj = artifact('grafana', {'auth.generic_oauth': fields})
    source = '[auth.generic_oauth]\nclient_secret = ${OAUTH_SECRET}\n[server]\nroot_url = https://app.example\n'
    merged, _ = module.merge(obj, source)
    self.assertIn('client_secret = ${OAUTH_SECRET}', merged)
    self.assertIn('root_url = https://app.example', merged)
    self.assertEqual(module.merge(obj, merged)[0], merged)
    fields['client_secret'] = 'injected'
    with self.assertRaises(ValueError):
      module.merge(artifact('grafana', {'auth.generic_oauth': fields}), source)

  def test_argocd_preserves_other_policy_and_rejects_default_conflicts(self):
    obj = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'argocd-rbac-cm', 'namespace': 'argocd'},
      'data': {'policy.default': 'role:ldapium-unassigned', 'scopes': '[groups]', 'policy.csv': 'g, developer, role:readonly'}}
    source = {**obj, 'data': {'policy.csv': 'p, role:owner, applications, *, */*, allow', 'policy.other.csv': 'g, ops, role:owner'}}
    exported = artifact('argocd', obj)
    merged, _ = module.merge(exported, json.dumps(source))
    result = json.loads(merged)
    self.assertEqual(result['data']['policy.csv'], source['data']['policy.csv'])
    self.assertEqual(result['data']['policy.other.csv'], source['data']['policy.other.csv'])
    self.assertEqual(result['data']['policy.ldapium.team-a.csv'], obj['data']['policy.csv'])
    self.assertEqual(result['metadata']['namespace'], 'argocd')
    self.assertEqual(module.merge(exported, merged)[0], merged)
    second = {**exported, 'filename': 'team-b-argocd-rbac.json'}
    both = json.loads(module.merge(second, merged)[0])
    self.assertIn('policy.ldapium.team-a.csv', both['data'])
    self.assertIn('policy.ldapium.team-b.csv', both['data'])
    source['data']['policy.default'] = 'role:readonly'
    with self.assertRaises(ValueError):
      module.merge(exported, json.dumps(source))


  def test_cli_private_output_and_refuses_existing_target(self):
    with tempfile.TemporaryDirectory() as directory:
      root = Path(directory)
      fields = dict.fromkeys(module.GRAFANA_FIELDS, 'value')
      export = root / 'artifact.json'
      export.write_text(json.dumps(artifact('grafana', {'auth.generic_oauth': fields})))
      source = root / 'original.ini'
      source.write_text('[server]\nsecret = preserved-value\n')
      output = root / 'merged.ini'
      command = [sys.executable, str(Path(module.__file__)), '--artifact', str(export), '--existing', str(source)]
      dry = subprocess.run(command, capture_output=True, text=True, check=True)
      self.assertFalse(json.loads(dry.stdout)['output_written'])
      self.assertNotIn('preserved-value', dry.stdout)
      subprocess.run(command + ['--output', str(output)], capture_output=True, check=True)
      self.assertEqual(output.stat().st_mode & 0o777, 0o600)
      before = output.read_text()
      failed = subprocess.run(command + ['--output', str(output)], capture_output=True, text=True)
      self.assertNotEqual(failed.returncode, 0)
      self.assertEqual(output.read_text(), before)
      self.assertEqual(source.read_text(), '[server]\nsecret = preserved-value\n')


if __name__ == '__main__':
  unittest.main()
