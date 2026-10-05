#!/usr/bin/env python3
"""Merge a supported configuration-export artifact offline; never contact apps."""
import argparse
import configparser
import io
import json
import os
import re
from pathlib import Path

GRAFANA_FIELDS = {
  'enabled', 'client_id', 'scopes', 'auth_url', 'token_url', 'api_url',
  'role_attribute_path', 'role_attribute_strict', 'allow_assign_grafana_admin',
  'use_pkce', 'use_refresh_token', 'groups_attribute_path',
}
ARGO_FIELDS = {'policy.default', 'scopes', 'policy.csv'}


def merge(artifact, existing):
  adapter = artifact.get('adapter')
  if artifact.get('status') != 'exported' or adapter not in {'grafana', 'argocd'}:
    raise ValueError('supported exported Grafana/Argo CD artifact required')
  content = json.loads(artifact['content'])
  if adapter == 'grafana':
    if set(content) != {'auth.generic_oauth'}:
      raise ValueError('unexpected Grafana export sections')
    fields = content['auth.generic_oauth']
    if set(fields) != GRAFANA_FIELDS:
      raise ValueError('unexpected or incomplete managed Grafana fields')
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(existing)
    if parser.defaults():
      raise ValueError('Grafana INI DEFAULT inheritance is unsupported')
    section = 'auth.generic_oauth'
    if not parser.has_section(section):
      parser.add_section(section)
    for key, value in fields.items():
      if not isinstance(value, (str, bool)) or '\n' in str(value) or '\r' in str(value):
        raise ValueError('invalid Grafana setting')
      parser.set(section, key, str(value).lower() if isinstance(value, bool) else value)
    # D26: only exported fields are owned here. Secret and unrelated settings are
    # retained; INI comments are lost. Escape hatch: keep the source file unchanged.
    output = io.StringIO()
    parser.write(output)
    return output.getvalue(), sorted(fields)
  for obj in [content, json.loads(existing)]:
    if (obj.get('apiVersion') != 'v1' or obj.get('kind') != 'ConfigMap'
        or obj.get('metadata', {}).get('name') != 'argocd-rbac-cm'):
      raise ValueError('argocd-rbac-cm ConfigMap JSON required')
  current = json.loads(existing)
  fields = content['data']
  if set(fields) != ARGO_FIELDS or not all(isinstance(v, str) for v in fields.values()):
    raise ValueError('unexpected or incomplete managed Argo CD fields')
  data = current.setdefault('data', {})
  # D27: preserve policy.csv and AppProject policies; isolate this writer in a
  # composed policy key. Existing defaults/scopes must agree to avoid changing
  # unrelated users. Conflicts require the application's owner to resolve them.
  for key in ['policy.default', 'scopes']:
    if key in data and data[key] != fields[key]:
      raise ValueError(f'Argo CD {key} conflicts; owner must resolve before merging')
    data[key] = fields[key]
  match = re.fullmatch(r'([a-z0-9][a-z0-9-]{0,63})-argocd-rbac\.json', artifact.get('filename', ''))
  if not match:
    raise ValueError('valid profile-specific Argo CD artifact filename required')
  managed_key = 'policy.ldapium.' + match.group(1) + '.csv'
  data[managed_key] = fields['policy.csv']
  return json.dumps(current, indent=2) + '\n', ['policy.default', 'scopes', managed_key]


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--artifact', type=Path, required=True)
  parser.add_argument('--existing', type=Path, required=True)
  parser.add_argument('--output', type=Path, help='New private file; source is never overwritten')
  args = parser.parse_args()
  artifact = json.loads(args.artifact.read_text())
  result, fields = merge(artifact, args.existing.read_text())
  if args.output:
    if args.output.resolve() == args.existing.resolve():
      raise ValueError('output must differ from source')
    # Exclusive creation avoids clobbering an existing target or symlink.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
      stream.write(result)
  print(json.dumps({'adapter': artifact['adapter'], 'managed_fields': fields,
    'output_written': bool(args.output), 'permissions_applied': False,
    'source_preserved': True}))


if __name__ == '__main__':
  try:
    main()
  except (ValueError, KeyError, OSError, configparser.Error) as exc:
    # Avoid printing source configuration or credentials from parser exceptions.
    raise SystemExit(f'Merge rejected ({type(exc).__name__}); verify input/configuration contract')
