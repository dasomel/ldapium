#!/usr/bin/env python3
"""Disposable Linux fixtures prove restore refuses unsafe input before clearing."""
import base64
import gzip
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

repo=Path(__file__).resolve().parents[2];image='ldapium-restore-boundaries:'+uuid.uuid4().hex[:8]
try:
  with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary);(root/'backup').mkdir();(root/'other').mkdir()
    data=root/'backup/data-test.ldif.gz';data.write_bytes(gzip.compress(b'dn: dc=example,dc=org\nobjectClass: domain\ndc: example\n\n'))
    config=root/'backup/config-test.ldif.gz'
    encoded=base64.b64encode(b'/srv/live').decode()
    config.write_bytes(gzip.compress(('dn: olcDatabase={1}mdb,cn=config\nolcSuffix: dc=example,dc=org\nolcDbDirectory:: '+encoded+'\n\ndn: olcDatabase={2}mdb,cn=config\nolcDbDirectory: /tmp/data/accesslog\n').encode()))
    (root/'backup/manifest-test.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in [data,config]))
    shutil.copy2(repo/'scripts/restore.sh',root/'restore.sh');shutil.copy2(repo/'scripts/verify-backup.sh',root/'verify-backup.sh')
    (root/'Dockerfile').write_text('FROM ldapium:e2e\nUSER root\nCOPY backup/ /backup/\nCOPY other/ /other/\nCOPY restore.sh verify-backup.sh /scripts/\nRUN chmod 755 /scripts/*.sh\n')
    subprocess.run(['docker','build','-q','-t',image,str(root)],check=True,stdout=subprocess.DEVNULL)
  fixture='mkdir -p /tmp/data /tmp/config; touch /tmp/data/keep /tmp/config/keep; /scripts/restore.sh --backup-dir /backup --target-data /tmp/data --target-config /tmp/config --confirm-offline --force-empty >/dev/null 2>&1; result=$?; test "$result" -ne 0 && test -f /tmp/data/keep && test -f /tmp/config/keep'
  subprocess.run(['docker','run','--rm','--entrypoint','/bin/bash',image,'-c',fixture],check=True)
  linked='mkdir -p /tmp/real /tmp/data; touch /tmp/real/keep; ln -s /tmp/real /tmp/config; /scripts/restore.sh --backup-dir /backup --target-data /tmp/data --target-config /tmp/config --confirm-offline --force-empty >/dev/null 2>&1; result=$?; test "$result" -ne 0 && test -f /tmp/real/keep'
  subprocess.run(['docker','run','--rm','--entrypoint','/bin/bash',image,'-c',linked],check=True)
  mismatch='mkdir -p /tmp/data /tmp/config; touch /tmp/data/keep /tmp/config/keep; /scripts/restore.sh --backup-dir /other --manifest /backup/manifest-test.sha256 --target-data /tmp/data --target-config /tmp/config --confirm-offline --force-empty >/dev/null 2>&1; result=$?; test "$result" -ne 0 && test -f /tmp/data/keep && test -f /tmp/config/keep'
  subprocess.run(['docker','run','--rm','--entrypoint','/bin/bash',image,'-c',mismatch],check=True)
  print('PASS: encoded MDB path, symlink target and unrelated manifest rejected before target clearing')
finally:subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
