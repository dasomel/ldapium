#!/usr/bin/env python3
"""Real loopback S3/FTP/SSH-SFTP backup transport and retention checks."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('worker', repo / 'ui/backend/backup-tools/backup_worker.py')
worker = importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)

def port():
  with socket.socket() as stream: stream.bind(('127.0.0.1', 0));return stream.getsockname()[1]

parser=argparse.ArgumentParser();parser.add_argument('--container',action='store_true');options=parser.parse_args()

with tempfile.TemporaryDirectory(prefix='ldapium-transports-') as temporary:
  root = Path(temporary);os.chmod(root, 0o700);processes=[]
  try:
    ports={kind:port() for kind in ['s3','ftp','sftp']};password=secrets.token_urlsafe(24)
    key=root/'hostkey'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    public=(root/'hostkey.pub').read_text().split()
    known=root/'known_hosts';known.write_text(f'[127.0.0.1]:{ports["sftp"]} {public[0]} {public[1]}\n')
    obscured=subprocess.run(['rclone','obscure','-'],input=password+'\n',text=True,capture_output=True,check=True).stdout.strip()
    config=root/'rclone.conf'
    config.write_text(f'''[s3]
type = s3
provider = Other
access_key_id = test
secret_access_key = {password}
endpoint = http://127.0.0.1:{ports['s3']}
force_path_style = true
[ftp]
type = ftp
host = 127.0.0.1
port = {ports['ftp']}
user = backup
pass = {obscured}
[sftp]
type = sftp
host = 127.0.0.1
port = {ports['sftp']}
user = backup
pass = {obscured}
known_hosts_file = {known}
''');config.chmod(0o600)
    for kind in ports:
      store=root/kind;store.mkdir();env=dict(os.environ,RCLONE_USER='backup',RCLONE_PASS=password)
      args=['rclone','serve',kind,str(store),'--addr',f'127.0.0.1:{ports[kind]}']
      if kind=='s3':env['RCLONE_AUTH_KEY']='"test,'+password+'"';env.pop('RCLONE_USER');env.pop('RCLONE_PASS')
      if kind=='sftp':args+=['--key',str(key)]
      if kind=='ftp':args+=['--passive-port','38000-38020']
      log=open(root/(kind+'.log'),'w');processes.append(subprocess.Popen(args,env=env,stdout=log,stderr=log));log.close()
    for kind in ports:
      for _ in range(50):
        try:
          with socket.create_connection(('127.0.0.1',ports[kind]),timeout=.2):break
        except OSError:time.sleep(.1)
      else:raise RuntimeError(kind+' did not start: '+(root/(kind+'.log')).read_text().replace(password,'[redacted]'))
    source=root/'audit.log';source.write_text('audited backup event\n')
    destinations=[{'id':'local','type':'local'}]+[{'id':kind,'type':kind,'remote':kind,'prefix':'bucket/backups' if kind=='s3' else 'backups','allow_plaintext':kind=='ftp'} for kind in ports]
    cfg={'root':str(root/'local'),'instance_id':'transport-test','log_paths':[str(source)],'destinations':destinations,'rclone_config':str(config)}
    policy={'keep_days':7,'keep_count':1,'destinations':['local','s3','ftp','sftp']}
    first=worker.run(cfg,'logs',policy);second=worker.run(cfg,'logs',policy)
    if not (not (root/'local/logs'/first['run_id']).exists()):
      raise AssertionError("not (root/'local/logs'/first['run_id']).exists()")
    for kind in ports:
      base=(root/kind/('bucket/backups' if kind=='s3' else 'backups')/'transport-test/logs')
      if not (len(list(base.iterdir()))==1):
        raise AssertionError(kind)
      if not (worker.verify(base/second['run_id'])['run_id']==second['run_id']):
        raise AssertionError("worker.verify(base/second['run_id'])['run_id']==second['run_id']")
    managed = []
    for kind in ports:
      managed.append(dict(id='managed-'+kind, name='Managed '+kind, type=kind, host='127.0.0.1', port=ports[kind], user='backup', password=password, access_key='test', secret_key=password, endpoint='http://127.0.0.1:'+str(ports[kind]), region='us-east-1', bucket='bucket', prefix='managed-backups', known_hosts=known.read_text(), allow_plaintext=kind=='ftp'))
    managed_policy=dict(policy, connections=managed, destinations=['local']+[c['id'] for c in managed])
    managed_result=worker.managed_run(cfg,'logs',managed_policy)
    for kind in ports:
      base=root/kind/('bucket/managed-backups' if kind=='s3' else 'managed-backups')/'transport-test/logs'/managed_result['run_id']
      worker.verify(base)
    if not (not list((root/'local').glob('.connections-*'))):
      raise AssertionError("not list((root/'local').glob('.connections-*'))")
    print('PASS: UI-managed S3/FTP/SFTP credentials and pinned keys deliver verified archives; transient secrets cleaned')
    if options.container:
      fixture=root/'container-fixture';fixture.mkdir()
      (fixture/'rclone.conf').write_text(config.read_text().replace('127.0.0.1','host.docker.internal').replace(str(known),'/fixture/known_hosts'))
      (fixture/'known_hosts').write_text(known.read_text().replace('127.0.0.1','host.docker.internal'))
      (fixture/'audit.log').write_text(source.read_text())
      container_cfg=dict(cfg,root='/tmp/backups',instance_id='container-client-test',log_paths=['/fixture/audit.log'],rclone_config='/fixture/rclone.conf')
      (fixture/'operator.json').write_text(json.dumps(container_cfg))
      (fixture/'backup_worker.py').write_text((repo/'ui/backend/backup-tools/backup_worker.py').read_text())
      (fixture/'Dockerfile').write_text('FROM ldapium-ui:backup-e2e\nUSER root\nCOPY . /fixture/\nRUN chown -R 65532:65532 /fixture && chmod 700 /fixture\nUSER 65532:65532\n')
      image='ldapium-backup-client:'+secrets.token_hex(6)
      try:
        subprocess.run(['docker','build','-q','-t',image,str(fixture)],check=True,stdout=subprocess.DEVNULL)
        result=subprocess.run(['docker','run','--rm','-i','--entrypoint','/usr/bin/python3',image,'/fixture/backup_worker.py','--config','/fixture/operator.json','--kind','logs'],input=json.dumps(dict(managed_policy, connections=[dict(c,host='host.docker.internal',endpoint=c['endpoint'].replace('127.0.0.1','host.docker.internal'),known_hosts=c['known_hosts'].replace('127.0.0.1','host.docker.internal')) for c in managed])),capture_output=True,text=True,check=True)
        manifest=json.loads(result.stdout)
        if not (manifest['verified']):
          raise AssertionError("manifest['verified']")
        for kind in ports:
          base=root/kind/('bucket/managed-backups' if kind=='s3' else 'managed-backups')/'container-client-test/logs'/manifest['run_id']
          worker.verify(base)
        print('PASS: built non-root backup runtime UI-managed credentials against real S3/FTP/SFTP servers')
      finally:subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    # The same SSH server must reject a changed host-key pin.
    original_known=known.read_text();known.write_text(original_known.replace(public[1], 'AAAAinvalid'))
    try:worker.run(cfg,'logs',dict(policy,destinations=['local','sftp']))
    except subprocess.CalledProcessError:pass
    else:raise AssertionError('invalid SSH host pin accepted')
    finally:known.write_text(original_known)
    # Failed destination must not prune the existing valid local copy.
    processes[1].terminate();processes[1].wait(timeout=10)
    try:worker.run(cfg,'logs',policy)
    except subprocess.CalledProcessError:pass
    else:raise AssertionError('failed FTP reported success')
    if not (len(list((root/'local/logs').iterdir()))==1):
      raise AssertionError("len(list((root/'local/logs').iterdir()))==1")
    worker.verify(next((root/'local/logs').iterdir()))
    print('PASS: real S3/FTP/SFTP roundtrip checksums, remote/local independent namespaces, retention and failed transfers preserve local copies and SSH host-key mismatch denied')
  finally:
    for process in processes:
      if process.poll() is None:process.terminate()
    for process in processes:process.wait(timeout=10)
