#!/usr/bin/env python3
"""Run local UI data backup then restore into disposable Docker volumes."""
import argparse
import http.cookiejar
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request
import uuid

parser=argparse.ArgumentParser();parser.add_argument('--operator',required=True);parser.add_argument('--url',default='http://127.0.0.1:8080');args=parser.parse_args()
repo=Path(__file__).resolve().parents[2];cfg=json.loads(Path(args.operator).read_text());ldap=cfg['ldap']
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(path,body=None,method=None):
  data=None if body is None else json.dumps(body).encode()
  return json.load(opener.open(urllib.request.Request(args.url+'/api'+path,data,{'Content-Type':'application/json','Origin':args.url},method=method)))
call('/login',{'identity':ldap['admin_dn'],'password':Path(ldap['password_file']).read_text()})
call('/v1/backups/jobs/data',method='POST')
for _ in range(180):
  state=call('/v1/backups')['states'].get('data',{})
  if state.get('status')!='running':break
  time.sleep(1)
if not (state['status']=='succeeded'):
  raise AssertionError(state['status'])
run=Path(cfg['root'])/'data'/state['run_id']
source=subprocess.run(['ldapsearch','-x','-H',ldap['url'],'-D',ldap['admin_dn'],'-y',ldap['password_file'],'-b',ldap['base_dn'],'-s','base','entryUUID'],check=True,capture_output=True,text=True).stdout
source_uuid=next(line for line in source.splitlines() if line.startswith('entryUUID:'))
name='ldapium-backup-restore-'+uuid.uuid4().hex[:8];image=name+':test';volumes=[name+'-config',name+'-data']
try:
  with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary);shutil.copytree(run,root/'restore');shutil.copy2(ldap['password_file'],root/'restore/password');shutil.copy2(repo/'scripts/restore.sh',root/'restore.sh');shutil.copy2(repo/'scripts/verify-backup.sh',root/'verify-backup.sh')
    (root/'Dockerfile').write_text('FROM ldapium:e2e\nUSER root\nCOPY restore/ /restore/\nCOPY restore.sh verify-backup.sh /scripts/\nRUN chmod 755 /scripts/*.sh && chown -R ldap:ldap /restore\nUSER ldap\n')
    subprocess.run(['docker','build','-q','-t',image,str(root)],check=True,stdout=subprocess.DEVNULL)
  for volume in volumes:subprocess.run(['docker','volume','create',volume],check=True,stdout=subprocess.DEVNULL)
  mounts=['-v',volumes[0]+':/etc/openldap/slapd.d','-v',volumes[1]+':/var/lib/openldap/data']
  restore_result=subprocess.run(['docker','run','--rm','--user','0','--entrypoint','/bin/bash',*mounts,image,'/scripts/restore.sh','--backup-dir','/restore','--target-config','/etc/openldap/slapd.d','--target-data','/var/lib/openldap','--confirm-offline','--force-empty'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  if restore_result.returncode:
    raise RuntimeError(restore_result.stderr.decode().replace(Path(ldap['password_file']).read_text(),'[redacted]'))
  envfile=Path(tempfile.mktemp());envfile.write_text('LDAP_ROOT_DN='+ldap['base_dn']+'\nLDAP_ADMIN_PASSWORD='+Path(ldap['password_file']).read_text()+'\n');envfile.chmod(0o600)
  try:subprocess.run(['docker','run','-d','--name',name,'--env-file',str(envfile),*mounts,image],check=True,stdout=subprocess.DEVNULL)
  finally:envfile.unlink()
  for _ in range(60):
    result=subprocess.run(['docker','exec',name,'ldapsearch','-x','-H','ldap://127.0.0.1','-D',ldap['admin_dn'],'-y','/restore/password','-b',ldap['base_dn'],'-s','base','entryUUID'],capture_output=True,text=True)
    if result.returncode==0:break
    time.sleep(1)
  if result.returncode!=0:
    output=subprocess.run(['docker','logs','--tail','15',name],capture_output=True,text=True)
    raise RuntimeError(('restored directory failed to start: '+output.stderr+output.stdout).replace(Path(ldap['password_file']).read_text(),'[redacted]'))
  if not (source_uuid in result.stdout):
    raise AssertionError('entryUUID was not preserved')
  exported=next(run.glob('data-*.ldif.gz'))
  expected=sum(line.startswith('dn:') for line in gzip.open(exported,'rt'))
  restored=subprocess.run(['docker','exec',name,'ldapsearch','-x','-H','ldap://127.0.0.1','-D',ldap['admin_dn'],'-y','/restore/password','-b',ldap['base_dn'],'-E','pr=500/noprompt','1.1'],capture_output=True,text=True,check=True).stdout
  actual=sum(line.startswith('dn:') for line in restored.splitlines())
  if not (actual==expected):
    raise AssertionError(f'restored entry count mismatch: expected={expected} actual={actual}')
  print('PASS: restored entry count matches snapshot: '+str(expected))
  print('PASS: actual UI LDAP data+config backup, manifest integrity, offline restore, bound LDAP query and preserved entryUUID')
finally:
  subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for volume in volumes:subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
