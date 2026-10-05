#!/usr/bin/env python3
"""Disposable LDAP + backup-runtime UI containers; runs the @fixture backups Playwright spec.

Fixture contract (ui/README.md "Scheduled local / S3 / FTP / SSH backups"): operator.json and the
LDAP password file live in a volume the non-root UI user (65532) can read, the policy/backup root is
a private writable volume, and one log file is registered so the log policy is available. Named
volumes only: bind-mounted files readable by a non-root user are unreliable on Colima/Docker Desktop.
"""
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.request
import uuid
from pathlib import Path

repo=Path(__file__).resolve().parents[2]
ldap_image=os.environ.get('LDAPIUM_IMAGE','ldapium:e2e');ui_image=os.environ.get('LDAPIUM_UI_IMAGE','ldapium-ui:backup')
name='ldapium-backup-ui-'+uuid.uuid4().hex[:8]
network=name+'-network';ldap=name+'-ldap';ui=name+'-ui'
volumes={'config':name+'-config','data':name+'-data','etc':name+'-etc','state':name+'-state','log':name+'-log'}
base_dn='dc=example,dc=org';admin_dn='cn=admin,'+base_dn;password=secrets.token_urlsafe(32)
operator={'instance_id':'ui-e2e','root':'/var/lib/ldapium-backups',
  'ldap':{'url':'ldap://backup-ldap:389','base_dn':base_dn,'admin_dn':admin_dn,'password_file':'/etc/ldapium-backup/ldap-password','include_config':False},
  'log_paths':['/var/log/ldapium-backup/audit.log'],
  'destinations':[{'id':'local','name':'Local archive','type':'local'}]}

def command(args,**kw): return subprocess.run(args,check=True,capture_output=True,text=True,**kw).stdout.strip()
def prepare(script,stdin=''):
  # Runs as root in the UI image (debian-based backup-runtime has sh) to seed files with the right owner/mode.
  mounts=['-v',volumes['etc']+':/etc/ldapium-backup','-v',volumes['state']+':/var/lib/ldapium-backups','-v',volumes['log']+':/var/log/ldapium-backup']
  command(['docker','run','--rm','-i','--user','0','--entrypoint','sh',*mounts,ui_image,'-c',script],input=stdin)
try:
  command(['docker','network','create',network])
  for volume in volumes.values(): command(['docker','volume','create',volume])
  prepare('umask 077; cat > /etc/ldapium-backup/ldap-password',password)
  prepare('umask 077; cat > /etc/ldapium-backup/operator.json',json.dumps(operator))
  prepare('echo "audit line" > /var/log/ldapium-backup/audit.log; chown -R 65532:65532 /etc/ldapium-backup /var/lib/ldapium-backups /var/log/ldapium-backup; chmod 700 /etc/ldapium-backup /var/lib/ldapium-backups')
  with tempfile.TemporaryDirectory(prefix='ldapium-backup-ui-') as tmp:
    envfile=Path(tmp)/'ldap.env';envfile.write_text('LDAP_ROOT_DN='+base_dn+'\nLDAP_ADMIN_PASSWORD='+password+'\n');envfile.chmod(0o600)
    command(['docker','run','-d','--name',ldap,'--network',network,'--network-alias','backup-ldap','--env-file',str(envfile),
      '-v',volumes['config']+':/etc/openldap/slapd.d','-v',volumes['data']+':/var/lib/openldap/data',ldap_image])
  for _ in range(80):
    probe=subprocess.run(['docker','exec',ldap,'ldapsearch','-x','-H','ldap://127.0.0.1','-b','','-s','base','namingContexts'],capture_output=True)
    if probe.returncode==0: break
    time.sleep(.5)
  else: raise RuntimeError('disposable LDAP failed readiness')
  with tempfile.TemporaryDirectory(prefix='ldapium-backup-ui-') as tmp:
    envfile=Path(tmp)/'ui.env'
    envfile.write_text('\n'.join(['LDAP_URL=ldap://backup-ldap:389','LDAP_BASE_DN='+base_dn,'COOKIE_SECURE=false','SESSION_SECRET='+secrets.token_hex(32),
      'BACKUP_OPERATOR_CONFIG=/etc/ldapium-backup/operator.json','BACKUP_POLICY_PATH=/var/lib/ldapium-backups/policies.json',
      'BACKUP_ADMIN_DNS='+admin_dn])+'\n');envfile.chmod(0o600)
    command(['docker','run','-d','--name',ui,'--network',network,'-p','127.0.0.1::8080','--env-file',str(envfile),
      '-v',volumes['etc']+':/etc/ldapium-backup:ro','-v',volumes['state']+':/var/lib/ldapium-backups','-v',volumes['log']+':/var/log/ldapium-backup:ro',ui_image])
  port=command(['docker','port',ui,'8080/tcp']).splitlines()[0].rsplit(':',1)[1];url='http://127.0.0.1:'+port
  for _ in range(60):
    try:
      urllib.request.urlopen(url+'/api/auth/config',timeout=1).close();break
    except Exception: time.sleep(1)
  else: raise RuntimeError('backup UI failed readiness')
  subprocess.run(['npx','playwright','test','e2e/backups.spec.ts'],cwd=repo/'ui/frontend',check=True,
    env=dict(os.environ,E2E_BASE_URL=url,E2E_ADMIN_DN=admin_dn,E2E_ADMIN_PASSWORD=password))
  runs=command(['docker','exec',ui,'ls','/var/lib/ldapium-backups/logs']).split()
  assert runs,'log backup left no run directory in the backup root'
  print('PASS: backups spec against backup-runtime UI; log backup runs on disk: '+str(len(runs)))
except Exception:
  # Scrub the generated password: container logs must not leak it into CI output.
  logs=subprocess.run(['docker','logs','--tail','60',ui],capture_output=True,text=True);print((logs.stdout+logs.stderr).replace(password,'[redacted]'))
  raise
finally:
  subprocess.run(['docker','rm','-f',ui,ldap],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for volume in volumes.values(): subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
