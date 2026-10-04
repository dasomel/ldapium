#!/usr/bin/env python3
"""Disposable LDAP/UI containers prove generated credentials and restart reuse."""
import http.cookiejar
import json
import subprocess
import time
import urllib.request
import uuid

name='ldapium-secrets-'+uuid.uuid4().hex[:8]
network=name+'-network';volumes=[name+'-config',name+'-data',name+'-ui']
ldap=name+'-ldap';ui=name+'-ui';containers=[]
def command(args): return subprocess.run(args,check=True,capture_output=True,text=True).stdout.strip()
def start_ldap():
  command(['docker','run','-d','--name',ldap,'--network',network,'--network-alias','generated-ldap','-e','LDAP_ROOT_DN=dc=example,dc=org','-v',volumes[0]+':/etc/openldap/slapd.d','-v',volumes[1]+':/var/lib/openldap/data','ldapium:e2e'])
  containers.append(ldap)
  for _ in range(60):
    result=subprocess.run(['docker','exec',ldap,'ldapwhoami','-x','-H','ldap://127.0.0.1','-D','cn=admin,dc=example,dc=org','-y','/var/lib/openldap/data/.credentials/ldap-admin-password'],capture_output=True,text=True)
    if result.returncode==0: return
    time.sleep(1)
  raise RuntimeError('generated LDAP credential did not bind')
def start_ui():
  command(['docker','run','-d','--name',ui,'--network',network,'-p','127.0.0.1::8080','-e','LDAP_URL=ldap://generated-ldap:389','-e','LDAP_BASE_DN=dc=example,dc=org','-e','COOKIE_SECURE=false','-v',volumes[2]+':/var/lib/ldapium/secrets','ldapium-ui:secrets-e2e'])
  containers.append(ui)
  port=command(['docker','port',ui,'8080/tcp']).rsplit(':',1)[1];url='http://127.0.0.1:'+port
  for _ in range(60):
    try:
      urllib.request.urlopen(url+'/api/auth/config',timeout=1).close();return url
    except Exception: time.sleep(1)
  raise RuntimeError('generated UI secret did not start')
try:
  command(['docker','network','create',network])
  for volume in volumes: command(['docker','volume','create',volume])
  start_ldap()
  password=command(['docker','exec',ldap,'cat','/var/lib/openldap/data/.credentials/ldap-admin-password']);assert len(password)==64
  assert '600'==command(['docker','exec',ldap,'stat','-c','%a','/var/lib/openldap/data/.credentials/ldap-admin-password'])
  startup=subprocess.run(['docker','logs',ldap],check=True,capture_output=True,text=True);assert password not in startup.stdout+startup.stderr  # entrypoint logs to stderr too
  command(['docker','rm','-f',ldap]);start_ldap()
  assert password==command(['docker','exec',ldap,'cat','/var/lib/openldap/data/.credentials/ldap-admin-password'])
  url=start_ui();secret=command(['docker','exec',ui,'/server','-print-session-secret']);assert len(secret)==64
  opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
  request=urllib.request.Request(url+'/api/login',json.dumps({'identity':'cn=admin,dc=example,dc=org','password':password}).encode(),{'Content-Type':'application/json','Origin':url})
  opener.open(request).close()
  settings=opener.open(url+'/api/server-settings').read().decode();assert secret not in settings and password not in settings
  assert json.loads(settings)['sessionSecretSource']=='generated_file'
  command(['docker','rm','-f',ui]);start_ui()
  assert secret==command(['docker','exec',ui,'/server','-print-session-secret'])
  command(['docker','exec',ldap,'rm','/var/lib/openldap/data/.credentials/ldap-admin-password']);command(['docker','rm','-f',ldap])
  command(['docker','run','-d','--name',ldap,'-e','LDAP_ROOT_DN=dc=example,dc=org','-v',volumes[0]+':/etc/openldap/slapd.d','-v',volumes[1]+':/var/lib/openldap/data','ldapium:e2e'])
  code=command(['docker','wait',ldap]);assert code!='0';logs=subprocess.run(['docker','logs',ldap],check=True,capture_output=True,text=True);assert 'original admin password' in logs.stdout+logs.stderr  # entrypoint errors go to stderr
  print('PASS: generated LDAP bind, private mode, no log leaks, LDAP/UI recreation reuse, authenticated safe metadata, missing original credential fails closed')
finally:
  for container in set(containers+[ldap,ui]): subprocess.run(['docker','rm','-f',container],capture_output=True)
  for volume in volumes: subprocess.run(['docker','volume','rm',volume],capture_output=True)
  subprocess.run(['docker','network','rm',network],capture_output=True)
