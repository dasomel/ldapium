#!/usr/bin/env python3
# Disposable LDAP + built UI test; credentials stay in a temporary 0600 file.
import os,subprocess,tempfile,secrets,time,urllib.request,json
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
ldap_image=os.environ.get('LDAPIUM_IMAGE','ldapium:e2e')
name='ldapium-profile-e2e-'+secrets.token_hex(4)
with tempfile.TemporaryDirectory(prefix='ldapium-profile-') as tmp:
 env=dict(os.environ,LDAP_ROOT_DN='dc=example,dc=org',LDAP_ADMIN_PASSWORD=secrets.token_urlsafe(32))
 ldapenv=Path(tmp)/'ldap.env';ldapenv.write_text('LDAP_ROOT_DN='+env['LDAP_ROOT_DN']+'\nLDAP_ADMIN_PASSWORD='+env['LDAP_ADMIN_PASSWORD']+'\n');ldapenv.chmod(0o600)
 backend=None
 try:
  subprocess.run(['docker','run','--rm','-d','--name',name,'--env-file',str(ldapenv),'-p','127.0.0.1:13890:389',ldap_image],check=True,stdout=subprocess.DEVNULL)
  for _ in range(80):
   probe=subprocess.run(['docker','exec',name,'ldapsearch','-x','-H','ldap://127.0.0.1','-b','','-s','base','namingContexts'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   if probe.returncode==0:break
   time.sleep(.5)
  else:raise RuntimeError('disposable LDAP failed readiness')
  subprocess.run(['go','build','-o',tmp+'/server','./cmd/server'],cwd=repo/'ui/backend',check=True)
  env.update(LDAP_URL='ldap://127.0.0.1:13890',LDAP_BASE_DN='dc=example,dc=org',SESSION_SECRET=secrets.token_hex(32),COOKIE_SECURE='false',LISTEN_ADDR='127.0.0.1:18083',APP_PROFILES_PATH=tmp+'/profiles.json',APP_PROFILES_ADMIN_DNS='cn=admin,dc=example,dc=org',E2E_ADMIN_DN='cn=admin,dc=example,dc=org',E2E_ADMIN_PASSWORD=env['LDAP_ADMIN_PASSWORD'],E2E_BASE_URL='http://127.0.0.1:18083')
  def start():
   log=open(tmp+'/server.log','a');p=subprocess.Popen([tmp+'/server'],env=env,stdout=log,stderr=log);log.close()
   for _ in range(60):
    try:urllib.request.urlopen(env['E2E_BASE_URL']+'/api/auth/config',timeout=1);return p
    except Exception:time.sleep(.2)
   p.terminate();raise RuntimeError('backend failed readiness')
  backend=start()
  subprocess.run(['npx','playwright','test','e2e/applications.spec.ts','e2e/ui-review.spec.ts'],cwd=repo/'ui/frontend',env=env,check=True)
  profiles=json.loads(Path(env['APP_PROFILES_PATH']).read_text());assert len(profiles)==3 and all(p['status']=='configured' for p in profiles)
  assert any(p.get('integration_type')=='harbor' for p in profiles)
  methods=json.loads(Path(env['APP_PROFILES_PATH']+'.templates.json').read_text());assert len(methods)==1 and methods[0]['revision']==2
  backend.terminate();backend.wait(timeout=10);backend=start()
  cookies=urllib.request.HTTPCookieProcessor();opener=urllib.request.build_opener(cookies)
  body=json.dumps({'identity':env['E2E_ADMIN_DN'],'password':env['E2E_ADMIN_PASSWORD']}).encode()
  opener.open(urllib.request.Request(env['E2E_BASE_URL']+'/api/login',body,{'Content-Type':'application/json'}))
  got=json.load(opener.open(env['E2E_BASE_URL']+'/api/v1/applications'))
  assert got['applications']==profiles
  assert json.load(opener.open(env['E2E_BASE_URL']+'/api/v1/applications/integration-methods'))['methods']==methods
  print('PASS: real LDAP login, browser save/reload, unsupported mapping denied, backend restart persistence')
 finally:
  if backend:backend.terminate();backend.wait(timeout=10)
  subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
