#!/usr/bin/env python3
"""Disposable LDAP/Keycloak integration; never uses existing service credentials."""
import json,os,secrets,subprocess,tempfile,time,urllib.request,urllib.error,urllib.parse
from pathlib import Path
repo=Path(__file__).resolve().parents[2]

def request(url,data=None,token=None,method=None):
    headers={}
    if data is not None: data=json.dumps(data).encode();headers['Content-Type']='application/json'
    if token:headers['Authorization']='Bearer '+token
    with urllib.request.urlopen(urllib.request.Request(url,data,headers,method=method),timeout=20) as r:
        b=r.read();return json.loads(b) if b else None

with tempfile.TemporaryDirectory(prefix='ldapium-kc-role-') as tmp:
    suffix=secrets.token_hex(4);ldap='ldapium-profile-ldap-'+suffix;kc='ldapium-profile-kc-'+suffix
    ldap_pw=secrets.token_urlsafe(32);admin_pw=secrets.token_urlsafe(32);svc_secret=secrets.token_urlsafe(32)
    ldap_env=Path(tmp)/'ldap.env';ldap_env.write_text('LDAP_ROOT_DN=dc=example,dc=org\nLDAP_ADMIN_PASSWORD='+ldap_pw+'\n');ldap_env.chmod(0o600)
    kc_env=Path(tmp)/'kc.env';kc_env.write_text('KC_BOOTSTRAP_ADMIN_USERNAME=admin\nKC_BOOTSTRAP_ADMIN_PASSWORD='+admin_pw+'\nKC_HOSTNAME=http://127.0.0.1:18185\n');kc_env.chmod(0o600)
    base='http://127.0.0.1:18185';realm='profile-test';api=base+'/admin/realms/'+realm
    backend=None
    grafana='ldapium-profile-grafana-'+suffix
    try:
        subprocess.run(['docker','run','--rm','-d','--name',ldap,'--env-file',str(ldap_env),'-p','127.0.0.1:13891:389','ldapium:e2e'],check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['docker','run','--rm','-d','--name',kc,'--env-file',str(kc_env),'-p','127.0.0.1:18185:8080','quay.io/keycloak/keycloak:26.7.4','start-dev'],check=True,stdout=subprocess.DEVNULL)
        for _ in range(120):
            try:request(base+'/realms/master');break
            except Exception:time.sleep(.5)
        else:raise RuntimeError('Keycloak readiness failed')
        form=urllib.parse.urlencode({'grant_type':'password','client_id':'admin-cli','username':'admin','password':admin_pw}).encode()
        with urllib.request.urlopen(urllib.request.Request(base+'/realms/master/protocol/openid-connect/token',form,{'Content-Type':'application/x-www-form-urlencoded'})) as r:admin=json.load(r)['access_token']
        request(base+'/admin/realms',{'realm':realm,'enabled':True},admin)
        request(api+'/clients',{'clientId':'ldapium-role-service','serviceAccountsEnabled':True,'secret':svc_secret,'publicClient':False},admin)
        svc=request(api+'/clients?clientId=ldapium-role-service',token=admin)[0]['id']
        user=request(api+'/clients/'+svc+'/service-account-user',token=admin)['id']
        mgmt=request(api+'/clients?clientId=realm-management',token=admin)[0]['id']
        roles=request(api+'/clients/'+mgmt+'/roles',token=admin)
        selected=[r for r in roles if r['name'] in ['manage-clients','view-clients','query-clients','manage-users','view-users','query-groups']]
        request(api+'/users/'+user+'/role-mappings/clients/'+mgmt,selected,admin)
        for client in ['custom-client','other-client']:
            request(api+'/clients',{'clientId':client,'publicClient':True,'directAccessGrantsEnabled':True},admin)
        request(api+'/groups',{'name':'developers'},admin)
        group=request(api+'/groups',token=admin)[0]['id']
        client=request(api+'/clients?clientId=custom-client',token=admin)[0]['id']
        alice_pw=secrets.token_urlsafe(24)
        request(api+'/users',{'username':'alice','enabled':True,'email':'alice@example.org','emailVerified':True,'firstName':'Alice','lastName':'Test','credentials':[{'type':'password','value':alice_pw,'temporary':False}]},admin)
        alice=request(api+'/users?username=alice',token=admin)[0]['id']
        request(api+'/users/'+alice+'/groups/'+group,token=admin,method='PUT')
        subprocess.run(['go','build','-o',tmp+'/server','./cmd/server'],cwd=repo/'ui/backend',check=True)
        env=dict(os.environ,LDAP_URL='ldap://127.0.0.1:13891',LDAP_BASE_DN='dc=example,dc=org',SESSION_SECRET=secrets.token_hex(32),COOKIE_SECURE='false',LISTEN_ADDR='127.0.0.1:18084',APP_PROFILES_PATH=tmp+'/profiles.json',APP_PROFILES_ADMIN_DNS='cn=admin,dc=example,dc=org',KEYCLOAK_ADMIN_URL=base,KEYCLOAK_ADMIN_REALM=realm,KEYCLOAK_ADMIN_CLIENT_ID='ldapium-role-service',KEYCLOAK_ADMIN_CLIENT_SECRET=svc_secret,KEYCLOAK_OBSERVE_CLIENTS='custom-client',KEYCLOAK_DELEGATE_CLIENTS='custom-client',KEYCLOAK_MANAGED_GROUP_IDS=group,KEYCLOAK_ISOLATED_REALM='true',KEYCLOAK_ALLOW_LOCAL_HTTP='true')
        log=open(tmp+'/server.log','w');backend=subprocess.Popen([tmp+'/server'],env=env,stdout=log,stderr=log);log.close()
        ui='http://127.0.0.1:18084'
        for _ in range(100):
            try:request(ui+'/api/auth/config');break
            except Exception:time.sleep(.2)
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        def ui_call(path,data=None,method=None,etag=None):
            headers={'Origin':ui,'Content-Type':'application/json'}
            if etag is not None:headers['If-Match']='"'+str(etag)+'"'
            b=json.dumps(data).encode() if data is not None else None
            with opener.open(urllib.request.Request(ui+'/api/v1/applications/'+path,b,headers,method=method),timeout=60) as r:return json.load(r)
        opener.open(urllib.request.Request(ui+'/api/login',json.dumps({'identity':'cn=admin,dc=example,dc=org','password':ldap_pw}).encode(),{'Content-Type':'application/json'}))
        profile={'id':'custom','name':'Custom','client_id':'custom-client','issuer':base+'/realms/'+realm,'claim_path':'groups','token_source':'access_token','enforcement':'native_app','scope':'app','mappings':[{'keycloak_role':'admin','native_role':'owner'}]}
        ui_call('custom/integration-profile',profile,'PUT',0)
        snapshot=ui_call('custom/keycloak-roles')
        def change(action,role,**kw):
            global snapshot
            snapshot=ui_call('custom/keycloak-role-operations',dict(action=action,role=role,**kw),'POST',snapshot['fingerprint'])
        change('create','reader');change('create','operator');change('include_add','operator',include='reader')
        try:change('include_add','reader',include='operator');raise AssertionError('role cycle allowed')
        except urllib.error.HTTPError as e:assert e.code==409
        change('group_add','operator',group_id=group)
        form=urllib.parse.urlencode({'grant_type':'password','client_id':'custom-client','username':'alice','password':alice_pw}).encode()
        with urllib.request.urlopen(urllib.request.Request(base+'/realms/'+realm+'/protocol/openid-connect/token',form,{'Content-Type':'application/x-www-form-urlencoded'})) as r:token=json.load(r)['access_token']
        import base64
        claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'=='))
        assert set(['operator','reader']).issubset(claims['resource_access']['custom-client']['roles'])
        change('group_remove','operator',group_id=group)
        with urllib.request.urlopen(urllib.request.Request(base+'/realms/'+realm+'/protocol/openid-connect/token',form,{'Content-Type':'application/x-www-form-urlencoded'})) as r:token=json.load(r)['access_token']
        claims=json.loads(base64.urlsafe_b64decode(token.split('.')[1]+'=='))
        assert 'operator' not in claims.get('resource_access',{}).get('custom-client',{}).get('roles',[])
        stale=snapshot['fingerprint'];request(api+'/clients/'+client+'/roles',{'name':'external-change'},admin)
        try:ui_call('custom/keycloak-role-operations',{'action':'create','role':'stale'},'POST',stale);raise AssertionError('stale write allowed')
        except urllib.error.HTTPError as e:assert e.code==412
        profile['id']='other';profile['name']='Other';profile['client_id']='other-client';ui_call('other/integration-profile',profile,'PUT',0)
        try:ui_call('other/keycloak-roles');raise AssertionError('outside client observed')
        except urllib.error.HTTPError as e:assert e.code==403
        artifact=ui_call('custom/configuration-export');assert artifact['status']=='exported'
        preview=ui_call('custom/mapping-preview',{'claim_values':['admin','unknown']},'POST');assert preview['native_roles']==['owner'] and not preview['authoritative']
        browser_env=dict(env,E2E_ADMIN_DN='cn=admin,dc=example,dc=org',E2E_ADMIN_PASSWORD=ldap_pw,E2E_BASE_URL=ui)
        subprocess.run(['npx','playwright','test','e2e/keycloak-apps.spec.ts'],cwd=repo/'ui/frontend',env=browser_env,check=True)
        request(api+'/clients/'+client,{'redirectUris':['http://127.0.0.1:18085/login/generic_oauth'],'webOrigins':['http://127.0.0.1:18085']},admin,method='PUT')
        request(api+'/clients/'+client+'/protocol-mappers/models',{'name':'groups','protocol':'openid-connect','protocolMapper':'oidc-group-membership-mapper','config':{'claim.name':'groups','full.path':'true','id.token.claim':'true','access.token.claim':'true','userinfo.token.claim':'true'}},admin)
        request(api+'/users',{'username':'unmapped','enabled':True,'email':'unmapped@example.org','emailVerified':True,'firstName':'Unmapped','lastName':'Test','credentials':[{'type':'password','value':alice_pw,'temporary':False}]},admin)
        gf_profile=dict(profile,id='grafana-demo',name='Grafana demo',client_id='custom-client',token_source='id_token',mappings=[{'keycloak_role':'/developers','native_role':'Editor'}])
        ui_call('grafana-demo/integration-profile',gf_profile,'PUT',0)
        gf_artifact=ui_call('grafana-demo/configuration-export?adapter=grafana')
        artifact_path=Path(tmp)/'grafana-export.json';artifact_path.write_text(json.dumps(gf_artifact))
        source_path=Path(tmp)/'grafana-existing.ini';source_path.write_text('[auth.generic_oauth]\nallow_sign_up = true\n')
        merged_path=Path(tmp)/'grafana-merged.ini'
        subprocess.run(['python3',str(repo/'scripts/integration/merge-app-oidc.py'),'--artifact',str(artifact_path),'--existing',str(source_path),'--output',str(merged_path)],check=True)
        import configparser
        parsed=configparser.ConfigParser(interpolation=None);parsed.read(merged_path)
        settings=dict(parsed['auth.generic_oauth'])
        assert merged_path.stat().st_mode & 0o777 == 0o600
        assert source_path.read_text() == '[auth.generic_oauth]\nallow_sign_up = true\n'
        gf_env=Path(tmp)/'grafana.env'
        entries=['GF_SERVER_ROOT_URL=http://127.0.0.1:18085','GF_SECURITY_ADMIN_PASSWORD='+secrets.token_urlsafe(32),'GF_AUTH_GENERIC_OAUTH_ALLOW_SIGN_UP=true','GF_PLUGINS_PREINSTALL_DISABLED=true']
        for key,value in settings.items():
            if key in ['token_url','api_url']:value=value.replace('127.0.0.1','host.docker.internal')
            if isinstance(value,bool):value=str(value).lower()
            entries.append('GF_AUTH_GENERIC_OAUTH_'+key.upper()+'='+str(value))
        gf_env.write_text('\n'.join(entries)+'\n');gf_env.chmod(0o600)
        subprocess.run(['docker','run','--rm','-d','--name',grafana,'--env-file',str(gf_env),'-p','127.0.0.1:18085:3000','grafana/grafana:latest'],check=True,stdout=subprocess.DEVNULL)
        for _ in range(100):
            try:health=request('http://127.0.0.1:18085/api/health');break
            except Exception:time.sleep(.5)
        else:raise RuntimeError('Grafana readiness failed')
        browser_env.update(E2E_OIDC_USERNAME='alice',E2E_OIDC_PASSWORD=alice_pw,E2E_GRAFANA_URL='http://127.0.0.1:18085')
        subprocess.run(['npx','playwright','test','e2e/grafana-permissions.spec.ts'],cwd=repo/'ui/frontend',env=browser_env,check=True)
        print('PASS: exported Grafana configuration; OIDC Editor role and unmapped login denial; Grafana version '+health['version'])
        print('PASS: live Keycloak service account, create/composite/group mapping, JWT inherited roles, revocation on fresh token, cycle/stale/client-boundary denials, export/preview')
    finally:
        if backend:backend.terminate();backend.wait(timeout=10)
        subprocess.run(['docker','rm','-f',ldap,kc,grafana],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
