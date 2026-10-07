#!/usr/bin/env python3
"""Live e2e of machine bearer authentication against a REAL Keycloak (#214, unit 5a, T-021).

Stack: the pinned Keycloak image (default quay.io/keycloak/keycloak:26.7.4, start-dev, fixed
KC_HOSTNAME), a real slapd with the package's machine ACL LDIF, and the real UI backend in BOTH
UI auth modes (LDAP mode with MACHINE_OIDC_ISSUER_URL set explicitly, SSO mode inheriting
SSO_ISSUER_URL). Realm, scopes, clients and users are created through the Keycloak admin REST API.
docs/changes/machine-principal-auth: AC-001..AC-007, AC-009..AC-012, AC-015, AC-017.

Positive: service-account tokens (audience mapper, default client scopes) -> 200 on all 8 allowed
operations (cursor paging, getEntry in BASE_DN, monitor without accesslog), a refresh-enabled SA
token (carries `sid`) -> 200.
Negative (each answers 401/403/400/503 and slapd's accesslog shows ZERO new binds as the machine
DN): aud `account` only, expired (real and re-signed), tampered signature, alg none, HS256 with the
public key as secret, RS512, wrong issuer (other realm), ID token, refresh token, the SSO browser
client's tokens (also with the audience mapper shared into its scope), the SAME client's HUMAN
password-grant token, an EXCHANGED token (standard token exchange), a LIGHTWEIGHT access token,
tokens whose client_id/preferred_username mappers were removed, one-claim-wrong re-signed tokens,
scope insufficient, the 37 operations that are never allowed (derived from openapi.json), HEAD,
cookie+bearer, Origin gate, malformed/duplicate Authorization, JWKS outage (cached kid keeps
working, unknown kid is 503 + Retry-After, recovery without restart), wrong machine password (503),
rate limit 429 + Retry-After, a forged X-Forwarded-For, and an over-privileged bind identity that
still cannot expose a secret value. Finally every container log is scanned for tokens, client
secrets and passwords (AC-010).

Keycloak client settings the operator must apply (verified by the settings script,
test-machine-keycloak-settings-live.py, and listed in
docs/changes/machine-principal-auth/EVIDENCE.md section 5):
  1. lightweight access tokens OFF (client attribute client.use.lightweight.access.token.enabled)
  2. default client scopes `service_account` and `profile` kept (client_id, preferred_username)
  3. token exchange NOT enabled (standard.token.exchange.enabled=false, no legacy feature)
  4. refresh tokens for the service account are fine (sid is not a rejection reason)
  5. service-account-only client (no standard flow, no direct access grants); the audience mapper
     lives on that client (or a scope only it uses), never on a scope shared with the SSO client.

Run: python3 scripts/test/test-machine-keycloak-live.py
Override LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE / KEYCLOAK_IMAGE / LDAPIUM_TEST_PREFIX /
LDAPIUM_TEST_DEADLINE as needed.
"""
import base64
import http.client
import json
import os
import pathlib
import secrets
import socket
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / 'scripts/lib'))
from machine_live import (ensure, ADMIN_DN, ALL_SCOPES, AUDIENCE, AUDIT, BASE_DN, HUMAN_DN, MACHINE_DN, OVER_DN, READER,  # noqa: E402
                          REPO, SEED_USER_DN, Keycloak, Live, Signer, Slapd, decode_jwt, jbody, free_port, tamper)

live = Live('ldapium-mk-', deadline_seconds=1200)
REALM = 'ldapium'
OTHER_REALM = 'other'
check = live.check


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}', flush=True)
  live.make_network()
  slapd = Slapd(live)
  slapd.start()
  slapd.seed()
  rules = slapd.apply_acl(over_privileged=True)
  check(len(rules) >= 5 and f'by dn.exact="{OVER_DN}" read' in rules[0] and rules[2].startswith('{2}to dn.subtree="' + BASE_DN),
        'olcAccess read back: the machine ACL rules sit in front of the existing rules')
  found = slapd.seed_password_secret()
  check(bool(found), f'the accesslog holds {len(found)} userPassword reqMod value(s) (the secret-value probes are not vacuous)')

  kc_name = live.name_prefix + '-kc'
  kc = Keycloak(live, kc_name, f'http://{kc_name}:8080')
  kc.start()
  issuer = kc.issuer(REALM)
  alice_pw = live.secret('Alice-' + secrets.token_urlsafe(12))
  sso_secret = live.secret('sso-' + secrets.token_hex(10))

  # ---- realm, scopes, clients ---------------------------------------------------
  kc.create_realm(REALM)
  kc.create_user(REALM, 'alice', alice_pw)
  for s in ALL_SCOPES:
    kc.create_scope(REALM, s)
  signer = Signer(live)
  signer.import_into(kc, REALM)
  secrets_by_client = {}

  def add(name, scopes, **kw):
    sec = live.secret(name + '-' + secrets.token_hex(8))
    secrets_by_client[name] = sec
    return kc.create_client(REALM, name, sec, scopes=scopes, **kw)

  add('svc-all', ALL_SCOPES)
  add('svc-reader', READER)
  add('svc-reader2', ['directory.users.read', 'directory.groups.read'])
  add('svc-groups', ['directory.groups.read'])
  add('svc-audit', AUDIT)
  add('svc-refresh', READER, attributes={'client_credentials.use_refresh_token': 'true'})
  add('svc-hybrid', READER, direct_grant=True)                       # the SAME client's human tokens
  add('svc-short', READER, attributes={'access.token.lifespan': '3'})
  add('svc-light', READER, attributes={'client.use.lightweight.access.token.enabled': 'true'})
  nomap_noprofile = add('svc-noprofile', READER)
  nomap_nosa = add('svc-nosa', READER)
  add('svc-noaud', READER, audience=None)
  add('svc-exch', READER, direct_grant=True, attributes={'standard.token.exchange.enabled': 'true'})
  kc.remove_default_scope(REALM, nomap_noprofile, 'profile')                                  # no preferred_username
  kc.remove_default_scope(REALM, nomap_nosa, 'profile')
  kc.remove_default_scope(REALM, nomap_nosa, 'service_account')                               # no client_id either
  # The SSO browser client (the UI's own login client) with the audience mapper SHARED into one of
  # its client scopes: its user tokens then carry aud ldapium-api, and must still be refused.
  shared_scope = kc.create_scope(REALM, 'api-audience-shared')
  kc.admin('POST', f'/{REALM}/client-scopes/{shared_scope}/protocol-mappers/models',
           {'name': 'aud-shared', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
            'config': {'included.custom.audience': AUDIENCE, 'id.token.claim': 'false', 'access.token.claim': 'true'}},
           expect=(201,))
  sso_cid = kc.create_client(REALM, 'ldapium-sso', sso_secret, scopes=[], audience=None, direct_grant=True, standard_flow=True,
                   service_account=False)
  kc.admin('PUT', f'/{REALM}/clients/{sso_cid}/default-client-scopes/{shared_scope}', expect=(204,))
  # another realm with a client of the same name: a token from the wrong issuer
  kc.create_realm(OTHER_REALM)
  for s in ALL_SCOPES:
    kc.create_scope(OTHER_REALM, s)
  other_secret = live.secret('other-' + secrets.token_hex(8))
  kc.create_client(OTHER_REALM, 'svc-reader', other_secret, scopes=READER)

  def sa(name, **form):
    return kc.sa_token(REALM, name, secrets_by_client[name], **form)

  allowed_clients = ';'.join([
      'svc-all=' + ','.join(ALL_SCOPES), 'svc-reader=' + ','.join(READER),
      'svc-reader2=directory.users.read,directory.groups.read', 'svc-groups=directory.groups.read',
      'svc-audit=' + ','.join(AUDIT)] + [f'{c}=' + ','.join(READER) for c in (
          'svc-refresh', 'svc-hybrid', 'svc-short', 'svc-light', 'svc-noprofile', 'svc-nosa', 'svc-noaud', 'svc-exch')])

  # ---- UI containers ---------------------------------------------------------------
  session_secret = live.secret(secrets.token_hex(32))
  ldap_url = f'ldap://{slapd.name}:389'

  def machine_env(bind_dn, limits=None, **extra):
    # Generous limiters in the probe containers (hundreds of deliberate 401/403 from ONE source IP
    # would otherwise be 429s); the limiter phase has its own small-limit container.
    env = {'LDAP_BASE_DN': BASE_DN, 'LDAP_USER_CREATE_BASE': 'ou=people,' + BASE_DN,
           'LDAP_GROUP_CREATE_BASE': 'ou=groups,' + BASE_DN, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
           'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true', 'MACHINE_OIDC_AUDIENCE': AUDIENCE,
           'MACHINE_ALLOWED_CLIENTS': allowed_clients, 'MACHINE_LDAP_BIND_DN': bind_dn,
           'MACHINE_LDAP_ROOT_DNS': ADMIN_DN, 'MACHINE_REQUEST_TIMEOUT': '5s'}
    env.update(limits or {'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000',
                          'MACHINE_RATE_LIMIT_BURST': '10000', 'MACHINE_CLIENT_CONCURRENCY': '1000',
                          'MACHINE_MAX_AUTH_CONCURRENCY': '1000', 'MACHINE_MAX_CONCURRENCY': '1000'})
    env.update(extra)
    return env

  held = {'SESSION_SECRET': session_secret}
  ldap_api = live.start_ui(live.name_prefix + '-uildap', ldap_url,
                           machine_env(MACHINE_DN, MACHINE_OIDC_ISSUER_URL=issuer),
                           dict(held, MACHINE_LDAP_BIND_PASSWORD=slapd.machine_password))
  sso_port = free_port()
  sso_env = machine_env(MACHINE_DN)           # NO MACHINE_OIDC_ISSUER_URL: inherited from SSO_ISSUER_URL
  sso_env.update({'SSO_ENABLED': 'true', 'SSO_ISSUER_URL': issuer, 'SSO_CLIENT_ID': 'ldapium-sso',
                  'SSO_ADMIN_ROLE': 'admin', 'LDAP_SERVICE_ACCOUNT_DN': ADMIN_DN, 'LDAP_USER_SEARCH_FILTER': '(uid=%s)',
                  'SSO_CALLBACK_ORIGINS': f'http://127.0.0.1:{sso_port}'})
  sso_api = live.start_ui(live.name_prefix + '-uisso', ldap_url, sso_env,
                          dict(held, MACHINE_LDAP_BIND_PASSWORD=slapd.machine_password, SSO_CLIENT_SECRET=sso_secret,
                               LDAP_SERVICE_ACCOUNT_PASSWORD=slapd.admin_password), port=sso_port)
  over_api = live.start_ui(live.name_prefix + '-uiover', ldap_url,
                           machine_env(OVER_DN, MACHINE_OIDC_ISSUER_URL=issuer),
                           dict(held, MACHINE_LDAP_BIND_PASSWORD=slapd.over_password))
  strict_api = live.start_ui(live.name_prefix + '-uistrict', ldap_url,
                             machine_env(MACHINE_DN, MACHINE_OIDC_ISSUER_URL=issuer, MACHINE_CLOCK_SKEW='0s'),
                             dict(held, MACHINE_LDAP_BIND_PASSWORD=slapd.machine_password))
  modes = [('LDAP mode (explicit issuer)', ldap_api, live.name_prefix + '-uildap'),
           ('SSO mode (inherited issuer)', sso_api, live.name_prefix + '-uisso')]
  check(True, 'UI containers up: LDAP mode with MACHINE_OIDC_ISSUER_URL, SSO mode inheriting SSO_ISSUER_URL, over-privileged, skew-0')

  tokens_used = []

  def tok(name, **form):
    t = sa(name, **form)
    tokens_used.append(t)
    return t

  def binds():
    time.sleep(0.4)  # the accesslog entry for the last request is written
    return slapd.binds(MACHINE_DN)

  messages = {}

  def expect(api, desc, token, status, code=None, path='/api/users?limit=2', method='GET', **kw):
    st, hdrs, body = api.machine(token, path, method=method, **kw)
    ensure(st == status and (code is None or jbody(body).get('code') == code), f'{desc}: expected {status} {code}, got {st} {live.mask(body)[:200]}')
    parsed = jbody(body)
    if st in (401, 403) and isinstance(parsed, dict):
      messages.setdefault(parsed.get('code'), set()).add(parsed.get('message'))
    return st, hdrs, body

  def zero_binds(desc, fn):
    before = binds()
    out = fn()
    after = binds()
    check(after == before, f'{desc}: BIND COUNT 0 (slapd accesslog binds as the machine DN {before} -> {after})')
    return out

  # ---- AC-001 / AC-007: every allowed operation, both modes -------------------------
  for label, api, cname in modes:
    start = binds()
    t = tok('svc-all')
    st, _, body = expect(api, 'users', t, 200)
    p1 = jbody(body)
    check(len(p1.get('users', [])) == 2 and p1.get('nextCursor'), f'{label}: GET /api/users?limit=2 -> 200 with a next cursor')
    st, _, body = expect(api, 'users p2', t, 200, path='/api/users?limit=2&cursor=' + urllib.parse.quote(p1['nextCursor']))
    p2 = jbody(body)
    check({u['uid'] for u in p1['users']}.isdisjoint({u['uid'] for u in p2['users']}), f'{label}: users cursor page 2 continues without overlap')
    st, _, body = expect(api, 'groups', t, 200, path='/api/groups?limit=2')
    g1 = jbody(body)
    st, _, body = expect(api, 'groups p2', t, 200, path='/api/groups?limit=2&cursor=' + urllib.parse.quote(g1['nextCursor']))
    check(jbody(body)['groups'][0]['cn'] == 'g03', f'{label}: groups cursor page 2 continues (g03...)')
    st, _, body = expect(api, 'entry', t, 200, path='/api/entry?dn=' + urllib.parse.quote(SEED_USER_DN))
    check('userPassword' not in body and jbody(body)['dn'] == SEED_USER_DN, f'{label}: getEntry inside BASE_DN -> 200 without userPassword')
    expect(api, 'entry base', t, 200, path='/api/entry?dn=' + urllib.parse.quote(BASE_DN))
    st, _, body = expect(api, 'tree', t, 200, path='/api/tree')
    check(any(n['dn'].startswith('ou=people') for n in jbody(body)), f'{label}: listTree -> 200')
    expect(api, 'policies', t, 200, path='/api/password-policies')
    st, _, body = expect(api, 'monitor', tok('svc-reader'), 200, path='/api/monitor')
    check(jbody(body).get('connectionsCurrent') is not None and not jbody(body).get('recentLogs'),
          f'{label}: getMonitor (no audit.read) -> 200 with statistics and WITHOUT accesslog entries')
    st, _, body = expect(api, 'monitor+audit', tok('svc-audit'), 200, path='/api/monitor')
    check(not jbody(body).get('recentLogs'), f'{label}: getMonitor with audit.read but WITHOUT the operator accesslog ACL opt-in -> 200, still no accesslog entries (the directory ACL is the backstop)')
    # audit.read passes the scope guard, but the least-privilege DN has no accesslog ACL opt-in, so the
    # directory refuses (403 `forbidden`, NOT `scope_denied`); the over-privileged container returns 200.
    expect(api, 'audit actions', t, 403, 'forbidden', path='/api/audit/actions')
    expect(api, 'server settings', t, 200, path='/api/server-settings')
    new = binds() - start
    check(new == 12, f'{label}: all 8 allowed operations passed the guard (listAuditActions needs the accesslog ACL opt-in: 403 forbidden from the directory without it); slapd shows exactly one machine bind per request ({new} binds for 12 requests), no administrator bind')

  # ---- refresh-enabled service account (carries sid) ---------------------------------
  st, body = kc.token(REALM, 'svc-refresh', secrets_by_client['svc-refresh'])
  rt_access, refresh_token = body['access_token'], body.get('refresh_token')
  tokens_used.append(rt_access)
  check('sid' in decode_jwt(rt_access)[1] and refresh_token, 'the refresh-enabled SA token really carries sid and comes with a refresh token (non-vacuous)')
  for label, api, _ in modes:
    expect(api, 'refresh SA', rt_access, 200)
  check(True, 'a refresh-enabled service-account token (sid present) -> 200 in both modes')

  # ---- AC-002: every invalid token, both modes, bind count 0 --------------------------
  base_token = tok('svc-reader')
  _, base_claims = decode_jwt(base_token)
  exp_ttl = base_claims['exp'] - base_claims['iat']
  now_real = base_claims['iat']

  def crafted(**kw):
    t = signer.craft(base_claims, **kw)
    tokens_used.append(t)
    return t

  _, sso_user_body = kc.token(REALM, 'ldapium-sso', sso_secret, grant_type='password', username='alice', password=alice_pw, scope='openid')
  sso_access, sso_id = sso_user_body['access_token'], sso_user_body['id_token']
  tokens_used.extend([sso_access, sso_id])
  sso_claims = decode_jwt(sso_access)[1]
  check(AUDIENCE in (sso_claims['aud'] if isinstance(sso_claims['aud'], list) else [sso_claims['aud']]) and sso_claims['azp'] == 'ldapium-sso',
        'the SSO browser client token carries aud ldapium-api via the SHARED scope mapper (the hypothesis is real, not vacuous)')
  _, hybrid_human = kc.token(REALM, 'svc-hybrid', secrets_by_client['svc-hybrid'], grant_type='password', username='alice', password=alice_pw)
  hh = decode_jwt(hybrid_human['access_token'])[1]
  check('client_id' not in hh and hh['azp'] == 'svc-hybrid' and hh['aud'] == base_claims['aud'] and hh['preferred_username'] == 'alice',
        'the same client\'s HUMAN token has the SA token\'s aud/azp but no client_id (EVIDENCE 2.3 reproduced)')
  sa_for_exchange = tok('svc-exch')
  ex_args = {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
             'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
             'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token'}
  st, ex_sa = kc.token(REALM, 'svc-exch', secrets_by_client['svc-exch'], subject_token=sa_for_exchange, **ex_args)
  exchange_ok = st == 200
  exchanged = []
  if exchange_ok:
    exchanged.append(ex_sa['access_token'])
    _, human_exch_src = kc.token(REALM, 'svc-exch', secrets_by_client['svc-exch'], grant_type='password', username='alice', password=alice_pw)
    st2, ex_human = kc.token(REALM, 'svc-exch', secrets_by_client['svc-exch'], subject_token=human_exch_src['access_token'], **ex_args)
    if st2 == 200:
      exchanged.append(ex_human['access_token'])
    ec = decode_jwt(exchanged[0])[1]
    check('client_id' not in ec, f'standard token exchange is ENABLED on svc-exch and produced {len(exchanged)} exchanged token(s) without client_id (non-vacuous)')
    tokens_used.extend(exchanged)
  else:
    print(f'NOTE: standard token exchange could not be enabled here ({st} {ex_sa}); exchanged-token cases skipped', flush=True)
  _, other_body = kc.token(OTHER_REALM, 'svc-reader', other_secret)
  other_token = other_body['access_token']
  tokens_used.append(other_token)
  _, id_body = kc.token(REALM, 'svc-reader', secrets_by_client['svc-reader'], scope='openid')
  id_token = id_body.get('id_token')
  tokens_used.append(id_token)
  check(decode_jwt(id_token)[1].get('typ') == 'ID', 'the SA ID token (scope=openid) exists and has payload typ ID')

  tamper_base = tok('svc-reader')
  cases = [
      ('aud account only (no audience mapper)', tok('svc-noaud'), 401, 'token_invalid'),
      ('ID token', id_token, 401, 'token_invalid'),
      ('refresh token', refresh_token, 401, 'token_invalid'),
      ('SSO browser client access token (audience mapper shared into its scope)', sso_access, 401, 'token_invalid'),
      ('SSO browser client ID token', sso_id, 401, 'token_invalid'),
      ("the same client's HUMAN password-grant token", hybrid_human['access_token'], 401, 'token_invalid'),
      ('LIGHTWEIGHT access token', tok('svc-light'), 401, 'token_invalid'),
      ('profile scope removed (no preferred_username)', tok('svc-noprofile'), 401, 'token_invalid'),
      ('profile and service_account scopes removed (no client_id, no preferred_username)', tok('svc-nosa'), 401, 'token_invalid'),
      ('token of the same client name in ANOTHER realm (wrong issuer)', other_token, 401, 'token_invalid'),
      ('tampered signature', tamper(tamper_base), 401, 'token_invalid'),
      ('alg none', crafted(alg='none'), 401, 'token_invalid'),
      ('HS256 signed with the JWKS public key as the HMAC secret', crafted(alg='HS256'), 401, 'token_invalid'),
      ('RS512 (alg outside the allowlist), correctly signed', crafted(alg='RS512'), 401, 'token_invalid'),
      ('issuer with a trailing slash', crafted(set_claims={'iss': issuer + '/'}), 401, 'token_invalid'),
      ('aud = account only (re-signed)', crafted(set_claims={'aud': 'account'}), 401, 'token_invalid'),
      ('aud missing', crafted(drop=['aud']), 401, 'token_invalid'),
      ('aud null', crafted(set_claims={'aud': None}), 401, 'token_invalid'),
      ('aud numeric array', crafted(set_claims={'aud': [1, 2]}), 401, 'token_invalid'),
      ('azp != client_id', crafted(set_claims={'azp': 'svc-reader2'}), 401, 'token_invalid'),
      ('client_id missing', crafted(drop=['client_id']), 401, 'token_invalid'),
      ('azp and client_id outside the allowed clients', crafted(set_claims={'azp': 'rogue', 'client_id': 'rogue',
                                                                           'preferred_username': 'service-account-rogue'}), 401, 'token_invalid'),
      ('azp = the SSO browser client', crafted(set_claims={'azp': 'ldapium-sso', 'client_id': 'ldapium-sso',
                                                          'preferred_username': 'service-account-ldapium-sso'}), 401, 'token_invalid'),
      ('preferred_username is the same but client_id missing', crafted(drop=['client_id', 'clientHost', 'clientAddress']), 401, 'token_invalid'),
      ('preferred_username is a human', crafted(set_claims={'preferred_username': 'alice'}), 401, 'token_invalid'),
      ('payload typ ID', crafted(set_claims={'typ': 'ID'}), 401, 'token_invalid'),
      ('payload typ Refresh', crafted(set_claims={'typ': 'Refresh'}), 401, 'token_invalid'),
      ('JOSE typ missing', crafted(header={'typ': None}), 401, 'token_invalid'),
      ('JOSE typ JOSE', crafted(header={'typ': 'JOSE'}), 401, 'token_invalid'),
      ('kid missing', crafted(header={'kid': None}), 401, 'token_invalid'),
      ('unknown kid', crafted(header={'kid': 'no-such-kid'}), 401, 'token_invalid'),
      ('iat missing', crafted(drop=['iat']), 401, 'token_invalid'),
      ('iat in the future (beyond skew)', crafted(set_claims={'iat': now_real + 3600, 'exp': now_real + 3900}), 401, 'token_invalid'),
      ('exp <= iat', crafted(set_claims={'exp': base_claims['iat']}), 401, 'token_invalid'),
      ('lifetime beyond MAX_TTL (exp - iat = 1h)', crafted(set_claims={'exp': base_claims['iat'] + 3600}), 401, 'token_invalid'),
      ('nbf in the future (beyond skew, inside 5 minutes)', crafted(set_claims={'nbf': now_real + 120}), 401, 'token_invalid'),
      ('expired (re-signed, past exp + skew)', crafted(set_claims={'iat': now_real - 7200, 'exp': now_real - 7200 + exp_ttl}), 401, 'token_expired'),
      ('token over 8 KiB', crafted(set_claims={'padding': 'x' * 9000}), 401, 'token_invalid'),
  ] + [(f'EXCHANGED token ({i + 1})', t, 401, 'token_invalid') for i, t in enumerate(exchanged)]
  for label, api, _ in modes:
    def batch(api=api):
      for desc, t, status, code in cases:
        expect(api, desc, t, status, code)
    zero_binds(f'{label}: {len(cases)} invalid tokens -> 401 token_invalid/token_expired', batch)
  check(all(len(m) == 1 for m in messages.values() if m), 'the 401 bodies carry one generic message per code (no per-reason detail): ' + str({k: list(v) for k, v in messages.items()}))
  positive_control = crafted()                                   # unmodified claims re-signed: must pass
  for label, api, _ in modes:
    expect(api, 'positive control', positive_control, 200)
  check(True, 'positive control: the unmodified claims re-signed with the imported key -> 200 in both modes (a failing token fails for its one change)')
  # real expiry with skew 0
  short = tok('svc-short')
  expect(strict_api, 'short-lived token still valid', short, 200)
  time.sleep(4.5)
  zero_binds('real Keycloak token past its 3s lifetime, skew 0', lambda: expect(strict_api, 'expired real', short, 401, 'token_expired'))
  check(True, 'a real Keycloak token is 401 token_expired after its lifetime (skew 0 container)')

  # ---- scope, routes, methods, the 37 never-allowed operations -----------------------
  spec = json.loads((REPO / 'ui/backend/internal/httpapi/openapi/openapi.json').read_text())
  denied, allowed = [], []
  for path, item in spec['paths'].items():
    for method, op in item.items():
      if method not in ('get', 'put', 'post', 'delete', 'patch'):
        continue
      if op.get('security') == []:
        continue
      concrete = path.replace('{id}', 'abc123').replace('{name}', 'abc123')
      (allowed if any('machineBearer' in s for s in op.get('security', [])) else denied).append((method.upper(), concrete))
  check(len(allowed) == 8 and len(denied) == 37, f'openapi.json classifies {len(allowed)} allowed + {len(denied)} never-allowed protected operations (8 + 37)')
  for label, api, _ in modes:
    def denied_batch(api=api):
      t = tok('svc-all')
      for method, path in denied:
        st, _, body = api.machine(t, path, method=method)
        ensure(st == 403 and jbody(body).get('code') == 'scope_denied', f'{method} {path}: {st} {live.mask(body)[:160]}')
      st, _, body = api.machine(t, '/api/users', method='HEAD')
      ensure(st == 403, f'HEAD /api/users: {st}')
      st, _, body = api.machine(tok('svc-groups'), '/api/users?limit=2')
      ensure(st == 403 and jbody(body).get('code') == 'scope_denied', f'groups-only token on users: {st}')
      st, _, body = api.machine(tok('svc-reader2'), '/api/audit/actions')
      ensure(st == 403, f'token without audit.read on audit actions: {st}')
      st, _, body = api.machine(t, '/api/no-such-route')
      ensure(st == 404, f'unknown route: {st}')
      for dn in ['cn=accesslog', 'cn=config', 'cn=Monitor', 'dc=org', 'cn=ACCESSLOG', 'cn=\\61ccesslog']:
        for route in ('/api/entry', '/api/tree'):
          st, _, body = api.machine(tok('svc-reader'), route + '?dn=' + urllib.parse.quote(dn))
          ensure(st == 403 and jbody(body).get('code') == 'scope_denied', f'{route} dn={dn}: {st}')
    zero_binds(f'{label}: all 37 never-allowed operations (scope_denied with a token holding every scope), HEAD, scope-insufficient tokens, an unknown route and sensitive DNs',
               denied_batch)
  st, _, body = ldap_api.machine(tok('svc-groups'), '/api/groups?limit=1')
  check(st == 200, 'the groups-only token is served on the operation it holds (/api/groups)')

  # ---- mixed credentials, Origin gate, malformed headers ------------------------------
  human = ldap_api.login_human(slapd.human_password)

  def mixed():
    t = tok('svc-reader')
    st, hdrs, body = ldap_api.machine(t, '/api/users?limit=2', extra=human)
    ensure(st == 400 and 'Set-Cookie' not in hdrs, f'bearer + real session cookie: {st} {body[:120]}')
    st, hdrs, body = sso_api.machine(t, '/api/users?limit=2', extra={'Cookie': 'ldapium_session=forged'})
    ensure(st == 400 and 'Set-Cookie' not in hdrs, f'bearer + cookie in SSO mode: {st}')
    st, _, body = ldap_api.machine(t, '/api/users', method='POST', extra={'Origin': 'https://evil.example', 'Content-Type': 'application/json'})
    ensure(st == 403 and jbody(body).get('code') == 'origin_mismatch', f'foreign Origin POST with a valid bearer: {st} {body[:120]}')
    st, _, body = ldap_api.machine(t, '/api/users', method='POST', extra={'Origin': 'null', 'Content-Type': 'application/json'})
    ensure(st == 403, f'null Origin POST: {st}')
    for bad in ('Bearer', 'Bearer  two-spaces', 'Basic dXNlcjpwYXNz', 'bearer ' + t + ',x'):
      st, _, body = ldap_api.call('GET', '/api/users?limit=2', {'Authorization': bad})
      ensure(st == 401, f'malformed Authorization {bad[:20]!r}: {st}')
    host, port = ldap_api.base_url.split('//')[1].split(':')
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    conn.putrequest('GET', '/api/users?limit=2')
    conn.putheader('Authorization', 'Bearer ' + t)
    conn.putheader('Authorization', 'Bearer ' + t)
    conn.endheaders()
    resp = conn.getresponse()
    ensure(resp.status == 401, f'two Authorization headers: {resp.status}')
    resp.read()
    conn.close()
    st, hdrs, body = ldap_api.call('OPTIONS', '/api/users', {'Origin': 'https://evil.example', 'Access-Control-Request-Method': 'GET',
                                                                'Access-Control-Request-Headers': 'authorization'})
    ensure('authorization' not in (hdrs.get('Access-Control-Allow-Headers') or '').lower() and 'Access-Control-Allow-Origin' not in hdrs, f'preflight must not allow authorization: {st} {dict(hdrs)}')
    st, _, body = ldap_api.machine(t, '/api/users?limit=2', extra={'Origin': 'https://evil.example'})
    ensure(st == 200, f'GET with a foreign Origin and a valid bearer is not gated: {st}')
  before_mixed = binds()
  mixed()
  check(binds() == before_mixed + 1, 'mixed cookie+bearer (400), foreign/null Origin POST (403), malformed and duplicate Authorization (401) and the preflight were all refused with no bind; '
        'the only bind is the foreign-Origin GET (200: GET is not gated, no CORS header lets a browser read it)')

  # ---- cursor isolation (AC-017) and human path unchanged ----------------------------
  st, _, body = ldap_api.machine(tok('svc-reader'), '/api/users?limit=2')
  cur_a = jbody(body)['nextCursor']
  st, _, body = ldap_api.call('GET', '/api/users?limit=2', human)
  human_cursor = jbody(body)['nextCursor']
  check(st == 200 and ldap_api.call('GET', '/api/users?limit=2&cursor=' + urllib.parse.quote(human_cursor), human)[0] == 200,
        'human session: users page 1 and its own cursor continue (unchanged cookie path)')
  st, _, body = ldap_api.machine(tok('svc-reader2'), '/api/users?limit=2&cursor=' + urllib.parse.quote(cur_a))
  check(st == 400 and jbody(body).get('code') == 'cursor_invalid', "client B replaying client A's cursor -> 400 cursor_invalid")
  st, _, body = ldap_api.call('GET', '/api/users?limit=2&cursor=' + urllib.parse.quote(cur_a), human)
  check(st == 400 and jbody(body).get('code') == 'cursor_invalid', 'a human session replaying a machine cursor -> 400')
  st, _, body = ldap_api.machine(tok('svc-reader'), '/api/users?limit=2&cursor=' + urllib.parse.quote(human_cursor))
  check(st == 400 and jbody(body).get('code') == 'cursor_invalid', 'the machine path replaying a human cursor -> 400')
  st, _, body = ldap_api.machine(tok('svc-reader'), '/api/users?limit=2&cursor=' + urllib.parse.quote(cur_a))
  check(st == 200, 'a refreshed token of the same client continues its cursor (200)')

  # ---- concurrency and aborted connections --------------------------------------------
  results = []

  def worker():
    results.append(ldap_api.machine(tok('svc-reader'), '/api/users?limit=2')[0])
  threads = [threading.Thread(target=worker) for _ in range(30)]
  for th in threads:
    th.start()
  for th in threads:
    th.join()
  check(results.count(200) == 30, f'30 concurrent valid requests -> all 200 ({sorted(set(results))})')
  host, port = ldap_api.base_url.split('//')[1].split(':')
  abort_token = tok('svc-reader')
  for _ in range(20):
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(f'GET /api/users?limit=5 HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {abort_token}\r\n\r\n'.encode())
    s.close()
  time.sleep(0.5)
  check(all(ldap_api.machine(tok('svc-reader'), '/api/users?limit=2')[0] == 200 for _ in range(5)), '20 clients that disconnected mid-request leave the machine path healthy (next 5 requests 200)')

  # ---- over-privileged bind identity: no secret value in any response (AC-005) -------
  collected = []

  def over_get(client_name, path):
    st, _, body = over_api.machine(tok(client_name), path)
    collected.append(body)
    return st, body

  st, body = over_get('svc-reader', '/api/entry?dn=' + urllib.parse.quote(SEED_USER_DN))
  check(st == 200 and 'userPassword' not in body, 'over-privileged bind: getEntry(user) -> 200 and still no userPassword')
  for dn in ['cn=accesslog', 'reqStart=20260101000000.000000Z,cn=accesslog', 'cn=config', 'cn=Monitor']:
    check(over_get('svc-reader', '/api/entry?dn=' + urllib.parse.quote(dn))[0] == 403, f'over-privileged bind: getEntry({dn}) -> 403')
  for resource, pages in (('users', 5), ('groups', 3)):
    cursor, seen = '', 0
    while True:
      st, body = over_get('svc-reader', f'/api/{resource}?limit=2' + (('&cursor=' + urllib.parse.quote(cursor)) if cursor else ''))
      ensure(st == 200, f'{resource}: {st}')
      seen += 1
      cursor = jbody(body).get('nextCursor', '')
      if not cursor:
        break
    check(seen == pages, f'over-privileged bind: {resource} paged to the end in {seen} pages')
  over_get('svc-reader', '/api/tree')
  st, body = over_get('svc-reader', '/api/monitor')
  check(st == 200 and not jbody(body).get('recentLogs'), 'over-privileged bind: getMonitor without audit.read -> no recentLogs although the ACL would allow reading the accesslog')
  st, body = over_get('svc-audit', '/api/monitor')
  check(st == 200 and len(jbody(body).get('recentLogs') or []) > 0, 'over-privileged bind: getMonitor with audit.read -> recentLogs present')
  st, body = over_get('svc-audit', '/api/audit/actions')
  check(st == 200, 'over-privileged bind: listAuditActions with audit.read -> 200')
  blob = '\n'.join(collected)
  forbidden = ['{SSHA}', '{ARGON2}', 'initial-pw-1', slapd.over_password, slapd.machine_password, slapd.human_password]
  for value in slapd.accesslog_secrets + [slapd.seed_secret]:
    forbidden += [value, base64.b64encode(value.encode()).decode(), base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')]
  hits = [f for f in forbidden if f in blob]
  check(not hits and 'userPassword' in blob and '"changedAttrs"' in blob,
        f'no seeded secret value, hash or password in {len(collected)} responses (the attribute NAME userPassword may appear in audit DTOs, and does)')

  # ---- bind failure (AC-009) and rate limits (AC-011) ---------------------------------
  bad_api = live.start_ui(live.name_prefix + '-uibad', ldap_url, machine_env(MACHINE_DN, MACHINE_OIDC_ISSUER_URL=issuer),
                          dict(held, MACHINE_LDAP_BIND_PASSWORD=live.secret('wrong-' + secrets.token_hex(8))))
  for i in range(2):  # below the ppolicy lockout (5), so the good containers keep working
    st, _, body = bad_api.machine(tok('svc-reader'), '/api/users?limit=2')
    ensure(st == 503 and jbody(body).get('code') == 'unavailable' and 'userPassword' not in body, f'wrong machine password: {st} {body[:120]}')
  check(True, 'wrong machine bind password -> 503 unavailable, no data, no fallback to another identity (2 attempts)')
  check(ldap_api.machine(tok('svc-reader'), '/api/users?limit=2')[0] == 200, 'the correct-password container still binds (account not locked)')
  lim_api = live.start_ui(live.name_prefix + '-uilim', ldap_url,
                          machine_env(MACHINE_DN, {'MACHINE_AUTH_FAILURE_LIMIT': '3', 'MACHINE_AUTH_FAILURE_WINDOW': '5s',
                                                   'MACHINE_RATE_LIMIT_RPS': '1', 'MACHINE_RATE_LIMIT_BURST': '2',
                                                   'MACHINE_CLIENT_CONCURRENCY': '4', 'MACHINE_MAX_AUTH_CONCURRENCY': '16'},
                                      MACHINE_OIDC_ISSUER_URL=issuer),
                          dict(held, MACHINE_LDAP_BIND_PASSWORD=slapd.machine_password))
  codes = [lim_api.machine(tok('svc-reader'), '/api/users?limit=1')[0] for _ in range(2)]
  st, hdrs, body = lim_api.machine(tok('svc-reader'), '/api/users?limit=1')
  retry = hdrs.get('Retry-After', '')
  check(codes == [200, 200] and st == 429 and jbody(body).get('code') == 'machine_rate_limited' and retry.isdigit() and int(retry) >= 1,
        f'per-client rate limit: burst of 2 passes, the 3rd is 429 machine_rate_limited with Retry-After={retry}')
  check(lim_api.machine(tok('svc-reader2'), '/api/users?limit=1')[0] == 200, 'budget isolation: another client is still served while svc-reader is exhausted')
  time.sleep(int(retry) + 6)  # budget and failure window both drain
  forged = [lim_api.machine(tamper(tok('svc-reader')), '/api/users?limit=1', extra={'X-Forwarded-For': f'203.0.113.{i + 1}'})[0] for i in range(3)]
  st, hdrs, body = lim_api.machine(tamper(tok('svc-reader')), '/api/users?limit=1', extra={'X-Forwarded-For': '203.0.113.99'})
  check(forged == [401, 401, 401] and st == 429 and hdrs.get('Retry-After', '').isdigit(),
        f'a forged X-Forwarded-For per request does not escape the IP failure throttle: 3 x 401 then 429 ({forged}, {st})')
  st, _, _ = lim_api.machine(tok('svc-reader'), '/api/users?limit=1', extra={'X-Forwarded-For': '203.0.113.200'})
  check(st == 429, 'a VALID token from the throttled source is refused before verification (429)')

  # ---- JWKS outage (AC-008, scenario row 3 vs rows 5/6) ---------------------------------
  cached = {label: tok('svc-reader') for label, _, _ in modes}
  ghost = crafted(header={'kid': 'ghost-kid'})
  time.sleep(32)  # the refresh budget (30s after the last fetch) is open, so an unknown kid triggers a fetch
  kc.stop()
  for label, api, _ in modes:
    expect(api, 'cached kid while Keycloak is down', cached[label], 200)
    st, hdrs, body = api.machine(ghost, '/api/users?limit=2')
    ra = hdrs.get('Retry-After', '')
    check(st == 503 and jbody(body).get('code') == 'unavailable' and ra.isdigit() and 1 <= int(ra) <= 300,
          f'{label}, Keycloak stopped: a token with a CACHED kid -> 200, an unknown kid -> 503 unavailable with Retry-After={ra} (never an accept)')
    st, hdrs, _ = api.machine(ghost, '/api/users?limit=2')
    check(st == 503 and hdrs.get('Retry-After', '').isdigit(), f'{label}: a second unknown-kid request inside the backoff -> 503 + Retry-After')
  kc.restart()
  for label, api, _ in modes:
    def recovered(api=api):
      return api.machine(ghost, '/api/users?limit=2')[0] == 401
    live.wait_until(recovered, f'{label} to fetch the JWKS again after Keycloak is back (no UI restart)', timeout=150, interval=3)
    expect(api, 'after recovery', cached[label], 200)
  check(True, 'Keycloak back up: both modes recover without a restart (unknown kid -> 401 again, cached kid -> 200)')

  # ---- AC-010: one audit line per Authorization-carrying request, nothing secret in any log --
  rid = 'mk-audit-' + secrets.token_hex(3)
  ldap_api.machine(tok('svc-reader'), '/api/users?limit=2', req_id=rid)
  bad_rid = 'mk-audit-bad-' + secrets.token_hex(3)
  ldap_api.machine(tamper(tok('svc-reader')), '/api/users', req_id=bad_rid)
  den_rid = 'mk-audit-den-' + secrets.token_hex(3)
  ldap_api.machine(tok('svc-groups'), '/api/users', req_id=den_rid)
  time.sleep(0.5)
  lines = live.audit_lines(live.name_prefix + '-uildap')
  for r in (rid, bad_rid, den_rid):
    check(sum(1 for ln in lines if f'"request_id":"{r}"' in ln) == 1, f'request {r}: exactly one machine_access audit line')
  check(any(f'"request_id":"{rid}"' in ln and '"actor":"svc-reader"' in ln for ln in lines), 'the accepted request names the verified client as actor')
  check(any(f'"request_id":"{bad_rid}"' in ln and '"actor":"unknown"' in ln and '"token_fingerprint"' in ln for ln in lines), 'a bad signature is logged as actor unknown plus a token fingerprint')
  scan = live.all_logs()
  leaks = []
  secret_pool = [s for s in tokens_used if s] + [live.secret_values[i] for i in range(len(live.secret_values))] + ['Bearer ey']
  for value in secret_pool:
    parts = [value] if value.count('.') != 2 else [value] + value.split('.')
    for part in parts:
      if len(part) >= 8 and part in scan:
        leaks.append(part[:10] + '...')
  user_secrets = [slapd.seed_secret, 'initial-pw-1', 'initial-pw-2'] + slapd.accesslog_secrets
  leaks += [v[:10] + '...' for v in user_secrets if v in scan]
  check(not leaks, f'secret scan of ALL {len(live.containers)} container logs ({len(scan)} bytes): no token, JWT segment, client secret, bind/admin password or userPassword value: {leaks}')

  print(f'\nAll machine Keycloak live checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
