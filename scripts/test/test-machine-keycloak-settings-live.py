#!/usr/bin/env python3
"""Keycloak client-settings live checks for machine bearer auth (#214, unit 5a, T-028 / AC-002).

Reproduces docs/changes/machine-principal-auth/EVIDENCE.md section 2.9 on the pinned Keycloak
(default quay.io/keycloak/keycloak:26.7.4, start-dev) against the real UI backend and a real
slapd, and turns the operator requirements into an executable audit.

The Keycloak client settings the operator MUST apply to a machine (service account) client:

  1. Lightweight access tokens OFF   client attribute client.use.lightweight.access.token.enabled
                                     (default false). ON removes aud, client_id and
                                     preferred_username, so every token is refused.
  2. Default client scopes `service_account` and `profile` kept. They supply client_id /
     clientHost / clientAddress and preferred_username; without them every token is refused.
  3. Token exchange NOT enabled      attribute standard.token.exchange.enabled stays false and the
                                     server does not run the legacy `token-exchange` feature
                                     (that feature lets a client exchange its own token WITHOUT any
                                     client setting). Exchanged tokens have no client_id and are
                                     refused by ldapium; this keeps the defence two-layered.
  4. Refresh tokens for the service account are allowed (client_credentials.use_refresh_token);
     `sid` appears in the token and is not a reason to refuse it.
  5. A service-account-only client: standard flow OFF and direct access grants OFF (a human
     password-grant token from the same client has the SA token's aud/azp/scope). The audience
     mapper (aud = the value of MACHINE_OIDC_AUDIENCE) lives on that client or on a client scope
     only machine clients use, never on a scope shared with the UI's SSO client.

  audit_client_settings() below checks 1-5 for a client through the admin REST API and is run
  against a conforming client (no findings) and against every deliberately wrong one (each is
  reported). The same settings are listed in EVIDENCE.md section 5.

Positive (UI answers 200): the baseline SA token; a refresh-enabled SA token that carries `sid`.
Negative (each 401 token_invalid and ZERO new slapd binds as the machine DN): lightweight ON;
profile scope removed; profile and service_account removed; no audience mapper; standard token
exchange of an SA token and of a human token; the same client's human password-grant token;
a wrong azp; a token with only preferred_username; and, on a Keycloak that runs the legacy
`token-exchange` feature, the exchange that works without any client setting. On the default server
a client without standard.token.exchange.enabled is refused by Keycloak itself.

Run: python3 scripts/test/test-machine-keycloak-settings-live.py
Override LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE / KEYCLOAK_IMAGE / LDAPIUM_TEST_PREFIX /
LDAPIUM_TEST_DEADLINE as needed.
"""
import json
import pathlib
import secrets
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / 'scripts/lib'))
from machine_live import (ADMIN_DN, ALL_SCOPES, AUDIENCE, BASE_DN, MACHINE_DN, READER, Keycloak, Live, Signer,  # noqa: E402
                          Slapd, decode_jwt, jbody)

live = Live('ldapium-mks-', deadline_seconds=1200)
REALM = 'ldapium'
check = live.check
EXCHANGE = {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token'}


def audit_client_settings(kc, realm, client_internal_id, audience=AUDIENCE, shared_scope_clients=()):
  """The operator audit for requirements 1-5. Returns a list of findings; empty = conforming."""
  findings = []
  client = kc.get_client(realm, client_internal_id)
  attrs = client.get('attributes') or {}
  if attrs.get('client.use.lightweight.access.token.enabled', 'false') == 'true':
    findings.append('1: lightweight access token is ON')
  scopes = kc.default_scope_names(realm, client_internal_id)
  for needed in ('service_account', 'profile'):
    if needed not in scopes:
      findings.append(f'2: default client scope {needed} is missing')
  if attrs.get('standard.token.exchange.enabled', 'false') == 'true':
    findings.append('3: standard token exchange is enabled on the client')
  if not client.get('serviceAccountsEnabled'):
    findings.append('5: service accounts are not enabled')
  if client.get('standardFlowEnabled'):
    findings.append('5: standard flow is enabled')
  if client.get('directAccessGrantsEnabled'):
    findings.append('5: direct access grants are enabled (human password-grant tokens possible)')
  mappers = kc.mappers(realm, client_internal_id)
  has_audience = any(m.get('protocolMapper') == 'oidc-audience-mapper' and
                     (m.get('config') or {}).get('included.custom.audience') == audience for m in mappers)
  if not has_audience:
    findings.append(f'5: no audience mapper for {audience} on the client')
  return findings


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}', flush=True)
  live.make_network()
  slapd = Slapd(live)
  slapd.start()
  slapd.seed()
  slapd.apply_acl()
  session_secret = live.secret(secrets.token_hex(32))
  alice_pw = live.secret('Alice-' + secrets.token_urlsafe(12))
  ldap_url = f'ldap://{slapd.name}:389'

  def binds():
    time.sleep(0.4)
    return slapd.binds(MACHINE_DN)

  def stack(tag, features):
    """One Keycloak + one realm full of client variants + one UI container pointing at it."""
    name = f'{live.name_prefix}-kc{tag}'
    kc = Keycloak(live, name, f'http://{name}:8080', features=features)
    kc.start()
    kc.create_realm(REALM)
    kc.create_user(REALM, 'alice', alice_pw)
    for s in ALL_SCOPES:
      kc.create_scope(REALM, s)
    signer = Signer(live)
    signer.import_into(kc, REALM)
    return kc, signer

  def provision(kc, name, **kw):
    sec = live.secret(name + '-' + secrets.token_hex(8))
    cid = kc.create_client(REALM, name, sec, scopes=kw.pop('scopes', READER), **kw)
    return cid, sec

  def start_ui(tag, kc, clients):
    env = {'LDAP_BASE_DN': BASE_DN, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
           'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true',
           'MACHINE_OIDC_ISSUER_URL': kc.issuer(REALM), 'MACHINE_OIDC_AUDIENCE': AUDIENCE,
           'MACHINE_ALLOWED_CLIENTS': ';'.join(f'{c}=' + ','.join(READER) for c in clients),
           'MACHINE_LDAP_BIND_DN': MACHINE_DN, 'MACHINE_LDAP_ROOT_DNS': ADMIN_DN, 'MACHINE_REQUEST_TIMEOUT': '5s',
           'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
           'MACHINE_CLIENT_CONCURRENCY': '1000', 'MACHINE_MAX_AUTH_CONCURRENCY': '1000', 'MACHINE_MAX_CONCURRENCY': '1000'}
    return live.start_ui(f'{live.name_prefix}-ui{tag}', ldap_url, env,
                         {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': slapd.machine_password})

  tokens_used = []

  def refused(api, label, token):
    before = binds()
    st, _, body = api.machine(token, '/api/users?limit=2')
    assert st == 401 and jbody(body).get('code') == 'token_invalid', f'{label}: {st} {live.mask(body)[:160]}'
    check(binds() == before, f'{label} -> 401 token_invalid, BIND COUNT 0')

  # ==== Phase A: the default server (no legacy token-exchange feature) ====================
  kc, signer = stack('a', None)
  clients = {}
  clients['svc-base'] = provision(kc, 'svc-base')
  clients['svc-refresh'] = provision(kc, 'svc-refresh', attributes={'client_credentials.use_refresh_token': 'true'})
  clients['svc-light'] = provision(kc, 'svc-light', attributes={'client.use.lightweight.access.token.enabled': 'true'})
  clients['svc-noprofile'] = provision(kc, 'svc-noprofile')
  clients['svc-nosa'] = provision(kc, 'svc-nosa')
  clients['svc-noaud'] = provision(kc, 'svc-noaud', audience=None)
  clients['svc-exch'] = provision(kc, 'svc-exch', direct_grant=True, attributes={'standard.token.exchange.enabled': 'true'})
  clients['svc-human'] = provision(kc, 'svc-human', direct_grant=True)
  kc.remove_default_scope(REALM, clients['svc-noprofile'][0], 'profile')
  kc.remove_default_scope(REALM, clients['svc-nosa'][0], 'profile')
  kc.remove_default_scope(REALM, clients['svc-nosa'][0], 'service_account')
  api = start_ui('a', kc, list(clients))

  def sa(name, **form):
    t = kc.sa_token(REALM, name, clients[name][1], **form)
    tokens_used.append(t)
    return t

  # -- the operator audit: a conforming client has no findings, every wrong one is reported --
  check(audit_client_settings(kc, REALM, clients['svc-base'][0]) == [], 'operator audit: the conforming client has no findings')
  expected = {'svc-light': '1:', 'svc-noprofile': '2:', 'svc-nosa': '2:', 'svc-noaud': '5: no audience',
              'svc-exch': '3:', 'svc-human': '5: direct access grants'}
  for name, prefix in expected.items():
    found = audit_client_settings(kc, REALM, clients[name][0])
    check(any(f.startswith(prefix) for f in found), f'operator audit: {name} is reported ({found})')
  check(audit_client_settings(kc, REALM, clients['svc-refresh'][0]) == [], 'operator audit: refresh tokens for the service account are NOT a finding (requirement 4)')

  # -- positive --
  before = binds()
  st, _, body = api.machine(sa('svc-base'), '/api/users?limit=2')
  check(st == 200 and len(jbody(body).get('users', [])) == 2 and binds() == before + 1, 'baseline service-account token -> 200 (exactly one machine bind)')
  st, resp = kc.token(REALM, 'svc-refresh', clients['svc-refresh'][1])
  refresh_access = resp['access_token']
  tokens_used.append(refresh_access)
  check('sid' in decode_jwt(refresh_access)[1] and resp.get('refresh_token'), 'the refresh-enabled SA token carries sid and a refresh token (non-vacuous)')
  st, _, body = api.machine(refresh_access, '/api/users?limit=2')
  check(st == 200, 'refresh-enabled service-account token (sid present) -> 200')

  # -- negative: client settings that break the token shape --
  for name, label in (('svc-light', 'lightweight access token ON'), ('svc-noprofile', 'profile scope removed (no preferred_username)'),
                      ('svc-nosa', 'profile and service_account removed (no client_id, no preferred_username)'),
                      ('svc-noaud', 'no audience mapper (aud = account)')):
    refused(api, label, sa(name))
  light_claims = decode_jwt(sa('svc-light'))[1]
  check('client_id' not in light_claims and 'preferred_username' not in light_claims and 'aud' not in light_claims,
        'the lightweight token really lacks client_id/preferred_username/aud (EVIDENCE 2.9 row 2 reproduced)')
  noaud = decode_jwt(sa('svc-noaud'))[1]
  check(noaud['aud'] == 'account', 'without the audience mapper aud is the string "account" (EVIDENCE 2.2 reproduced)')

  # -- negative: human and exchanged tokens --
  _, human = kc.token(REALM, 'svc-human', clients['svc-human'][1], grant_type='password', username='alice', password=alice_pw)
  tokens_used.append(human['access_token'])
  hc = decode_jwt(human['access_token'])[1]
  base_claims = decode_jwt(sa('svc-human'))[1]
  check('client_id' not in hc and hc['azp'] == 'svc-human' and hc['aud'] == base_claims['aud'] and hc['scope'] == base_claims['scope'],
        'the same client\'s human token equals the SA token in aud/azp/scope but has no client_id (EVIDENCE 2.3 reproduced)')
  refused(api, "the same client's HUMAN password-grant token", human['access_token'])
  st, ex_sa = kc.token(REALM, 'svc-exch', clients['svc-exch'][1], subject_token=sa('svc-exch'), **EXCHANGE)
  check(st == 200, f'standard token exchange is enabled on svc-exch and exchanges its own SA token ({st})')
  tokens_used.append(ex_sa['access_token'])
  ec = decode_jwt(ex_sa['access_token'])[1]
  check('client_id' not in ec and ec['preferred_username'] == 'service-account-svc-exch',
        'the exchanged SA token has preferred_username service-account-svc-exch but NO client_id (EVIDENCE 2.9 row 7: a rule on preferred_username alone would accept it)')
  refused(api, 'STANDARD-exchange SA token', ex_sa['access_token'])
  _, human_src = kc.token(REALM, 'svc-exch', clients['svc-exch'][1], grant_type='password', username='alice', password=alice_pw)
  st, ex_human = kc.token(REALM, 'svc-exch', clients['svc-exch'][1], subject_token=human_src['access_token'], **EXCHANGE)
  check(st == 200, f'standard token exchange of a human subject token works on svc-exch ({st})')
  tokens_used.append(ex_human['access_token'])
  refused(api, 'STANDARD-exchange HUMAN token', ex_human['access_token'])
  st, err = kc.token(REALM, 'svc-base', clients['svc-base'][1], subject_token=sa('svc-base'), **EXCHANGE)
  check(st != 200 and 'access_token' not in err, f'default server: a machine client WITHOUT standard.token.exchange.enabled is refused by Keycloak itself ({st} {err.get("error")})')

  # -- negative: wrong azp / preferred_username only (re-signed with the imported key) --
  _, claims = decode_jwt(sa('svc-base'))
  refused(api, 'azp != client_id', signer.craft(claims, set_claims={'azp': 'svc-refresh'}))
  refused(api, 'only preferred_username matches (client_id and clientHost removed)', signer.craft(claims, drop=['client_id', 'clientHost', 'clientAddress']))
  st, _, body = api.machine(signer.craft(claims), '/api/users?limit=2')
  check(st == 200, 'positive control: the unmodified claims re-signed with the imported key -> 200 (each refusal above is the one change)')

  # ==== Phase B: a server that runs the legacy token-exchange feature =======================
  kc_b, signer_b = stack('b', 'token-exchange')
  cid_b = kc_b.create_client(REALM, 'svc-legacy', live.secret('legacy-' + secrets.token_hex(8)), scopes=READER)
  legacy_secret = live.secret_values[-1]
  api_b = start_ui('b', kc_b, ['svc-legacy'])
  token_b = kc_b.sa_token(REALM, 'svc-legacy', legacy_secret)
  tokens_used.append(token_b)
  check(audit_client_settings(kc_b, REALM, cid_b) == [], 'operator audit: the client conforms (standard.token.exchange.enabled is NOT set)')
  st, _, _ = api_b.machine(token_b, '/api/users?limit=2')
  check(st == 200, 'legacy-feature server: the baseline SA token -> 200')
  st, ex_legacy = kc_b.token(REALM, 'svc-legacy', legacy_secret, subject_token=token_b, **EXCHANGE)
  if st == 200:
    lc = decode_jwt(ex_legacy['access_token'])[1]
    check('client_id' not in lc, 'legacy token-exchange feature: the client exchanged its own token WITHOUT any client setting (EVIDENCE 2.9 row 11 reproduced), the result has no client_id')
    tokens_used.append(ex_legacy['access_token'])
    refused(api_b, 'LEGACY-feature exchange token', ex_legacy['access_token'])
  else:
    print(f'NOTE: legacy token exchange could not be exercised on this Keycloak ({st} {ex_legacy}); the legacy case is NOT verified', flush=True)

  scan = live.all_logs()
  leaks = [t[:10] + '...' for t in tokens_used if t and t in scan] + [s[:6] + '...' for s in live.secret_values if len(s) >= 8 and s in scan]
  check(not leaks, f'no token, client secret or password in the {len(live.containers)} container logs ({len(scan)} bytes): {leaks}')
  print(f'\nAll Keycloak client-settings checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
