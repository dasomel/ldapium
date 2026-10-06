#!/usr/bin/env python3
"""JWKS rotation, flood, hostile-issuer and discovery-recovery e2e (#214, unit 5a, T-025).

The UI backend's issuer is a COUNTING PROXY in front of a REAL Keycloak (the proxy is the issuer
URL: KC_HOSTNAME is fixed to it, so `iss`, `jwks_uri` and every fetch go through it). The proxy
records every discovery / JWKS request with a timestamp and can answer the issuer's paths with
hostile responses. docs/changes/machine-principal-auth CHANGE.md "JWKS and discovery state
machine" (D8, D15), AC-008, AC-016, REQ-016:

  A. rotation with overlap: a new realm key is added; right after the last fetch the new kid is
     refused (401, documented cost, 0 upstream fetches); after MIN_REFRESH it is accepted with
     exactly ONE fetch; old and new kid validate together; after the old key is removed the old kid
     still validates from the cache until the TTL passes and is then refused (401) while the new
     one keeps working.
  B. floods from one source: known-kid + wrong signature (all 401, ZERO fetches) and random
     kids for 65 s (all 401); the number of upstream JWKS fetches stays inside the closed-interval
     bound 1 + ceil(T / 30s) and consecutive fetch starts are at least MIN_REFRESH apart; a token
     with a cached kid keeps being served throughout.
  C. hostile issuer responses to a JWKS refresh: a body over 1 MiB, a redirect (not followed), a
     response slower than 5 s, and more than 20 keys: each is refused with 503 + Retry-After and
     the cached keys stay in use (a cached-kid token is still 200).
  D. discovery failure then recovery: the issuer's discovery fails while the UI starts, the UI
     still starts (cookie login works), bearer requests are 503 + Retry-After, and after the
     issuer recovers a bearer request is 200 without restarting the UI (fetch starts >= 30 s apart).
  E. an http:// issuer fails the UI's startup without the local-test exception, and with it the
     UI logs the WARN.

Not run live (covered by the fake-clock unit tests of internal/machineauth): the STALE and EXPIRED
rows of the state table at their one-hour defaults and the exact scenario a-h fetch counts.

Run: python3 scripts/test/test-machine-jwks-live.py
Override LDAPIUM_IMAGE / LDAPIUM_UI_IMAGE / KEYCLOAK_IMAGE / LDAPIUM_TEST_PREFIX /
LDAPIUM_TEST_DEADLINE as needed.
"""
import base64
import json
import math
import os
import pathlib
import secrets
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request
import http.server

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / 'scripts/lib'))
from machine_live import (ADMIN_DN, AUDIENCE, BASE_DN, MACHINE_DN, READER, ALL_SCOPES, Keycloak, Live, Slapd,  # noqa: E402
                          b64u, decode_jwt, jbody, tamper)

live = Live('ldapium-mj-', deadline_seconds=1500)
REALM = 'ldapium'
MIN_REFRESH = 30
check = live.check


class CountingProxy:
  """The issuer as the UI sees it. Counts and timestamps requests per path class and can answer
  discovery / JWKS with a hostile response (modes: pass, down, redirect, oversize, slow, manykeys)."""

  def __init__(self):
    parent = self
    self.upstream_port = None
    self.modes = {'discovery': 'pass', 'jwks': 'pass'}
    self.log = []                 # (monotonic, class)
    self.lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
      def log_message(self, *_):
        pass

      def reply(self, status, body=b'', headers=None):
        self.send_response(status)
        for k, v in (headers or {'Content-Type': 'application/json'}).items():
          self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
          self.wfile.write(body)
        except OSError:
          pass

      def upstream(self):
        try:
          with urllib.request.urlopen(f'http://127.0.0.1:{parent.upstream_port}{self.path}', timeout=10) as r:
            return r.status, r.read()
        except urllib.error.HTTPError as err:
          return err.code, err.read()

      def do_GET(self):
        if self.path.endswith('/.well-known/openid-configuration'):
          klass = 'discovery'
        elif self.path.endswith('/protocol/openid-connect/certs'):
          klass = 'jwks'
        else:
          klass = 'other:' + self.path
        with parent.lock:
          parent.log.append((time.monotonic(), klass))
        mode = parent.modes.get(klass, 'pass')
        if mode == 'down':
          return self.reply(503, b'{"error":"down"}')
        if mode == 'redirect':
          return self.reply(302, b'', {'Location': '/elsewhere/keys'})
        if mode == 'oversize':
          return self.reply(200, b'{"keys":[],"pad":"' + b'a' * (2 << 20) + b'"}')
        if mode == 'slow':
          time.sleep(7)
        status, body = self.upstream()
        if mode == 'manykeys' and status == 200:
          keys = json.loads(body)['keys']
          sig = next(k for k in keys if k.get('use') == 'sig')
          many = [dict(sig, kid=f'clone-{i}') for i in range(25)]
          body = json.dumps({'keys': many + keys}).encode()
        self.reply(status, body)

    self.server = socketserver.ThreadingTCPServer(('0.0.0.0', 0), Handler)
    self.server.daemon_threads = True
    self.port = self.server.server_address[1]

  def start(self):
    threading.Thread(target=self.server.serve_forever, daemon=True).start()

  def close(self):
    self.server.shutdown()
    self.server.server_close()

  def count(self, klass, since=0.0):
    with self.lock:
      return sum(1 for t, k in self.log if k == klass and t >= since)

  def times(self, klass, since=0.0):
    with self.lock:
      return [t for t, k in self.log if k == klass and t >= since]


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}', flush=True)
  live.make_network()
  proxy = CountingProxy()
  live.closers.append(proxy.close)
  proxy.start()
  slapd = Slapd(live)
  slapd.start()
  slapd.seed(users=3, groups=1)
  slapd.apply_acl()
  session_secret = live.secret(secrets.token_hex(32))
  issuer_host = f'http://host.docker.internal:{proxy.port}'
  kc = Keycloak(live, live.name_prefix + '-kc', issuer_host)
  proxy.upstream_port = kc.port
  kc.start()
  issuer = kc.issuer(REALM)
  kc.create_realm(REALM)
  for s in ALL_SCOPES:
    kc.create_scope(REALM, s)
  secret = live.secret('svc-' + secrets.token_hex(8))
  kc.create_client(REALM, 'svc-reader', secret, scopes=READER)
  ldap_url = f'ldap://{slapd.name}:389'
  tokens = []

  def new_token():
    t = kc.sa_token(REALM, 'svc-reader', secret)
    tokens.append(t)
    return t

  def ui(tag, issuer_url=issuer, wait=True, **extra):
    env = {'LDAP_BASE_DN': BASE_DN, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
           'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_ISSUER_URL': issuer_url, 'MACHINE_OIDC_AUDIENCE': AUDIENCE,
           'MACHINE_ALLOWED_CLIENTS': 'svc-reader=' + ','.join(READER), 'MACHINE_LDAP_BIND_DN': MACHINE_DN,
           'MACHINE_LDAP_ROOT_DNS': ADMIN_DN, 'MACHINE_REQUEST_TIMEOUT': '5s',
           # a flood of invalid tokens from one source must reach the key set, not the IP throttle
           'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_AUTH_FAILURE_WINDOW': '1s', 'MACHINE_RATE_LIMIT_RPS': '10000',
           'MACHINE_RATE_LIMIT_BURST': '10000', 'MACHINE_CLIENT_CONCURRENCY': '1000',
           'MACHINE_MAX_AUTH_CONCURRENCY': '1000', 'MACHINE_MAX_CONCURRENCY': '1000'}
    env.update(extra)
    if 'MACHINE_OIDC_INSECURE_HTTP' not in env and tag != 'noflag':
      env['MACHINE_OIDC_INSECURE_HTTP'] = 'true'
    return live.start_ui(f'{live.name_prefix}-ui{tag}', ldap_url, env,
                         {'SESSION_SECRET': session_secret, 'MACHINE_LDAP_BIND_PASSWORD': slapd.machine_password},
                         wait=wait)

  def forge(base_claims, kid):
    hdr = b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': kid}).encode())
    return f'{hdr}.{b64u(json.dumps(base_claims).encode())}.{b64u(os.urandom(256))}'

  path = '/api/users?limit=1'

  # ==== A. rotation with overlap ==========================================================
  proxy.log.clear()
  api = ui('rot', MACHINE_JWKS_CACHE_TTL='60s', MACHINE_JWKS_MAX_STALE='0s', MACHINE_JWKS_MIN_REFRESH=f'{MIN_REFRESH}s')
  s_mark = time.monotonic()
  check(proxy.count('discovery') == 1 and proxy.count('jwks') == 1, f'startup: one discovery and one JWKS fetch ({proxy.count("discovery")}, {proxy.count("jwks")})')
  old_token = new_token()
  old_kid = decode_jwt(old_token)[0]['kid']
  check(api.machine(old_token, path)[0] == 200 and proxy.count('jwks') == 1, f'old kid {old_kid[:8]}...: 200 from the cache, no extra fetch')
  kc.admin('POST', f'/{REALM}/components', {'name': 'rsa-rotated', 'providerId': 'rsa-generated',
                                              'providerType': 'org.keycloak.keys.KeyProvider',
                                              'config': {'priority': ['200'], 'enabled': ['true'], 'active': ['true'],
                                                         'algorithm': ['RS256'], 'keySize': ['2048']}}, expect=(201,))
  new_token_value = new_token()
  new_kid = decode_jwt(new_token_value)[0]['kid']
  check(new_kid != old_kid and {k['kid'] for k in kc.jwks(REALM) if k.get('use') == 'sig'} >= {old_kid, new_kid},
        f'Keycloak now publishes both signing keys ({old_kid[:8]}..., {new_kid[:8]}...) and signs with the new one')
  since = time.monotonic() - s_mark
  assert since < MIN_REFRESH - 3, f'the rotation steps took {since:.0f}s, too close to MIN_REFRESH={MIN_REFRESH}s for the 401 assertion'
  before = proxy.count('jwks')
  st, _, body = api.machine(new_token_value, path)
  check(st == 401 and jbody(body).get('code') == 'token_invalid' and proxy.count('jwks') == before,
        f'{since:.0f}s after the last fetch (< {MIN_REFRESH}s): the NEW kid is refused, 401, and costs 0 upstream fetches (documented rotation cost)')
  time.sleep(max(0.0, MIN_REFRESH + 1 - (time.monotonic() - s_mark)))
  st, _, body = api.machine(new_token_value, path)
  check(st == 200 and proxy.count('jwks') == before + 1, f'after MIN_REFRESH the new kid is accepted with exactly ONE fetch ({proxy.count("jwks") - before})')
  s_mark = time.monotonic()
  check(api.machine(old_token, path)[0] == 200 and api.machine(new_token_value, path)[0] == 200 and proxy.count('jwks') == before + 1,
        'overlap: old and new kid both validate, no further fetch')
  comps = json.loads(kc.admin('GET', f'/{REALM}/components?type=org.keycloak.keys.KeyProvider', expect=(200,))[2])
  old_provider = next(c for c in comps if c['providerId'] == 'rsa-generated' and c['name'] != 'rsa-rotated')
  kc.admin('DELETE', f'/{REALM}/components/{old_provider["id"]}', expect=(204,))
  check(old_kid not in {k['kid'] for k in kc.jwks(REALM)}, 'the old signing key is removed from Keycloak (the overlap is over upstream)')
  check(api.machine(old_token, path)[0] == 200, 'right after the removal the old kid still validates from the UI cache (the cost: up to the cache TTL)')
  time.sleep(max(0.0, 61 - (time.monotonic() - s_mark)))   # TTL 60s, MAX_STALE 0: EXPIRED, next request refreshes
  fetches = proxy.count('jwks')
  st, _, body = api.machine(old_token, path)
  check(st == 401 and proxy.count('jwks') == fetches + 1, f'after the TTL the cache refreshes (1 fetch) and the REMOVED kid is refused: {st}')
  check(api.machine(new_token_value, path)[0] == 200 and proxy.count('jwks') == fetches + 1, 'the new kid keeps validating after the old one is gone')
  check(proxy.count('discovery') == 1, 'discovery was fetched once in total (the issuer stays known)')

  # ==== B. floods from one source ==========================================================
  proxy.log.clear()
  api = ui('flood', MACHINE_JWKS_MIN_REFRESH=f'{MIN_REFRESH}s')
  start_fetch = proxy.times('jwks')[0]
  good = new_token()
  good_claims = decode_jwt(good)[1]
  bad_sig = tamper(good)
  stop = threading.Event()
  stats = {'known': {}, 'random': {}}
  stats_lock = threading.Lock()

  def flood(kind):
    while not stop.is_set():
      t = bad_sig if kind == 'known' else forge(good_claims, 'rnd-' + secrets.token_hex(6))
      st, _, _ = api.machine(t, path, timeout=20)
      with stats_lock:
        stats[kind][st] = stats[kind].get(st, 0) + 1
      time.sleep(0.005)  # a few hundred requests per second: well under the 1000/1s IP failure throttle

  threads = [threading.Thread(target=flood, args=('known',)) for _ in range(3)]
  for th in threads:
    th.start()
  time.sleep(10)
  stop.set()
  for th in threads:
    th.join()
  n_known = sum(stats['known'].values())
  check(n_known >= 1000 and set(stats['known']) == {401} and proxy.count('jwks') == 1,
        f'known kid + wrong signature flood: {n_known} requests, all 401 ({stats["known"]}), ZERO extra JWKS fetches (total {proxy.count("jwks")})')
  stop.clear()
  threads = [threading.Thread(target=flood, args=('random',)) for _ in range(3)]
  for th in threads:
    th.start()
  flood_start = time.monotonic()
  served = []
  while time.monotonic() - flood_start < 65:
    time.sleep(5)
    served.append(api.machine(good, path)[0])
  stop.set()
  for th in threads:
    th.join()
  flood_end = time.monotonic()
  n_random = sum(stats['random'].values())
  check(n_random >= 1000 and set(stats['random']) == {401}, f'random-kid flood for {flood_end - flood_start:.0f}s: {n_random} requests, all 401 ({stats["random"]})')
  check(set(served) == {200}, f'a token with a cached kid kept being served during the flood ({len(served)} probes all 200)')
  fetch_times = proxy.times('jwks')
  window = flood_end - fetch_times[0]
  bound = 1 + math.ceil(window / MIN_REFRESH)
  gaps = [b - a for a, b in zip(fetch_times, fetch_times[1:])]
  check(len(fetch_times) <= bound, f'upstream JWKS fetches {len(fetch_times)} within the closed-interval bound 1 + ceil({window:.1f}s/{MIN_REFRESH}s) = {bound} (for {n_known + n_random} flood requests)')
  check(all(g >= MIN_REFRESH - 1 for g in gaps) and proxy.count('discovery') == 1,
        f'fetch starts are at least MIN_REFRESH apart (gaps {[round(g, 1) for g in gaps]}s); discovery fetched once')

  # ==== C. hostile issuer responses ==========================================================
  for mode, desc in (('oversize', 'a JWKS body over 1 MiB'), ('redirect', 'a redirect (must not be followed)'),
                     ('slow', 'a response slower than the 5 s fetch timeout'), ('manykeys', 'more than 20 keys')):
    proxy.log.clear()
    api = ui('h' + mode, MACHINE_JWKS_MIN_REFRESH='1s')
    cached = new_token()
    assert api.machine(cached, path)[0] == 200
    time.sleep(1.5)
    proxy.modes['jwks'] = mode
    t0 = time.monotonic()
    st, hdrs, body = api.machine(forge(good_claims, 'hostile-' + secrets.token_hex(4)), path, timeout=30)
    elapsed = time.monotonic() - t0
    proxy.modes['jwks'] = 'pass'
    ra = hdrs.get('Retry-After', '')
    check(st == 503 and jbody(body).get('code') == 'unavailable' and ra.isdigit() and 1 <= int(ra) <= 300 and proxy.count('jwks') == 2,
          f'{desc}: the refresh is refused, unknown kid -> 503 unavailable + Retry-After={ra} after {elapsed:.1f}s (2 JWKS requests in total)')
    if mode == 'slow':
      check(4 <= elapsed < 7.5, f'the slow issuer was cut off by the 5s fetch timeout ({elapsed:.1f}s, proxy delay 7s)')
    if mode == 'redirect':
      check(proxy.count('other:/elsewhere/keys') == 0, 'the redirect target was never requested (redirects are not followed)')
    check(api.machine(cached, path)[0] == 200, f'{desc}: the cached keys stay in use (a cached-kid token is still 200)')

  # ==== D. discovery failure, then recovery ====================================================
  proxy.log.clear()
  proxy.modes['discovery'] = 'down'
  api = ui('disc', wait=True)
  down_started = time.monotonic()
  human = api.login_human(slapd.human_password)
  check(api.call('GET', '/api/users?limit=1', human)[0] == 200, 'issuer discovery failed at startup: the UI still started and a cookie login + read works')
  token = new_token()
  st, hdrs, body = api.machine(token, path)
  ra = hdrs.get('Retry-After', '')
  check(st == 503 and ra.isdigit() and 1 <= int(ra) <= 300, f'bearer request while discovery is down -> 503 + Retry-After={ra}')
  check(proxy.count('discovery') >= 1 and 'ERROR' in live.run(['docker', 'logs', f'{live.name_prefix}-uidisc']).stderr + live.run(['docker', 'logs', f'{live.name_prefix}-uidisc']).stdout,
        'the failed discovery was logged at ERROR and the issuer was asked at startup')
  time.sleep(8)
  proxy.modes['discovery'] = 'pass'

  def recovered():
    return api.machine(token, path)[0] == 200
  live.wait_until(recovered, 'a bearer request to succeed after the issuer recovered (no UI restart)', timeout=150, interval=3)
  attempts = proxy.times('discovery')
  gaps = [b - a for a, b in zip(attempts, attempts[1:])]
  check(all(g >= MIN_REFRESH - 1 for g in gaps), f'discovery attempts {len(attempts)} were at least 30s apart (gaps {[round(g, 1) for g in gaps]}s), recovery after {time.monotonic() - down_started:.0f}s without restarting the UI')
  check(api.call('GET', '/api/users?limit=1', human)[0] == 200, 'the cookie session kept working throughout')

  # ==== E. an http:// issuer ===================================================================
  name = f'{live.name_prefix}-uinoflag'
  api_no = ui('noflag', wait=False, MACHINE_OIDC_INSECURE_HTTP='false')

  def exited():
    return live.run(['docker', 'inspect', '-f', '{{.State.Status}}', name]).stdout.strip() == 'exited'
  live.wait_until(exited, 'the UI with an http issuer and no exception to exit', timeout=30)
  code = live.run(['docker', 'inspect', '-f', '{{.State.ExitCode}}', name]).stdout.strip()
  logs = live.run(['docker', 'logs', name])
  check(code != '0' and 'must use https' in logs.stdout + logs.stderr,
        f'an http:// issuer without MACHINE_OIDC_INSECURE_HTTP stops the UI at startup (exit {code}): ' + (logs.stdout + logs.stderr).strip().splitlines()[-1][:120])
  warn_logs = live.run(['docker', 'logs', f'{live.name_prefix}-uiflood'])
  check('MACHINE_OIDC_INSECURE_HTTP is on' in warn_logs.stdout + warn_logs.stderr, 'with the local-test exception the UI starts and logs the WARN')

  scan = live.all_logs()
  leaks = [t[:10] + '...' for t in tokens if t in scan] + [s[:6] + '...' for s in live.secret_values if len(s) >= 8 and s in scan]
  check(not leaks, f'no token or secret in the {len(live.containers)} container logs ({len(scan)} bytes): {leaks}')
  print(f'\nAll JWKS live checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
