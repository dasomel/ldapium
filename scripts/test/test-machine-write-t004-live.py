#!/usr/bin/env python3
"""Machine WRITE live measurements (machine-write-scope T-004, REQ-007, REQ-012, D12, D18, #378).

Real slapd (the normal image with the accesslog overlay), the package's W_data ACL fragment applied as the guide
documents it, and for the replay measurement the normal UI image + Keycloak. Everything here is MEASURED: the OBS lines
are what docs/changes/machine-write-scope/EVIDENCE.md (T-004) quotes; the checks pin the facts the decisions rely on.

  1. accesslog: what reqDN / reqAuthzID / reqType / reqResult a W_data Add/Modify/Delete (direct and through the five
     operations) leaves, including a refused (50) write
  2. notAllowedOnNonLeaf (rc 66) and container delete as W_data
  3. `by dn.exact=W write` vs the memberOf and refint overlays (W has no access to memberOf)
  4. entryCSN / objectClass assertion (the AND filter of the If-Match precondition) evaluated for W_data
  5. objectClass on Add versus Modify (D18), and the Password Modify extended operation; 5e the #386 ACL/overlay candidate
     matrix (objectClass slot swapped, olcAddContentAcl TRUE, constraint overlay), restored afterwards
  6. Idempotency-Key replay after a UI restart (the memory store is empty again)

The W password rotation / lockout effect on in-flight and next requests is measured by test-machine-write-drill.py
(phases C, E, F); it is not repeated here.

Run (local):  LDAPIUM_IMAGE=ldapium:x LDAPIUM_UI_IMAGE=ldapium-ui:x \
              python3 scripts/test/test-machine-write-t004-live.py
"""
import json
import pathlib
import re
import secrets
import sys
import time
import uuid
from urllib.parse import quote as urlquote

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'lib'))
from machine_live import (ADMIN_DN, AUDIENCE, BASE_DN, FIXTURES, MACHINE_DN, READER, Api, Keycloak, Live,  # noqa: E402
                          Slapd, ensure)

live = Live('ldapium-t004-', deadline_seconds=1200)
REALM = 't004'
SYSTEM_DN = 'ou=system,' + BASE_DN
WDATA_DN = 'uid=machine-write-data,' + SYSTEM_DN
PEOPLE = 'ou=people,' + BASE_DN
GROUPS = 'ou=groups,' + BASE_DN
G1 = 'cn=g01,' + GROUPS
WRITE_SCOPES = ['directory.users.create', 'directory.users.update', 'directory.users.delete',
                'directory.groups.members.add', 'directory.groups.members.remove']


def obs(text):
  print('OBS ' + text, flush=True)


def acl_rules(ldap, main_db):
  out = ldap.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', main_db, '-s', 'base', 'olcAccess']).stdout
  return [re.sub(r'^\{\d+\}', '', l[len('olcAccess: '):]) for l in out.splitlines() if l.startswith('olcAccess: ')]


def main():
  print(f'Run {live.name_prefix}: server {live.ldap_image}, UI {live.ui_image}, Keycloak {live.keycloak_image}', flush=True)
  live.make_network()
  ldap = Slapd(live)
  ldap.start()
  ldap.seed(users=4, groups=2)
  ldap.apply_acl()

  wdata_pw = live.secret('WData-' + secrets.token_urlsafe(18))
  r = ldap.admin_tool('ldapadd', [], f'dn: {WDATA_DN}\nobjectClass: inetOrgPerson\nuid: machine-write-data\ncn: machine-write-data\n'
                                     f'sn: w\nuserPassword: {wdata_pw}\n')
  ensure(r.returncode == 0, 'W_data account: ' + live.mask(r.stderr))
  main_db = next(l[4:] for l in ldap.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config',
                                                               '(&(objectClass=olcMdbConfig)(olcSuffix=' + BASE_DN + '))', 'dn']).stdout.splitlines()
                 if l.startswith('dn: '))
  text = (FIXTURES / 'write-data.ldif').read_text()
  for k, v in {'WDATA_DN': WDATA_DN, 'WRITE_DN': BASE_DN, 'SYSTEM_DN': SYSTEM_DN, 'REPL_DN': 'cn=replicator,' + BASE_DN,
               'MAIN_DB_DN': main_db}.items():
    text = text.replace('@' + k + '@', v)
  text = re.sub(r'(?m)^olcAccess: \{(\d+)\}', lambda m: 'olcAccess: {%d}' % (int(m.group(1)) + 3), text)  # after the three M rules
  r = ldap.config_tool('ldapmodify', [], text)
  ensure(r.returncode == 0, 'W_data fragment: ' + live.mask(r.stderr))
  ldap.put_password('/tmp/.pw-wdata', wdata_pw)

  def w(tool, args=(), data=None):
    return ldap.tool(tool, list(args), WDATA_DN, '/tmp/.pw-wdata', data)

  def adm(tool, args=(), data=None):
    return ldap.admin_tool(tool, list(args), data)

  def attrs(dn, *names):
    out = adm('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', dn, '-s', 'base', *names]).stdout
    return [l for l in out.splitlines() if l and not l.startswith('dn: ')]

  def exists(dn):
    return adm('ldapsearch', ['-LLL', '-b', dn, '-s', 'base', 'dn']).returncode == 0

  def accesslog(flt, want):
    time.sleep(0.6)
    out = ldap.tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=accesslog', flt, *want],
                    'cn=admin,cn=accesslog', '/tmp/.pw-admin').stdout
    return [l for l in out.splitlines() if l and not l.startswith('dn: ')]

  def tail(r):
    return (live.mask(r.stdout) + live.mask(r.stderr)).strip().replace('\n', ' | ')[:200]

  # ======== 1. accesslog: reqDN / reqAuthzID for W_data writes (direct) ======================================
  u1 = 'uid=t1,' + PEOPLE
  r_add = w('ldapadd', [], f'dn: {u1}\nobjectClass: inetOrgPerson\nuid: t1\ncn: t1\nsn: t1\nmail: t1@example.org\n')
  r_mod = w('ldapmodify', [], f'dn: {u1}\nchangetype: modify\nreplace: mail\nmail: t1b@example.org\n')
  r_ref = w('ldapmodify', [], f'dn: {u1}\nchangetype: modify\nreplace: objectClass\nobjectClass: person\n')
  r_del = w('ldapdelete', [u1])
  live.check((r_add.returncode, r_mod.returncode, r_ref.returncode, r_del.returncode) == (0, 0, 50, 0),
             f'[1] direct W_data Add/Modify/refused-Modify/Delete -> rc 0/0/50/0 (got {r_add.returncode}/{r_mod.returncode}/{r_ref.returncode}/{r_del.returncode})')
  rows = accesslog(f'(&(reqDN={u1})(!(reqType=search)))', ['reqType', 'reqDN', 'reqAuthzID', 'reqResult', 'reqMod'])
  text = '\n'.join(rows)
  for typ in ('add', 'modify', 'delete'):
    live.check(f'reqType: {typ}' in text, f'[1] accesslog has a {typ} record for the W_data write on {u1}')
  live.check(f'reqAuthzID: {WDATA_DN}' in text or f'reqAuthzID: dn:{WDATA_DN}' in text,
             '[1] reqAuthzID names W_data (the writer), not the bind DN of any client')
  live.check('reqResult: 50' in text, '[1] the refused (50) write is logged with reqResult 50 (writes are logged on failure too)')
  authz = sorted({l.split(': ', 1)[1] for l in rows if l.startswith('reqAuthzID:')})
  req_dn = sorted({l.split(': ', 1)[1] for l in rows if l.startswith('reqDN:')})
  obs(f'1a direct W_data writes: reqAuthzID values {authz}; reqDN values {req_dn}; reqType/reqResult pairs '
      + str(sorted(set(zip([l for l in rows if l.startswith("reqType:")], [l for l in rows if l.startswith("reqResult:")])))))
  obs('1b accesslog rows (reqMod included, no password was written): ' + ' ; '.join(rows)[:900])

  # ======== 2. notAllowedOnNonLeaf, container delete ==========================================================
  parent = 'uid=t2,' + PEOPLE
  child = 'ou=child,' + parent
  r = w('ldapadd', [], f'dn: {parent}\nobjectClass: inetOrgPerson\nuid: t2\ncn: t2\nsn: t2\n')
  ensure(r.returncode == 0, 'add t2: ' + tail(r))
  r = w('ldapadd', [], f'dn: {child}\nobjectClass: organizationalUnit\nou: child\n')
  obs(f'2a W_data adds an organizationalUnit UNDER a user entry: rc {r.returncode} {tail(r)}')
  non_leaf = w('ldapdelete', [parent])
  obs(f'2b W_data deletes a user that has a child: rc {non_leaf.returncode} {tail(non_leaf)}')
  live.check(non_leaf.returncode == 66 and exists(parent), '[2] delete of a non-leaf user is refused by slapd with 66 (notAllowedOnNonLeaf) and the entry stays')
  ou = w('ldapdelete', [PEOPLE])
  obs(f'2c W_data deletes the non-leaf container {PEOPLE}: rc {ou.returncode} {tail(ou)}')
  live.check(ou.returncode == 66 and exists(PEOPLE), '[2] delete of the non-empty container ou=people is refused with 66')
  empty = 'ou=emptyc,' + PEOPLE
  w('ldapadd', [], f'dn: {empty}\nobjectClass: organizationalUnit\nou: emptyc\n')
  r = w('ldapdelete', [empty])
  obs(f'2d W_data deletes an EMPTY container (a leaf) inside the write subtree: rc {r.returncode}')
  live.check(r.returncode == 0 and not exists(empty), '[2] an empty container inside the write subtree IS deletable by W_data (ACL cannot tell a container from a user: the app class assertion D8e is the guard)')
  if exists(child):
    adm('ldapdelete', [child])
  w('ldapdelete', [parent])

  # ======== 3. memberOf / refint under `by dn.exact=W write` ==================================================
  u3 = 'uid=t3,' + PEOPLE
  w('ldapadd', [], f'dn: {u3}\nobjectClass: inetOrgPerson\nuid: t3\ncn: t3\nsn: t3\n')
  direct = w('ldapmodify', [], f'dn: {u3}\nchangetype: modify\nreplace: memberOf\nmemberOf: {G1}\n')
  obs(f'3a W_data writes memberOf directly: rc {direct.returncode} {tail(direct)}')
  r = w('ldapmodify', [], f'dn: {G1}\nchangetype: modify\nadd: member\nmember: {u3}\n')
  mo = attrs(u3, 'memberOf')
  as_w = w('ldapsearch', ['-LLL', '-b', u3, '-s', 'base', 'memberOf']).stdout
  obs(f'3b W_data adds a group member: rc {r.returncode}; memberOf on the user (as admin) {mo}; W_data cannot read memberOf: {"memberOf" not in as_w}')
  live.check(r.returncode == 0 and 'memberOf: ' + G1 in mo, '[3] the member Add by W_data updates memberOf on the user although W has no access to memberOf')
  live.check('memberOf' not in as_w, '[3] W_data cannot read memberOf (ACL none)')
  r = w('ldapdelete', [u3])
  member_left = [l for l in attrs(G1, 'member') if u3 in l]
  obs(f'3c W_data deletes a member user directly: rc {r.returncode}; group still lists it: {bool(member_left)}')
  live.check(r.returncode == 0 and not member_left, '[3] refint removes the deleted user from the group member list (W_data has write on the entry, the group member rewrite is the overlay)')

  # ======== 4. entryCSN / objectClass assertion for W_data ====================================================
  u4 = 'uid=t4,' + PEOPLE
  w('ldapadd', [], f'dn: {u4}\nobjectClass: inetOrgPerson\nuid: t4\ncn: t4\nsn: t4\n')
  u4_pw = live.secret('U4pw-' + secrets.token_urlsafe(12))
  r = adm('ldapmodify', [], f'dn: {u4}\nchangetype: modify\nadd: userPassword\nuserPassword: {u4_pw}\n')
  ensure(r.returncode == 0, 'u4 password: ' + live.mask(r.stderr))
  csn = attrs(u4, 'entryCSN')[0].split(': ', 1)[1]
  mod = f'dn: {u4}\nchangetype: modify\nreplace: mail\nmail: %s@example.org\n'
  good = w('ldapmodify', ['-e', f'!assert=(&(entryCSN={csn})(objectClass=inetOrgPerson))'], mod % 'ok')
  obs(f'4a assertion (&(entryCSN=current)(objectClass=inetOrgPerson)) as W_data: rc {good.returncode} {tail(good)}')
  live.check(good.returncode == 0 and attrs(u4, 'mail') == ['mail: ok@example.org'], '[4] a matching entryCSN+objectClass assertion lets the W_data Modify through')
  stale = w('ldapmodify', ['-e', f'!assert=(&(entryCSN={csn})(objectClass=inetOrgPerson))'], mod % 'stale')
  obs(f'4b the SAME assertion after the entry changed (entryCSN moved): rc {stale.returncode} {tail(stale)}')
  live.check(stale.returncode == 122 and attrs(u4, 'mail') == ['mail: ok@example.org'], '[4] a stale entryCSN is refused with 122 (assertionFailed) and nothing changes')
  csn2 = attrs(u4, 'entryCSN')[0].split(': ', 1)[1]
  wrong = w('ldapmodify', ['-e', f'!assert=(&(entryCSN={csn2})(objectClass=groupOfNames))'], mod % 'wrongtype')
  obs(f'4c current entryCSN but the wrong objectClass (groupOfNames on a user): rc {wrong.returncode} {tail(wrong)}')
  live.check(wrong.returncode == 122 and attrs(u4, 'mail') == ['mail: ok@example.org'], '[4] the objectClass half of the AND filter is evaluated: a wrong target type is refused with 122')
  # the target really has a userPassword: the admin sees it, W_data must not (search filters and assertion)
  stored = adm('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', u4, '-s', 'base', 'userPassword']).stdout
  prefix = next((l.split(': ', 1)[1][:3] for l in stored.splitlines() if l.lower().startswith('userpassword')), '')
  ensure(prefix != '', 'admin must read the stored userPassword of u4')
  found = {}
  for label, flt in (('presence', '(userPassword=*)'), ('prefix', '(userPassword=' + prefix + '*)')):
    a = adm('ldapsearch', ['-LLL', '-b', u4, '-s', 'base', flt, 'dn']).stdout
    x = w('ldapsearch', ['-LLL', '-b', u4, '-s', 'base', flt, 'dn']).stdout
    found[label] = ('dn: ' + u4 in a, 'dn: ' + u4 in x)
  obs(f'4d0 search on u4 (has a userPassword) as (admin finds, W_data finds): presence {found["presence"]}, 3-char prefix {found["prefix"]}')
  live.check(found['presence'] == (True, False), '[4] (userPassword=*) finds u4 as admin and finds nothing as W_data')
  if found['prefix'][0]:
    live.check(found['prefix'][1] is False, '[4] a value-prefix filter on userPassword finds nothing as W_data although the admin finds the entry')
  else:
    obs('4d1 the admin prefix filter did not match either (no substring rule on userPassword): prefix probe is not informative')
  blind = w('ldapmodify', ['-e', '!assert=(userPassword=*)'], mod % 'blind')
  obs(f'4d assertion on an attribute W_data has no access to, (userPassword=*): rc {blind.returncode} {tail(blind)}')
  live.check(blind.returncode == 122 and attrs(u4, 'mail') == ['mail: ok@example.org'], '[4] an assertion on an attribute W_data may not read evaluates false (122): it cannot be used as an oracle')
  dele = w('ldapdelete', ['-e', f'!assert=(&(entryCSN={csn})(objectClass=inetOrgPerson))', u4])
  obs(f'4e Delete with the stale assertion: rc {dele.returncode} {tail(dele)}')
  live.check(dele.returncode == 122 and exists(u4), '[4] a stale assertion on Delete is refused with 122 and the entry stays')
  w('ldapdelete', [u4])

  # ======== 5. objectClass on Add versus Modify (D18) ========================================================
  u5 = 'uid=t5,' + PEOPLE
  r_add = w('ldapadd', [], f'dn: {u5}\nobjectClass: inetOrgPerson\nuid: t5\ncn: t5\nsn: t5\n')
  r_rep = w('ldapmodify', [], f'dn: {u5}\nchangetype: modify\nreplace: objectClass\nobjectClass: inetOrgPerson\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\n')
  r_vdel = w('ldapmodify', [], f'dn: {u5}\nchangetype: modify\ndelete: objectClass\nobjectClass: inetOrgPerson\n')
  r_vadd = w('ldapmodify', [], f'dn: {u5}\nchangetype: modify\nadd: objectClass\nobjectClass: extensibleObject\n')
  obs(f'5 W_data Add user (objectClass inetOrgPerson): rc {r_add.returncode}; Modify REPLACE objectClass: rc {r_rep.returncode}; '
      f'Modify DELETE objectClass value: rc {r_vdel.returncode}; Modify ADD objectClass extensibleObject: rc {r_vadd.returncode}')
  live.check(r_add.returncode == 0, '[5] objectClass `add` access is enough for W_data to create a user (the Add carries objectClass)')
  live.check(r_rep.returncode == 50 and r_vdel.returncode == 50, '[5] Modify REPLACE / DELETE of objectClass is refused (50)')
  live.check(r_vadd.returncode == 0,
             '[5] KNOWN LIMIT (#386): Modify ADD of an objectClass VALUE is allowed by `add` (extensibleObject); only the application closed-attribute guard stops it (D18 contradicted for value-add). '
             'An ACL fix (EVIDENCE.md "#386") must flip this check deliberately; section 6 asserts the app guard end to end')
  # #386: slapd's Add evaluates `entry`/`children` only, not per-attribute rules: a secret on the Add lands
  add_pw = live.secret('AddPw-' + secrets.token_urlsafe(12))
  r_pwadd = w('ldapadd', [], f'dn: uid=t5p,{PEOPLE}\nobjectClass: inetOrgPerson\nuid: t5p\ncn: t5p\nsn: t5p\nuserPassword: {add_pw}\n')
  pw_landed = any(l.lower().startswith('userpassword') for l in attrs('uid=t5p,' + PEOPLE, 'userPassword'))
  ldap.put_password('/tmp/.pw-t5p', add_pw)
  bind_t5p = ldap.tool('ldapwhoami', [], 'uid=t5p,' + PEOPLE, '/tmp/.pw-t5p')
  obs(f'5d W_data Add of a user carrying userPassword (rule {{2}} gives W_data none on it): rc {r_pwadd.returncode}; stored: {pw_landed}; '
      f'bind as the new entry with that password: rc {bind_t5p.returncode}')
  live.check(r_pwadd.returncode == 0 and pw_landed and bind_t5p.returncode == 0,
             '[5] KNOWN LIMIT (#386, olcAddContentAcl FALSE): an Add is not checked per attribute, so W_data creates a BINDABLE entry with its own userPassword; '
             'the createUser closed body (D15) is the only barrier')
  adm('ldapdelete', ['uid=t5p,' + PEOPLE])
  r_ocadd = w('ldapadd', [], f'dn: cn=t5b,{PEOPLE}\nobjectClass: groupOfNames\ncn: t5b\nmember: {ADMIN_DN}\n')
  obs(f'5b W_data Add of a groupOfNames with member={ADMIN_DN} under the user subtree: rc {r_ocadd.returncode}')
  # the RFC 3062 Password Modify extended operation as W_data (T-004 item 5)
  new_pw = live.secret('NewPw-' + secrets.token_urlsafe(12))
  old_pw = live.secret('OldPw-' + secrets.token_urlsafe(12))
  r = adm('ldapmodify', [], f'dn: {u5}\nchangetype: modify\nadd: userPassword\nuserPassword: {old_pw}\n')
  ensure(r.returncode == 0, 'u5 password: ' + live.mask(r.stderr))
  ldap.put_password('/tmp/.pw-u5old', old_pw)
  ldap.put_password('/tmp/.pw-u5new', new_pw)
  r_pm = w('ldappasswd', ['-s', new_pw, u5])
  bind_old = ldap.tool('ldapwhoami', [], u5, '/tmp/.pw-u5old')
  bind_new = ldap.tool('ldapwhoami', [], u5, '/tmp/.pw-u5new')
  live.check(bind_old.returncode == 0 and bind_new.returncode == 49,
             f'[5] after the refused Password Modify the user still binds with the OLD password (rc {bind_old.returncode}) and not with the new one (rc {bind_new.returncode}, 49 = invalid credentials)')
  r_pm_self = bind_old
  obs(f'5c W_data Password Modify (ldappasswd) on a managed user: rc {r_pm.returncode} {tail(r_pm)}; bind with the OLD password rc {bind_old.returncode}, with the new one rc {bind_new.returncode}')
  live.check(r_pm.returncode != 0 and 'Insufficient access (50)' in r_pm.stdout + r_pm.stderr, '[5] secret attributes `none` stop the Password Modify extended operation of W_data (50)')
  w('ldapdelete', [u5])
  w('ldapdelete', ['cn=t5b,' + PEOPLE])

  # ======== 5e. #386: which ACL / overlay forms refuse the Modify objectClass value ADD (candidate matrix) =======
  # Only the W_data objectClass rule (fragment {4}) is swapped; the shipped rule and settings are restored and
  # asserted afterwards. Probe order matters (P7/P8 run after the value adds). Expected rc per probe is what
  # EVIDENCE.md "#386" records; a different slapd behaviour fails the matching check.
  oc_rules = acl_rules(ldap, main_db)
  slot = next(i for i, r in enumerate(oc_rules) if 'attrs=objectClass by dn.exact="' + WDATA_DN + '"' in r)
  shipped = oc_rules[slot]
  wd = f'dn.exact="{WDATA_DN}"'
  in_slot = [1]

  def set_slot(rules):
    mod = (f'dn: {main_db}\nchangetype: modify\ndelete: olcAccess\n'
           + ''.join(f'olcAccess: {{{slot + i}}}\n' for i in reversed(range(in_slot[0])))
           + '-\nadd: olcAccess\n' + ''.join(f'olcAccess: {{{slot + i}}}{r}\n' for i, r in enumerate(rules)))
    r = ldap.config_tool('ldapmodify', [], mod)
    ensure(r.returncode == 0, 'swap objectClass slot: ' + tail(r))
    in_slot[0] = len(rules)

  def oc_rule(level, val=''):
    return f'to dn.subtree="{BASE_DN}" attrs=objectClass{val} by {wd} {level} by * break'

  def probe_row():
    u, g, x, d, p = ('uid=p386,' + PEOPLE, 'cn=p386g,' + GROUPS, 'uid=p386x,' + PEOPLE, 'uid=p386d,' + PEOPLE, 'uid=p386p,' + PEOPLE)
    oc_add = f'dn: {u}\nchangetype: modify\nadd: objectClass\nobjectClass: %s\n'
    rcs = [
      w('ldapadd', [], f'dn: {u}\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: inetOrgPerson\nuid: p386\ncn: p\nsn: p\n'),
      w('ldapadd', [], f'dn: {g}\nobjectClass: top\nobjectClass: groupOfNames\ncn: p386g\nmember: {u}\n'),
      w('ldapmodify', [], oc_add % 'extensibleObject'),
      w('ldapmodify', [], oc_add % 'shadowAccount'),
      w('ldapmodify', [], oc_add % 'groupOfNames' + f'-\nadd: member\nmember: {u}\n'),
      w('ldapadd', [], f'dn: {x}\nobjectClass: inetOrgPerson\nobjectClass: extensibleObject\nuid: p386x\ncn: x\nsn: x\n'),
      w('ldapadd', [], f'dn: {d}\nobjectClass: inetOrgPerson\nuid: p386d\ncn: d\nsn: d\ndescription: outside the list\n'),
      w('ldapadd', [], f'dn: {p}\nobjectClass: inetOrgPerson\nuid: p386p\ncn: p\nsn: p\nuserPassword: {live.secret("P386-" + secrets.token_urlsafe(10))}\n'),
      w('ldapmodify', [], f'dn: {u}\nchangetype: modify\nreplace: objectClass\nobjectClass: top\nobjectClass: person\nobjectClass: organizationalPerson\nobjectClass: inetOrgPerson\n'),
      w('ldapmodify', [], f'dn: {u}\nchangetype: modify\ndelete: objectClass\nobjectClass: top\n'),
      adm('ldapmodify', [], f'dn: uid=u02,{PEOPLE}\nchangetype: modify\nadd: objectClass\nobjectClass: extensibleObject\n'),
    ]
    adm('ldapmodify', [], f'dn: uid=u02,{PEOPLE}\nchangetype: modify\ndelete: objectClass\nobjectClass: extensibleObject\n')
    for dn in (g, u, x, d, p):
      adm('ldapdelete', [dn])
    return tuple(r.returncode for r in rcs)

  heads = 'P1 add-user P2 add-group P3 mod+extensibleObject P4 mod+shadowAccount P5 mod+groupOfNames P6 add+extensibleObject ' \
          'P11 add+description P12 add+userPassword P7 mod-replace P8 mod-delete P10 admin-mod+extensibleObject'
  obs('5e probe columns: ' + heads)
  base = (0, 0, 0, 0, 65, 0, 0, 0, 50, 50, 0)
  refuse = (0, 0, 50, 50, 65, 0, 0, 0, 50, 50, 0)
  allow = [f'val={v}' for v in ('top', 'person', 'organizationalPerson', 'inetOrgPerson', 'groupOfNames')]
  candidates = [
    ('C0 shipped `add`', [shipped], base),
    ('C1 `=a`', [oc_rule('=a')], base),
    ('C1b `=wa`', [oc_rule('=wa')], (0, 0, 0, 0, 65, 0, 0, 0, 0, 0, 0)),
    ('C2 val= allowlist incl. top', [oc_rule('add', ' ' + v) for v in allow], base),
    ('C2b val= allowlist without top', [oc_rule('add', ' ' + v) for v in allow[1:]], refuse),
    ('C3 val.regex allowlist', [oc_rule('add', ' val.regex="^(top|person|organizationalPerson|inetOrgPerson|groupOfNames)$"')], refuse),
    ('C3b val.regex lower-case', [oc_rule('add', ' val.regex="^(top|person|organizationalperson|inetorgperson|groupofnames)$"')], refuse),
    ('C4 val=extensibleObject none, then add', [oc_rule('none', ' val=extensibleObject'), shipped], (0, 0, 50, 0, 65, 0, 0, 0, 50, 50, 0)),
    ('C6 objectClass read only', [oc_rule('read')], (0, 0, 50, 50, 50, 0, 0, 0, 50, 50, 0)),
  ]
  for label, rules, want in candidates:
    set_slot(rules)
    got = probe_row()
    obs(f'5e {label}: {got}')
    live.check(got == want, f'[5e] #386 {label}: rc {got} == {want}')

  # olcAddContentAcl (slapd.access(5)): TRUE makes slapd check `=a` on every attribute of an Add.
  # Not set by image/entrypoint.sh, so the default (FALSE) is what ships.
  cur = [l for l in ldap.config_tool('ldapsearch', ['-LLL', '-b', main_db, '-s', 'base', 'olcAddContentAcl']).stdout.splitlines() if l.startswith('olcAddContentAcl')]
  obs(f'5e olcAddContentAcl on the main database as shipped: {cur or "absent (default FALSE)"}')
  live.check(cur in ([], ['olcAddContentAcl: FALSE']), '[5e] the image does not turn olcAddContentAcl on (C6 / point 1 of EVIDENCE "#386" depend on it)')
  aca = f'dn: {main_db}\nchangetype: modify\nreplace: olcAddContentAcl\nolcAddContentAcl: %s\n'
  ensure(ldap.config_tool('ldapmodify', [], aca % 'TRUE').returncode == 0, 'olcAddContentAcl TRUE')
  for label, rules, want in [('C0 shipped `add` + olcAddContentAcl TRUE', [shipped], (0, 0, 0, 0, 65, 0, 50, 50, 50, 50, 0)),
                             ('C3 val.regex + olcAddContentAcl TRUE', [candidates[5][1][0]], (0, 0, 50, 50, 65, 50, 50, 50, 50, 50, 0)),
                             # the Adds fail (50), so the Modify probes hit a missing entry (32)
                             ('C6 read + olcAddContentAcl TRUE', [oc_rule('read')], (50, 50, 32, 32, 32, 50, 50, 50, 32, 32, 0))]:
    set_slot(rules)
    got = probe_row()
    obs(f'5e {label}: {got}')
    live.check(got == want, f'[5e] #386 {label}: rc {got} == {want}')
  ensure(ldap.config_tool('ldapmodify', [], f'dn: {main_db}\nchangetype: modify\ndelete: olcAddContentAcl\n').returncode == 0, 'olcAddContentAcl reset')

  # the constraint overlay (on by default for mail): an objectClass allowlist applies to EVERY identity
  set_slot([shipped])
  cdn = next(l[4:] for l in ldap.config_tool('ldapsearch', ['-LLL', '-o', 'ldif-wrap=no', '-b', 'cn=config', '(objectClass=olcConstraintConfig)', 'dn']).stdout.splitlines() if l.startswith('dn: '))
  c_val = 'objectClass regex "^(top|person|organizationalPerson|inetOrgPerson|groupOfNames|organizationalUnit|dcObject|organization)$"'
  ensure(ldap.config_tool('ldapmodify', [], f'dn: {cdn}\nchangetype: modify\nadd: olcConstraintAttribute\nolcConstraintAttribute: {c_val}\n').returncode == 0, 'constraint add')
  got = probe_row()
  obs(f'5e C5 constraint overlay objectClass allowlist + shipped `add`: {got}')
  live.check(got == (0, 0, 19, 19, 65, 19, 0, 0, 50, 50, 19), f'[5e] #386 C5 constraint overlay refuses value adds AND the Add-time extra class (19) but also the admin: rc {got}')
  ensure(ldap.config_tool('ldapmodify', [], f'dn: {cdn}\nchangetype: modify\ndelete: olcConstraintAttribute\nolcConstraintAttribute: {c_val}\n').returncode == 0, 'constraint reset')
  live.check(acl_rules(ldap, main_db) == oc_rules, '[5e] the shipped W_data fragment is restored exactly after the candidate matrix')

  # ======== 6. the five operations through the UI: accesslog, then Idempotency-Key replay after a restart ======
  kcname = live.name_prefix + '-kc'
  kc = Keycloak(live, kcname, f'http://{kcname}:8080')
  kc.start()
  kc.create_realm(REALM)
  for scope in READER + WRITE_SCOPES:
    kc.create_scope(REALM, scope)
  client_secret = live.secret('svc-writer-' + secrets.token_hex(10))
  kc.create_client(REALM, 'svc-writer', client_secret, scopes=READER + WRITE_SCOPES)
  issued = []

  def token():
    value = kc.sa_token(REALM, 'svc-writer', client_secret)
    issued.append(value)
    return value

  env = {'LDAP_BASE_DN': BASE_DN, 'LDAP_USER_CREATE_BASE': PEOPLE, 'COOKIE_SECURE': 'false', 'UI_TRUSTED_PROXIES': 'none',
         'MACHINE_AUTH_ENABLED': 'true', 'MACHINE_OIDC_INSECURE_HTTP': 'true', 'MACHINE_OIDC_ISSUER_URL': kc.issuer(REALM),
         'MACHINE_OIDC_AUDIENCE': AUDIENCE, 'MACHINE_CLOCK_SKEW': '0s',
         'MACHINE_ALLOWED_CLIENTS': 'svc-writer=' + ','.join(READER + WRITE_SCOPES),
         'MACHINE_LDAP_BIND_DN': MACHINE_DN, 'MACHINE_LDAP_ROOT_DNS': ADMIN_DN,
         'MACHINE_AUTH_FAILURE_LIMIT': '1000', 'MACHINE_RATE_LIMIT_RPS': '10000', 'MACHINE_RATE_LIMIT_BURST': '10000',
         'UI_IDEMPOTENCY_ENABLED': 'true', 'MACHINE_WRITE_ENABLED': 'true', 'MACHINE_WRITE_DATA_BIND_DN': WDATA_DN,
         'MACHINE_WRITE_SUBTREES': f'svc-writer={PEOPLE}|{GROUPS}', 'MACHINE_WRITE_GROUPS': f'svc-writer={G1}',
         'MACHINE_WRITE_PRIVILEGED_GROUPS': 'cn=admins,' + GROUPS,
         'MACHINE_WRITE_RATE_LIMIT_RPS': '100', 'MACHINE_WRITE_RATE_LIMIT_BURST': '100'}
  held = {'SESSION_SECRET': live.secret(secrets.token_hex(32)), 'MACHINE_LDAP_BIND_PASSWORD': ldap.machine_password,
          'MACHINE_WRITE_DATA_BIND_PASSWORD': wdata_pw}
  uiname = live.name_prefix + '-ui'
  api = live.start_ui(uiname, f'ldap://{ldap.name}:389', env, held)

  def call(client, tok, method, path, body=None, key=None, etag=None):
    headers = {'Authorization': 'Bearer ' + tok}
    if body is not None:
      headers['Content-Type'] = 'application/json'
    if key:
      headers['Idempotency-Key'] = key
    if etag:
      headers['If-Match'] = etag
    status, hdrs, text = client.call(method, path, headers, body)
    return status, hdrs, text

  def etag_of(client, tok, dn):
    status, hdrs, text = call(client, tok, 'GET', '/api/entry?dn=' + urlquote(dn))
    ensure(status == 200 and hdrs.get('ETag'), f'entry {dn}: {status} {text[:160]}')
    return hdrs['ETag']

  tok = token()
  u6 = 'uid=t6,' + PEOPLE
  body = {'uid': 't6', 'cn': 't6', 'sn': 'T', 'mail': 't6@example.org'}
  st, _, text = call(api, tok, 'POST', '/api/users', body, 'k-' + uuid.uuid4().hex)
  ensure(st == 201, f'createUser {st} {text[:160]}')
  st, _, text = call(api, tok, 'PATCH', '/api/users', {'dn': u6, 'mail': 't6b@example.org'}, 'k-' + uuid.uuid4().hex, etag_of(api, tok, u6))
  ensure(st in (200, 204), f'patchUser {st} {text[:160]}')
  # #386: the same objectClass value ADD that slapd lets W_data make (section 5) is stopped by the app guard
  oc_before = attrs(u6, 'objectClass')
  mods_before = len([l for l in accesslog(f'(&(reqDN={u6})(reqType=modify))', ['reqResult']) if l.startswith('reqResult:')])
  refused = []
  for shape in ({'dn': u6, 'objectClass': ['extensibleObject']}, {'dn': u6, 'mail': 't6c@example.org', 'objectClass': 'extensibleObject'}):
    st, _, text = call(api, tok, 'PATCH', '/api/users', shape, 'k-' + uuid.uuid4().hex, etag_of(api, tok, u6))
    refused.append(st)
    obs(f'6i patchUser through the UI carrying objectClass {sorted(shape)}: {st} {text[:140]}')
  mods_after = len([l for l in accesslog(f'(&(reqDN={u6})(reqType=modify))', ['reqResult']) if l.startswith('reqResult:')])
  live.check(all(s in (400, 403) for s in refused) and attrs(u6, 'objectClass') == oc_before and mods_after == mods_before,
             f'[6] #386: a patchUser carrying objectClass is refused by the app guard ({refused}), objectClass unchanged, no modify reached slapd ({mods_before} -> {mods_after} accesslog rows)')
  st, _, text = call(api, tok, 'DELETE', f'/api/users?dn={urlquote(u6)}', None, 'k-' + uuid.uuid4().hex, etag_of(api, tok, u6) if exists(u6) else None)
  ensure(st in (200, 204), f'deleteUser {st} {text[:160]}')
  rows = accesslog(f'(&(reqDN={u6})(!(reqType=search)))', ['reqType', 'reqAuthzID', 'reqResult'])
  authz = sorted({l.split(': ', 1)[1] for l in rows if l.startswith('reqAuthzID:')})
  types = [l.split(': ', 1)[1] for l in rows if l.startswith('reqType:')]
  obs(f'1c the same writes through the UI (createUser/patchUser/deleteUser): reqType {sorted(types)}, reqAuthzID values {authz} (one value: W_data; the client id is NOT in slapd, only in the app audit line)')
  live.check(authz == [WDATA_DN] or authz == ['dn:' + WDATA_DN], '[1] through the UI every write is attributed to W_data in slapd, never to M, an admin or the client')

  # addGroupMember / removeGroupMember through the UI
  u8 = 'uid=t8,' + PEOPLE
  ensure(call(api, tok, 'POST', '/api/users', {'uid': 't8', 'cn': 't8', 'sn': 'T'}, 'k-' + uuid.uuid4().hex)[0] == 201, 'create t8')
  g_before = len(accesslog(f'(&(reqDN={G1})(reqType=modify))', ['reqAuthzID']))
  st_a, _, ta = call(api, tok, 'POST', '/api/groups/members', {'groupDn': G1, 'memberDn': u8}, 'k-' + uuid.uuid4().hex, etag_of(api, tok, G1))
  st_r, _, tr = call(api, tok, 'DELETE', f'/api/groups/members?groupDn={urlquote(G1)}&memberDn={urlquote(u8)}', None, 'k-' + uuid.uuid4().hex, etag_of(api, tok, G1))
  ensure(st_a in (200, 204) and st_r in (200, 204), f'group member add/remove {st_a} {ta[:100]} / {st_r} {tr[:100]}')
  g_rows = accesslog(f'(&(reqDN={G1})(reqType=modify))', ['reqAuthzID'])
  g_authz = sorted({l.split(': ', 1)[1] for l in g_rows if l.startswith('reqAuthzID:')})
  obs(f'1d addGroupMember/removeGroupMember through the UI: {st_a}/{st_r}; new group-modify accesslog rows {len(g_rows) - g_before}; reqAuthzID values over all rows {g_authz}')
  live.check(len(g_rows) - g_before >= 2 and g_authz in ([WDATA_DN], ['dn:' + WDATA_DN]), '[1] addGroupMember and removeGroupMember through the UI each leave a modify record attributed to W_data')
  call(api, tok, 'DELETE', f'/api/users?dn={urlquote(u8)}', None, 'k-' + uuid.uuid4().hex, etag_of(api, tok, u8))

  # -- idempotency replay after a restart ---------------------------------------------------------------------
  u7 = 'uid=t7,' + PEOPLE
  key = 'k-' + uuid.uuid4().hex
  create7 = {'uid': 't7', 'cn': 't7', 'sn': 'T', 'mail': 't7@example.org'}
  st1, _, text1 = call(api, tok, 'POST', '/api/users', create7, key)
  st1b, h1b, _ = call(api, tok, 'POST', '/api/users', create7, key)
  obs(f'6a createUser key K: first {st1}; replay in the same process {st1b} (Idempotent-Replayed={h1b.get("Idempotent-Replayed")})')
  ensure(st1 == 201 and st1b == 201 and h1b.get('Idempotent-Replayed') == 'true', 'same-process replay baseline')
  patch_key = 'k-' + uuid.uuid4().hex
  tag_before = etag_of(api, tok, u7)
  stp, _, _ = call(api, tok, 'PATCH', '/api/users', {'dn': u7, 'mail': 't7b@example.org'}, patch_key, tag_before)
  ensure(stp in (200, 204), 'patch before restart')
  del_key = 'k-' + uuid.uuid4().hex
  tag_del = etag_of(api, tok, u7)
  std, _, _ = call(api, tok, 'DELETE', f'/api/users?dn={urlquote(u7)}', None, del_key, tag_del)
  ensure(std in (200, 204) and not exists(u7), 'delete before restart')

  ensure(live.run(['docker', 'restart', uiname]).returncode == 0, 'restart UI')
  api = Api(live, f'http://127.0.0.1:{live.published_port(uiname, "8080/tcp")}')
  live.wait_ui(api, uiname)
  tok = token()

  # (i) the create key replayed after the restart, entry gone: the memory store forgot the key
  st_i, h_i, text_i = call(api, tok, 'POST', '/api/users', create7, key)
  obs(f'6b AFTER the UI restart, createUser key K replayed (entry had been deleted): {st_i} Idempotent-Replayed={h_i.get("Idempotent-Replayed")} {text_i[:120]} -> the entry exists again: {exists(u7)}')
  live.check(st_i == 201 and h_i.get('Idempotent-Replayed') is None and exists(u7),
             '[6] KNOWN LIMIT (D9): after a restart the same createUser key is RE-EXECUTED (201, not a replay)')
  # (ii) the same key again with the entry present: entryAlreadyExists stops the duplicate
  st_ii, _, text_ii = call(api, tok, 'POST', '/api/users', create7, 'k-' + uuid.uuid4().hex)
  obs(f'6c createUser (new key) while the entry exists: {st_ii} {text_ii[:140]}')
  live.check(st_ii in (409, 412), '[6] a duplicate create is stopped by entryAlreadyExists (409), not by the key')
  # (iii) a patch replay with the OLD If-Match tag: the entry moved on, the precondition fails
  st_iii, _, text_iii = call(api, tok, 'PATCH', '/api/users', {'dn': u7, 'mail': 't7b@example.org'}, patch_key, tag_before)
  obs(f'6d AFTER the restart, patchUser key P replayed with the pre-restart If-Match tag: {st_iii} {text_iii[:140]}; mail now {attrs(u7, "mail")}')
  live.check(st_iii == 412 and attrs(u7, 'mail') == ['mail: t7@example.org'], '[6] a replayed patch is stopped by the stale If-Match (412), mail unchanged')
  # (iv) the delete replay with the old tag: the current entry (re-created) has a new entryCSN
  st_iv, _, text_iv = call(api, tok, 'DELETE', f'/api/users?dn={urlquote(u7)}', None, del_key, tag_del)
  obs(f'6e AFTER the restart, deleteUser key D replayed with the pre-restart If-Match tag against the re-created entry: {st_iv} {text_iv[:140]}; entry still there: {exists(u7)}')
  live.check(st_iv == 412 and exists(u7), '[6] a replayed delete with the stale If-Match tag deletes nothing (412)')
  # (v) a delete replay whose target is already gone
  adm('ldapdelete', [u7])
  st_v, _, text_v = call(api, tok, 'DELETE', f'/api/users?dn={urlquote(u7)}', None, del_key, tag_del)
  obs(f'6f AFTER the restart, deleteUser key D replayed when the entry is already gone: {st_v} {text_v[:140]}')
  live.check(st_v == 404 and 'not_found' in text_v, '[6] #385: a delete whose target no longer exists is 404 not_found (permanent), not a retryable 503')
  st_vi, _, text_vi = call(api, tok, 'DELETE', f'/api/users?dn={urlquote(u7)}', None, 'k-' + uuid.uuid4().hex, tag_del)
  obs(f'6g deleteUser, NEW key, stale tag, entry already gone: {st_vi} {text_vi[:140]}')
  live.check(st_vi == 404, '[6] #385: the same with a new key is 404 as well')
  lines = live.audit_lines(uiname)
  live.check(sum('"outcome":"target_not_found"' in l for l in lines[-2:]) == 2 and not any('upstream_error' in l for l in lines[-2:]),
             '[6] #385: both missing-target deletes are audited outcome=target_not_found, not reason=upstream_error')
  obs('6h last machine audit lines: ' + ' ## '.join(l[-330:] for l in lines[-2:]))

  logs = live.all_logs()
  leaked = [v for v in issued + live.secret_values if len(v) >= 8 and v in logs]
  live.check(not leaked, 'no token or secret value appears in any container log')
  print(f'All T-004 measurement checks passed: {live.checks} checks in {live.elapsed():.0f}s.', flush=True)


if __name__ == '__main__':
  try:
    main()
  except BaseException:
    live.dump_logs()
    raise
