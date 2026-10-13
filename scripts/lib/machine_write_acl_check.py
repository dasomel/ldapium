#!/usr/bin/env python3
"""Operator check of the machine WRITE ACL order (#285, T-023, REQ-011).

Reads the main database's olcAccess (never writes) and verifies the defined order of
docs/machine-write-account.md section 2. See scripts/check-machine-write-acl.sh for usage.

Decisions (D-ids local to this tool):
  D1 the expected rules are embedded here (an operator may have no fixture directory);
     scripts/test/test_machine_write_acl_check.py compares them with the fixtures, so the
     two cannot drift.
  D2 a rule is compared structurally (selector, attribute SET, ordered by-clauses), not as
     text: slapd's stored spelling may differ in case and spacing, never in meaning.
  D3 never a false pass: unreadable/empty/unparseable input, a rule the static evaluator
     cannot decide, or a count that is not exactly the fragment size is a failure.
"""
import argparse
import base64
import re
import subprocess
import sys

OK, FAILED, USAGE, UNREADABLE = 0, 1, 2, 3

# The LDIF rule text of docs/machine-ldap-account.md 5 and docs/machine-write-account.md 4.2/4.3
# (the non-comment fixture text, rules only). Tokens are substituted like the guide's sed.
M_RULES = '''olcAccess: {0}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN
  by dn.exact="@MACHINE_DN@" none
  by * break
olcAccess: {1}to dn.subtree="@ALLOWED_DN@"
  by dn.exact="@MACHINE_DN@" read
  by * break
olcAccess: {2}to *
  by dn.exact="@MACHINE_DN@" none
  by * break
'''
DATA_RULES = '''olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WHO@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WHO@" none
  by * break
olcAccess: {2}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdAccountLockedTime,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WHO@" none
  by * break
olcAccess: {3}to dn.subtree="@WRITE_DN@" attrs=entry,children
  by dn.exact="@WHO@" write
  by * break
olcAccess: {4}to dn.subtree="@WRITE_DN@" attrs=objectClass
  by dn.exact="@WHO@" add
  by * break
olcAccess: {5}to dn.subtree="@WRITE_DN@" filter=(objectClass=groupOfNames) attrs=description
  by dn.exact="@WHO@" write
  by * break
olcAccess: {6}to dn.subtree="@WRITE_DN@" attrs=uid,cn,sn,givenName,mail,departmentNumber,o,ou,member
  by dn.exact="@WHO@" write
  by * break
olcAccess: {7}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WHO@" read
  by * break
olcAccess: {8}to *
  by dn.exact="@WHO@" none
  by * break
'''
LOCK_RULES = '''olcAccess: {0}to dn.subtree="@SYSTEM_DN@"
  by dn.exact="@WHO@" none
  by * break
olcAccess: {1}to dn.exact="@REPL_DN@"
  by dn.exact="@WHO@" none
  by * break
olcAccess: {2}to attrs=userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN,memberOf,pwdChangedTime,pwdFailureTime,pwdGraceUseTime,pwdReset,pwdPolicySubentry,pwdStartTime,pwdEndTime,pwdLastSuccess
  by dn.exact="@WHO@" none
  by * break
olcAccess: {3}to dn.subtree="@WRITE_DN@" attrs=pwdAccountLockedTime
  by dn.exact="@WHO@" add
  by * break
olcAccess: {4}to dn.subtree="@WRITE_DN@"
  by dn.exact="@WHO@" read
  by * break
olcAccess: {5}to *
  by dn.exact="@WHO@" none
  by * break
'''
# What each position of a fragment is for, for the failure message.
DATA_LABELS = ['SYSTEM_DN none backstop', 'replication identity entry none backstop',
               'secret/pwd*/memberOf attributes none', 'entry+children write inside WRITE_DN',
               'objectClass add inside WRITE_DN', 'group description write inside WRITE_DN (filter)',
               'closed attribute list write inside WRITE_DN',
               'rest of WRITE_DN read', 'everything else none']
LOCK_LABELS = ['SYSTEM_DN none backstop', 'replication identity entry none backstop',
               'secret/pwd*/memberOf attributes none', 'pwdAccountLockedTime add inside WRITE_DN',
               'rest of WRITE_DN read', 'everything else none']
M_LABELS = ['M secret attributes none', 'M read under ALLOWED_DN', 'M everything else none']

# Attributes no W identity may read or write (the secrets rule of both fragments), plus the
# lock attribute that only W_lock owns.
SECRET_ATTRS = ['userPassword', 'shadowLastChange', 'pwdHistory', 'pKCS8PrivateKey', 'userPKCS12',
                'oathSecret', 'oathEncKey', 'oathTokenPIN', 'memberOf', 'pwdChangedTime',
                'pwdFailureTime', 'pwdGraceUseTime', 'pwdReset', 'pwdPolicySubentry',
                'pwdStartTime', 'pwdEndTime', 'pwdLastSuccess']
LOCK_ATTR = 'pwdAccountLockedTime'

ACCESS_RANK = {'none': 0, 'disclose': 1, 'auth': 2, 'compare': 3, 'search': 4, 'read': 5,
               'write': 6, 'add': 6, 'delete': 6, 'manage': 7}
CONTROLS = ('stop', 'continue', 'break')
WRITE_LEVEL = 6
TOKEN = re.compile(r'(?:[^\s"]|"[^"]*")+')


class Unreadable(Exception):
  pass


def dn_norm(dn):
  # Light normalization for comparing DNs slapd already stored normalized.
  return re.sub(r'\s*([,=])\s*', r'\1', dn.strip().strip('"')).lower()


def dn_under(dn, base):
  return dn == base or dn.endswith(',' + base)


class Rule:
  def __init__(self, index, text):
    self.index = index
    self.text = text
    self.parse_error = None
    self.dn_sel = None      # ('exact'|'subtree'|..., normalized dn) or None = every entry
    self.attrs = None       # frozenset(lowercase) or None = every attribute
    self.filter = None      # lowercase filter= text (compared, never evaluated: opaque)
    self.opaque = False     # selector the static evaluator cannot decide
    self.by = []            # (who, modifiers frozenset, access, control)
    self._parse()

  def _parse(self):
    if '\\"' in self.text:
      self.parse_error = 'escaped quote in rule'
      return
    tokens = TOKEN.findall(self.text)
    if not tokens or tokens[0] != 'to':
      self.parse_error = 'rule does not start with "to"'
      return
    i = 1
    sel = []
    while i < len(tokens) and tokens[i] != 'by':
      sel.append(tokens[i])
      i += 1
    if not sel:
      self.parse_error = 'rule has no selector'
      return
    for t in sel:
      low = t.lower()
      m = re.match(r'dn\.(exact|base|subtree|sub|children|one)=(.*)$', low)
      if t == '*':
        continue
      if m and self.dn_sel is None:
        self.dn_sel = (m.group(1), dn_norm(t.split('=', 1)[1]))
      elif low.startswith('filter=') and self.filter is None:
        self.filter = low[len('filter='):]
        self.opaque = True
      elif low.startswith('attrs='):
        names = [a for a in low[len('attrs='):].split(',') if a]
        if not names or any(not re.match(r'^[a-z0-9-]+$', a) for a in names):
          self.opaque = True
        else:
          self.attrs = frozenset(names)
      else:
        self.opaque = True
    while i < len(tokens):
      if tokens[i] != 'by' or i + 1 >= len(tokens):
        self.parse_error = 'malformed by-clause'
        return
      who = tokens[i + 1]
      i += 2
      mods, access, control = set(), None, None
      while i < len(tokens) and tokens[i] != 'by':
        t = tokens[i].lower()
        if t in ACCESS_RANK or re.match(r'^[=+-][a-z0-9]+$', t):
          if access is not None:
            self.parse_error = 'two access levels in one by-clause'
            return
          access = t
        elif t in CONTROLS:
          if control is not None:
            self.parse_error = 'two controls in one by-clause'
            return
          control = t
        else:
          mods.add(t)
        i += 1
      self.by.append((self._who(who), frozenset(mods), access, control))
    if not self.by:
      self.parse_error = 'rule has no by-clause'

  @staticmethod
  def _who(token):
    low = token.lower()
    m = re.match(r'dn\.(exact|base|subtree|sub|children|one)=(.*)$', low)
    if m:
      return (m.group(1), dn_norm(token.split('=', 1)[1]))
    return (low, None)

  def sig(self):
    return (self.dn_sel, self.attrs, self.filter, self.opaque, tuple(self.by))

  def names(self, dn):
    # True when a by-clause names dn as its identity.
    return any(w[0] in ('exact', 'base') and w[1] == dn for w, _, _, _ in self.by)

  def mentions(self, dn):
    return self.names(dn) or (self.dn_sel is not None and self.dn_sel[1] == dn)


def unfold(text):
  return re.sub(r'\r?\n[ \t]', '', text)


def parse_rule_lines(lines):
  # lines: raw "olcAccess: {n}to ..." values -> [Rule], strictly sequential.
  rules = []
  for expect, value in enumerate(lines):
    m = re.match(r'^\{(\d+)\}(.*)$', value.strip(), re.S)
    if not m:
      raise Unreadable('olcAccess value without a {n} index: %r' % value[:80])
    if int(m.group(1)) != expect:
      raise Unreadable('olcAccess indices are not sequential: expected {%d}, got {%s}' % (expect, m.group(1)))
    rules.append(Rule(expect, ' '.join(m.group(2).split())))
  return rules


def main_db_rules(dump, main_db_dn):
  text = unfold(dump)
  entries = [b for b in re.split(r'\r?\n\s*\r?\n', text) if b.strip()]
  want = main_db_dn.lower()
  chosen = []
  has_dn = False
  for block in entries:
    dn = None
    vals = []
    for line in block.splitlines():
      if line.startswith('#'):
        continue
      if line.lower().startswith('dn:: '):
        dn = base64.b64decode(line[5:].strip()).decode('utf-8', 'replace')
      elif line.lower().startswith('dn:'):
        dn = line[3:].strip()
      elif line.startswith('olcAccess:: '):
        vals.append(base64.b64decode(line[len('olcAccess:: '):].strip()).decode('utf-8', 'replace'))
      elif line.startswith('olcAccess:'):
        vals.append(line[len('olcAccess:'):].strip())
    if dn is not None:
      has_dn = True
      if dn.strip().lower() == want:
        chosen.append(vals)
    elif not has_dn and vals:
      chosen.append(vals)
  if has_dn and not chosen:
    raise Unreadable('the dump has no entry %s (wrong database or truncated slapcat output)' % main_db_dn)
  if len(chosen) != 1:
    raise Unreadable('expected exactly one main database olcAccess list, found %d' % len(chosen))
  if not chosen[0]:
    raise Unreadable('the main database entry carries no olcAccess values')
  return parse_rule_lines(chosen[0])


def expected_rules(template, subst):
  out = []
  for n, line in enumerate(re.split(r'(?m)^olcAccess: ', template)[1:]):
    text = unfold(line)
    for k, v in subst.items():
      text = text.replace(k, v)
    m = re.match(r'^\{\d+\}(.*)$', ' '.join(text.split()), re.S)
    out.append(Rule(n, m.group(1)))
  return out


class Report:
  def __init__(self):
    self.checks = 0
    self.failed = 0

  def ok(self, msg):
    self.checks += 1
    print('PASS: ' + msg)

  def bad(self, msg):
    self.checks += 1
    self.failed += 1
    print('FAIL: ' + msg, file=sys.stderr)

  def check(self, cond, msg_ok, msg_bad):
    if cond:
      self.ok(msg_ok)
    else:
      self.bad(msg_bad)
    return cond


def access_of(clause_access):
  # Rank of a stored access spelling; None = cannot be ranked (=rwx style).
  if clause_access is None:
    return 0
  return ACCESS_RANK.get(clause_access)


def rule_applies(rule, target, attr):
  # True / False / None (cannot decide statically).
  if rule.dn_sel is not None:
    style, base = rule.dn_sel
    if style in ('exact', 'base'):
      hit = target == base
    elif style in ('subtree', 'sub'):
      hit = dn_under(target, base)
    elif style == 'children':
      hit = target != base and dn_under(target, base)
    else:  # one
      hit = target.split(',', 1)[-1] == base and target != base
    if not hit:
      return False
  if rule.attrs is not None and attr.lower() not in rule.attrs:
    return False
  if rule.opaque:
    return None
  return True


def clause_applies(who, identity, target):
  kind, dn = who
  if kind == '*' or kind == 'users':
    return True
  if kind == 'anonymous':
    return False
  if kind in ('exact', 'base'):
    return dn == identity
  if kind in ('subtree', 'sub'):
    return dn_under(identity, dn)
  if kind == 'children':
    return identity != dn and dn_under(identity, dn)
  if kind == 'one':
    return identity != dn and identity.split(',', 1)[-1] == dn
  if kind == 'self':
    return identity == target
  return None


def effective_access(rules, identity, target, attr):
  # Rank of the access `identity` gets on `attr` of `target` under slapd's first-match
  # rules with by-clause controls, or an explanation string when it cannot be decided.
  # A matching clause that grants something but breaks on counts as granting it (fail safe).
  best = 0
  for rule in rules:
    if rule.parse_error:
      return 'rule {%d} is not parseable: %s' % (rule.index, rule.parse_error)
    applies = rule_applies(rule, target, attr)
    if applies is False:
      continue
    for who, _mods, access, control in rule.by:
      hit = clause_applies(who, identity, target)
      if hit is False:
        continue
      rank = access_of(access)
      if hit is None or applies is None or rank is None:
        return 'rule {%d} cannot be evaluated statically (%s)' % (rule.index, rule.text[:90])
      best = max(best, rank)
      if control in (None, 'stop'):
        return best
      if control == 'break':
        break
  return best


def check(rules, a, rep):
  repl = a.repl_dn
  # --- the dump itself -----------------------------------------------------------------
  bad_rules = [r for r in rules if r.parse_error]
  rep.check(not bad_rules, '%d olcAccess rules parsed' % len(rules),
            'unparseable rule(s): ' + '; '.join('{%d} %s' % (r.index, r.parse_error) for r in bad_rules))

  # --- (1) replication identity rule first, when present --------------------------------
  repl_rule_text = 'to * by dn.exact="%s" ssf=128 read by dn.exact="%s" none by * break' % (repl, repl)
  repl_expected = Rule(0, repl_rule_text)
  holders = [r for r in rules if r.dn_sel is None and r.names(repl)]
  if holders:
    rep.check(len(holders) == 1, 'replication identity rule present once',
              'duplicate: %d rules grant the replication identity access (%s)' % (len(holders), ','.join('{%d}' % r.index for r in holders)))
    rep.check(holders[0].index == 0 and holders[0].sig() == repl_expected.sig(),
              'replication identity rule is {0} and is the prepare contract',
              'replication identity rule must be {0} with the exact prepare text; found at {%d}: %s' % (holders[0].index, holders[0].text[:110]))
  else:
    rep.check(a.replication_identity != 'required', 'no replication identity rule (replication-identity=auto)',
              'replication identity rule missing but --replication-identity required: the prepare/dedicated contract needs it at {0}')
  pos = 1 if holders and holders[0].index == 0 else 0

  # --- (2) M read rules directly after ----------------------------------------------------
  m_exp = expected_rules(M_RULES, {'@MACHINE_DN@': a.machine_dn, '@ALLOWED_DN@': a.allowed_dn})
  m_have = [r for r in rules if r.names(a.machine_dn)]
  rep.check(len(m_have) == len(m_exp), 'M has exactly %d rules' % len(m_exp),
            'M rules: %d found, expected %d%s' % (len(m_have), len(m_exp), ' (duplicate: a fragment applied twice?)' if len(m_have) > len(m_exp) else ' (missing rule)'))
  for k, exp in enumerate(m_exp):
    got = rules[pos + k] if pos + k < len(rules) else None
    rep.check(got is not None and got.sig() == exp.sig(), 'M rule {%d}: %s' % (pos + k, M_LABELS[k]),
              'M rule expected at {%d} (%s) but %s' % (pos + k, M_LABELS[k], 'the list ends' if got is None else 'found {%d}: %s' % (got.index, got.text[:110])))
  pos += len(m_exp)

  # --- (2)(3)(6) W fragments: complete, in order, tiled right after M, no duplicates ----
  frags = []
  if a.wdata_dn:
    frags.append(('W_data', a.wdata_dn, DATA_RULES, DATA_LABELS))
  if a.wlock_dn:
    frags.append(('W_lock', a.wlock_dn, LOCK_RULES, LOCK_LABELS))
  located = []
  for name, dn, tpl, labels in frags:
    exp = expected_rules(tpl, {'@WHO@': dn, '@SYSTEM_DN@': a.system_dn, '@REPL_DN@': repl, '@WRITE_DN@': a.write_dn})
    have = [r for r in rules if r.names(dn)]
    if len(have) > len(exp):
      rep.bad('duplicate: %d rules name %s, expected exactly %d (the fragment was applied twice; roll back first, guide section 7)' % (len(have), name, len(exp)))
    elif len(have) < len(exp):
      rep.bad('%s rules incomplete: %d found, expected %d' % (name, len(have), len(exp)))
    else:
      rep.ok('%s has exactly %d rules' % (name, len(exp)))
    first = have[0].index if have else None
    located.append((first if first is not None else 10 ** 9, name, dn, exp, labels, have))
  located.sort(key=lambda t: t[0])
  for first, name, dn, exp, labels, have in located:
    start = pos
    contiguous = bool(have) and [r.index for r in have[:len(exp)]] == list(range(have[0].index, have[0].index + min(len(have), len(exp))))
    rep.check(have and have[0].index == start and contiguous,
              '%s starts at {%d} directly after the previous fragment, contiguous' % (name, start),
              '%s rules must be contiguous starting at {%d} (after replication, M, earlier W); found at %s' % (
                  name, start, ','.join('{%d}' % r.index for r in have) or 'nowhere'))
    for k, e in enumerate(exp):
      got = rules[start + k] if start + k < len(rules) else None
      rep.check(got is not None and got.sig() == e.sig(), '%s rule {%d}: %s' % (name, start + k, labels[k]),
                '%s rule {%d} (%s) is wrong or missing: %s' % (name, start + k, labels[k],
                  'the list ends' if got is None else 'found %s' % got.text[:140]))
    pos = start + len(exp)
  # Nothing after the fragments may still name a W identity (also catches a fragment
  # applied after the image's allow rules).
  for name, dn, _t, _l in frags:
    late = [r for r in rules[pos:] if r.names(dn)]
    rep.check(not late, 'no %s rule after the W block (all before the image rules)' % name,
              '%s rules found after the defined block, i.e. behind the image rules: %s' % (name, ','.join('{%d}' % r.index for r in late)))
  rep.check(pos < len(rules), 'the image\'s own rules follow the W block',
            'no rules follow the W block: the image rules (by self write / by users read ...) are missing')

  # --- (4) no write ACL for W_cred ---------------------------------------------------------
  known = {a.machine_dn, repl, a.wdata_dn, a.wlock_dn} - {None}
  for cred in a.wcred_dn:
    hit = [r for r in rules if r.mentions(cred)]
    rep.check(not hit, 'no rule names W_cred %s' % cred,
              'W_cred %s is named by rule(s) %s: W_cred has no ACL fragment (guide section 8)' % (cred, ','.join('{%d}' % r.index for r in hit)))
  stray = []
  for r in rules:
    for (kind, dn), _m, acc, _c in r.by:
      rank = access_of(acc)
      if kind in ('exact', 'base') and dn and dn_under(dn, a.system_dn) and dn not in known and dn not in map(dn_norm, a.wcred_dn):
        if rank is None or rank >= WRITE_LEVEL:
          stray.append('{%d} %s' % (r.index, dn))
  rep.check(not stray, 'no other identity under SYSTEM_DN holds write access',
            'unknown identity under SYSTEM_DN holds write access (a W_cred rule?): ' + '; '.join(stray))

  # --- (3)(5) static reach of every W identity -------------------------------------------
  probe = 'uid=probe,' + a.write_dn
  protected = [('M', a.machine_dn), ('replication identity', repl)] + [('admin', d) for d in a.admin_dn] + \
      [('W_data', a.wdata_dn) if a.wdata_dn else None, ('W_lock', a.wlock_dn) if a.wlock_dn else None]
  protected = [p for p in protected if p] + [('protected', d) for d in a.protected_dn]
  for name, dn, _t, _l in frags:
    for label, target in protected:
      if target == dn and name == label:
        label = 'its own entry'
      for attr in ('entry', 'children'):
        res = effective_access(rules, dn, target, attr)
        rep.check(res == 0, '%s has no %s access to %s (%s)' % (name, attr, label, target),
                  '%s can reach %s %s (%s)%s' % (name, label, attr, target,
                    ': ' + res if isinstance(res, str) else ' with access rank %d: the entry is inside WRITE_DN and no earlier rule denies it (guide section 3: move it under SYSTEM_DN)' % res))
    secrets = SECRET_ATTRS + ([LOCK_ATTR] if name == 'W_data' else [])
    bad = []
    for attr in secrets:
      res = effective_access(rules, dn, probe, attr)
      if res != 0:
        bad.append('%s=%s' % (attr, res if isinstance(res, str) else res))
    rep.check(not bad, '%s secret attributes (userPassword, pwd*, memberOf ...) are none' % name,
              '%s can touch secret attributes: %s' % (name, '; '.join(bad)))
    if name == 'W_lock':
      res = effective_access(rules, dn, probe, LOCK_ATTR)
      rep.check(res == WRITE_LEVEL, 'W_lock can add %s inside WRITE_DN' % LOCK_ATTR,
                'W_lock does not get add on %s (result %s)' % (LOCK_ATTR, res))
    outside_dn = 'ou=outside-x,' + a.root_dn
    if not dn_under(outside_dn, a.write_dn):
      res = effective_access(rules, dn, outside_dn, 'entry')
      rep.check(res == 0, '%s has no access outside WRITE_DN' % name,
                '%s reaches an entry outside WRITE_DN: %s' % (name, res))


def run_text(cmd, what):
  try:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
  except (OSError, subprocess.TimeoutExpired) as e:
    raise Unreadable('cannot run %s: %s' % (what, e))
  if p.returncode != 0:
    raise Unreadable('%s failed (rc %d): %s' % (what, p.returncode, p.stderr.strip()[-300:]))
  return p.stdout


def read_dump(a):
  slapcat = ['slapcat', '-n', '0', '-F', a.config_dir, '-o', 'ldif-wrap=no']
  if a.input:
    try:
      if a.input == '-':
        return sys.stdin.read()
      with open(a.input, encoding='utf-8') as f:
        return f.read()
    except OSError as e:
      raise Unreadable('cannot read %s: %s' % (a.input, e))
  if a.container:
    return run_text(['docker', 'exec', a.container] + slapcat, 'docker exec slapcat')
  if a.kube_pod:
    cmd = ['kubectl'] + (['-n', a.namespace] if a.namespace else []) + ['exec', a.kube_pod] + \
        (['-c', a.kube_container] if a.kube_container else []) + ['--'] + slapcat
    return run_text(cmd, 'kubectl exec slapcat')
  return run_text(slapcat, 'slapcat')


def parser():
  p = argparse.ArgumentParser(description='Check the machine WRITE ACL order in the main database olcAccess (read only).')
  g = p.add_argument_group('source (default: local slapcat -n 0 -F CONFIG_DIR)')
  g.add_argument('--input', metavar='FILE', help='slapcat/ldapsearch LDIF containing the main database olcAccess; - = stdin')
  g.add_argument('--container', metavar='NAME', help='docker exec NAME slapcat -n 0')
  g.add_argument('--kube-pod', metavar='POD', help='kubectl exec POD -- slapcat -n 0')
  g.add_argument('--namespace', '-n')
  g.add_argument('--kube-container', metavar='C')
  g.add_argument('--config-dir', default='/etc/openldap/slapd.d')
  g.add_argument('--main-db-dn', default='olcDatabase={1}mdb,cn=config')
  d = p.add_argument_group('deployment (the guide section 3 variables)')
  d.add_argument('--root-dn', required=True)
  d.add_argument('--machine-dn', required=True, help='M, the read-only machine identity')
  d.add_argument('--system-dn', required=True, help='SYSTEM_DN container of M and W_*')
  d.add_argument('--write-dn', required=True, help='WRITE_DN, union of the client caps')
  d.add_argument('--wdata-dn')
  d.add_argument('--wlock-dn')
  d.add_argument('--wcred-dn', action='append', default=[], help='W_cred DN: no rule may name it (repeatable)')
  d.add_argument('--allowed-dn', help='M read base (default --root-dn)')
  d.add_argument('--repl-dn', help='default cn=replicator,<root-dn>')
  d.add_argument('--admin-dn', action='append', default=[], help='admin entry W must not reach (default cn=admin,<root-dn>; repeatable)')
  d.add_argument('--protected-dn', action='append', default=[], help='further entry W must not reach (repeatable)')
  d.add_argument('--replication-identity', choices=('auto', 'required'), default='auto',
                 help='required: fail when the prepare/dedicated rule is not at {0} (default auto: checked only when present)')
  return p


def main(argv):
  a = parser().parse_args(argv)
  if not (a.wdata_dn or a.wlock_dn):
    print('machine-write-acl-check: give --wdata-dn and/or --wlock-dn', file=sys.stderr)
    print('RESULT status=error reason=usage')
    return USAGE
  dns = [a.root_dn, a.machine_dn, a.system_dn, a.write_dn, a.wdata_dn, a.wlock_dn, a.allowed_dn, a.repl_dn] + a.wcred_dn
  if any(d and ('"' in d or '\n' in d) for d in dns):
    print('machine-write-acl-check: a DN contains a character this tool refuses', file=sys.stderr)
    print('RESULT status=error reason=usage')
    return USAGE
  a.root_dn = dn_norm(a.root_dn)
  a.machine_dn = dn_norm(a.machine_dn)
  a.system_dn = dn_norm(a.system_dn)
  a.write_dn = dn_norm(a.write_dn)
  a.wdata_dn = dn_norm(a.wdata_dn) if a.wdata_dn else None
  a.wlock_dn = dn_norm(a.wlock_dn) if a.wlock_dn else None
  a.allowed_dn = dn_norm(a.allowed_dn) if a.allowed_dn else a.root_dn
  a.repl_dn = dn_norm(a.repl_dn) if a.repl_dn else 'cn=replicator,' + a.root_dn
  a.admin_dn = [dn_norm(d) for d in a.admin_dn] or ['cn=admin,' + a.root_dn]
  a.protected_dn = [dn_norm(d) for d in a.protected_dn]
  a.wcred_dn = [dn_norm(d) for d in a.wcred_dn]
  ids = [x for x in (a.machine_dn, a.wdata_dn, a.wlock_dn, a.repl_dn) + tuple(a.wcred_dn) if x]
  if len(set(ids)) != len(ids):
    print('machine-write-acl-check: M, W_data, W_lock, W_cred and the replication identity must be different DNs', file=sys.stderr)
    print('RESULT status=error reason=usage')
    return USAGE
  try:
    rules = main_db_rules(read_dump(a), a.main_db_dn)
  except Unreadable as e:
    print('machine-write-acl-check: cannot verify, treating as FAILED: %s' % e, file=sys.stderr)
    print('RESULT status=error reason=unreadable')
    return UNREADABLE
  rep = Report()
  try:
    check(rules, a, rep)
  except Exception as e:  # a crash must never read as a verdict
    print('machine-write-acl-check: internal error, treating as FAILED: %r' % e, file=sys.stderr)
    print('RESULT status=error reason=internal')
    return UNREADABLE
  status = 'pass' if rep.failed == 0 else 'fail'
  print('RESULT status=%s checks=%d failed=%d rules=%d' % (status, rep.checks, rep.failed, len(rules)))
  if rep.failed:
    print('machine-write-acl-check: %d check(s) failed; do NOT enable machine writes on this node' % rep.failed, file=sys.stderr)
    return FAILED
  return OK


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
