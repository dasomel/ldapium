"""Conservative configuration predicates for dedicated identity inspection."""
import hashlib
import re
import shlex
from replication_uri import valid_uri

FIELDS = ('olcSuffix', 'olcRootDN', 'olcAccess', 'olcLimits', 'olcSyncrepl',
          'olcTLSVerifyClient', 'olcAuthzRegexp', 'olcAuthIDRewrite', 'olcAuthzPolicy')


def normal_dn(value):
  # D65: operator base and common config DNs only. Reject escaped/quoted forms
  # rather than guessing at LDAP equivalence; full slapdn normalization is pending.
  text = value.decode('ascii')
  if any(character in text for character in '\\"\n\r\0'):
    raise ValueError('unsupported DN normalization')
  text = re.sub(r'\s*=\s*', '=', re.sub(r'\s*,\s*', ',', text.strip())).lower()
  if any(not re.fullmatch(r'(cn|dc|ou|uid|o|c|l|st)=[^,+;=]+', component)
         for component in text.split(',')):
    raise ValueError('unsupported DN normalization')
  return text


def configuration(rows, base, dedicated=False, password=None):
  wanted = normal_dn(('cn=replicator,' + base).encode())
  suffix = normal_dn(base.encode())
  databases = []
  fingerprints = []
  for row in rows.values():
    for key in ('olcauthzregexp', 'olcauthidrewrite'):
      if row.get(key):
        raise ValueError('delegated authorization configured')
    if any(value.lower() != b'never' for value in row.get('olctlsverifyclient', ())):
      raise ValueError('client certificate authentication configured')
    if any(value.lower() != b'none' for value in row.get('olcauthzpolicy', ())):
      raise ValueError('proxy authorization configured')
    if any(normal_dn(value) == wanted for value in row.get('olcrootdn', ())):
      raise ValueError('reserved identity is rootDN')
    if any(normal_dn(value) == suffix for value in row.get('olcsuffix', ())):
      databases.append(row)
  if len(databases) != 1:
    raise ValueError('exactly one suffix database required')
  row = databases[0]
  acl = row.get('olcaccess', ())
  expected = '{0}to * by dn.exact="%s" ssf=128 read by dn.exact="%s" none by * break' % (wanted, wanted)
  if not acl or acl[0].decode().lower() != expected:
    raise ValueError('identity ACL is not the first exact rule')
  limits = row.get('olclimits', ())
  expected_limit = '{0}dn.exact="%s" size=unlimited time=unlimited' % wanted
  if not limits or limits[0].decode().lower() != expected_limit:
    raise ValueError('identity limit rule is not first')
  if dedicated:
    syncrepl = row.get('olcsyncrepl', ())
    if not syncrepl:
      raise ValueError('dedicated consumers missing')
    for value in syncrepl:
      fields = {}
      for part in shlex.split(value.decode()):
        key, sep, item = part.partition('=')
        if not sep or key in fields:
          raise ValueError('invalid consumer configuration')
        fields[key] = item
      if fields.get('bindmethod') != 'simple':
        raise ValueError('consumer is not a simple bind')
      if normal_dn(fields.get('binddn', '').encode()) != wanted:
        raise ValueError('consumer identity differs')
      if fields.get('tls_reqcert') != 'demand' or not fields.get('tls_cacert'):
        raise ValueError('consumer certificate verification missing')
      if not valid_uri(fields.get('provider', '')):
        raise ValueError('consumer provider is not LDAPS')
      credential = fields.get('credentials', '').encode()
      if (len(credential) < 32 or len(set(credential)) < 10 or
          any(value < 33 or value > 126 or value in (34, 92) for value in credential)):
        raise ValueError('consumer credential hygiene failed')
      fingerprint = hashlib.sha256(credential).digest()
      if password is not None and fingerprint != hashlib.sha256(password).digest():
        raise ValueError('consumer credential does not match current file')
      fingerprints.append(fingerprint)
  return len(fingerprints)
