#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest
import sys

sys.path.insert(0, str(Path(__file__).parents[1] / "lib"))

spec = importlib.util.spec_from_file_location('config', Path(__file__).parents[1] / 'lib/replication_identity_config.py')
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)
BASE = 'dc=example,dc=org'
DN = 'cn=replicator,' + BASE
PW = b'testCredentialOnly-0123456789AbCdEf'


def rows():
  return {b'cn=config': {}, b'olcDatabase={1}mdb,cn=config': {
    'olcsuffix': (BASE.encode(),), 'olcrootdn': (('cn=admin,' + BASE).encode(),),
    'olcaccess': (('{0}to * by dn.exact="%s" ssf=128 read by dn.exact="%s" none by * break' % (DN, DN)).encode(),),
    'olclimits': (('{0}dn.exact="%s" size=unlimited time=unlimited' % DN).encode(),),
    'olcsyncrepl': (('rid=001 bindmethod=simple provider=ldaps://node:636 binddn="%s" credentials="%s" tls_reqcert=demand tls_cacert=/ca' % (DN, PW.decode())).encode(),)
  }}


class ConfigCheck(unittest.TestCase):
  def test_valid(self):
    self.assertEqual(config.configuration(rows(), BASE, True, PW), 1)

  def test_unsafe_global_fields(self):
    for key, value in [('olcauthzregexp', b'map'), ('olcauthidrewrite', b'rewrite'), ('olctlsverifyclient', b'try'), ('olcauthzpolicy', b'to')]:
      data = rows(); data[b'cn=config'][key] = (value,)
      with self.assertRaises(ValueError): config.configuration(data, BASE)

  def test_rootdn_and_order(self):
    for key, value in [('olcrootdn', DN.encode()), ('olcaccess', b'{0}to * by * read'), ('olclimits', b'dn.exact="any" size=unlimited time=unlimited')]:
      data = rows(); data[b'olcDatabase={1}mdb,cn=config'][key] = (value,)
      with self.assertRaises(ValueError): config.configuration(data, BASE)

  def test_fingerprint_gate(self):
    with self.assertRaises(ValueError): config.configuration(rows(), BASE, True, b'other')

  def test_credential_hygiene_and_dn_refusal(self):
    data = rows(); key = b'olcDatabase={1}mdb,cn=config'
    for password in (b'short', b'a' * 43, b'Credential HasSpace-0123456789AbCdEf'):
      data[key]['olcsyncrepl'] = tuple(value.replace(PW, password) for value in rows()[key]['olcsyncrepl'])
      with self.assertRaises(ValueError): config.configuration(data, BASE, True, password)
    for dn in (b'cn=replicator\\2c,dc=example,dc=org', b'2.5.4.3=replicator,dc=example,dc=org'):
      with self.assertRaises(ValueError): config.normal_dn(dn)
    self.assertEqual(config.normal_dn(b' CN = Replicator , DC=Example, DC=Org '), DN)

  def test_unverified_provider(self):
    data = rows(); key = b'olcDatabase={1}mdb,cn=config'
    for old, new in [(b'ldaps://', b'ldap://'), (b'tls_reqcert=demand', b'tls_reqcert=never'), (b'provider=ldaps://node:636', b'provider="ldaps://dead:636 ldap://real:389"')]:
      data[key]['olcsyncrepl'] = tuple(value.replace(old, new) for value in rows()[key]['olcsyncrepl'])
      with self.assertRaises(ValueError): config.configuration(data, BASE, True, PW)


if __name__ == '__main__': unittest.main()
