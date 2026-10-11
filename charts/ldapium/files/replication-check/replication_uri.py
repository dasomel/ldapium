"""Single pinned verified-LDAPS target validation (D60)."""
import ipaddress
import re
from urllib.parse import urlsplit


def valid_uri(value):
  # D60: ldapsearch -H accepts URI lists; reject fallback to plaintext before
  # passing any administrator credential to the LDAP client.
  try:
    if any(character.isspace() for character in value):
      return False
    parsed = urlsplit(value)
    if (not value.startswith('ldaps://') or parsed.scheme != 'ldaps' or
        not parsed.hostname or parsed.username is not None or parsed.password is not None or
        parsed.path or parsed.query or parsed.fragment or parsed.netloc.endswith(':')):
      return False
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
      return False
    host = parsed.hostname
    if ':' in host:
      ipaddress.IPv6Address(host)
      return parsed.netloc.startswith('[')
    if len(host) > 253:
      return False
    return all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
               for label in host.rstrip('.').split('.'))
  except ValueError:
    return False


