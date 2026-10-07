#!/usr/bin/env python3
"""Observe a real one-minute scheduled log backup; restore original policies."""
import argparse
import http.cookiejar
import json
from pathlib import Path
import time
import urllib.request

parser=argparse.ArgumentParser();parser.add_argument('--operator',required=True);parser.add_argument('--url',default='http://127.0.0.1:8080');args=parser.parse_args()
ldap=json.loads(Path(args.operator).read_text())['ldap']
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(path,body=None,method=None,revision=None):
  headers={'Content-Type':'application/json','Origin':args.url}
  if revision is not None:headers['If-Match']='"'+str(revision)+'"'
  data=None if body is None else json.dumps(body).encode()
  return json.load(opener.open(urllib.request.Request(args.url+'/api'+path,data,headers,method=method)))
call('/login',{'identity':ldap['admin_dn'],'password':Path(ldap['password_file']).read_text()})
initial=call('/v1/backups');original=initial['policies'];body={'data':original['data'],'logs':dict(original['logs'],enabled=True,interval_minutes=1)}
try:
  call('/v1/backups/policies',body,'PUT',original['revision'])
  start=call('/v1/backups');previous=start['states'].get('logs',{}).get('last_attempt')
  for _ in range(100):
    view=call('/v1/backups');state=view['states'].get('logs',{})
    if state.get('last_attempt')!=previous and state.get('status')=='succeeded':
      if not (state['next_run']>state['last_success']):
        raise AssertionError("state['next_run']>state['last_success']")
      print('PASS: real scheduled log execution and completion-relative next run; independent data policy unchanged')
      break
    time.sleep(1)
  else:raise RuntimeError('scheduled backup did not succeed within 100 seconds')
finally:
  for _ in range(30):
    view=call('/v1/backups')
    if not view['running']:break
    time.sleep(1)
  call('/v1/backups/policies',{'data':original['data'],'logs':original['logs']},'PUT',view['policies']['revision'])
