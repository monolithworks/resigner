#!/usr/bin/env python3
# resign.sh: iOS app re-signing exploit
# Copyright (C) 2015-2017 Takahiro and Ken-ya Yoshimura.  All rights reserved.
import glob
import re
import os
import shutil
import shlex
import subprocess
import sys
import tempfile
import plistlib
import getopt

config = dict()

class ShellProcess:
  def __init__(self, cmdline, cwd=None, check=False):
    self._cmdline = cmdline
    self._cwd = cwd
    self._check = check

  def invoked(self):
    return self._as_str(subprocess.run(self._cmdline, cwd=self._cwd, shell=True, check=self._check, stdout=subprocess.PIPE).stdout)

  def _as_str(self, x):
    if x is not None:
      return x.decode('utf-8')
    else:
      return None

def resolved_path_of(path, mask):
  return glob.glob(os.path.join(path, mask))[0]

def decoded_profile(profile):
    return bytes(re.search(rb'<\?xml version="1.0".*</plist>', profile, flags=re.DOTALL).group(0))

def merged_entitlements(profile, entitlements):
  a = plistlib.loads(decoded_profile(profile))['Entitlements']
  if entitlements is not None:
    b = plistlib.loads(entitlements, fmt=plistlib.FMT_XML)
    for k in 'get-task-allow',:
      if k in b:
        print('merged_entitilements: dropping entitlement key "%s"' % k, file=sys.stderr)
        del b[k]
    if '.*' in a['application-identifier']:
      for k in 'aps-environment',:
        if k in b:
          print('merged_entitilements: dropping entitlement key "%s" due to we are signing with wildcard provisioning profile' % k, file=sys.stderr)
          del b[k]
    a.update(b)
  return plistlib.dumps(a)

def do_resign(identity, provisioning_profile, entitlement, target, output):
  identity = shlex.quote(identity)
  provisioning_profile = shlex.quote(provisioning_profile)
  target = shlex.quote(target)
  output = shlex.quote(output)

  with tempfile.TemporaryDirectory() as t:
    os.chdir(t)
    ShellProcess('unzip -q %s' % target, check=True).invoked()
    bundle_path = resolved_path_of('Payload', '*.app')
    profiled_paths = [l for l in ShellProcess('find "%s" -name "embedded.mobileprovision" -print0' % (bundle_path), check=True).invoked().split('\0') if l]
    for l in profiled_paths:
        shutil.copyfile(provisioning_profile, l)
    if entitlement is not None:
      shutil.copyfile(entitlement, os.path.join(bundle_path, 'ent.xcent'))

    with tempfile.NamedTemporaryFile() as tf:
      try:
        ent = open(resolved_path_of(bundle_path, '*.xcent'), 'rb').read()
      except IndexError:
        ent = None
      tf.write(merged_entitlements(open(provisioning_profile, 'rb').read(), ent))
      tf.flush()

      ShellProcess('find -E "%s" -depth -regex "^.*\.(app|appex|framework|dylib|car)" -print0 | xargs -0 codesign -vvvvf -s "%s" --deep --entitlements %s' % (bundle_path, identity, tf.name), check=True).invoked()

    ShellProcess('rm -f %(target)s && zip -qr %(target)s *' % dict(target=output), check=True).invoked()

if __name__ == '__main__':
  opts, targets = getopt.getopt(sys.argv[1:], 'o:i:p:', ['output=', 'identity=', 'profile=', 'entitlement='])
  for o,a in opts:
    if o in ['-o', '--output']: config['output'] = a
    if o in ['-i', '--identity']: config['identity'] = a
    if o in ['-p', '--profile']: config['provisioning_profile'] = a
    if o in ['-e', '--entitlement']: config['entitlement'] = a

  if len(targets) != 1 or not all([(x in config) for x in ['identity', 'provisioning_profile']]):
    print('%(arg0)s: usage: %(arg0)s [--output <outputfile>] [--entitilement <ent.xcent>] --identity <identity> --profile <provisioning_profile> <target>' % dict(arg0=sys.argv[0]))
    sys.exit(2)

  output = config.get('output')
  if not output:
    output = re.sub(r'(.ipa)$', r'-resigned\g<1>', targets[0], flags=re.IGNORECASE)

  do_resign(
    identity=config['identity'],
    provisioning_profile=os.path.realpath(config['provisioning_profile']),
    entitlement=os.path.realpath(config['entitlement']) if 'entitlement' in config else None,
    target=os.path.realpath(targets[0]),
    output=os.path.realpath(output),
  )
