#!/usr/bin/env python3.6
# resign.sh: iOS app re-signing exploit
# Copyright (C) 2015-2017 Takahiro and Ken-ya Yoshimura.  All rights reserved.
import glob
import re
import os
import shutil
import subprocess
import sys
import tempfile
import plistlib

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
    b = plistlib.loads(entitlements)
    if '.*' in a['application-identifier']:
      for k in 'aps-environment',:
        print('merged_entitilements: dropping entitlement key "%s" due to we are signing with wildcard provisioning profile' % k, file=sys.stderr)
        del b[k]
    a.update(b)
  return plistlib.dumps(a)

if __name__ == '__main__':
  try:
    target, identity, provisioning_profile = sys.argv[1:]
  except ValueError:
    print('%(arg0)s: usage: %(arg0)s <target> <identity> <provisioning_profile>' % dict(arg0=sys.argv[0]))
    sys.exit(2)
  else:
    target = os.path.realpath(target)
    target_resigned = re.sub(r'(.ipa)$', r'-resigned\g<1>', target, flags=re.IGNORECASE)
    with tempfile.TemporaryDirectory() as t:
      os.chdir(t)
      ShellProcess('unzip -q "%s"' % target, check=True).invoked()
      bundle_path = resolved_path_of('Payload', '*.app')
      shutil.copyfile(provisioning_profile, os.path.join(bundle_path, 'embedded.mobileprovision'))

      with tempfile.NamedTemporaryFile() as tf:
        try:
          ent = open(resolved_path_of(bundle_path, '*.xcent'), 'rb').read()
        except IndexError:
          ent = None
        tf.write(merged_entitlements(open(provisioning_profile, 'rb').read(), ent))
        tf.flush()

        ShellProcess('find -E "%s" -depth -regex "^.*\.(app|framework|dylib|car)" -print0 | xargs -0 codesign -vvvvf -s "%s" --entitlements %s' % (bundle_path, identity, tf.name), check=True).invoked()

      ShellProcess('rm -f "%(target)s" && zip -qr "%(target)s" *' % dict(target=target_resigned), check=True).invoked()
