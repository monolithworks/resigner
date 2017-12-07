# resign.sh: iOS app re-signing exploit
# Copyright (C) 2015-2017 Takahiro and Ken-ya Yoshimura.  All rights reserved.
import glob
import re
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

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

def bundle_id_of_profile(profile):
  with open(profile, 'rb') as f:
    return re.search(b'<string>([0-9A-Z]+)\..*?</string>', f.read(), flags=re.DOTALL).group(1)

def bundle_namespace_of_profile(profile):
  with open(profile, 'rb') as f:
    return re.search(b'<string>[0-9A-Z]+\.([0-9A-Za-z].*?)</string>', f.read(), flags=re.DOTALL).group(1)
      
if __name__ == '__main__':
  try:
    target, identity, provisioning_profile = sys.argv[1:]
  except ValueError:
    print('%(arg0)s: usage: %(arg0)s <target> <identity> <provisioning_profile>' % dict(arg0=sys.argv[0]))
    sys.exit(2)
  else:
    target = os.path.realpath(target)
    target_resigned = re.sub(r'(.ipa)$', r'-resigned\g<1>', target, flags=re.IGNORECASE)
    bundle_id = bundle_id_of_profile(provisioning_profile)
    with tempfile.TemporaryDirectory() as t:
      os.chdir(t)
      ShellProcess('unzip -q "%s"' % target, check=True).invoked()
      bundle_path = resolved_path_of('Payload', '*.app')
      bundle_namespace = b'xobai8na.%s' % bundle_namespace_of_profile(os.path.join(bundle_path, 'embedded.mobileprovision'))      
      entitlements = resolved_path_of(bundle_path, '*.xcent')
      shutil.copyfile(provisioning_profile, os.path.join(bundle_path, 'embedded.mobileprovision'))

      try:
        with open(entitlements, 'rb') as f:          
          if b'application-identifier' in f.read():
            has_valid_entitlements = True
          else:
            has_valid_entitilements = False
      except OSError:
        has_valid_entitilements = False

      if not has_valid_entitilements:
        if os.path.exists(entitlements):
          os.unlink(entitlements)
          
        entitlements = os.path.join(bundle_path, 'generated.xcent')
        with open(entitlements, 'wb') as f:
          f.write(b'''\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	  <string>%(id)s.%(ns)s</string>
	<key>get-task-allow</key>
	<true/>
	<key>keychain-access-groups</key>
	<array>
		<string>%(id)s.%(ns)s</string>
	</array>
</dict>
</plist>
''' % {b'id':bundle_id, b'ns':bundle_namespace})
        
      for fn in (x for x in ['META-INF', 'iTunes'] if os.path.exists(x)):
        os.unlink(fn)

      ShellProcess('plutil -convert xml1 "%s"' % os.path.join(bundle_path, 'Info.plist')).invoked()

      with tempfile.TemporaryFile() as f:
        with open(entitlements, 'rb') as s:
          f.write(re.sub(rb'(<string>)[0-9A-Z]+?(\.)', rb'\g<1>%s\g<2>' % bundle_id, s.read(), flags=re.DOTALL))
          f.flush()
          f.seek(0)
        with open(entitlements, 'wb') as d:
          d.write(f.read())
          d.flush()

      ShellProcess('find -E "%s" -depth -regex "^.*\.(app|framework|dylib)" -print0 | xargs -0 codesign --verbose --force -s "%s" --entitlements %s' % (bundle_path, identity, entitlements)).invoked()
      ShellProcess('rm -f "%s"' % target_resigned).invoked()
      ShellProcess('zip -qr "%s" Payload' % target_resigned).invoked()

