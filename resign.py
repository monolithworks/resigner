"""resigner is an iOS app re-signer."""
from __future__ import annotations
from typing import TYPE_CHECKING
import glob
import re
import os
import shutil
import shlex
import subprocess
import sys
import tempfile
import plistlib

if TYPE_CHECKING:
  from typing import Optional

__version__ = '1.0.0'

class ShellProcess:
  def __init__(self, cmdline: str, cwd: Optional[str] = None, check: bool = False) -> None:
    self._cmdline = cmdline
    self._cwd = cwd
    self._check = check

  def invoked(self) -> str:
    return self._as_str(subprocess.run(self._cmdline, cwd=self._cwd, shell=True, check=self._check, stdout=subprocess.PIPE).stdout)

  def _as_str(self, x: bytes) -> str:
    return x.decode('utf-8')

def resolved_path_of(path: str, mask: str) -> str:
  return glob.glob(os.path.join(path, mask))[0]

def decoded_profile(profile: bytes) -> bytes:
  m = re.search(rb'<\?xml version="1.0".*</plist>', profile, flags=re.DOTALL)
  assert m
  return bytes(m.group(0))

def merged_entitlements(profile: bytes, entitlements: Optional[bytes]) -> bytes:
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

def do_resign(identity: str, provisioning_profile: str, entitlement: Optional[str], target: str, output: str) -> None:
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

      ShellProcess(r'find -E "%s" -depth -regex "^.*\.(app|appex|framework|dylib|car)" -print0 | xargs -0 codesign -vvvvf -s "%s" --deep --entitlements %s' % (bundle_path, identity, tf.name), check=True).invoked()

    ShellProcess('rm -f %(target)s && zip -qr %(target)s *' % dict(target=output), check=True).invoked()

def entry() -> None:
  from argparse import ArgumentParser

  parser = ArgumentParser(description='iOS app resigner.')
  parser.add_argument('target')
  parser.add_argument('-o', '--output', help='Output filename')
  parser.add_argument('-i', '--identity', required=True, help='Identity to use, typically fingerprint of the certificate')
  parser.add_argument('-p', '--profile', required=True, help='Provisioning profile file to use')
  parser.add_argument('-e', '--entitlement', help='Entitlement to include, if any')
  args = parser.parse_args()

  if not args.output:
    args.output = re.sub(r'(.ipa)$', r'-resigned\g<1>', args.target, flags=re.IGNORECASE)

  do_resign(
    identity=args.identity,
    provisioning_profile=os.path.realpath(args.profile),
    entitlement=os.path.realpath(args.entitlement) if args.entitlement else None,
    target=os.path.realpath(args.target),
    output=os.path.realpath(args.output),
  )
