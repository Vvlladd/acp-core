#!/usr/bin/env python3
import argparse,hashlib,json,os,shutil,subprocess,tempfile
from pathlib import Path
parser=argparse.ArgumentParser(description="Verify a free runtime installer using disposable local fixtures, without model calls.")
parser.add_argument("plugin_repo",type=Path)
parser.add_argument("archive",type=Path)
args=parser.parse_args()
repo=args.plugin_repo.resolve();archive=args.archive.resolve()
release=json.loads((repo/"docs/runtime-release.json").read_text())["releaseId"]
observed=[]
def call(root,asset=archive,ok=True):
 r=subprocess.run(['/bin/bash',str(repo/'scripts/install-runtime.sh'),'--archive',str(asset),'--install-root',str(root)],text=True,capture_output=True)
 assert (r.returncode==0)==ok,(r.returncode,r.stdout,r.stderr)
 return r
with tempfile.TemporaryDirectory(prefix='acp-public-install-',dir='/private/tmp') as folder:
 root=Path(folder);install=root/'with spaces';r=call(install);dest=install/release
 assert (dest/'acp').is_file() and os.access(dest/'acp',os.X_OK)
 assert (dest/'acp-swift-checks').is_file() and os.access(dest/'acp-swift-checks',os.X_OK)
 check=subprocess.run(['shasum','-a','256','-c','SHA256SUMS.txt'],cwd=dest,capture_output=True,text=True)
 assert check.returncode==0
 original=hashlib.sha256((dest/'acp').read_bytes()).hexdigest()
 assert subprocess.check_output([str(dest/'acp'),'--version'],text=True).strip()=='acp 0.1.0'
 assert subprocess.check_output([str(dest/'acp-swift-checks'),'--version'],text=True).strip()=='1.0.0-swiftsyntax603.0.1'
 observed.append('positive: spaces in destination, full checksums, executable modes, CLI/helper version smoke')
 r=call(install,ok=False);assert 'already exists' in r.stderr
 assert hashlib.sha256((dest/'acp').read_bytes()).hexdigest()==original
 observed.append('existing installation refused and preserved')
 corrupt=root/'corrupt.zip';corrupt.write_bytes(archive.read_bytes()+b'corrupt')
 r=call(root/'bad',corrupt,False);assert 'checksum mismatch' in r.stderr and not (root/'bad'/release).exists()
 observed.append('corrupt archive refused before extraction/installation')
 gitroot=root/'checkout';gitroot.mkdir();subprocess.run(['git','init','-q',str(gitroot)],check=True)
 r=call(gitroot/'runtime',ok=False);assert 'outside a Git checkout' in r.stderr
 observed.append('install into Git checkout refused')
 linked=root/'link';linked.mkdir();(linked/release).symlink_to(dest,target_is_directory=True)
 r=call(linked,ok=False);assert 'already exists' in r.stderr
 observed.append('symlink version destination refused')
 qzip=root/'browser.zip';shutil.copyfile(archive,qzip)
 q='0081;67000000;ACPInstallerFixture;'
 subprocess.run(['/usr/bin/xattr','-w','com.apple.quarantine',q,str(qzip)],check=True)
 r=call(root/'browser',qzip)
 for n in ['acp','acp-swift-checks']:
  attr=subprocess.check_output(['/usr/bin/xattr','-p','com.apple.quarantine',str(root/'browser'/release/n)],text=True).strip()
  assert attr==q,(n,attr)
 observed.append('browser quarantine preserved on both installed executables; neither executed')
 print(json.dumps(dict(ok=True,checks=observed),indent=2))
