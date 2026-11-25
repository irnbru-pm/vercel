"""Package and test the reviewed Isotope checkout on Apple Silicon."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

src = Path(__file__).resolve().parent
tree = src.parent
output = Path(sys.argv[1]).resolve()
version = sys.argv[2]
output.parent.mkdir(parents=True, exist_ok=True)
identity = 'Developer ID Application: Max Howell (ZU76A67LGU)'

def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)

def sign(path, identifier=None):
    options = ['--identifier', identifier] if identifier else []
    if identifier:
        entitlements = output.parent / ('.' + tool + '-worker-entitlements.plist')
        entitlements.write_bytes(plistlib.dumps({'com.apple.security.cs.allow-jit': True}))
        options += ['--entitlements', entitlements]
    run('codesign', '-f', '-s', identity, '--options', 'runtime', '--timestamp', *options, path)

tool = 'vercel'
name = tool.capitalize()
with tempfile.TemporaryDirectory(dir=output.parent) as temp:
    stage = Path(temp)
    bundle = stage / (name + '.app')
    contents = bundle / 'Contents'
    mac, helpers, resources = (contents / folder for folder in ('MacOS','Helpers','Resources'))
    for directory in (mac,helpers,resources):
        directory.mkdir(parents=True)
    worker = helpers / 'worker'
    run('pnpm', 'install', '--frozen-lockfile', cwd=tree)
    run('pnpm', '--filter', 'vercel...', 'build', cwd=tree)
    cli = tree/'packages/cli'
    run('node', 'scripts/build-binary.mjs', '--stage-only', cwd=cli)
    shutil.copytree(cli/'.pkg-staging', resources/'vercel')
    archive = stage/'node.tar.gz'
    run('curl', '--fail', '--location', '--silent', '--show-error', '--output', archive,
        'https://nodejs.org/dist/v22.22.0/node-v22.22.0-darwin-arm64.tar.gz')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != '5ed4db0fcf1eaf84d91ad12462631d73bf4576c1377e192d222e48026a902640':
        raise ValueError('Unexpected Node runtime archive')
    with worker.open('wb') as stream:
        run('tar', 'xOf', archive, 'node-v22.22.0-darwin-arm64/bin/node', stdout=stream)
    worker.chmod(0o755)
    run('clang++','-std=c++17','-fobjc-arc','-framework','Foundation','-framework','Security',
        f'-DTOOL="{tool}"',f'-DBUNDLE="{name}"','-D'+tool.upper(),src/'launcher.mm','-o',mac/tool)
    (contents/'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier='dev.mxcl.irnbru.'+tool,
        CFBundleExecutable=tool,CFBundlePackageType='APPL',CFBundleVersion=version.split('-')[0], CFBundleShortVersionString=version)))
    sign(worker, 'dev.mxcl.irnbru.' + tool + '.worker')
    sign(bundle)
    run('codesign','--verify','--deep','--strict',bundle)
    run(mac/tool, '--version', timeout=30)
    run('tar','czf',stage/'artifact.tgz','-C',stage,bundle.name,env=dict(os.environ,COPYFILE_DISABLE='1'))
    (stage/'artifact.tgz').replace(output)
