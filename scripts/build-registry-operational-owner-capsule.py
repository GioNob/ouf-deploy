#!/usr/bin/env python3
"""Deterministic source-only capsule; building never invokes a target entry."""
import argparse
import ast
import base64
import gzip
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
NAMES=('core','store','contract','guard','adapter','service','installation','entry')
DEPENDENCY_HASH='f7d5c566dc3bab63873970ed781682d65f18f10aa69b01b74c037c9e1780cb57'
DEPENDENCY_CLOSURE='e78fca8785b3424271e9edbb1900a78944f68d2bd512417f093360b772195200'


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


BOOTSTRAP='''import base64,gzip,hashlib,io,json,os,re,signal,stat,sys,types
def require(ok,code):
 if not ok:raise ValueError(code)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unique(pairs):
 value={}
 for k,v in pairs:
  require(k not in value,'DUPLICATE_OPERATIONAL_CAPSULE_FIELD');value[k]=v
 return value
def bound_input(path,maximum,expected,executable=False):
 require(type(path)is str and path.startswith('/') and os.path.normpath(path)==path and '..'not in path.split('/'),'EXACT_BOOTSTRAP_INPUT_PATH_REQUIRED')
 fds=[];pins=[]
 def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
 try:
  fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
  parts=path.split('/')[1:]
  for part in parts[:-1]:
   row=os.fstat(fd);require(row.st_uid==row.st_gid==0 and not row.st_mode&0o022,'ROOT_BOOTSTRAP_INPUT_ANCESTRY_REQUIRED')
   parent=fd;fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);fds.append(fd)
   pins.append((parent,part,fd,identity(os.fstat(fd))[:5]))
  row=os.fstat(fd);require(row.st_uid==row.st_gid==0 and not row.st_mode&0o022,'ROOT_BOOTSTRAP_INPUT_ANCESTRY_REQUIRED')
  leaf=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd);fds.append(leaf);before=os.fstat(leaf)
  require(stat.S_ISREG(before.st_mode) and before.st_uid==before.st_gid==0 and before.st_nlink==1 and not before.st_mode&0o022 and 0<before.st_size<=maximum,'CUSTODIED_BOOTSTRAP_INPUT_REQUIRED')
  require(bool(before.st_mode&0o111)if executable else stat.S_IMODE(before.st_mode)in(0o400,0o600),'EXACT_BOOTSTRAP_INPUT_MODE_REQUIRED')
  pieces=[];count=0
  while count<before.st_size:
   piece=os.read(leaf,min(65536,before.st_size-count));require(bool(piece),'COMPLETE_BOOTSTRAP_INPUT_REQUIRED');pieces.append(piece);count+=len(piece)
  raw=b''.join(pieces)
  require(identity(before)==identity(os.fstat(leaf))==identity(os.stat(parts[-1],dir_fd=fd,follow_symlinks=False))and hashlib.sha256(raw).hexdigest()==expected,'BOOTSTRAP_INPUT_OR_HASH_CHANGED')
  for parent,name,child,pin in pins:require(pin==identity(os.fstat(child))[:5]==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))[:5],'BOOTSTRAP_INPUT_ANCESTRY_CHANGED')
  return raw
 finally:
  for fd in reversed(fds):os.close(fd)
mode=None
try:
 require(os.geteuid()==os.getegid()==0 and sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,'ISOLATED_ROOT_OPERATIONAL_CAPSULE_REQUIRED')
 require(hashlib.sha256(BOOTSTRAP.encode()).hexdigest()==DELIVERY['sourceManifest']['bootstrapHash'] and hashlib.sha256(encoded(DELIVERY)).hexdigest()==DELIVERY_HASH,'OPERATIONAL_DELIVERY_DECLARATION_CHANGED')
 require(len(sys.argv)>1 and sys.argv[1] in ('worker','prepare','issue','install','start','status'),'ONE_OPERATIONAL_MODE_REQUIRED')
 mode=sys.argv[1]
 if mode!='worker':
  binding=DELIVERY['case']['inputs'];raw=bound_input(binding['path'],8388608,binding['sha256']);retained=json.loads(raw,object_pairs_hook=unique)
  require(encoded(retained)==raw,'CANONICAL_RETAINED_BOOTSTRAP_INPUT_REQUIRED')
  python=retained['review']['authorityInputs']['executables']['python'];bound_input(python['path'],67108864,python['sha256'],executable=True)
  if os.path.realpath(sys.executable)!=python['path']:
   os.execve(python['path'],[python['path'],'-I','-B','-S',os.path.abspath(__file__),*sys.argv[1:]],{'PATH':'/usr/bin:/bin','LC_ALL':'C','OPENSSL_CONF':'/dev/null'})
 if mode!='worker':
  signal.signal(signal.SIGALRM,lambda *_:require(False,'FINITE_OPERATIONAL_INSTALLATION_DEADLINE'));signal.alarm(900)
 packed=base64.b64decode(PACKED,validate=True);require(0<len(packed)<=2097152,'BOUNDED_OPERATIONAL_CAPSULE_REQUIRED')
 with gzip.GzipFile(fileobj=io.BytesIO(packed))as stream:raw=stream.read(16777217)
 require(0<len(raw)<=16777216 and hashlib.sha256(raw).hexdigest()==DELIVERY['payloadHash'],'OPERATIONAL_PAYLOAD_CHANGED')
 payload=json.loads(raw,object_pairs_hook=unique)
 require(set(payload)=={'dependency','sources'},'CLOSED_OPERATIONAL_PAYLOAD_REQUIRED')
 old=payload['dependency'];declaration=DELIVERY['dependencyDeclaration'];loader=old['loader'].encode()
 sources={k:v.encode()for k,v in old['sources'].items()}
 require(len(sources)==142 and set(sources)==set(declaration['sourceHashes']) and hashlib.sha256(loader).hexdigest()==declaration['loaderHash'],'EXACT_OPERATIONAL_DEPENDENCY_CLOSURE_REQUIRED')
 require(all(hashlib.sha256(v).hexdigest()==declaration['sourceHashes'][k]for k,v in sources.items()),'OPERATIONAL_DEPENDENCY_BYTES_CHANGED')
 namespace={};exec(compile(loader,'<verified-operational-dependency-loader>','exec'),namespace)
 _,observed=namespace['load_entry'](declaration['sourceCommit'],sources,loader,hashlib.sha256(encoded(declaration)).hexdigest(),declaration['sourcePins'])
 require(observed==declaration,'OPERATIONAL_DEPENDENCY_DECLARATION_CHANGED')
 manifest=DELIVERY['sourceManifest'];new=payload['sources']
 require(set(new)==set(manifest['sourceHashes']) and len(new)==8,'COMPLETE_OPERATIONAL_SOURCE_SET_REQUIRED')
 require(all(hashlib.sha256(v.encode()).hexdigest()==manifest['sourceHashes'][k]for k,v in new.items()),'OPERATIONAL_SOURCE_BYTES_CHANGED')
 package='tools.semantic_registry_operational_owner';module=types.ModuleType(package);module.__path__=[];sys.modules[package]=module
 for leaf in ('core','store','contract','guard','adapter','service','installation','entry'):
  name=package+'.'+leaf;source=new[name].encode();path='<sealed:'+name+'>'
  module=types.ModuleType(name);module.__package__=package;module.__file__=path
  module.__qualified_source_sha256__=manifest['sourceHashes'][name];module.__qualified_source_path__=path
  sys.modules[name]=module;exec(compile(source,path,'exec'),module.__dict__)
 if mode=='worker':code=sys.modules[package+'.entry'].execute(sys.argv[2:])
 else:
  result=sys.modules[package+'.installation'].operator(DELIVERY,sys.argv[1:],os.path.abspath(__file__))
  print(encoded(result).decode(),flush=True);code=0
 signal.alarm(0);raise SystemExit(code)
except (Exception,KeyboardInterrupt)as error:
 signal.alarm(0)
 reason=str(error);reason=reason if re.fullmatch('[A-Z][A-Z0-9_]{0,127}',reason)else'OPERATIONAL_INSTALLATION_UNPROVEN_PRIVATE_DETAILS_REDACTED'
 print(encoded({'schema':'ouf.registry-operational-installation-operator-result.v1','status':'STOP_RECONCILE','complete':False,'reasonCode':reason,'runtimeEffectsMayBePartial':mode in('issue','install','start'),'contextsAndClaimsRetained':True,'automaticReplayAllowed':False,'budgetReset':False,'releaseAcceptance':False}).decode(),flush=True)
 raise SystemExit(2)
'''


def build(source_commit):
    assert re.fullmatch('[a-f0-9]{40}',source_commit)
    raw=(ROOT/'releases/semantic-registry-checkpoint-successor-20261023.py').read_bytes()
    assert sha(raw)==DEPENDENCY_HASH
    rows={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(raw).body
          if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
    old=json.loads(gzip.decompress(base64.b64decode(rows['PACKED'],validate=True)))
    declaration=rows['DELIVERY']['nativeDeclaration']
    assert len(old['sources'])==142 and set(old['sources'])==set(declaration['sourceHashes'])
    assert sha(old['loader'].encode())==declaration['loaderHash']
    assert all(sha(v.encode())==declaration['sourceHashes'][k] for k,v in old['sources'].items())
    sources={'tools.semantic_registry_operational_owner.'+name:
             (ROOT/('tools/semantic_registry_operational_owner/'+name+'.py')).read_text() for name in NAMES}
    payload=encoded({'dependency':old,'sources':sources})
    manifest={'schema':'ouf.registry-operational-owner-sources.v1','sourceCommit':source_commit,
        'sourceHashes':{k:sha(v.encode()) for k,v in sources.items()},
        'dependencyClosureHash':DEPENDENCY_CLOSURE,'bootstrapHash':sha(BOOTSTRAP.encode())}
    case={'inputs':{'path':'/etc/ouf/deploy-snapshots/semantic-registry-running-policy-inputs-47eb283d194f9a9b81f22852c278e1f9b24d0c72c63e60e968cf8ce67d876f89/inputs.json',
                   'sha256':'1ab900e9818543788df36f5bc7f101da99507dd01933bd10a8194137b5de42de'},
          'predecessorDependencyCapsuleHash':DEPENDENCY_HASH}
    delivery={'schema':'ouf.registry-operational-owner-delivery.v1','sourceManifest':manifest,
              'case':case,'dependencyDeclaration':declaration,'payloadHash':sha(payload)}
    program=('#!/usr/bin/env python3\n"""Sealed Registry operational owner; no embedded credential or address."""\n'+
        'BOOTSTRAP='+repr(BOOTSTRAP)+'\nDELIVERY='+repr(delivery)+'\nDELIVERY_HASH='+repr(sha(encoded(delivery)))+
        '\nPACKED='+repr(base64.b64encode(gzip.compress(payload,mtime=0)).decode())+
        '\nexec(compile(BOOTSTRAP,"<verified-operational-bootstrap>","exec"))\n').encode()
    compile(program,'operational-capsule','exec')
    return program,delivery


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source-commit',required=True)
    parser.add_argument('--output',required=True);args=parser.parse_args()
    raw,delivery=build(args.source_commit);path=Path(args.output)
    with path.open('xb')as stream:stream.write(raw)
    print(json.dumps({'sha256':sha(raw),'bytes':len(raw),'sourceManifestHash':sha(encoded(delivery['sourceManifest']))}))


if __name__=='__main__':main()
