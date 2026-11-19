from pathlib import Path
import subprocess,json,hashlib,os
R=Path(__file__).resolve().parent.parent;D=R/'source32-tree-diagnostic-stage';G=D/'git';subprocess.run(['git','init','--bare',str(G)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);(G/'objects/info/alternates').write_text(str(R/'source32-integrated-stage/source/.git/objects')+'\n');env=os.environ.copy();env.update(GIT_DIR=str(G),GIT_INDEX_FILE=str(D/'exact-prefix-index'));run=lambda a:subprocess.run(['git']+a,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
M=R/'image32-stage/proposal/releases/seaweedfs-452-generation32-build-manifest-20261103.json';m=json.loads(M.read_text());run(['read-tree',m['upstreamCommit']]);steps=[]
for i,p in enumerate(m['orderedPatches'],1):
 f=R/'image32-stage/test-root'/p['path'];b=f.read_bytes();assert hashlib.sha256(b).hexdigest()==p['sha256'];r=run(['apply','--cached','--whitespace=nowarn',str(f)]);tree=run(['write-tree']).stdout.decode().strip();steps.append({'number':i,'path':p['path'],'sha256':p['sha256'],'resultTree':tree,'stderr':r.stderr.decode()})
actual=steps[-1]['resultTree'];claimed=m['build']['patchedSourceTree'];assert actual=='80632ef3a54debb04531c1913860d2f94d2b418d'
def entries(tree):
 raw=run(['ls-tree','-rz','--full-tree',tree]).stdout;(D/(tree+'.ls-tree.z')).write_bytes(raw);out={}
 for line in raw.split(b'\0'):
  if not line:continue
  info,path=line.split(b'\t',1);mode,kind,oid=info.decode().split();out[path.decode()]={'mode':mode,'kind':kind,'oid':oid}
 return out
x=entries(claimed);y=entries(actual);delta=[];source=R/'source32-integrated-stage/source';manifest=json.loads((R/'source32-integrated-stage/evidence/source-manifest.json').read_text())
for path in sorted(x.keys()|y.keys()):
 if x.get(path)==y.get(path):continue
 a=x.get(path);b=y.get(path);data=(source/path).read_bytes();blob=run(['cat-file','blob',b['oid']]).stdout;sha=hashlib.sha256(data).hexdigest();assert data==blob and manifest['files'][path]==sha
 ignore=subprocess.run(['git','-C',str(source),'check-ignore','--no-index','-v',path],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 delta.append({'path':path,'claimedTreeEntry':a,'cachedReplayEntry':b,'workingFilePresent':True,'workingBytesEqualCorrectBlob':True,'sourceManifestContainsMatchingSha256':True,'sha256':sha,'ignoreRule':ignore.stdout.decode().strip()})
assert len(delta)==24 and all(v['claimedTreeEntry']is None for v in delta)
out={'schema':'ouf.source32-tree-binding-diagnosis.v1','manifestSha256':hashlib.sha256(M.read_bytes()).hexdigest(),'upstreamCommit':m['upstreamCommit'],'method':'isolated bare Git object store with readonly alternates, alternate index read-tree upstream followed by all32 exact patch blobs via git apply --cached; no worktree reconstruction','allPatchHashesVerified':True,'steps':steps,'claimedLocalTree':claimed,'claimedLocalEntryCount':len(x),'exactCachedPrefixTree':actual,'exactCachedPrefixEntryCount':len(y),'matchesHostedTree':True,'differences':delta,'cause':'An initially empty alternate index followed by git add -A omitted24 pre-existing tracked upstream files matched by ignore rules. The working files and source-file manifest retained all24 correct bytes. Cached replay seeded from upstream preserves their tracked state.','scope':'Git tree provenance computation is wrong in the local frozen receipt; compiled bytes and source file bytes are not shown to differ by this discrepancy. No frozen files or expected values changed.'};(D/'diagnosis.json').write_text(json.dumps(out,indent=2)+'\n');print(actual,len(y),'claimed',len(x),'delta',len(delta));print('diagnosisSHA',hashlib.sha256((D/'diagnosis.json').read_bytes()).hexdigest())
