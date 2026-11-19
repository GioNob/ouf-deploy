from pathlib import Path
import json,hashlib,difflib,subprocess,os
R=Path.cwd();S=R/'source32-integrated-stage'; A=R/'source31-stage/source';B=S/'source';P=S/'proposal/patches/seaweedfs';P.mkdir(parents=True,exist_ok=True)
def files(root):return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()for p in root.rglob('*')if p.is_file()and'.git'not in p.relative_to(root).parts}
a,b=files(A),files(B);delta=sorted(k for k in a.keys()|b.keys()if a.get(k)!=b.get(k));assert delta==json.loads((S/'expected-source-delta.json').read_text());out=[]
for k in delta:
 old=(A/k).read_text().splitlines(keepends=True)if k in a else [];new=(B/k).read_text().splitlines(keepends=True)if k in b else []
 out.append(f'diff --git a/{k} b/{k}\n')
 if k not in a:out.append('new file mode 100644\n')
 if k not in b:out.append('deleted file mode 100644\n')
 out.extend(difflib.unified_diff(old,new,fromfile='a/'+k if k in a else '/dev/null',tofile='b/'+k if k in b else '/dev/null'))
p=P/'4.52-maintained-profiles-mongodb-v2-generation32.patch';p.write_text(''.join(out));env=os.environ.copy();env['GIT_INDEX_FILE']=str(S/'source32-index');subprocess.run(['git','add','-A'],cwd=B,env=env,check=True);tree=subprocess.check_output(['git','write-tree'],cwd=B,env=env,text=True).strip();(S/'evidence/source-manifest.json').write_text(json.dumps({'files':b,'tree':tree,'changedFrom31':delta,'patch':{'path':str(p.relative_to(S/'proposal')),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}},indent=2)+'\n');print('tree',tree,'files',len(b),'patch',hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_size)
