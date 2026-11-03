from pathlib import Path
import json,hashlib
S=Path(__file__).resolve().parent;E=S/'evidence';D=json.JSONDecoder()
def seq(p):
 s=p.read_text();i=0;a=[]
 while i<len(s):
  while i<len(s)and s[i].isspace():i+=1
  if i==len(s):break
  x,i=D.raw_decode(s,i);a.append(x)
 return a
p=seq(E/'production-graph.stdout');m=seq(E/'root-modules-complete.stdout');pk={x['ImportPath']for x in p};mods={x['Module']['Path']for x in p if 'Module'in x};deny=['github.com/aws/aws-sdk-go','github.com/aws/aws-sdk-go-v2/feature/s3/manager','github.com/boltdb/bolt','github.com/mitchellh/mapstructure','github.com/rcrowley/go-metrics','github.com/Shopify/sarama','github.com/benbjohnson/clock','github.com/montanaflynn/stats','go.mongodb.org/mongo-driver','go.opencensus.io','github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp','github.com/envoyproxy/protoc-gen-validate','github.com/mitchellh/colorstring','github.com/schollz/progressbar/v3','github.com/rivo/uniseg'];assert not mods.intersection(deny)
rows=sorted((x['Module']['Path'],x['Module']['Version'])for x in p if 'Module'in x and not x['Module'].get('Main'));rows=sorted(set(rows));(E/'compiled-module-rows.json').write_text(json.dumps(rows,indent=2)+'\n');r={'compiledPackageCount':len(pk),'compiledDependencyModuleCount':len(rows),'rootModuleCountIncludingMain':len(m),'compiledDeniedModuleAbsent':deny,'remainingRootLegacyEdges':[{k:x[k]for k in ('Path','Version')if k in x}for x in m if x['Path']in deny],'yamlCompiled':[x for x in rows if 'yaml'in x[0]],'rootGraphClaim':'No lifecycle closure claim for uncompiled transitive graph; YAML remains OPEN.','moduleVersionsHash':hashlib.sha256(('\n'.join('@'.join(x)for x in rows)+'\n').encode()).hexdigest()};(E/'graph-summary.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
