#!/usr/bin/env python3
import hashlib,json,os,shutil,xml.etree.ElementTree as ET
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];out=ROOT/'correction-evidence';lab=ROOT/'sw-evaluation';base=ROOT/'sw-readback'
assert os.environ.get('GITHUB_ACTIONS')=='true'
for name in ['byte-readback.json','publisher-verification.json']:
 shutil.copyfile(base/name,out/('original-'+name))
for name in ['candidate.json','trivy-binary.json','openpgp-applicability.json','native-target-inventory-result.json','contract-result.json','inventory-live-result.json','inventory-sealed-fd-result.json','adapter-source-inventory.json']:
 shutil.copyfile(lab/name,out/name)
shutil.copytree(lab/'contract-reports',out/'contract-reports')
native=json.loads((out/'native-target-inventory-result.json').read_text());assert native['status']=='PASS' and native['realDockerEngineQualified'] and native['directIdInspects']==13 and native['containerListRequests']==0
assert json.loads((out/'root-install-fixture.json').read_text())['status']=='PASS'
tests=0
for p in (out/'contract-reports').glob('TEST-*.xml'):
 r=ET.parse(p).getroot();assert all(int(r.attrib[k])==0 for k in ['failures','errors','skipped']);tests+=int(r.attrib['tests'])
assert tests==12
delivery=json.loads((out/'inventory-delivery/delivery.json').read_text());assert delivery['original23SourcesUnchanged'] and delivery['closedSourceCount']==24 and delivery['payloadBytes']<=262144
candidate=json.loads((out/'candidate.json').read_text());assert candidate['isolatedLabEligible'] or candidate['securityGate']=='PASS'
report={'schema':'ouf.storage-inventory-reconciliation-qualification.v1','status':'PASS','producerSource':os.environ['GITHUB_SHA'],'exactPreviousReaderSha256':delivery['backendSha256'],'closedSources':24,'original23SourcesUnchanged':True,'javaTests':tests,'newPythonGuards':10,'nativeDirectIdInspects':13,'nativeContainerListRequests':0,'realDockerEngineQualified':True,'historicalScopeChecks':'MODELLED','vpsObserved':False,'rawServerGate':candidate['securityGate'],'releaseAdmitted':False,'targetOperations':0,'oldScopeRearmed':False}
(out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
files=sorted(p for p in out.rglob('*') if p.is_file() and p.name not in ['SHA256SUMS','provenance.json'])
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(out))+'\n' for p in files))
print(json.dumps(report))
