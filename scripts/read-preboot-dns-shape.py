"""Installation-specific three-container DNS shape read, no values or effects."""
import importlib.util,json,signal,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('retained_read',Path(__file__).with_name('read-retained-udp-startup.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def shape(value):
 m.require(value is None or(type(value)is list and len(value)<=64 and all(type(v)is str for v in value)),'DNS_SHAPE_UNPROVEN')
 return {'kind':'null'if value is None else'list','count':None if value is None else len(value),'explicitOverridePresent':bool(value),'valuesPrinted':False}
def collect(selection):
 m.require(set(selection)=={'schema','applications'}and selection['schema']=='ouf.preboot-dns-shape-selection.v1'and set(selection['applications'])=={'udp','mcp','onboarding'},'CLOSED_THREE_APPLICATIONS_REQUIRED')
 ids=list(selection['applications'].values());m.require(len(set(ids))==3 and all(type(v)is str and len(v)==64 and all(c in'0123456789abcdef'for c in v)for v in ids),'EXACT_CONTAINER_IDS_REQUIRED')
 fmt='{"id":{{json .Id}},"running":{{json .State.Running}},"dns":{{json .HostConfig.Dns}}}'
 rows=[json.loads(line)for line in m.invoke(['inspect','--type','container','--format',fmt,*ids]).splitlines()if line]
 m.require(len(rows)==3 and {r['id']for r in rows}==set(ids),'EXACT_READBACK_REQUIRED')
 output={}
 for role,cid in selection['applications'].items():
  row=next(r for r in rows if r['id']==cid);m.require(type(row['running'])is bool,'STATE_REQUIRED');output[role]={'containerId':cid,'running':row['running'],'dns':shape(row['dns'])}
 return {'schema':'ouf.preboot-dns-shape-read.v1','complete':True,'applications':output,'runtimeMutations':0,'engineWrites':0,'credentialValuesPrinted':False,'dnsValuesPrinted':False,'configurationValuesPrinted':False,'completedTechnicalPhases':8,'functionalMilestonesProven':4}
if __name__=='__main__':
 signal.alarm(30)
 try:result=collect(json.loads(Path(sys.argv[1]).read_bytes()))
 except Exception as error:result={'schema':'ouf.preboot-dns-shape-read.v1','complete':False,'errorClass':type(error).__name__,'exceptionMessagePrinted':False,'runtimeMutations':0,'engineWrites':0}
 print(json.dumps(result,sort_keys=True));sys.exit(0 if result['complete']else 2)
