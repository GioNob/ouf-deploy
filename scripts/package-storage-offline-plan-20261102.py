#!/usr/bin/env python3
"""Build a standalone two-source offline plan compiler; no target calls."""
import hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SOURCES=['tools/storage_planning/inventory_manifest.py','tools/storage_planning/target_plan_20261102.py']
def build(receipt):
 core,target=[(ROOT/p).read_text() for p in SOURCES]
 assert target.count('EXPECTED_RECEIPT = None')==1
 bound={k:v for k,v in receipt.items() if k not in ['inventoryReconciliationProducer','inventoryReconciliationPublication']}
 manifest={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES}
 entry=target.replace('EXPECTED_RECEIPT = None','EXPECTED_RECEIPT = '+repr(bound))
 body='#!/usr/bin/env python3\n'+core+'\n'+entry+'\nSOURCE_MANIFEST = '+repr(manifest)+'''\nif __name__ == '__main__':
    if sys.argv[1:] == ['--inspect-source']:
        print(json.dumps({'status':'OFFLINE_PLAN_SOURCE_INSPECTED','sources':SOURCE_MANIFEST,'targetOperations':0,'runtimeAuthorityIssued':False},sort_keys=True))
    else:
        raise SystemExit(main())
'''
 compile(body,'prepare-plan.py','exec');return body,manifest
if __name__=='__main__':
 out=Path(sys.argv[1]);revision=sys.argv[2];out.mkdir()
 receipt=json.loads((ROOT/'evidence/seaweedfs-private-baseline-target-20261102.json').read_text())
 body,manifest=build(receipt);p=out/'prepare-plan.py';p.write_text(body)
 inspect=json.loads(subprocess.check_output([sys.executable,'-I','-B','-S',str(p),'--inspect-source'],timeout=10));assert inspect['sources']==manifest and not inspect['runtimeAuthorityIssued']
 delivery={'schema':'ouf.storage-offline-plan-delivery.v1','producerSource':revision,'sourceCount':2,'sources':manifest,'capsuleSha256':hashlib.sha256(p.read_bytes()).hexdigest(),'capsuleBytes':p.stat().st_size,'sourceInventorySha256':receipt['privateInventorySha256'],'scopePath':'/etc/ouf/deploy-snapshots/seaweedfs-offline-plan-20261102-v1','installPath':'/usr/local/lib/ouf-storage-offline-plan-20261102','controlAttempt':17,'previousControlAttempts':16,'previousEngineGets':52,'newEngineGets':0,'newS3Requests':0,'credentialFileReads':0,'objectBodiesRead':0,'oldScopeRearmed':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False}
 (out/'delivery.json').write_text(json.dumps(delivery,indent=2)+'\n');print(json.dumps(delivery))
