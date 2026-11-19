"""Pure index/receipt/role checks; synthetic rows do not prove actual tar bytes."""
import copy,json,stat,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT)]
from tools.m2_discovery_installation_profile import retained_image_intake as m
from tools.m2_discovery_installation_profile.retained_mount_role_correction import stable_binding


def fixture():
    seed={'schema':'ouf.m2-discovery-current-private-bindings.v1','bootId':'fixture-boot',
        'historicalAuthorityReused':False,'runtimeAuthorityIssued':False,'automaticReplayAllowed':False,
        'budgetReset':False,'observations':{},'processPins':{}};roster={};rows={}
    for i,role in enumerate(sorted(m.ROSTER),1):
        alias='inventory-'+str(i);pin={'pid':i,'startTicks':i,'namespaces':{}}
        image='sha256:'+format(i,'064x')
        row={'Id':format(i,'064x'),'Image':image,'Name':'/fixture-'+role,'Config':{},'HostConfig':{},
            'Mounts':[],'NetworkSettings':{},'State':{'Pid':i,'StartedAt':'fixture','Running':True,'Paused':False,'Restarting':False}}
        seed['observations'][alias]=row;seed['processPins'][alias]=pin
        roster[role]={'containerId':row['Id'],'nativeBindingHash':m.digest(stable_binding(row)),'generation':pin}
        rows[role]={'imageIdRequested':image,'filename':'image-'+role+'.docker.tar','bytes':10240,
            'sha256':format(i,'064x'),'metadata':[1,i,stat.S_IFREG|0o400,0,0,1,10240,1,1],
            'nativeIdentityAndSourceAdmissionEstablished':False}
    case={**m.CASE,'seedHash':m.digest(seed)}
    record={'schema':'ouf.retained-native-image-archive-candidates.v1','caseHash':m.digest(case),
        'profile':copy.deepcopy(m.PROFILE),'viewCandidateHash':case['viewCandidateHash'],
        'seedHash':case['seedHash'],'bootId':seed['bootId'],'archives':rows,**dict.fromkeys(m.RECORD_FALSE,False)}
    counts={**dict.fromkeys(m.ZERO_COUNTS,0),'bytes':1000,'engineBytes':133120,'engineGets':13,
        'imageArchiveBytes':133120,'imageArchivesCaptured':13,'metadataReads':5}
    receipt={'schema':'ouf.retained-native-image-archive-result.v1','status':'NATIVE_IMAGE_ARCHIVE_CANDIDATES_CAPTURED_NOT_ADMITTED',
        'candidateHash':m.digest(record),'viewCandidateHash':case['viewCandidateHash'],'counts':counts,
        'allSixPriorScopesPreserved':True,'cumulativeControlAttempts':7,'cumulativeDirectEngineGets':35,
        'imageBytesRetainedPrivately':True,**dict.fromkeys(m.RESULT_FALSE,False)}
    return record,receipt,seed,case,roster


class Intake(unittest.TestCase):
    def validate(self,record,receipt,seed,case,roster):
        receipt['candidateHash']=m.digest(record)
        return m.validate_archives(record,receipt,seed,candidate_hash=m.digest(record),
            result_hash=m.digest(receipt),case=case,roster=roster)

    def test_thirteen_distinct_role_bound_archives_and_defensive_copy(self):
        args=fixture();rows=self.validate(*args);self.assertEqual(len(rows),13)
        rows['mcp']['bytes']=1;self.assertEqual(args[0]['archives']['mcp']['bytes'],10240)

    def test_default_public_target_receipt_and_candidate_are_exact_and_not_admission(self):
        target=json.loads((ROOT/'evidence/m2-native-image-archives-target-20261101.json').read_text())
        self.assertEqual(m.digest(target['receipt']),m.RESULT_HASH)
        self.assertEqual(target['receipt']['candidateHash'],m.CANDIDATE_HASH)
        self.assertFalse(target['privateRecordReadByAgent']);self.assertTrue(target['scopeConsumed'])
        self.assertEqual(target['receipt']['counts']['imageArchiveBytes'],2774726144)

    def test_rehashed_role_path_hash_custody_and_count_forgeries_still_deny(self):
        for kind in ('role','path','size','hash','mode','uid','link','extra','count','claim','view','boot','bool'):
            record,receipt,seed,case,roster=fixture();row=record['archives']['mcp']
            if kind=='role':row['imageIdRequested']=record['archives']['udp']['imageIdRequested']
            elif kind=='path':row['filename']='../must-not-read'
            elif kind=='size':row['bytes']+=512
            elif kind=='hash':row['sha256']='not-a-hash'
            elif kind=='mode':row['metadata'][2]=stat.S_IFREG|0o600
            elif kind=='uid':row['metadata'][3]=10001
            elif kind=='link':row['metadata'][5]=2
            elif kind=='extra':record['archives']['foreign']=copy.deepcopy(row)
            elif kind=='count':receipt['counts']['imageArchiveBytes']+=512
            elif kind=='claim':record['nativeIdentityAndSourceAdmissionEstablished']=True
            elif kind=='view':record['viewCandidateHash']='e'*64
            elif kind=='boot':record['bootId']='foreign'
            else:receipt['counts']['metadataReads']=True
            with self.subTest(kind=kind),self.assertRaises((ValueError,KeyError)):
                self.validate(record,receipt,seed,case,roster)

    def test_wrong_pinned_input_hash_denies_without_read_or_repair_callbacks(self):
        record,receipt,seed,case,roster=fixture()
        with self.assertRaises(ValueError):m.validate_archives(record,receipt,seed,case=case,roster=roster)
        with self.assertRaises(TypeError):m.validate_archives(record,receipt,seed,engine=lambda:True)


if __name__=='__main__':unittest.main()
