"""Actual fork/unshare/ip/nft template; exact parent table pair is preserved."""
import copy,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools/semantic_cohort_admission/cohort-draft')]
from tools.m2_discovery_installation_profile.transport_template import isolated_footprint

def main():
    assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'
    assert Path('/proc/self/ns/net').stat().st_ino!=Path('/proc/1/ns/net').stat().st_ino
    nft=str(Path(shutil.which('nft')).resolve());ip=str(Path(shutil.which('ip')).resolve())
    def run(*args,raw=None):
        return subprocess.run(args,input=raw,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            check=True,timeout=10).stdout
    def binding(p):return {'path':p,'sha256':hashlib.sha256(Path(p).read_bytes()).hexdigest()}
    table='ci_template_collision'
    run(nft,'-f','-',raw='table inet '+table+' {}\ntable bridge '+table+' {}\n')
    def snapshot():
        return {f:json.loads(run(nft,'-j','list','table',f,table)) for f in ('inet','bridge')}
    before=snapshot()
    profile={'schema':'ouf.semantic-preexec-profile.v2','namespaceOrigin':'OCI_CREATED',
        'transactionId':'a'*64,'containerId':'b'*64,'bundlePath':'/fixture/bundle','bundleHash':'c'*64,
        'namespacePath':'/fixture/namespace','namespaceInode':123,'namespaceLinks':[
            {'interface':'eth0','ifindex':2,'hostIfindex':10004}],
        'policy':{'schema':'ouf.semantic-shared-faces.v1','tableName':table,'attachments':[
            {'workloadRef':'synthetic','interface':'ciport','ifindex':10004,'bridge':'cibridge',
             'mac':'02:00:00:00:00:02','ipv4':'10.77.0.2','bindingRef':'synthetic-port'}],
            'flows':[{'purpose':'IDENTITY','authorityRef':'synthetic-identity','source':'10.77.0.2',
                'destination':'1.1.1.1','protocol':'tcp','port':443,'peerIngress':{'kind':'HOST','ifindex':0}}]},
        'expectedFootprint':'0'*64,'applicationStartAuthorized':False,'infrastructureAuthorityComplete':False}
    links=[{'interface':'ciport','ifindex':10004}];commands={'ip':binding(ip),'nft':binding(nft)}
    initial=copy.deepcopy((profile,links,commands))
    try:
        first=isolated_footprint(profile,links,commands,seconds=10)
        second=isolated_footprint(profile,links,commands,seconds=10)
        assert first==second and first['isolated'] and not first['hostRulesChanged'] and not first['startAuthorized']
        assert first['footprint']!='0'*64 and snapshot()==before
        assert initial==(profile,links,commands)
        bad=copy.deepcopy(commands);bad['nft']['sha256']='0'*64
        try:isolated_footprint(profile,links,bad,seconds=10);raise AssertionError('wrong command admitted')
        except (ValueError,RuntimeError):pass
        bad_links=[{'interface':'ciport','ifindex':1}]
        try:isolated_footprint(profile,bad_links,commands,seconds=10);raise AssertionError('wrong mirror admitted')
        except (ValueError,RuntimeError):pass
        false=str(Path(shutil.which('false')).resolve());failing={**commands,'nft':binding(false)}
        try:isolated_footprint(profile,links,failing,seconds=10);raise AssertionError('failed template used host fallback')
        except (ValueError,RuntimeError):pass
        assert snapshot()==before and initial==(profile,links,commands)
        print(json.dumps({'schema':'ouf.m2-discovery-isolated-transport-template-ci.v1',
            'actualForkUnshareIpNft':True,'sameTableNamesAlreadyPresentInParent':True,
            'parentTablePairPreserved':True,'twoIndependentTemplatesEqual':True,
            'badCommandAndMirrorDenied':True,'childFailureDoesNotUseHostReadback':True,
            'inputsPreserved':True,'expectedFootprint':first['footprint'],
            'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'applicationE2EProven':False},sort_keys=True))
    finally:
        for family in ('inet','bridge'):run(nft,'delete','table',family,table)

if __name__=='__main__':main()
