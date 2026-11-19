#!/usr/bin/env python3
"""Direct GitHub artifact transport on the existing runner; no OUF runtime access."""
import hashlib,json,os,re,signal,stat,sys,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
CASE_HASH='2f9a2336572e1bbc57215bc6fc7b4f3a5f9bc5fa74e160be751cc0f57dcb8a80'
class Stop(RuntimeError):pass
def require(ok,code):
    if not ok:raise Stop(code)
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def unique(pairs):
    result={}
    for k,v in pairs:require(k not in result,'DUPLICATE_CASE_KEY');result[k]=v
    return result
def put(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(os.dup(fd),'wb')as stream:stream.write(encoded(value));stream.flush();os.fsync(stream.fileno())
    finally:os.close(fd)
def fsync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def safe_parent(path):
    require(path.is_absolute()and'..'not in path.parts and path.resolve()==path,'CANONICAL_RUNNER_PARENT_REQUIRED')
    for current in(path,*path.parents):
        info=current.lstat();require(stat.S_ISDIR(info.st_mode)and info.st_uid in(0,os.geteuid())and not info.st_mode&0o022,'CUSTODIED_RUNNER_PARENT_REQUIRED')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_):return None
OPENER=urllib.request.build_opener(NoRedirect())
def request(url,headers):
    req=urllib.request.Request(url,headers=headers,method='GET')
    try:return OPENER.open(req,timeout=30)
    except urllib.error.HTTPError as error:return error

def storage_url(url):
    parsed=urllib.parse.urlsplit(url)
    host=parsed.hostname or''
    require(parsed.scheme=='https'and parsed.username is None and parsed.password is None and parsed.port in(None,443)
        and (bool(re.fullmatch(r'productionresultssa[0-9]+\.blob\.core\.windows\.net',host))
             or host=='objects.githubusercontent.com'or host.endswith('.actions.githubusercontent.com')),'GITHUB_STORAGE_REDIRECT_REQUIRED')
    return url

def artifact_response(descriptor,token,root,role,open_request=request):
    repository=descriptor['repository'];artifact=descriptor['artifactId']
    require(repository in('GioNob/ouf-ingestion-runtime','GioNob/ouf-udp-object-resolution','GioNob/ouf-mcp-server','GioNob/ouf-api-gateway')and type(artifact)is int and artifact>0,'PINNED_GITHUB_ARTIFACT_REQUIRED')
    put(root/(role+'-api-attempt.json'),{'artifactId':artifact,'attemptNotCompletion':True,'githubApiGetAttempts':1})
    endpoint='https://api.github.com/repos/'+repository+'/actions/artifacts/'+str(artifact)+'/zip'
    with open_request(endpoint,{'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'ouf-pinned-artifact-transport'})as response:
        require(response.status==302,'GITHUB_ARTIFACT_REDIRECT_STATUS_REQUIRED');url=storage_url(response.headers.get('Location',''))
    # Authorization is NEVER attached to signed storage requests or redirects.
    for ordinal in range(1,4):
        put(root/(role+'-storage-attempt-'+str(ordinal)+'.json'),{'artifactId':artifact,'attemptNotCompletion':True,'authorizationHeaderSent':False})
        response=open_request(url,{'Accept':'application/octet-stream','User-Agent':'ouf-pinned-artifact-transport'})
        if response.status==200:return response
        try:
            require(response.status in(301,302,303,307,308),'GITHUB_ARTIFACT_STORAGE_STATUS_REQUIRED');url=storage_url(response.headers.get('Location',''))
        finally:response.close()
    raise Stop('FINITE_STORAGE_REDIRECTS_EXHAUSTED')

def download(role,descriptor,token,root,open_request=request):
    require(role in('ingestion','udp','mcp','gateway'),'CLOSED_ARTIFACT_ROLE_REQUIRED')
    size=descriptor['zipBytes'];wanted=descriptor['zipSha256']
    require(type(size)is int and 0<size<=220*1024*1024 and re.fullmatch('[a-f0-9]{64}',wanted)is not None,'BOUNDED_PINNED_ARTIFACT_REQUIRED')
    temporary=root/(role+'.zip.part');target=root/(role+'.zip')
    require(not os.path.lexists(temporary)and not os.path.lexists(target),'ARTIFACT_ALREADY_PRESENT_RECONCILE')
    digest=hashlib.sha256();received=0
    with artifact_response(descriptor,token,root,role,open_request)as response:
        declared=response.headers.get('Content-Length')
        require(declared is None or declared.isdigit()and int(declared)==size,'PINNED_CONTENT_LENGTH_REQUIRED')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
        try:
            with os.fdopen(os.dup(fd),'wb')as stream:
                while chunk:=response.read(65536):
                    received+=len(chunk);require(received<=size,'EXACT_ARTIFACT_SIZE_BOUND');digest.update(chunk);stream.write(chunk)
                stream.flush();os.fsync(stream.fileno())
        finally:os.close(fd)
    require(received==size and digest.hexdigest()==wanted,'PINNED_ARTIFACT_BYTES_REQUIRED')
    os.link(temporary,target,follow_symlinks=False);temporary.unlink();fsync_directory(root)
    receipt={'artifactId':descriptor['artifactId'],'zipBytes':received,'zipSha256':wanted,'verified':True}
    put(root/(role+'-verified.json'),receipt);return receipt

def transport(case,parent,token,open_request=request):
    require(bool(token)and'\n'not in token and'\r'not in token,'JOB_GITHUB_TOKEN_REQUIRED')
    require(sha(encoded(case))==CASE_HASH,'EXACT_STAGING_CASE_REQUIRED')
    safe_parent(parent);root=parent/('ouf-acquisition-read-transport-'+CASE_HASH[:16])
    require(not os.path.lexists(root),'TRANSPORT_SCOPE_EXISTS_NO_REPLAY');root.mkdir(mode=0o700)
    put(root/'claim.json',{'schema':'ouf.acquisition-artifact-transport-claim.v1','caseHash':CASE_HASH,'automaticReplayAllowed':False,'maximumGithubApiGets':4,'maximumStorageRedirectGets':12,'maximumSeconds':540,'oufOAuthRequests':0,'targetApplyAuthorized':False})
    receipts={}
    for role,descriptor in case['artifacts'].items():receipts[role]=download(role,descriptor,token,root,open_request)
    require(set(receipts)=={'ingestion','udp','mcp','gateway'},'FOUR_VERIFIED_ARCHIVES_REQUIRED')
    result={'schema':'ouf.acquisition-read-artifact-transport-result.v1','status':'EXACT_ARTIFACTS_DOWNLOADED_ON_EXISTING_RUNNER','complete':True,'caseHash':CASE_HASH,'downloadDirectory':str(root),'runnerUid':os.geteuid(),'artifacts':receipts,'githubApiGetAttempts':4,'rootStagingInvoked':False,'engineGetAttempts':0,'sqlSessions':0,'oufOAuthRequests':0,'serviceCredentialFilesOpened':0,'privateSigningKeysRead':0,'imageImports':0,'containerWrites':0,'runnerReinstalled':False,'runtimeAuthorityIssued':False,'runtimeEffectsDispatched':0,'targetApplyAuthorized':False,'applicationE2EProven':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False}
    put(root/'complete.json',result);fsync_directory(root);return result

def main():
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode and len(sys.argv)==3,'ISOLATED_TRANSPORT_CASE_AND_PARENT_REQUIRED')
        signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(Stop('FINITE_TRANSPORT_TIMEOUT')));signal.alarm(540)
        raw=Path(sys.argv[1]).read_bytes();require(len(raw)<=65536,'BOUNDED_CASE_REQUIRED');case=json.loads(raw,object_pairs_hook=unique)
        result=transport(case,Path(sys.argv[2]),os.environ.get('GH_TOKEN',''));print(json.dumps(result,sort_keys=True,separators=(',',':')));return 0
    except Exception as error:
        reason=str(error)if isinstance(error,Stop)and re.fullmatch('[A-Z0-9_]{1,120}',str(error))else'GITHUB_ARTIFACT_TRANSPORT_UNPROVEN'
        print(json.dumps({'schema':'ouf.acquisition-read-artifact-transport-result.v1','status':'STOP_RECONCILE','reasonCode':reason,'complete':False,'partialTransportMayExist':True,'rootStagingInvoked':False,'engineGetAttempts':0,'sqlSessions':0,'oufOAuthRequests':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False,'automaticReplayAllowed':False,'budgetReset':False},sort_keys=True,separators=(',',':')));return 2
    finally:signal.alarm(0)
if __name__=='__main__':raise SystemExit(main())
