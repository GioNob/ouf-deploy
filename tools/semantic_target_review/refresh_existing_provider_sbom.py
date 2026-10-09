"""CI-only fresh vulnerability evidence from unchanged, signed existing SBOMs.

No image build/import, Docker, target inputs, authority keys or target grants.
The new DB is discovered, frozen, checksum verified and scanned offline.
"""
import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile

SEMANTIC = Path(sys.argv[1]).resolve()
sys.path.insert(0,str(SEMANTIC))
from tools import review_semantic_image_vulnerabilities as reviewer
from tools import prepare_semantic_image_sbom as sbom

OLD_SIDECAR_SHA = 'a23ee77e6f2e21fc9a7ca1beb144d11f22228cc801693cac5fad47ee30e863ea'
ORIGINAL_ARTIFACT_SHA = '2cdd7a73c1fc2a710f1e6604eb6cab2988492e4c45b5252defffa9832b91d9d0'
OLD_INVENTORY_SHA = '1024e4f3e53664afe7a20de6760388308f80f640f8e420acfea675b45c579c55'
ROOT = Path('/root/ouf-ci-vulnerability')
OUT = Path('generated/provider-v2-fresh-existing-sbom').resolve()

def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def require(v,reason):
    if not v:raise RuntimeError(reason)
def fetch(url,limit):
    request=urllib.request.Request(url,headers={'User-Agent':'grype 0.120.0'})
    with urllib.request.urlopen(request,timeout=30) as response:
        require(response.geturl().startswith('https://'),'PUBLIC_DOWNLOAD_HTTPS_REQUIRED')
        raw=response.read(limit+1)
    require(0<len(raw)<=limit,'PUBLIC_DOWNLOAD_BOUND_EXCEEDED')
    return raw
def run(argv,**kwargs):
    return subprocess.run(argv,stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        timeout=180,check=True,**kwargs)

require(os.geteuid()==0,'ROOT_CI_SCANNER_REQUIRED')
os.umask(0o077)
OUT.mkdir(parents=True,mode=0o700)
ROOT.mkdir(mode=0o700)
old=run(['gh','api','repos/GioNob/ouf-semantic-registry/actions/artifacts/11478662099/zip'],stdout=subprocess.PIPE).stdout
require(len(old)<=16777216 and sha(old)==OLD_SIDECAR_SHA,'EXACT_EXISTING_SIGNED_SIDECAR_REQUIRED')
sidecar=ROOT/'existing-sidecar';sidecar.mkdir(mode=0o700)
with zipfile.ZipFile(io.BytesIO(old)) as archive:
    members=archive.infolist()
    require(len(members)<=64 and sum(i.file_size for i in members)<=134217728,'SIDECAR_EXTRACTION_BOUND_EXCEEDED')
    for item in members:
        if item.is_dir():continue
        require(Path(item.filename).name==item.filename and item.file_size<=67108864,'FLAT_EXISTING_SIDECAR_REQUIRED')
        (sidecar/item.filename).write_bytes(archive.read(item))
subjects=('inventory.json','adapter.extended.syft.json','southbound.extended.syft.json',
          'adapter.extended.grype.json','southbound.extended.grype.json')
for name in subjects:
    with (OUT/('previous-'+name+'.verification.json')).open('wb') as output:
        run(['gh','attestation','verify',str(sidecar/name),'--repo','GioNob/ouf-semantic-registry',
            '--signer-workflow','GioNob/ouf-semantic-registry/.github/workflows/semantic-extended-dependency-inventory.yml',
            '--source-digest','00ba8b2ca6caf01902943b6d8d3dba60c00df6a9','--deny-self-hosted-runners',
            '--bundle',str(sidecar/'provenance.json'),'--format','json'],stdout=output)
require(sha((sidecar/'inventory.json').read_bytes())==OLD_INVENTORY_SHA,'EXACT_PREVIOUS_INVENTORY_REQUIRED')
inventory=json.loads((sidecar/'inventory.json').read_bytes())
listing=fetch('https://grype.anchore.io/databases/v6/latest.json',65536)
latest=json.loads(listing)
require(type(latest) is dict,'EXACT_DATABASE_LISTING_OBJECT_REQUIRED')
pin=reviewer.database_pin(latest)
now=datetime.datetime.now(datetime.timezone.utc).timestamp()
built=datetime.datetime.fromisoformat(pin['built'].replace('Z','+00:00')).timestamp()
require(0<=now-built<=86400,'REFRESH_DATABASE_MUST_HAVE_AT_LEAST_24_HOURS_REMAINING')
(OUT/'database-listing.json').write_bytes(listing)
(OUT/'database-pin.json').write_bytes(canonical(pin))
reviewer.scanner_from_archive(fetch('https://github.com/anchore/grype/releases/download/v0.120.0/grype_0.120.0_linux_amd64.tar.gz',reviewer.LIMIT),ROOT/'grype')
database=ROOT/'database.tar.zst'
run(['/usr/bin/curl','--fail','--silent','--show-error','--location','--proto','=https','--tlsv1.2',
    '--max-time','180','--max-filesize','1073741824','--user-agent','grype 0.120.0',
    'https://grype.anchore.io/databases/v6/'+pin['path'],'--output',str(database)],stdout=subprocess.DEVNULL)
database.chmod(0o600);reviewer.hash_file(database,pin['checksum'][7:],1073741824)
(ROOT/'database-pin.json').write_bytes(canonical(pin))
scans=[]
for role in ('adapter','southbound'):
    raw=(sidecar/(role+'.extended.syft.json')).read_bytes()
    (OUT/(role+'.extended.syft.json')).write_bytes(raw)
    with (OUT/(role+'.extended.grype.json')).open('wb') as output:
        run([sys.executable,'-B',str(SEMANTIC/'tests/scan_semantic_extended_inventory.py'),
            '--sbom',str(OUT/(role+'.extended.syft.json'))],stdout=output)
    report_raw=(OUT/(role+'.extended.grype.json')).read_bytes()
    report=json.loads(report_raw)
    require(not report.get('ignoredMatches'),'IGNORED_MATCHES_NOT_ALLOWED')
    counts={k:0 for k in ('Critical','High','Medium','Low','Negligible','Unknown')}
    for match in report['matches']:counts[match['vulnerability']['severity']]+=1
    scans.append({'role':role,'severityCounts':counts,'scannerSeverityThresholdMet':
        not any(counts[k] for k in ('Critical','High','Unknown')) and not report.get('alertsByPackage'),
        'reportSha256':sha(report_raw),'unchangedSbomSha256':sha(raw)})
inventory.update(databasePin=pin,scannerInvoked=True,networkIsolatedScanner=True,scans=scans,
    allScannerSeverityThresholdsMet=all(s['scannerSeverityThresholdMet'] for s in scans),
    refreshSourceSidecarSha256=OLD_SIDECAR_SHA,sourceArtifactSha256=ORIGINAL_ARTIFACT_SHA,
    acceptanceGranted=False,startAuthorized=False,imagesModified=False,notReleaseAcceptance=True)
(OUT/'inventory.json').write_bytes(canonical(inventory))
sums=[sha(p.read_bytes())+'  '+str(p.relative_to(Path.cwd())) for p in sorted(OUT.iterdir()) if p.is_file()]
(OUT/'checksums.sha256').write_text('\n'.join(sums)+'\n')
print('OUF_EXISTING_SBOM_FRESH_SCAN='+json.dumps({'databasePin':pin,'scans':scans,
    'imagesModified':False,'targetOperations':0,'acceptanceGranted':False,'startAuthorized':False},sort_keys=True))
require(inventory['allScannerSeverityThresholdsMet'],'FRESH_SCAN_REQUIRES_VULNERABILITY_REVIEW')
