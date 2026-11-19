"""Read-only bindings to completed draft and consumed history; no replay."""
import base64,copy,hashlib,json
from pathlib import Path
from tools.installation_binding_apply.baseline import read,parsed,write_new,strong_active
from tools.ingestion_read_owner_reference.owner import require,digest,DRAFT_HASH,CANDIDATE_HASH,ROUTES
DRAFT=Path('/etc/ouf/deploy-snapshots/ingestion-read-owner-draft-71atrj6k')
INPUT=Path('/etc/ouf/deploy-snapshots/ingestion-read-owner-inputs-z048j_zr')
INPUT_HASH='7b5d811ba31ab5899f969759eb5140c586785b1a17bdfe9287b6666ba788b314'
PREDECESSOR=Path('/etc/ouf/deploy-snapshots/installation-binding-apply-execution-w8nfc1ko')
PACKAGE_HASH='4b21a5733ccd6212432e3aa69dc08b8ad0f4f402d50044fa8c442da585130f82'
CLOSURE_HASH='1191c3817a2c152b4070ec9c946fae29746b6f2b155e54d9dba504e3803bd965'
def history():
 draft=parsed(DRAFT/'draft-plan.json',DRAFT_HASH);receipt=parsed(DRAFT/'preparation-result.json');inputs=parsed(INPUT/'inputs.json',INPUT_HASH)
 require(receipt['complete']is True and receipt['status']=='DRAFT_COMPILED_NO_AUTHORITY'and receipt['draftPlanHash']==DRAFT_HASH
  and receipt['contextPath']==str(DRAFT)and receipt['candidatePayloadChecksum']==CANDIDATE_HASH
  and receipt['candidateRootfsByteCustodyProven']is True and receipt['installedSqlResourceEqualityProven']is True
  and receipt['databaseAdmissionProven']is False and receipt['runtimeExecutorQualified']is False
  and receipt['runtimeAuthorityIssued']is False and receipt['oauthRequests']==0,'EXACT_COMPLETED_DRAFT_NO_AUTHORITY_REQUIRED')
 proof=parsed(draft['imageAndMigrationAuditBinding']['path'],draft['imageAndMigrationAuditBinding']['sha256'])
 require(proof['candidateImageImported']is False and proof['candidateJar']['migrationFilesUnchanged']is True
  and proof['installedJar']['migrationFilesUnchanged']is True and proof['databaseAdmissionProven']is False
  and draft['owner']['candidatePayloadChecksum']==CANDIDATE_HASH and draft['inputBinding']['sha256']==INPUT_HASH,'EXACT_COMPLETED_DRAFT_AUDIT_BINDINGS_REQUIRED')
 package=parsed(PREDECESSOR/'package.json',PACKAGE_HASH);require(digest(package['closure'])==CLOSURE_HASH,'EXACT_COMPLETED226_CLOSURE_REQUIRED')
 raw={n:read(PREDECESSOR/n,h)for n,h in package['fileHashes'].items()}
 sources={n:base64.b64decode(v,validate=True)for n,v in json.loads(raw['sources.json']).items()}
 require(len(sources)==226 and set(sources)==set(package['closure']['declaration']['sourceHashes'])
  and all(hashlib.sha256(v).hexdigest()==package['closure']['declaration']['sourceHashes'][n]for n,v in sources.items()),'EXACT_COMPLETED226_SOURCE_BYTES_REQUIRED')
 require(parsed(PREDECESSOR/'runtime.claim.json')=={'packageHash':PACKAGE_HASH,'automaticReplayAllowed':False},'CONSUMED_PREDECESSOR_MUST_NOT_BE_REPLAYED')
 prior=parsed(PREDECESSOR/'execution-plan.json');result=parsed(PREDECESSOR/'update-result.json')
 require(digest(result)=='032ed7f9f1de0be2760a79c5e36911f82e1385bf1a7c1287205fa4bd0fbeb387'and result['status']=='PUBLISHED_PROFILE_RECONCILED_AND_TWO_GATEWAY_ROUTES_COMPLETE'and result['complete']is True
  and result['oauthAttemptsAfter']==259 and result['maximumCumulativeOAuthAttempts']==264 and result['sourceActivated']is False
  and len(prior['gateway']['afterRoutes'])==82 and digest(prior['gateway']['afterRoutes'])==ROUTES,'EXACT_COMPLETED_ROUTE259_RESULT_REQUIRED')
 require(all(prior['currentApplications'][n]==v for n,v in draft['runtime']['expectedBindings'].items()),'RETAINED_RUNTIME_BINDINGS_MUST_MATCH_QUALIFIED_DRAFT')
 login=parsed(PREDECESSOR/'login-window-receipt.json');binding=prior['humanBinding']
 require(login['schema']=='ouf.installation-route-budget264-receipt.v1'and login['directory']==binding['sessionDirectory']
  and login['oauthAttemptsAfter']==259 and login['expiresAt']==binding['expiresAt']==1792436155
  and login['maximumCumulativeOAuthAttempts']==264 and login['budgetReset']is False,'EXACT_VERIFIED_PREDECESSOR264_HUMAN_BINDING_REQUIRED')
 return draft,inputs,prior,package,raw,sources,binding
