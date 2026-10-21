"""Exact native identity rebase after protected V11 byte-custody reconciliation.

Pure review transformation. Caller authenticates original publisher, private
journal/context and live generations. No hash or plan confers apply authority.
"""
import copy,hashlib,json
CONFIG='sha256:83635be46d1fe61dea08597ea4488980b4349e5f6e0ed8bbd3ab6f5e2686370e'
NATIVE='sha256:bd48ab35db0441b1f4f48422e7190adaff176a61cddde5f981d93e496ad4b24a'
SOURCE='8a2e84b32d4ce2bdc3bc529b56afb5663ab133e3'
ZIP='b6ae1051cee4ec9fb1b28f532622ecd39e038ec2e6a384d50565cbf92f2a0def'
ARCHIVE='52baabdfd39189c598a9ded3aeec08367d20ae2fccbf14330481c98f1ad7783f'
DECL='ffc02da66a08fb1f1b06c143ef0f2aa18d68a6fb7b2bfaa616a812aa37eabe0f'
REQUEST='798de748a4fcc0d8c2b6eb70f3577430d690729a4a03bc00ebbf3adcae765836'
DESCRIPTOR={'mediaType':'application/vnd.docker.distribution.manifest.v2+json','digest':NATIVE,'size':1845}
CONFIG_PROJECTION='52d4e0beabafa92afc603a5cd1fc9e226a367b5d0cc139db1fb27bb75880cd6b'
ROOTFS='11ef2e90fcd021cdcd0a06bf3ab5b0fb3d645b8f575d71affef3f5fb1960d775'
FIELDS=('User','Entrypoint','Cmd','Env','WorkingDir','Labels','Volumes','ExposedPorts','StopSignal','Healthcheck','Shell')
def require(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def native_proof(native):
 require(type(native) is dict and native.get('Id')==NATIVE and native.get('Descriptor')==DESCRIPTOR,
  'EXACT_RECONCILED_MANIFEST_IDENTITY_REQUIRED')
 require(native.get('Os')=='linux' and native.get('Architecture')=='amd64' and not native.get('RepoTags'),
  'EXACT_RECONCILED_PLATFORM_AND_TAGLESS_REQUIRED')
 require(type(native.get('Config')) is dict and digest({k:native['Config'].get(k) for k in FIELDS})==CONFIG_PROJECTION,
  'EXACT_RECONCILED_EXECUTION_CONFIG_REQUIRED')
 require(digest(native.get('RootFS'))==ROOTFS,'EXACT_RECONCILED_ROOTFS_REQUIRED')
 # Exact shape/digests were byte-derived and recorded by the sealed reconciler.
 # Return that same proof; the protected journal must contain its exact digest.
 return {'schema':'ouf.native-manifest-image-byte-custody.v1','configImageId':CONFIG,
  'nativeEngineImageId':NATIVE,'manifestDescriptor':copy.deepcopy(DESCRIPTOR),'sourceCommit':SOURCE,
  'archiveSha256':ARCHIVE,'rootfsLayerCount':10,'nativeConfigProjectionHash':CONFIG_PROJECTION,
  'nativeRootfsHash':ROOTFS,'imageByteCustodyProven':True,'completeContainerOciProven':False,
  'transportClosureProven':False,'targetApplyAuthorized':False}
def verified_record(row,proof,expected_context):
 require(type(row) is dict and row.get('schema')=='ouf.image-import-journal.v1'
  and row.get('state')=='VERIFIED' and row.get('version')==2 and row.get('effectAttemptCount')==1
  and row.get('imageCustodyProven') is True and row.get('automaticReplayAllowed') is False
  and row.get('contextHash')==expected_context
  and row.get('intent')=={'imageId':CONFIG,'sourceCommit':SOURCE,'archiveSha256':ARCHIVE}
  and row.get('nativeEvidenceHash')==digest(proof),'EXACT_VERIFIED_IMPORT_HISTORY_REQUIRED')
def rebase(declaration,request,row,proof,expected_context,expected_declaration=DECL,expected_request=REQUEST):
 require(digest(declaration)==expected_declaration and digest(request)==expected_request,'EXACT_PREPARED_V11_PLAN_REQUIRED')
 require(declaration.get('schema')=='ouf.discovery.private-file-secret-runtime-declaration.v1'
  and declaration.get('candidateImageId')==CONFIG and request.get('Image')==CONFIG
  and all(declaration.get(k) is False for k in ('productionApplyReady','applicationCutoverAuthorized','completeReplacementOciProven'))
  and 'nativeImageBinding' not in declaration,'EXACT_UNAPPLIED_CONFIG_ID_PLAN_REQUIRED')
 binding=declaration.get('qualifiedPackageBinding',{})
 require(binding.get('sourceCommit')==SOURCE and binding.get('zipSha256')==ZIP and binding.get('imageId')==CONFIG,
  'ORIGINAL_PUBLISHER_BINDING_REQUIRED')
 verified_record(row,proof,expected_context)
 require(proof=={'schema':'ouf.native-manifest-image-byte-custody.v1','configImageId':CONFIG,
  'nativeEngineImageId':NATIVE,'manifestDescriptor':DESCRIPTOR,'sourceCommit':SOURCE,
  'archiveSha256':ARCHIVE,'rootfsLayerCount':10,'nativeConfigProjectionHash':CONFIG_PROJECTION,
  'nativeRootfsHash':ROOTFS,'imageByteCustodyProven':True,'completeContainerOciProven':False,
  'transportClosureProven':False,'targetApplyAuthorized':False},'EXACT_RECONCILED_PROOF_REQUIRED')
 following=copy.deepcopy(declaration);new_request=copy.deepcopy(request)
 following['candidateImageId']=NATIVE;new_request['Image']=NATIVE
 following['nativeImageBinding']={'schema':'ouf.native-manifest-image-binding.v1','configImageId':CONFIG,
  'nativeEngineImageId':NATIVE,'manifestDescriptor':copy.deepcopy(DESCRIPTOR),'sourceCommit':SOURCE,
  'originalZipSha256':ZIP,'derivedArchiveSha256':ARCHIVE,'importJournalContextHash':expected_context,
  'importJournalVersion':2,'nativeEvidenceHash':row['nativeEvidenceHash'],
  'predecessorDeclarationHash':expected_declaration,'predecessorCreationRequestHash':expected_request,
  'imageByteCustodyProven':True,'containerRuntimeCustodyProven':False,'applicationCutoverAuthorized':False}
 require({k:v for k,v in following.items() if k not in ('candidateImageId','nativeImageBinding')}
  =={k:v for k,v in declaration.items() if k!='candidateImageId'}
  and {k:v for k,v in new_request.items() if k!='Image'}=={k:v for k,v in request.items() if k!='Image'},
  'ONLY_EXACT_NATIVE_IDENTITY_DELTA_ALLOWED')
 return following,new_request
