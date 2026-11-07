#!/usr/bin/env python3
"""One exact selected manifest lookup in the original MinIO registry; no fallback."""
import hashlib,importlib.util,json,os,resource,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
selected='sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2'
expected='sha256:69b2ec208575b69597784255eec6fa6a2985ee9e1a47f4411a51f7f5fdd193a9'
reference='quay.io/minio/minio@'+selected
MAXIMUM=2097152


def run():
    spec=importlib.util.spec_from_file_location('descriptor',ROOT/'scripts/read-m2-retained-vendor-descriptors-20261101.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    output=ROOT/'minio-selected-descriptor';output.mkdir(exist_ok=False)
    result={'schema':'ouf.m2-retained-minio-selected-descriptor.v1','reference':reference,
        'selectedRuntimeManifestDigest':selected,'expectedConfigurationDigest':expected,
        'exactSelectedDescriptorProven':False,'completeOriginalIndexProven':False,
        'repositoryFallbackUsed':False,'mutableTagUsed':False,'publisherAuthenticated':False,
        'lookupProcessInvocations':1,'targetCalls':0,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
    with tempfile.TemporaryDirectory(prefix='ouf-minio-public-') as isolated:
        with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
            try:
                process=subprocess.run(['/usr/bin/docker','--config',isolated,'buildx','imagetools','inspect','--raw',reference],
                    stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=45,preexec_fn=module.file_limit,
                    env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','DOCKER_CONFIG':isolated})
                module.require(process.returncode==0,'EXACT_SELECTED_MINIO_DESCRIPTOR_UNAVAILABLE')
                stdout.seek(0);raw=stdout.read(MAXIMUM+1)
                module.require(0<len(raw)<=MAXIMUM and 'sha256:'+hashlib.sha256(raw).hexdigest()==selected,'EXACT_SELECTED_MINIO_DESCRIPTOR_BYTES_REQUIRED')
                document=module.parse(raw);config,layers=module.manifest(document)
                module.require(config==expected,'MINIO_CONFIGURATION_DIFFERS_FROM_PRIVATE_RUNTIME_JOIN')
                (output/'selected.json').write_bytes(raw)
                result.update(status='EXACT_SELECTED_MINIO_DESCRIPTOR_VERIFIED',exactSelectedDescriptorProven=True,
                    layerCount=len(layers),descriptorBytes=len(raw),configurationDigest=config)
            except (ValueError,subprocess.TimeoutExpired) as error:
                code=str(error) if type(error) is ValueError else 'SELECTED_MINIO_DESCRIPTOR_TIMEOUT'
                result.update(status='UNRESOLVED_NOT_ADMITTED',reasonCode=code if code.isupper() and len(code)<=100 else 'SELECTED_MINIO_DESCRIPTOR_UNPROVEN')
    (output/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True))


if __name__=='__main__':run()
