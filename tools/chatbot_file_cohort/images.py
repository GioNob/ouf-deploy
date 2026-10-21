"""Exact five-image import using the existing one-use image custody owner."""
import copy
import hashlib
import os
from pathlib import Path
import stat
import subprocess

from image_custody import archive, tagless_archive, loaded, native_identity, runtime_image_id, unbound_audit
from image_import import Import
from engine_creation import Engine
from tools.semantic_policy_token_owner.owner_installation import AggregateAction
from tools.semantic_policy_token_owner.producer import protected_directory
from tools.semantic_lease_recovery.recovery_journal import Journal
from tools.chatbot_file_cohort.plan import MODULES, digest, require

IMAGE_MODULES = ('semantic', *MODULES)


def private_open(path, maximum=2147483648):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'EXACT_IMAGE_FILE_PATH_REQUIRED')
    with protected_directory(path.parent) as directory:
        fd = os.open(path.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and 0 < info.st_size <= maximum,
                'CUSTODIED_BOUNDED_IMAGE_FILE_REQUIRED')
        return os.fdopen(fd, 'rb')
    except Exception:
        os.close(fd)
        raise


def engine_image_profile(engine):
    code,info=engine.request('GET','/v1.44/info')
    require(code==200 and type(info)is dict,'CURRENT_NATIVE_IMAGE_STORE_REQUIRED')
    status=info.get('DriverStatus') or []
    require(type(status)is list and all(type(row)is list and len(row)==2 for row in status),
            'NATIVE_IMAGE_STORE_PROFILE_REQUIRED')
    containerd=info.get('Driver')=='overlayfs' and dict(status).get('driver-type')=='io.containerd.snapshotter.v1'
    classic=info.get('Driver')=='overlay2' and dict(status).get('driver-type')!='io.containerd.snapshotter.v1'
    require(containerd or classic,'QUALIFIED_NATIVE_IMAGE_STORE_REQUIRED')
    return {'profile':'CONTAINERD_MANIFEST' if containerd else 'CLASSIC_CONFIG',
        **{k:info.get(k) for k in ('ServerVersion','Driver','DriverStatus','CgroupDriver')}}


def prepare_imports(package_directory, manifest, output_directory, *, engine=None):
    """Private preparation only; no Docker load or daemon mutation."""
    package_directory, output_directory = Path(package_directory), Path(output_directory)
    rows = {r['module']:r for r in manifest['modules']}
    require(set(rows) == {'semantic','gateway',*MODULES}, 'ONE_COMPLETE_PACKAGE_REQUIRED')
    planned = []
    native_profile=engine_image_profile(engine) if engine is not None else None
    containerd=native_profile is not None and native_profile['profile']=='CONTAINERD_MANIFEST'
    with protected_directory(output_directory) as output:
        for module in IMAGE_MODULES:
            record = rows[module]
            require(record.get('artifactKind') == 'DOCKER_SAVE'
                    and record.get('scanGate') == 'PASS_HIGH_CRITICAL_UNKNOWN_INCLUDING_UNFIXED',
                    'EXACT_QUALIFIED_IMAGE_RECORD_REQUIRED')
            source = package_directory/module/'image.docker.tar'
            destination = output_directory/(module+'.tagless.tar')
            with private_open(source) as raw:
                original = archive(raw, record['files']['image.docker.tar'], record['imageId'], record['sourceCommit'])
                fd = os.open(destination.name, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=output)
                with os.fdopen(fd, 'w+b') as derived:
                    derivation = tagless_archive(raw, derived, original,containerd=containerd)
                    os.fsync(derived.fileno())
                    audit = archive(derived, derivation['derivedArchiveSha256'], record['imageId'], record['sourceCommit'])
            require(not audit['repositoryTags'], 'TAG_MUTATION_NOT_AUTHORIZED')
            if containerd:audit['nativeIdentity']=native_identity(audit)
            planned.append({'module':module, 'archivePath':str(destination), 'audit':audit,
                'originalArchiveSha256':original['archiveSha256'],
                'modulePackageHash':digest({k:v for k,v in record.items() if k != 'files'})})
        os.fsync(output)
    result={'schema':'ouf.chatbot-cohort-image-import-plan.v1', 'cohortManifestHash':digest(manifest),
        'images':planned, 'maximumImportSecondsPerImage':180, 'maximumImportAttemptsPerImage':1,
        'retagAllowed':False, 'automaticReplayAllowed':False, 'runtimeAuthorityIssued':False}
    if native_profile is not None:result['nativeEngineProfile']=native_profile
    return result


def image_import_scope(plan):
    require(plan.get('schema') == 'ouf.chatbot-cohort-image-import-plan.v1'
            and [r['module'] for r in plan['images']] == list(IMAGE_MODULES)
            and plan['maximumImportSecondsPerImage'] == 180 and plan['maximumImportAttemptsPerImage'] == 1
            and plan['retagAllowed'] is False and plan['automaticReplayAllowed'] is False,
            'EXACT_FIVE_IMAGE_IMPORT_PLAN_REQUIRED')
    return {'profile':'ouf.chatbot-cohort-five-image-import.v1','planHash':digest(plan),
        'cohortManifestHash':plan['cohortManifestHash'], 'imageCount':5,
        'maximumImportAttemptsPerImage':1,'maximumImportSecondsPerImage':180,
        'retagAllowed':False,'automaticReplayAllowed':False}


class CohortImages:
    def __init__(self, action, engine, plan, journals, docker_binding):
        require(type(action) is AggregateAction and type(engine) is Engine
                and set(journals) == set(IMAGE_MODULES) and all(type(j) is Journal for j in journals.values()),
                'REAL_FIVE_IMAGE_IMPORT_OWNERS_REQUIRED')
        self.action,self.engine,self.plan,self.journals = action,engine,copy.deepcopy(plan),journals
        self.scope,self.docker = image_import_scope(plan),copy.deepcopy(docker_binding)
        require(set(self.docker) == {'path','sha256'}, 'EXACT_IMAGE_DOCKER_EXECUTABLE_REQUIRED')

    def guard(self, phase=None):
        require(image_import_scope(self.plan) == self.scope, 'IMAGE_IMPORT_INTENT_DRIFT')
        self.action.guard('cohortImageImport', self.scope)
        self.engine.check_socket()
        if 'nativeEngineProfile' in self.plan:
            require(engine_image_profile(self.engine)==self.plan['nativeEngineProfile'],'NATIVE_IMAGE_STORE_CHANGED')
        path = Path(self.docker['path']); info = path.lstat()
        require(path.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022 and hashlib.sha256(path.read_bytes()).hexdigest() == self.docker['sha256'],
                'IMAGE_IMPORT_DOCKER_EXECUTABLE_DRIFT')
        return self.action.authority_hash

    def inspect(self, image_id):
        self.guard()
        code, value = self.engine.request('GET','/v1.44/images/'+image_id+'/json')
        require(code in (200,404), 'CURRENT_NATIVE_IMAGE_READ_REQUIRED')
        return value if code == 200 else None

    def initialize(self):
        self.guard()
        for row in self.plan['images']:
            self.journals[row['module']].initialize(Import.initial(row['audit'],self.action.authority_hash))

    def load(self, row):
        self.guard()
        with private_open(row['archivePath']) as source:
            require(archive(source,row['audit']['archiveSha256'],row['audit']['imageId'],row['audit']['sourceCommit']) == unbound_audit(row['audit']),
                    'CURRENT_IMAGE_ARCHIVE_CUSTODY_DRIFT')
            require(not row['audit']['repositoryTags'], 'TAG_MUTATION_NOT_AUTHORIZED')
            source.seek(0)
            self.guard()
            result = subprocess.run([self.docker['path'],'--host','unix://'+self.engine.path,
                '--config',str(self.journals[row['module']].root),'load'],
                stdin=source,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                timeout=self.plan['maximumImportSecondsPerImage'])
            require(result.returncode == 0, 'IMAGE_IMPORT_OUTCOME_REQUIRES_RECONCILIATION')
        self.guard()

    def apply(self):
        self.guard()
        evidence = []
        for row in self.plan['images']:
            journal = self.journals[row['module']]
            initial = Import.initial(row['audit'],self.action.authority_hash)
            owner = Import(journal,initial['contextHash'])
            with owner.invocation():
                state = owner.read(row['audit'])
                if state['state'] == 'READY':
                    proof = owner.import_once(row['audit'],lambda:self.load(row),self.inspect,self.guard)
                elif state['state'] == 'IN_FLIGHT':
                    proof = owner.reconcile(row['audit'],self.inspect,self.guard)
                else:
                    proof = loaded(row['audit'],self.inspect(runtime_image_id(row['audit'])))
                    require(digest(proof) == state['nativeEvidenceHash'], 'VERIFIED_IMAGE_EVIDENCE_DRIFT')
                evidence.append({'module':row['module'],'evidenceHash':digest(proof)})
        return {'schema':'ouf.chatbot-cohort-image-import-receipt.v1','planHash':digest(self.plan),
            'images':evidence,'runtimeAuthorityIssued':False,'notReleaseAcceptance':True}
