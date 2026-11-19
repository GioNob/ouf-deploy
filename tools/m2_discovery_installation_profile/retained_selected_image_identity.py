"""Bind one native OCI root to its unique classic/runtime image and exact bytes.

Other-platform and explicitly nonruntime manifest branches remain unadmitted.
Selected config/every layer/diff ID are mandatory; no extraction/import/fetch.
The archive/hash/TAR and layer checks reuse the frozen verifier's algorithms.
"""
import base64,gzip,hashlib,re,tarfile
from pathlib import PurePosixPath
from .custody_capture import decode,digest,require
from .retained_image_identity import VerificationBudget,LIMITS,SHA,IMAGE_TYPES,INDEX_TYPES,CONFIG_TYPES,LAYER_TYPES,ATTESTATION

def verified_selected_image(stream,expected_sha,expected_image,expected_bytes,expected_platform,budget):
    require(type(budget) is VerificationBudget and type(expected_bytes) is int
        and 0<expected_bytes<=LIMITS['maximumArchiveBytes'] and type(expected_sha) is str
        and re.fullmatch('[a-f0-9]{64}',expected_sha) and type(expected_image) is str
        and re.fullmatch(SHA,expected_image),'EXACT_PRIVATE_IMAGE_STREAM_BINDINGS_REQUIRED')
    require(type(expected_platform) is dict and set(expected_platform)=={'os','architecture'}
        and all(type(v) is str and re.fullmatch('[a-z0-9_.-]{1,32}',v) and v!='unknown'
            for v in expected_platform.values()),'EXACT_SELECTED_RUNTIME_PLATFORM_REQUIRED')
    def hashed(source,maximum,expanded=False):
        value=hashlib.sha256();size=0
        while True:
            budget.check();block=source.read(min(1048576,maximum-size+1))
            if not block:break
            size+=len(block);require(size<=maximum,'BOUNDED_PRIVATE_IMAGE_STREAM_REQUIRED')
            if expanded:budget.add_expanded(len(block))
            value.update(block)
        return value.hexdigest(),size
    stream.seek(0);actual,size=hashed(stream,LIMITS['maximumArchiveBytes'])
    require(actual==expected_sha and size==expected_bytes,'PRIVATE_IMAGE_ARCHIVE_BYTES_CHANGED');stream.seek(0)
    class BoundedInfo(tarfile.TarInfo):
        def _proc_member(self,tar):
            # Reject unsupported types and oversized extension bodies before
            # tarfile allocates PAX/GNU metadata, not after it yields a member.
            budget.check()
            extensions=(tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.SOLARIS_XHDTYPE,
                tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK)
            require(self.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE,*extensions)
                and (self.size<=131072 if self.type in extensions else self.size<=LIMITS['maximumArchiveBytes']),
                'BOUNDED_REGULAR_PRIVATE_TAR_HEADER_REQUIRED')
            return super()._proc_member(tar)
    with tarfile.open(fileobj=stream,mode='r:',tarinfo=BoundedInfo) as archive:
        members={}
        for row in archive:
            budget.check();name=row.name.rstrip('/') if row.isdir() else row.name;path=PurePosixPath(name)
            require(name and len(name)<=4096 and not path.is_absolute() and '..' not in path.parts
                and str(path)==name and name not in members and len(members)<LIMITS['maximumMembers']
                and (row.isfile() or row.isdir()) and 0<=row.size<=LIMITS['maximumArchiveBytes'],
                'SAFE_UNIQUE_REGULAR_PRIVATE_IMAGE_MEMBERS_REQUIRED')
            members[name]=row
        def member(name):
            require(type(name) is str and name in members and members[name].isfile(),
                'EXACT_PRIVATE_IMAGE_MEMBER_REQUIRED')
            return members[name]
        metadata_bytes=0
        def small(name,maximum):
            nonlocal metadata_bytes
            row=member(name);require(0<row.size<=maximum,'BOUNDED_PRIVATE_IMAGE_DOCUMENT_REQUIRED')
            metadata_bytes+=row.size
            require(metadata_bytes<=16777216,'BOUNDED_SELECTED_IMAGE_METADATA_REQUIRED')
            with archive.extractfile(row) as content:raw=content.read(maximum+1)
            require(len(raw)==row.size,'COMPLETE_PRIVATE_IMAGE_DOCUMENT_REQUIRED');budget.check()
            return raw,decode(raw)
        def blob(descriptor,maximum=2097152):
            require(type(descriptor) is dict and type(descriptor.get('digest')) is str
                and re.fullmatch(SHA,descriptor['digest']) and type(descriptor.get('size')) is int
                and 0<descriptor['size']<=maximum,'EXACT_SELECTED_IMAGE_DESCRIPTOR_REQUIRED')
            name='blobs/sha256/'+descriptor['digest'][7:];raw,value=small(name,maximum)
            require(len(raw)==descriptor['size'] and 'sha256:'+hashlib.sha256(raw).hexdigest()==descriptor['digest'],
                'SELECTED_IMAGE_DESCRIPTOR_CONTENT_DIGEST_DIFFERS')
            if 'data' in descriptor:
                data=descriptor['data']
                require(type(data) is str and len(data)<=maximum*4//3+4
                    and base64.b64decode(data,validate=True)==raw,'EXACT_SELECTED_INLINE_DESCRIPTOR_DATA_REQUIRED')
            return name,raw,value
        _,layout=small('oci-layout',131072);_,index=small('index.json',131072)
        require(type(layout) is dict and layout.get('imageLayoutVersion')=='1.0.0',
            'SELECTED_RUNTIME_OCI_LAYOUT_REQUIRED')
        classic_raw,classic=small('manifest.json',131072)
        require(type(classic) is list and len(classic)==1 and type(classic[0]) is dict
            and type(classic[0].get('Config')) is str and type(classic[0].get('Layers')) is list
            and len(classic[0]['Layers'])<=LIMITS['maximumLayers'],'EXACT_ONE_CLASSIC_RUNTIME_IMAGE_REQUIRED')
        classic=classic[0];member(classic['Config'])
        for name in classic['Layers']:member(name)
        nodes={};declared={};children={};seen=set()
        def visit(document,depth,parent=None):
            require(type(document) is dict and document.get('schemaVersion')==2
                and type(document.get('manifests')) is list and 1<=len(document['manifests'])<=64
                and depth<=LIMITS['maximumIndexDepth'],'BOUNDED_SELECTED_NATIVE_INDEX_REQUIRED')
            children[parent]=[]
            for descriptor in document['manifests']:
                budget.check()
                require(type(descriptor) is dict and descriptor.get('mediaType') in IMAGE_TYPES|INDEX_TYPES
                    and type(descriptor.get('digest')) is str and re.fullmatch(SHA,descriptor['digest'])
                    and type(descriptor.get('size')) is int and 0<descriptor['size']<=2097152,
                    'EXACT_SELECTED_NATIVE_INDEX_MEMBER_REQUIRED')
                address=descriptor['digest']
                require(address not in seen and len(seen)<LIMITS['maximumDescriptors'],
                    'UNIQUE_BOUNDED_SELECTED_NATIVE_GRAPH_REQUIRED')
                seen.add(address);declared[address]=descriptor;children[parent].append(address)
                if 'blobs/sha256/'+address[7:] not in members:continue
                _,_,node=blob(descriptor)
                require(type(node) is dict and node.get('schemaVersion')==2
                    and node.get('mediaType') in (None,descriptor['mediaType']),
                    'EXACT_SELECTED_NATIVE_DOCUMENT_REQUIRED')
                nodes[address]=(descriptor['mediaType'],node)
                if descriptor['mediaType'] in INDEX_TYPES:visit(node,depth+1,address)
        visit(index,0)
        require(expected_image in nodes,'EXACT_REQUESTED_NATIVE_DOCUMENT_MUST_BE_PRESENT')
        def descendants(address):
            return {address}|set().union(*(descendants(child) for child in children.get(address,[])))
        included=descendants(expected_image)
        def platform(desc):
            value=desc.get('platform')
            if value is None:return None
            require(type(value) is dict and all(type(value.get(k)) is str
                and re.fullmatch('[a-z0-9_.-]{1,32}',value[k]) for k in ('os','architecture')),
                'TYPED_SELECTED_NATIVE_PLATFORM_REQUIRED')
            return {k:value[k] for k in ('os','architecture')}
        def annotations(desc):
            value=desc.get('annotations') or {}
            require(type(value) is dict,'TYPED_SELECTED_NATIVE_ANNOTATIONS_REQUIRED');return value
        def is_auxiliary(address):
            desc=declared[address];node=nodes.get(address,(None,{}))[1]
            return annotations(desc).get('vnd.docker.reference.type')=='attestation-manifest' \
                or node.get('artifactType')==ATTESTATION
        def other_platform(desc):
            value=platform(desc)
            return value is not None and all(v!='unknown' for v in value.values()) and value!=expected_platform
        def auxiliary_target(address):
            desc=declared[address];node=nodes.get(address,(None,{}))[1];ann=annotations(desc)
            require(platform(desc)=={'os':'unknown','architecture':'unknown'} and is_auxiliary(address)
                and node.get('artifactType') in (None,ATTESTATION),
                'EXPLICIT_NONRUNTIME_NATIVE_BRANCH_REQUIRED')
            target=ann.get('vnd.docker.reference.digest');subject=node.get('subject')
            if subject is not None:
                require(type(subject) is dict and subject.get('mediaType') in IMAGE_TYPES
                    and type(subject.get('digest')) is str and re.fullmatch(SHA,subject['digest'])
                    and target in (None,subject['digest']),'EXACT_AUXILIARY_NATIVE_SUBJECT_REQUIRED')
                target=subject['digest']
            require(type(target) is str and target in included and target in declared
                and declared[target]['mediaType'] in IMAGE_TYPES and not is_auxiliary(target)
                and platform(declared[target]) is not None
                and all(v!='unknown' for v in platform(declared[target]).values()),
                'AUXILIARY_TARGET_MUST_BE_DECLARED_NONAUXILIARY_PLATFORM_MANIFEST')
            return target
        candidates=[]
        for address in sorted(included):
            if address not in nodes or nodes[address][0] not in IMAGE_TYPES or is_auxiliary(address):continue
            node=nodes[address][1];cfg=node.get('config');layers=node.get('layers')
            require(type(cfg) is dict and type(layers) is list and len(layers)<=LIMITS['maximumLayers']
                and all(type(row) is dict for row in layers),'TYPED_SELECTED_RUNTIME_MANIFEST_REQUIRED')
            if cfg.get('digest') is None or any(type(v.get('digest')) is not str for v in layers):continue
            if 'blobs/sha256/'+cfg['digest'][7:]==classic['Config'] \
                    and ['blobs/sha256/'+v['digest'][7:] for v in layers]==classic['Layers']:
                candidates.append(address)
        require(len(candidates)==1,'EXACT_UNIQUE_CLASSIC_AND_NATIVE_RUNTIME_BINDING_REQUIRED')
        manifest_digest=candidates[0];native=nodes[manifest_digest][1]
        require(platform(declared[manifest_digest]) in (None,expected_platform),
            'SELECTED_RUNTIME_DESCRIPTOR_PLATFORM_DIFFERS')
        omitted=[];present_unselected=0
        for address in sorted(included):
            desc=declared[address]
            if address==manifest_digest:continue
            if address in nodes and nodes[address][0] in INDEX_TYPES:continue
            require(desc['mediaType'] in IMAGE_TYPES,'MISSING_NATIVE_INDEX_CANNOT_BE_EXCLUDED')
            auxiliary=is_auxiliary(address)
            if auxiliary:target=auxiliary_target(address)
            else:
                require(other_platform(desc),'UNRESOLVED_OR_SELECTED_PLATFORM_BRANCH_CANNOT_BE_EXCLUDED')
                target=None
            if address not in nodes:
                omitted.append({'digest':address,'descriptorHash':digest(desc),'parentPlatform':platform(desc),
                    'classification':'AUXILIARY_NONRUNTIME' if auxiliary else 'OTHER_PLATFORM',
                    'target':target,'contentAvailable':False,'branchAdmitted':False})
            else:present_unselected+=1
        cfg=native.get('config',{})
        require(cfg.get('mediaType') in CONFIG_TYPES,'SELECTED_RUNTIME_CONFIGURATION_DESCRIPTOR_REQUIRED')
        config_name,config_raw,config=blob(cfg)
        require(type(config) is dict and all(config.get(k)==v for k,v in expected_platform.items())
            and type(config.get('config')) is dict,'EXACT_SELECTED_RUNTIME_CONFIGURATION_PLATFORM_REQUIRED')
        layer_descriptors=native.get('layers');layers=[]
        for row in layer_descriptors:
            require(type(row) is dict and row.get('mediaType') in LAYER_TYPES
                and type(row.get('digest')) is str and re.fullmatch(SHA,row['digest'])
                and type(row.get('size')) is int and row['size']>0,'EXACT_SELECTED_RUNTIME_LAYER_REQUIRED')
            name='blobs/sha256/'+row['digest'][7:]
            require(member(name).size==row['size'],'SELECTED_RUNTIME_LAYER_SIZE_CHANGED');layers.append(name)
        config_digest='sha256:'+hashlib.sha256(config_raw).hexdigest()
        root=config.get('rootfs',{});diffs=root.get('diff_ids')
        require(root.get('type')=='layers' and type(diffs) is list and len(layers)==len(diffs)
            and len(layers)<=LIMITS['maximumLayers'] and all(type(v) is str and re.fullmatch(SHA,v) for v in diffs),
            'EXACT_ORDERED_SELECTED_RUNTIME_ROOTFS_REQUIRED')
        proofs=[];expanded_total=0
        for index,(name,expected) in enumerate(zip(layers,diffs)):
            row=member(name)
            with archive.extractfile(row) as content:blob_hash,blob_bytes=hashed(content,LIMITS['maximumArchiveBytes'])
            if name.startswith('blobs/sha256/'):
                require(name=='blobs/sha256/'+blob_hash,'PRIVATE_LAYER_CONTENT_ADDRESS_CHANGED')
            with archive.extractfile(row) as content:
                magic=content.read(2);content.seek(0);compressed=magic==b'\x1f\x8b'
                if layer_descriptors is not None:
                    require(compressed==(layer_descriptors[index]['mediaType'].endswith('+gzip')
                        or layer_descriptors[index]['mediaType'].endswith('.gzip')),'PRIVATE_LAYER_COMPRESSION_DESCRIPTOR_CHANGED')
                if compressed:
                    with gzip.GzipFile(fileobj=content) as expanded:
                        actual,expanded_bytes=hashed(expanded,LIMITS['maximumExpandedImageBytes']-expanded_total,True)
                else:actual,expanded_bytes=hashed(content,LIMITS['maximumExpandedImageBytes']-expanded_total,True)
            require('sha256:'+actual==expected,'PRIVATE_EXPANDED_LAYER_DIFF_ID_CHANGED')
            expanded_total+=expanded_bytes;proofs.append({'blobSha256':blob_hash,'diffId':expected,
                'archiveBytes':blob_bytes,'expandedBytes':expanded_bytes})
        budget.check()
        return {'schema':'ouf.retained-selected-runtime-byte-identity.v1','requestedNativeDigest':expected_image,
            'requestedIdentityKind':'OCI_INDEX' if nodes[expected_image][0] in INDEX_TYPES else 'OCI_MANIFEST',
            'selectedRuntimeManifestDigest':manifest_digest,'selectedPlatform':expected_platform,
            'configurationDigest':config_digest,'archiveSha256':expected_sha,'archiveBytes':expected_bytes,
            'expandedBytes':expanded_total,'layerCount':len(proofs),'layersHash':digest(proofs),
            'executionConfigurationHash':digest(config['config']),'classicManifestHash':hashlib.sha256(classic_raw).hexdigest(),
            'nativeGraphBindingsHash':digest({a:declared[a] for a in sorted(included)}),
            'unavailableOtherPlatformManifests':sum(v['classification']=='OTHER_PLATFORM' for v in omitted),
            'unavailableAuxiliaryManifests':sum(v['classification']=='AUXILIARY_NONRUNTIME' for v in omitted),
            'unavailableBranchBindingsHash':digest(omitted),'presentNonselectedManifests':present_unselected,
            'selectedRuntimeBytesProven':True,'selectedRuntimeContentComplete':True,
            'completeIndexAccepted':False,'nonselectedBranchesAdmitted':False,'auxiliaryTrustAccepted':False,
            'sourcePublisherAuthenticated':False,'scanAdmissionProven':False,'runtimeAuthorityIssued':False,
            'targetApplyAuthorized':False,'releaseAcceptance':False}
