"""Diagnose archive reference presence; never admit an incomplete image.

Read only the retained TAR and bounded index/manifest JSON. Configuration and
layer bodies are not opened. Missing references stay absent, never fetched or
silently accepted. Full names/digests/descriptor values stay in private evidence.
"""
import base64,hashlib,re,tarfile
from collections import Counter
from pathlib import PurePosixPath
from .custody_capture import decode,require
from .retained_image_identity import (VerificationBudget,LIMITS,SHA,IMAGE_TYPES,INDEX_TYPES,
    CONFIG_TYPES,EMPTY,EMPTY_DIGEST,ATTESTATION)

GRAPH_LIMITS={'schema':'ouf.retained-image-graph-diagnostic-limits.v1',
    'maximumSeconds':600,'maximumMembers':2048,'maximumDocuments':256,
    'maximumReferences':1024,'maximumIndexDepth':4,'maximumDocumentBytes':2097152,
    'maximumMetadataBytesPerImage':16777216,'maximumClassicManifests':64,
    'maximumArchiveBytes':2147483648,'maximumArchiveSetBytes':8589934592,
    'maximumEngineGets':0,'maximumConfigurationMembersOpened':0,'maximumLayerMembersOpened':0,
    'maximumExpandedLayerBytes':0}


def platform_class(value):
    if type(value) is not dict:return 'UNSPECIFIED'
    if value.get('os')==value.get('architecture')=='unknown':return 'UNKNOWN_NONRUNTIME'
    if value.get('os')=='linux' and value.get('architecture')=='amd64':return 'LINUX_AMD64'
    if type(value.get('os')) is str and type(value.get('architecture')) is str:
        return 'EXPLICIT_OTHER_PLATFORM'
    return 'UNSPECIFIED'


def inspect_graph(stream,archive_sha,requested_image,expected_bytes,budget):
    require(type(budget) is VerificationBudget and type(expected_bytes) is int
        and 0<expected_bytes<=GRAPH_LIMITS['maximumArchiveBytes']
        and type(archive_sha) is str and re.fullmatch('[a-f0-9]{64}',archive_sha)
        and type(requested_image) is str and re.fullmatch(SHA,requested_image),
        'EXACT_PRIVATE_GRAPH_ARCHIVE_BINDINGS_REQUIRED')
    stream.seek(0);hasher=hashlib.sha256();total=0
    while True:
        budget.check();block=stream.read(min(1048576,expected_bytes-total+1))
        if not block:break
        total+=len(block);require(total<=expected_bytes,'BOUNDED_PRIVATE_GRAPH_ARCHIVE_REQUIRED')
        hasher.update(block)
    require(total==expected_bytes and hasher.hexdigest()==archive_sha,'PRIVATE_GRAPH_ARCHIVE_BYTES_CHANGED')
    stream.seek(0)
    class BoundedInfo(tarfile.TarInfo):
        def _proc_member(self,archive):
            budget.check();extensions=(tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.SOLARIS_XHDTYPE,
                tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_LONGLINK)
            require(self.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE,*extensions)
                and 0<=self.size<=(131072 if self.type in extensions else GRAPH_LIMITS['maximumArchiveBytes']),
                'BOUNDED_REGULAR_PRIVATE_GRAPH_TAR_HEADER_REQUIRED')
            return super()._proc_member(archive)
    with tarfile.open(fileobj=stream,mode='r:',tarinfo=BoundedInfo) as archive:
        members={};metadata_bytes=0;documents={};references=[];runtime_manifests={}
        for row in archive:
            budget.check();name=row.name.rstrip('/') if row.isdir() else row.name;p=PurePosixPath(name)
            require(name and len(name)<=4096 and not p.is_absolute() and '..' not in p.parts
                and str(p)==name and name not in members and len(members)<GRAPH_LIMITS['maximumMembers']
                and (row.isfile() or row.isdir()) and 0<=row.size<=GRAPH_LIMITS['maximumArchiveBytes'],
                'SAFE_UNIQUE_PRIVATE_GRAPH_TAR_MEMBERS_REQUIRED')
            members[name]=row
        def safe_name(name):
            require(type(name) is str and name and len(name)<=4096 and str(PurePosixPath(name))==name
                and not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,
                'SAFE_PRIVATE_GRAPH_REFERENCED_PATH_REQUIRED')
            return name
        def document(name):
            nonlocal metadata_bytes
            if name in documents:return documents[name]
            budget.check();row=members.get(name)
            require(row is not None and row.isfile() and 0<row.size<=GRAPH_LIMITS['maximumDocumentBytes']
                and len(documents)<GRAPH_LIMITS['maximumDocuments'],'BOUNDED_PRIVATE_GRAPH_DOCUMENT_REQUIRED')
            metadata_bytes+=row.size
            require(metadata_bytes<=GRAPH_LIMITS['maximumMetadataBytesPerImage'],'BOUNDED_PRIVATE_GRAPH_METADATA_REQUIRED')
            with archive.extractfile(row) as content:raw=content.read(row.size+1)
            require(len(raw)==row.size,'COMPLETE_PRIVATE_GRAPH_DOCUMENT_REQUIRED')
            value=decode(raw);documents[name]=(raw,value);return raw,value
        def reference(desc,context,platform,parent,depth,*,walk=False,ancestors=()):
            require(type(desc) is dict and type(desc.get('digest')) is str
                and re.fullmatch(SHA,desc['digest']) and type(desc.get('size')) is int
                and 0<desc['size']<=GRAPH_LIMITS['maximumArchiveBytes']
                and type(desc.get('mediaType')) is str and len(desc['mediaType'])<=256
                and len(references)<GRAPH_LIMITS['maximumReferences'],'BOUNDED_PRIVATE_GRAPH_DESCRIPTOR_REQUIRED')
            budget.check();name='blobs/sha256/'+desc['digest'][7:];row=members.get(name)
            present=row is not None
            if present:
                require(row.isfile() and row.size==desc['size'],'PRIVATE_GRAPH_DESCRIPTOR_MEMBER_SIZE_DIFFERS')
                state='PRESENT_METADATA_ONLY'
            else:
                canonical=context=='ATTESTATION_CONFIG' and desc['mediaType']==EMPTY \
                    and desc['digest']==EMPTY_DIGEST and desc['size']==2 \
                    and ('data' not in desc or desc['data']=='e30=')
                state='ABSENT_CANONICAL_EMPTY_CONFIG' if canonical else 'ABSENT'
            info={'descriptor':desc,'context':context,'platformClass':platform,'parentDigest':parent,
                'member':name,'state':state,'inlineDataPresent':'data' in desc,'depth':depth}
            references.append(info)
            if not walk or not present:return
            require(desc['mediaType'] in INDEX_TYPES|IMAGE_TYPES and depth<=GRAPH_LIMITS['maximumIndexDepth']
                and desc['digest'] not in ancestors,'BOUNDED_ACYCLIC_PRIVATE_GRAPH_REQUIRED')
            raw,node=document(name)
            require(hashlib.sha256(raw).hexdigest()==desc['digest'][7:]
                and type(node) is dict and node.get('schemaVersion')==2
                and node.get('mediaType') in (None,desc['mediaType']),
                'PRIVATE_GRAPH_DOCUMENT_DIGEST_OR_MEDIA_DIFFERS')
            if 'data' in desc:
                require(type(desc['data']) is str and len(desc['data'])<=GRAPH_LIMITS['maximumDocumentBytes']*4//3+4
                    and base64.b64decode(desc['data'],validate=True)==raw,'PRIVATE_GRAPH_INLINE_DOCUMENT_DIFFERS')
            info['state']='PRESENT_DOCUMENT_DIGEST_VERIFIED'
            walk_node(node,desc['digest'],desc['mediaType'],depth,(*ancestors,desc['digest']),desc)
        def walk_node(node,parent,media,depth,ancestors,descriptor):
            if media in INDEX_TYPES:
                children=node.get('manifests')
                require(type(children) is list and 1<=len(children)<=GRAPH_LIMITS['maximumReferences'],
                    'BOUNDED_PRIVATE_GRAPH_INDEX_REQUIRED')
                for child in children:
                    require(type(child) is dict,'TYPED_PRIVATE_GRAPH_INDEX_MEMBER_REQUIRED')
                    reference(child,'INDEX_MEMBER',platform_class(child.get('platform')),parent,depth+1,
                        walk=True,ancestors=ancestors)
                return
            annotations=descriptor.get('annotations') or {}
            require(type(annotations) is dict,'TYPED_PRIVATE_GRAPH_ANNOTATIONS_REQUIRED')
            auxiliary=annotations.get('vnd.docker.reference.type')=='attestation-manifest' \
                or node.get('artifactType')==ATTESTATION
            platform=platform_class(descriptor.get('platform'));cfg=node.get('config')
            reference(cfg,'ATTESTATION_CONFIG' if auxiliary else 'RUNTIME_CONFIG',platform,parent,depth)
            layers=node.get('layers')
            require(type(layers) is list and len(layers)<=LIMITS['maximumLayers'],'BOUNDED_PRIVATE_GRAPH_LAYERS_REQUIRED')
            for layer in layers:reference(layer,'ATTESTATION_LAYER' if auxiliary else 'RUNTIME_LAYER',platform,parent,depth)
            subject=node.get('subject')
            if subject is not None:reference(subject,'SUBJECT',platform,parent,depth)
            if not auxiliary:runtime_manifests[parent]=node
        classic=[]
        if 'manifest.json' in members:
            _,classic=document('manifest.json')
            require(type(classic) is list and 1<=len(classic)<=GRAPH_LIMITS['maximumClassicManifests'],
                'BOUNDED_PRIVATE_CLASSIC_GRAPH_MANIFEST_REQUIRED')
            for item in classic:
                require(type(item) is dict and type(item.get('Layers')) is list
                    and len(item['Layers'])<=LIMITS['maximumLayers'],'TYPED_PRIVATE_CLASSIC_GRAPH_ROW_REQUIRED')
                safe_name(item.get('Config'))
                for name in item['Layers']:safe_name(name)
        layout_kind='CLASSIC'
        if 'index.json' in members:
            layout_kind='OCI';_,layout=document('oci-layout');_,root=document('index.json')
            require(type(layout) is dict and layout.get('imageLayoutVersion')=='1.0.0'
                and type(root) is dict and root.get('schemaVersion')==2,'PRIVATE_GRAPH_OCI_LAYOUT_REQUIRED')
            walk_node(root,None,'application/vnd.oci.image.index.v1+json',0,(),{})
        else:require(classic,'PRIVATE_GRAPH_OCI_OR_CLASSIC_MANIFEST_REQUIRED')
        classic_refs=[];classic_matches=[]
        for item in classic:
            for context,name in [('CLASSIC_CONFIG',item['Config']),*[( 'CLASSIC_LAYER',v) for v in item['Layers']]]:
                row=members.get(name)
                require(row is None or row.isfile(),'REGULAR_PRIVATE_CLASSIC_GRAPH_MEMBER_REQUIRED')
                classic_refs.append({'context':context,'member':name,'state':'ABSENT' if row is None else 'PRESENT_METADATA_ONLY'})
            for address,node in runtime_manifests.items():
                cfg='blobs/sha256/'+node['config']['digest'][7:]
                layers=['blobs/sha256/'+v['digest'][7:] for v in node['layers']]
                if cfg==item['Config'] and layers==item['Layers']:classic_matches.append(address)
        missing=[r for r in references if r['state'].startswith('ABSENT')]
        def media_class(media):
            if media in INDEX_TYPES:return 'IMAGE_INDEX'
            if media in IMAGE_TYPES:return 'IMAGE_MANIFEST'
            if media in CONFIG_TYPES:return 'IMAGE_CONFIGURATION'
            if media==EMPTY:return 'OCI_EMPTY'
            if media=='application/vnd.in-toto+json':return 'ATTESTATION_BLOB'
            if media.startswith('application/vnd.oci.image.layer.') or media.startswith('application/vnd.docker.image.rootfs.'):
                return 'IMAGE_LAYER'
            return 'OTHER'
        groups=Counter((r['context'],r['platformClass'],r['state'],media_class(r['descriptor']['mediaType']),
            r['inlineDataPresent']) for r in missing)
        context_counts=Counter(r['context'] for r in missing)
        public={'layoutKind':layout_kind,'archiveBytesHashed':total,'metadataBytesRead':metadata_bytes,
            'presentDocumentsDigestVerified':sum(r['state']=='PRESENT_DOCUMENT_DIGEST_VERIFIED' for r in references),
            'descriptorReferencesObserved':len(references),'missingReferences':len(missing),
            'missingReferenceGroups':[{'context':k[0],'platformClass':k[1],'presenceClass':k[2],
                'mediaClass':k[3],'inlineDataPresent':k[4],'count':v}
                for k,v in sorted(groups.items())],
            'unobservedManifestSubgraphs':context_counts['INDEX_MEMBER'],
            'allReferencedManifestsObserved':context_counts['INDEX_MEMBER']==0,
            'classicManifestRows':len(classic),'classicMissingMembers':sum(v['state']=='ABSENT' for v in classic_refs),
            'classicMatchesPresentRuntimeManifests':len(set(classic_matches)),
            'requestedDigestDocumentPresent':any(r['descriptor']['digest']==requested_image
                and r['state']=='PRESENT_DOCUMENT_DIGEST_VERIFIED' for r in references),
            'configurationMembersOpened':0,'layerMembersOpened':0,'expandedLayerBytesRead':0,'externalBlobFetches':0,
            'missingBlobAdmitted':False,'nativeImageByteIdentityProven':False,
            'publisherTrustAccepted':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
        private={'schema':'ouf.retained-private-image-graph-diagnostic.v1','archiveSha256':archive_sha,
            'requestedImageId':requested_image,'references':references,'classicReferences':classic_refs,
            'classicMatchedManifestDigests':sorted(set(classic_matches)),'summary':public}
        budget.check();return private,public
