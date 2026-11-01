"""Read existing Docker-save image bytes without extraction, import or execution.

Authenticate the requested native/config digest, every referenced blob and every
expanded layer. Source labels and vendor names do not establish publisher trust.
This read-only helper does not replace any source/publisher admission contract.
"""
import gzip,hashlib,re,tarfile,time
from pathlib import PurePosixPath
from .custody_capture import decode,digest,require

SHA=r'sha256:[a-f0-9]{64}'
IMAGE_TYPES={'application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}
INDEX_TYPES={'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'}
CONFIG_TYPES={'application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json'}
LAYER_TYPES={'application/vnd.oci.image.layer.v1.tar','application/vnd.oci.image.layer.v1.tar+gzip',
    'application/vnd.docker.image.rootfs.diff.tar','application/vnd.docker.image.rootfs.diff.tar.gzip'}
LIMITS={'schema':'ouf.retained-image-byte-verification-profile.v1','maximumSeconds':600,
    'maximumArchiveBytes':2147483648,'maximumArchiveSetBytes':8589934592,
    'maximumExpandedImageBytes':8589934592,'maximumExpandedSetBytes':34359738368,
    'maximumMembers':2048,'maximumLayers':256,'maximumIndexDepth':4,'maximumDescriptors':64}


class VerificationBudget:
    def __init__(self):
        self.until=time.monotonic()+LIMITS['maximumSeconds'];self.expanded=0
    def check(self):require(time.monotonic()<self.until,'PRIVATE_IMAGE_VERIFICATION_DEADLINE')
    def add_expanded(self,size):
        self.check();self.expanded+=size
        require(self.expanded<=LIMITS['maximumExpandedSetBytes'],'BOUNDED_EXPANDED_PRIVATE_IMAGE_SET_REQUIRED')


def verified_image(stream,expected_sha,expected_image,expected_bytes,budget):
    require(type(budget) is VerificationBudget and type(expected_bytes) is int
        and 0<expected_bytes<=LIMITS['maximumArchiveBytes'] and type(expected_sha) is str
        and re.fullmatch('[a-f0-9]{64}',expected_sha) and type(expected_image) is str
        and re.fullmatch(SHA,expected_image),'EXACT_PRIVATE_IMAGE_STREAM_BINDINGS_REQUIRED')
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
        def small(name,maximum):
            row=member(name);require(0<row.size<=maximum,'BOUNDED_PRIVATE_IMAGE_DOCUMENT_REQUIRED')
            with archive.extractfile(row) as content:raw=content.read(maximum+1)
            require(len(raw)==row.size,'COMPLETE_PRIVATE_IMAGE_DOCUMENT_REQUIRED');budget.check()
            return raw,decode(raw)
        def blob(descriptor,maximum=2097152):
            require(type(descriptor) is dict and re.fullmatch(SHA,descriptor.get('digest',''))
                and type(descriptor.get('size')) is int and 0<descriptor['size']<=maximum,
                'BOUNDED_CONTENT_ADDRESSED_IMAGE_DESCRIPTOR_REQUIRED')
            name='blobs/sha256/'+descriptor['digest'][7:];raw,value=small(name,maximum)
            require(len(raw)==descriptor['size'] and 'sha256:'+hashlib.sha256(raw).hexdigest()==descriptor['digest'],
                'PRIVATE_IMAGE_DESCRIPTOR_CONTENT_DIGEST_DIFFERS')
            return name,raw,value
        manifest_digest=None;identity_kind='CLASSIC_CONFIGURATION';native_archive_digest=None
        if 'index.json' in members:
            _,layout=small('oci-layout',131072)
            require(layout=={'imageLayoutVersion':'1.0.0'},'PRIVATE_OCI_IMAGE_LAYOUT_REQUIRED')
            _,index=small('index.json',131072);nodes={};seen=set()
            def visit(document,depth):
                require(type(document) is dict and document.get('schemaVersion')==2
                    and type(document.get('manifests')) is list and 1<=len(document['manifests'])<=64
                    and depth<=LIMITS['maximumIndexDepth'],'BOUNDED_PRIVATE_IMAGE_INDEX_REQUIRED')
                for descriptor in document['manifests']:
                    budget.check();name,raw,node=blob(descriptor)
                    address=descriptor['digest']
                    require(address not in seen and len(seen)<LIMITS['maximumDescriptors'],
                        'UNIQUE_BOUNDED_PRIVATE_IMAGE_DESCRIPTOR_GRAPH_REQUIRED');seen.add(address)
                    media=descriptor.get('mediaType')
                    require(media in IMAGE_TYPES|INDEX_TYPES and node.get('mediaType') in (None,media)
                        and node.get('schemaVersion')==2,'PRIVATE_IMAGE_DESCRIPTOR_MEDIA_TYPE_REQUIRED')
                    nodes[address]=(media,node)
                    if media in INDEX_TYPES:visit(node,depth+1)
            visit(index,0)
            def leaves(address):
                media,node=nodes[address]
                if media in IMAGE_TYPES:return [(address,node)]
                return [leaf for child in node['manifests'] for leaf in leaves(child['digest'])]
            if expected_image in nodes:
                media,_=nodes[expected_image];native_archive_digest=expected_image
                identity_kind='OCI_MANIFEST' if media in IMAGE_TYPES else 'OCI_INDEX'
                candidates=leaves(expected_image)
                if media in INDEX_TYPES:
                    selected=[]
                    for address,node in candidates:
                        cfg=node.get('config',{})
                        require(cfg.get('mediaType') in CONFIG_TYPES,'PRIVATE_INDEX_IMAGE_CONFIG_DESCRIPTOR_REQUIRED')
                        _,_,value=blob(cfg)
                        if value.get('os')=='linux' and value.get('architecture')=='amd64':selected.append((address,node))
                    candidates=selected
            else:
                # A Docker container can retain a configuration digest while
                # its save transport is OCI. Bind that exact config to one
                # authenticated manifest; never guess from a tag or label.
                identity_kind='OCI_CONFIGURATION'
                candidates=[(address,node) for address,(media,node) in nodes.items()
                    if media in IMAGE_TYPES and node.get('config',{}).get('digest')==expected_image]
            require(len(candidates)==1,'EXACT_UNIQUE_REQUESTED_NATIVE_OR_CONFIGURATION_IMAGE_REQUIRED')
            manifest_digest,native=candidates[0]
            cfg=native.get('config',{})
            require(cfg.get('mediaType') in CONFIG_TYPES,'PRIVATE_IMAGE_CONFIGURATION_DESCRIPTOR_REQUIRED')
            config_name,config_raw,config=blob(cfg)
            layer_descriptors=native.get('layers')
            require(type(layer_descriptors) is list and len(layer_descriptors)<=LIMITS['maximumLayers'],
                'BOUNDED_PRIVATE_NATIVE_IMAGE_LAYERS_REQUIRED')
            layers=[]
            for row in layer_descriptors:
                require(type(row) is dict and row.get('mediaType') in LAYER_TYPES
                    and re.fullmatch(SHA,row.get('digest','')) and type(row.get('size')) is int and row['size']>0,
                    'EXACT_PRIVATE_NATIVE_LAYER_DESCRIPTOR_REQUIRED')
                name='blobs/sha256/'+row['digest'][7:]
                require(member(name).size==row['size'],'PRIVATE_NATIVE_LAYER_SIZE_CHANGED');layers.append(name)
        else:
            _,manifest=small('manifest.json',131072)
            require(type(manifest) is list and len(manifest)==1 and type(manifest[0]) is dict,
                'EXACT_ONE_CLASSIC_PRIVATE_IMAGE_REQUIRED')
            image=manifest[0];config_name=image.get('Config');config_raw,config=small(config_name,2097152)
            require('sha256:'+hashlib.sha256(config_raw).hexdigest()==expected_image,
                'EXACT_REQUESTED_CLASSIC_IMAGE_CONFIGURATION_REQUIRED')
            layers=image.get('Layers');layer_descriptors=None
        config_digest='sha256:'+hashlib.sha256(config_raw).hexdigest()
        require(type(config) is dict and config.get('os')=='linux' and config.get('architecture')=='amd64'
            and type(config.get('config')) is dict,'EXACT_PRIVATE_LINUX_AMD64_IMAGE_REQUIRED')
        root=config.get('rootfs',{});diffs=root.get('diff_ids')
        require(root.get('type')=='layers' and type(layers) is list and type(diffs) is list
            and len(layers)==len(diffs) and len(layers)<=LIMITS['maximumLayers']
            and all(type(v) is str and re.fullmatch(SHA,v) for v in diffs),'EXACT_ORDERED_PRIVATE_IMAGE_ROOTFS_REQUIRED')
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
        return {'schema':'ouf.retained-private-image-byte-identity.v1','requestedImageId':expected_image,
            'requestedIdentityKind':identity_kind,'nativeArchiveIdentityDigest':native_archive_digest,
            'nativeManifestDigest':manifest_digest,'configurationDigest':config_digest,'archiveSha256':expected_sha,
            'archiveBytes':expected_bytes,'expandedBytes':expanded_total,'layersHash':digest(proofs),
            'layerCount':len(proofs),'executionConfigurationHash':digest(config['config']),
            'nativeOrClassicImageByteIdentityProven':True,'sourcePublisherAuthenticated':False,
            'scanAdmissionProven':False,'runtimeAuthorityIssued':False,'targetApplyAuthorized':False,'releaseAcceptance':False}
