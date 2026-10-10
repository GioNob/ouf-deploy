"""Public cacerts byte capture from an exact candidate archive; no signature or apply authority implied."""
import hashlib,json,os,posixpath,stat,tarfile
from pathlib import Path
def require(v,why):
    if not v:raise ValueError(why)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def roots(path,expected_archive,expected_image):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as raw:
        initial=os.fstat(raw.fileno());require(stat.S_ISREG(initial.st_mode) and initial.st_nlink==1 and initial.st_size<=2147483648,'BOUNDED_REGULAR_CANDIDATE_ARCHIVE_REQUIRED')
        def same(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(hashlib.file_digest(raw,'sha256').hexdigest()==expected_archive,'EXACT_CANDIDATE_ARCHIVE_BYTES_REQUIRED')
        raw.seek(0)
        with tarfile.open(fileobj=raw,mode='r:*') as archive:
            def small(name,limit):
                item=archive.getmember(name);require(item.isfile() and 0<item.size<=limit,'BOUNDED_IMAGE_METADATA_REQUIRED')
                return archive.extractfile(item).read(limit+1)
            manifest=json.loads(small('manifest.json',131072));require(len(manifest)==1,'ONE_CANDIDATE_IMAGE_REQUIRED')
            entry=manifest[0];config_raw=small(entry['Config'],2097152)
            require('sha256:'+digest(config_raw)==expected_image,'EXACT_CANDIDATE_IMAGE_CONFIG_REQUIRED')
            config=json.loads(config_raw);env={v.split('=',1)[0]:v.split('=',1)[1] for v in config['config']['Env']}
            home=env.get('JAVA_HOME');require(home=='/opt/java/openjdk','EXACT_CANDIDATE_JAVA_HOME_REQUIRED')
            chosen=home.lstrip('/')+'/lib/security/cacerts'
            allowed={chosen,'etc/ssl/certs/java/cacerts','etc/pki/java/cacerts'};state={}
            layers=entry['Layers'];require(1<=len(layers)<=128,'BOUNDED_CANDIDATE_IMAGE_LAYERS_REQUIRED')
            for name in layers:
                member=archive.getmember(name);require(member.isfile() and member.size<=2147483648,'BOUNDED_CANDIDATE_LAYER_REQUIRED')
                with tarfile.open(fileobj=archive.extractfile(member),mode='r|*') as layer:
                    count=0
                    for item in layer:
                        count+=1;require(count<=500000,'BOUNDED_LAYER_ENTRIES_REQUIRED')
                        name=item.name.removeprefix('./').lstrip('/');parts=name.split('/')
                        require('..' not in parts,'LAYER_PATH_ESCAPE_DENIED')
                        parent,base=posixpath.split(name)
                        if base=='.wh..wh..opq':
                            for p in list(state):
                                if not parent or p.startswith(parent+'/'):state.pop(p)
                        elif base.startswith('.wh.'):
                            removed=posixpath.join(parent,base[4:])
                            for p in list(state):
                                if p==removed or p.startswith(removed+'/'):state.pop(p)
                        elif name in allowed:
                            if item.isfile():
                                require(0<item.size<=2097152,'BOUNDED_PUBLIC_STORE_REQUIRED');state[name]=('file',layer.extractfile(item).read(2097153))
                            elif item.issym() or item.islnk():
                                dest=posixpath.normpath(item.linkname.lstrip('/') if item.linkname.startswith('/') or item.islnk() else posixpath.join(parent,item.linkname))
                                require(dest in allowed,'BOUNDED_PUBLIC_STORE_LINK_REQUIRED');state[name]=('link',dest)
                            else:raise ValueError('PUBLIC_STORE_NODE_TYPE_DENIED')
            seen=set();current=chosen
            while True:
                require(current not in seen and current in state,'EXACT_FINAL_PUBLIC_STORE_REQUIRED');seen.add(current)
                kind,value=state[current]
                if kind=='file':
                    require(same(initial)==same(os.fstat(raw.fileno()))==same(Path(path).lstat()),'CANDIDATE_ARCHIVE_CHANGED_DURING_READ')
                    return value,{'javaHome':home,'imageId':expected_image,'sourcePath':current,'publicStoreHash':digest(value),'layersRead':len(layers)}
                current=value
