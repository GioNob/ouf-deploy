"""Derive v2 from the retained v1 closure, changing only configured tmpfs review.

No owner generator is present in this repository (v1 is a copied sealed blob).
The wrapper, schema and other embedded modules are retained verbatim.
"""
import argparse
import ast
import hashlib
from pathlib import Path


TMPFS_REVIEW = '''    tmpfs=spec.get('tmpfs',{})
    require(type(tmpfs) is dict,'OCI_DECLARED_TMPFS_DRIFT')
    declared={v['target']:v for v in spec['mounts']}
    kernel={'/proc','/dev','/dev/pts','/dev/shm','/dev/mqueue','/sys','/sys/fs/cgroup','/etc/hosts','/etc/hostname','/etc/resolv.conf'}
    for target,options in tmpfs.items():
        path(target)
        require(not any(PurePosixPath(target)==PurePosixPath(other)
            or PurePosixPath(target) in PurePosixPath(other).parents
            or PurePosixPath(other) in PurePosixPath(target).parents
            for other in set(declared)|kernel),'OCI_DECLARED_TMPFS_OVERLAP')
        require(type(options) is str and bool(options),'OCI_DECLARED_TMPFS_DRIFT')
        declared_options=['rprivate']+options.split(',')
        matches=[m for m in mounts if m['destination']==target]
        require(len(matches)==1,'OCI_DECLARED_TMPFS_DRIFT')
        actual=matches[0]
        require(actual.get('type')=='tmpfs' and actual.get('source')=='tmpfs'
            and 'uidMappings' not in actual and 'gidMappings' not in actual,'OCI_DECLARED_TMPFS_DRIFT')
        for values in (declared_options,actual.get('options') or []):
            require(len(values)==len(set(values)),'OCI_DECLARED_TMPFS_DRIFT')
            require({'noexec','nosuid','nodev'}<=set(values)
                and not set(values)&{'exec','suid','dev','shared','rshared','slave','rslave'},
                'OCI_DECLARED_TMPFS_HARDENING_REQUIRED')
            keyed={key:[v.split('=',1)[1] for v in values if v.startswith(key+'=')]
                for key in ('size','uid','gid','mode')}
            require(all(len(v)==1 for v in keyed.values()),'OCI_DECLARED_TMPFS_HARDENING_REQUIRED')
            size=re.fullmatch(r'([0-9]{1,10})([kKmMgG]?)',keyed['size'][0])
            require(size is not None,'OCI_DECLARED_TMPFS_HARDENING_REQUIRED')
            require(0<int(size[1])*1024**({'':0,'k':1,'m':2,'g':3}[size[2].lower()])<=64*1024*1024,
                'OCI_DECLARED_TMPFS_HARDENING_REQUIRED')
            require(all(re.fullmatch(r'[0-9]{1,10}',keyed[k][0])
                and 0<int(keyed[k][0])<2**32 for k in ('uid','gid')),
                'OCI_DECLARED_TMPFS_HARDENING_REQUIRED')
            mode=keyed['mode'][0]
            require(re.fullmatch(r'[0-7]{1,4}',mode) and int(mode,8)<=0o777
                and not int(mode,8)&0o077,'OCI_DECLARED_TMPFS_HARDENING_REQUIRED')
        # Docker 29's retained southbound fixture preserves this exact order.
        require(actual.get('options')==declared_options,'OCI_DECLARED_TMPFS_DRIFT')
'''


def literal(tree, name):
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))


def build(raw):
    raw = raw.replace('\r\n', '\n')
    tree = ast.parse(raw)
    sources = literal(tree, 'SOURCES')
    hashes = literal(tree, 'SOURCE_HASHES')
    for name, source in sources.items():
        if hashlib.sha256(source.encode()).hexdigest() != hashes[name]:
            raise ValueError('V1_SOURCE_HASH_DRIFT')
    if hashlib.sha256(literal(tree, 'SCHEMA_BYTES')).hexdigest() != hashes['semantic_oci_shape_schema.json']:
        raise ValueError('V1_SCHEMA_HASH_DRIFT')
    reviewer = sources['review_semantic_oci_policy']
    old = "    mounts=bundle.get('mounts') or [];seen={}\n"
    assert reviewer.count(old) == 1
    reviewer = reviewer.replace(old, "    mounts=bundle.get('mounts') or []\n" + TMPFS_REVIEW + "    seen={}\n")
    old = "require(not set(seen)-set(declared)-kernel,'OCI_UNDECLARED_MOUNT_DENIED')"
    assert reviewer.count(old) == 1
    reviewer = reviewer.replace(old, "require(not set(seen)-set(declared)-set(tmpfs)-kernel,'OCI_UNDECLARED_MOUNT_DENIED')")
    sources['review_semantic_oci_policy'] = reviewer
    hashes['review_semantic_oci_policy'] = hashlib.sha256(reviewer.encode()).hexdigest()
    lines = raw.splitlines(keepends=True)
    replacements = {'SOURCES': sources, 'SOURCE_HASHES': hashes}
    for node in reversed(tree.body):
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in replacements:
                lines[node.lineno-1:node.end_lineno] = [name + '=' + repr(replacements[name]) + '\n']
    return ''.join(lines).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    result = build((root / 'frame-observer.py').read_bytes().decode())
    target = root / 'frame-observer-v2.py'
    if args.check:
        if target.read_bytes() != result:
            raise SystemExit('FRAME_OBSERVER_V2_BUILD_DRIFT')
    else:
        target.write_bytes(result)


if __name__ == '__main__':
    main()
