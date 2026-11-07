"""Live leaf custody continuity only; no credential body or policy admission."""
import os,stat
from pathlib import Path
from .custody_capture import attrs,require
from .retained_view_intake import live_fields
from .retained_view_primitives import view_node,fd_mount_id


def observe_live_leaf(scanner,view,mount,kind,baseline,mount_id,budget):
    name=baseline['name'];source=scanner.node(Path(mount['source'])/name)
    target=current=named=None
    try:
        target=view_node(view,'/'+name);a=attrs(os.fstat(source));b=attrs(os.fstat(target))
        token=kind=='RENEWABLE_TOKEN_OWNER_INPUT'
        require(stat.S_ISREG(a[2]) and stat.S_ISREG(b[2]) and a[5]==b[5]==1
            and (a==b and 0<a[6]<=16384 if token else a[:6]==b[:6]),
            'CURRENT_LIVE_LEAF_SOURCE_AND_EFFECTIVE_VIEW_NOT_STABLE')
        fields=live_fields(kind);expected=baseline['currentSource']
        require(all(a[i]==expected[i] for i in fields),'CURRENT_LIVE_LEAF_CUSTODY_DIFFERS_FROM_CAPTURE')
        current=view_node(view,'/'+name);named=scanner.node(Path(mount['source'])/name)
        after=attrs(os.fstat(current));host=attrs(os.fstat(named))
        require((after==host==attrs(os.fstat(source))==a if token else after[:6]==host[:6]==attrs(os.fstat(source))[:6]==a[:6])
            and fd_mount_id(target,budget)==fd_mount_id(current,budget)==mount_id,
            'CURRENT_LIVE_LEAF_ROTATED_OR_REBOUND_DURING_METADATA_READ')
        return [a[i] for i in fields]
    finally:
        for fd in (named,current,target,source):
            if fd is not None:os.close(fd)
