"""Classic binding over inert original OCI fixtures, with explicit graph edits."""
import json
from retained_image_bytes import fixture,attested_fixture,package,encoded,address
from retained_image_graph_cases import partial_index


def classic_bound(*,attested=False,modern=True,compressed=True,bad_diff=False):
    raw,image,entries=attested_fixture(modern=modern) if attested else fixture(compressed=compressed,bad_diff=bad_diff)
    runtime=None
    for name,body in entries:
        if not name.startswith('blobs/'):continue
        try:node=json.loads(body)
        except (ValueError,UnicodeError):continue
        if type(node) is dict and type(node.get('config')) is dict and type(node.get('layers')) is list:
            if node['config'].get('mediaType')!='application/vnd.oci.image.config.v1+json':continue
            cfg=next((v for k,v in entries if k=='blobs/sha256/'+node['config']['digest'][7:]),None)
            if cfg and json.loads(cfg).get('os')=='linux':runtime=node;break
    assert runtime
    classic=encoded([{'Config':'blobs/sha256/'+runtime['config']['digest'][7:],
        'Layers':['blobs/sha256/'+v['digest'][7:] for v in runtime['layers']],
        'RepoTags':['PRIVATE_TAG_IS_NOT_AN_AUTHORITY']}])
    entries=[*entries,('manifest.json',classic)]
    return package(entries),image,entries


def changed_partial(kind):
    _,image,entries=partial_index();root_name='blobs/sha256/'+image[7:]
    node=json.loads(next(v for k,v in entries if k==root_name))
    if kind=='same_platform':node['manifests'][1]['platform']={'os':'linux','architecture':'amd64'}
    elif kind=='unknown_unmarked':node['manifests'][2].pop('annotations')
    elif kind=='unknown_target':node['manifests'][2]['annotations']['vnd.docker.reference.digest']='sha256:'+'c'*64
    elif kind=='missing_index':node['manifests'][1]['mediaType']='application/vnd.oci.image.index.v1+json'
    elif kind=='untyped_platform':node['manifests'][1]['platform']={'os':'linux','architecture':False}
    elif kind=='duplicate':node['manifests'].append(node['manifests'][0])
    else:raise AssertionError(kind)
    raw=encoded(node);image=address(raw)
    entries=[(k,v) for k,v in entries if k not in (root_name,'index.json')]
    entries.extend([('blobs/sha256/'+image[7:],raw),('index.json',encoded({'schemaVersion':2,
        'manifests':[{'mediaType':'application/vnd.oci.image.index.v1+json','digest':image,'size':len(raw)}]}))])
    return package(entries),image,entries
