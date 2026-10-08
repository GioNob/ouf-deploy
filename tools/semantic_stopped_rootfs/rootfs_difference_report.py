"""Classify exact v1 seal entry differences without exposing file contents.

Use the verified sealer's unchanged code and a private copy of its globals to
record the canonical entries it already hashes. No metadata is omitted and no
installed runtime module is modified. Reports contain counts and image paths,
never content hashes, xattr values, symlink targets or environment values.
"""
import types
from prepare_provider_image_rootfs import Budget,require


def entries(sealer,path,limits):
    result={};original=sealer.__globals__['encoded']
    def record(item):
        require(item['path'] not in result,'DUPLICATE_SEAL_ENTRY')
        result[item['path']]=item
        return original(item)
    globals_copy={**sealer.__globals__,'encoded':record}
    observer=types.FunctionType(sealer.__code__,globals_copy,sealer.__name__,sealer.__defaults__,sealer.__closure__)
    seal=observer(path,limits,Budget())
    return seal,result


def classify(expected,actual,max_samples=30):
    counts={};samples=[]
    for path in sorted(set(expected)|set(actual)):
        left=expected.get(path);right=actual.get(path)
        if left is None:fields=['UNEXPECTED_ENTRY']
        elif right is None:fields=['MISSING_ENTRY']
        else:fields=[name for name in sorted(set(left)|set(right)) if name!='path' and left.get(name)!=right.get(name)]
        if not fields:continue
        for field in fields:counts[field]=counts.get(field,0)+1
        if len(samples)<max_samples:
            samples.append({'path':path[:512] or '.', 'differentFields':fields})
    return {'differentEntryCount':sum(1 for p in set(expected)|set(actual) if expected.get(p)!=actual.get(p)),
        'fieldCounts':counts,'samples':samples,'samplesTruncated':sum(1 for p in set(expected)|set(actual) if expected.get(p)!=actual.get(p))>max_samples,
        'fileContentsPrinted':False,'xattrValuesPrinted':False,'symlinkTargetsPrinted':False}
