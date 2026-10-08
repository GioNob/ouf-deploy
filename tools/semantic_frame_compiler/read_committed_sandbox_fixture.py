"""CI-only bounded Bolt snapshot reader, not production custody/authority.

Reads reachable committed pages rather than scanning stale database bytes.
Moby sandbox records bind Cid to ID; the namespace key uses ID[:12].
Do not deploy this fixture as an authenticated target-context reader.
"""
import json
import re
import struct


class Denied(ValueError):
    pass


def require(ok):
    if not ok:
        raise Denied('CI_COMMITTED_SANDBOX_SNAPSHOT_UNPROVEN')


def fnv(raw):
    value = 14695981039346656037
    for byte in raw:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def committed_sandbox(raw, cid):
    require(type(raw) is bytes and 8192 <= len(raw) <= 16777216
            and re.fullmatch('[0-9a-f]{64}', cid))
    page_size = struct.unpack_from('<I', raw, 24)[0]
    require(page_size in (4096, 8192, 16384, 32768, 65536) and len(raw) >= 2 * page_size)
    metas = []
    for index in (0, 1):
        start = index * page_size
        header_id, flags, count, overflow = struct.unpack_from('<QHHI', raw, start)
        magic, version, size, ignored = struct.unpack_from('<IIII', raw, start + 16)
        root, sequence, freelist, upper, txid, checksum = struct.unpack_from('<QQQQQQ', raw, start + 32)
        if header_id == index and flags == 4 and magic == 0xED0CDAED and version == 2 and size == page_size and checksum == fnv(raw[start + 16:start + 72]):
            require(2 <= root < upper <= len(raw) // page_size)
            metas.append((txid, root, upper))
    require(bool(metas)); txid, root, upper = max(metas)
    visited = set(); budget = [4096]; records = []

    def page(pgid):
        require(type(pgid) is int and 2 <= pgid < upper and pgid not in visited)
        visited.add(pgid)
        start = pgid * page_size
        actual, flags, count, overflow = struct.unpack_from('<QHHI', raw, start)
        require(actual == pgid and pgid + overflow < upper)
        return raw[start:(pgid + overflow + 1) * page_size]

    def walk(data, depth=0):
        budget[0] -= 1
        require(budget[0] >= 0 and depth <= 16 and len(data) >= 16)
        ignored, flags, count, overflow = struct.unpack_from('<QHHI', data)
        require(flags in (1, 2) and count <= 4096 and 16 + count * 16 <= len(data))
        for index in range(count):
            at = 16 + index * 16
            if flags == 1:
                pos, key_size, child = struct.unpack_from('<IIQ', data, at)
                require(at + pos + key_size <= len(data))
                walk(page(child), depth + 1)
                continue
            item_flags, pos, key_size, value_size = struct.unpack_from('<IIII', data, at)
            start = at + pos; end = start + key_size + value_size
            require(item_flags in (0, 1) and start >= 16 + count * 16 and end <= len(data))
            key, value = data[start:start + key_size], data[start + key_size:end]
            if item_flags == 1:
                require(len(value) >= 16)
                bucket_root = struct.unpack_from('<Q', value)[0]
                walk(page(bucket_root) if bucket_root else value[16:], depth + 1)
            elif key.startswith(b'docker/network/v1.0/sandbox/'):
                require(len(value) >= 8 and value_size <= 131072)
                record = json.loads(value[8:])
                require(type(record) is dict)
                if record.get('Cid') == cid:
                    sid = record.get('ID')
                    require(type(sid) is str and re.fullmatch('[0-9a-f]{64}', sid)
                            and key in (b'docker/network/v1.0/sandbox/' + sid.encode(),
                                        b'docker/network/v1.0/sandbox/' + sid.encode() + b'/'))
                    records.append(sid)
    walk(page(root))
    require(len(records) == 1)
    return {'sandboxId': records[0], 'namespaceName': records[0][:12], 'transactionId': txid,
            'committedPagesOnly': True, 'productionContextAuthenticated': False}
