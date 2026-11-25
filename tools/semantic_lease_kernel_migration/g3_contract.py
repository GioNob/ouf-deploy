"""Pure contract for generation 3. Inputs are duplicate-free decoded JSON."""
import ipaddress
import math
import re
from uuid import UUID

from .boot_dispatcher import digest, stable, structure


PROJECTION = 'ouf.lease-kernel.structure.g3.v1'
SEAL = 'ouf.lease-kernel.seal.g3.v1'
JOURNAL = 'ouf.lease-kernel.journal.g3.v1'
NFT_FORMAT = 'G3_NFT_FORMAT'
NFT_VERSION_DENIED = 'G3_NFT_VERSION'
SETS_NOT_EMPTY = 'G3_SETS_NOT_EMPTY'
BINDING = 'G3_BINDING'
SEAL_DRIFT = 'G3_SEAL_DRIFT'
POLICY_DRIFT = 'G3_POLICY_DRIFT'
MEMBERS = 'G3_MEMBERS'
TTL = 'G3_TTL'
QUIESCENT = 'QUIESCENT'
RESIDUE_PREVIOUS_BOOT = 'RESIDUE_PREVIOUS_BOOT'
DENY = 'DENY'


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _boot_id(value):
    try:
        uid = UUID(value) if isinstance(value, str) else None
        return uid is not None and uid.version == 4 and str(uid) == value
    except ValueError:
        return False


def _binding(head, owner, generation, boot_id):
    _require(_hash(head) and _hash(owner) and type(generation) is int
             and generation == 3 and _boot_id(boot_id), BINDING)
    return dict(head=head, owner=owner, generation=generation, bootId=boot_id)


def _fields(value, required, optional=(), code=NFT_FORMAT):
    _require(isinstance(value, dict) and set(required) <= value.keys()
             and value.keys() <= set(required).union(optional), code)


def _integer(value, minimum):
    return type(value) is int and value >= minimum


def _validate_profile(profile):
    _fields(profile, ['version', 'jsonSchemaVersion'], code=NFT_VERSION_DENIED)
    _require(isinstance(profile['version'], str) and profile['version'].strip()
             and _integer(profile['jsonSchemaVersion'], 1), NFT_VERSION_DENIED)


def listing_profile(row, expected=None):
    """Read metainfo. Only the installation may use the result as a profile candidate."""
    _fields(row, ['metainfo'])
    meta = row['metainfo']
    _require(isinstance(meta, dict), NFT_FORMAT)
    profile = {'version': meta.get('version'), 'jsonSchemaVersion': meta.get('json_schema_version')}
    _validate_profile(profile)
    if expected is not None:
        _require(profile == expected, NFT_VERSION_DENIED)
    _fields(meta, ['version', 'json_schema_version'], ['release_name'])
    _require(isinstance(meta.get('release_name', ''), str), NFT_FORMAT)
    return profile


def _statements(expr):
    _require(isinstance(expr, list) and expr, NFT_FORMAT)
    result = []
    for stmt in expr:
        _require(isinstance(stmt, dict) and len(stmt) == 1, NFT_FORMAT)
        kind, body = next(iter(stmt.items()))
        if kind == 'counter':
            _fields(body, ['packets', 'bytes'])
            _require(all(_integer(v, 0) for v in body.values()), NFT_FORMAT)
            result.append(structure(stmt))
        else:
            if kind == 'match':
                _fields(body, ['op', 'left', 'right'])
                _require(isinstance(body['op'], str), NFT_FORMAT)
            elif kind == 'jump':
                _fields(body, ['target'])
                _require(isinstance(body['target'], str) and body['target'], NFT_FORMAT)
            else:
                _require(kind in ('accept', 'drop') and body is None, NFT_FORMAT)
            # Operands are atoms for comparison. No recursive volatile-key filter.
            result.append(stmt)
    return result


def _family(family, document, live, nft_profile):
    _fields(document, ['nftables'])
    rows = document['nftables']
    _require(isinstance(rows, list) and len(rows) >= 2, NFT_FORMAT)
    listing_profile(rows[0], nft_profile)
    _fields(rows[1], ['table'])
    name = None
    sets = {}
    chains = set()
    referenced_chains = set()
    records = []
    children = set()
    for row in rows[1:]:
        _require(isinstance(row, dict) and len(row) == 1, NFT_FORMAT)
        kind, obj = next(iter(row.items()))
        _require(isinstance(obj, dict) and obj.get('family') == family, NFT_FORMAT)
        base = ['family']
        if kind != 'table':
            _require(obj.get('table') == name, NFT_FORMAT)
            base.append('table')
        handle = obj.get('handle')
        if live or 'handle' in obj:
            _require(_integer(handle, 1), NFT_FORMAT)
        if live and kind != 'table':
            _require(handle not in children, NFT_FORMAT)
            children.add(handle)
        if kind != 'rule':
            label = obj.get('name')
            _require(isinstance(label, str) and label, NFT_FORMAT)
            base.append('name')
        optional = ['handle']
        if kind == 'table':
            _require(name is None, NFT_FORMAT)
            name = label
        elif kind == 'set':
            base.extend(['flags', 'type'])
            optional.append('elem')
            _require(re.fullmatch('provider_(0|[1-9][0-9]*)', label)
                     and label not in sets and obj.get('flags') == ['timeout']
                     and obj.get('type') in ('ipv4_addr', 'ipv6_addr'), NFT_FORMAT)
            elements = obj.get('elem', [])
            _require(isinstance(elements, list), NFT_FORMAT)
            sets[label] = (obj['type'], elements)
        elif kind == 'chain':
            _require(label not in chains, NFT_FORMAT)
            chains.add(label)
            if obj.keys() & {'hook', 'type', 'prio', 'policy'}:
                base.extend(['hook', 'type', 'prio', 'policy'])
                _require(obj.get('hook') in ('input', 'output', 'forward')
                         and obj.get('type') == 'filter' and type(obj.get('prio')) is int
                         and obj.get('policy') in ('accept', 'drop'), NFT_FORMAT)
        elif kind == 'rule':
            base.extend(['chain', 'expr'])
            _require(isinstance(obj.get('chain'), str), NFT_FORMAT)
            referenced_chains.add(obj['chain'])
        else:
            raise ValueError(NFT_FORMAT)
        _fields(obj, base, optional)
        # Filter the declaration header only. Statements and set elements each
        # have their own grammar, including inline constant sets in match operands.
        header = stable({k: v for k, v in obj.items() if k not in ('expr', 'elem')})
        if kind == 'rule':
            header['expr'] = _statements(obj['expr'])
        # A stable sort preserves rule sequence within each chain. Sort keys
        # exclude handles, which stay attached to their respective records.
        order = ('table', 'set', 'chain', 'rule').index(kind)
        key = obj['chain'] if kind == 'rule' else ''
        records.append(((order, key), {kind: header}, handle))
    records.sort(key=lambda record: record[0])
    _require(referenced_chains <= chains, NFT_FORMAT)
    projected = [row for _, row, _ in records]
    handles = [handle for _, _, handle in records] if live else []
    return name, projected, handles, sets


def _project(tables, nft_profile, *, live, empty):
    _validate_profile(nft_profile)
    _fields(tables, ['inet', 'bridge'])
    projection, handles, members = {}, {}, {}
    names = set()
    for family in ('inet', 'bridge'):
        name, projection[family], handles[family], members[family] = _family(
            family, tables[family], live, nft_profile)
        names.add(name)
    _require(len(names) == 1, NFT_FORMAT)
    if empty:
        _require(not any(elements for sets in members.values()
                         for _, elements in sets.values()), SETS_NOT_EMPTY)
    return {'schema': PROJECTION, 'tables': projection}, handles, members


def policy_footprint(tables, nft_profile):
    """SHA-256 of the empty compiler image. Declaration handles are optional."""
    projection, _, _ = _project(tables, nft_profile, live=False, empty=True)
    return digest(projection)


def _seal(binding, projection, handles):
    return {'schema': SEAL, **binding, 'handles': handles,
            'structureHash': digest({'projection': projection, 'handles': handles})}


def local_seal(head, owner, generation, boot_id, tables, nft_profile):
    """Construct an empty readback receipt. The caller qualifies its provenance."""
    binding = _binding(head, owner, generation, boot_id)
    projection, handles, _ = _project(tables, nft_profile, live=True, empty=True)
    return _seal(binding, projection, handles)


def _verify_seal(seal, binding, projection, handles):
    _require(isinstance(seal, dict) and all(seal.get(k) == v for k, v in binding.items()), BINDING)
    # Canonical bytes distinguish integer handles from JSON true and floats.
    _require(digest(seal) == digest(_seal(binding, projection, handles)), SEAL_DRIFT)


def verify_boot(seal, current_boot_id, head, owner, tables, nft_profile, footprint):
    binding = _binding(head, owner, 3, current_boot_id)
    projection, handles, _ = _project(tables, nft_profile, live=True, empty=True)
    _require(digest(projection) == footprint, POLICY_DRIFT)
    _verify_seal(seal, binding, projection, handles)


def verify_renewal_margin(margin_seconds, tick_seconds):
    """Validate the renewal schedule before use. nft truncates expires to seconds."""
    for duration in (margin_seconds, tick_seconds):
        _require(type(duration) in (int, float) and duration > 0, TTL)
        if type(duration) is float:
            _require(math.isfinite(duration), TTL)
    _require(margin_seconds > tick_seconds + 1, TTL)


def _address(value, nft_type):
    _require(isinstance(value, str) and '%' not in value, MEMBERS)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(MEMBERS) from None
    _require(str(parsed) == value and (parsed.version == 4) == (nft_type == 'ipv4_addr'), MEMBERS)
    return value


def _verify_members(nft_type, elements, policy, now):
    _fields(policy, ['maxSeconds', 'validUntil'], code=MEMBERS)
    maximum, deadlines = policy['maxSeconds'], policy['validUntil']
    _require(isinstance(deadlines, dict), MEMBERS)
    _require(_integer(maximum, 1), TTL)
    seen = set()
    for entry in elements:
        _fields(entry, ['elem'])
        element = entry['elem']
        _fields(element, ['val', 'expires'], ['timeout'])
        address = _address(element['val'], nft_type)
        _require(address in deadlines and address not in seen, MEMBERS)
        seen.add(address)
        ttl = element['expires']
        timeout = element.get('timeout', maximum)
        deadline = deadlines[address]
        _require(_integer(deadline, 0) and _integer(ttl, 1) and _integer(timeout, 1)
                 and ttl <= timeout <= maximum and now + ttl <= deadline, TTL)
    _require(seen == deadlines.keys(), MEMBERS)


def verify_tick(policy, seal, tables, membership_policy, now):
    """policy joins authenticated head/owner values and independently read bootId."""
    _fields(policy, ['head', 'owner', 'generation', 'bootId', 'footprint'], ['nftProfile'], code=BINDING)
    binding = _binding(policy['head'], policy['owner'], policy['generation'], policy['bootId'])
    projection, handles, members = _project(tables, policy.get('nftProfile'), live=True, empty=False)
    _require(digest(projection) == policy['footprint'], POLICY_DRIFT)
    _verify_seal(seal, binding, projection, handles)
    _require(_integer(now, 0), TTL)
    _require(isinstance(membership_policy, dict), MEMBERS)
    for sets in members.values():
        _require(sets.keys() == membership_policy.keys(), MEMBERS)
        for name, (nft_type, elements) in sets.items():
            _verify_members(nft_type, elements, membership_policy[name], now)


def classify_journal(journal, current_boot_id):
    """Classify a custody/binding-checked journal; never permission to write."""
    if not isinstance(journal, dict) or journal.keys() != {
            'schema', 'head', 'owner', 'generation', 'bootId', 'state',
            'leaseAuthorized', 'startAuthorized'}:
        return DENY
    if (journal['schema'] != JOURNAL or not _boot_id(current_boot_id)
            or not _boot_id(journal['bootId']) or not _hash(journal['head'])
            or not _hash(journal['owner']) or type(journal['generation']) is not int
            or journal['generation'] != 3 or journal['startAuthorized'] is not False):
        return DENY
    state, lease = journal['state'], journal['leaseAuthorized']
    if state in ('QUIESCED', 'BLOCKED') and lease is False:
        return QUIESCENT
    if ((state in ('LEASE_READY', 'LEASE_UPDATING') and lease is True)
            or (state == 'QUIESCING' and lease is False)):
        if journal['bootId'] != current_boot_id:
            return RESIDUE_PREVIOUS_BOOT
    return DENY
