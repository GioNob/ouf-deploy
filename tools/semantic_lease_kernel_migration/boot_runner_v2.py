"""Sealed generation-2 empty boot reconstruction; called under the common lock.

Reconstruction changes native handles, as in the historical boot contract.
It BLOCKS the coordinator for explicit reconciliation, never adopts a new seal
into a running owner, opens a lease, starts a container or resolves DNS.
"""
from pathlib import Path


def run(receipt, api):
    root = Path(receipt['directory'])
    profile = api.document(api.private(receipt['bootProfile']['path'], receipt['bootProfile']['sha256']))
    owner = api.document(api.private(profile['coordinatedConfiguration'], profile['coordinatedConfigurationHash']))
    boot = api.document(api.private(profile['bootConfiguration'], profile['bootConfigurationHash']))
    api.need(owner['kernel'] == boot['kernel'] and owner['commonLockFile'] == boot['lockFile']
             and owner['nftPath'] == boot['nftPath'], 'BOOT_OWNER_SCOPE_DRIFT')
    journal_raw = api.private(owner['journalFile'])
    journal = api.document(journal_raw)
    api.need(all(journal.get(k) == v for k, v in owner['binding'].items())
             and journal.get('leaseAuthorized') is False and journal.get('startAuthorized') is False
             and journal.get('state') in ('QUIESCED', 'BLOCKED'), 'BOOT_JOURNAL_NOT_QUIESCED')
    nft = {'path': owner['nftPath'], 'sha256': owner['nftSha256']}
    current = api.tables(nft, boot['kernel']['tableName'])
    rebuilt = current is None
    if rebuilt:
        sources = {k.removeprefix('source/'): v for k, v in receipt['closure'].items() if k.startswith('source/')}
        rules = api.compiler(root / 'source', sources).materialize(boot['kernel'], empty_provider_sets=True)['nftRules']
        api.command(nft, ['-f', '-'], rules.encode('ascii'))
        current = api.tables(nft, boot['kernel']['tableName'])
    api.empty(current)
    api.need(api.digest(api.stable(current)) == boot['expectedFootprint'], 'BOOT_FOOTPRINT_DRIFT')
    if rebuilt or api.digest(api.structure(current)) != owner['expectedStructureHash']:
        api.cas(owner['journalFile'], journal_raw, api.canonical({**journal, 'state': 'BLOCKED',
                  'leaseAuthorized': False, 'startAuthorized': False}))
    # A predecessor may reappear after an interrupted migration/reboot. Do not
    # delete it here: task-66 must require its absence before any v12 start.
