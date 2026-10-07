# Remediated provider private TLS inputs

> **Target attempt blocked, 7 October 23:49 Europe/Rome.** Snapshot `/etc/ouf/deploy-snapshots/semantic-provider-v2-trust-dlz2t6B6` is retained. Source hashes passed; the installer reported BLOCKED with partial evidence and no raw details. The failing phase and generated file inventory are not yet known. Do not rerun apply or delete/adopt its files. The previous bootstrap is withdrawn pending fixed read-only diagnosis in `scripts/diagnose-provider-v2-trust.py` at revision `5f16b4e79f3dd8d1c7cd71b52ec66636ba51f9d0`. This diagnosis never invokes preparation, opens no private keys and performs no runtime or configuration writes.


The issuer source is installed at `/etc/ouf/deploy-snapshots/semantic-creation-issuer-install-USjonf22`. It is not a configured or accepted deployment transaction.

Target run [37690207099](https://github.com/GioNob/ouf-deploy/actions/runs/37690207099) verified the two exact remediated archive/config identities and startup. Target run [37691307786](https://github.com/GioNob/ouf-deploy/actions/runs/37691307786), job 113031925326, independently verified every ordered layer and resolved numeric runtime identities: adapter 10006:10006; southbound 636:636. Eight overlay/refusal tests passed. No image was imported or executed.

## Concrete next bounded operator action

`scripts/bootstrap-provider-v2-private-trust.sh` downloads two exact hash-pinned sources from revision `4645afc0a8f3b98f06a6bb02b0b94876d700ae92`, copies them into a fresh root-private snapshot, and rechecks their hashes before isolated Python execution. It requires the existing installation authority profile hash and fixed OpenSSL hash. It verifies the original role archives/layers again and generates a new private CA, two distinct hostname-bound leaf pairs and one shared provider-purpose receipt key. The new names are `ouf-semantic-provider-v2` and `ouf-semantic-southbound-v2`; files are owned by their actual numeric runtime identities.

The action does not import images, create/start/restart containers, install mounts, change services/rules/IAM/databases, issue deployment signatures or grant startup. Existing installation authority keys are never opened. Original candidates, private trust, journals, authority policies and the live Gateway remain untouched. The generated CA key is not a runtime mount input. Partial preparations are retained; do not rerun apply in a failed snapshot.

Source validation uses actual OpenSSL key generation, key-pair/hostname acceptance and wrong-hostname refusal, role-owned mode-0600 files and public trust parsing in a root-private CI fixture. Those are preparation tests, not actual target TLS connectivity or application acceptance.

## Remaining outcome

After target private-input preparation, the role-specific runtime configuration, candidate creation transaction and existing admission/guard/lease consumers still need completion. No real national discovery job or Teatri candidate exists yet. Semantic/MCP rollout, governed adoption/review/approval, ingestion and UDP chat readback remain incomplete. The product flow must be executed through MCP; this operator bootstrap is infrastructure preparation.
