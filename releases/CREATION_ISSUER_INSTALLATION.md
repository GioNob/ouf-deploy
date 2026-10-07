# Install creation issuer source and reference existing authority

Run `scripts/bootstrap-creation-issuer-installation.sh` at revision `942acda2ca5d0638714c2958ffe6dfdff427340c` on the VPS as oufadmin. SHA256: `95f8a7911fa49422c32b75ef68a18ef8bf005d4e49078c33f3be010b6251fad7`.

This bounded action creates a fresh root-private source snapshot and authority-reference profile. It compiles but never executes the 19 installed source bodies, verifies the fixed historical custody/policy hashes, checks each existing public key against the policy and checks private-key metadata without opening either key. It preserves original policy, keys and receipts and creates no general sudo rule. No transaction is configured or signed, no consumer is linked, no container/daemon/rule/database/IAM/provider action is invoked.

Actual installation is pending. The final source-installation receipt reports `SOURCE_INSTALLED_EXISTING_AUTHORITY_BOUND`; that is a source installation, not provider activation. Unknown/partial failures preserve their root snapshot and claim. Do not rerun or erase a failed package. Supply the redacted report and snapshot path for reconciliation. Bootstrap download failures before root copy modify only a private temporary directory.

Evidence and CI are recorded in `evidence/discovery-creation-intent-preparation-20261007.json`. The transaction-specific accepted artifacts, fresh mandates, broker/runtime profiles, target guard/admission/lease/reboot proof and product rollout remain required. Product operations remain chatbot/MCP-only.
