# Untrusted installed producer static observation — 12 October 2026

The selected source is /opt/ouf/ops/refresh-policy-token.py (operator-reported root:root0755, regular, one link). /opt/ouf is UID/GID1000 mode0750. The authenticated reader remains blocked; its guard is unchanged.

This separate diagnostic is explicitly an UNTRUSTED static observation, never authentication or writer/output authority. It opens the exact selected path using descriptor-relative no-follow traversal and requires the exact reported custody for /opt, /opt/ouf and /opt/ouf/ops, plus root:root0755 regular single-link source <=128KiB. It checks descriptor and path identities through all ancestors after the bounded read, observes twice, and confirms selected root oneshot Python routing before/after. Any source/path/configuration drift blocks, without retry.

It parses AST but never imports or executes producer code. All string/numeric literal values are replaced with opaque markers; only a small set of public protocol dictionary KEY names are retained. Output is capped at12,000 characters and truncation disclosed. It reads this installed CODE file twice; it does not follow its references or read token, delegation key, EnvironmentFile, credential config or imported modules. No grants, provider calls, service mutations, custody changes, baseline refresh or R12 operations.

The source digest is only an observed code fingerprint, not approved install provenance. Literal redaction hides endpoint/output values, so this read alone cannot prove mount0 correspondence or issuer/client scope. Native fixtures exercise no-execution, literal redaction, symlink/hardlink/FIFO/size/custody denial, replacement during read, direct command routing and UID1000 ancestry. Local8passed/1nativeownershipfixture skipped; CI target qualification pending.

No root custody repair is proposed until observed source behavior and installation provenance are reviewed. Do not globally chown/chmod /opt/ouf or copy unauthenticated source into an approved root path.
