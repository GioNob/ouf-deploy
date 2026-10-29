# Recommended module repository layout

```text
<module>/
├── src/
├── db/migration/              # if persistent
├── openapi/
├── schemas/                   # module-owned contracts only
├── examples/
├── contracts/                 # immutable reference/link to ouf-contracts freeze
├── helm/
├── docs/runbook/
├── tests/contract/
├── tests/integration/
├── tests/e2e/
└── sbom/                      # generated in CI
```

The exact internal Java package layout may follow domain/application/adapters/boot or the module PET, but shared OUF contracts must remain external canonical artifacts.
