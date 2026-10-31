# OUF Ingestion Core Contract Consistency Check — v0.5

## Scope

Checked only:

`CanonicalDataEnvelope v1 -> HandoffPayload v1 -> LineageRecord v1`

No new DTO, API, capability, infrastructure component or module responsibility has been introduced.

## Result

**PASS**

Valid fixture:
- return code: 0
- output: `OUF core contract consistency OK.`

Negative fixture:
- return code: 1
- detected mismatches:
```
CC-02 run identity: 'run-CC01' != 'run-WRONG'
CC-07 bundle ref: 'suo-prod-bundle@12' != 'suo-prod-bundle@13'
CC-13 correlationId: 'corr-CC01' != 'corr-WRONG'
```

## Naming/representation findings

1. `runId` vs `ingestionRunId`: same semantic run identity; explicit invariant, no schema rename.
2. split `sourceSchemaId` + `sourceSchemaVersion` vs opaque `sourceSchemaRef`: must resolve the same exact historical version.
3. split `configurationBundleId` + `configurationBundleVersion` vs `bundleRef`: same rule.
4. `observedAt` vs `sourceObservedAt`: explicit propagation mapping.
5. `contentHash` vs `outputHash`: conditional equality only when lineage `outputHash` is the exact logical content delivered in the handoff.

## Conclusion

The three Ingestion core contracts are internally consistent once the cross-contract mappings in
`consistency/cross-contract-invariants.yaml` are applied. No blocking semantic contradiction was found.
