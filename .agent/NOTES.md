# Implementation Notes

## Summary

The ZKPassport circuits have been successfully ported to Hyli-compatible format. The key changes are:

1. **All circuits now use HyliOutput as public input** instead of returning Field/tuple values
2. **Blob contents are validated** by building expected blob and comparing against HyliOutput.blob
3. **Standard Hyli assertions** are included (version, state, blob metadata)

## Changes Made

### circuit-builder.ts Templates Updated
- `DSC_ECDSA_TEMPLATE`: HyliOutput<64>
- `DSC_RSA_TEMPLATE`: HyliOutput<64>
- `ID_DATA_ECDSA_TEMPLATE`: HyliOutput<64>
- `ID_DATA_RSA_TEMPLATE`: HyliOutput<64>
- `DATA_INTEGRITY_CHECK_TEMPLATE`: HyliOutput<64>
- `FACEMATCH_ANDROID_TEMPLATE`: HyliOutput<96>
- `OUTER_CIRCUIT_TEMPLATE`: HyliOutput<520>

### Static Circuits Updated (22 total)
- compare/age, compare/expiry, compare/birthdate (standard/evm)
- disclose/bytes (standard/evm)
- bind (standard/evm)
- exclusion-check/issuing-country, exclusion-check/nationality, exclusion-check/sanctions (standard/evm)
- inclusion-check/issuing-country, inclusion-check/nationality (standard/evm)
- facematch/ios (standard/evm)

### Generated Circuits
All 900+ circuits regenerated with:
- noir_utils dependency added to Nargo.toml
- HyliOutput pattern in main.nr

## Path Resolution

The noir_utils path calculation depends on circuit depth:
- **DSC/ID Data circuits** (10 levels deep): `../../../../../../../../../../../noir-utils`
- **Data Integrity circuits** (7 levels deep): `../../../../../../../../noir-utils`
- **Disclosure circuits** (6 levels deep): `../../../../../../../noir-utils`
- **Outer circuits** (6 levels deep): `../../../../../../../noir-utils`
- **FaceMatch Android** (dynamic): calculated based on intermediate certificate count

## Important: Compilation

**You must run `nargo check` from the parent directory (`hyli-noir/`)**, not from inside `zkpassport/`. This is due to how nargo resolves relative paths.

```bash
cd /path/to/hyli-noir  # NOT zkpassport
nargo check
```

## Commits Made

1. `feat: port circuit templates to Hyli-compatible format` - Template changes
2. `feat: port all static disclosure circuits to Hyli-compatible format` - Static circuit changes
3. `feat: fix noir_utils dependency paths and regenerate all circuits` - Path fixes + regeneration

## Testing

The circuits pass `nargo check` when run from the hyli-noir parent directory.
