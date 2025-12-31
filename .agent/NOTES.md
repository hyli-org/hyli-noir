# Implementation Notes

## Summary

The ZKPassport circuits have been successfully ported to Hyli-compatible format. The key changes are:

1. **All circuits now use HyliOutput as public input** instead of returning Field/tuple values
2. **Blob contents are validated** by building expected blob and comparing against HyliOutput.blob
3. **Standard Hyli assertions** are included (version, state, blob metadata)
4. **Circuits are now in `zkpassport-circuits/`** directory within the main project

## Project Structure

```
hyli-noir/
├── check-jwt/              # Existing Hyli-compatible JWT circuit
├── check-secret/           # Existing Hyli-compatible secret circuit
├── noir-utils/             # HyliOutput struct definition
├── zkpassport-circuits/    # New ZKPassport Hyli-compatible circuits
│   ├── Nargo.toml          # Workspace with all circuits
│   ├── noir-utils/         # Local copy of noir-utils (for path resolution)
│   ├── bin/                # Binary circuits
│   │   ├── bind/
│   │   ├── compare/
│   │   ├── data-check/
│   │   ├── disclose/
│   │   ├── exclusion-check/
│   │   ├── facematch/
│   │   ├── inclusion-check/
│   │   ├── main/outer/
│   │   └── sig-check/
│   └── lib/                # Library modules
│       ├── bind/
│       ├── commitment/
│       ├── compare/
│       ├── data-check/
│       ├── disclose/
│       ├── exclusion-check/
│       ├── facematch/
│       ├── inclusion-check/
│       ├── outer/
│       ├── sig-check/
│       └── utils/
└── scripts/
    └── circuit-builder.ts  # Circuit generator script (from zkpassport)
```

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

### Circuit Count
- Libraries: 21
- Binary circuits: 933
- Total: 955 workspace members (including noir-utils)

## Blob Size Requirements

- **DSC circuits**: 64 bytes (comm_out + certificate_registry_root)
- **ID Data circuits**: 64 bytes (comm_in + comm_out)
- **Data Integrity circuits**: 64 bytes (comm_in + comm_out)
- **Disclosure circuits**: 96 bytes (param_commitment + nullifier_type + scoped_nullifier)
- **FaceMatch circuits**: 96 bytes (param_commitment + nullifier_type + scoped_nullifier)
- **Outer circuits**: 520 bytes (all public inputs)

## Running nargo

To check all circuits:
```bash
cd zkpassport-circuits
nargo check
```

## Important Notes

1. **Local noir-utils copy**: The `zkpassport-circuits/noir-utils/` is a copy of the main `noir-utils/` to handle nargo's path resolution. Keep these in sync when updating.

2. **Path calculation**: All Nargo.toml files in circuits reference libraries using relative paths from their location to `zkpassport-circuits/lib/`.

3. **Circuit builder**: The `scripts/circuit-builder.ts` contains the templates used to generate circuits. It requires zkpassport dependencies to run.

## Commits Made

1. `feat: port circuit templates to Hyli-compatible format` - Template changes
2. `feat: port all static disclosure circuits to Hyli-compatible format` - Static circuit changes
3. `feat: fix noir_utils dependency paths and regenerate all circuits` - Path fixes + regeneration
4. `feat: restructure zkpassport circuits into main project` - Move to zkpassport-circuits/

## Testing

The circuits pass `nargo check` when run from the zkpassport-circuits directory.
