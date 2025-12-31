# ZKPassport to Hyli Compatibility Implementation TODO

## Overview
Port ZKPassport Noir circuits to use HyliOutput<B> as public input instead of returning Field commitments.

## Status: COMPLETE

### Phase 1: Template Modification in circuit-builder.ts
- [x] Understand existing templates and patterns
- [x] Update NARGO_TEMPLATE to include noir_utils dependency
- [x] Update DSC_ECDSA_TEMPLATE to use HyliOutput
- [x] Update DSC_RSA_TEMPLATE to use HyliOutput
- [x] Update ID_DATA_ECDSA_TEMPLATE to use HyliOutput
- [x] Update ID_DATA_RSA_TEMPLATE to use HyliOutput
- [x] Update DATA_INTEGRITY_CHECK_TEMPLATE to use HyliOutput
- [x] Update FACEMATCH_ANDROID_TEMPLATE to use HyliOutput
- [x] Update OUTER_CIRCUIT_TEMPLATE to use HyliOutput

### Phase 2: Static Circuit Updates
- [x] Update compare_age (standard/evm)
- [x] Update compare_expiry (standard/evm)
- [x] Update compare_birthdate (standard/evm)
- [x] Update disclose_bytes (standard/evm)
- [x] Update bind (standard/evm)
- [x] Update exclusion_check circuits
- [x] Update inclusion_check circuits
- [x] Update facematch_ios circuits

### Phase 3: Restructure and Verify
- [x] Move circuits from zkpassport/ to zkpassport-circuits/
- [x] Fix path calculations for noir_utils dependencies
- [x] Add local copy of noir-utils for path resolution
- [x] Verify successful compilation with `nargo check`
- [x] Update documentation

## Blob Size Requirements
- DSC circuits: 64 bytes (comm_out + certificate_registry_root)
- ID Data circuits: 64 bytes (comm_in + comm_out)
- Data Integrity circuits: 64 bytes (comm_in + comm_out)
- Disclosure circuits: 96 bytes (param_commitment + nullifier_type + scoped_nullifier)
- FaceMatch circuits: 96 bytes (param_commitment + nullifier_type + scoped_nullifier)
- Outer circuits: 520 bytes (all public inputs)

## Final Structure
```
hyli-noir/
├── zkpassport-circuits/    # Hyli-compatible ZKPassport circuits
│   ├── Nargo.toml          # Workspace (955 members)
│   ├── noir-utils/         # Local copy for path resolution
│   ├── bin/                # 933 binary circuits
│   └── lib/                # 21 library modules
└── scripts/
    └── circuit-builder.ts  # Circuit generator template
```
