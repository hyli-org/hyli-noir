# ZKPassport to Hyli Compatibility Implementation Plan

## Architecture Change

### Current Pattern
```noir
fn main(
    certificate_registry_root: pub Field,
    // ... inputs
) -> pub Field {
    // compute
    commit_out
}
```

### New Hyli Pattern
```noir
use noir_utils::HyliOutput;

fn main(
    hyli: HyliOutput<BLOB_SIZE>,
    certificate_registry_root: Field,  // Now private or can stay pub
    // ... inputs
) {
    // compute
    // Build blob
    let mut blob: BoundedVec<u8, BLOB_SIZE> = BoundedVec::new();
    blob.extend_from_array(commit_out.to_be_bytes::<32>());
    // ... add other data

    // Validate HyliOutput
    assert(hyli.blob == blob.storage());
    assert(hyli.success == true);
    assert(hyli.version == 1);
    // ... standard assertions
}
```

## Blob Structures by Circuit Type

### DSC Circuits (64 bytes)
```
| comm_out (32 bytes) | certificate_registry_root (32 bytes) |
```

### ID Data Circuits (64 bytes)
```
| comm_in (32 bytes) | comm_out (32 bytes) |
```

### Data Integrity Circuits (64 bytes)
```
| comm_in (32 bytes) | comm_out (32 bytes) |
```

### Disclosure Circuits (96 bytes)
```
| param_commitment (32 bytes) | nullifier_type (32 bytes) | scoped_nullifier (32 bytes) |
```

### FaceMatch Circuits (96 bytes)
```
| param_commitment (32 bytes) | nullifier_type (32 bytes) | scoped_nullifier (32 bytes) |
```

### Outer Circuits
More complex - needs careful consideration of what goes in blob.

## Implementation Steps

1. **Modify NARGO_TEMPLATE** - Add noir_utils dependency
2. **Create helper functions** - For blob building and HyliOutput assertions
3. **Update each template** - One at a time with careful testing
4. **Update static circuits** - Manual updates to 22 circuits
5. **Regenerate** - Run circuit generation
6. **Test** - Compile and verify

## Path Calculations
- From `zkpassport/src/noir/bin/sig-check/dsc/tbs_X/ecdsa/family/curve/hash/` to `noir-utils/`:
  - 9 levels up, then into noir-utils: `../../../../../../../../../noir-utils`

- From `zkpassport/src/noir/bin/data-check/integrity/sa_X/dg_Y/`:
  - 7 levels up: `../../../../../../noir-utils`
