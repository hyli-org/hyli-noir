# ZKPassport to Hyli Compatibility Implementation Guide

You are an AI agent tasked with porting ZKPassport Noir circuits to be Hyli-compatible. This involves modifying the circuit templates in the TypeScript circuit builder to generate circuits that use `HyliOutput` as a public input.

## Project Locations

- **Main Project**: `/Users/matteo/projects/hyli-noir`
- **ZKPassport Circuits**: `/Users/matteo/projects/hyli-noir/zkpassport`
- **Hyli-compatible Examples**: `/Users/matteo/projects/hyli-noir/check-jwt`, `/Users/matteo/projects/hyli-noir/check-secret`
- **Noir Utils Library**: `/Users/matteo/projects/hyli-noir/noir-utils`

## Goal

Transform ZKPassport circuits from their current output format to Hyli-compatible format:

```
[Current ZKPassport Circuit] --outputs--> Field (commitment)
                            ↓
[Hyli-Compatible Circuit]   --validates--> HyliOutput<B> (public input)
```

The key change: Instead of returning a single `Field` commitment, circuits should accept a `HyliOutput<B>` struct as public input and validate that the computed values match expectations.

## Key Reference Files

### Files to Modify (ZKPassport)
| File | Purpose |
|------|---------|
| `zkpassport/src/ts/scripts/circuit-builder.ts` | Main circuit generator - modify templates |
| `zkpassport/src/noir/lib/*/` | Library modules may need adaptation |

### Reference Files (Do Not Modify)
| File | Purpose |
|------|---------|
| `noir-utils/src/lib.nr` | HyliOutput struct definition |
| `check-jwt/src/main.nr` | Example of Hyli-compatible circuit |
| `check-secret/src/main.nr` | Simple Hyli-compatible circuit example |

## HyliOutput Structure

```noir
pub struct HyliOutput<let B: u32> {
    pub version: u32,
    pub initial_state_len: u32,
    pub initial_state: [u8; 4],
    pub next_state_len: u32,
    pub next_state: [u8; 4],
    pub identity_len: u8,
    pub identity: str<256>,
    pub tx_hash: str<64>,
    pub index: u32,
    pub blob_number: u32,
    pub blob_index: u32,
    pub blob_contract_name_len: u8,
    pub blob_contract_name: str<256>,
    pub blob_capacity: u32,
    pub blob_len: u32,
    pub blob: [u8; B],       // Generic size parameter
    pub tx_blob_count: u32,
    pub success: bool,
}
```

## Circuit Categories to Port

### Priority 1: Disclosure Circuits (22 static circuits)
These are the most user-facing circuits:
- `compare_age` / `compare_age_evm`
- `compare_birthdate` / `compare_birthdate_evm`
- `compare_expiry` / `compare_expiry_evm`
- `disclose_bytes` / `disclose_bytes_evm`
- `bind` / `bind_evm`
- `exclusion_check_*` / `inclusion_check_*`

### Priority 2: Data Integrity Check Circuits (25 generated)
- `data_check_integrity_sa_*_dg_*`

### Priority 3: Signature Check Circuits (933+ generated)
- DSC circuits: `sig_check_dsc_*`
- ID Data circuits: `sig_check_id_data_*`

### Priority 4: FaceMatch Circuits (500+ generated)
- iOS: `facematch_ios` / `facematch_ios_evm`
- Android: `facematch_android_*`

### Priority 5: Outer Circuits (10 generated)
- `outer_count_*` (recursive proof verification)

## Implementation Strategy

### Step 1: Add noir-utils dependency
Update `Nargo.toml` templates in `circuit-builder.ts` to include:
```toml
noir_utils = { path = "path/to/noir-utils" }
```

### Step 2: Modify Circuit Templates

**Current Pattern** (example from DSC ECDSA):
```noir
fn main(
    certificate_registry_root: pub Field,
    // ... other inputs
) -> pub Field {
    // ... computation
    let comm_out = commit_to_dsc(...);
    comm_out
}
```

**New Hyli Pattern**:
```noir
use noir_utils::HyliOutput;

fn main(
    hyli: HyliOutput<BLOB_SIZE>,  // Public input - size depends on circuit
    certificate_registry_root: Field,  // Now private (or can stay pub)
    // ... other inputs
) {
    // ... same computation
    let comm_out = commit_to_dsc(...);

    // Build blob from circuit outputs
    let mut blob: BoundedVec<u8, BLOB_SIZE> = BoundedVec::new();
    blob.extend_from_array(comm_out.to_be_bytes::<32>());
    // ... add other relevant data to blob

    // Validate HyliOutput
    assert(hyli.blob == blob.storage(), "blob mismatch");
    assert(hyli.success == true);
    assert(hyli.version == 1);
    // ... other standard Hyli assertions
}
```

### Step 3: Determine Blob Content Per Circuit Type

Each circuit type needs its own blob structure. Consider what data verifiers need:

**DSC Circuits** (Blob ~64-96 bytes):
- `comm_out` (32 bytes) - the commitment
- `certificate_registry_root` (32 bytes) - for verification context

**ID Data Circuits** (Blob ~64-96 bytes):
- `comm_in` (32 bytes) - input commitment
- `comm_out` (32 bytes) - output commitment

**Data Integrity Circuits** (Blob ~64 bytes):
- `comm_in` (32 bytes)
- `comm_out` (32 bytes)

**Disclosure Circuits** (Blob varies):
- Parameter commitment
- Nullifier type
- Scoped nullifier
- Disclosed data (circuit-specific)

**FaceMatch Circuits** (Blob ~96 bytes):
- Parameter commitment (32 bytes)
- Nullifier type (32 bytes)
- Nullifier (32 bytes)

### Step 4: Update TypeScript Templates

Modify these template functions in `circuit-builder.ts`:
- `DSC_ECDSA_TEMPLATE`
- `DSC_RSA_TEMPLATE`
- `ID_DATA_ECDSA_TEMPLATE`
- `ID_DATA_RSA_TEMPLATE`
- `DATA_INTEGRITY_CHECK_TEMPLATE`
- `FACEMATCH_ANDROID_TEMPLATE`
- `OUTER_CIRCUIT_TEMPLATE`

Also update `NARGO_TEMPLATE` to include `noir_utils` dependency.

### Step 5: Update Static Circuits

The static circuits in `STATIC_CIRCUITS` array also need manual porting:
- `zkpassport/src/noir/bin/compare/age/standard/src/main.nr`
- `zkpassport/src/noir/bin/disclose/bytes/standard/src/main.nr`
- etc.

## Important Notes

### Blob Size Determination
The generic parameter `B` in `HyliOutput<B>` must be a compile-time constant. Calculate the exact blob size needed for each circuit type and use that as the template parameter.

### Naming Convention
Consider creating Hyli-specific circuit variants:
- Original: `sig_check_dsc_tbs_1000_ecdsa_nist_p256_sha256`
- Hyli: `sig_check_dsc_tbs_1000_ecdsa_nist_p256_sha256_hyli`

Or replace entirely if Hyli is the only target.

### Commit Strategy
Make frequent commits after each milestone:
```bash
git add -A && git commit -m "feat: port DSC ECDSA template to Hyli format"
git push
```

### Notes Location
Store implementation notes in `.agent/NOTES.md` and track progress in `.agent/TODO.md`.

## Success Criteria

The implementation is complete when:
1. All circuit templates in `circuit-builder.ts` generate Hyli-compatible circuits
2. `bun run zkpassport/src/ts/scripts/circuit-builder.ts generate` successfully generates new circuits
3. Static circuits are manually ported to Hyli format
4. `nargo compile` succeeds for at least a representative sample of circuits
5. A test proof can be generated and validated with HyliOutput

