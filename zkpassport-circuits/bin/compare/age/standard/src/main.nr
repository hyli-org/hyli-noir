use noir_utils::HyliOutput;
use commitment::nullify;
use compare_age::{calculate_param_commitment, compare_age};
use data_check_expiry::check_expiry;
use utils::types::{DG1Data, SaltedValue};
use utils::types::MRZExpiryDate;

// Blob size for disclosure circuits: param_commitment (32) + nullifier_type (32) + nullifier (32) = 96 bytes
global DISCLOSURE_BLOB_SIZE: u32 = 96;

fn main(
    hyli: HyliOutput<96>,
    comm_in: Field,
    current_date: u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    // @committed
    // The minimum age required is public (via the parameter commitment) so verifiers can check
    // the age provided to the proof is correct
    min_age_required: u8,
    // @committed
    // The maximum age required is public (via the parameter commitment) so verifiers can check
    // the age provided to the proof is correct
    // If the maximum age is 0, it is not checked
    max_age_required: u8,
    nullifier_secret: Field,
    service_scope: Field,
    service_subscope: Field,
) {
    // Check the ID is not expired
    check_expiry(salted_dg1.value, current_date);

    // Verify the age of the ID holder
    compare_age(
        salted_dg1.value,
        min_age_required,
        max_age_required,
        current_date,
    );
    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    // Use Poseidon2 to calculate the parameter commitment so the prover has less work to do
    let param_commitment = calculate_param_commitment(min_age_required, max_age_required);

    // Build blob: param_commitment (32) + nullifier_type (32) + nullifier (32) = 96 bytes
    let mut blob: BoundedVec<u8, DISCLOSURE_BLOB_SIZE> = BoundedVec::new();
    blob.extend_from_array(param_commitment.to_be_bytes::<32>());
    blob.extend_from_array(nullifier_type.to_be_bytes::<32>());
    blob.extend_from_array(nullifier.to_be_bytes::<32>());

    // Validate HyliOutput
    assert(hyli.blob == blob.storage(), "blob mismatch");
    assert(hyli.success == true);
    assert(hyli.version == 1);
    assert(hyli.initial_state_len == 4);
    assert(hyli.next_state_len == 4);
    assert(hyli.initial_state == [0; 4]);
    assert(hyli.next_state == [0; 4]);
    assert(hyli.blob_capacity == DISCLOSURE_BLOB_SIZE);
    assert(hyli.blob_len == DISCLOSURE_BLOB_SIZE);
    assert(hyli.blob_number == 1);
    assert(hyli.tx_blob_count >= 1);
}
