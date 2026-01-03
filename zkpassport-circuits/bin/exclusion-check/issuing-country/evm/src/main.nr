use noir_utils::HyliOutput;
use commitment::nullify;
use data_check_expiry::check_expiry;
use exclusion_check_country::{calculate_param_commitment_sha2, check_issuing_country_exclusion};
use utils::{constants::PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION, types::{DG1Data, SaltedValue}};
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
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    // The list must be sorted in ascending order
    // For efficiency, the list is not sorted in the circuit
    // but it is checked to be sorted.
    // So it is up to the prover to properly sort the list before passing it to the circuit
    // or the proof will fail to generate
    country_list: [u32; 200],
    nullifier_secret: Field,
    service_scope: Field,
    service_subscope: Field,
) {
    // Check the ID is not expired
    check_expiry(salted_dg1.value, current_date);

    // Check that the issuing country of the passport is not in the list of countries
    check_issuing_country_exclusion(salted_dg1.value, country_list);
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
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment =
        calculate_param_commitment_sha2(PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION, country_list);

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
