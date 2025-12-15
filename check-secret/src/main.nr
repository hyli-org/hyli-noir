// Simple Token Contract implementation in Noir
use noir_utils::HyliOutput32 as HyliOutput;

fn main(
    // The version of the HyleOutput. This is unchecked for now.
    hyli_output: HyliOutput,
    // ------ Private inputs ------
    password: [u8; 32],
) {
    // Build padded "identity:password" buffer
    let mut id: BoundedVec<u8, 256> = BoundedVec::from_parts(
        hyli_output.identity.as_bytes(),
        hyli_output.identity_len as u32,
    );
    id.extend_from_slice(":".as_bytes());
    id.extend_from_slice(password);

    // Hash the combined input using SHA-256
    let input_hash = sha256::sha256_var(id.storage(), hyli_output.identity_len as u32 + 1 + 32);

    assert(input_hash == hyli_output.blob);

    assert(hyli_output.success == true);
    assert(hyli_output.version == 1);
    assert(hyli_output.initial_state_len == 4);
    assert(hyli_output.next_state_len == 4);
    assert(hyli_output.initial_state == [0; 4]);
    assert(hyli_output.next_state == [0; 4]);
    assert(hyli_output.blob_capacity == 32);
    assert(hyli_output.blob_len == 32);
    assert(hyli_output.blob_number == 1);
    assert(hyli_output.tx_blob_count >= 1);
}
