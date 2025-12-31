// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use noir_utils::HyliOutput;
use commitment::commit_to_dsc;
use sig_check_common::sha512_and_check_data_to_sign;
use sig_check_ecdsa::verify_brainpool_512r1;
use utils::{split_array, types::Alpha3CountryCode};

fn main(
    hyli: HyliOutput<64>,
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 16],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    csc_pubkey_x: [u8; 64],
    csc_pubkey_y: [u8; 64],
    dsc_signature: [u8; 128],
    tbs_certificate: [u8; 700],
) {
    // Get the length of tbs_certificate by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let tbs_certificate_len =
        unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    let (r, s) = split_array(dsc_signature);
    let msg_hash = sha512_and_check_data_to_sign(tbs_certificate, tbs_certificate_len);
    assert(verify_brainpool_512r1(csc_pubkey_x, csc_pubkey_y, r, s, msg_hash), "ECDSA signature verification failed");
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        csc_pubkey_x.concat(csc_pubkey_y),
    );

    // Build blob: comm_out (32 bytes) + certificate_registry_root (32 bytes)
    let mut blob: BoundedVec<u8, 64> = BoundedVec::new();
    blob.extend_from_array(comm_out.to_be_bytes::<32>());
    blob.extend_from_array(certificate_registry_root.to_be_bytes::<32>());

    // Validate HyliOutput
    assert(hyli.blob == blob.storage(), "blob mismatch");
    assert(hyli.success == true);
    assert(hyli.version == 1);
    assert(hyli.initial_state_len == 4);
    assert(hyli.next_state_len == 4);
    assert(hyli.initial_state == [0; 4]);
    assert(hyli.next_state == [0; 4]);
    assert(hyli.blob_capacity == 64);
    assert(hyli.blob_len == 64);
    assert(hyli.blob_number == 1);
    assert(hyli.tx_blob_count >= 1);
}
