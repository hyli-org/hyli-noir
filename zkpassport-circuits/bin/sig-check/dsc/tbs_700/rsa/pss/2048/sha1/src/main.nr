// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use noir_utils::HyliOutput;
use commitment::commit_to_dsc;
use sig_check_rsa::verify_signature;
use utils::types::Alpha3CountryCode;

fn main(
    hyli: HyliOutput<64>,
    certificate_registry_root: Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; 16],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    tbs_certificate: [u8; 700],
    csc_pubkey: [u8; 256],
    csc_pubkey_redc_param: [u8; 257],
    dsc_signature: [u8; 256],
    exponent: u32,
    pss_salt_len: u32,
) {
    // Get the length of tbs_certificate by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let tbs_certificate_len =
        unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    assert(verify_signature::<256, 1, 700, 20>(
        csc_pubkey,
        dsc_signature,
        csc_pubkey_redc_param,
        exponent,
        tbs_certificate,
        tbs_certificate_len,
        pss_salt_len,
    ), "RSA signature verification failed");
    let comm_out = commit_to_dsc(
        certificate_registry_root,
        certificate_registry_index,
        certificate_registry_hash_path,
        certificate_tags,
        country,
        tbs_certificate,
        salt,
        csc_pubkey,
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
