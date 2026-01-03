// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use noir_utils::HyliOutput;
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use sig_check_rsa::verify_signature;
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    hyli: HyliOutput<64>,
    comm_in: Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey: [u8; 512],
    dsc_pubkey_redc_param: [u8; 513],
    sod_signature: [u8; 512],
    tbs_certificate: [u8; 1200],
    signed_attributes: SignedAttrsData,
    exponent: u32,
    e_content: EContentData,
    
) {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length must be correct for the hash and signature to be valid
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    assert(verify_signature::<512, 0, 220, 48>(
        dsc_pubkey,
        sod_signature,
        dsc_pubkey_redc_param,
        exponent,
        signed_attributes,
        signed_attributes_size,
        0,
    ), "RSA signature verification failed");
    let comm_out = commit_to_id(
        comm_in,
        salt_in,
        salt_out,
        dg1,
        tbs_certificate,
        sod_signature,
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
    );

    // Build blob: comm_in (32 bytes) + comm_out (32 bytes)
    let mut blob: BoundedVec<u8, 64> = BoundedVec::new();
    blob.extend_from_array(comm_in.to_be_bytes::<32>());
    blob.extend_from_array(comm_out.to_be_bytes::<32>());

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
