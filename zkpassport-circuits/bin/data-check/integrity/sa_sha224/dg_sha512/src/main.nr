// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use noir_utils::HyliOutput;
use commitment::commit_to_disclosure;
use data_check_integrity::{check_dg1_sha512, check_signed_attributes_sha224, get_dg2_hash_from_econtent};
use utils::{types::{DG1Data, EContentData, SignedAttrsData, SaltedValue}, constants::{SHA512_IDENTIFIER, SHA512_DIGEST_LENGTH}};

fn main(
    hyli: HyliOutput<64>,
    comm_in: Field,
    salt_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<Field>,
) {
    // Get the length of e_content by parsing the ASN.1
    // Safety: This is safe because the length must be correct for econtent to hash to
    // the expected digest in signed attributes as checked below in check_signed_attributes_sha512
    let e_content_size =
        unsafe { utils::unsafe_get_asn1_element_length(e_content) };
    // Check the integrity of the data
    check_dg1_sha512(salted_dg1.value, e_content, e_content_size);
    // Get the length of signed_attributes by parsing the ASN.1
    // Safety: This is safe because the length was checked in the ID data circuit and the whole signed attributes
    // was committed over in that same circuit
    let signed_attributes_size =
        unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    check_signed_attributes_sha224(
        signed_attributes,
        e_content,
        e_content_size,
    );

    // Get the hash of DG2 from eContent
    let dg2_hash = get_dg2_hash_from_econtent(e_content, e_content_size);

    let comm_out = commit_to_disclosure::<SHA512_DIGEST_LENGTH>(
        comm_in,
        salt_in,
        salted_dg1,
        expiry_date_salt,
        SaltedValue::from_value(dg2_hash_salt, dg2_hash),
        SaltedValue::from_value(dg2_hash_salt, SHA512_IDENTIFIER),
        signed_attributes,
        signed_attributes_size as Field,
        e_content,
        salted_private_nullifier,
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
