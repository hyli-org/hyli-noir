import { Barretenberg, Fr, reconstructHonkProof, UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js";
import defaultCircuit from "../check-jwt/target/check-jwt.json";
import { assert, b64urlToU8, bytesToBigInt, flattenFieldsAsArray } from "./common";
import { generateInputs } from "noir-jwt";
import { Blob } from "hyli";

export const build_proof_transaction = async ({
  identity,
  stored_hash,
  tx,
  blob_index,
  tx_blob_count,
  idToken,
  jwtPubkey,
  circuit = defaultCircuit as CompiledCircuit,
}: {
  identity: string;
  stored_hash: number[];
  tx: string;
  blob_index: number;
  tx_blob_count: number;
  idToken: string;
  jwtPubkey: JsonWebKey;
  circuit: CompiledCircuit;
}) => {
  if (!idToken || !jwtPubkey) {
    throw new Error("[JWT Circuit] Proof generation failed: idToken and jwtPubkey are required");
  }

  const jwtInputs = await generateInputs({
    jwt: idToken,
    pubkey: jwtPubkey,
    shaPrecomputeTillKeys: ["email", "email_verified", "nonce"],
    maxSignedDataLength: 640,
  });

  const inputs = {
    ...generateProverData(identity, stored_hash, tx, blob_index, tx_blob_count),
    partial_data: jwtInputs.partial_data,
    partial_hash: jwtInputs.partial_hash,
    full_data_length: jwtInputs.full_data_length,
    base64_decode_offset: jwtInputs.base64_decode_offset,
    jwt_pubkey_modulus_limbs: jwtInputs.pubkey_modulus_limbs,
    jwt_pubkey_redc_params_limbs: jwtInputs.redc_params_limbs,
    jwt_signature_limbs: jwtInputs.signature_limbs,
  };

  const backend = new UltraHonkBackend(circuit.bytecode);
  const vk = await backend.getVerificationKey();
  const noir = new Noir(circuit as CompiledCircuit);

  // Generate witness and prove
  const startTime = performance.now();
  const { witness } = await noir.execute(inputs as InputMap);

  const proof = await backend.generateProof(witness);
  const provingTime = performance.now() - startTime;

  const reconstructedProof = reconstructHonkProof(flattenFieldsAsArray(proof.publicInputs), proof.proof);

  console.log(`Proof generated in ${provingTime}ms`);

  return {
    contract_name: "check_jwt",
    program_id: Array.from(vk),
    verifier: "noir",
    proof: Array.from(reconstructedProof),
  };
};

export async function jwk_pubkey_mod(jwk: JsonWebKey) {
  // Parse pubkeyJWK
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"],
  );

  const publicKeyJWK = await crypto.subtle.exportKey("jwk", publicKey);
  const modulusBigInt = BigInt("0x" + Buffer.from(publicKeyJWK.n as string, "base64").toString("hex"));

  return modulusBigInt;
}

const generateProverData = (id: string, stored_hash: number[], tx_hash: string, blob_index: number, tx_blob_count: number): InputMap => {
  const version = 1;
  const initial_state = [0, 0, 0, 0];
  const initial_state_len = initial_state.length;
  const next_state = [0, 0, 0, 0];
  const next_state_len = next_state.length;
  const identity_len = id.length;
  const identity = id.padEnd(256, "0");
  const tx_hash_padded = tx_hash.padEnd(64, "0");
  const tx_hash_len = tx_hash.length;
  const index = blob_index;
  const blob_number = 1;
  const blob_contract_name_len = "check_jwt".length;
  const blob_contract_name = "check_jwt".padEnd(256, "0");
  const blob_capacity = 306;
  const blob_len = 306;
  const blob: number[] = stored_hash;
  const success = 1;
  assert(blob.length == blob_len, `Blob length is ${blob.length} not 306 bytes`);

  return {
    version,
    initial_state,
    initial_state_len,
    next_state,
    next_state_len,
    identity,
    identity_len,
    tx_hash: tx_hash_padded,
    tx_hash_len,
    index,
    blob_number,
    blob_index,
    blob_contract_name_len,
    blob_contract_name,
    blob_capacity,
    blob_len,
    blob,
    tx_blob_count,
    success,
  };
};

export const extract_jwt_claims = (jwt: string): { email: string; nonce: string; kid: string } => {
  const [header, payload] = jwt.split(".");
  const headers = JSON.parse(atob(header));
  const json = JSON.parse(atob(payload));
  const email = json.email.toLowerCase();
  const nonce = json.nonce.toLowerCase();
  const kid = headers.kid;

  return { email, nonce, kid };
};

export const build_blob = (mail_hash: Uint8Array, nonce: string, pubkey: string): Blob => {
  let encoded = Uint8Array.from(`${nonce}`, (c) => c.charCodeAt(0));
  let remaining_len = 16 - encoded.length;

  let zeros = new Array(remaining_len).fill(0);

  const jwtBlob: Blob = {
    contract_name: "check_jwt",
    data: [...mail_hash, 58, ...encoded, ...zeros, 58, ...b64urlToU8(pubkey).reverse()],
  };

  return jwtBlob;
};

export const poseidon_hash = async (string: string) => {
  const bb = await Barretenberg.new();
  return await bb.poseidon2Hash([new Fr(bytesToBigInt(new TextEncoder().encode(string)))]);
};
