import { Barretenberg, Fr, reconstructHonkProof, UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit, InputMap, Noir } from "@noir-lang/noir_js";
import defaultCircuit from "../target/check_jwt.json";
import { assert, b64urlToU8, bytesToBigInt, flattenFieldsAsArray } from "./common";
import { generateInputs } from "noir-jwt";
import { Blob, NodeApiHttpClient } from "hyli";

export const contract_name = "check_jwt";

/**
 * Generates a cryptographic proof for a transaction using a JWT circuit.
 *
 * @param {Object} params - Parameters required for proof generation.
 * @param {string} params.identity - The user's identity string.
 * @param {number[]} params.stored_hash - The precomputed/stored hash.
 * @param {string} params.tx - The transaction identifier or hash.
 * @param {number} params.blob_index - The index of the blob within the transaction.
 * @param {number} params.tx_blob_count - The total number of blobs in the transaction.
 * @param {string} params.idToken - The signed JWT token.
 * @param {JsonWebKey} params.jwtPubkey - The JWT public key in JWK format.
 * @param {CompiledCircuit} params.circuit - The compiled circuit to execute (defaults to check-jwt).
 *
 * @returns {Promise<{ contract_name: string; program_id: number[]; verifier: string; proof: number[] }>}
 * An object containing verifier details and the generated proof.
 */
export const build_proof_transaction = async (
  identity: string,
  stored_hash: number[],
  tx: string,
  blob_index: number,
  tx_blob_count: number,
  idToken: string,
  jwtPubkey: JsonWebKey,
  circuit: CompiledCircuit = defaultCircuit as CompiledCircuit,
  jwtInputsOverride?: Awaited<ReturnType<typeof generateInputs>>
): Promise<{ contract_name: string; program_id: number[]; verifier: string; proof: number[] }> => {
  if (!jwtInputsOverride && (!idToken || !jwtPubkey)) {
    throw new Error("[JWT Circuit] Proof generation failed: idToken and jwtPubkey are required");
  }

  const jwtInputs =
    jwtInputsOverride ??
    (await generateInputs({
      jwt: idToken,
      pubkey: jwtPubkey,
      shaPrecomputeTillKeys: ["email", "email_verified", "nonce"],
      maxSignedDataLength: 640,
    }));

  const inputs = {
    hyli: generateHyli(identity, stored_hash, tx, blob_index, tx_blob_count),
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
    contract_name,
    program_id: Array.from(vk),
    verifier: "noir",
    proof: Array.from(reconstructedProof),
  };
};

/**
 * Extracts and computes the modulus (n) from a JWK public key.
 *
 * @param {JsonWebKey} jwk - The public key in JWK format.
 * @returns {Promise<bigint>} The modulus of the public key as a BigInt.
 */
export async function jwk_pubkey_mod(jwk: JsonWebKey): Promise<bigint> {
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"]
  );

  const publicKeyJWK = await crypto.subtle.exportKey("jwk", publicKey);
  const modulusBytes = b64urlToU8(publicKeyJWK.n as string);
  const modulusBigInt = bytesToBigInt(modulusBytes);

  return modulusBigInt;
}

/**
 * Generates prover input data used to feed the zero-knowledge circuit.
 *
 * @param {string} id - User identity string.
 * @param {number[]} stored_hash - Stored hash array.
 * @param {string} tx_hash - Transaction hash.
 * @param {number} blob_index - Index of the blob in the transaction.
 * @param {number} tx_blob_count - Total number of blobs in the transaction.
 *
 * @returns {InputMap} Structured input data for the prover.
 */
const generateHyli = (id: string, stored_hash: number[], tx_hash: string, blob_index: number, tx_blob_count: number) => {
  const initial_state = [0, 0, 0, 0];
  const next_state = [0, 0, 0, 0];
  const blob_capacity = 512;
  const blob_len = 306;

  assert(stored_hash.length === blob_len, `Blob length is ${stored_hash.length} not ${blob_len} bytes`);

  const padded_blob = new Array(512).fill(0);
  for (let i = 0; i < stored_hash.length; i++) {
    padded_blob[i] = stored_hash[i];
  }

  return {
    version: 1,
    initial_state,
    initial_state_len: initial_state.length,
    next_state,
    next_state_len: next_state.length,
    identity: id.padEnd(256, "0"),
    identity_len: id.length,
    tx_hash: tx_hash.padEnd(64, "0"),
    index: blob_index,
    blob_number: 1,
    blob_index,
    blob_contract_name_len: contract_name.length,
    blob_contract_name: contract_name.padEnd(256, "0"),
    blob_capacity,
    blob_len,
    blob: padded_blob,
    tx_blob_count,
    success: true,
  };
};

/**
 * Extracts specific claims from a JWT.
 *
 * @param {string} jwt - A JWT string in the format header.payload.signature.
 * @returns {{ email: string; nonce: string; kid: string }}
 * An object containing the email, nonce, and key ID (kid).
 */
export const extract_jwt_claims = (jwt: string): { email: string; nonce: string; kid: string } => {
  const [header, payload] = jwt.split(".");
  const headers = JSON.parse(atob(header));
  const json = JSON.parse(atob(payload));
  const email = json.email.toLowerCase();
  const nonce = json.nonce.toLowerCase();
  const kid = headers.kid;

  return { email, nonce, kid };
};

/**
 * Registers the Noir contract with the node if it is not already registered.
 * The contract is identified by its name "check_secret".
 * If the contract is not found, it registers the contract using the provided circuit.
 *
 * @param node - The NodeApiHttpClient instance to interact with the NodeApiHttpClient
 * @returns A Promise that resolves when the contract is registered
 */
export const register_contract = async (
  node: NodeApiHttpClient,
  circuit = defaultCircuit as CompiledCircuit
): Promise<undefined | number[]> => {
  return await node
    .getContract(contract_name)
    .then(() => undefined)
    .catch(async () => {
      const backend = new UltraHonkBackend(circuit.bytecode);

      const vk = await backend.getVerificationKey();
      const contract = {
        verifier: "noir",
        program_id: Array.from(vk),
        state_commitment: [0, 0, 0, 0],
        contract_name,
      };

      await node.registerContract(contract);
      return contract.program_id;
    });
};

/**
 * Computes the Poseidon2 hash of a string.
 *
 * @param {string} string - The input string to be hashed.
 * @returns {Promise<Fr>} The Poseidon2 hash result.
 */
export const poseidon_hash = async (string: string): Promise<Fr> => {
  const bb = await Barretenberg.new();
  return await bb.poseidon2Hash([new Fr(bytesToBigInt(new TextEncoder().encode(string)))]);
};

export const build_blob_from_jwt = async <T extends { kid: string } & JsonWebKey>(
  jwt: string,
  keys: T[]
): Promise<{ blob: Blob; nonce: number; mail_hash: number[]; pubkey: JsonWebKey }> => {
  const { email, nonce, kid } = extract_jwt_claims(jwt);

  if (!email || !nonce || !kid) {
    const error = "Invalid Google token: missing email, nonce, or kid";
    throw new Error(error);
  }

  const pubkey: JsonWebKey | undefined = keys.find((key) => key.kid == kid);
  if (!pubkey) {
    throw new Error(`Google public key with id ${kid} not found`);
  }

  const nonce_int = parseInt(nonce, 10);
  const hash = await build_stored_hash(email, nonce_int, pubkey.n as string);

  return {
    nonce: nonce_int,
    mail_hash: hash.mail_hash,
    pubkey,
    blob: {
      contract_name,
      data: hash.stored_hash,
    },
  };
};

/**
 * Builds a blob representing a JWT, used for proof generation in the circuit.
 *
 * @param {Uint8Array} email - The hashed email value.
 * @param {string} nonce - The nonce value from the JWT.
 * @param {string} pubkey - The public key (base64url encoded).
 * @returns {Blob} A structured Blob object containing the JWT data.
 */
export const build_stored_hash = async (
  email: string,
  nonce: number,
  pubkey: string
): Promise<{ mail_hash: number[]; stored_hash: number[] }> => {
  const mail_hash: Fr = await poseidon_hash(email);
  let encoded = Uint8Array.from(`${nonce}`, (c) => c.charCodeAt(0));
  let remaining_len = 16 - encoded.length;

  let zeros = new Array(remaining_len).fill(0);

  return {
    mail_hash: Array.from(mail_hash.value),
    stored_hash: [...mail_hash.value, 58, ...encoded, ...zeros, 58, ...b64urlToU8(pubkey).reverse()],
  };
};
