import { Noir } from "@noir-lang/noir_js";
import { reconstructHonkProof, UltraHonkBackend } from "@aztec/bb.js";
import { CompiledCircuit, InputMap } from "@noir-lang/types";
import { Blob, ProofTransaction, NodeApiHttpClient } from "hyli";

/**
 * Hashes a password using SHA-256.
 * The password is converted to a Uint8Array and hashed using SHA-256.
 * The resulting hash is returned as a Uint8Array.
 *
 * @param password - The password string to hash
 * @returns A Promise resolving to the Uint8Array of the computed hash
 */
export const hash_password = async (password: string): Promise<Uint8Array> => {
  const hashed_password_bytes = await sha256(stringToBytes(password));
  return hashed_password_bytes;
};

/**
 * Hashes an identity and password together using SHA-256.
 * The identity is concatenated with ':' and the hashed password.
 * The resulting combined value is hashed again using SHA-256.
 * The resulting hash is returned as a hexadecimal string that can be
 * stored publicly.
 *
 * This function is mainly used to check the given password against a stored hash.
 *
 * @param identity - The user's identity string
 * @param password - The user's password string
 * @returns A Promise resolving to the hexadecimal string of the computed hash
 */
export const identity_hash = async (identity: string, password: string): Promise<string> => {
  const hashed_password_bytes = await sha256(stringToBytes(password));
  let encoder = new TextEncoder();
  let id_prefix = encoder.encode(`${identity}:`);
  let extended_id = new Uint8Array([...id_prefix, ...hashed_password_bytes]);
  const computed_hash = await sha256(extended_id);
  const computed_hash_hex = encodeToHex(computed_hash);
  return computed_hash_hex;
};

/**
 * Builds a blob transaction containing a secret derived from an identity and password.
 * The secret is constructed by:
 * 1. Hashing the password in order to have a fixed-size secret
 * 2. Concatenating the padded identity (to 64 chars) with ':' and the hashed password
 * 3. Hashing this combined value
 *
 * @param identity - The user's identity string
 * @param password - The user's password string
 * @returns A Promise resolving to a BlobTransaction containing the hashed secret
 */
export const build_blob = async (identity: string, password: string): Promise<Blob> => {
  const hashed_password_bytes = await sha256(stringToBytes(password));
  let encoder = new TextEncoder();
  let id_prefix = encoder.encode(`${identity}:`);
  let extended_id = new Uint8Array([...id_prefix, ...hashed_password_bytes]);
  const stored_hash = await sha256(extended_id);

  const secretBlob: Blob = {
    contract_name: "check_secret",
    data: Array.from(stored_hash),
  };

  return secretBlob;
};

import defaultCircuit from "../target/check_secret.json";
import { assert, encodeToHex, flattenFieldsAsArray, sha256, stringToBytes } from "./common";

/**
 * Builds a proof transaction by generating a zero-knowledge proof for checking a secret.
 * The proof demonstrates knowledge of a password that, when combined with an identity and hashed,
 * matches a stored hash value. The process involves:
 * 1. Hashing the password and combining it with the identity
 * 2. Generating a witness and proof using the UltraHonk backend
 * 3. Reconstructing and formatting the proof for the transaction
 *
 * @param identity - The user's identity string
 * @param password - The user's password string
 * @param tx_hash - The blob transaction hash string
 * @param circuit - The compiled Noir circuit (defaults to the check_secret circuit)
 * @returns A Promise resolving to a ProofTransaction containing the generated proof
 */
export const build_proof_transaction = async (
  identity: string,
  password: string,
  tx_hash: string,
  blob_index: number,
  tx_blob_count: number,
  circuit: CompiledCircuit = defaultCircuit as CompiledCircuit
): Promise<ProofTransaction> => {
  const noir = new Noir(circuit);
  const backend = new UltraHonkBackend(circuit.bytecode);
  const vk = await backend.getVerificationKey();

  const hashed_password_bytes = await sha256(stringToBytes(password));
  let encoder = new TextEncoder();
  let id_prefix = encoder.encode(`${identity}:`);
  let extended_id = new Uint8Array([...id_prefix, ...hashed_password_bytes]);
  const stored_hash = await sha256(extended_id);

  const { witness } = await noir.execute(
    generateProverData(identity, hashed_password_bytes, stored_hash, tx_hash, blob_index, tx_blob_count)
  );

  const proof = await backend.generateProof(witness);
  const reconstructedProof = reconstructHonkProof(flattenFieldsAsArray(proof.publicInputs), proof.proof);

  return {
    contract_name: "check_secret",
    program_id: Array.from(vk),
    verifier: "noir",
    proof: Array.from(reconstructedProof),
  };
};

/**
 * Registers the Noir contract with the node if it is not already registered.
 * The contract is identified by its name "check_secret".
 * If the contract is not found, it registers the contract using the provided circuit.
 *
 * @param node - The NodeApiHttpClient instance to interact with the NodeApiHttpClient
 * @param circuit - The compiled Noir circuit (defaults to the check_secret circuit)
 * @returns A Promise that resolves when the contract is registered
 */
export const register_contract = async (
  node: NodeApiHttpClient,
  circuit: CompiledCircuit = defaultCircuit as CompiledCircuit
): Promise<void> => {
  await node.getContract("check_secret").catch(async () => {
    const backend = new UltraHonkBackend(circuit.bytecode);

    const vk = await backend.getVerificationKey();

    await node.registerContract({
      verifier: "noir",
      program_id: Array.from(vk),
      state_commitment: [0, 0, 0, 0],
      contract_name: "check_secret",
    });
  });
};

/**
 * Generates the prover data required for the Noir circuit.
 *
 * @param id - The user's identity string
 * @param pwd - The hashed password as a Uint8Array
 * @param stored_hash - The stored hash as a Uint8Array
 * @param tx - The transaction hash string
 * @returns An object containing the prover data
 */
const generateProverData = (
  id: string,
  pwd: Uint8Array,
  stored_hash: Uint8Array,
  tx: string,
  blob_index: number,
  tx_blob_count: number
): InputMap => {
  const hyli_output = {
    version: 1,
    initial_state: [0, 0, 0, 0],
    initial_state_len: 4,
    next_state: [0, 0, 0, 0],
    next_state_len: 4,
    identity_len: id.length,
    identity: id.padEnd(256, "0"),
    tx_hash: tx.padEnd(64, "0"),
    index: blob_index,
    blob_number: 1,
    blob_index,
    blob_contract_name_len: "check_secret".length,
    blob_contract_name: "check_secret".padEnd(256, "0"),
    blob_capacity: 32,
    blob_len: 32,
    blob: (() => {
      const padded = new Array(32).fill(0);
      for (let i = 0; i < stored_hash.length; i++) {
        padded[i] = stored_hash[i];
      }
      return padded;
    })(),
    tx_blob_count,
    success: 1,
  };
  assert(hyli_output.blob.length === 32, "HyliOutput blob must be 32 bytes");
  const password: number[] = Array.from(pwd);
  assert(password.length == 32, "Password length is not 32 bytes");

  return { hyli_output, password };
};
