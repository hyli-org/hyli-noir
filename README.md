# Hyli-noir

Noir circuits and TypeScript helpers used by Hyli to build, store, and prove data blobs. The package ships the compiled circuits plus a small JS/TS API for generating blobs, building UltraHonk proofs, and registering the Noir contracts with a Hyli node.

## What's inside

- **check_secret circuit**: password-based proof showing a user knows the secret behind a stored hash (32-byte blobs).
- **check_jwt circuit**: JWT proof that binds an email + nonce + RSA public key to a transaction blob using `noir-jwt`.
- **Shared utilities**: hashing helpers and Noir proof serialization helpers (exported as `noir_utils`).

## Installation

```bash
npm install hyli-noir
npm install @aztec/bb.js@2.0.3 @noir-lang/noir_js@1.0.0-beta.14 @noir-lang/noir_wasm@1.0.0-beta.14
```

The library expects a WebCrypto-compatible environment (Node 18+ or browsers) and the `hyli` package (pulled in as a dependency) for `Blob`, `ProofTransaction`, and `NodeApiHttpClient` types.

## Usage

### Secret proofs (`check_secret`)

```ts
import { check_secret } from "hyli-noir";
import { NodeApiHttpClient } from "hyli";

const identity = "user@example.com";
const password = "my-secret-password";

// 1) Create the blob to attach to your Hyli transaction
const blob = await check_secret.build_blob(identity, password);

// 2) Register the circuit on the node once per network
await check_secret.register_contract(new NodeApiHttpClient("http://localhost:8080"));

// 3) Generate a proof bound to the transaction hash/blob position
const proofTx = await check_secret.build_proof_transaction(identity, password, "<tx-hash-hex>", 0, 1);
```

Other helpers:
- `hash_password(password)` returns the SHA-256 bytes of a password.
- `identity_hash(identity, password)` returns the public hash string (can be stored server-side).

### JWT proofs (`check_jwt`)

```ts
import { check_jwt } from "hyli-noir";
import { NodeApiHttpClient } from "hyli";

const idToken = "<oidc-id-token>";
const jwkKeys = await fetchGoogleJwks(); // array of JsonWebKey objects

// 1) Derive the blob and extracted values from the JWT
const { blob, nonce, mail_hash, pubkey } = await check_jwt.build_blob_from_jwt(idToken, jwkKeys);

// 2) Register the JWT circuit if it is not already on the node
await check_jwt.register_contract(new NodeApiHttpClient("http://localhost:8080"));

// 3) Build a proof that ties the JWT data to your transaction
const proofTx = await check_jwt.build_proof_transaction(
  "user@example.com",
  blob.data,          // stored hash from step 1
  "<tx-hash-hex>",    // transaction hash
  0,                  // blob index within the transaction
  1,                  // total number of blobs
  idToken,
  pubkey
);
```

Other helpers:
- `build_stored_hash(email, nonce, pubkey)` if you already parsed the JWT yourself.
- `extract_jwt_claims(jwt)` to pull `email`, `nonce`, and `kid`.
- `jwk_pubkey_mod(jwk)` and `poseidon_hash(string)` for lower-level needs.

## Development

- Build Noir circuits: `cd check-secret && nargo build` and `cd check-jwt && nargo build` (use `nargo execute` if you want to run the provided `Prover.toml` inputs).
- Build the TypeScript bundle: `bun run build`
- Publish: `bun run pub`

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions:
- GitHub Issues: [https://github.com/hyli-org/hyli-noir/issues](https://github.com/hyli-org/hyli-noir/issues)
- Repository: [https://github.com/hyli-org/hyli-noir](https://github.com/hyli-org/hyli-noir)

## Related Projects

- [Hyli](https://github.com/hyli-org/hyli) - The main Hyli ecosystem
- [Noir](https://noir-lang.org/) - Zero-knowledge proof language
