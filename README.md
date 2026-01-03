# Hyli-noir

A TypeScript/JavaScript library providing Noir-based zero-knowledge proof functionality for the Hyli ecosystem. This library enables secure secret verification through cryptographic proofs without revealing sensitive information.

## Features

- 🔐 **Zero-Knowledge Secret Verification**: Generate proofs that demonstrate knowledge of a password without revealing it
- 🛡️ **Identity-Based Authentication**: Combine user identity with password hashing for secure authentication
- 📦 **Blob Transaction Support**: Create and manage blob transactions containing encrypted secrets
- 🪪 **JWT Proofs**: Build proofs from signed JWT claims via the `check_jwt` circuit
- ⚡ **Noir Circuit Integration**: Built on Noir's zero-knowledge proof system with UltraHonk backend
- 🔧 **TypeScript Support**: Full TypeScript definitions and type safety

## Installation

```bash
npm install hyli-noir
```

### Peer Dependencies

This library requires the following peer dependencies:

```bash
npm install @aztec/bb.js@2.0.3 @noir-lang/noir_js@1.0.0-beta.14 @noir-lang/noir_wasm@1.0.0-beta.14
```

## Quick Start

```typescript
import { check_secret } from 'hyli-noir';

// Hash a password
const hashedPassword = await check_secret.hash_password('my-secret-password');

// Generate identity hash
const identityHash = await check_secret.identity_hash('user@example.com', 'my-secret-password');

// Build a blob transaction
const blob = await check_secret.build_blob('user@example.com', 'my-secret-password');

// Generate a proof transaction
const proofTx = await check_secret.build_proof_transaction(
  'user@example.com',
  'my-secret-password',
  '0x1234567890abcdef...', // transaction hash
  0, // blob index
  1  // total blob count
);
```

## API Reference

### Core Functions

#### `hash_password(password: string): Promise<Uint8Array>`

Hashes a password using SHA-256.

**Parameters:**
- `password` - The password string to hash

**Returns:** Promise resolving to a 32-byte Uint8Array containing the SHA-256 hash

#### `identity_hash(identity: string, password: string): Promise<string>`

Creates a combined hash of identity and password for authentication.

**Parameters:**
- `identity` - The user's identity string
- `password` - The user's password string

**Returns:** Promise resolving to a hex-encoded string of the combined hash

#### `build_blob(identity: string, password: string): Promise<Blob>`

Creates a blob transaction containing a secret derived from identity and password.

**Parameters:**
- `identity` - The user's identity string
- `password` - The user's password string

**Returns:** Promise resolving to a Blob object containing the encrypted secret

#### `build_proof_transaction(identity, password, tx_hash, blob_index, tx_blob_count, circuit?): Promise<ProofTransaction>`

Generates a zero-knowledge proof transaction demonstrating knowledge of the password.

**Parameters:**
- `identity` - The user's identity string
- `password` - The user's password string
- `tx_hash` - The blob transaction hash string
- `blob_index` - The index of the blob in the transaction
- `tx_blob_count` - Total number of blobs in the transaction
- `circuit` - Optional compiled Noir circuit (defaults to check_secret circuit)

**Returns:** Promise resolving to a ProofTransaction containing the generated proof

#### `register_contract(node, circuit?): Promise<void>`

Registers the Noir contract with the node if not already registered.

**Parameters:**
- `node` - The NodeApiHttpClient instance
- `circuit` - Optional compiled Noir circuit (defaults to check_secret circuit)

### Noir Utilities (`noir_utils`)

- `sha256(data: Uint8Array): Promise<Uint8Array>`: SHA-256 helper used by the circuits
- `stringToBytes(input: string): Uint8Array`: UTF-8 encoding helper
- `encodeToHex(data: Uint8Array): string`: Hex encoding helper
- `flattenFieldsAsArray(fields: string[]): Uint8Array`: Flattens Noir public inputs for proof reconstruction
- `assert(condition, message)`: Simple runtime assertion

### Noir Utils Circuit Library

A companion Noir library lives in `./noir-utils` exposing `HyliOutput` structs with common blob sizes (32/64/128/256/512/1024/2048). Add it as a Nargo dependency to reuse the shared Hyli I/O schema in custom circuits.

## How It Works

The library implements a zero-knowledge proof system for secret verification:

1. **Password Hashing**: The user's password is hashed using SHA-256 to create a fixed-size secret
2. **Identity Combination**: The identity is concatenated with the hashed password using a colon separator
3. **Final Hash**: The combined value is hashed again to create the stored secret
4. **Proof Generation**: A zero-knowledge proof is generated that demonstrates knowledge of the password without revealing it
5. **Verification**: The proof can be verified against the stored hash without exposing the original password

## Security Considerations

- Passwords are never stored in plain text
- The zero-knowledge proof system ensures password privacy
- All cryptographic operations use industry-standard algorithms (SHA-256)
- The system is designed to prevent replay attacks and unauthorized access

## Development

### Building Noir contract

In `./check-jwt/`  folder if `./Prover.toml` is present and well constructed

```bash
nargo execute
```
It builds and executes the circuit.

In `./check-secret/`, to build without executing do

```bash
nargo build
```

### Building library

```bash
bun run build
```

### Publishing

```bash
bun run pub
```

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
