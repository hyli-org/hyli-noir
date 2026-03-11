// ============================================================================
// Hyli Noir SDK
// ============================================================================

// ----------------------------------------------------------------------------
// Core structs
// ----------------------------------------------------------------------------

pub struct BlobInput<let NAME_MAX: u32, let DATA_MAX: u32> {
    pub index: u32,
    pub contract_name_len: u32,
    pub contract_name: str<NAME_MAX>,
    pub data_len: u32,
    pub data: [u8; DATA_MAX],
}

pub struct HyliOutput<let INITIAL_STATE_MAX: u32, let NEXT_STATE_MAX: u32, let IDENTITY_MAX: u32, let BLOBS_MAX: u32, let BLOB_NAME_MAX: u32, let BLOB_DATA_MAX: u32, let PROGRAM_OUTPUT_MAX: u32> {
    pub version: u32,
    pub initial_state_len: u32,
    pub initial_state_max: u32,
    pub initial_state: [u8; INITIAL_STATE_MAX],
    pub next_state_len: u32,
    pub next_state_max: u32,
    pub next_state: [u8; NEXT_STATE_MAX],
    pub identity_len: u32,
    pub identity_max: u32,
    pub identity: str<IDENTITY_MAX>,
    pub index: u32,
    pub blob_count: u32,
    pub blob_slots: u32,
    pub blob_name_max: u32,
    pub blob_data_max: u32,
    pub blobs: [BlobInput<BLOB_NAME_MAX, BLOB_DATA_MAX>; BLOBS_MAX],
    pub tx_blob_count: u32,
    pub tx_hash: [u8; 32],
    pub success: bool,
    pub program_outputs_max: u32,
    pub program_outputs_len: u32,
    pub program_outputs: [u8; PROGRAM_OUTPUT_MAX],
}

// ----------------------------------------------------------------------------
// HyliOutput validation
// ----------------------------------------------------------------------------

impl<let INITIAL_STATE_MAX: u32, let NEXT_STATE_MAX: u32, let IDENTITY_MAX: u32, let BLOBS_MAX: u32, let BLOB_NAME_MAX: u32, let BLOB_DATA_MAX: u32, let PROGRAM_OUTPUT_MAX: u32> HyliOutput<INITIAL_STATE_MAX, NEXT_STATE_MAX, IDENTITY_MAX, BLOBS_MAX, BLOB_NAME_MAX, BLOB_DATA_MAX, PROGRAM_OUTPUT_MAX> {
    /// Validate the standard HyliOutput framing constraints.
    ///
    /// - `expected_blob_count`        : how many blobs this contract consumes
    /// - `expected_initial_state_len` : expected initial_state byte length
    /// - `expected_next_state_len`    : expected next_state byte length
    pub fn verify(
        self,
        expected_blob_count: u32,
        expected_initial_state_len: u32,
        expected_next_state_len: u32,
    ) {
        assert(self.success, "contract execution must succeed");
        assert(self.version == 2, "unsupported Hyli output version");

        assert(self.initial_state_len == expected_initial_state_len, "initial_state_len mismatch");
        assert(self.next_state_len == expected_next_state_len, "next_state_len mismatch");
        assert(self.initial_state_max == INITIAL_STATE_MAX, "initial_state_max mismatch");
        assert(self.next_state_max == NEXT_STATE_MAX, "next_state_max mismatch");
        assert(self.identity_max == IDENTITY_MAX, "identity_max mismatch");

        assert(self.blob_slots == BLOBS_MAX, "blob_slots mismatch");
        assert(self.blob_name_max == BLOB_NAME_MAX, "blob_name_max mismatch");
        assert(self.blob_data_max == BLOB_DATA_MAX, "blob_data_max mismatch");
        assert(self.blob_count == expected_blob_count, "blob_count mismatch");
        assert(self.blob_count <= self.tx_blob_count, "transaction must provide enough blobs");

        assert(self.program_outputs_max == PROGRAM_OUTPUT_MAX, "program_outputs_max mismatch");
        assert(
            self.program_outputs_len <= self.program_outputs_max,
            "program_outputs_len overflow",
        );

        assert(self.identity_len <= IDENTITY_MAX, "identity length overflow");
    }
}

// ----------------------------------------------------------------------------
// BlobInput validation
// ----------------------------------------------------------------------------

impl<let NAME_MAX: u32, let DATA_MAX: u32> BlobInput<NAME_MAX, DATA_MAX> {
    /// Validate standard blob framing constraints.
    ///
    /// - `expected_name_len` : exact expected contract_name_len
    /// - `expected_data_len` : exact expected data_len
    /// - `expected_index`    : must equal the invocation index from HyliOutput
    pub fn verify(self, expected_name_len: u32, expected_data_len: u32, expected_index: u32) {
        assert(self.contract_name_len == expected_name_len, "blob contract_name_len mismatch");
        assert(self.index == expected_index, "blob index must align with invocation index");
        assert(self.data_len == expected_data_len, "blob data_len mismatch");
    }
}

// ----------------------------------------------------------------------------
// Structured blob parsing
//
// Wire format (Borsh-encoded StructuredBlobData from the Hyli runtime):
//
//  [0]      : u8     - caller present flag (0 = None, 1 = Some)
//  [1..9]   : u64 LE - caller BlobIndex   (valid only when byte 0 == 1)
//  [9]      : u8     - callees tag         (0 = empty list)
//  [10..14] : u32 LE - parameters byte length
//  [14..]   : u8*    - parameters bytes
// ----------------------------------------------------------------------------

/// Parsed header of a structured blob.
///
/// `data` is the full raw blob byte array; use `parameter_byte(i)` or
/// `read_bytes32(offset)` / `read_field_be(offset)` / `read_field_le(offset)`
/// to access the parameters region.
pub struct StructuredBlobData<let DATA_MAX: u32> {
    pub caller_present: bool,
    /// Caller BlobIndex as a u64 (only meaningful when `caller_present` is true).
    pub caller_index: u64,
    /// True when the callees list is non-empty.
    pub callees_present: bool,
    /// Number of valid bytes in the parameters region.
    pub parameters_len: u32,
    /// Raw blob data. Parameters begin at index STRUCTURED_PARAMETERS_OFFSET (14).
    pub data: [u8; DATA_MAX],
}

/// Byte offset at which parameters begin inside a structured blob.
pub global STRUCTURED_PARAMETERS_OFFSET: u32 = 14;

impl<let DATA_MAX: u32> StructuredBlobData<DATA_MAX> {
    /// Return the `i`-th parameter byte (0-indexed, relative to parameters start).
    pub fn parameter_byte(self, i: u32) -> u8 {
        self.data[STRUCTURED_PARAMETERS_OFFSET + i]
    }

    /// Read 32 bytes from the parameters region starting at `offset`.
    /// Useful for extracting a Field encoded as a 32-byte BE or LE value.
    pub fn read_bytes32(self, offset: u32) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0; 32];
        for i in 0..32 {
            bytes[i] = self.data[STRUCTURED_PARAMETERS_OFFSET + offset + i];
        }
        bytes
    }

    /// Read 32 BE bytes at parameter `offset` and return as a Field.
    pub fn read_field_be(self, offset: u32) -> Field {
        be_bytes_to_field(self.read_bytes32(offset))
    }

    /// Read 32 LE bytes at parameter `offset` and return as a Field.
    /// Matches the Borsh/H256 encoding used by the Hyli runtime (e.g. SMT node keys).
    pub fn read_field_le(self, offset: u32) -> Field {
        le_bytes_to_field(self.read_bytes32(offset))
    }
}

/// Parse the header of a Hyli structured blob and return a `StructuredBlobData`.
///
/// Does NOT assert anything about the header values; add contract-specific
/// asserts on the returned struct (e.g. `assert(blob.caller_present, ...)`).
pub fn parse_structured_blob<let DATA_MAX: u32>(
    data: [u8; DATA_MAX],
) -> StructuredBlobData<DATA_MAX> {
    let caller_present = data[0] == 1;

    let mut caller_index: u64 = 0;
    for i in 0..8 {
        caller_index |= (data[1 + i] as u64) << ((i * 8) as u64);
    }

    let callees_present = data[9] != 0;

    let mut parameters_len: u32 = 0;
    for i in 0..4 {
        parameters_len |= (data[10 + i] as u32) << (i * 8);
    }

    StructuredBlobData { caller_present, caller_index, callees_present, parameters_len, data }
}

// ----------------------------------------------------------------------------
// Byte / Field conversion utilities
// ----------------------------------------------------------------------------

/// Interpret 32 bytes as a big-endian unsigned integer and return it as a Field.
pub fn be_bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + (bytes[i] as Field);
    }
    result
}

/// Interpret 32 bytes as a little-endian unsigned integer and return it as a Field.
/// Matches the Borsh / H256 encoding used by the Hyli runtime (e.g. SMT node keys).
pub fn le_bytes_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    let mut scale: Field = 1;
    for i in 0..32 {
        result += (bytes[i] as Field) * scale;
        scale *= 256;
    }
    result
}

// ----------------------------------------------------------------------------
// Blob payload builder
// ----------------------------------------------------------------------------

/// Serialize N Field values as concatenated 32-byte big-endian arrays.
///
/// Example - build a 128-byte blob from four field elements:
///   let blob = fields_to_blob([c0, c1, n0, n1]);
///   assert(blob_input.data == blob, "blob mismatch");
pub fn fields_to_blob<let N: u32>(fields: [Field; N]) -> [u8; 32 * N] {
    let mut out: [u8; 32 * N] = [0; 32 * N];
    for i in 0..N {
        let bytes: [u8; 32] = fields[i].to_be_bytes();
        for j in 0..32 {
            out[i * 32 + j] = bytes[j];
        }
    }
    out
}
