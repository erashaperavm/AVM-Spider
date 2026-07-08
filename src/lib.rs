use schemars::JsonSchema;
use sov_modules_macros::serialize;

pub const AVM_MOCK_DA_SCHEMA_VERSION: u32 = 1;

pub type Address = String;
pub type ChannelId = u64;
pub type SubchannelId = u64;
pub type Digest = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct MockDaMetadata {
    /// Version of the serialized AVM DA payload schema.
    pub schema_version: u32,
    /// Rollup/protocol domain separator. Prevents replaying the same payload on another rollup.
    pub rollup_id: Digest,
    /// Deterministic producer-supplied id for indexing, replay checks, and deduplication.
    pub message_id: Digest,
    /// Public routing channel. Nodes subscribed to this channel scan the message.
    pub channel_id: ChannelId,
    /// Public routing subchannel. Nodes scan their subchannels and try to decrypt matching data.
    pub subchannel_id: SubchannelId,
    /// Commitment to the serialized payload carried by this envelope.
    pub payload_commitment: Commitment,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct MockDaEnvelope {
    pub metadata: MockDaMetadata,
    pub authorization: DaAuthorization,
    pub payload: MockDaPayload,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum MockDaPayload {
    Future(Future),
    Task(Box<Task>),
    Event(Event),
    Condition(Condition),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct DaAuthorization {
    /// Entity submitting the DA message. The exact address scheme is defined by the rollup.
    pub submitter: Address,
    /// Monotonic or otherwise unique value scoped to `submitter` for replay protection.
    pub nonce: u64,
    /// Public key used to verify `signature`, if it is not recoverable from `submitter`.
    pub public_key: Vec<u8>,
    /// Signature algorithm used by `signature`.
    pub signature_scheme: SignatureScheme,
    /// Commitment over the canonical signing payload, usually metadata plus payload commitment.
    pub signed_commitment: Commitment,
    /// Signature over `signed_commitment`.
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum SignatureScheme {
    Ed25519,   // EdDSA
    Secp256k1, // ECDSA
    Schnorr,
    SphincsPlus(LenLevel, HashAlgorithmForSphincsPlus, SorF),
    Falcon(SecurityLevel),
    Custom(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum LenLevel {
    Bit128,
    Bit192,
    Bit256,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithmForSphincsPlus {
    Sha256,
    Shake256,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum SorF {
    S,
    F,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    Bit512,
    Bit1024,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Commitment {
    pub scheme: CommitmentScheme,
    /// Number of bytes committed to before hashing. Useful for bounds and preallocation.
    pub byte_len: u64,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentScheme {
    Sha256,
    Blake3,
    Keccak256,
    Poseidon,
    Custom(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct EncryptedBundle {
    /// Commitment to the encrypted bundle bytes, not necessarily to the plaintext.
    pub commitment: Commitment,
    /// One ciphertext per intended decryptor in the channel/subchannel.
    pub ciphertexts: Vec<Ciphertext>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Ciphertext {
    pub encryption_scheme: EncryptionScheme,
    /// Key version or committee epoch used to derive the decryption key.
    pub key_epoch: u64,
    /// Identifier of the concrete encryption key. This avoids guessing across key rotations.
    pub key_id: Digest,
    /// Nonce/IV required by the encryption scheme.
    pub nonce: Vec<u8>,
    /// Actual encrypted bytes.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionScheme {
    Hpke,
    XChaCha20Poly1305,
    Aes256GcmSiv,
    Custom(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct ZkProof {
    /// What this proof is supposed to establish.
    pub purpose: ProofPurpose,
    /// Proof system used to verify `proof`.
    pub proof_system: ProofSystem,
    /// Stable id of the circuit/program being proven.
    pub circuit_id: Digest,
    /// Circuit/program version. Allows upgrades without changing `circuit_id` semantics.
    pub circuit_version: u32,
    /// Verifying key commitment/id used by verifiers.
    pub verifying_key_id: Digest,
    /// Commitment to public inputs. Keeps the proof bound to DA-visible commitments.
    pub public_inputs_commitment: Commitment,
    /// Raw proof bytes.
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum ProofPurpose {
    EncryptionCorrectness,
    ExecutionCorrectness,
    WorkerElectionCorrectness,
    ConditionCheckCorrectness,
    Custom(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum ProofSystem {
    Stark,
    Groth16,
    Plonk,
    Sp1,
    Risc0,
    Custom(u32),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct OriginFuture {
    pub smart_contract_addr: Address,
    pub billing_addr: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct OriginTask {
    pub future_addr: Address,
    pub workgroup: Vec<WorkGroup>,
    pub status: Status,
    pub workers_vote_proof: Vec<u8>,
    pub checkpoints: Vec<OriginCheckpoint>,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct OriginEvent {
    pub action: Action,
    pub future_addr: Address,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct OriginCondition {
    pub observation_data_addr: Address,
    pub describer: Describer,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct WorkGroup {
    /// Workers compete within one group; groups provide fallback ordering.
    pub workers: Vec<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Describer {
    /// Version of the describer byte format, owned by the condition subsystem.
    pub schema_version: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Working,
    Finished,
    Error(ExecutionError),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct ExecutionError {
    /// Stable protocol-defined error code.
    pub code: u32,
    /// Optional binary error details. Prefer bounded, protocol-defined encodings over free text.
    pub details: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Do,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct OriginCheckpoint {
    pub index: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Checkpoint {
    pub index: u64,
    /// Commitment to the checkpoint payload before worker-specific encryption.
    pub checkpoint_commitment: Commitment,
    /// Commitment to the state observed before this checkpoint executes.
    pub pre_state_commitment: Commitment,
    /// Commitment to the state produced by this checkpoint.
    pub post_state_commitment: Commitment,
    /// Commitment to the smart contract output produced at this checkpoint.
    pub output_commitment: Commitment,
    /// Worker-readable checkpoint payloads.
    pub encrypted_payload: EncryptedBundle,
    /// Proof that checkpoint execution was computed correctly.
    pub execution_proof: ZkProof,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Future {
    /// Encrypted smart contract address, routed through the envelope channel/subchannel.
    pub enc_smart_contract_addr: EncryptedBundle,
    /// Anonymous billing address; intentionally not encrypted.
    pub billing_addr: Address,
    /// Proof that encrypted fields were produced from the committed plaintext correctly.
    pub encryption_proof: ZkProof,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Task {
    /// Encrypted future address for the selected worker group.
    pub enc_future_addr: EncryptedBundle,
    /// Dynamically elected worker group, encrypted for workers.
    pub enc_workgroup: EncryptedBundle,
    /// Task progress is intentionally public.
    pub status: Status,
    /// Proof that dynamic worker election was valid.
    pub workers_vote_proof: ZkProof,
    /// Checkpoints carry public commitments and execution-correctness proofs.
    pub checkpoints: Vec<Checkpoint>,
    /// Worker-readable task input.
    pub input: EncryptedBundle,
    /// Worker-readable smart contract output.
    pub output: EncryptedBundle,
    /// Proof that task encrypted fields were produced correctly.
    pub encryption_proof: ZkProof,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Event {
    /// Encrypted event action for condition checkers.
    pub enc_action: EncryptedBundle,
    /// Encrypted future address for condition checkers.
    pub enc_future_addr: EncryptedBundle,
    /// Proof that event encrypted fields were produced correctly.
    pub encryption_proof: ZkProof,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Condition {
    /// Encrypted observation data address for condition checkers.
    pub enc_observation_data_addr: EncryptedBundle,
    /// Encrypted condition describer. Branch selection remains describer-defined.
    pub enc_describer: EncryptedBundle,
    /// Proof that condition encrypted fields were produced correctly.
    pub encryption_proof: ZkProof,
}
