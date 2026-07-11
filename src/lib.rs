use schemars::JsonSchema;
use sov_modules_macros::serialize;

pub const AVM_MOCK_DA_SCHEMA_VERSION: u32 = 1;

pub type Address = String;
pub type ChannelId = u64;
pub type SubchannelId = u64;
pub type Digest = [u8; 32];
pub type VramSize = u32; // MiB
pub type RamSize = u32; // MiB
pub type CoreNum = u32;
pub type Frequency = u32; // MHz
pub type ExecuteSpeed = u64; // instructions per second

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
    ExecuteNode(Box<ExecuteNode>),
    SmartContract(SmartContract),
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
    pub channel_id: ChannelId,
    pub subchannel_id: Option<SubchannelId>,
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
pub struct Checkpoint {
    pub index: u64,
    /// The address of a worker who hands in the checkpoint.
    pub hand_in_worker_address: Address,
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
    /// Proof that payload was encrypted correctly.
    pub encryption_proof: ZkProof,

    /// Verification of the Checkpoints, it can't append by hand-in worker
    pub verification_ok: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct Future {
    /// Raw smart contract address, unencrypted because caller:Task has been implemented.
    pub smart_contract_addr: Address,
    /// Anonymous billing address; intentionally not encrypted.
    pub billing_addr: Address,
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

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct ExecuteNode {
    // identity
    pub address: Address,
    pub endpoint: String, // 网络地址
    pub permanent_pk: Vec<u8>,
    pub session_pk: Vec<u8>,
    pub signature: Vec<u8>,

    // software ability
    pub encryption_scheme: Vec<EncryptionScheme>,
    pub signature_scheme: Vec<SignatureScheme>,
    pub commitment_scheme: Vec<Commitment>,

    // hardware ability
    pub gpu_model: Option<GpuModel>,
    pub cpu_model: CpuModel,
    pub ram_cap: RamSize,
    pub ram_type: RamType,
    pub ntwk_up_bandwidth: i64,   // Mbps
    pub ntwk_down_bandwidth: i64, // Mbps

    // performance
    pub recent_10_tasks_speed: Option<ExecuteSpeed>,
    pub recent_50_tasks_speed: Option<ExecuteSpeed>,
    pub recent_100_tasks_speed: Option<ExecuteSpeed>,
    pub recent_500_tasks_speed: Option<ExecuteSpeed>,
    pub sum_tasks_speed: Option<ExecuteSpeed>,
    pub latency_variance: Option<i128>,
    pub interrupt_tasks: Option<i64>,
    pub successful_tasks: Option<i64>,
    pub reg_time: u64,
    pub alive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct SmartContract {
    pub address: Address,
    pub encrypt_body: Option<EncryptedBundle>,
    pub raw_body: Option<Vec<u8>>,
    pub encryption_proof: ZkProof,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct GpuBase {
    pub vram_size: VramSize,
    pub vram_type: VramType,
    pub tensor_core_num: CoreNum,
    pub cuda_core_num: CoreNum,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub struct CpuBase {
    pub avx256: bool,
    pub avx512: bool,
    pub aes_ni: bool,
    pub core_num: CoreNum,
    pub architecture: CpuArchitecture,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum GpuModel {
    Nvidia(GpuBase),
    Amd(GpuBase),
    Igpu(GpuBase),
    Unknown(String, GpuBase),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum CpuModel {
    Intel(CpuBase),
    Amd(CpuBase),
    Unknown(String, CpuBase),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum CpuArchitecture {
    Arm,
    X86,
    X86_64,
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum VramType {
    GDDR4(Frequency),
    GDDR5(Frequency),
    GDDR6(Frequency),
    Unknown(String, Frequency),
}

#[derive(Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serialize(Borsh, Serde)]
#[serde(rename_all = "snake_case")]
pub enum RamType {
    DDR3(Frequency),
    DDR4(Frequency),
    DDR5(Frequency),
    LPDDR3(Frequency),
    LPDDR4(Frequency),
    LPDDR5(Frequency),
    Unknown(String, Frequency),
}
