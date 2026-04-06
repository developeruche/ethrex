use ethrex_common::{Address, Bloom, H256, U256};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U1048576, U1073741824, U16, U256 as TypenumU256, U32, U4096, U64},
    FixedVector, VariableList,
};

pub type MaxExtraDataBytes = U32;
pub type MaxBytesPerTransaction = U1073741824;
pub type MaxTransactionsPerPayload = U1048576;
pub type MaxWithdrawalsPerPayload = U16;
pub type MaxBlobCommitmentsPerBlock = U4096;

pub type MaxWitnessItems = U1048576;
pub type MaxBytesPerWitnessItem = U1048576;

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszRpcExecutionWitness {
    pub state: VariableList<VariableList<u8, MaxBytesPerWitnessItem>, MaxWitnessItems>,
    pub keys: VariableList<VariableList<u8, MaxBytesPerWitnessItem>, MaxWitnessItems>,
    pub codes: VariableList<VariableList<u8, MaxBytesPerWitnessItem>, MaxWitnessItems>,
    pub headers: VariableList<VariableList<u8, MaxBytesPerWitnessItem>, MaxWitnessItems>,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszWithdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszExecutionPayloadV3 {
    pub parent_hash: [u8; 32],
    pub fee_recipient: [u8; 20],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: FixedVector<u8, TypenumU256>,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: VariableList<u8, MaxExtraDataBytes>,
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: [u8; 32],
    pub transactions: VariableList<VariableList<u8, MaxBytesPerTransaction>, MaxTransactionsPerPayload>,
    pub withdrawals: VariableList<SszWithdrawal, MaxWithdrawalsPerPayload>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszPayloadRequestV3 {
    pub payload: SszExecutionPayloadV3,
    pub expected_blob_versioned_hashes: VariableList<[u8; 32], MaxBlobCommitmentsPerBlock>,
    pub parent_beacon_block_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszExecutionPayloadV4 {
    pub parent_hash: [u8; 32],
    pub fee_recipient: [u8; 20],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: FixedVector<u8, TypenumU256>,
    pub prev_randao: [u8; 32],
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: VariableList<u8, MaxExtraDataBytes>,
    pub base_fee_per_gas: [u8; 32],
    pub block_hash: [u8; 32],
    pub transactions: VariableList<VariableList<u8, MaxBytesPerTransaction>, MaxTransactionsPerPayload>,
    pub withdrawals: VariableList<SszWithdrawal, MaxWithdrawalsPerPayload>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszPayloadRequestV4 {
    pub payload: SszExecutionPayloadV4,
    pub expected_blob_versioned_hashes: VariableList<[u8; 32], MaxBlobCommitmentsPerBlock>,
    pub parent_beacon_block_root: [u8; 32],
    pub execution_requests: VariableList<VariableList<u8, MaxBytesPerTransaction>, U64>, // Using U64 limit for requests
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct SszPayloadResponse {
    pub status: u8,
    pub latest_valid_hash: VariableList<u8, U32>,
    pub validation_error: VariableList<u8, MaxBytesPerTransaction>, // Hack: using large limit
    pub witness: VariableList<u8, MaxBytesPerTransaction>, // Large limit for binary witness
}
