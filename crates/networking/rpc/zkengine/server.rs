use axum::{
    extract::{State, DefaultBodyLimit},
    routing::post,
    Router,
    http::StatusCode,
};
use axum_extra::{TypedHeader, headers::{Authorization, authorization::Bearer}};
use bytes::Bytes;
use ssz_derive::{Decode, Encode};
use ssz_types::VariableList;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{info, error, debug};
use ethrex_common::{H256, Address, U256, Bloom};
use ethrex_common::types::Withdrawal;
use ssz::Decode as SszDecode;
use ssz::Encode as SszEncode;

use crate::{
    RpcApiContext,
    authentication::authenticate,
    types::payload::{ExecutionPayload, EncodedTransaction},
    engine::payload::{get_block_from_payload, handle_new_payload_v3, handle_new_payload_v4},
};

use super::types::{
    SszPayloadRequestV3, SszPayloadRequestV4, SszPayloadResponse,
    SszExecutionPayloadV3, SszExecutionPayloadV4, MaxBytesPerTransaction,
    SszRpcExecutionWitness
};

// Define zkengine router
pub fn router(context: RpcApiContext) -> Router {
    Router::new()
        .route("/new-payload-v3", post(handle_new_payload_v3_ssz))
        .route("/new-payload-v4", post(handle_new_payload_v4_ssz))
        // 512MB limit for payloads
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024))
        .with_state(context)
}

fn convert_payload_v3(val: SszExecutionPayloadV3) -> ExecutionPayload {
    ExecutionPayload {
        parent_hash: H256::from(val.parent_hash),
        fee_recipient: Address::from(val.fee_recipient),
        state_root: H256::from(val.state_root),
        receipts_root: H256::from(val.receipts_root),
        logs_bloom: Bloom::from_slice(&val.logs_bloom),
        prev_randao: H256::from(val.prev_randao),
        block_number: val.block_number,
        gas_limit: val.gas_limit,
        gas_used: val.gas_used,
        timestamp: val.timestamp,
        extra_data: Bytes::from(val.extra_data.to_vec()),
        base_fee_per_gas: U256::from_little_endian(&val.base_fee_per_gas).as_u64(),
        block_hash: H256::from(val.block_hash),
        transactions: val.transactions.into_iter().map(|tx| EncodedTransaction(Bytes::from(tx.to_vec()))).collect(),
        withdrawals: Some(val.withdrawals.into_iter().map(|w| Withdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: Address::from(w.address),
            amount: w.amount,
        }).collect()),
        blob_gas_used: Some(val.blob_gas_used),
        excess_blob_gas: Some(val.excess_blob_gas),
        slot_number: None, // V3 has no slot in our ExecutionPayload payload.rs
        block_access_list: None,
    }
}

// Handler for V3
async fn handle_new_payload_v3_ssz(
    State(context): State<RpcApiContext>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    body: Bytes,
) -> Result<Bytes, StatusCode> {
    let total_start = std::time::Instant::now();
    authenticate(&context.node_data.jwt_secret, auth).map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Decode SSZ request
    let decode_start = std::time::Instant::now();
    let req = SszPayloadRequestV3::from_ssz_bytes(&body).map_err(|e| {
        error!("SSZ decode failed: {:?}", e);
        StatusCode::BAD_REQUEST
    })?;
    let decode_dur = decode_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V3 Request Decode (SSZ): {:?}", decode_dur);

    let convert_start = std::time::Instant::now();
    let expected_blobs: Vec<H256> = req.expected_blob_versioned_hashes.into_iter().map(H256::from).collect();
    let parent_beacon = H256::from(req.parent_beacon_block_root);
    let payload = convert_payload_v3(req.payload);
    let convert_dur = convert_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V3 Payload Conversion (SSZ -> Internal): {:?}", convert_dur);
    
    // Convert to block
    let block_start = std::time::Instant::now();
    let block = get_block_from_payload(&payload, Some(parent_beacon), None, None)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let block_dur = block_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V3 Block Construction: {:?}", block_dur);

    let exec_start = std::time::Instant::now();
    let status = handle_new_payload_v3(&payload, context, block, expected_blobs, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let exec_dur = exec_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V3 Execution Call (new_payload_v3): {:?}", exec_dur);

    let resp_prep_start = std::time::Instant::now();
    let ssz_status = match status.status {
        crate::types::payload::PayloadValidationStatus::Valid => 0,
        crate::types::payload::PayloadValidationStatus::Invalid => 1,
        crate::types::payload::PayloadValidationStatus::Syncing => 2,
        crate::types::payload::PayloadValidationStatus::Accepted => 3,
    };

    let mut witness_bytes = VariableList::empty();
    if let Some(w_val) = status.witness {
        if let Some(hex_str) = w_val.as_str() {
            let wit_conv_start = std::time::Instant::now();
            match hex::decode(hex_str.trim_start_matches("0x")) {
                Ok(json_bytes) => {
                    match serde_json::from_slice::<ethrex_common::types::block_execution_witness::RpcExecutionWitness>(&json_bytes) {
                        Ok(rpc_wit) => {
                            let ssz_wit = SszRpcExecutionWitness {
                                state: VariableList::try_from(rpc_wit.state.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                                keys: VariableList::try_from(rpc_wit.keys.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                                codes: VariableList::try_from(rpc_wit.codes.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                                headers: VariableList::try_from(rpc_wit.headers.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                            };
                            let encoded = ssz_wit.as_ssz_bytes();
                            let wit_conv_dur = wit_conv_start.elapsed();
                            info!("[WITNESS_BENCH] zkengine V3 Witness Serialization (JSON -> SSZ): {:?} | Size: {} bytes", wit_conv_dur, encoded.len());
                            witness_bytes = VariableList::try_from(encoded).unwrap_or_default();
                        }
                        Err(e) => error!("[WITNESS_BENCH] zkengine V3 failed to deserialize RpcExecutionWitness from JSON: {:?}", e),
                    }
                }
                Err(e) => error!("[WITNESS_BENCH] zkengine V3 failed to hex decode witness: {:?}", e),
            }
        }
    } else {
        debug!("[WITNESS_BENCH] zkengine V3: No witness in PayloadStatus (status: {:?})", status.status);
    }

    let latest_valid_hash = match status.latest_valid_hash {
        Some(hash) => VariableList::try_from(hash.0.to_vec()).unwrap_or_default(),
        None => VariableList::empty(),
    };
    
    let validation_error = match status.validation_error {
        Some(s) => VariableList::try_from(s.as_bytes().to_vec()).unwrap_or_default(),
        None => VariableList::empty(),
    };

    let res = SszPayloadResponse {
        status: ssz_status,
        latest_valid_hash,
        validation_error,
        witness: witness_bytes,
    };
    let resp_prep_dur = resp_prep_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V3 Response Preparation (Internal -> SSZ): {:?}", resp_prep_dur);

    let total_dur = total_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V3 Total Internal Time: {:?}", total_dur);

    Ok(Bytes::from(res.as_ssz_bytes()))
}

fn convert_payload_v4(val: SszExecutionPayloadV4) -> ExecutionPayload {
    ExecutionPayload {
        parent_hash: H256::from(val.parent_hash),
        fee_recipient: Address::from(val.fee_recipient),
        state_root: H256::from(val.state_root),
        receipts_root: H256::from(val.receipts_root),
        logs_bloom: Bloom::from_slice(&val.logs_bloom),
        prev_randao: H256::from(val.prev_randao),
        block_number: val.block_number,
        gas_limit: val.gas_limit,
        gas_used: val.gas_used,
        timestamp: val.timestamp,
        extra_data: Bytes::from(val.extra_data.to_vec()),
        base_fee_per_gas: U256::from_little_endian(&val.base_fee_per_gas).as_u64(),
        block_hash: H256::from(val.block_hash),
        transactions: val.transactions.into_iter().map(|tx| EncodedTransaction(Bytes::from(tx.to_vec()))).collect(),
        withdrawals: Some(val.withdrawals.into_iter().map(|w| Withdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: Address::from(w.address),
            amount: w.amount,
        }).collect()),
        blob_gas_used: Some(val.blob_gas_used),
        excess_blob_gas: Some(val.excess_blob_gas),
        slot_number: None,
        block_access_list: None,
    }
}

// Handler for V4
async fn handle_new_payload_v4_ssz(
    State(context): State<RpcApiContext>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
    body: Bytes,
) -> Result<Bytes, StatusCode> {
    let total_start = std::time::Instant::now();
    authenticate(&context.node_data.jwt_secret, auth).map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Decode SSZ request
    let decode_start = std::time::Instant::now();
    let req = SszPayloadRequestV4::from_ssz_bytes(&body).map_err(|e| {
        error!("SSZ decode failed: {:?}", e);
        StatusCode::BAD_REQUEST
    })?;
    let decode_dur = decode_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V4 Request Decode (SSZ): {:?}", decode_dur);

    let convert_start = std::time::Instant::now();
    let expected_blobs: Vec<H256> = req.expected_blob_versioned_hashes.into_iter().map(H256::from).collect();
    let parent_beacon = H256::from(req.parent_beacon_block_root);
    
    let base_requests: Vec<ethrex_common::types::requests::EncodedRequests> = req.execution_requests.into_iter()
        .map(|v| ethrex_common::types::requests::EncodedRequests(bytes::Bytes::from(v.to_vec())))
        .collect();
    let requests_hash = ethrex_common::types::requests::compute_requests_hash(&base_requests);
    
    let payload = convert_payload_v4(req.payload);
    let convert_dur = convert_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V4 Payload Conversion (SSZ -> Internal): {:?}", convert_dur);
    
    // Convert to block
    let block_start = std::time::Instant::now();
    let block = get_block_from_payload(&payload, Some(parent_beacon), Some(requests_hash), None)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let block_dur = block_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V4 Block Construction (with hash compute): {:?}", block_dur);

    let exec_start = std::time::Instant::now();
    let status = handle_new_payload_v4(&payload, context, block, expected_blobs, None)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let exec_dur = exec_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V4 Execution Call (new_payload_v4): {:?}", exec_dur);

    let resp_prep_start = std::time::Instant::now();
    let ssz_status = match status.status {
        crate::types::payload::PayloadValidationStatus::Valid => 0,
        crate::types::payload::PayloadValidationStatus::Invalid => 1,
        crate::types::payload::PayloadValidationStatus::Syncing => 2,
        crate::types::payload::PayloadValidationStatus::Accepted => 3,
    };

    let mut witness_bytes = VariableList::empty();
    if let Some(w_val) = status.witness {
        if let Some(hex_str) = w_val.as_str() {
            let wit_conv_start = std::time::Instant::now();
            match hex::decode(hex_str.trim_start_matches("0x")) {
                Ok(json_bytes) => {
                    match serde_json::from_slice::<ethrex_common::types::block_execution_witness::RpcExecutionWitness>(&json_bytes) {
                        Ok(rpc_wit) => {
                            let ssz_wit = SszRpcExecutionWitness {
                                state: VariableList::try_from(rpc_wit.state.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                                keys: VariableList::try_from(rpc_wit.keys.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                                codes: VariableList::try_from(rpc_wit.codes.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                                headers: VariableList::try_from(rpc_wit.headers.into_iter().map(|b| VariableList::try_from(b.to_vec()).unwrap()).collect::<Vec<_>>()).unwrap(),
                            };
                            let encoded = ssz_wit.as_ssz_bytes();
                            let wit_conv_dur = wit_conv_start.elapsed();
                            info!("[WITNESS_BENCH] zkengine V4 Witness Serialization (JSON -> SSZ): {:?} | Size: {} bytes", wit_conv_dur, encoded.len());
                            witness_bytes = VariableList::try_from(encoded).unwrap_or_default();
                        }
                        Err(e) => error!("[WITNESS_BENCH] zkengine V4 failed to deserialize RpcExecutionWitness from JSON: {:?}", e),
                    }
                }
                Err(e) => error!("[WITNESS_BENCH] zkengine V4 failed to hex decode witness: {:?}", e),
            }
        }
    } else {
        debug!("[WITNESS_BENCH] zkengine V4: No witness in PayloadStatus (status: {:?})", status.status);
    }

    let latest_valid_hash = match status.latest_valid_hash {
        Some(hash) => VariableList::try_from(hash.0.to_vec()).unwrap_or_default(),
        None => VariableList::empty(),
    };
    
    let validation_error = match status.validation_error {
        Some(s) => VariableList::try_from(s.as_bytes().to_vec()).unwrap_or_default(),
        None => VariableList::empty(),
    };

    let res = SszPayloadResponse {
        status: ssz_status,
        latest_valid_hash,
        validation_error,
        witness: witness_bytes,
    };
    let resp_prep_dur = resp_prep_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V4 Response Preparation (Internal -> SSZ): {:?}", resp_prep_dur);

    let total_dur = total_start.elapsed();
    info!("[WITNESS_BENCH] zkengine V4 Total Internal Time: {:?}", total_dur);

    Ok(Bytes::from(res.as_ssz_bytes()))
}
