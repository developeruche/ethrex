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
use ethrex_common::{Address, Bloom, H256, U256, types::block_execution_witness::RpcExecutionWitness};
use ethrex_common::types::Withdrawal;
use ssz::Decode as SszDecode;
use ssz::Encode as SszEncode;

use crate::{
    RpcApiContext,
    authentication::authenticate,
    types::payload::{ExecutionPayload, EncodedTransaction},
    engine::payload::{get_block_from_payload, handle_new_payload_v3, handle_new_payload_v4},
};

fn encode_witness_to_ssz(witness: &ethrex_common::types::block_execution_witness::RpcExecutionWitness) -> Vec<u8> {
    fn encode_list_of_bytes<T: AsRef<[u8]>>(list: &[T], out: &mut Vec<u8>) {
        let n = list.len();
        let mut offset = (n * 4) as u32;
        // write offsets
        for item in list {
            out.extend_from_slice(&offset.to_le_bytes());
            offset += item.as_ref().len() as u32;
        }
        // write data
        for item in list {
            out.extend_from_slice(item.as_ref());
        }
    }

    fn size_of_list_of_bytes<T: AsRef<[u8]>>(list: &[T]) -> usize {
        list.len() * 4 + list.iter().map(|b| b.as_ref().len()).sum::<usize>()
    }

    let state_size = size_of_list_of_bytes(&witness.state);
    let keys_size = size_of_list_of_bytes(&witness.keys);
    let codes_size = size_of_list_of_bytes(&witness.codes);
    let headers_size = size_of_list_of_bytes(&witness.headers);

    let total_size = 16 + state_size + keys_size + codes_size + headers_size;
    let mut out = Vec::with_capacity(total_size);

    let offset_state = 16u32;
    let offset_keys = offset_state + state_size as u32;
    let offset_codes = offset_keys + keys_size as u32;
    let offset_headers = offset_codes + codes_size as u32;

    out.extend_from_slice(&offset_state.to_le_bytes());
    out.extend_from_slice(&offset_keys.to_le_bytes());
    out.extend_from_slice(&offset_codes.to_le_bytes());
    out.extend_from_slice(&offset_headers.to_le_bytes());

    encode_list_of_bytes(&witness.state, &mut out);
    encode_list_of_bytes(&witness.keys, &mut out);
    encode_list_of_bytes(&witness.codes, &mut out);
    encode_list_of_bytes(&witness.headers, &mut out);

    out
}

pub fn decode_witness_from_ssz(data: &[u8]) -> Result<RpcExecutionWitness, String> {
    fn decode_list_of_bytes(data: &[u8]) -> Result<Vec<bytes::Bytes>, String> {
        if data.is_empty() {
            return Ok(vec![]);
        }
        if data.len() < 4 {
            return Err(format!("list too short to contain offset table: {} bytes", data.len()));
        }

        // Read first offset to determine how many items are in the list.
        // The offset table occupies [0, first_offset) bytes.
        // Each entry in the offset table is 4 bytes, so item count = first_offset / 4.
        let first_offset = u32::from_le_bytes(
            data[0..4].try_into().map_err(|_| "failed to read first offset")?
        ) as usize;

        if first_offset % 4 != 0 {
            return Err(format!("first offset {} is not a multiple of 4", first_offset));
        }
        if first_offset > data.len() {
            return Err(format!(
                "first offset {} exceeds data length {}",
                first_offset, data.len()
            ));
        }

        let n = first_offset / 4;
        if data.len() < n * 4 {
            return Err(format!(
                "data too short for offset table: need {} bytes, have {}",
                n * 4, data.len()
            ));
        }

        // Read all offsets
        let mut offsets = Vec::with_capacity(n);
        for i in 0..n {
            let start = i * 4;
            let offset = u32::from_le_bytes(
                data[start..start + 4].try_into().map_err(|_| "failed to read offset")?
            ) as usize;
            offsets.push(offset);
        }

        // Decode each item using adjacent offsets to find boundaries
        let mut items = Vec::with_capacity(n);
        for i in 0..n {
            let item_start = offsets[i];
            let item_end = if i + 1 < n {
                offsets[i + 1]
            } else {
                data.len()
            };

            if item_start > data.len() || item_end > data.len() || item_start > item_end {
                return Err(format!(
                    "invalid offset range [{}, {}) for data length {}",
                    item_start, item_end, data.len()
                ));
            }

            items.push(bytes::Bytes::copy_from_slice(&data[item_start..item_end]));
        }

        Ok(items)
    }

    // The outer structure has 4 fields, each variable-length.
    // The outer offset table occupies the first 16 bytes (4 fields × 4 bytes each).
    if data.len() < 16 {
        return Err(format!(
            "SSZ witness too short: need at least 16 bytes for outer offset table, got {}",
            data.len()
        ));
    }

    let offset_state = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let offset_keys   = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
    let offset_codes  = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    let offset_headers = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    // Validate outer offsets
    if offset_state != 16 {
        return Err(format!("expected state offset to be 16, got {}", offset_state));
    }
    for (name, offset) in [
        ("keys",    offset_keys),
        ("codes",   offset_codes),
        ("headers", offset_headers),
    ] {
        if offset > data.len() {
            return Err(format!(
                "outer offset for {} ({}) exceeds data length ({})",
                name, offset, data.len()
            ));
        }
    }

    // Slice each field's region using adjacent outer offsets
    let state_bytes   = &data[offset_state..offset_keys];
    let keys_bytes    = &data[offset_keys..offset_codes];
    let codes_bytes   = &data[offset_codes..offset_headers];
    let headers_bytes = &data[offset_headers..];

    Ok(RpcExecutionWitness {
        state:   decode_list_of_bytes(state_bytes)
            .map_err(|e| format!("state: {}", e))?,
        keys:    decode_list_of_bytes(keys_bytes)
            .map_err(|e| format!("keys: {}", e))?,
        codes:   decode_list_of_bytes(codes_bytes)
            .map_err(|e| format!("codes: {}", e))?,
        headers: decode_list_of_bytes(headers_bytes)
            .map_err(|e| format!("headers: {}", e))?,
    })
}

use super::types::{
    SszPayloadRequestV3, SszPayloadRequestV4, SszPayloadResponse,
    SszExecutionPayloadV3, SszExecutionPayloadV4
};

// Define zkengine router
pub fn router(context: RpcApiContext) -> Router {
    Router::new()
        .route("/new-payload-v3", post(handle_new_payload_v3_ssz))
        .route("/new-payload-v4", post(handle_new_payload_v4_ssz))
        // 1GB limit for payloads
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024))
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
    if let Some(rpc_wit) = status.witness_raw {
        // tracing::info!(
        //         "[WITNESS_BENCH] zkengine Received Witness: State Length {},  Code Lenght: {}, Key Length: {}, Header Length: {} for block {}",
        //         rpc_wit.state.len(),
        //         rpc_wit.codes.len(),
        //         rpc_wit.keys.len(),
        //         rpc_wit.headers.len(),
        //         payload.block_number
        //     );
        let wit_enc_start = std::time::Instant::now();
        let encoded = encode_witness_to_ssz(&rpc_wit);
        let wit_enc_dur = wit_enc_start.elapsed();
        info!("[WITNESS_BENCH] zkengine V3 Witness SSZ Encoding: {:?} | Size: {} bytes", wit_enc_dur, encoded.len());
        witness_bytes = VariableList::try_from(encoded).unwrap_or_default();
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
    if let Some(rpc_wit) = status.witness_raw {
        // tracing::info!(
        //         "[WITNESS_BENCH] zkengine Received Witness: State Length {},  Code Lenght: {}, Key Length: {}, Header Length: {} for block {}",
        //         rpc_wit.state.len(),
        //         rpc_wit.codes.len(),
        //         rpc_wit.keys.len(),
        //         rpc_wit.headers.len(),
        //         payload.block_number
        //     );

        let wit_enc_start = std::time::Instant::now();
        let encoded = encode_witness_to_ssz(&rpc_wit);
        let wit_enc_dur = wit_enc_start.elapsed();
        info!("[WITNESS_BENCH] zkengine V4 Witness SSZ Encoding: {:?} | Size: {} bytes", wit_enc_dur, encoded.len());
        witness_bytes = VariableList::try_from(encoded).unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;


    fn make_witness(
        state: Vec<Vec<u8>>,
        keys: Vec<Vec<u8>>,
        codes: Vec<Vec<u8>>,
        headers: Vec<Vec<u8>>,
    ) -> RpcExecutionWitness {
        RpcExecutionWitness {
            state:   state.into_iter().map(Bytes::from).collect(),
            keys:    keys.into_iter().map(Bytes::from).collect(),
            codes:   codes.into_iter().map(Bytes::from).collect(),
            headers: headers.into_iter().map(Bytes::from).collect(),
        }
    }

    fn assert_witness_eq(original: &RpcExecutionWitness, decoded: &RpcExecutionWitness) {
        assert_eq!(original.state.len(),   decoded.state.len(),   "state length mismatch");
        assert_eq!(original.keys.len(),    decoded.keys.len(),    "keys length mismatch");
        assert_eq!(original.codes.len(),   decoded.codes.len(),   "codes length mismatch");
        assert_eq!(original.headers.len(), decoded.headers.len(), "headers length mismatch");

        for (i, (a, b)) in original.state.iter().zip(decoded.state.iter()).enumerate() {
            assert_eq!(a, b, "state[{}] mismatch", i);
        }
        for (i, (a, b)) in original.keys.iter().zip(decoded.keys.iter()).enumerate() {
            assert_eq!(a, b, "keys[{}] mismatch", i);
        }
        for (i, (a, b)) in original.codes.iter().zip(decoded.codes.iter()).enumerate() {
            assert_eq!(a, b, "codes[{}] mismatch", i);
        }
        for (i, (a, b)) in original.headers.iter().zip(decoded.headers.iter()).enumerate() {
            assert_eq!(a, b, "headers[{}] mismatch", i);
        }
    }

    #[test]
    fn test_roundtrip_typical() {
        let witness = make_witness(
            vec![vec![0x01, 0x02, 0x03], vec![0xde, 0xad, 0xbe, 0xef]],
            vec![vec![0xaa; 32], vec![0xbb; 32]],
            vec![vec![0x60, 0x60, 0x60, 0x40, 0x52]],
            vec![vec![0xf8, 0x44]],
        );

        let encoded = encode_witness_to_ssz(&witness);
        let decoded = decode_witness_from_ssz(&encoded).expect("decode failed");
        assert_witness_eq(&witness, &decoded);
    }

     #[test]
    fn test_roundtrip_empty_witness() {
        let witness = make_witness(vec![], vec![], vec![], vec![]);

        let encoded = encode_witness_to_ssz(&witness);
        assert_eq!(encoded.len(), 16, "empty witness should be exactly 16 bytes (outer offset table)");

        let decoded = decode_witness_from_ssz(&encoded).expect("decode failed");
        assert_witness_eq(&witness, &decoded);
    }

    #[test]
    fn test_roundtrip_some_fields_empty() {
        let witness = make_witness(
            vec![vec![0x01, 0x02], vec![0x03, 0x04]],
            vec![],
            vec![vec![0x60; 100]],
            vec![],
        );

        let encoded = encode_witness_to_ssz(&witness);
        let decoded = decode_witness_from_ssz(&encoded).expect("decode failed");
        assert_witness_eq(&witness, &decoded);
    }

       #[test]
    fn test_roundtrip_single_item_each_field() {
        let witness = make_witness(
            vec![vec![0x11]],
            vec![vec![0x22]],
            vec![vec![0x33]],
            vec![vec![0x44]],
        );

        let encoded = encode_witness_to_ssz(&witness);
        let decoded = decode_witness_from_ssz(&encoded).expect("decode failed");
        assert_witness_eq(&witness, &decoded);
    }

    #[test]
    fn test_roundtrip_variable_item_sizes() {
        // items with very different sizes in the same field
        let witness = make_witness(
            vec![
                vec![],                // empty item
                vec![0x01],            // 1 byte
                vec![0xff; 1000],      // 1KB
                vec![0xab; 32],        // typical hash size
            ],
            vec![vec![0x00; 32]],
            vec![vec![0x60; 24576]],   // typical contract bytecode size
            vec![vec![0xf8; 508]],     // typical RLP block header
        );

        let encoded = encode_witness_to_ssz(&witness);
        let decoded = decode_witness_from_ssz(&encoded).expect("decode failed");
        assert_witness_eq(&witness, &decoded);
    }

    #[test]
    fn test_roundtrip_large_witness() {
        // simulate a realistic witness with many trie nodes
        let state: Vec<Vec<u8>> = (0..500)
            .map(|i| {
                let mut node = vec![0u8; 64 + (i % 400)];
                node[0] = (i % 256) as u8;
                node
            })
            .collect();

        let keys: Vec<Vec<u8>> = (0..500)
            .map(|_| vec![0xaa; 32])
            .collect();

        let codes: Vec<Vec<u8>> = (0..20)
            .map(|i| vec![(i % 256) as u8; 1000 + i * 100])
            .collect();

        let headers: Vec<Vec<u8>> = (0..10)
            .map(|_| vec![0xf8; 508])
            .collect();

        let witness = make_witness(state, keys, codes, headers);

        let encoded = encode_witness_to_ssz(&witness);
        let decoded = decode_witness_from_ssz(&encoded).expect("decode failed on large witness");
        assert_witness_eq(&witness, &decoded);
    }

    #[test]
    fn test_roundtrip_encoded_size_is_exact() {
        let witness = make_witness(
            vec![vec![0x01, 0x02, 0x03]],   
            vec![vec![0x04, 0x05]],          
            vec![vec![0x06]],                
            vec![vec![0x07, 0x08, 0x09, 0x0a]], 
        );

        let encoded = encode_witness_to_ssz(&witness);
        assert_eq!(encoded.len(), 42, "encoded size does not match expected");

        let decoded = decode_witness_from_ssz(&encoded).expect("decode failed");
        assert_witness_eq(&witness, &decoded);
    }

    #[test]
    fn test_decode_rejects_truncated_input() {
        let witness = make_witness(
            vec![vec![0x01, 0x02]],
            vec![vec![0x03]],
            vec![vec![0x04]],
            vec![vec![0x05]],
        );
        let encoded = encode_witness_to_ssz(&witness);

        let result = decode_witness_from_ssz(&encoded[..8]);
        assert!(result.is_err(), "should reject input shorter than 16 bytes");
    }

    #[test]
    fn test_decode_rejects_empty_input() {
        let result = decode_witness_from_ssz(&[]);
        assert!(result.is_err(), "should reject empty input");
    }
}