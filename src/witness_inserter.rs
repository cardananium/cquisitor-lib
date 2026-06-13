use base64::Engine;
use cardano_serialization_lib::{
    BootstrapWitness, FixedTransaction, TransactionWitnessSet, Vkeywitness,
};

use crate::bingen::wasm_bindgen;
use crate::js_error::JsError;

/// Witnesses extracted from a single user-provided input, ready to be spliced
/// into a transaction.
#[derive(Default)]
struct ExtractedWitnesses {
    vkeys: Vec<Vkeywitness>,
    bootstraps: Vec<BootstrapWitness>,
}

impl ExtractedWitnesses {
    fn is_empty(&self) -> bool {
        self.vkeys.is_empty() && self.bootstraps.is_empty()
    }
}

/// Add witnesses to an already built transaction, accepting witnesses in many
/// shapes — mirroring the format-flexible behaviour of the original PR.
///
/// The transaction body bytes (and therefore the transaction id / every existing
/// signature) are preserved exactly, because we rely on CSL's `FixedTransaction`,
/// which keeps the original body bytes and only re-encodes the witness set.
///
/// Each entry of `witnesses` is auto-detected and may be any of:
/// - a single `Vkeywitness` (`[ vkey, signature ]`);
/// - a single `BootstrapWitness`;
/// - a whole `TransactionWitnessSet` (e.g. the result of a CIP-30 `signTx`);
/// - a whole transaction (signed or not) — its vkey/bootstrap witnesses are taken;
///
/// each of those encoded as hex, base64, or wrapped in a cardano-cli style JSON
/// text-envelope (`{ "cborHex": "..." }`). Only vkey and bootstrap witnesses are
/// merged (the parts a signer can contribute); duplicates are ignored by CSL.
///
/// Returns the hex of the resulting transaction.
#[wasm_bindgen]
pub fn add_witnesses_to_tx(tx_hex: &str, witnesses: Vec<String>) -> Result<String, JsError> {
    let mut tx = FixedTransaction::from_hex(tx_hex)
        .map_err(|e| JsError::new(&format!("Failed to parse transaction: {:?}", e)))?;

    for (i, input) in witnesses.iter().enumerate() {
        let extracted = extract_witnesses(input)
            .map_err(|e| JsError::new(&format!("Failed to parse witness at index {}: {}", i, e)))?;
        apply_witnesses(&mut tx, &extracted);
    }

    Ok(tx.to_hex())
}

/// Strict helper: add a list of vkey witnesses, each the CBOR-hex of a single
/// `Vkeywitness` (`[ vkey, signature ]`). Use [`add_witnesses_to_tx`] if the
/// input format may vary.
#[wasm_bindgen]
pub fn add_vkey_witnesses_to_tx(
    tx_hex: &str,
    vkey_witnesses_hex: Vec<String>,
) -> Result<String, JsError> {
    let mut tx = FixedTransaction::from_hex(tx_hex)
        .map_err(|e| JsError::new(&format!("Failed to parse transaction: {:?}", e)))?;

    for (i, witness_hex) in vkey_witnesses_hex.iter().enumerate() {
        let witness = Vkeywitness::from_hex(witness_hex).map_err(|e| {
            JsError::new(&format!("Failed to parse vkey witness at index {}: {:?}", i, e))
        })?;
        tx.add_vkey_witness(&witness);
    }

    Ok(tx.to_hex())
}

/// Strict helper: merge a whole `TransactionWitnessSet` (CBOR-hex) into a
/// transaction. This is the canonical shape returned by a CIP-30 `signTx`.
/// Use [`add_witnesses_to_tx`] if the input format may vary.
#[wasm_bindgen]
pub fn add_witness_set_to_tx(tx_hex: &str, witness_set_hex: &str) -> Result<String, JsError> {
    let mut tx = FixedTransaction::from_hex(tx_hex)
        .map_err(|e| JsError::new(&format!("Failed to parse transaction: {:?}", e)))?;

    let witness_set = TransactionWitnessSet::from_hex(witness_set_hex)
        .map_err(|e| JsError::new(&format!("Failed to parse witness set: {:?}", e)))?;

    apply_witnesses(&mut tx, &witnesses_from_set(&witness_set));

    Ok(tx.to_hex())
}

fn apply_witnesses(tx: &mut FixedTransaction, extracted: &ExtractedWitnesses) {
    for vkey in &extracted.vkeys {
        tx.add_vkey_witness(vkey);
    }
    for bootstrap in &extracted.bootstraps {
        tx.add_bootstrap_witness(bootstrap);
    }
}

fn witnesses_from_set(witness_set: &TransactionWitnessSet) -> ExtractedWitnesses {
    let mut extracted = ExtractedWitnesses::default();
    if let Some(vkeys) = witness_set.vkeys() {
        for i in 0..vkeys.len() {
            extracted.vkeys.push(vkeys.get(i));
        }
    }
    if let Some(bootstraps) = witness_set.bootstraps() {
        for i in 0..bootstraps.len() {
            extracted.bootstraps.push(bootstraps.get(i));
        }
    }
    extracted
}

/// Decode one user-provided witness input (any supported encoding + shape) into
/// the concrete witnesses it carries.
fn extract_witnesses(input: &str) -> Result<ExtractedWitnesses, String> {
    let bytes = decode_input_to_bytes(input)?;
    extract_witnesses_from_bytes(&bytes)
}

/// Turn a textual witness input into raw CBOR bytes, accepting:
/// - a cardano-cli style JSON text-envelope with a `cborHex` field;
/// - plain hex;
/// - base64 (standard or url-safe).
fn decode_input_to_bytes(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty witness input".to_string());
    }

    // cardano-cli / text-envelope JSON: { "type": ..., "cborHex": "..." }
    if trimmed.starts_with('{') {
        let json: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("invalid JSON witness envelope: {}", e))?;
        let cbor_hex = json
            .get("cborHex")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "JSON witness envelope has no string `cborHex` field".to_string())?;
        return hex::decode(cbor_hex.trim())
            .map_err(|e| format!("invalid hex in `cborHex`: {}", e));
    }

    if let Ok(bytes) = hex::decode(trimmed) {
        return Ok(bytes);
    }

    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .map_err(|_| "witness input is neither valid hex, base64 nor a JSON envelope".to_string())
}

/// Detect which witness-bearing CBOR structure `bytes` encodes and pull the
/// vkey/bootstrap witnesses out of it. The candidate shapes are mutually
/// distinguishable by their CBOR layout (map vs. 4-array vs. 2-array vs. the
/// bootstrap 4-array), so the first successful parse is the right one.
fn extract_witnesses_from_bytes(bytes: &[u8]) -> Result<ExtractedWitnesses, String> {
    if let Some(extracted) = try_decode_witnesses(bytes) {
        return Ok(extracted);
    }

    // cardano-cli wraps a key witness as `[ tag, witness ]` (tag 0 = vkey,
    // tag 1 = bootstrap). Unwrap that one layer and try again.
    if let Some(inner) = unwrap_cli_key_witness(bytes) {
        if let Some(extracted) = try_decode_witnesses(&inner) {
            return Ok(extracted);
        }
    }

    Err("could not decode input as a vkey witness, bootstrap witness, witness set or transaction".to_string())
}

/// Try every directly-recognised witness-bearing CBOR shape.
fn try_decode_witnesses(bytes: &[u8]) -> Option<ExtractedWitnesses> {
    if let Ok(witness_set) = TransactionWitnessSet::from_bytes(bytes.to_vec()) {
        let extracted = witnesses_from_set(&witness_set);
        if !extracted.is_empty() {
            return Some(extracted);
        }
    }

    if let Ok(tx) = FixedTransaction::from_bytes(bytes.to_vec()) {
        let extracted = witnesses_from_set(&tx.witness_set());
        if !extracted.is_empty() {
            return Some(extracted);
        }
    }

    if let Ok(vkey) = Vkeywitness::from_bytes(bytes.to_vec()) {
        return Some(ExtractedWitnesses {
            vkeys: vec![vkey],
            bootstraps: vec![],
        });
    }

    if let Ok(bootstrap) = BootstrapWitness::from_bytes(bytes.to_vec()) {
        return Some(ExtractedWitnesses {
            vkeys: vec![],
            bootstraps: vec![bootstrap],
        });
    }

    None
}

/// If `bytes` is a cardano-cli style key-witness wrapper — a 2-element CBOR
/// array whose first element is an integer tag (`[ tag, witness ]`) — return the
/// CBOR bytes of the inner `witness`. A raw `Vkeywitness` is also a 2-element
/// array, but its first element is a byte string (the vkey), not an integer, so
/// the two are unambiguous.
fn unwrap_cli_key_witness(bytes: &[u8]) -> Option<Vec<u8>> {
    let value: ciborium::value::Value = ciborium::de::from_reader(bytes).ok()?;
    let items = value.as_array()?;
    if items.len() != 2 || !items[0].is_integer() {
        return None;
    }
    let mut inner = Vec::new();
    ciborium::ser::into_writer(&items[1], &mut inner).ok()?;
    Some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use cardano_serialization_lib::{PrivateKey, TransactionWitnessSet};

    // A real, signed Conway tx (1 existing vkey witness).
    const TX_HEX: &str = "84a400d901028182582016b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a00018282583900aef399a405edd6797117a3db6653e1a230e1f6f91dd5badb77f2be3720fc45da826093ae8ed2e4f0f81c4f5ea9b6f0dda561c974cfc6355d1a000f424082583900f275cb75d82f737c49280039947e484919ee044c82c2e4ceaf2f2d87984c3eb5c8a01b4b53c7cec4cfc139345a28d24a6ec918873c459add1a48b7d00d021a00030d40075820bdaa99eb158414dea0a91d6c727e2268574b23efe6e08ab3b841abe8059a030ca100d9010281825820f8f5750132a13473240e318dd36eccd70083e8f08ac589c74ebe776f43e9401d58401e149e081ff497d7f97c3ef7427a916d1b0632c6eb98bb54b040aca413a2ad94273291c9b63b2802083c72b0cfe03eef2b55f767ecf32dba894dd59701076409f5d90103a0";

    /// Sign the tx with a fresh key and return the resulting single Vkeywitness.
    fn fresh_witness() -> Vkeywitness {
        let tx = FixedTransaction::from_hex(TX_HEX).unwrap();
        let sk = PrivateKey::from_normal_bytes(&[7u8; 32]).unwrap();
        cardano_serialization_lib::make_vkey_witness(&tx.transaction_hash(), &sk)
    }

    fn vkey_count(tx_hex: &str) -> usize {
        FixedTransaction::from_hex(tx_hex)
            .unwrap()
            .witness_set()
            .vkeys()
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// The defining invariant: adding witnesses must not change the body bytes,
    /// the tx hash, or the validity flag / auxiliary data.
    fn assert_body_preserved(original_hex: &str, result_hex: &str) {
        let original = FixedTransaction::from_hex(original_hex).unwrap();
        let result = FixedTransaction::from_hex(result_hex).unwrap();
        assert_eq!(original.raw_body(), result.raw_body(), "body bytes changed");
        assert_eq!(
            original.transaction_hash().to_hex(),
            result.transaction_hash().to_hex(),
            "tx hash changed"
        );
        assert_eq!(original.is_valid(), result.is_valid());
        assert_eq!(original.raw_auxiliary_data(), result.raw_auxiliary_data());
    }

    #[test]
    fn adds_vkey_witness_hex() {
        let witness_hex = fresh_witness().to_hex();
        let result = add_witnesses_to_tx(TX_HEX, vec![witness_hex]).unwrap();
        assert_body_preserved(TX_HEX, &result);
        assert_eq!(vkey_count(&result), vkey_count(TX_HEX) + 1);
    }

    #[test]
    fn strict_vkey_helper_matches() {
        let witness_hex = fresh_witness().to_hex();
        let flexible = add_witnesses_to_tx(TX_HEX, vec![witness_hex.clone()]).unwrap();
        let strict = add_vkey_witnesses_to_tx(TX_HEX, vec![witness_hex]).unwrap();
        assert_eq!(flexible, strict);
    }

    #[test]
    fn accepts_base64_witness() {
        let witness = fresh_witness();
        let b64 = base64::engine::general_purpose::STANDARD.encode(witness.to_bytes());
        let result = add_witnesses_to_tx(TX_HEX, vec![b64]).unwrap();
        assert_body_preserved(TX_HEX, &result);
        assert_eq!(vkey_count(&result), vkey_count(TX_HEX) + 1);
    }

    #[test]
    fn accepts_json_envelope() {
        let witness_hex = fresh_witness().to_hex();
        let envelope = format!(
            "{{\"type\":\"TxWitness ConwayEra\",\"description\":\"\",\"cborHex\":\"{}\"}}",
            witness_hex
        );
        let result = add_witnesses_to_tx(TX_HEX, vec![envelope]).unwrap();
        assert_body_preserved(TX_HEX, &result);
        assert_eq!(vkey_count(&result), vkey_count(TX_HEX) + 1);
    }

    #[test]
    fn accepts_witness_set() {
        let mut ws = TransactionWitnessSet::new();
        let mut vkeys = cardano_serialization_lib::Vkeywitnesses::new();
        vkeys.add(&fresh_witness());
        ws.set_vkeys(&vkeys);
        let result = add_witnesses_to_tx(TX_HEX, vec![ws.to_hex()]).unwrap();
        assert_body_preserved(TX_HEX, &result);
        assert_eq!(vkey_count(&result), vkey_count(TX_HEX) + 1);

        let strict = add_witness_set_to_tx(TX_HEX, &ws.to_hex()).unwrap();
        assert_eq!(result, strict);
    }

    #[test]
    fn accepts_full_transaction_as_witness_source() {
        // A signed tx carrying the witness we want to graft onto TX_HEX.
        let mut donor = FixedTransaction::from_hex(TX_HEX).unwrap();
        let sk = PrivateKey::from_normal_bytes(&[9u8; 32]).unwrap();
        donor
            .sign_and_add_vkey_signature(&sk)
            .unwrap();
        let result = add_witnesses_to_tx(TX_HEX, vec![donor.to_hex()]).unwrap();
        assert_body_preserved(TX_HEX, &result);
        // donor's witness set has the original + the new one => 2 vkeys merged,
        // but the original is a duplicate of TX_HEX's and is deduped by CSL.
        assert_eq!(vkey_count(&result), vkey_count(TX_HEX) + 1);
    }

    #[test]
    fn accepts_cardano_cli_keywitness_wrapper() {
        // cardano-cli serialises a vkey key-witness as `[ 0, [vkey, signature] ]`.
        let witness = fresh_witness();
        let mut wrapped = Vec::new();
        let value = ciborium::value::Value::Array(vec![
            ciborium::value::Value::Integer(0u8.into()),
            ciborium::de::from_reader(witness.to_bytes().as_slice()).unwrap(),
        ]);
        ciborium::ser::into_writer(&value, &mut wrapped).unwrap();
        let wrapped_hex = hex::encode(&wrapped);

        // sanity: this must NOT parse as a bare vkeywitness
        assert!(Vkeywitness::from_hex(&wrapped_hex).is_err());

        let result = add_witnesses_to_tx(TX_HEX, vec![wrapped_hex]).unwrap();
        assert_body_preserved(TX_HEX, &result);
        assert_eq!(vkey_count(&result), vkey_count(TX_HEX) + 1);
    }

    #[test]
    fn duplicate_witness_is_deduped() {
        let witness_hex = fresh_witness().to_hex();
        let result =
            add_witnesses_to_tx(TX_HEX, vec![witness_hex.clone(), witness_hex]).unwrap();
        assert_eq!(vkey_count(&result), vkey_count(TX_HEX) + 1);
    }

    #[test]
    fn rejects_garbage_input() {
        assert!(add_witnesses_to_tx(TX_HEX, vec!["not a witness".to_string()]).is_err());
    }
}
