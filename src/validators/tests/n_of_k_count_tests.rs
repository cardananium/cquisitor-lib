//! `ScriptNOfK` counts outside `u32` (the ledger's `RequireMOf` takes any
//! `Int`; `n <= 0` always holds) through every reader of a transaction:
//! the script in the witness set, as an output's script reference and as a
//! spent UTxO's script reference, next to one Plutus redeemer, through
//! validation (phases 1 and 2), the UTxO list, script execution and the
//! reference-script reader.

use cardano_serialization_lib as csl;
use pallas_codec::minicbor;
use pallas_traverse::{ComputeHash, Era, MultiEraTx, OriginalHash};

use crate::js_value::JsValue;
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::tests::deep_native_script_tests::fixture_with_script;
use crate::validators::validator::validate_transaction;

/// Shortest-form CBOR integer.
fn cbor_int(n: i64) -> Vec<u8> {
    let mut out = Vec::new();
    minicbor::Encoder::new(&mut out).i64(n).unwrap();
    out
}

/// `ScriptAny[ScriptPubkey(key), ScriptNOfK(n, [ScriptPubkey(key)])]`:
/// holds with the key's signature; without it, holds iff `n <= 0`.
fn n_of_k_script(n: i64) -> Vec<u8> {
    let key_hash = csl::PrivateKey::from_normal_bytes(&[7u8; 32])
        .unwrap()
        .to_public()
        .hash()
        .to_bytes();
    let pubkey = |out: &mut Vec<u8>| {
        out.extend_from_slice(&[0x82, 0x00, 0x58, 0x1c]);
        out.extend_from_slice(&key_hash);
    };
    let mut script = vec![0x82, 0x02, 0x82];
    pubkey(&mut script);
    script.extend_from_slice(&[0x83, 0x03]);
    script.extend(cbor_int(n));
    script.push(0x81);
    pubkey(&mut script);
    script
}

fn native_script_failed(result: &crate::validators::validation_result::ValidationResult, hash: &str) -> bool {
    result.errors.iter().any(|e| {
        matches!(&e.error, Phase1Error::NativeScriptIsUnsuccessful { native_script_hash } if native_script_hash == hash)
    })
}

fn check(n: i64) {
    let script = n_of_k_script(n);
    let mut f = fixture_with_script(script.clone());
    // A spent UTxO carries the script as its reference too.
    let mut script_ref = vec![0x82, 0x00];
    script_ref.extend_from_slice(&script);
    let native_input = f
        .context
        .utxo_set
        .iter_mut()
        .find(|u| u.utxo.input.tx_hash == "11".repeat(32))
        .unwrap();
    native_input.utxo.output.script_ref = Some(hex::encode(&script_ref));
    let utxos: Vec<crate::common::UTxO> = f.context.utxo_set.iter().map(|u| u.utxo.clone()).collect();
    f.utxos_json = serde_json::to_string(&utxos).unwrap();

    // pallas reads the script, and its hash re-encoded (as the Plutus
    // context computes a reference script's hash) is the ledger's.
    let tx_bytes = hex::decode(&f.tx_signed_hex).unwrap();
    let MultiEraTx::Conway(tx) = MultiEraTx::decode_for_era(Era::Conway, &tx_bytes)
        .unwrap_or_else(|e| panic!("pallas decodes the tx at n = {}: {}", n, e))
    else {
        panic!("a Conway transaction")
    };
    let witness = &tx.transaction_witness_set.native_script.as_ref().unwrap()[0];
    assert_eq!(witness.raw_cbor(), &script[..]);
    assert_eq!(witness.original_hash().to_string(), f.script_hash);
    assert_eq!(witness.compute_hash().to_string(), f.script_hash);
    let output = match &tx.transaction_body.outputs[1] {
        pallas_primitives::conway::PseudoTransactionOutput::PostAlonzo(o) => o,
        _ => panic!("a post-Alonzo output"),
    };
    let owned: pallas_primitives::conway::ScriptRef = output.script_ref.clone().unwrap().unwrap().into();
    let pallas_primitives::conway::ScriptRef::NativeScript(native) = owned else {
        panic!("a native script reference")
    };
    assert_eq!(minicbor::to_vec(&native).unwrap(), script, "n = {}", n);
    assert_eq!(native.compute_hash().to_string(), f.script_hash);

    // Validation: phase 1 evaluates the script, phase 2 runs the redeemer.
    let signed = validate_transaction(&f.tx_signed_hex, f.context.clone())
        .unwrap_or_else(|e| panic!("validation at n = {}: {}", n, e));
    assert!(!native_script_failed(&signed, &f.script_hash), "{:?}", signed.errors);
    assert_eq!(signed.eval_redeemer_results.len(), 1, "n = {}: {:?}", n, signed);
    assert!(signed.eval_redeemer_results[0].success, "{:?}", signed.eval_redeemer_results);
    let unsigned = validate_transaction(&f.tx_unsigned_hex, f.context.clone())
        .unwrap_or_else(|e| panic!("validation at n = {}: {}", n, e));
    assert_eq!(native_script_failed(&unsigned, &f.script_hash), n > 0, "n = {}", n);
    assert_eq!(unsigned.eval_redeemer_results.len(), 1, "n = {}: {:?}", n, unsigned);
    assert!(unsigned.eval_redeemer_results[0].success, "{:?}", unsigned.eval_redeemer_results);

    let inputs = crate::plutus::execute_tx_scripts::get_utxo_list_from_tx(&f.tx_signed_hex)
        .unwrap_or_else(|e| panic!("UTxO list at n = {}: {}", n, e));
    assert_eq!(inputs.len(), 3);

    let executed = crate::plutus::execute_tx_scripts::execute_tx_scripts(
        &f.tx_signed_hex,
        JsValue::new(&f.utxos_json),
        JsValue::new(
            &serde_json::to_string(&crate::validators::tests::fixtures::default_cost_models()).unwrap(),
        ),
    )
    .map_err(|e| e.to_string())
    .unwrap_or_else(|e| panic!("execution at n = {}: {}", n, e));
    let executed: serde_json::Value = serde_json::from_str(&executed.as_string().unwrap()).unwrap();
    assert_eq!(executed.as_array().map(Vec::len), Some(1), "{}", executed);
    assert!(executed[0].get("error").is_none(), "{}", executed);

    let reference = crate::tx_utils::get_ref_script_bytes(&f.tx_signed_hex, 1)
        .unwrap_or_else(|e| panic!("reference script at n = {}: {}", n, e));
    assert_eq!(reference, f.script_hex);
}

#[test]
fn n_of_k_counts_outside_u32_go_through_every_entry_point() {
    for n in [-1, 0, 2, 1 << 32, 1 << 40, i64::MIN, i64::MAX] {
        check(n);
    }
}
