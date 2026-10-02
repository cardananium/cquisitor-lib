//! Transactions carrying native scripts nested as deep as a maximum-size
//! transaction can hold them (5,430 `ScriptAll` levels) and deeper
//! (10,000), through every entry point that reads a transaction: typed
//! decoding, the possible-types report, necessary data, hash extraction,
//! signature checks, validation (phase 1 evaluates the script, true and
//! false; phase 2 runs a Plutus redeemer next to it), the UTxO list and
//! script execution.

use cardano_serialization_lib as csl;

use crate::check_signatures::check_tx_signatures;
use crate::common::{Asset, TxInput, TxOutput, UTxO};
use crate::csl_decoders::universal_decoder::{decode_specific_type, get_possible_types_report};
use crate::hash_extractor::extract_hashes_from_transaction;
use crate::js_value::JsValue;
use crate::validators::common::NetworkType;
use crate::validators::input_contexts::{UtxoInputContext, ValidationInputContext};
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::tests::fixtures::preview_simple_context;
use crate::validators::validator::{get_necessary_data_list, validate_transaction};

/// A PlutusV1/V2 program that accepts any datum, redeemer and context.
const ALWAYS_SUCCEEDS: &str = "4d01000033222220051200120011";

/// The key whose signature the script's leaf asks for.
fn signing_key() -> csl::PrivateKey {
    csl::PrivateKey::from_normal_bytes(&[7u8; 32]).expect("a 32-byte ed25519 seed")
}

/// `levels` `ScriptAll`s around `ScriptPubkey(key_hash)`: `2 * levels + 1`
/// CBOR levels (the leaf's fields one more).
pub(crate) fn script_chain(levels: usize, key_hash: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(levels * 3 + 32);
    for _ in 0..levels {
        bytes.extend_from_slice(&[0x82, 0x01, 0x81]);
    }
    bytes.extend_from_slice(&[0x82, 0x00, 0x58, 0x1c]);
    bytes.extend_from_slice(key_hash);
    bytes
}

/// A definite byte string header and `payload`.
fn bstr(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x5a];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn enterprise_script_address(hash: &csl::ScriptHash) -> csl::Address {
    csl::EnterpriseAddress::new(0, &csl::Credential::from_scripthash(hash)).to_address()
}

fn lovelace(quantity: u64) -> Vec<Asset> {
    vec![Asset {
        unit: "lovelace".to_string(),
        quantity: quantity.to_string(),
    }]
}

/// Everything the tests need for one depth.
pub(crate) struct DeepFixture {
    /// The native script alone.
    pub(crate) script_hex: String,
    pub(crate) script_hash: String,
    /// Signed by the key the script asks for: the script holds.
    pub(crate) tx_signed_hex: String,
    /// The same body without the signature: the script fails.
    pub(crate) tx_unsigned_hex: String,
    /// The spent UTxOs (the preview key UTxO as collateral, the one locked
    /// by the native script, the one locked by the Plutus script).
    pub(crate) context: ValidationInputContext,
    /// The UTxOs `execute_tx_scripts` resolves, as JSON.
    pub(crate) utxos_json: String,
}

/// A Conway transaction spending a UTxO locked by a native script of
/// `levels` `ScriptAll`s (carried in the witness set), a UTxO locked by an
/// always-succeeding PlutusV2 script (one spend redeemer), paying an
/// output whose script reference is the same native script, with
/// auxiliary data carrying it once more.
pub(crate) fn deep_fixture(levels: usize) -> DeepFixture {
    let key_hash = signing_key().to_public().hash().to_bytes();
    fixture_with_script(script_chain(levels, &key_hash))
}

/// The transaction of [`deep_fixture`] around any native `script`.
pub(crate) fn fixture_with_script(script: Vec<u8>) -> DeepFixture {
    let key = signing_key();
    let vkey = key.to_public();
    let native = csl::NativeScript::from_bytes(script.clone()).expect("the chain reads");
    let script_hash = native.hash();
    drop(native);

    let plutus = csl::PlutusScript::new_v2(hex::decode(ALWAYS_SUCCEEDS).unwrap());
    let plutus_hash = plutus.hash();

    let key_utxo = preview_simple_context().utxo_set[0].clone();
    let key_address = crate::csl_preflight::address_from_bech32(&key_utxo.utxo.output.address)
        .unwrap()
        .to_bytes();
    let native_utxo = UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: "11".repeat(32),
                output_index: 0,
            },
            output: TxOutput {
                address: enterprise_script_address(&script_hash).to_bech32(None).unwrap(),
                amount: lovelace(5_000_000),
                data_hash: None,
                plutus_data: None,
                script_ref: None,
                script_hash: None,
            },
        },
        is_spent: false,
    };
    let plutus_utxo = UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: "22".repeat(32),
                output_index: 0,
            },
            output: TxOutput {
                address: enterprise_script_address(&plutus_hash).to_bech32(None).unwrap(),
                amount: lovelace(5_000_000),
                data_hash: None,
                plutus_data: Some("00".to_string()),
                script_ref: None,
                script_hash: None,
            },
        },
        is_spent: false,
    };

    // Auxiliary data `#6.259({1: [script]})`.
    let mut aux = hex::decode("d90103a10181").unwrap();
    aux.extend_from_slice(&script);
    let aux_hash = cryptoxide::hashing::blake2b_256(&aux);

    // Body: inputs (sorted: 11…#0 native, 22…#0 Plutus), a key output and
    // an output holding the script as its reference, fee, auxiliary data
    // hash, a script data hash, collateral.
    let mut script_ref = vec![0x82, 0x00];
    script_ref.extend_from_slice(&script);
    let mut body = Vec::new();
    body.push(0xa6);
    body.extend(hex::decode(format!(
        "00d90102828258 20{}00 8258 20{}00",
        "11".repeat(32),
        "22".repeat(32)
    )
    .replace(' ', ""))
    .unwrap());
    body.extend(hex::decode("0182").unwrap());
    body.push(0x82);
    body.push(0x58);
    body.push(key_address.len() as u8);
    body.extend_from_slice(&key_address);
    body.extend(hex::decode("1a006acfc0").unwrap()); // 7 ADA
    // An enterprise key address (testnet) for the payment part.
    body.extend(hex::decode("a3005 81d60".replace(' ', "")).unwrap());
    body.extend_from_slice(&key_address[1..29]);
    body.extend(hex::decode("01 1a 001e8480 03 d818".replace(' ', "")).unwrap()); // 2 ADA
    body.extend(bstr(&script_ref));
    body.extend(hex::decode("021a000f4240").unwrap()); // fee 1 ADA
    body.extend(hex::decode("075820").unwrap());
    body.extend_from_slice(&aux_hash);
    body.extend(hex::decode(format!("0b5820{}", "5d".repeat(32))).unwrap());
    body.extend(hex::decode(format!(
        "0dd90102818258 20{}00",
        key_utxo.utxo.input.tx_hash
    )
    .replace(' ', ""))
    .unwrap());
    let tx_hash = cryptoxide::hashing::blake2b_256(&body);
    let signature = key.sign(&tx_hash).to_bytes();

    let witness_set = |signed: bool| {
        let mut ws = Vec::new();
        ws.push(if signed { 0xa4 } else { 0xa3 });
        if signed {
            ws.extend(hex::decode("00d9010281825820").unwrap());
            ws.extend(vkey.as_bytes());
            ws.extend(hex::decode("5840").unwrap());
            ws.extend(&signature);
        }
        ws.extend(hex::decode("01d9010281").unwrap());
        ws.extend_from_slice(&script);
        // Redeemer `[0, 1, 0, [mem, steps]]` spending the Plutus input.
        ws.extend(hex::decode("058184000100821a000f42401a3b9aca00").unwrap());
        // The script as the witness set carries it: its CBOR in a byte string.
        ws.extend(
            hex::decode(format!("06d901028158{:02x}{}", ALWAYS_SUCCEEDS.len() / 2, ALWAYS_SUCCEEDS))
                .unwrap(),
        );
        ws
    };
    let tx = |signed: bool| {
        let mut tx = vec![0x84];
        tx.extend_from_slice(&body);
        tx.extend(witness_set(signed));
        tx.push(0xf5);
        tx.extend_from_slice(&aux);
        hex::encode(tx)
    };

    let mut context = preview_simple_context();
    context.utxo_set.push(native_utxo.clone());
    context.utxo_set.push(plutus_utxo.clone());
    let utxos: Vec<UTxO> = context.utxo_set.iter().map(|u| u.utxo.clone()).collect();

    DeepFixture {
        script_hex: hex::encode(&script),
        script_hash: script_hash.to_hex(),
        tx_signed_hex: tx(true),
        tx_unsigned_hex: tx(false),
        context,
        utxos_json: serde_json::to_string(&utxos).unwrap(),
    }
}

/// Whether `errors` report the native script unsuccessful.
fn native_script_failed(result: &crate::validators::validation_result::ValidationResult, hash: &str) -> bool {
    result.errors.iter().any(|e| {
        matches!(&e.error, Phase1Error::NativeScriptIsUnsuccessful { native_script_hash } if native_script_hash == hash)
    })
}

/// No answer may be a nesting refusal.
fn assert_not_refused(what: &str, levels: usize, text: &str) {
    assert!(
        !text.contains("supported limit") && !text.contains("nesting_too_deep"),
        "{} at {} levels was refused: {}",
        what,
        levels,
        &text[..text.len().min(400)]
    );
}

/// Every entry point on the fixture of `levels`, each answer checked.
pub(crate) fn every_entry_point(levels: usize) {
    let mut t = std::time::Instant::now();
    let mut lap = |what: &str| {
        if std::env::var("CQ_LAPS").is_ok() {
            eprintln!("{} {}: {:?}", levels, what, t.elapsed());
        }
        t = std::time::Instant::now();
    };
    let f = deep_fixture(levels);
    lap("fixture");
    // Typed decoding: the script alone, and the transaction.
    let params = || JsValue::new("{}");
    let decoded = decode_specific_type(&f.script_hex, "NativeScript", params())
        .unwrap_or_else(|e| panic!("NativeScript at {}: {}", levels, e));
    assert!(decoded.starts_with(&format!("{{\"script_hash\":\"{}\"", f.script_hash)));
    let decoded = decode_specific_type(&f.tx_signed_hex, "Transaction", params())
        .unwrap_or_else(|e| panic!("Transaction at {}: {}", levels, e));
    assert!(decoded.contains("\"transaction_hash\""));
    assert_eq!(decoded.matches("\"ScriptAll\"").count(), 3 * levels);

    lap("decode");
    let report = get_possible_types_report(&f.tx_signed_hex);
    assert!(report.contains("\"Transaction\""), "{}", &report[..report.len().min(300)]);
    let report: serde_json::Value =
        serde_json::from_str(&get_possible_types_report(&f.script_hex)).unwrap();
    assert!(
        report["types"].as_array().unwrap().contains(&serde_json::json!("NativeScript")),
        "{}",
        report
    );

    lap("report");
    let necessary = get_necessary_data_list(&f.tx_signed_hex, NetworkType::Preview)
        .unwrap_or_else(|e| panic!("necessary data at {}: {}", levels, e));
    assert_not_refused("necessary data", levels, &format!("{:?}", necessary));

    lap("necessary");
    let hashes = extract_hashes_from_transaction(&f.tx_signed_hex)
        .unwrap_or_else(|e| panic!("hashes at {}: {}", levels, e));
    assert_eq!(
        hashes.witness_native_script_hashes,
        vec![Some(f.script_hash.clone())]
    );

    lap("hashes");
    let signatures = check_tx_signatures(&f.tx_signed_hex)
        .unwrap_or_else(|e| panic!("signatures at {}: {}", levels, e));
    assert!(signatures.valid, "{:?}", signatures);

    lap("signatures");
    // Phase 1 evaluates the script: it holds with the signature, and fails
    // without it; phase 2 runs the Plutus redeemer next to it.
    let signed = validate_transaction(&f.tx_signed_hex, f.context.clone())
        .unwrap_or_else(|e| panic!("validation at {}: {}", levels, e));
    assert!(!native_script_failed(&signed, &f.script_hash), "{:?}", signed.errors);
    assert_eq!(signed.eval_redeemer_results.len(), 1);
    assert!(signed.eval_redeemer_results[0].success, "{:?}", signed.eval_redeemer_results);
    lap("validate signed");
    let unsigned = validate_transaction(&f.tx_unsigned_hex, f.context.clone())
        .unwrap_or_else(|e| panic!("validation at {}: {}", levels, e));
    assert!(native_script_failed(&unsigned, &f.script_hash), "{:?}", unsigned.errors);

    lap("validate unsigned");
    let inputs = crate::plutus::execute_tx_scripts::get_utxo_list_from_tx(&f.tx_signed_hex)
        .unwrap_or_else(|e| panic!("UTxO list at {}: {}", levels, e));
    assert_eq!(inputs.len(), 3);
    lap("utxo list");
    let executed = crate::plutus::execute_tx_scripts::execute_tx_scripts(
        &f.tx_signed_hex,
        JsValue::new(&f.utxos_json),
        JsValue::new(
            &serde_json::to_string(&crate::validators::tests::fixtures::default_cost_models())
                .unwrap(),
        ),
    )
    .map_err(|e| e.to_string())
    .unwrap_or_else(|e| panic!("execution at {}: {}", levels, e));
    let executed: serde_json::Value = serde_json::from_str(&executed.as_string().unwrap()).unwrap();
    assert_eq!(executed.as_array().map(Vec::len), Some(1), "{}", executed);
    assert!(executed[0].get("error").is_none(), "{}", executed);

    lap("execute");
    // The witness inserters take a witness set (or a whole transaction)
    // carrying the deep script.
    let signed_witness_set = hex::encode(
        csl::FixedTransaction::from_hex(&f.tx_signed_hex)
            .unwrap()
            .raw_witness_set(),
    );
    crate::witness_inserter::add_witness_set_to_tx(&f.tx_unsigned_hex, &signed_witness_set)
        .unwrap_or_else(|e| panic!("witness set insertion at {}: {:?}", levels, e));
    crate::witness_inserter::add_witnesses_to_tx(
        &f.tx_unsigned_hex,
        vec![signed_witness_set.clone(), f.tx_signed_hex.clone()],
    )
    .unwrap_or_else(|e| panic!("witness insertion at {}: {:?}", levels, e));
    lap("witness insertion");

    let script_ref = crate::tx_utils::get_ref_script_bytes(&f.tx_signed_hex, 1)
        .unwrap_or_else(|e| panic!("reference script at {}: {}", levels, e));
    assert_eq!(script_ref, f.script_hex);
}

/// 5,430 levels (the deepest a 16 KB transaction holds) and 10,000, on a
/// 4 MiB stack in a debug build.
#[test]
fn deep_native_scripts_go_through_every_entry_point() {
    std::thread::Builder::new()
        .stack_size(4 << 20)
        .spawn(|| {
            for levels in [5430, 10_000] {
                every_entry_point(levels);
            }
        })
        .unwrap()
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

/// Evaluation and key-hash collection are linear: 10,000 levels well
/// under 100 ms even unoptimised.
#[test]
fn native_script_evaluation_is_linear() {
    let key = [9u8; 28];
    let script = csl::NativeScript::from_bytes(script_chain(10_000, &key)).unwrap();
    let signed: std::collections::HashSet<csl::Ed25519KeyHash> =
        std::iter::once(csl::Ed25519KeyHash::from_bytes(key.to_vec()).unwrap()).collect();
    let started = std::time::Instant::now();
    let holds = crate::validators::phase_1::validation::NativeScriptExecutor::new(
        &script,
        &signed,
        crate::validators::phase_1::validation::native_script_executor::ValidityInterval::default(),
    )
        .execute()
        .unwrap();
    let elapsed = started.elapsed();
    assert!(holds);
    assert!(elapsed.as_millis() < 100, "{:?}", elapsed);
}
