//! Caller input that would otherwise abort the process (a wasm trap) is refused
//! with an error by every entry point that reads transactions, witness
//! sets and UTxO contexts: bytes that are not one well-formed CBOR item, a
//! witness list holding a simple value, and UTxO quantities that are not
//! integers.

use crate::check_signatures::{check_block_or_tx_signatures, check_tx_signatures};
use crate::common::{Asset, UTxO};
use crate::csl_decoders::tests::hazardous_transaction_hex;
use crate::hash_extractor::extract_hashes_from_transaction;
use crate::validators::common::NetworkType;
use crate::validators::helpers::normalize_script_ref;
use crate::validators::input_contexts::UtxoInputContext;
use crate::validators::phase_2::data_mapper::{
    to_pallas_multi_asset_value, to_pallas_utxos, to_pallas_value,
};
use crate::validators::tests::fixtures::{preview_simple_context, PREVIEW_SIMPLE_TX_HEX};
use crate::validators::validator::{get_necessary_data_list, validate_transaction};
use crate::validators::value::Value;
use crate::witness_inserter::{
    add_vkey_witnesses_to_tx, add_witness_set_to_tx, add_witnesses_to_tx,
};

/// Truncated array whose first item is an unassigned simple value.
const MALFORMED_TX_HEX: &str = "85e9";

fn asset(unit: &str, quantity: &str) -> Asset {
    Asset {
        unit: unit.to_string(),
        quantity: quantity.to_string(),
    }
}

#[test]
fn transaction_entry_points_refuse_malformed_cbor() {
    let err = validate_transaction(MALFORMED_TX_HEX, preview_simple_context())
        .err()
        .expect("malformed tx hex is an error")
        .to_string();
    assert!(err.contains("Malformed CBOR"), "{}", err);

    let err = get_necessary_data_list(MALFORMED_TX_HEX, NetworkType::Preview).unwrap_err();
    assert!(err.contains("Malformed CBOR"), "{}", err);

    let err = extract_hashes_from_transaction(MALFORMED_TX_HEX).unwrap_err();
    assert!(err.contains("Malformed CBOR"), "{}", err);

    let err = check_tx_signatures(MALFORMED_TX_HEX).unwrap_err();
    assert!(err.contains("Malformed CBOR"), "{}", err);
    assert!(check_block_or_tx_signatures(MALFORMED_TX_HEX).is_err());

    let err = add_witnesses_to_tx(MALFORMED_TX_HEX, vec![])
        .unwrap_err()
        .to_string();
    assert!(err.contains("Malformed CBOR"), "{}", err);
    // A malformed witness against a good transaction is refused the same way.
    let err = add_witnesses_to_tx(PREVIEW_SIMPLE_TX_HEX, vec![MALFORMED_TX_HEX.to_string()])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Failed to parse witness at index 0"),
        "{}",
        err
    );
    let err = add_vkey_witnesses_to_tx(PREVIEW_SIMPLE_TX_HEX, vec![MALFORMED_TX_HEX.to_string()])
        .unwrap_err()
        .to_string();
    assert!(err.contains("Malformed CBOR"), "{}", err);
    let err = add_witness_set_to_tx(PREVIEW_SIMPLE_TX_HEX, MALFORMED_TX_HEX)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Malformed CBOR"), "{}", err);
}

#[test]
fn transaction_entry_points_refuse_a_simple_value_in_a_witness_list() {
    // `[body, {0: [true]}, true, null]` and the bootstrap-witness variant.
    for witness_set in ["a10081f5", "a10281f6", "a100d9010281e9"] {
        let tx_hex = hazardous_transaction_hex(witness_set);

        let err = validate_transaction(&tx_hex, preview_simple_context())
            .err()
            .expect("witness list holding a simple value is an error")
            .to_string();
        assert!(err.contains("witness list"), "{}: {}", witness_set, err);

        let err = get_necessary_data_list(&tx_hex, NetworkType::Preview).unwrap_err();
        assert!(err.contains("witness list"), "{}: {}", witness_set, err);

        let err = extract_hashes_from_transaction(&tx_hex).unwrap_err();
        assert!(err.contains("witness list"), "{}: {}", witness_set, err);

        let err = check_tx_signatures(&tx_hex).unwrap_err();
        assert!(err.contains("witness list"), "{}: {}", witness_set, err);
        assert!(check_block_or_tx_signatures(&tx_hex).is_err());
        // A block carrying that witness set.
        let block_hex = format!("85a08081{witness_set}a080");
        assert!(check_block_or_tx_signatures(&block_hex).is_err());

        let err = add_witnesses_to_tx(&tx_hex, vec![])
            .unwrap_err()
            .to_string();
        assert!(err.contains("witness list"), "{}: {}", witness_set, err);
        let err = add_witness_set_to_tx(PREVIEW_SIMPLE_TX_HEX, witness_set)
            .unwrap_err()
            .to_string();
        assert!(err.contains("witness list"), "{}: {}", witness_set, err);
        // As a free-form witness input the set is simply not recognised.
        let err = add_witnesses_to_tx(PREVIEW_SIMPLE_TX_HEX, vec![witness_set.to_string()])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("could not decode input"),
            "{}: {}",
            witness_set,
            err
        );
        let err = add_witnesses_to_tx(PREVIEW_SIMPLE_TX_HEX, vec![tx_hex.clone()])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("could not decode input"),
            "{}: {}",
            witness_set,
            err
        );
    }
    // The fixture itself still validates, so the gate lets real data through.
    assert!(validate_transaction(PREVIEW_SIMPLE_TX_HEX, preview_simple_context()).is_ok());
    assert!(get_necessary_data_list(PREVIEW_SIMPLE_TX_HEX, NetworkType::Preview).is_ok());
    assert!(extract_hashes_from_transaction(PREVIEW_SIMPLE_TX_HEX).is_ok());
    assert!(check_tx_signatures(PREVIEW_SIMPLE_TX_HEX).is_ok());
    assert!(add_witnesses_to_tx(PREVIEW_SIMPLE_TX_HEX, vec![]).is_ok());
}

#[test]
fn validation_context_with_a_non_integer_quantity_is_an_error() {
    let mut context = preview_simple_context();
    context.utxo_set[0].utxo.output.amount[0].quantity = "1.5 ADA".to_string();
    let err = validate_transaction(PREVIEW_SIMPLE_TX_HEX, context)
        .err()
        .expect("a quantity that is not an integer is an input error")
        .to_string();
    assert!(
        err.contains("Invalid UTxO in the validation context"),
        "{}",
        err
    );
    assert!(err.contains("1.5 ADA"), "{}", err);
    assert!(err.contains("lovelace"), "{}", err);

    let err = Value::new_from_common_assets(&vec![asset("lovelace", "abc")]).unwrap_err();
    assert!(err.contains("abc"), "{}", err);
    assert!(
        Value::new_from_common_assets(&vec![asset("lovelace", "-5"), asset("aa", "7")]).is_ok()
    );
}

#[test]
fn phase_2_value_mapper_reports_bad_units_and_quantities() {
    let err = to_pallas_value(&vec![asset("lovelace", "abc")])
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid quantity 'abc'"), "{}", err);
    let err = to_pallas_value(&vec![asset("lovelace", "-1")])
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid quantity '-1'"), "{}", err);

    let policy = "ab".repeat(28);
    let assets = vec![asset("lovelace", "5"), asset(&format!("{policy}0102"), "0")];
    let err = to_pallas_multi_asset_value(&assets)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Non-positive asset quantity: 0"), "{}", err);

    let assets = vec![asset("lovelace", "5"), asset(&format!("{policy}0102"), "x")];
    let err = to_pallas_multi_asset_value(&assets)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid quantity 'x'"), "{}", err);

    // A unit shorter than a policy id, and one split inside a multibyte character.
    let err = to_pallas_multi_asset_value(&vec![asset("lovelace", "5"), asset("abcd", "1")])
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid asset unit 'abcd'"), "{}", err);
    let odd = format!("{}é", "a".repeat(55));
    let err = to_pallas_multi_asset_value(&vec![asset("lovelace", "5"), asset(&odd, "1")])
        .unwrap_err()
        .to_string();
    assert!(err.contains("Invalid asset unit"), "{}", err);

    let assets = vec![asset("lovelace", "5"), asset(&format!("{policy}0102"), "3")];
    assert!(to_pallas_multi_asset_value(&assets).is_ok());
}

/// A validation-context UTxO as phase 2 reads it, or the error naming the
/// field it could not read.
fn phase_2_utxo(utxo: UTxO) -> Result<(), String> {
    to_pallas_utxos(&vec![UtxoInputContext {
        utxo,
        is_spent: false,
    }])
    .map(|_| ())
    .map_err(|e| e.to_string())
}

#[test]
fn utxo_converter_reports_bad_fields() {
    let good: UTxO =
        serde_json::from_str(crate::validators::tests::fixtures::PREVIEW_SIMPLE_INPUT_UTXO)
            .unwrap();
    assert!(phase_2_utxo(good.clone()).is_ok());

    let mut utxo = good.clone();
    utxo.input.tx_hash = "zz".to_string();
    let err = phase_2_utxo(utxo).unwrap_err();
    assert!(err.contains("Invalid tx hash"), "{}", err);

    let mut utxo = good.clone();
    utxo.output.address = "addr1notanaddress".to_string();
    let err = phase_2_utxo(utxo).unwrap_err();
    assert!(err.contains("Invalid address"), "{}", err);

    let mut utxo = good.clone();
    utxo.output.amount[0].quantity = "many".to_string();
    let err = phase_2_utxo(utxo).unwrap_err();
    assert!(err.contains("Invalid quantity 'many'"), "{}", err);

    let mut utxo = good.clone();
    utxo.output.plutus_data = Some("85e9".to_string());
    let err = phase_2_utxo(utxo).unwrap_err();
    assert!(
        err.contains("Invalid plutus data") && err.contains("Malformed CBOR"),
        "{}",
        err
    );

    let mut utxo = good;
    utxo.output
        .amount
        .push(asset("lovelace", "1"));
    utxo.output
        .amount
        .push(asset(&format!("{}{}", "ab".repeat(28), "zz"), "1"));
    let err = phase_2_utxo(utxo).unwrap_err();
    assert!(err.contains("Invalid asset name"), "{}", err);
}

#[test]
fn short_asset_units_render_without_slicing() {
    let value = Value::new_from_common_assets(&vec![
        asset("lovelace", "1"),
        asset("ab", "2"),
        asset("é", "3"),
    ])
    .expect("phase 1 values take any integer quantity");
    let rendered = value.to_string();
    assert!(rendered.contains("\"policy_id\":\"ab\""), "{}", rendered);
    assert!(rendered.contains("\"policy_id\":\"é\""), "{}", rendered);
    let full = format!("{}{}", "ab".repeat(28), "0102");
    let value = Value::new_from_common_assets(&vec![asset(&full, "2")]).unwrap();
    let rendered = value.to_string();
    assert!(
        rendered.contains(&format!("\"policy_id\":\"{}\"", "ab".repeat(28))),
        "{}",
        rendered
    );
    assert!(rendered.contains("\"asset_name\":\"0102\""), "{}", rendered);
}

/// `[body, {}, true, null]` with `body_hex` as the body.
fn transaction_with_body(body_hex: &str) -> String {
    format!("84{body_hex}a0f5f6")
}

/// A transaction whose body holds a byte string of length zero where CSL
/// reads an address is refused by every entry point that parses it: an
/// output address in both output forms, a withdrawal key, a pool
/// registration's reward account, a proposal's reward account and a
/// treasury withdrawal key.
#[test]
fn transaction_entry_points_refuse_an_empty_embedded_address() {
    let bodies = [
        // outputs: `[h'', 0]` and `{0: h'', 1: 0}`
        "a3008001818240000200",
        "a300800181a20040010002 00",
        // collateral return
        "a30080020010824000",
        // withdrawals `{h'': 0}`
        "a400800180020005a14000",
        // an indefinite-length address with no payload
        "a400800180020005a15fff00",
        // pool registration `[3, …, h'' at 6, …]` in a tagged set
        "a40080018002000 4d90102818a030000000000408080f6",
        // proposal `[0, h'', [5], anchor]`
        "a4008001800200 148184004081058261 6100",
        // treasury withdrawals action `[2, {h'': 0}, null]` inside a proposal
        "a4008001800200 148184004101 8302a14000f6 826161 00",
    ];
    for body in bodies {
        let body = body.replace(' ', "");
        let tx_hex = transaction_with_body(&body);
        let expect = |err: String| {
            assert!(
                err.contains("Malformed address") && err.contains("empty byte string"),
                "{}: {}",
                body,
                err
            );
        };

        expect(
            validate_transaction(&tx_hex, preview_simple_context())
                .err()
                .expect("an empty embedded address is an error")
                .to_string(),
        );
        expect(get_necessary_data_list(&tx_hex, NetworkType::Preview).unwrap_err());
        expect(extract_hashes_from_transaction(&tx_hex).unwrap_err());
        expect(check_tx_signatures(&tx_hex).unwrap_err());
        // The combined entry point names both reasons it could not parse.
        expect(check_block_or_tx_signatures(&tx_hex).unwrap_err().to_string());
        let block_hex = format!("85a081{body}80a080");
        expect(check_block_or_tx_signatures(&block_hex).unwrap_err().to_string());
        expect(add_witnesses_to_tx(&tx_hex, vec![]).unwrap_err().to_string());
        expect(
            add_vkey_witnesses_to_tx(&tx_hex, vec![])
                .unwrap_err()
                .to_string(),
        );
        expect(add_witness_set_to_tx(&tx_hex, "a0").unwrap_err().to_string());
    }
}

/// The exports that read a transaction with pallas alone, never CSL:
/// `get_utxo_list_from_tx`, `get_ref_script_bytes` (output 0) and
/// `execute_tx_scripts` (the UTxO `11…11#0` it may spend, no cost models).
fn pallas_exports(tx_hex: &str) -> [Result<(), String>; 3] {
    let mut spent: UTxO =
        serde_json::from_str(crate::validators::tests::fixtures::PREVIEW_SIMPLE_INPUT_UTXO)
            .unwrap();
    spent.input.tx_hash = "11".repeat(32);
    spent.input.output_index = 0;
    let utxos = serde_json::to_string(&[spent]).unwrap();
    [
        crate::plutus::execute_tx_scripts::get_utxo_list_from_tx(tx_hex)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        crate::tx_utils::get_ref_script_bytes(tx_hex, 0)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        crate::plutus::execute_tx_scripts::execute_tx_scripts(
            tx_hex,
            crate::js_value::JsValue::new(&utxos),
            crate::js_value::JsValue::new("{}"),
        )
        .map(|_| ())
        .map_err(|e| e.to_string()),
    ]
}

/// Run `f` on a thread whose stack holds pallas' recursion at its bound in
/// an unoptimised build (the bound is calibrated on the shipped wasm; the
/// stack calibration tests hold the native build to its budget).
fn on_a_large_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(f)
        .expect("a thread starts")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

/// The pallas-backed exports refuse a transaction nested past
/// `MAX_PALLAS_NESTING_DEPTH`, and read one nested exactly to it.
#[test]
fn pallas_exports_refuse_nesting_past_their_own_bound() {
    on_a_large_stack(pallas_exports_refuse_nesting_past_their_own_bound_body);
}

fn pallas_exports_refuse_nesting_past_their_own_bound_body() {
    let bound = crate::cbor::limits::MAX_PALLAS_NESTING_DEPTH;
    for (datum_depth, refused) in [(bound - 3, false), (bound - 2, true)] {
        let datum = format!("{}00", "81".repeat(datum_depth));
        let tx_hex = format!("84a3008001800200a10481{datum}f5f6");
        for result in pallas_exports(&tx_hex) {
            match result {
                Err(err) if refused => assert!(
                    err.contains(&crate::cbor::limits::pallas_nesting_message(bound)),
                    "{}",
                    err
                ),
                Ok(()) if !refused => {}
                other => panic!("datum depth {}: {:?}", datum_depth, other),
            }
        }
    }
}

/// A transaction carrying a datum nested past the depth CSL's recursive
/// Plutus data reader is calibrated for is refused by every entry point
/// rather than walked on the host stack.
#[test]
fn transaction_entry_points_refuse_nesting_past_the_csl_bound() {
    on_a_large_stack(transaction_entry_points_refuse_nesting_past_the_csl_bound_body);
}

fn transaction_entry_points_refuse_nesting_past_the_csl_bound_body() {
    let bound = crate::cbor::limits::MAX_CSL_NESTING_DEPTH;
    for depth in [bound + 1, 2000] {
        let datum = format!("{}00", "81".repeat(depth));
        // `[body, {4: [datum]}, true, null]`
        let tx_hex = format!("84a3008001800200a10481{datum}f5f6");
        let expect = |err: String| {
            assert!(
                err.contains(&crate::cbor::limits::csl_nesting_message(bound)),
                "depth {}: {}",
                depth,
                err
            );
        };
        expect(
            validate_transaction(&tx_hex, preview_simple_context())
                .err()
                .expect("a datum past the nesting bound is an error")
                .to_string(),
        );
        expect(get_necessary_data_list(&tx_hex, NetworkType::Preview).unwrap_err());
        expect(extract_hashes_from_transaction(&tx_hex).unwrap_err());
        expect(check_tx_signatures(&tx_hex).unwrap_err());
        assert!(check_block_or_tx_signatures(&tx_hex).is_err());
        let block_hex = format!("85a08081a10481{datum}a080");
        assert!(check_block_or_tx_signatures(&block_hex).is_err());
        expect(add_witnesses_to_tx(&tx_hex, vec![]).unwrap_err().to_string());
        expect(
            add_witness_set_to_tx(PREVIEW_SIMPLE_TX_HEX, &format!("a10481{datum}"))
                .unwrap_err()
                .to_string(),
        );
        // As a free-form witness input it is not recognised as any witness.
        assert!(add_witnesses_to_tx(PREVIEW_SIMPLE_TX_HEX, vec![datum.clone()]).is_err());
        // The pallas-backed exports read it with pallas alone, whose bound
        // is its own: refused only past that (the array, the witness set
        // map and the datum list are three levels above the datum's).
        let pallas_bound = crate::cbor::limits::MAX_PALLAS_NESTING_DEPTH;
        for result in pallas_exports(&tx_hex) {
            if depth + 3 > pallas_bound {
                let err = result.expect_err("past the pallas bound");
                assert!(
                    err.contains(&crate::cbor::limits::pallas_nesting_message(pallas_bound)),
                    "depth {}: {}",
                    depth,
                    err
                );
            } else {
                result.unwrap_or_else(|e| panic!("depth {}: {}", depth, e));
            }
        }

        // The same datum as an inline datum or a script reference of a
        // context UTxO converted for CSL, and as a script reference to
        // normalise.
        let good: UTxO =
            serde_json::from_str(crate::validators::tests::fixtures::PREVIEW_SIMPLE_INPUT_UTXO)
                .unwrap();
        // The inline datum only pallas reads: refused past its own bound.
        let mut utxo = good.clone();
        utxo.output.plutus_data = Some(datum.clone());
        let read = phase_2_utxo(utxo);
        if depth > crate::cbor::limits::MAX_PALLAS_NESTING_DEPTH {
            let err = read.unwrap_err();
            assert!(err.contains("Invalid plutus data"), "{}", err);
            assert!(
                err.contains(&crate::cbor::limits::pallas_nesting_message(
                    crate::cbor::limits::MAX_PALLAS_NESTING_DEPTH
                )),
                "{}",
                err
            );
        } else {
            read.unwrap_or_else(|e| panic!("depth {}: {}", depth, e));
        }
        let mut utxo = good;
        utxo.output.script_ref = Some(datum.clone());
        expect(phase_2_utxo(utxo).unwrap_err());
        expect(normalize_script_ref(&datum).unwrap_err());
        expect(normalize_script_ref(&format!("82{datum}00")).unwrap_err());
    }
    // The bound counts the whole document: a datum that brings the
    // transaction (array, witness set map, datum list: three levels) to
    // exactly the bound is still parsed.
    let datum = format!("{}00", "81".repeat(bound - 3));
    let tx_hex = format!("84a3008001800200a10481{datum}f5f6");
    if let Err(err) = get_necessary_data_list(&tx_hex, NetworkType::Preview) {
        assert!(!err.contains("supported limit"), "{}", err);
    }
    assert!(extract_hashes_from_transaction(&tx_hex).is_ok());
}

/// `{0: address, 1: 2000000, 2: [1, #6.24(bytes)]}`: an output carrying
/// `payload` as its inline datum.
fn output_with_inline_datum(payload: &[u8]) -> String {
    format!(
        "a300581d61{}011a001e848002820 1d8185a{:08x}{}",
        "ab".repeat(28),
        payload.len(),
        hex::encode(payload)
    )
    .replace(' ', "")
}

/// `{0: address, 1: 2000000, 3: #6.24(bytes)}`: an output carrying
/// `payload` as its script reference.
fn output_with_script_ref(payload: &[u8]) -> String {
    format!(
        "a300581d61{}011a001e848003d8185a{:08x}{}",
        "ab".repeat(28),
        payload.len(),
        hex::encode(payload)
    )
}

/// `n` constructors, each holding the next: `121([121([… 0])])`, 2n levels.
fn nested_constr(n: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(3 * n + 1);
    for _ in 0..n {
        bytes.extend_from_slice(&[0xd8, 0x79, 0x81]);
    }
    bytes.push(0x00);
    bytes
}

/// `n` `script_all` native scripts, each holding the next, around a
/// `script_pubkey`: `[1, [[1, [ … [0, h'…']]]]]`, 2n + 1 levels.
fn nested_native_script(n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..n {
        bytes.extend_from_slice(&[0x82, 0x01, 0x81]);
    }
    bytes.extend_from_slice(&hex::decode(format!("8200581c{}", "cd".repeat(28))).unwrap());
    bytes
}

/// A small transaction whose inline datum or script reference nests past
/// the bound only inside its tag-24 byte string (the document around it is
/// a few levels deep) is refused by every entry point that parses it: CSL
/// and pallas parse those payloads while reading the transaction, on the
/// same stack.
#[test]
fn transaction_entry_points_refuse_nesting_past_the_csl_bound_inside_embedded_cbor() {
    on_a_large_stack(embedded_cbor_body);
}

fn embedded_cbor_body() {
    let bound = crate::cbor::limits::MAX_CSL_NESTING_DEPTH;
    // (output, whether it nests past the pallas bound too)
    let outputs = [
        (output_with_inline_datum(&nested_constr(1100)), true),
        (output_with_inline_datum(&nested_constr(bound / 2)), true),
    ];
    let pallas_bound = crate::cbor::limits::MAX_PALLAS_NESTING_DEPTH;
    for (output, past_pallas) in outputs {
        // `[{0: [input], 1: [output], 2: 0}, {}, true, null]`
        let body = format!("a3008182582011{}0001 81{output}0200", "11".repeat(31)).replace(' ', "");
        let tx_hex = transaction_with_body(&body);
        assert!(tx_hex.len() / 2 < 16_384, "a small transaction");
        let expect = |err: String| {
            assert!(
                err.contains(&crate::cbor::limits::csl_nesting_message(bound)),
                "{}",
                err
            );
        };
        expect(
            validate_transaction(&tx_hex, preview_simple_context())
                .err()
                .expect("an embedded payload past the nesting bound is an error")
                .to_string(),
        );
        expect(get_necessary_data_list(&tx_hex, NetworkType::Preview).unwrap_err());
        expect(extract_hashes_from_transaction(&tx_hex).unwrap_err());
        expect(check_tx_signatures(&tx_hex).unwrap_err());
        assert!(check_block_or_tx_signatures(&tx_hex).is_err());
        expect(add_witnesses_to_tx(&tx_hex, vec![]).unwrap_err().to_string());
        expect(add_vkey_witnesses_to_tx(&tx_hex, vec![]).unwrap_err().to_string());
        expect(add_witness_set_to_tx(&tx_hex, "a0").unwrap_err().to_string());
        // pallas alone reads it to its own bound.
        for result in pallas_exports(&tx_hex) {
            match result {
                Err(err) if past_pallas => assert!(
                    err.contains(&crate::cbor::limits::pallas_nesting_message(pallas_bound)),
                    "{}",
                    err
                ),
                Ok(()) if !past_pallas => {}
                other => panic!("{}: {:?}", output, other),
            }
        }
        // The output alone, as a typed decoder input.
        let output_hex = &body[body.find("81a3").unwrap() + 2..body.len() - 4];
        let output_bytes = hex::decode(output_hex).unwrap();
        for shape in [
            crate::csl_preflight::CslShape::Item,
            crate::csl_preflight::CslShape::TransactionOutput,
        ] {
            assert!(crate::csl_preflight::nests_past_csl(&output_bytes, shape));
        }
    }

    // A native script in a script reference is read without recursion by
    // every reader: its levels do not count, whatever the depth.
    for levels in [bound / 2, 1265, 5430] {
        let mut script_ref = vec![0x82, 0x00];
        script_ref.extend_from_slice(&nested_native_script(levels));
        let output = output_with_script_ref(&script_ref);
        let body = format!("a3008182582011{}000181{output}0200", "11".repeat(31));
        let tx_hex = transaction_with_body(&body);
        let not_nesting = |what: &str, result: Result<(), String>| {
            if let Err(err) = result {
                assert!(!err.contains("supported limit"), "{} at {}: {}", what, levels, err);
            }
        };
        not_nesting(
            "validate",
            validate_transaction(&tx_hex, preview_simple_context())
                .map(|_| ())
                .map_err(|e| e.to_string()),
        );
        not_nesting(
            "necessary data",
            get_necessary_data_list(&tx_hex, NetworkType::Preview).map(|_| ()),
        );
        assert!(extract_hashes_from_transaction(&tx_hex).is_ok());
        not_nesting("signatures", check_tx_signatures(&tx_hex).map(|_| ()));
        for result in pallas_exports(&tx_hex) {
            not_nesting("pallas", result);
        }
        let output_bytes = hex::decode(&output).unwrap();
        assert!(!crate::csl_preflight::nests_past_csl(
            &output_bytes,
            crate::csl_preflight::CslShape::TransactionOutput
        ));
        assert!(crate::csl_preflight::nests_past_csl(
            &output_bytes,
            crate::csl_preflight::CslShape::Item
        ));
    }

    // Within the bound, counted from the embedding site, the same shapes parse.
    let within = output_with_inline_datum(&nested_constr(bound / 2 - 8));
    let body = format!("a3008182582011{}000181{within}0200", "11".repeat(31));
    let tx_hex = transaction_with_body(&body);
    assert!(extract_hashes_from_transaction(&tx_hex).is_ok());
    assert!(crate::plutus::execute_tx_scripts::get_utxo_list_from_tx(&tx_hex).is_ok());
}

/// The same payloads as a validation-context UTxO's inline datum or `d818…`
/// script reference are never handed to pallas or CSL past their bounds,
/// and do not make the validation as a whole fail: they are an
/// implementation limit about one UTxO, not a verdict about the
/// transaction. The UTxO readers themselves still refuse them by name.
#[test]
fn validation_context_payloads_nested_past_the_csl_bound_are_refused() {
    on_a_large_stack(validation_context_payloads_body);
}

fn validation_context_payloads_body() {
    let bound = crate::cbor::limits::MAX_CSL_NESTING_DEPTH;
    let pallas_bound = crate::cbor::limits::MAX_PALLAS_NESTING_DEPTH;
    let good: UTxO =
        serde_json::from_str(crate::validators::tests::fixtures::PREVIEW_SIMPLE_INPUT_UTXO)
            .unwrap();
    let expect = |err: String| {
        assert!(
            err.contains(&crate::cbor::limits::csl_nesting_message(bound)),
            "{}",
            err
        );
    };
    let expect_pallas = |err: String| {
        assert!(
            err.contains(&crate::cbor::limits::pallas_nesting_message(pallas_bound)),
            "{}",
            err
        );
    };

    // A 5000-level inline datum: pallas overflowed the stack on it.
    let deep = format!("{}00", "81".repeat(5000));
    let mut utxo = good.clone();
    utxo.output.plutus_data = Some(deep.clone());
    expect_pallas(phase_2_utxo(utxo).unwrap_err());
    // The validation reads the rest: this transaction runs no script, so
    // the datum is simply not needed.
    let mut context = preview_simple_context();
    context.utxo_set[0].utxo.output.plutus_data = Some(deep.clone());
    let result = validate_transaction(PREVIEW_SIMPLE_TX_HEX, context)
        .unwrap_or_else(|e| panic!("a context datum past the bound fails nothing: {}", e));
    assert!(result.phase2_errors.is_empty());
    // Within pallas' bound, the datum is read.
    let mut context = preview_simple_context();
    context.utxo_set[0].utxo.output.plutus_data =
        Some(format!("{}00", "81".repeat(pallas_bound)));
    validate_transaction(PREVIEW_SIMPLE_TX_HEX, context)
        .unwrap_or_else(|e| panic!("a datum within the pallas bound is read: {}", e));
    // A UTxO the transaction does not spend or reference enters no script
    // context, so its datum refuses nothing.
    let mut context = preview_simple_context();
    let mut unrelated = context.utxo_set[0].clone();
    unrelated.utxo.input.output_index += 7;
    unrelated.utxo.output.plutus_data = Some(deep);
    context.utxo_set.push(unrelated);
    validate_transaction(PREVIEW_SIMPLE_TX_HEX, context)
        .unwrap_or_else(|e| panic!("an unrelated UTxO's datum is not read: {}", e));

    // A script reference in its tag-24 form whose native script nests past
    // the CSL bound only inside the byte string: native scripts do not
    // count toward it, so it is read.
    let _ = expect;
    let wrapped_script = |levels: usize| {
        let mut script = vec![0x82, 0x00];
        script.extend_from_slice(&nested_native_script(levels));
        format!("d8185a{:08x}{}", script.len(), hex::encode(&script))
    };
    let wrapped = wrapped_script(bound);
    normalize_script_ref(&wrapped).expect("a deep native script reference is read");
    let mut utxo = good.clone();
    utxo.output.script_ref = Some(wrapped);
    phase_2_utxo(utxo).expect("a deep native script reference is read");
    // Past the walkers' bound (tag, byte string, `[0, script]`, two
    // levels a script) it is refused by that bound.
    let walkers = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
    let past = wrapped_script((walkers - 3) / 2 + 1);
    let expect_walkers = |err: String| {
        assert!(
            err.contains(&crate::cbor::limits::nesting_depth_message(walkers)),
            "{}",
            err
        );
    };
    expect_walkers(normalize_script_ref(&past).unwrap_err());
    let mut utxo = good;
    utxo.output.script_ref = Some(past);
    expect_walkers(phase_2_utxo(utxo).unwrap_err());

    // The execution export's own UTxO reader applies the pallas gate.
    let mut utxo: UTxO =
        serde_json::from_str(crate::validators::tests::fixtures::PREVIEW_SIMPLE_INPUT_UTXO)
            .unwrap();
    utxo.output.plutus_data = Some(format!("{}00", "81".repeat(5000)));
    expect_pallas(
        crate::plutus::data_mapper::to_pallas_utxos(&[utxo])
            .unwrap_err()
            .to_string(),
    );
}

/// A spent UTxO locked by a native script whose only copy is the UTxO's
/// own script reference, nested past the bound: the script counts as
/// provided (its hash is read from the bytes, as the ledger hashes it),
/// is reported not examined, and the rest of the transaction validates.
#[test]
fn a_context_script_reference_past_the_bound_is_a_warning_not_a_failure() {
    on_a_large_stack(a_context_script_reference_past_the_bound_body);
}

fn a_context_script_reference_past_the_bound_body() {
    use crate::validators::phase_1::errors::{Phase1Error, Phase1Warning};
    use cardano_serialization_lib as csl;
    // Past the walkers' bound: tag, byte string, `[0, script]`, two
    // levels a script.
    let walkers = crate::cbor::limits::MAX_CBOR_NESTING_DEPTH;
    let levels = (walkers - 3) / 2 + 1;
    let native = nested_native_script(levels);
    let mut script = vec![0x82, 0x00];
    script.extend_from_slice(&native);
    let wrapped = format!("d8185a{:08x}{}", script.len(), hex::encode(&script));

    let unexamined = crate::validators::helpers::unexamined_script_ref(&wrapped)
        .expect("the reference nests past the bound");
    // The hash the ledger computes: over the script's bytes as written.
    let mut tagged = vec![0x00];
    tagged.extend_from_slice(&native);
    assert_eq!(
        unexamined.script_hash.to_bytes(),
        cryptoxide::hashing::blake2b_224(&tagged).to_vec()
    );
    assert_eq!(unexamined.size, native.len() as u64);
    assert_eq!(
        crate::validators::helpers::reference_script_size(&wrapped).unwrap(),
        native.len() as u64
    );
    // Within the bound nothing is left unexamined, however deep the script
    // nests past the serialization library's bound.
    for within in [8, crate::cbor::limits::MAX_CSL_NESTING_DEPTH, 5430] {
        let mut shallow = vec![0x82, 0x00];
        shallow.extend_from_slice(&nested_native_script(within));
        assert!(crate::validators::helpers::unexamined_script_ref(&hex::encode(&shallow)).is_none());
    }

    let credential = csl::Credential::from_scripthash(&unexamined.script_hash);
    let address = csl::EnterpriseAddress::new(0, &credential)
        .to_address()
        .to_bech32(None)
        .unwrap();
    let mut context = preview_simple_context();
    context.utxo_set[0].utxo.output.address = address;
    context.utxo_set[0].utxo.output.script_ref = Some(wrapped);

    let result = validate_transaction(PREVIEW_SIMPLE_TX_HEX, context)
        .unwrap_or_else(|e| panic!("a deep context script reference fails nothing: {}", e));
    let hash = unexamined.script_hash.to_hex();
    assert!(
        result.warnings.iter().any(|w| matches!(
            &w.warning,
            Phase1Warning::NativeScriptNotExamined { script_hash, reason }
                if *script_hash == hash
                    && reason.contains(&crate::cbor::limits::nesting_depth_message(walkers))
        )),
        "{:?}",
        result.warnings
    );
    assert!(
        !result.errors.iter().any(|e| matches!(
            &e.error,
            Phase1Error::MissingScriptWitnesses { .. }
        )),
        "{:?}",
        result.errors
    );
}

/// [`PREVIEW_SIMPLE_TX_HEX`] with one more body entry (`key` then `value`,
/// hex).
fn with_body_entry(key: &str, value: &str) -> String {
    let tx = cardano_serialization_lib::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap();
    let mut body = tx.raw_body();
    assert_eq!(body[0], 0xa4);
    body[0] = 0xa5;
    format!(
        "84{}{}{}{}f5{}",
        hex::encode(&body),
        key,
        value,
        hex::encode(tx.raw_witness_set()),
        hex::encode(tx.raw_auxiliary_data().unwrap())
    )
}

/// A parameter change proposal whose protocol parameter update sets the
/// cost models `cost_models` (hex).
fn cost_model_proposal(cost_models: &str) -> String {
    with_body_entry(
        "14",
        &format!(
            "81841a000f4240581de1{}8400f6a112{}f68269{}5820{}",
            "ab".repeat(28),
            cost_models,
            hex::encode("https://x"),
            "ab".repeat(32)
        ),
    )
}

/// The ledger accepts a cost model of a language it does not know yet; the
/// transaction reader does not, and the refusal says so by name instead of
/// CSL's `No variant matched`. Only the validator's refusal says what the
/// transaction cannot be (validated) and what still runs it.
#[test]
fn a_cost_model_of_an_unknown_language_is_refused_by_name() {
    const REFUSED: &str = "knows only languages 0-2 (PlutusV1-V3) and refuses the transaction";
    const NOT_VALIDATED: &str =
        "so it cannot be validated here (executeTxScripts still runs its scripts)";
    for (cost_models, language) in [("a1038107", 3), ("a2008105098107", 9)] {
        let tx_hex = cost_model_proposal(cost_models);
        let err = validate_transaction(&tx_hex, preview_simple_context())
            .err()
            .expect("CSL cannot read the transaction")
            .to_string();
        let named = format!(
            "Failed to parse transaction: the parameter change of proposal 0 carries a cost model for language {};",
            language
        );
        assert!(err.contains(&named), "{}", err);
        assert!(
            err.contains(REFUSED) && err.contains(NOT_VALIDATED),
            "{}",
            err
        );
        // The readers that do not validate: named, without the validator's clause.
        let named = format!("carries a cost model for language {};", language);
        let readers = [
            (
                "get_necessary_data_list",
                get_necessary_data_list(&tx_hex, NetworkType::Preview).unwrap_err(),
            ),
            (
                "check_tx_signatures",
                check_tx_signatures(&tx_hex).unwrap_err(),
            ),
            (
                "extract_hashes_from_transaction",
                extract_hashes_from_transaction(&tx_hex).unwrap_err(),
            ),
            (
                "add_witnesses_to_tx",
                add_witnesses_to_tx(&tx_hex, vec![])
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "add_vkey_witnesses_to_tx",
                add_vkey_witnesses_to_tx(&tx_hex, vec![])
                    .unwrap_err()
                    .to_string(),
            ),
            (
                "add_witness_set_to_tx",
                add_witness_set_to_tx(&tx_hex, "a0")
                    .unwrap_err()
                    .to_string(),
            ),
        ];
        for (reader, err) in readers {
            assert!(
                err.contains(&named) && err.contains(REFUSED),
                "{}: {}",
                reader,
                err
            );
            assert!(
                !err.contains("validated") && !err.contains("executeTxScripts"),
                "{}: {}",
                reader,
                err
            );
        }
    }
    // The pre-Conway update route (body key 6).
    let update = with_body_entry("06", &format!("82a1581c{}a112a109810700", "cd".repeat(28)));
    let err = get_necessary_data_list(&update, NetworkType::Preview).unwrap_err();
    assert!(
        err.contains(
            "the protocol parameter update (body key 6) carries a cost model for language 9"
        ),
        "{}",
        err
    );
    // Known languages parse.
    assert!(
        get_necessary_data_list(&cost_model_proposal("a2008105028107"), NetworkType::Preview)
            .is_ok()
    );
}
