//! Transactions whose script context the evaluator would panic building
//! (a wasm trap that loses the whole report) are answered with a phase-2
//! error for each redeemer instead, and phase 1's report comes back with
//! them: an output address the context cannot read, a Byron output, a
//! zero token quantity or a policy with no tokens in an array-form output,
//! a reward account that is not a stake address, a rational number with
//! denominator 0 in a proposal, a Conway certificate or body field next to
//! a PlutusV1/V2 script, and an inline datum on an output next to a
//! PlutusV1 script. `execute_tx_scripts`, which no CSL decoding guards,
//! answers the same content per redeemer.

use cardano_serialization_lib as csl;
use std::convert::TryInto;

use crate::common::{Asset, TxInput, TxOutput, UTxO};
use crate::js_value::JsValue;
use crate::validators::input_contexts::UtxoInputContext;
use crate::validators::phase_2::errors::Phase2Error;
use crate::validators::tests::fixtures::{default_cost_models, preview_simple_context};
use crate::validators::validator::validate_transaction;

/// A PlutusV1/V2 program that accepts any datum, redeemer and context, as
/// the witness set carries it (the flat program in one byte string).
const ALWAYS_SUCCEEDS: &str = "4d01000033222220051200120011";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Version {
    V1,
    V2,
    V3,
}

/// The script as the witness set carries it: for V1/V2 [`ALWAYS_SUCCEEDS`],
/// for V3 `(lam ctx (con unit ()))`, which returns unit whatever the context.
fn script_hex(version: Version) -> String {
    match version {
        Version::V1 | Version::V2 => ALWAYS_SUCCEEDS.to_string(),
        Version::V3 => {
            let program = uplc::parser::program("(program 1.1.0 (lam ctx (con unit ())))")
                .expect("the program parses");
            let program: uplc::ast::Program<uplc::ast::DeBruijn> =
                program.try_into().expect("the program is closed");
            hex::encode(program.to_cbor().expect("the program encodes"))
        }
    }
}

fn script(version: Version) -> csl::PlutusScript {
    let bytes = hex::decode(script_hex(version)).unwrap();
    match version {
        Version::V1 => csl::PlutusScript::new(bytes),
        Version::V2 => csl::PlutusScript::new_v2(bytes),
        Version::V3 => csl::PlutusScript::new_v3(bytes),
    }
}

fn script_address(version: Version) -> String {
    let credential = csl::Credential::from_scripthash(&script(version).hash());
    csl::EnterpriseAddress::new(0, &credential)
        .to_address()
        .to_bech32(None)
        .unwrap()
}

/// The spent UTxO `11…11#0`, locked by the script: an inline datum for
/// V2, the hash of the witnessed datum `0` for V1.
fn script_utxo(version: Version) -> UtxoInputContext {
    let datum = csl::PlutusData::new_integer(&csl::BigInt::from(0));
    UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: "11".repeat(32),
                output_index: 0,
            },
            output: TxOutput {
                address: script_address(version),
                amount: vec![Asset {
                    unit: "lovelace".to_string(),
                    quantity: "5000000".to_string(),
                }],
                data_hash: (version == Version::V1)
                    .then(|| hex::encode(csl::hash_plutus_data(&datum).to_bytes())),
                plutus_data: (version != Version::V1).then(|| "00".to_string()),
                script_ref: None,
                script_hash: None,
            },
        },
        is_spent: false,
    }
}

/// `[body, witnesses, true, null]` spending the script UTxO with one
/// redeemer, paying a valid output and then `extra_output` (hex), with
/// `extra_body` (hex map entries) appended to the body map.
fn transaction(version: Version, extra_output: Option<&str>, extra_body: &[&str]) -> String {
    transaction_with_redeemers(version, extra_output, extra_body, &[])
}

/// [`transaction`] with `extra_redeemers` (hex `[tag, index, data,
/// ex_units]` items) after the spend redeemer.
fn transaction_with_redeemers(
    version: Version,
    extra_output: Option<&str>,
    extra_body: &[&str],
    extra_redeemers: &[&str],
) -> String {
    let valid_output = format!("82581d61{}1a001e8480", "ab".repeat(28));
    let outputs = match extra_output {
        Some(extra) => format!("82{valid_output}{extra}"),
        None => format!("81{valid_output}"),
    };
    let collateral = format!(
        "818258{:02x}{}00",
        32, "16b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a"
    );
    let body = format!(
        "{:02x}00818258 20{}00 01{outputs} 021a00030d40 0d{collateral}{}",
        0xa0 + 4 + extra_body.len(),
        "11".repeat(32),
        extra_body.concat(),
    )
    .replace(' ', "");
    // Redeemer `[0, 0, 0, [mem, steps]]`; the script under key 3 (V1), 6
    // (V2) or 7 (V3).
    let redeemers = format!(
        "05{:02x}84000000821a000f42401a3b9aca00{}",
        0x81 + extra_redeemers.len(),
        extra_redeemers.concat()
    );
    let script_key = match version {
        Version::V1 => "03",
        Version::V2 => "06",
        Version::V3 => "07",
    };
    let datums = if version == Version::V1 { "048100" } else { "" };
    let witness_count = if version == Version::V1 { 3 } else { 2 };
    let script = script_hex(version);
    let witnesses = format!(
        "{:02x}{datums}{redeemers}{script_key}8158{:02x}{script}",
        0xa0 + witness_count,
        script.len() / 2
    );
    format!("84{body}{witnesses}f5f6")
}

fn context(version: Version) -> crate::validators::input_contexts::ValidationInputContext {
    let mut context = preview_simple_context();
    context.utxo_set.push(script_utxo(version));
    context
}

/// The phase-2 errors of validating `tx_hex`; the report must also come
/// back with its phase-1 part and one evaluation result per redeemer.
fn phase_2_errors(tx_hex: &str, version: Version) -> Vec<Phase2Error> {
    let result = validate_transaction(tx_hex, context(version))
        .map_err(|e| e.to_string())
        .expect("the transaction is validated, not refused");
    assert_eq!(result.eval_redeemer_results.len(), 1);
    result.phase2_errors.into_iter().map(|e| e.error).collect()
}

fn legacy_output(address_hex: &str, value_hex: &str) -> String {
    format!("8258{:02x}{address_hex}{value_hex}", address_hex.len() / 2)
}

#[test]
fn a_valid_transaction_is_evaluated() {
    for version in [Version::V1, Version::V2] {
        let tx_hex = transaction(version, None, &[]);
        let errors = phase_2_errors(&tx_hex, version);
        assert!(
            !errors.iter().any(|e| matches!(
                e,
                Phase2Error::UnreadableOutput { .. }
                    | Phase2Error::ByronAddressNotAllowed
                    | Phase2Error::CertificateNotSupportedInPlutusV1V2 { .. }
                    | Phase2Error::FieldNotSupportedInPlutusV1V2 { .. }
                    | Phase2Error::InlineDatumNotAllowedForPlutusV1
            )),
            "{:?}",
            errors
        );
        let result = validate_transaction(&tx_hex, context(version))
            .map_err(|e| e.to_string())
            .unwrap();
        assert!(
            result.eval_redeemer_results[0].success,
            "{:?}",
            result.eval_redeemer_results
        );
    }
}

#[test]
fn outputs_the_context_cannot_be_built_from_are_a_phase_2_error() {
    let address = format!("61{}", "ab".repeat(28));
    let coin = "1a001e8480";
    let policy = "77".repeat(28);
    let cases = [
        // A script/script base address header with a 27-byte payload.
        (
            legacy_output(&format!("31{}", "01".repeat(27)), coin),
            "address",
        ),
        // A key/key base address cut short after the payment part.
        (
            legacy_output(&format!("01{}", "02".repeat(28)), coin),
            "address",
        ),
        // A pointer address whose pointer ends mid-varint.
        (
            legacy_output(&format!("41{}ff", "03".repeat(28)), coin),
            "address",
        ),
        // `[address, [coin, {policy: {}}]]`
        (
            legacy_output(&address, &format!("82{coin}a1581c{policy}a0")),
            "holds no tokens",
        ),
        // `[address, [coin, {policy: {h'41': 0}}]]`
        (
            legacy_output(&address, &format!("82{coin}a1581c{policy}a1414100")),
            "quantity 0",
        ),
        // The map form with an unreadable address.
        (
            format!("a2005819{}01{coin}", format!("31{}", "01".repeat(24))),
            "address",
        ),
    ];
    for (output, reason_part) in cases {
        let tx_hex = transaction(Version::V2, Some(&output), &[]);
        let errors = phase_2_errors(&tx_hex, Version::V2);
        assert!(
            errors.iter().any(|e| matches!(
                e,
                Phase2Error::UnreadableOutput { output_index: 1, reason } if reason.contains(reason_part)
            )),
            "{}: {:?}",
            output,
            errors
        );
    }

    // A Byron output address: the ledger's ByronTxOutInContext. Well-formed
    // Byron bytes and Byron-headed garbage alike.
    let key = csl::Bip32PrivateKey::from_bip39_entropy(&[7u8; 16], &[]).to_public();
    let byron = hex::encode(
        csl::ByronAddress::icarus_from_key(&key, 1)
            .to_address()
            .to_bytes(),
    );
    for address in [byron.as_str(), "80010203"] {
        let tx_hex = transaction(Version::V2, Some(&legacy_output(address, coin)), &[]);
        let errors = phase_2_errors(&tx_hex, Version::V2);
        assert!(
            errors.iter().any(|e| matches!(
                e,
                Phase2Error::ByronAddressNotAllowed
                    | Phase2Error::UnreadableOutput {
                        output_index: 1,
                        ..
                    }
            )),
            "{}: {:?}",
            address,
            errors
        );
    }
    let tx_hex = transaction(Version::V2, Some(&legacy_output(&byron, coin)), &[]);
    assert!(phase_2_errors(&tx_hex, Version::V2)
        .iter()
        .any(|e| matches!(e, Phase2Error::ByronAddressNotAllowed)));
}

/// `[kind, …]` certificates of every Conway kind, with key credentials.
fn certificate(kind: u8) -> String {
    let cred = |c: &str| format!("8200581c{}", c.repeat(28));
    let pool = format!("581c{}", "55".repeat(28));
    let abstain = "8102";
    let coin = "1a001e8480";
    match kind {
        0 => format!("8200{}", cred("cd")),
        7 => format!("8307{}{coin}", cred("cd")),
        8 => format!("8308{}{coin}", cred("cd")),
        9 => format!("8309{}{abstain}", cred("cd")),
        10 => format!("840a{}{pool}{abstain}", cred("cd")),
        11 => format!("840b{}{pool}{coin}", cred("cd")),
        12 => format!("840c{}{abstain}{coin}", cred("cd")),
        13 => format!("850d{}{pool}{abstain}{coin}", cred("cd")),
        14 => format!("830e{}{}", cred("ce"), cred("cf")),
        15 => format!("830f{}f6", cred("ce")),
        16 => format!("8410{}{coin}f6", cred("ce")),
        17 => format!("8311{}{coin}", cred("ce")),
        18 => format!("8312{}f6", cred("ce")),
        _ => unreachable!(),
    }
}

#[test]
fn conway_certificates_next_to_a_plutus_v1_v2_script_are_a_phase_2_error() {
    for version in [Version::V1, Version::V2] {
        for kind in 9..=18u8 {
            let certs = format!("0481{}", certificate(kind));
            let tx_hex = transaction(version, None, &[&certs]);
            let errors = phase_2_errors(&tx_hex, version);
            assert!(
                errors.iter().any(|e| matches!(
                    e,
                    Phase2Error::CertificateNotSupportedInPlutusV1V2 {
                        certificate_index: 0,
                        ..
                    }
                )),
                "kind {}: {:?}",
                kind,
                errors
            );
        }
        // The pre-Conway kinds and the deposit-carrying registration and
        // deregistration translate.
        for kind in [0u8, 7, 8] {
            let certs = format!("0481{}", certificate(kind));
            let tx_hex = transaction(version, None, &[&certs]);
            let errors = phase_2_errors(&tx_hex, version);
            assert!(
                !errors
                    .iter()
                    .any(|e| matches!(e, Phase2Error::CertificateNotSupportedInPlutusV1V2 { .. })),
                "kind {}: {:?}",
                kind,
                errors
            );
        }
    }
}

#[test]
fn conway_body_fields_next_to_a_plutus_v1_v2_script_are_a_phase_2_error() {
    // Key 22: treasury donation; key 21: current treasury value.
    for (entry, field) in [
        ("161a000f4240", "treasury_donation"),
        ("151a000f4240", "current_treasury_value"),
    ] {
        let tx_hex = transaction(Version::V2, None, &[entry]);
        let errors = phase_2_errors(&tx_hex, Version::V2);
        assert!(
            errors.iter().any(|e| matches!(
                e,
                Phase2Error::FieldNotSupportedInPlutusV1V2 { field: f, .. } if f == field
            )),
            "{}: {:?}",
            field,
            errors
        );
    }
}

#[test]
fn an_inline_datum_on_an_output_next_to_a_plutus_v1_script_is_a_phase_2_error() {
    let output = format!("a300581d61{}011a001e8480028201d8184100", "ab".repeat(28));
    let tx_hex = transaction(Version::V1, Some(&output), &[]);
    let errors = phase_2_errors(&tx_hex, Version::V1);
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, Phase2Error::InlineDatumNotAllowedForPlutusV1)),
        "{:?}",
        errors
    );
    // PlutusV2 contexts carry inline datums.
    let tx_hex = transaction(Version::V2, Some(&output), &[]);
    let errors = phase_2_errors(&tx_hex, Version::V2);
    assert!(
        !errors
            .iter()
            .any(|e| matches!(e, Phase2Error::InlineDatumNotAllowedForPlutusV1)),
        "{:?}",
        errors
    );
}

/// The execution export answers the same content per redeemer too.
#[test]
fn execute_tx_scripts_reports_unbuildable_contexts_per_redeemer() {
    let output = legacy_output(&format!("31{}", "01".repeat(27)), "1a001e8480");
    let tx_hex = transaction(Version::V2, Some(&output), &[]);
    let utxos: Vec<UTxO> = context(Version::V2)
        .utxo_set
        .into_iter()
        .map(|u| u.utxo)
        .collect();
    let result = crate::plutus::execute_tx_scripts::execute_tx_scripts(
        &tx_hex,
        JsValue::new(&serde_json::to_string(&utxos).unwrap()),
        JsValue::new(&serde_json::to_string(&default_cost_models()).unwrap()),
    )
    .map_err(|e| e.to_string())
    .expect("the export answers");
    let json: serde_json::Value = serde_json::from_str(&result.as_string().unwrap()).unwrap();
    let error = json[0]["error"]
        .as_str()
        .expect("the redeemer carries an error");
    assert!(error.contains("Output 1 cannot be translated"), "{}", json);
}

/// The unspent outputs of [`context`], as `execute_tx_scripts` takes them.
fn context_utxos(version: Version) -> Vec<UTxO> {
    context(version).utxo_set.into_iter().map(|u| u.utxo).collect()
}

/// `execute_tx_scripts` on `tx_hex` against [`context`]: its per-redeemer
/// results.
fn execute(tx_hex: &str, version: Version) -> serde_json::Value {
    let result = crate::plutus::execute_tx_scripts::execute_tx_scripts(
        tx_hex,
        JsValue::new(&serde_json::to_string(&context_utxos(version)).unwrap()),
        JsValue::new(&serde_json::to_string(&default_cost_models()).unwrap()),
    )
    .map_err(|e| e.to_string())
    .expect("the export answers");
    serde_json::from_str(&result.as_string().unwrap()).unwrap()
}

/// `[deposit, return_account, action, anchor]`.
fn proposal(return_account: &str, action: &str) -> String {
    format!(
        "841a000f4240{}{action}8269{}5820{}",
        byte_string(return_account),
        hex::encode("https://x"),
        "ab".repeat(32)
    )
}

/// A byte string item holding `hex_bytes`.
fn byte_string(hex_bytes: &str) -> String {
    let len = hex_bytes.len() / 2;
    if len < 24 {
        format!("{:02x}{hex_bytes}", 0x40 + len)
    } else {
        format!("58{:02x}{hex_bytes}", len)
    }
}

#[test]
fn every_script_version_runs_on_the_test_transaction() {
    for version in [Version::V1, Version::V2, Version::V3] {
        let json = execute(&transaction(version, None, &[]), version);
        assert!(json[0]["error"].is_null(), "{}", json);
    }
}

/// A reward account that is not a stake address: the context builder reads
/// withdrawal keys, proposal return accounts and treasury withdrawal keys
/// with an `unwrap` (and orders withdrawals with an `unreachable!`), and
/// `execute_tx_scripts` has no CSL decoding in front of it to refuse them.
#[test]
fn reward_accounts_that_are_not_stake_addresses_are_a_phase_2_error() {
    let short = format!("e1{}", "ab".repeat(10));
    let base_a = format!("01{}", "ab".repeat(56));
    let base_b = format!("01{}", "cd".repeat(56));
    let stake = format!("e1{}", "ab".repeat(28));
    let cases = [
        (
            format!("05a1{}00", byte_string(&short)),
            "withdrawals[0]",
        ),
        (
            format!("05a2{}00{}00", byte_string(&base_a), byte_string(&base_b)),
            "withdrawals[0]",
        ),
        (
            format!("1481{}", proposal(&short, "8106")),
            "proposal_procedures[0].reward_account",
        ),
        (
            format!("1481{}", proposal(&"82".repeat(29), "8106")),
            "proposal_procedures[0].reward_account",
        ),
        (
            format!(
                "1481{}",
                proposal(&stake, &format!("8302a1{}05f6", byte_string(&short)))
            ),
            "proposal_procedures[0].gov_action.withdrawals[0]",
        ),
    ];
    for (entry, field) in cases {
        for version in [Version::V2, Version::V3] {
            let tx_hex = transaction(version, None, &[&entry]);
            let json = execute(&tx_hex, version);
            let error = json[0]["error"].as_str().unwrap_or_default();
            assert!(
                error.contains(&format!("The transaction's {} cannot be translated", field)),
                "{} under {}: {}",
                entry,
                script_hex(version),
                json
            );
        }
    }
}

/// A rational number `0/0` in a proposal: CSL reads it, and the V3 context
/// builder divides by the greatest common divisor of its parts. The ledger
/// refuses a zero denominator while decoding.
#[test]
fn a_rational_with_denominator_zero_in_a_proposal_is_a_phase_2_error() {
    let stake = format!("e1{}", "ab".repeat(28));
    let zero = "d81e820000";
    let cases = [
        // UpdateCommittee with quorum 0/0.
        (
            format!("8504f680a0{zero}"),
            "proposal_procedures[0].gov_action.quorum",
        ),
        // ParameterChange of the execution prices.
        (
            format!("8400f6a11382{zero}d81e820102f6"),
            "proposal_procedures[0].gov_action.parameter_update.execution_costs.mem_price",
        ),
        // ParameterChange of the pledge influence, denominator 0 alone.
        (
            "8400f6a109d81e820100f6".to_string(),
            "proposal_procedures[0].gov_action.parameter_update.pool_pledge_influence",
        ),
    ];
    for (action, field) in cases {
        let entry = format!("1481{}", proposal(&stake, &action));
        let tx_hex = transaction(Version::V3, None, &[&entry]);
        let json = execute(&tx_hex, Version::V3);
        let error = json[0]["error"].as_str().unwrap_or_default();
        assert!(
            error.contains(&format!("The transaction's {} cannot be translated", field)),
            "{}: {}",
            action,
            json
        );
        let errors = phase_2_errors(&tx_hex, Version::V3);
        assert!(
            errors.iter().any(|e| matches!(
                e,
                Phase2Error::UnreadableTransactionField { field: f, .. } if f == field
            )),
            "{}: {:?}",
            action,
            errors
        );
    }
}

/// A redeemer whose context is refused never ran: it carries its script and
/// version, zero calculated units, and no budget comparison.
#[test]
fn a_refused_redeemer_carries_its_script_and_no_budget_verdict() {
    let output = legacy_output(&format!("31{}", "01".repeat(27)), "1a001e8480");
    let tx_hex = transaction(Version::V2, Some(&output), &[]);
    let result = validate_transaction(&tx_hex, context(Version::V2))
        .map_err(|e| e.to_string())
        .expect("the transaction is validated");
    let eval = &result.eval_redeemer_results[0];
    assert!(!eval.success);
    assert_eq!(eval.plutus_version.as_deref(), Some("V2"));
    assert_eq!(eval.script_bytes.as_deref(), Some(ALWAYS_SUCCEEDS));
    assert_eq!((eval.calculated_ex_units.mem, eval.calculated_ex_units.steps), (0, 0));
    assert!(result.phase2_warnings.is_empty(), "{:?}", result.phase2_warnings);
    assert!(
        !result
            .phase2_errors
            .iter()
            .any(|e| matches!(e.error, Phase2Error::NoEnoughBudget { .. })),
        "{:?}",
        result.phase2_errors
    );

    // A script that ran under its budget still gets the warning.
    let tx_hex = transaction(Version::V2, None, &[]);
    let result = validate_transaction(&tx_hex, context(Version::V2))
        .map_err(|e| e.to_string())
        .unwrap();
    assert!(result.eval_redeemer_results[0].success);
    assert!(!result.phase2_warnings.is_empty());
}

/// The script's hash, as a proposal names its guardrail policy.
fn script_hash_hex(version: Version) -> String {
    hex::encode(script(version).hash().to_bytes())
}

/// `data` written out whole, whatever its definite or indefinite lengths:
/// integers in decimal, byte strings in hex, `Constr n [...]`, `[...]`
/// and `{k: v}`.
fn plain(data: &uplc::PlutusData) -> String {
    use uplc::{BigInt, PlutusData};
    let join = |items: Vec<String>| items.join(", ");
    match data {
        PlutusData::Constr(c) => format!(
            "Constr {} [{}]",
            c.constr_index(),
            join(c.fields.iter().map(plain).collect())
        ),
        PlutusData::Map(pairs) => format!(
            "{{{}}}",
            join(
                pairs
                    .iter()
                    .map(|(k, v)| format!("{}: {}", plain(k), plain(v)))
                    .collect()
            )
        ),
        PlutusData::Array(items) => format!("[{}]", join(items.iter().map(plain).collect())),
        PlutusData::BigInt(BigInt::Int(i)) => i128::from(i.0).to_string(),
        PlutusData::BigInt(other) => format!("{:?}", other),
        PlutusData::BoundedBytes(b) => format!("h'{}'", hex::encode(b.as_slice())),
    }
}

fn data_fields(data: &uplc::PlutusData) -> &[uplc::PlutusData] {
    match data {
        uplc::PlutusData::Constr(c) => &c.fields,
        other => panic!("not a constructor: {}", plain(other)),
    }
}

fn data_constr_index(data: &uplc::PlutusData) -> u64 {
    match data {
        uplc::PlutusData::Constr(c) => c.constr_index(),
        other => panic!("not a constructor: {}", plain(other)),
    }
}

/// The changed parameters of a `ProposalProcedure` holding a
/// `ParameterChange`: `Constr 0 [deposit, return, Constr 0 [prev, params, guardrail]]`.
fn changed_parameters(proposal: &uplc::PlutusData) -> String {
    let action = &data_fields(proposal)[2];
    assert_eq!(data_constr_index(action), 0, "{}", plain(action));
    plain(&data_fields(action)[1])
}

/// A parameter change of the cost models: uplc has no translation of
/// `ProtocolParamUpdate` key 18 (`unimplemented!`, a wasm trap), and a
/// PlutusV3 context carries every proposal, so no V3 script of such a
/// transaction could run, the guardrail script every such proposal runs
/// included. The ledger (`ToPlutusData CostModels`) writes the cost models
/// as a map from each language's key to its parameter list, in ascending
/// key order, at key 18 between keys 17 and 19 of the changed parameters.
#[test]
fn a_cost_model_update_reaches_plutus_v3_scripts_as_the_ledger_writes_it() {
    let stake = format!("e1{}", "ab".repeat(28));
    // {0: 44, 18: {2: [1, -2, 3], 0: [5]}, 22: 5000}, guarded by the script.
    let update = "a3 00182c 12a202830121030081 05 16191388".replace(' ', "");
    let action = format!("8400f6{update}581c{}", script_hash_hex(Version::V3));
    let entry = format!("1481{}", proposal(&stake, &action));
    // A Propose redeemer for proposal 0 after the spend redeemer.
    let propose = "84050000821a000f42401a3b9aca00";
    let tx_hex = transaction_with_redeemers(Version::V3, None, &[&entry], &[propose]);
    let expected = "{0: 44, 18: {0: [5], 2: [1, -2, 3]}, 22: 5000}";

    let result = validate_transaction(&tx_hex, context(Version::V3))
        .map_err(|e| e.to_string())
        .expect("the transaction is validated");
    assert_eq!(result.eval_redeemer_results.len(), 2);
    for eval in &result.eval_redeemer_results {
        assert!(eval.success, "{:?}", eval);
        let bytes = hex::decode(eval.script_context_bytes.as_ref().unwrap()).unwrap();
        let context = uplc::plutus_data(&bytes).unwrap();
        let [tx_info, _, script_info] = data_fields(&context) else {
            panic!("{}", plain(&context));
        };
        let tx_info = data_fields(tx_info);
        // txInfoProposalProcedures
        let uplc::PlutusData::Array(proposals) = &tx_info[13] else {
            panic!("{}", plain(&tx_info[13]));
        };
        assert_eq!(changed_parameters(&proposals[0]), expected);
        // txInfoRedeemers: the `Proposing 0 proposal` purpose.
        let uplc::PlutusData::Map(redeemers) = &tx_info[9] else {
            panic!("{}", plain(&tx_info[9]));
        };
        let proposing: Vec<_> = redeemers
            .iter()
            .filter(|(purpose, _)| data_constr_index(purpose) == 5)
            .collect();
        assert_eq!(proposing.len(), 1);
        assert_eq!(changed_parameters(&data_fields(&proposing[0].0)[1]), expected);
        // scriptContextScriptInfo of the Propose redeemer: `ProposingScript 0 proposal`.
        if data_constr_index(script_info) == 5 {
            assert_eq!(changed_parameters(&data_fields(script_info)[1]), expected);
        }
    }
    assert!(result
        .eval_redeemer_results
        .iter()
        .any(|eval| matches!(eval.tag, crate::validators::validation_result::RedeemerTag::Propose)));

    let json = execute(&tx_hex, Version::V3);
    assert_eq!(json.as_array().map(Vec::len), Some(2), "{}", json);
    for redeemer in json.as_array().unwrap() {
        assert!(redeemer["error"].is_null(), "{}", json);
        assert!(redeemer["calculated_ex_units"]["mem"].is_string(), "{}", json);
    }
}

/// A parameter change of the cost models as proposed on chain, guarded by
/// the constitution's guardrail script (PlutusV3, in the witness set).
const COST_MODEL_UPDATE_TX: &str = concat!(
    "84a800d901028282582099e4f95ed2fd4126e7b5b1e65b701a2b7b6c6636c1d51df3536dfd3af5d056f100825820f62c",
    "bd988004b98c3264ac07e7aa2e5e03ed5a57ece021e1d2eaf9ebf2bcca06010dd9010281825820f62cbd988004b98c32",
    "64ac07e7aa2e5e03ed5a57ece021e1d2eaf9ebf2bcca0601018182583901076ad93c90e7dafc2ad468212fb2e2701559",
    "d1d32f25ebdc1facdada611943783e94de22f533778841521e97f77588fe05447f464be192c91a0037b9bf1082583901",
    "076ad93c90e7dafc2ad468212fb2e2701559d1d32f25ebdc1facdada611943783e94de22f533778841521e97f77588fe",
    "05447f464be192c91a00344f61111a000a3f1a021a0006d4bc0b58202de07a4f20b398c859a036345442670b3eb54f06",
    "2b4002f65a1c5d244b9b2a7314d9010281841b000000174876e800581de1192688a334130db2b51aedea594301010b0d",
    "1d2e9a86a460932520ba8400825820c21b00f90f18fce4003edf42b0b0d455126e01c946e80cc5341a9f9750caf79500",
    "a112a3009f1a000189b41901a401011903e818ad00011903e819ea350401192baf18201a000312591920a404193e8018",
    "64193e801864193e801864193e801864193e801864193e80186418641864193e8018641a000170a718201a0002078218",
    "2019f016041a0001194a18b2000119568718201a0001643519030104021a00014f581a00037c71187a0001011903e819",
    "a7a9040219779f197053184b011a000db464196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a00",
    "0144ce1820193bc318201a0001291101193371041956540a197147184a01197147184a0119a9151902280119aecd1902",
    "1d0119843c18201a00010a9618201a00011aaa1820191c4b1820191cdf1820192d1a18201a00014f581a00037c71187a",
    "0001011a0001614219020700011a000122c118201a00014f581a00037c71187a0001011a00014f581a00037c71187a00",
    "01011a0004213c19583c041a00163cad19fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff",
    "182019e86a1820194eae182019600c1820195108182019654d182019602f18201a032e93af1937fd0a1a000e94721a00",
    "03414000021a0290f1e70a1a0298e40b1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be9801",
    "1a0321aac7190eac121a00041699121a048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e",
    "011a09f2f6d31910d318241a0004578218241a096e44021967b518241a0473cee818241a13e62472011a0f23d4011848",
    "1a00212c5618481a0022814619fc3b041a00032b00192076041a0013be0419702c183f00011a000f59d919aa6718fb00",
    "011a000187551902d61902cf00011a000187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a8",
    "00011a00017468011a00044a391949a000011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a",
    "0001a3e2190ce2011a00019e4919028f011a001df8bb195fc8031a000943b11a0003891119cf9800011a0001c7e71907",
    "a5041a000389cb0a1903e819610607011a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a818241a00",
    "05723c1947ed182d151a00035b2f1924e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce",
    "196e62011903e819950f02161903e81a000176bd01010b1903e81a00043c490c15ff019f1a000189b41901a401011903",
    "e818ad00011903e819ea350401192baf18201a000312591920a404193e801864193e801864193e801864193e80186419",
    "3e801864193e80186418641864193e8018641a000170a718201a00020782182019f016041a0001194a18b20001195687",
    "18201a0001643519030104021a00014f581a00037c71187a0001011903e819a7a9040219779f197053184b011a000db4",
    "64196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a000129110119",
    "3371041956540a197147184a01197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a0001",
    "1aaa1820191c4b1820191cdf1820192d1a18201a00014f581a00037c71187a0001011a0001614219020700011a000122",
    "c118201a00014f581a00037c71187a0001011a00014f581a00037c71187a0001011a000e94721a0003414000021a0004",
    "213c19583c041a00163cad19fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e86a",
    "1820194eae182019600c1820195108182019654d182019602f18201a0290f1e70a1a032e93af1937fd0a1a0298e40b19",
    "66c40a1a0013be0419702c183f00011a000f59d919aa6718fb0001193e801864193e8018641a000eaf1f121a002a6e06",
    "061a0006be98011a0321aac7190eac121a00041699121a048e466e1922a4121a0327ec9a121a001e743c18241a003141",
    "0f0c1a000dbf9e011a09f2f6d31910d318241a0004578218241a096e44021967b518241a0473cee818241a13e6247201",
    "1a0f23d40118481a00212c5618481a0022814619fc3b041a00032b00192076041a000187551902d61902cf00011a0001",
    "87551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a391949a000",
    "011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f01",
    "1a001df8bb195fc8031a000943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e819610607011a",
    "00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a818241a0005723c1947ed182d151a00035b2f1924e4",
    "011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f02161903e81a00",
    "0176bd01010b1903e81a00043c490c15ff029f1a000189b41901a401011903e818ad00011903e819ea350401192baf18",
    "201a000312591920a404193e801864193e801864193e801864193e801864193e801864193e80186418641864193e8018",
    "641a000170a718201a00020782182019f016041a0001194a18b2000119568718201a0001643519030104021a00014f58",
    "1a0001e143191c893903831906b41903c018391a00014f580001011903e819a7a9040219779f197053184b011a000db4",
    "64196a8f0119ca3f19022e011999101903e819ecb2011a00022a4718201a000144ce1820193bc318201a000129110119",
    "3371041956540a197147184a01197147184a0119a9151902280119aecd19021d0119843c18201a00010a9618201a0001",
    "1aaa1820191c4b1820191cdf1820192d1a18201a00014f581a0001e143191c893903831906b41903c018391a00014f58",
    "00011a0001614219020700011a000122c118201a00014f581a0001e143191c893903831906b41903c018391a00014f58",
    "0001011a00014f581a0001e143191c893903831906b41903c018391a00014f5800011a000e94721a0003414000021a00",
    "04213c19583c041a00163cad19fc3604194ff30104001a00022aa818201a000189b41901a401011a00013eff182019e8",
    "6a1820194eae182019600c1820195108182019654d182019602f18201a0290f1e70a1a032e93af1937fd0a1a0298e40b",
    "1966c40a193e801864193e8018641a000eaf1f121a002a6e06061a0006be98011a0321aac7190eac121a00041699121a",
    "048e466e1922a4121a0327ec9a121a001e743c18241a0031410f0c1a000dbf9e011a09f2f6d31910d318241a00045782",
    "18241a096e44021967b518241a0473cee818241a13e62472011a0f23d40118481a00212c5618481a0022814619fc3b04",
    "1a00032b00192076041a0013be0419702c183f00011a000f59d919aa6718fb00011a000187551902d61902cf00011a00",
    "0187551902d61902cf00011a000187551902d61902cf00011a0001a5661902a800011a00017468011a00044a391949a0",
    "00011a0002bfe2189f01011a00026b371922ee00011a00026e9219226d00011a0001a3e2190ce2011a00019e4919028f",
    "011a001df8bb195fc8031a000943b11a0003891119cf9800011a0001c7e71907a5041a000389cb0a1903e81961060701",
    "1a00038a4a18201a132ed9841a017eceb5121a24d436c71a0402f5a818241a0005723c1947ed182d151a00035b2f1924",
    "e4011903e81a0002a0541a0002cb6e061818151a000341231a00096fa11907ce196e62011903e819950f02161903e81a",
    "000176bd01010b1903e81a00043c490c15ff581cfa24fb305126805cf2164c161d852a0e7330cf988f1fe558cf7d4a64",
    "827842697066733a2f2f6261666b7265696534796b62626b36726a706971716a63716875626b33623279727a6776706e",
    "746d346f7a6f7078326f7370656e647566766879755820828cf92b170812446820c9f393446a2daf7d7e47d5f87354fe",
    "9f9e21a2635fb4a300d9010281825820b34db9badbd148ffdcc73259bad2bc5981a382e657a2b27c2bc014fc16387119",
    "584018be92848aa9d5fd6935d950391eebb9a86da98fd4f3957ded59b598b8e85abd938c5167486103327e4bfa304e31",
    "dbf23ddc097a4b8f7df4ae4d85cc26c1f90f07d901028159085459085101010032323232323232323232323232323232",
    "32323232323232323232323232323232323232323232323232259323255333573466e1d20000011180098111bab35742",
    "6ae88d55cf00104554ccd5cd19b87480100044600422c6aae74004dd51aba1357446ae88d55cf1baa3255333573466e1",
    "d200a35573a002226ae84d5d11aab9e00111637546ae84d5d11aba235573c6ea800642b26006003149a2c8a4c301f801",
    "c0052000c00e0070018016006901e4070c00e003000c00d20d00fc000c0003003800a4005801c00e003002c00d20c09a",
    "0c80e1801c006001801a4101b5881380018000600700148013003801c006005801a410100078001801c006001801a410",
    "1001f8001800060070014801b0038018096007001800600690404002600060001801c0052008c00e006025801c006001",
    "801a41209d8001800060070014802b003801c006005801a410112f501c3003800c00300348202b7881300030000c00e0",
    "0290066007003800c00b003482032ad7b806038403060070014803b00380180960003003800a4021801c00e003002c00",
    "d20f40380e1801c006001801a41403f800100a0c00e0029009600f0030078040c00e002900a600f003800c00b003301a",
    "483403e01a600700180060066034904801e00060001801c0052016c01e00600f801c006001801980c2402900e30000c0",
    "0e002901060070030128060c00e00290116007003800c00b003483c0ba03860070018006006906432e00040283003800",
    "a40498003003800a404d802c00e00f003800c00b003301a480cb0003003800c003003301a4802b00030001801c01e007",
    "0018016006603490605c0160006007001800600660349048276000600030000c00e0029014600b003801c00c04b00380",
    "0c00300348203a2489b00030001801c00e006025801c006001801a4101b11dc2df80018000c0003003800a4055802c00",
    "e007003012c00e003000c00d2080b8b872c000c0006007003801809600700180060069040607e4155016000600030000",
    "c00e00290166007003012c00e003000c00d2080c001c000c0003003800a405d801c00e003002c00d20c80180e1801c00",
    "6001801a412007800100a0c00e00290186007003013c0006007001480cb005801801e006003801800e00600500403003",
    "800a4069802c00c00f003001c00c007003803c00e003002c00c05300333023480692028c0004014c00c00b003003c00c",
    "00f003003c00e00f003800c00b00301480590052008003003800a406d801c00e003002c00d2000c00d2006c000600700",
    "18006006900a600060001801c0052038c00e007001801600690006006901260003003800c00300348328130002014180",
    "1c005203ac00e006027801c006001801a403d800180006007001480f3003801804e00700180060069040404af3c4e302",
    "600060001801c005203ec00e006013801c006001801a4101416f0fd20b80018000600700148103003801c006005801a4",
    "03501c3003800c0030034812b00030000c00e0029021600f003800c00a01ac00e003000c00ccc08d20d00f4800b00030",
    "000c0000000000803c00c016008401e006009801c006001801807e0060298000c000401e006007801c00600180180740",
    "20c000400e00f003800c00b003010c000802180020070018006006019801805e00030004006005801807600601380008",
    "00c00b00330134805200c400e00300080330004006005801a4001801a410112f58000801c00600901260008019806a40",
    "118002007001800600690404a75ee01e00060008018046000801801e000300c4832004c025201430094800a003002805",
    "2003002c00d2002c000300648010c0092002300748028c0312000300b48018c0292012300948008c0212066801a40018",
    "000c0192008300a2233335573e00250002801994004d55ce800cd55cf0008d5d08014c00cd5d10011263009222532900",
    "389800a4d2219002912c80344c01526910c80148964cc04cdd68010034564cc03801400626601800e007180122660180",
    "0e01518010096400a3000910c008600444002600244004a6646002002442464660044600444600400646004446002006",
    "46a660080080066a00600224446600644b20051800484ccc02600244666ae68cdc3801000c00200500a91199ab9a3371",
    "0004003000801488ccd5cd19b89002001800400a44666ae68cdc4801000c00a00122333573466e20008006005000912a",
    "999ab9a3371200400222002220052255333573466e2400800444008440040026eb400a42660080026eb000a426466601",
    "5001229002914801c8954ccd5cd19b8700400211333573466e1c00c006001002118011229002914801c88cc044cdc100",
    "200099b82002003245200522900391199ab9a3371066e08010004cdc1001001c002004403245200522900391199ab9a3",
    "371266e08010004cdc1001001c00a00048a400a45200722333573466e20cdc100200099b820020038014000912c99807",
    "001000c40062004912c99807001000c400a2002001199919ab9a357466ae880048cc028dd69aba1003375a6ae84008d5",
    "d1000934000dd60010a40064666ae68d5d1800c0020052225933006003357420031330050023574400318010600a444a",
    "a666ae68cdc3a400000222c22aa666ae68cdc4000a4000226600666e05200000233702900000088994004cdc2001800c",
    "cdc20010008cc010008004c01088954ccd5cd19b87480000044400844cc00c004cdc300100091119803112c800c60012",
    "219002911919806912c800c4c02401a442b26600a004019130040018c008002590028c804c8888888800d19009911111",
    "11002a244b267201722222222008001000c600518000001112a999ab9a3370e004002230001155333573466e24008004",
    "4600823002229002914801c88ccd5cd19b893370400800266e0800800e00100208c8c0040048c0088cc00800800505a1",
    "82050082a0821a00074dc91a063bad70f5f6",
);

/// The guardrail script runs on the cost-model proposal above and uses
/// exactly the units the transaction declares; with the cost models left
/// out of its context it would use fewer (79597332 steps, 349967 memory).
#[test]
fn the_guardrail_script_uses_the_declared_units_on_a_cost_model_update() {
    let utxos: Vec<UTxO> = [
        ("f62cbd988004b98c3264ac07e7aa2e5e03ed5a57ece021e1d2eaf9ebf2bcca06", 1, "addr1qyrk4kfujrna4lp2635zztajufcp2kw36vhjt67ur7kd4knpr9phs055mc302vmh3pq4y85h7a6c3ls9g3l5vjlpjtysqfydlq", "4099707"),
        ("99e4f95ed2fd4126e7b5b1e65b701a2b7b6c6636c1d51df3536dfd3af5d056f1", 0, "addr1qyrk4kfujrna4lp2635zztajufcp2kw36vhjt67ur7kd4knpr9phs055mc302vmh3pq4y85h7a6c3ls9g3l5vjlpjtysqfydlq", "100000000000"),
    ]
    .iter()
    .map(|(tx_hash, output_index, address, lovelace)| UTxO {
        input: TxInput {
            tx_hash: tx_hash.to_string(),
            output_index: *output_index,
        },
        output: TxOutput {
            address: address.to_string(),
            amount: vec![Asset {
                unit: "lovelace".to_string(),
                quantity: lovelace.to_string(),
            }],
            data_hash: None,
            plutus_data: None,
            script_ref: None,
            script_hash: None,
        },
    })
    .collect();
    let result = crate::plutus::execute_tx_scripts::execute_tx_scripts(
        COST_MODEL_UPDATE_TX,
        JsValue::new(&serde_json::to_string(&utxos).unwrap()),
        JsValue::new(&serde_json::to_string(&default_cost_models()).unwrap()),
    )
    .map_err(|e| e.to_string())
    .expect("the export answers");
    let json: serde_json::Value = serde_json::from_str(&result.as_string().unwrap()).unwrap();
    assert_eq!(json[0]["redeemer_tag"], "Propose", "{}", json);
    assert!(json[0]["error"].is_null(), "{}", json);
    assert_eq!(json[0]["calculated_ex_units"], json[0]["original_ex_units"], "{}", json);
    assert_eq!(json[0]["calculated_ex_units"]["steps"], "104574320", "{}", json);
}

/// A spent script UTxO whose inline datum nests past what pallas reads:
/// the validation does not fail as a whole; each redeemer is reported not
/// examined (an implementation limit), none is evaluated, and phase 1
/// stands.
#[test]
fn a_context_datum_past_the_bound_leaves_the_redeemers_not_examined() {
    use crate::validators::phase_2::errors::Phase2Warning;
    let bound = crate::cbor::limits::MAX_PALLAS_NESTING_DEPTH;
    let tx_hex = transaction(Version::V2, None, &[]);
    let mut context = context(Version::V2);
    let script_utxo = context.utxo_set.last_mut().unwrap();
    script_utxo.utxo.output.plutus_data = Some(format!("{}00", "81".repeat(bound + 1)));
    let result = validate_transaction(&tx_hex, context)
        .map_err(|e| e.to_string())
        .expect("the transaction is validated, not refused");
    assert!(result.phase2_errors.is_empty(), "{:?}", result.phase2_errors);
    assert!(result.eval_redeemer_results.is_empty());
    assert_eq!(result.phase2_warnings.len(), 1, "{:?}", result.phase2_warnings);
    match &result.phase2_warnings[0].warning {
        Phase2Warning::ScriptContextNotExamined { input, reason } => {
            assert_eq!(input, &format!("{}#0", "11".repeat(32)));
            assert!(reason.contains(&crate::cbor::limits::pallas_nesting_message(bound)), "{}", reason);
        }
        other => panic!("{:?}", other),
    }
    assert_eq!(
        result.phase2_warnings[0].locations,
        vec!["transaction.witness_set.redeemers.0".to_string()]
    );
}
