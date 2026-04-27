//! Unit tests for [`crate::validators::phase_1::validation::WitnessValidator`].
//!
//! Covers the Shelley-era UTXOW rule as extended through Conway:
//! * Every key-locked input/cert/withdrawal/mint/vote needs a matching vkey
//! * Every script-locked requirement needs a matching native or plutus script
//! * Plutus spends need a datum (unless inline) and a redeemer
//! * Extraneous signatures/scripts/datums must be rejected
//! * script_data_hash must match the hash computed from redeemers/datums/cms

use crate::common::{Asset, TxInput, TxOutput, UTxO};
use crate::validators::input_contexts::UtxoInputContext;
use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::WitnessValidator;
use crate::validators::tests::fixtures::{preview_simple_context, PREVIEW_SIMPLE_TX_HEX};
use cardano_serialization_lib as csl;

fn parse_tx() -> csl::FixedTransaction {
    csl::FixedTransaction::from_hex(PREVIEW_SIMPLE_TX_HEX).unwrap()
}

#[test]
fn happy_path_real_tx_has_no_witness_errors() {
    let tx = parse_tx();
    let ctx = preview_simple_context();

    let validator =
        WitnessValidator::new(&tx.body(), &tx.witness_set(), &tx.transaction_hash(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "expected no witness errors, got: {:?}",
        result.errors
    );
}

#[test]
fn missing_vkey_is_reported_as_missing_and_invalid() {
    // Strip all vkey witnesses from the witness set. The validator should
    // both flag the missing key (by required hash) and not raise
    // InvalidSignature (because the vkey isn't there at all).
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let stripped_witness_set = csl::TransactionWitnessSet::new();

    let validator = WitnessValidator::new(
        &tx.body(),
        &stripped_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingVKeyWitnesses { .. }
        )),
        "expected MissingVKeyWitnesses, got: {:?}",
        result.errors
    );
    assert!(
        !result
            .errors
            .iter()
            .any(|e| matches!(e.error, Phase1Error::InvalidSignature { .. })),
        "no signature was provided → InvalidSignature should not fire"
    );
}

#[test]
fn tampered_vkey_signature_triggers_invalid_signature() {
    // The signature in the real tx is 64 bytes. Toggle one byte and re-attach.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let original_vkeys = tx.witness_set().vkeys().unwrap();
    assert_eq!(original_vkeys.len(), 1);
    let orig = original_vkeys.get(0);
    let public_key = orig.vkey().public_key();
    let mut bad_sig_bytes = orig.signature().to_bytes();
    bad_sig_bytes[0] ^= 0x01;
    let bad_sig = csl::Ed25519Signature::from_bytes(bad_sig_bytes).unwrap();
    let tampered = csl::Vkeywitness::new(&csl::Vkey::new(&public_key), &bad_sig);
    let mut new_vkeys = csl::Vkeywitnesses::new();
    new_vkeys.add(&tampered);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_vkeys(&new_vkeys);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::InvalidSignature { .. }
        )),
        "expected InvalidSignature, got: {:?}",
        result.errors
    );
}

#[test]
fn extraneous_vkey_signature_is_flagged() {
    // Add a second, unrequested vkey witness built from a zero private key.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let sk = csl::Bip32PrivateKey::generate_ed25519_bip32().unwrap();
    let raw_sk = sk.to_raw_key();
    let pk = raw_sk.to_public();
    let dummy_sig = raw_sk.sign(&tx.transaction_hash().to_bytes());
    let dummy_witness =
        csl::Vkeywitness::new(&csl::Vkey::new(&pk), &dummy_sig);

    let mut new_vkeys = tx.witness_set().vkeys().unwrap_or(csl::Vkeywitnesses::new());
    new_vkeys.add(&dummy_witness);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_vkeys(&new_vkeys);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ExtraneousSignature { .. }
        )),
        "expected ExtraneousSignature, got: {:?}",
        result.errors
    );
}

#[test]
fn script_locked_input_without_script_witness_is_flagged() {
    // Replace the input UTxO's address with a script-locked one so the
    // validator treats the input as needing a plutus/native script witness.
    // The real tx doesn't carry one, so both MissingScriptWitnesses and
    // MissingRedeemer should fire.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();

    // addr_test with CredKind::Script uses header byte 0x70/0x30.
    // Build a script-locked preview base address programmatically:
    let script_hash = csl::ScriptHash::from_bytes(vec![0xEE; 28]).unwrap();
    let stake_hash = csl::Ed25519KeyHash::from_bytes(vec![0xAA; 28]).unwrap();
    let script_cred = csl::Credential::from_scripthash(&script_hash);
    let stake_cred = csl::Credential::from_keyhash(&stake_hash);
    let addr = csl::BaseAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &script_cred,
        &stake_cred,
    )
    .to_address();
    ctx.utxo_set[0].utxo.output.address = addr.to_bech32(None).unwrap();

    let validator =
        WitnessValidator::new(&tx.body(), &tx.witness_set(), &tx.transaction_hash(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingScriptWitnesses { .. }
        )),
        "expected MissingScriptWitnesses, got: {:?}",
        result.errors
    );
}

#[test]
fn extraneous_native_script_witness_is_rejected() {
    // Attach a native script to the witness set that nothing in the body
    // requires.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let extra_script = csl::NativeScript::new_script_pubkey(&csl::ScriptPubkey::new(
        &csl::Ed25519KeyHash::from_bytes(vec![0x11; 28]).unwrap(),
    ));
    let mut scripts = csl::NativeScripts::new();
    scripts.add(&extra_script);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_native_scripts(&scripts);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ExtraneousScriptWitnesses { .. }
        )),
        "expected ExtraneousScriptWitnesses, got: {:?}",
        result.errors
    );
}

#[test]
fn extraneous_datum_is_flagged() {
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let datum = csl::PlutusData::new_integer(&csl::BigInt::from(42));
    let mut data_list = csl::PlutusList::new();
    data_list.add(&datum);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_plutus_data(&data_list);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ExtraneousDatumWitnesses { .. }
        )),
        "expected ExtraneousDatumWitnesses, got: {:?}",
        result.errors
    );
}

#[test]
fn script_data_hash_mismatch_is_reported_when_redeemers_added() {
    // Non-script tx + redeemers in the witness set → expected script_data_hash
    // will be non-None, but the body carries no script_data_hash field, so the
    // validator should flag the mismatch.
    let tx = parse_tx();
    let ctx = preview_simple_context();
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(&csl::BigNum::from(1u64), &csl::BigNum::from(1u64)),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_redeemers(&redeemers);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::ScriptDataHashMismatch { .. }
        )),
        "expected ScriptDataHashMismatch, got: {:?}",
        result.errors
    );
}

#[test]
fn vkey_satisfying_native_script_is_not_flagged_as_extraneous() {
    // Mint under a native `pubkey(k)` policy. Provide k's vkey signature.
    // The required_vkey_witnesses set does NOT include k (no input/cert wants
    // it), so k would look "extraneous" UNLESS native_scripts_signature_candidates
    // are added to the allow-set — which is exactly what the validator does.
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;

    let tx = parse_tx();
    let mut ctx = preview_simple_context();

    // Generate a keypair; use its key hash as both the policy script pubkey
    // and the vkey witness.
    let sk = csl::Bip32PrivateKey::generate_ed25519_bip32().unwrap();
    let raw_sk = sk.to_raw_key();
    let pk = raw_sk.to_public();
    let kh = pk.hash();

    let policy_script = csl::NativeScript::new_script_pubkey(
        &csl::ScriptPubkey::new(&kh),
    );
    let policy_hash = policy_script.hash();

    // 1-unit mint under that policy.
    let mut assets = csl::MintAssets::new();
    assets
        .insert(
            &csl::AssetName::new(b"X".to_vec()).unwrap(),
            &csl::Int::new_i32(1),
        )
        .unwrap();
    let mut mint = csl::Mint::new();
    mint.insert(&policy_hash, &assets);
    let mut body = tx.body();
    body.set_mint(&mint);

    // Provide the script via reference input (not witness set — otherwise it
    // would itself be "extraneous" if unused; it IS used here but the happy
    // path through ref inputs is cleaner).
    let ref_tx_hash = vec![0xAB; 32];
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_hash.clone()).unwrap(),
        0,
    ));
    body.set_reference_inputs(&ref_inputs);
    let script_ref_hex = hex::encode(
        csl::ScriptRef::new_native_script(&policy_script).to_bytes(),
    );
    ctx.utxo_set.push(UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: hex::encode(&ref_tx_hash),
                output_index: 0,
            },
            output: TxOutput {
                address: ctx.utxo_set[0].utxo.output.address.clone(),
                amount: vec![Asset {
                    unit: "lovelace".to_string(),
                    quantity: "10000000".to_string(),
                }],
                data_hash: None,
                plutus_data: None,
                script_ref: Some(script_ref_hex),
                script_hash: Some(policy_hash.to_hex()),
            },
        },
        is_spent: false,
    });

    // Sign the tx hash with k and add to the witness set (alongside the
    // existing vkey witness for the spending input).
    let sig = raw_sk.sign(&tx.transaction_hash().to_bytes());
    let extra_witness = csl::Vkeywitness::new(&csl::Vkey::new(&pk), &sig);
    let mut vkeys = tx.witness_set().vkeys().unwrap_or(csl::Vkeywitnesses::new());
    vkeys.add(&extra_witness);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_vkeys(&vkeys);

    let validator = WitnessValidator::new(
        &body,
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| match &e.error {
            Phase1Error::ExtraneousSignature { extraneous_signature } => {
                *extraneous_signature == kh.to_hex()
            }
            _ => false,
        }),
        "native script sig candidate must NOT be flagged extraneous, got: {:?}",
        result.errors
    );
}

#[test]
fn plutus_v1_script_satisfies_spending_requirement() {
    // PlutusV1 witness works same as V2/V3.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();

    let plutus_script = csl::PlutusScript::new(vec![0x00; 16]);
    let script_hash = plutus_script.hash();
    let stake_hash = csl::Ed25519KeyHash::from_bytes(vec![0xAA; 28]).unwrap();
    let addr = csl::BaseAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &csl::Credential::from_scripthash(&script_hash),
        &csl::Credential::from_keyhash(&stake_hash),
    )
    .to_address()
    .to_bech32(None)
    .unwrap();
    ctx.utxo_set[0].utxo.output.address = addr;
    ctx.utxo_set[0].utxo.output.plutus_data = Some("d87980".to_string());

    let mut plutus_scripts = csl::PlutusScripts::new();
    plutus_scripts.add(&plutus_script);
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(&csl::BigNum::from(1u64), &csl::BigNum::from(1u64)),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_plutus_scripts(&plutus_scripts);
    new_witness_set.set_redeemers(&redeemers);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingScriptWitnesses { .. }
        )),
        "PlutusV1 script should satisfy requirement, got: {:?}",
        result.errors
    );
}

#[test]
fn plutus_v3_script_satisfies_spending_requirement() {
    let tx = parse_tx();
    let mut ctx = preview_simple_context();

    let plutus_script = csl::PlutusScript::new_v3(vec![0x00; 16]);
    let script_hash = plutus_script.hash();
    let stake_hash = csl::Ed25519KeyHash::from_bytes(vec![0xAA; 28]).unwrap();
    let addr = csl::BaseAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &csl::Credential::from_scripthash(&script_hash),
        &csl::Credential::from_keyhash(&stake_hash),
    )
    .to_address()
    .to_bech32(None)
    .unwrap();
    ctx.utxo_set[0].utxo.output.address = addr;
    ctx.utxo_set[0].utxo.output.plutus_data = Some("d87980".to_string());

    let mut plutus_scripts = csl::PlutusScripts::new();
    plutus_scripts.add(&plutus_script);
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(&csl::BigNum::from(1u64), &csl::BigNum::from(1u64)),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_plutus_scripts(&plutus_scripts);
    new_witness_set.set_redeemers(&redeemers);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingScriptWitnesses { .. }
        )),
        "PlutusV3 script should satisfy requirement, got: {:?}",
        result.errors
    );
}

#[test]
fn required_signer_without_witness_is_rejected() {
    let tx = parse_tx();
    let ctx = preview_simple_context();
    // Force an extra required_signer that nothing else needs and for which
    // no vkey witness exists.
    let mut body = tx.body();
    let mut signers = csl::Ed25519KeyHashes::new();
    signers.add(&csl::Ed25519KeyHash::from_bytes(vec![0x99; 28]).unwrap());
    body.set_required_signers(&signers);

    let validator =
        WitnessValidator::new(&body, &tx.witness_set(), &tx.transaction_hash(), &ctx).unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingVKeyWitnesses { .. }
        )),
        "expected MissingVKeyWitnesses from required_signers, got: {:?}",
        result.errors
    );
}

fn script_locked_address_for(script_hash: &csl::ScriptHash) -> String {
    let stake_hash = csl::Ed25519KeyHash::from_bytes(vec![0xAA; 28]).unwrap();
    let script_cred = csl::Credential::from_scripthash(script_hash);
    let stake_cred = csl::Credential::from_keyhash(&stake_hash);
    csl::BaseAddress::new(
        csl::NetworkInfo::testnet_preview().network_id(),
        &script_cred,
        &stake_cred,
    )
    .to_address()
    .to_bech32(None)
    .unwrap()
}

fn fixture_plutus_script_v2() -> (csl::PlutusScript, csl::ScriptHash) {
    let script = csl::PlutusScript::new_v2(vec![0x00; 16]);
    let hash = script.hash();
    (script, hash)
}

#[test]
fn script_spend_with_datum_hash_missing_witness_datum_errors() {
    // Plutus-locked input whose output carries a datum_hash but no inline
    // datum. The witness set must include that datum — we deliberately omit
    // it and expect MissingDatum.
    use crate::validators::phase_1::validation::NativeScriptExecutor;
    let _ = NativeScriptExecutor::new; // silence import check

    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    let (plutus_script, script_hash) = fixture_plutus_script_v2();
    ctx.utxo_set[0].utxo.output.address = script_locked_address_for(&script_hash);
    // Put a fixed datum_hash on the output, no inline datum, no datum in witness set.
    ctx.utxo_set[0].utxo.output.data_hash = Some(
        "cf39f3c0c16bcd0c85c79b7fbcf75bd6afc8d01ffd8e3edc1b26f2cb90cfaeec".to_string(),
    );

    // Provide a Plutus script and redeemer so the script path is reachable.
    let mut plutus_scripts = csl::PlutusScripts::new();
    plutus_scripts.add(&plutus_script);
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(&csl::BigNum::from(1u64), &csl::BigNum::from(1u64)),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_plutus_scripts(&plutus_scripts);
    new_witness_set.set_redeemers(&redeemers);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingDatum { .. }
        )),
        "expected MissingDatum, got: {:?}",
        result.errors
    );
}

#[test]
fn inline_datum_on_same_spending_input_satisfies_datum_requirement() {
    // Same script-locked UTxO, but this time it carries an inline datum via
    // `plutus_data`. The validator should NOT require a datum witness.
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    let (plutus_script, script_hash) = fixture_plutus_script_v2();
    ctx.utxo_set[0].utxo.output.address = script_locked_address_for(&script_hash);
    ctx.utxo_set[0].utxo.output.plutus_data = Some("d87980".to_string()); // Plutus Unit
    ctx.utxo_set[0].utxo.output.data_hash = None;

    let mut plutus_scripts = csl::PlutusScripts::new();
    plutus_scripts.add(&plutus_script);
    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(&csl::BigNum::from(1u64), &csl::BigNum::from(1u64)),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_plutus_scripts(&plutus_scripts);
    new_witness_set.set_redeemers(&redeemers);

    let validator = WitnessValidator::new(
        &tx.body(),
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingDatum { .. }
        )),
        "inline datum should cover the witness requirement, got: {:?}",
        result.errors
    );
}

#[test]
fn plutus_script_from_reference_input_satisfies_script_requirement() {
    // Script isn't in the witness set's plutus_scripts — it's provided via a
    // reference input's script_ref. The witness validator should resolve it
    // and NOT produce MissingScriptWitnesses.
    use crate::common::{Asset, TxInput, TxOutput, UTxO};
    use crate::validators::input_contexts::UtxoInputContext;

    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    let (plutus_script, script_hash) = fixture_plutus_script_v2();
    ctx.utxo_set[0].utxo.output.address = script_locked_address_for(&script_hash);
    ctx.utxo_set[0].utxo.output.plutus_data = Some("d87980".to_string());

    // Attach reference input carrying the script.
    let script_ref = csl::ScriptRef::new_plutus_script(&plutus_script);
    let script_ref_hex = hex::encode(script_ref.to_bytes());
    let ref_tx_id = vec![0xC1; 32];
    let ref_input = csl::TransactionInput::new(
        &csl::TransactionHash::from_bytes(ref_tx_id.clone()).unwrap(),
        0,
    );
    let mut ref_inputs = csl::TransactionInputs::new();
    ref_inputs.add(&ref_input);
    let mut body = tx.body();
    body.set_reference_inputs(&ref_inputs);
    ctx.utxo_set.push(UtxoInputContext {
        utxo: UTxO {
            input: TxInput {
                tx_hash: hex::encode(&ref_tx_id),
                output_index: 0,
            },
            output: TxOutput {
                address: ctx.utxo_set[0].utxo.output.address.clone(),
                amount: vec![Asset {
                    unit: "lovelace".to_string(),
                    quantity: "10000000".to_string(),
                }],
                data_hash: None,
                plutus_data: None,
                script_ref: Some(script_ref_hex),
                script_hash: Some(script_hash.to_hex()),
            },
        },
        is_spent: false,
    });

    let redeemer = csl::Redeemer::new(
        &csl::RedeemerTag::new_spend(),
        &csl::BigNum::from(0u64),
        &csl::PlutusData::new_integer(&csl::BigInt::from(0)),
        &csl::ExUnits::new(&csl::BigNum::from(1u64), &csl::BigNum::from(1u64)),
    );
    let mut redeemers = csl::Redeemers::new();
    redeemers.add(&redeemer);
    let mut new_witness_set = tx.witness_set();
    new_witness_set.set_redeemers(&redeemers);

    let validator = WitnessValidator::new(
        &body,
        &new_witness_set,
        &tx.transaction_hash(),
        &ctx,
    )
    .unwrap();
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingScriptWitnesses { .. }
        )),
        "reference-input script should satisfy witness requirement, got: {:?}",
        result.errors
    );
}

#[test]
fn missing_collected_utxo_does_not_require_witnesses_for_that_input() {
    // If an input UTxO can't be resolved, the witness validator can't infer
    // what cred it carries, so it must not fabricate a vkey requirement.
    // This locks in the current behaviour — resolving inputs is the limits
    // validator's job (BadInputsUTxO).
    let tx = parse_tx();
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator =
        WitnessValidator::new(&tx.body(), &tx.witness_set(), &tx.transaction_hash(), &ctx)
            .unwrap();
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::MissingVKeyWitnesses { .. }
        )),
        "witness validator must stay silent on unresolved inputs: {:?}",
        result.errors
    );
}

// Silence unused-import warnings when new tests are added later.
#[allow(dead_code)]
fn _unused_types() -> (Asset, TxInput, TxOutput, UTxO, UtxoInputContext) {
    unreachable!()
}
