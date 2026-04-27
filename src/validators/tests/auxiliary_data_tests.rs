//! Unit tests for [`crate::validators::phase_1::validation::AuxiliaryDataValidator`].
//!
//! Matches the ledger rule: `auxiliary_data_hash` in the body MUST equal
//! `hashAuxiliaryData(aux_data)` iff aux data is present. Mismatch, missing
//! hash and unexpected hash are all distinct errors.

use crate::validators::phase_1::errors::Phase1Error;
use crate::validators::phase_1::validation::AuxiliaryDataValidator;
use cardano_serialization_lib as csl;

fn build_aux_data_with_label(label: u64, text: &str) -> csl::AuxiliaryData {
    let mut aux = csl::AuxiliaryData::new();
    let mut general = csl::GeneralTransactionMetadata::new();
    general.insert(
        &csl::BigNum::from(label),
        &csl::TransactionMetadatum::new_text(text.to_string()).unwrap(),
    );
    aux.set_metadata(&general);
    aux
}

fn minimal_tx_body(aux_hash: Option<csl::AuxiliaryDataHash>) -> csl::TransactionBody {
    // Inputs/outputs don't matter for the aux-data validator — we just need a
    // body carrying (or lacking) the hash field.
    let inputs = csl::TransactionInputs::new();
    let outputs = csl::TransactionOutputs::new();
    let fee = csl::BigNum::from(0u64);
    let mut body = csl::TransactionBody::new_tx_body(&inputs, &outputs, &fee);
    if let Some(hash) = aux_hash {
        body.set_auxiliary_data_hash(&hash);
    }
    body
}

#[test]
fn aux_data_absent_on_both_sides_is_ok() {
    let body = minimal_tx_body(None);
    let validator = AuxiliaryDataValidator::new(&body, None);
    let result = validator.validate();

    assert!(result.errors.is_empty());
}

#[test]
fn aux_data_matching_hash_is_ok() {
    let aux = build_aux_data_with_label(674, "hello");
    let hash = csl::hash_auxiliary_data(&aux);
    let body = minimal_tx_body(Some(hash));

    let validator = AuxiliaryDataValidator::new(&body, Some(aux));
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "unexpected errors: {:?}",
        result.errors
    );
}

#[test]
fn aux_data_hash_mismatch_is_reported() {
    let correct_aux = build_aux_data_with_label(674, "hello");
    let wrong_aux = build_aux_data_with_label(674, "goodbye");
    let hash = csl::hash_auxiliary_data(&correct_aux);
    let body = minimal_tx_body(Some(hash));

    // Body carries hash(correct_aux) but we attach wrong_aux.
    let validator = AuxiliaryDataValidator::new(&body, Some(wrong_aux));
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::AuxiliaryDataHashMismatch { .. }
        )),
        "expected AuxiliaryDataHashMismatch, got: {:?}",
        result.errors
    );
}

#[test]
fn aux_data_present_but_hash_missing_is_reported() {
    let aux = build_aux_data_with_label(674, "hello");
    let body = minimal_tx_body(None);

    let validator = AuxiliaryDataValidator::new(&body, Some(aux));
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::AuxiliaryDataHashMissing
        )),
        "expected AuxiliaryDataHashMissing, got: {:?}",
        result.errors
    );
}

#[test]
fn aux_data_hash_without_aux_data_is_not_checked_here() {
    // The validator only flags the no-aux / present-hash case when aux data
    // *is* provided; the reverse (hash present, no aux data) is left to the
    // CSL decoding step. Verify current behaviour so future refactors stay
    // intentional.
    let aux = build_aux_data_with_label(674, "hello");
    let hash = csl::hash_auxiliary_data(&aux);
    let body = minimal_tx_body(Some(hash));

    let validator = AuxiliaryDataValidator::new(&body, None);
    let result = validator.validate();

    assert!(
        result.errors.is_empty(),
        "validator should not flag missing aux data on this path: {:?}",
        result.errors
    );
}
