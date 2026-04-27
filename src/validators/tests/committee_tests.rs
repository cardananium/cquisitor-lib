//! Unit tests for the committee-cert branch of
//! [`crate::validators::phase_1::validation::RegistrationValidator`].
//!
//! Covers the Conway GOVCERT rule for committee hot-key authorization and
//! cold-key resignation:
//! * Hot-auth / cold-resign for an unknown cold credential → `CommitteeIsUnknown`
//! * Second hot-auth after a cold-resign (same tx or ledger state) →
//!   `CommitteeHasPreviouslyResigned`
//! * Repeated hot-auth / cold-resign for the same cold key in one tx emits a
//!   warning (the ledger silently overwrites / ignores).

use crate::validators::common::LocalCredential;
use crate::validators::input_contexts::CommitteeInputContext;
use crate::validators::phase_1::errors::{Phase1Error, Phase1Warning};
use crate::validators::phase_1::validation::RegistrationValidator;
use crate::validators::tests::fixtures::preview_simple_context;
use cardano_serialization_lib as csl;

fn cold_cred_bytes(byte: u8) -> (csl::Credential, LocalCredential) {
    let kh = csl::Ed25519KeyHash::from_bytes(vec![byte; 28]).unwrap();
    let cred = csl::Credential::from_keyhash(&kh);
    let local = LocalCredential::KeyHash(kh.to_bytes());
    (cred, local)
}

fn body_with_cert(cert: csl::Certificate) -> csl::TransactionBody {
    let mut certs = csl::Certificates::new();
    assert!(certs.add(&cert));
    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_certs(&certs);
    body
}

fn body_with_certs(certs_in_order: Vec<csl::Certificate>) -> csl::TransactionBody {
    let mut certs = csl::Certificates::new();
    for c in certs_in_order {
        certs.add(&c);
    }
    let mut body = csl::TransactionBody::new_tx_body(
        &csl::TransactionInputs::new(),
        &csl::TransactionOutputs::new(),
        &csl::BigNum::from(0u64),
    );
    body.set_certs(&certs);
    body
}

#[test]
fn hot_auth_for_unknown_cold_key_is_rejected() {
    let (cold_cred, _) = cold_cred_bytes(0x01);
    let (hot_cred, _) = cold_cred_bytes(0x02);
    let cert = csl::Certificate::new_committee_hot_auth(
        &csl::CommitteeHotAuth::new(&cold_cred, &hot_cred),
    );

    let body = body_with_cert(cert);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    // Both committee lists empty → cold key is unknown.

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CommitteeIsUnknown { .. }
        )),
        "expected CommitteeIsUnknown, got: {:?}",
        result.errors
    );
}

#[test]
fn hot_auth_for_current_member_is_accepted() {
    let (cold_cred, cold_local) = cold_cred_bytes(0x03);
    let (hot_cred, _) = cold_cred_bytes(0x04);
    let cert = csl::Certificate::new_committee_hot_auth(
        &csl::CommitteeHotAuth::new(&cold_cred, &hot_cred),
    );

    let body = body_with_cert(cert);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: cold_local,
        committee_member_hot: None,
        is_resigned: false,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CommitteeIsUnknown { .. }
        )),
        "current committee member should not be flagged unknown: {:?}",
        result.errors
    );
}

#[test]
fn hot_auth_on_previously_resigned_member_is_rejected() {
    let (cold_cred, cold_local) = cold_cred_bytes(0x05);
    let (hot_cred, _) = cold_cred_bytes(0x06);
    let cert = csl::Certificate::new_committee_hot_auth(
        &csl::CommitteeHotAuth::new(&cold_cred, &hot_cred),
    );

    let body = body_with_cert(cert);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: cold_local,
        committee_member_hot: None,
        is_resigned: true,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CommitteeHasPreviouslyResigned { .. }
        )),
        "expected CommitteeHasPreviouslyResigned, got: {:?}",
        result.errors
    );
}

#[test]
fn cold_resign_for_unknown_member_is_rejected() {
    let (cold_cred, _) = cold_cred_bytes(0x07);
    let cert = csl::Certificate::new_committee_cold_resign(
        &csl::CommitteeColdResign::new(&cold_cred),
    );

    let body = body_with_cert(cert);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CommitteeIsUnknown { .. }
        )),
        "expected CommitteeIsUnknown, got: {:?}",
        result.errors
    );
}

#[test]
fn cold_resign_on_already_resigned_member_is_rejected() {
    let (cold_cred, cold_local) = cold_cred_bytes(0x08);
    let cert = csl::Certificate::new_committee_cold_resign(
        &csl::CommitteeColdResign::new(&cold_cred),
    );

    let body = body_with_cert(cert);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: cold_local,
        committee_member_hot: None,
        is_resigned: true,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CommitteeHasPreviouslyResigned { .. }
        )),
        "expected CommitteeHasPreviouslyResigned, got: {:?}",
        result.errors
    );
}

#[test]
fn hot_auth_after_cold_resign_in_same_tx_is_rejected() {
    let (cold_cred, cold_local) = cold_cred_bytes(0x09);
    let (hot_cred, _) = cold_cred_bytes(0x0A);

    // cert[0] = cold resign; cert[1] = hot-auth of the same cold key. The
    // validator walks certs in order and applies state updates as it goes, so
    // the second cert sees the resignation.
    let resign = csl::Certificate::new_committee_cold_resign(
        &csl::CommitteeColdResign::new(&cold_cred),
    );
    let hot_auth = csl::Certificate::new_committee_hot_auth(
        &csl::CommitteeHotAuth::new(&cold_cred, &hot_cred),
    );
    let body = body_with_certs(vec![resign, hot_auth]);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: cold_local,
        committee_member_hot: None,
        is_resigned: false,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CommitteeHasPreviouslyResigned { .. }
        )),
        "expected CommitteeHasPreviouslyResigned after in-tx resign, got: {:?}",
        result.errors
    );
}

#[test]
fn duplicate_hot_auth_in_same_tx_produces_warning() {
    let (cold_cred, cold_local) = cold_cred_bytes(0x0B);
    let (hot_cred_a, _) = cold_cred_bytes(0x0C);
    let (hot_cred_b, _) = cold_cred_bytes(0x0D);

    // Two distinct hot creds, same cold key → two distinct certs, but both
    // register a hot key for the same cold credential.
    let auth1 = csl::Certificate::new_committee_hot_auth(
        &csl::CommitteeHotAuth::new(&cold_cred, &hot_cred_a),
    );
    let auth2 = csl::Certificate::new_committee_hot_auth(
        &csl::CommitteeHotAuth::new(&cold_cred, &hot_cred_b),
    );
    let body = body_with_certs(vec![auth1, auth2]);

    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.current_committee_members.push(CommitteeInputContext {
        committee_member_cold: cold_local,
        committee_member_hot: None,
        is_resigned: false,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        result.warnings.iter().any(|w| matches!(
            w.warning,
            Phase1Warning::DuplicateCommitteeHotRegistrationInTx { .. }
        )),
        "expected DuplicateCommitteeHotRegistrationInTx warning, got: {:?}",
        result.warnings
    );
}

#[test]
fn potential_committee_member_is_treated_as_known() {
    // A cold credential that isn't *currently* seated but is scheduled by an
    // enacted UpdateCommitteeAction should still be a legal target for
    // hot-auth.
    let (cold_cred, cold_local) = cold_cred_bytes(0x0E);
    let (hot_cred, _) = cold_cred_bytes(0x0F);
    let cert = csl::Certificate::new_committee_hot_auth(
        &csl::CommitteeHotAuth::new(&cold_cred, &hot_cred),
    );

    let body = body_with_cert(cert);
    let mut ctx = preview_simple_context();
    ctx.utxo_set.clear();
    ctx.potential_committee_members.push(CommitteeInputContext {
        committee_member_cold: cold_local,
        committee_member_hot: None,
        is_resigned: false,
    });

    let validator = RegistrationValidator::new(&body, &ctx);
    let result = validator.validate();

    assert!(
        !result.errors.iter().any(|e| matches!(
            e.error,
            Phase1Error::CommitteeIsUnknown { .. }
        )),
        "potential committee member should be accepted: {:?}",
        result.errors
    );
}
