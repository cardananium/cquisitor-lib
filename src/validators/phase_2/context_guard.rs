//! Transaction content the script-context builder cannot translate.
//!
//! uplc builds a script's `TxInfo` with `unwrap`s and `unreachable!`s on
//! content it assumes a valid transaction never holds, and on wasm a panic
//! is an uncatchable trap (the crate builds with `panic = abort`, so
//! `catch_unwind` is no way out). CSL is more lenient than uplc on some of
//! that content, and `execute_tx_scripts` hands pallas' decoding straight to
//! uplc, so each such content is found here first and answered as a
//! phase-2 error of the redeemer being evaluated; phase 1's report survives.
//!
//! Where the ledger has a rule for the same content, the error is the
//! ledger's (Conway `TxInfo`: `transTxOutV1` / `transTxOutV2` refuse Byron
//! output addresses as `ByronTxOutInContext`, `transTxOutV1` refuses inline
//! datums, `transTxCertV1V2` refuses Conway certificates as
//! `CertificateNotSupported`, `guardConwayFeaturesForPlutusV1V2` refuses the
//! Conway body fields). The others are values the node refuses while
//! decoding the transaction, which CSL let through or never saw: an output
//! address it cannot read, a zero token quantity, a policy with no tokens,
//! a reward account (withdrawal key, proposal return account, treasury
//! withdrawal key) that is not a stake address, a rational number with
//! denominator 0. Content the ledger accepts and uplc cannot translate, a
//! parameter change of the cost models, is no refusal: `context_data`
//! translates it.

use pallas_addresses::Address;
use pallas_primitives::alonzo;
use pallas_primitives::conway::{
    Certificate, GovAction, Language, MintedTx, ProtocolParamUpdate, PseudoDatumOption,
    PseudoTransactionOutput, RationalNumber,
};

use crate::validators::phase_2::errors::Phase2Error;

/// The first withdrawal key of `tx` that is no stake address, as the error
/// to report for every redeemer. Checked before a redeemer's script is
/// looked up: the lookup of a reward redeemer reads every withdrawal key.
pub(crate) fn withdrawal_refusal(tx: &MintedTx) -> Option<Phase2Error> {
    let withdrawals = tx.transaction_body.withdrawals.as_ref()?;
    withdrawals
        .iter()
        .enumerate()
        .find_map(|(index, (account, _))| {
            reward_account_refusal(account, || format!("withdrawals[{}]", index))
        })
}

/// The first content of `tx` no script context can be built from, whatever
/// the script's language, as the error to report for every redeemer;
/// `None` when there is none. Includes [`withdrawal_refusal`].
pub(crate) fn transaction_refusal(tx: &MintedTx) -> Option<Phase2Error> {
    if let Some(error) = withdrawal_refusal(tx) {
        return Some(error);
    }
    let body = &tx.transaction_body;

    for (index, output) in body.outputs.iter().enumerate() {
        let output_index = index as u64;
        let address = match output {
            PseudoTransactionOutput::Legacy(output) => &output.address,
            PseudoTransactionOutput::PostAlonzo(output) => &output.address,
        };
        match Address::from_bytes(address) {
            Err(error) => {
                return Some(Phase2Error::UnreadableOutput {
                    output_index,
                    reason: format!("its address cannot be read: {}", error),
                })
            }
            Ok(Address::Byron(_)) => return Some(Phase2Error::ByronAddressNotAllowed),
            Ok(_) => {}
        }
        if let PseudoTransactionOutput::Legacy(output) = output {
            if let Some(reason) = legacy_value_fault(&output.amount) {
                return Some(Phase2Error::UnreadableOutput {
                    output_index,
                    reason,
                });
            }
        }
    }

    if let Some(proposals) = &body.proposal_procedures {
        for (index, proposal) in proposals.iter().enumerate() {
            let field = format!("proposal_procedures[{}]", index);
            if let Some(error) = reward_account_refusal(&proposal.reward_account, || {
                format!("{}.reward_account", field)
            }) {
                return Some(error);
            }
            if let Some(error) = governance_action_refusal(&proposal.gov_action, &field) {
                return Some(error);
            }
        }
    }
    None
}

/// The first content of `tx` the builder of a `language` script context
/// would panic on, or that the ledger refuses in that context, as the
/// error to report for the redeemer; `None` when the context can be built.
/// [`transaction_refusal`] covers what refuses every language.
pub(crate) fn script_context_refusal(tx: &MintedTx, language: &Language) -> Option<Phase2Error> {
    let body = &tx.transaction_body;
    let legacy_language = matches!(language, Language::PlutusV1 | Language::PlutusV2);

    if matches!(language, Language::PlutusV1)
        && body.outputs.iter().any(|output| {
            matches!(
                output,
                PseudoTransactionOutput::PostAlonzo(output)
                    if matches!(output.datum_option, Some(PseudoDatumOption::Data(_)))
            )
        })
    {
        return Some(Phase2Error::InlineDatumNotAllowedForPlutusV1);
    }

    if legacy_language {
        let language_name = language_name(language);
        if let Some(certificates) = &body.certificates {
            for (index, certificate) in certificates.iter().enumerate() {
                if let Some(certificate_type) = conway_certificate_name(certificate) {
                    return Some(Phase2Error::CertificateNotSupportedInPlutusV1V2 {
                        certificate_index: index as u64,
                        certificate_type: certificate_type.to_string(),
                        language: language_name.to_string(),
                    });
                }
            }
        }
        let unsupported_field = if body
            .voting_procedures
            .as_ref()
            .is_some_and(|votes| !votes.is_empty())
        {
            Some("voting_procedures")
        } else if body.proposal_procedures.is_some() {
            Some("proposal_procedures")
        } else if body.donation.is_some() {
            Some("treasury_donation")
        } else if body.treasury_value.is_some() {
            Some("current_treasury_value")
        } else {
            None
        };
        if let Some(field) = unsupported_field {
            return Some(Phase2Error::FieldNotSupportedInPlutusV1V2 {
                field: field.to_string(),
                language: language_name.to_string(),
            });
        }
    }
    None
}

/// Why `account` is no reward account: the ledger reads a withdrawal key, a
/// proposal's return account and a treasury withdrawal key as a stake
/// address (header `0b111x`, then a 28-byte credential), and the context
/// builder parses each one with an `unwrap` and orders withdrawals with an
/// `unreachable!` for anything else.
fn reward_account_refusal(account: &[u8], field: impl FnOnce() -> String) -> Option<Phase2Error> {
    let reason = match Address::from_bytes(account) {
        Ok(Address::Stake(_)) => return None,
        Ok(Address::Shelley(_)) => "it is a payment address, not a stake address".to_string(),
        Ok(Address::Byron(_)) => "it is a Byron address, not a stake address".to_string(),
        Err(error) => format!("it cannot be read as a stake address: {}", error),
    };
    Some(Phase2Error::UnreadableTransactionField {
        field: field(),
        reason,
    })
}

/// The first reward account or rational number of `action` (proposal
/// `field`) the context builder cannot translate.
fn governance_action_refusal(action: &GovAction, field: &str) -> Option<Phase2Error> {
    match action {
        GovAction::TreasuryWithdrawals(withdrawals, _) => {
            withdrawals.iter().enumerate().find_map(|(index, (account, _))| {
                reward_account_refusal(account, || {
                    format!("{}.gov_action.withdrawals[{}]", field, index)
                })
            })
        }
        GovAction::UpdateCommittee(_, _, _, quorum) => {
            rational_refusal(quorum, || format!("{}.gov_action.quorum", field))
        }
        GovAction::ParameterChange(_, update, _) => parameter_update_refusal(update, field),
        GovAction::HardForkInitiation(..)
        | GovAction::NoConfidence(..)
        | GovAction::NewConstitution(..)
        | GovAction::Information => None,
    }
}

/// The first rational number of a parameter change with denominator 0.
fn parameter_update_refusal(update: &ProtocolParamUpdate, field: &str) -> Option<Phase2Error> {
    let optional = [
        ("pool_pledge_influence", update.pool_pledge_influence.as_ref()),
        ("expansion_rate", update.expansion_rate.as_ref()),
        ("treasury_growth_rate", update.treasury_growth_rate.as_ref()),
        (
            "minfee_refscript_cost_per_byte",
            update.minfee_refscript_cost_per_byte.as_ref(),
        ),
    ];
    let mut rationals: Vec<(&str, &RationalNumber)> = optional
        .iter()
        .filter_map(|&(name, value)| value.map(|value| (name, value)))
        .collect();
    if let Some(prices) = &update.execution_costs {
        rationals.push(("execution_costs.mem_price", &prices.mem_price));
        rationals.push(("execution_costs.step_price", &prices.step_price));
    }
    if let Some(t) = &update.pool_voting_thresholds {
        rationals.extend([
            ("pool_voting_thresholds.motion_no_confidence", &t.motion_no_confidence),
            ("pool_voting_thresholds.committee_normal", &t.committee_normal),
            ("pool_voting_thresholds.committee_no_confidence", &t.committee_no_confidence),
            ("pool_voting_thresholds.hard_fork_initiation", &t.hard_fork_initiation),
            ("pool_voting_thresholds.security_voting_threshold", &t.security_voting_threshold),
        ]);
    }
    if let Some(t) = &update.drep_voting_thresholds {
        rationals.extend([
            ("drep_voting_thresholds.motion_no_confidence", &t.motion_no_confidence),
            ("drep_voting_thresholds.committee_normal", &t.committee_normal),
            ("drep_voting_thresholds.committee_no_confidence", &t.committee_no_confidence),
            ("drep_voting_thresholds.update_constitution", &t.update_constitution),
            ("drep_voting_thresholds.hard_fork_initiation", &t.hard_fork_initiation),
            ("drep_voting_thresholds.pp_network_group", &t.pp_network_group),
            ("drep_voting_thresholds.pp_economic_group", &t.pp_economic_group),
            ("drep_voting_thresholds.pp_technical_group", &t.pp_technical_group),
            ("drep_voting_thresholds.pp_governance_group", &t.pp_governance_group),
            ("drep_voting_thresholds.treasury_withdrawal", &t.treasury_withdrawal),
        ]);
    }
    rationals.into_iter().find_map(|(name, value)| {
        rational_refusal(value, || format!("{}.gov_action.parameter_update.{}", field, name))
    })
}

/// A rational number with denominator 0: the ledger's bounded rationals
/// refuse it while decoding, and the context builder divides by the
/// greatest common divisor of its parts, which for `0/0` is 0.
fn rational_refusal(value: &RationalNumber, field: impl FnOnce() -> String) -> Option<Phase2Error> {
    (value.denominator == 0).then(|| Phase2Error::UnreadableTransactionField {
        field: field(),
        reason: format!(
            "the rational number {}/{} has denominator 0",
            value.numerator, value.denominator
        ),
    })
}

/// Why a legacy (array-form) output value cannot be translated: the
/// builder asserts every token quantity is positive and every policy holds
/// a token.
fn legacy_value_fault(value: &alonzo::Value) -> Option<String> {
    let alonzo::Value::Multiasset(_, assets) = value else {
        return None;
    };
    for (policy_id, tokens) in assets.iter() {
        if tokens.is_empty() {
            return Some(format!("policy {} holds no tokens", policy_id));
        }
        for (asset_name, quantity) in tokens.iter() {
            if *quantity == 0 {
                return Some(format!(
                    "token {}.{} has quantity 0",
                    policy_id,
                    hex::encode(asset_name.as_slice())
                ));
            }
        }
    }
    None
}

/// The Conway certificate kinds (7-18 less the deposit-carrying stake
/// registration and deregistration, 7 and 8, which translate to their
/// pre-Conway forms) that a PlutusV1/V2 context cannot represent.
fn conway_certificate_name(certificate: &Certificate) -> Option<&'static str> {
    match certificate {
        Certificate::StakeRegistration(..)
        | Certificate::StakeDeregistration(..)
        | Certificate::StakeDelegation(..)
        | Certificate::PoolRegistration { .. }
        | Certificate::PoolRetirement(..)
        | Certificate::Reg(..)
        | Certificate::UnReg(..) => None,
        Certificate::VoteDeleg(..) => Some("VoteDeleg"),
        Certificate::StakeVoteDeleg(..) => Some("StakeVoteDeleg"),
        Certificate::StakeRegDeleg(..) => Some("StakeRegDeleg"),
        Certificate::VoteRegDeleg(..) => Some("VoteRegDeleg"),
        Certificate::StakeVoteRegDeleg(..) => Some("StakeVoteRegDeleg"),
        Certificate::AuthCommitteeHot(..) => Some("AuthCommitteeHot"),
        Certificate::ResignCommitteeCold(..) => Some("ResignCommitteeCold"),
        Certificate::RegDRepCert(..) => Some("RegDRepCert"),
        Certificate::UnRegDRepCert(..) => Some("UnRegDRepCert"),
        Certificate::UpdateDRepCert(..) => Some("UpdateDRepCert"),
    }
}

fn language_name(language: &Language) -> &'static str {
    match language {
        Language::PlutusV1 => "PlutusV1",
        Language::PlutusV2 => "PlutusV2",
        Language::PlutusV3 => "PlutusV3",
    }
}
