use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::{common::ExUnits, validators::phase_2::hints::{get_error_hint, get_warning_hint}};

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct ValidationPhase2Error {
    pub error: Phase2Error,
    pub error_message: String,
    pub locations: Vec<String>,
    pub hint: Option<String>,
}

impl ValidationPhase2Error {
    pub fn new(error: Phase2Error, location: String) -> Self {
        let error_message = error.to_string();
        let hint = get_error_hint(&error);
        Self {
            error,
            error_message,
            locations: vec![location],
            hint,
        }
    }

    pub fn new_with_locations(error: Phase2Error, locations: &[String]) -> Self {
        let error_message = error.to_string();
        let hint = get_error_hint(&error);
        Self {
            error,
            error_message,
            locations: locations.to_vec(),
            hint,
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct ValidationPhase2Warning {
    pub warning: Phase2Warning,
    pub warning_message: String,
    pub locations: Vec<String>,
    pub hint: Option<String>,
}

impl ValidationPhase2Warning {
    pub fn new(warning: Phase2Warning, location: String) -> Self {
        let warning_message = warning.to_string();
        let hint = get_warning_hint(&warning);
        Self {
            warning,
            warning_message,
            locations: vec![location],
            hint,
        }
    }

    pub fn new_with_locations(warning: Phase2Warning, locations: &[String]) -> Self {
        let warning_message = warning.to_string();
        let hint = get_warning_hint(&warning);
        Self {
            warning,
            warning_message,
            locations: locations.to_vec(),
            hint,
        }
    }
}

/// Phase 1 validation errors
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub enum Phase2Error {
    NoEnoughBudget {
        expected_budget: ExUnits,
        actual_budget: ExUnits,
    },
    InvalidRedeemerIndex {
        tag: String,
        index: u64,
    },
    MachineError { error: String },
    NativeScriptIsReferencedByRedeemer,
    CostModelNotFound { language: String },
    ScriptDecodeError { error: String },
    
    // ========== Transaction Context Building Errors ==========
    
    /// Input referenced in the transaction was not found in the provided UTxOs
    ResolvedInputNotFound { tx_hash: String, tx_index: u64 },
    
    /// Byron addresses are not allowed in Plutus script transactions (any version)
    ByronAddressNotAllowed,
    
    /// Inline datums are not allowed when PlutusV1 scripts are present
    InlineDatumNotAllowedForPlutusV1,
    
    /// The evaluator cannot build a PlutusV1 context for a transaction with
    /// reference inputs, or spending an output that carries a reference
    /// script. The Conway ledger accepts both for PlutusV1 (it refuses
    /// only inline datums), so this is the evaluator's limit, not a ledger rule.
    ReferenceInputsNotAllowedForPlutusV1,

    /// A transaction output the script context cannot be built from: an
    /// address that cannot be read, a zero token quantity or a policy with
    /// no tokens (values the node refuses while decoding the transaction)
    UnreadableOutput { output_index: u64, reason: String },

    /// A body field other than an output the script context cannot be
    /// built from: a reward account (withdrawal key, proposal return
    /// account, treasury withdrawal key) that is not a stake address, or a
    /// rational number with denominator 0 in a proposal (values the node
    /// refuses while decoding the transaction). `field` names it, e.g.
    /// `withdrawals[0]`, `proposal_procedures[1].gov_action.quorum`
    UnreadableTransactionField { field: String, reason: String },

    /// A Conway certificate (kinds 9-18) in a transaction that runs a
    /// PlutusV1/V2 script: the ledger's `CertificateNotSupported`
    CertificateNotSupportedInPlutusV1V2 {
        certificate_index: u64,
        certificate_type: String,
        language: String,
    },

    /// A Conway body field (votes, proposals, treasury donation, current
    /// treasury value) in a transaction that runs a PlutusV1/V2 script: the
    /// ledger's `VotingProceduresFieldNotSupported`,
    /// `ProposalProceduresFieldNotSupported`, `TreasuryDonationFieldNotSupported`
    /// and `CurrentTreasuryFieldNotSupported`
    FieldNotSupportedInPlutusV1V2 { field: String, language: String },
    
    /// The validity slot is too far in the past for slot-to-time conversion
    SlotTooFarInThePast { oldest_allowed: u64 },
    
    /// Address doesn't contain a payment credential
    NoPaymentCredential,
    
    /// Extraneous redeemer without corresponding script element
    ExtraneousRedeemer { tag: String, index: u64 },
    
    /// Generic build context error (fallback for unrecognized errors)
    BuildTxContextError { error: String },

    // ========== Script Lookup Errors ==========

    /// Redeemer index points to a non-existent element (e.g., no mint policy, no input, no certificate at that index)
    RedeemerIndexOutOfBounds { tag: String, index: u64, max_index: Option<u64> },
    
    /// Script with the given hash not found in witness set or reference inputs
    MissingRequiredScript { script_hash: String },
    
    /// Datum not found for a spending input that requires it
    MissingRequiredDatum { datum_hash: String },
    
    /// Redeemer points to a non-script withdrawal (key-based withdrawal)
    NonScriptWithdrawal,
    
    /// Redeemer points to a non-script credential (e.g., key-based stake credential)
    NonScriptCredential,
    
    /// Redeemer points to an unsupported certificate type (StakeRegistration, PoolRetirement, PoolRegistration)
    UnsupportedCertificateType,
    
    /// No guardrail script defined for the governance proposal procedure
    NoGuardrailScriptForProcedure,
    
    /// Missing inline datum or datum hash in script input (datum hash required for PlutusV1, inline datum or hash for PlutusV2)
    MissingRequiredInlineDatumOrHash,
    
    /// Generic script lookup error (fallback for unrecognized errors from uplc)
    ScriptLookupError { error: String },
}

impl Phase2Error {
    pub fn to_string(&self) -> String {
        match self {
            Phase2Error::NoEnoughBudget { expected_budget, actual_budget } => {
                format!(
                    "Not enough budget available. Expected: {:?}, Actual: {:?}",
                    expected_budget, actual_budget
                )
            }
            Phase2Error::InvalidRedeemerIndex { tag, index } => {
                format!("Invalid redeemer index for tag '{}': {}", tag, index)
            }
            Phase2Error::MachineError { error } => {
                format!("Plutus machine error: {}", error)
            }
            Phase2Error::NativeScriptIsReferencedByRedeemer => {
                "Native script cannot be referenced by redeemer".to_string()
            }
            Phase2Error::CostModelNotFound { language } => {
                format!("Cost model not found for language: {}", language)
            }
            Phase2Error::ScriptDecodeError { error } => {
                format!("Failed to decode script: {}", error)
            }
            Phase2Error::ResolvedInputNotFound { tx_hash, tx_index } => {
                format!("Input {}#{} not found in the provided UTxO set", tx_hash, tx_index)
            }
            Phase2Error::ByronAddressNotAllowed => {
                "Byron (legacy) addresses cannot be used in Plutus script transactions".to_string()
            }
            Phase2Error::InlineDatumNotAllowedForPlutusV1 => {
                "Inline datums are not supported in PlutusV1, use datum hash instead".to_string()
            }
            Phase2Error::ReferenceInputsNotAllowedForPlutusV1 => {
                "The evaluator cannot build a PlutusV1 script context for a transaction with reference inputs or spending an output with a reference script (the Conway ledger accepts both for PlutusV1; it refuses only inline datums)".to_string()
            }
            Phase2Error::UnreadableOutput { output_index, reason } => {
                format!(
                    "Output {} cannot be translated into a script context: {}",
                    output_index, reason
                )
            }
            Phase2Error::UnreadableTransactionField { field, reason } => {
                format!(
                    "The transaction's {} cannot be translated into a script context: {}",
                    field, reason
                )
            }
            Phase2Error::CertificateNotSupportedInPlutusV1V2 {
                certificate_index,
                certificate_type,
                language,
            } => {
                format!(
                    "Certificate {} ({}) is a Conway certificate, which a {} script context cannot represent (CertificateNotSupported)",
                    certificate_index, certificate_type, language
                )
            }
            Phase2Error::FieldNotSupportedInPlutusV1V2 { field, language } => {
                format!(
                    "The transaction body sets {}, which a {} script context cannot represent",
                    field, language
                )
            }
            Phase2Error::SlotTooFarInThePast { oldest_allowed } => {
                format!(
                    "Validity interval references a slot before the network's zero slot (oldest allowed: {})",
                    oldest_allowed
                )
            }
            Phase2Error::NoPaymentCredential => {
                "Address lacks a payment credential (possibly a stake address used where payment address is required)".to_string()
            }
            Phase2Error::ExtraneousRedeemer { tag, index } => {
                format!(
                    "{} redeemer at index {} has no corresponding script element in the transaction",
                    tag, index
                )
            }
            Phase2Error::BuildTxContextError { error } => {
                format!("Failed to build transaction context: {}", error)
            }
            Phase2Error::RedeemerIndexOutOfBounds { tag, index, max_index } => {
                match max_index {
                    Some(max) => format!(
                        "{} redeemer index {} is out of bounds (only {} elements available, max index: {})",
                        tag, index, max + 1, max
                    ),
                    None => format!(
                        "{} redeemer index {} is out of bounds (no elements available)",
                        tag, index
                    ),
                }
            }
            Phase2Error::MissingRequiredScript { script_hash } => {
                format!(
                    "Script {} not found in witness set, inputs, or reference inputs",
                    script_hash
                )
            }
            Phase2Error::MissingRequiredDatum { datum_hash } => {
                format!("Datum {} not found in witness set or as inline datum in the input", datum_hash)
            }
            Phase2Error::NonScriptWithdrawal => {
                "Withdrawal uses a key-based credential, but redeemer expects a script".to_string()
            }
            Phase2Error::NonScriptCredential => {
                "Expected script credential but found key credential".to_string()
            }
            Phase2Error::UnsupportedCertificateType => {
                "Certificate type does not support redeemers (StakeRegistration, PoolRetirement, PoolRegistration)".to_string()
            }
            Phase2Error::NoGuardrailScriptForProcedure => {
                "Governance proposal does not define a guardrail script".to_string()
            }
            Phase2Error::MissingRequiredInlineDatumOrHash => {
                "Missing required datum: PlutusV1 requires a datum hash (inline datums not supported), PlutusV2 accepts either inline datum or datum hash".to_string()
            }
            Phase2Error::ScriptLookupError { error } => {
                format!("Script lookup failed: {}", error)
            }
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub enum Phase2Warning {
    BudgetIsBiggerThanExpected {
        expected_budget: ExUnits,
        actual_budget: ExUnits,
    },
    /// A UTxO the transaction spends or references carries a script
    /// reference or inline datum nested deeper than the library reads, so
    /// no script context was built and the redeemer was not evaluated. An
    /// implementation limit, not a finding about the transaction.
    ScriptContextNotExamined {
        input: String,
        reason: String,
    },
}

impl Phase2Warning {
    pub fn to_string(&self) -> String {
        match self {
            Phase2Warning::BudgetIsBiggerThanExpected { expected_budget, actual_budget } => {
                format!(
                    "Budget is bigger than expected. Expected: {:?}, Actual: {:?}",
                    expected_budget, actual_budget
                )
            }
            Phase2Warning::ScriptContextNotExamined { input, reason } => {
                format!(
                    "The redeemer was not evaluated (implementation limit, not a finding): UTxO {} cannot enter a script context: {}",
                    input, reason
                )
            }
        }
    }
}