use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::{common::ExUnits, validators::{
    phase_1::errors::{ValidationPhase1Error, ValidationPhase1Warning},
    phase_2::errors::{ValidationPhase2Error, ValidationPhase2Warning},
}};



#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub enum RedeemerTag {
    Mint,
    Spend,
    Cert,
    Propose,
    Vote,
    Reward,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct EvalRedeemerResult {
    pub tag: RedeemerTag,
    pub index: u64,
    pub provided_ex_units: ExUnits,
    pub calculated_ex_units: ExUnits,
    pub logs: Vec<String>,
    pub success: bool,
    pub error: Option<String>,
    pub script_context_bytes: Option<String>,
    /// The mapped script context, serialized as a JSON string.
    pub script_context: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct ValidationResult {
    pub errors: Vec<ValidationPhase1Error>,
    pub warnings: Vec<ValidationPhase1Warning>,
    pub phase2_errors: Vec<ValidationPhase2Error>,
    pub phase2_warnings: Vec<ValidationPhase2Warning>,
    pub eval_redeemer_results: Vec<EvalRedeemerResult>,
}

impl ValidationResult {

    pub fn new_empty() -> Self {
        Self {
            errors: vec![],
            warnings: vec![],
            phase2_errors: vec![],
            phase2_warnings: vec![],
            eval_redeemer_results: vec![],
        }
    }

    pub fn new_phase_1(
        errors: Vec<ValidationPhase1Error>,
        warnings: Vec<ValidationPhase1Warning>,
    ) -> Self {
        Self {
            errors,
            warnings,
            phase2_errors: vec![],
            phase2_warnings: vec![],
            eval_redeemer_results: vec![],
        }
    }

    pub fn new_phase_2(
        errors: Vec<ValidationPhase2Error>,
        warnings: Vec<ValidationPhase2Warning>,
        eval_redeemer_results: Vec<EvalRedeemerResult>,
    ) -> Self {
        Self {
            errors: vec![],
            warnings: vec![],
            phase2_errors: errors,
            phase2_warnings: warnings,
            eval_redeemer_results: eval_redeemer_results,
        }
    }

    pub fn append(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
        self.phase2_errors.extend(other.phase2_errors);
        self.phase2_warnings.extend(other.phase2_warnings);
        self.eval_redeemer_results.extend(other.eval_redeemer_results);
    }
}
