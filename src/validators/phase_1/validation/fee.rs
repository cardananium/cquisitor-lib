use crate::{
    js_error::JsError,
    validators::{
        common::FeeDecomposition,
        helpers::reference_script_size,
        input_contexts::{UtxoInputContext, ValidationInputContext},
        phase_1::errors::{
            Phase1Error, Phase1Warning, ValidationPhase1Error, ValidationPhase1Warning,
        },
        validation_result::ValidationResult,
    },
};
use cardano_serialization_lib as csl;
use std::collections::HashSet;

pub struct FeeValidator {
    pub fee_decomposition: FeeDecomposition,
    pub actual_fee: u64,
    pub expected_fee: u64,
}

impl FeeValidator {
    pub fn new<'a>(
        tx_size: usize,
        tx_body: &csl::TransactionBody,
        tx_witness_set: &csl::TransactionWitnessSet,
        validation_input_context: &'a ValidationInputContext,
    ) -> Result<Self, JsError> {
        let utxos = collect_utxos(tx_body, validation_input_context);
        let redeemers = tx_witness_set.redeemers().unwrap_or(csl::Redeemers::new());
        // Per cardano-ledger Conway `txNonDistinctRefScriptsSize`:
        // * iterate UTxOs referenced by `inputs ∪ reference_inputs` (set union)
        // * for each, add `originalBytesSize Script` (raw UPLC for plutus, CBOR
        //   of NativeScript for native — no outer `[language, bytes]` wrapper)
        // * duplicates by script hash are counted as many times as they appear
        let mut total_reference_scripts_size: usize = 0;
        for utxo in &utxos {
            if let Some(script_ref) = &utxo.utxo.output.script_ref {
                let size = reference_script_size(script_ref).map_err(|e| {
                    JsError::new(&format!("Failed to parse reference script: {}", e))
                })?;
                total_reference_scripts_size += size as usize;
            }
        }
        let ref_script_coins_per_byte_csl = validation_input_context
            .protocol_parameters
            .reference_script_cost_per_byte
            .to_csl();

        let csl_ref_script_fee =
            csl::min_ref_script_fee(total_reference_scripts_size, &ref_script_coins_per_byte_csl)
                .map_err(|e| {
                JsError::new(&format!("Failed to calculate min ref script fee: {:?}", e))
            })?;
        let ref_script_fee: u64 = csl_ref_script_fee.into();
        let total_execution_units = redeemers.total_ex_units().map_err(|e| {
            JsError::new(&format!(
                "Failed to calculate total execution units: {:?}",
                e
            ))
        })?;

        let execution_prices = validation_input_context
            .protocol_parameters
            .execution_prices
            .to_csl();
        let execution_units_fee_csl =
            csl::calculate_ex_units_ceil_cost(&total_execution_units, &execution_prices).map_err(
                |e| JsError::new(&format!("Failed to calculate execution units fee: {:?}", e)),
            )?;
        let execution_units_fee: u64 = execution_units_fee_csl.into();

        let linear_fee = csl::LinearFee::new(
            &csl::BigNum::from(
                validation_input_context
                    .protocol_parameters
                    .min_fee_coefficient_a,
            ),
            &csl::BigNum::from(
                validation_input_context
                    .protocol_parameters
                    .min_fee_constant_b,
            ),
        );
        let tx_size_fee_csl = csl::min_fee_for_size(tx_size, &linear_fee)
            .map_err(|e| JsError::new(&format!("Failed to calculate min fee for size: {:?}", e)))?;
        let tx_size_fee: u64 = tx_size_fee_csl.into();

        let fee_decomposition = FeeDecomposition {
            tx_size_fee: tx_size_fee,
            reference_scripts_fee: ref_script_fee,
            execution_units_fee: execution_units_fee,
        };

        let expected_fee = tx_size_fee + ref_script_fee + execution_units_fee;
        let actual_fee = tx_body.fee().into();

        Ok(Self {
            fee_decomposition: fee_decomposition,
            actual_fee: actual_fee,
            expected_fee: expected_fee,
        })
    }

    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if self.actual_fee < self.expected_fee {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::FeeTooSmallUTxO {
                    actual_fee: self.actual_fee,
                    min_fee: self.expected_fee,
                    fee_decomposition: self.fee_decomposition.clone(),
                },
                "transaction.body.fee".to_string(),
            ));
        };

        // Only add warning if actual fee is more than 10% higher than expected fee
        if self.actual_fee > (self.expected_fee + (self.expected_fee / 10)) {
            warnings.push(ValidationPhase1Warning::new(
                Phase1Warning::FeeIsBiggerThanMinFee {
                    actual_fee: self.actual_fee,
                    min_fee: self.expected_fee,
                    fee_decomposition: self.fee_decomposition.clone(),
                },
                "transaction.body.fee".to_string(),
            ));
        };

        ValidationResult::new_phase_1(errors, warnings)
    }
}

fn collect_utxos<'a>(
    tx_body: &csl::TransactionBody,
    validation_input_context: &'a ValidationInputContext,
) -> HashSet<&'a UtxoInputContext> {
    // cardano-ledger uses `inputs ∪ reference_inputs` set-union — any UTxO
    // that appears in both collections is counted once for fee purposes.
    let mut utxos: HashSet<&'a UtxoInputContext> = HashSet::new();
    for input in tx_body.inputs().into_iter() {
        if let Some(utxo) = validation_input_context
            .find_utxo(input.transaction_id().to_hex(), input.index())
        {
            utxos.insert(utxo);
        }
    }
    if let Some(ref_inputs) = tx_body.reference_inputs() {
        for input in ref_inputs.into_iter() {
            if let Some(utxo) = validation_input_context
                .find_utxo(input.transaction_id().to_hex(), input.index())
            {
                utxos.insert(utxo);
            }
        }
    }
    utxos
}
