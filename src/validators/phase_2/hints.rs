use super::errors::{Phase2Error, Phase2Warning};

pub fn get_error_hint(error: &Phase2Error) -> Option<String> {
    match error {
        Phase2Error::RedeemerIndexOutOfBounds { tag, .. } => {
            Some(format!(
                "The redeemer index for '{}' doesn't match any element in the transaction. \
                Check that the redeemer index corresponds to the correct position in the sorted list of {}s. \
                Remember: indices are 0-based and elements are lexicographically sorted in case of transaction inputs and withdrawals.",
                tag,
                tag.to_lowercase()
            ))
        }
        Phase2Error::MissingRequiredScript { .. } => {
            Some(
                "The required script is not present in the transaction. \
                Make sure the script is included in one of: \
                (1) the witness set (plutus_v1_script, plutus_v2_script, or plutus_v3_script), \
                (2) a reference input with script_ref (inline script), or \
                (3) a regular input with script_ref (inline script).".to_string()
            )
        }
        Phase2Error::MissingRequiredDatum { .. } => {
            Some(
                "The required datum is not present in the transaction. \
                For spending script inputs, you must provide the datum in one of: \
                (1) the witness set (plutus_data field) when using datum hash, or \
                (2) inline in the spending input UTxO itself (datum_option: Data). \
                Note: datums from reference inputs are NOT used for spending validation.".to_string()
            )
        }
        Phase2Error::NonScriptWithdrawal => {
            Some(
                "A redeemer was provided for a withdrawal, but the withdrawal address uses a key-based \
                stake credential instead of a script. Redeemers can only be attached to script-based withdrawals.".to_string()
            )
        }
        Phase2Error::NonScriptCredential => {
            Some(
                "A redeemer was provided for an element that uses a key-based credential instead of a script. \
                This typically happens with certificates or voting where the stake/DRep credential is a key hash, not a script hash.".to_string()
            )
        }
        Phase2Error::UnsupportedCertificateType => {
            Some(
                "The certificate type at this index cannot have a redeemer attached. \
                StakeRegistration, PoolRetirement, and PoolRegistration certificates don't support redeemers. \
                Check if you're using the correct certificate index.".to_string()
            )
        }
        Phase2Error::NoGuardrailScriptForProcedure => {
            Some(
                "A redeemer was provided for a governance proposal, but the proposal doesn't define a guardrail script. \
                Only ParameterChange and TreasuryWithdrawals proposals with an explicit guardrail script can have redeemers.".to_string()
            )
        }
        Phase2Error::MissingRequiredInlineDatumOrHash => {
            Some(
                "PlutusV1 spending scripts require a datum hash in the input UTxO (inline datums are NOT supported in V1). \
                PlutusV2 spending scripts accept either an inline datum or a datum hash. \
                PlutusV3 spending scripts can work with UTxOs that have no datum at all (CIP-69), \
                but if the UTxO has a datum hash, the datum must still be provided in the witness set.".to_string()
            )
        }
        
        // Transaction Context Building Errors
        Phase2Error::ResolvedInputNotFound { tx_hash, tx_index } => {
            Some(format!(
                "The transaction input {}#{} is referenced but its UTxO data was not provided. \
                Make sure you pass all required UTxOs when validating the transaction. \
                This includes all inputs AND all reference inputs.",
                tx_hash, tx_index
            ))
        }
        Phase2Error::ByronAddressNotAllowed => {
            Some(
                "Byron (legacy) addresses cannot be used in transactions that execute Plutus scripts (any version: V1, V2, or V3). \
                If you need to spend from a Byron address, first move the funds to a Shelley address in a separate transaction \
                that doesn't involve any Plutus scripts.".to_string()
            )
        }
        Phase2Error::InlineDatumNotAllowedForPlutusV1 => {
            Some(
                "PlutusV1 scripts do not support inline datums. If your transaction includes PlutusV1 scripts, \
                all script inputs must use datum hashes instead of inline datums. \
                Consider upgrading to PlutusV2 or higher to use inline datums.".to_string()
            )
        }
        Phase2Error::ReferenceInputsNotAllowedForPlutusV1 => {
            Some(
                "PlutusV1 scripts do not support reference inputs or script references (CIP-31/CIP-33). \
                If you need reference inputs, upgrade your script to PlutusV2 or higher. \
                Remove any reference_inputs from the transaction body when using PlutusV1.".to_string()
            )
        }
        Phase2Error::SlotTooFarInThePast { .. } => {
            Some(
                "The validity interval (validity_interval_start or ttl) references a slot that is before \
                the network's zero slot, making it impossible to convert to POSIX time. \
                Check your validity interval settings and ensure they reference valid slots.".to_string()
            )
        }
        Phase2Error::NoPaymentCredential => {
            Some(
                "An address used in the transaction doesn't have a payment credential. \
                This typically happens when a stake address (reward address) is used where a payment address is expected. \
                Make sure all inputs and outputs use proper payment addresses.".to_string()
            )
        }
        Phase2Error::ExtraneousRedeemer { tag, index } => {
            Some(format!(
                "A {} redeemer at index {} was provided, but there's no corresponding script element. \
                This can happen if: (1) the index is wrong, (2) the element was removed from the transaction, \
                or (3) the element uses a key credential instead of a script.",
                tag, index
            ))
        }
        _ => None,
    }
}

pub fn get_warning_hint(warning: &Phase2Warning) -> Option<String> {
    match warning {
        Phase2Warning::BudgetIsBiggerThanExpected { .. } => {
            Some(
                "The actual execution units used are less than what was allocated in the redeemer. \
                This means you're overpaying for script execution. Consider reducing the budget values \
                in the redeemer to save on transaction fees. You can use the actual execution units \
                reported here as a baseline, adding a small safety margin (e.g., 10-20%) for variations.".to_string()
            )
        }
    }
}