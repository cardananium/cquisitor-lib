use super::errors::{Phase1Error, Phase1Warning};

/// Provides helpful hints for resolving Phase 1 validation errors
pub fn get_error_hint(error: &Phase1Error) -> Option<String> {
    match error {
        Phase1Error::BadInputsUTxO { .. } => Some(
            "Ensure all transaction inputs reference valid, unspent UTxOs. Check that the UTxO exists in the current ledger state and hasn't been consumed by another transaction.".to_string()
        ),
        Phase1Error::OutsideValidityIntervalUTxO { .. } => Some(
            "Adjust the transaction's validity interval to include the current slot. Use 'ttl' and 'validity_start_interval' fields to set appropriate bounds.".to_string()
        ),
        Phase1Error::MaxTxSizeUTxO { .. } => Some(
            "Reduce transaction size by: 1) Combining multiple outputs to the same address, 2) Removing unnecessary metadata or auxiliary data, 3) Using more efficient scripts, 4) Use refenced scripts and datums instead of providing them in the transaction witness set, 5) Splitting into multiple transactions.".to_string()
        ),
        Phase1Error::InputSetEmptyUTxO => Some(
            "Add at least one input UTxO to the transaction. Every transaction must consume at least one UTxO.".to_string()
        ),
        Phase1Error::FeeTooSmallUTxO { .. } => Some(
            "Increase the transaction fee to meet the minimum required amount. Consider the transaction size, script execution costs referenced scripts size, and current protocol parameters when calculating fees.".to_string()
        ),
        Phase1Error::ValueNotConservedUTxO { .. } => Some(
            "Ensure the sum of input values equals the sum of output values plus fees. Account for all native tokens and Ada. Check for missing outputs or incorrect fee calculation.".to_string()
        ),
        Phase1Error::WrongNetwork { .. } => Some(
            "Verify that all output addresses belong to the correct network (mainnet vs testnet). Update addresses to match the target network.".to_string()
        ),
        Phase1Error::WrongNetworkWithdrawal { .. } => Some(
            "Ensure withdrawal reward addresses match the expected network. Check that stake addresses are formatted for the correct network (mainnet vs testnet).".to_string()
        ),
        Phase1Error::WrongNetworkInTxBody { .. } => Some(
            "Set the correct network ID in the transaction body. Use network ID 1 for mainnet and 0 for testnet.".to_string()
        ),
        Phase1Error::OutputTooSmallUTxO { .. } => Some(
            "Increase the Ada amount in the output to meet the minimum UTxO requirement. Consider the size of native assets and datum when calculating the minimum Ada needed.".to_string()
        ),
        Phase1Error::CollateralReturnTooSmall { .. } => Some(
            "Increase the Ada amount in the collateral return output to meet minimum UTxO requirements, or remove the collateral return if not needed. But if you remove the collateral return you have risk of losing all your collateral funds instead of just a part of it.".to_string()
        ),
        Phase1Error::OutputBootAddrAttrsTooBig { .. } => Some(
            "Reduce the size of Byron address attributes or use a Shelley-era address instead. Byron addresses have strict size limitations on their attributes.".to_string()
        ),
        Phase1Error::OutputsValueTooBig { .. } => Some(
            "Reduce the output size by splitting into multiple outputs.".to_string()
        ),
        Phase1Error::InsufficientCollateral { .. } => Some(
            "Add more collateral inputs or increase the Ada amount in existing collateral inputs. Ensure collateral covers the required percentage of the transaction fee.".to_string()
        ),
        Phase1Error::ExUnitsTooBigUTxO { .. } => Some(
            "Optimize Plutus scripts to use fewer execution units, or split the transaction to distribute script execution across multiple transactions.".to_string()
        ),
        Phase1Error::CalculatedCollateralContainsNonAdaAssets => Some(
            "Check the collateral return to be sure that you are return all non-Ada assets. Collateral inputs cannot contain native assets..".to_string()
        ),
        Phase1Error::CollateralInputContainsNonAdaAssets { .. } => Some(
            "Replace the collateral input with an Ada-only UTxO. Collateral inputs must contain only Ada, no native tokens. Otherwise you need to use the collateral return output, to return all non-Ada assets.".to_string()
        ),
        Phase1Error::CollateralIsLockedByScript { .. } => Some(
            "Use UTxOs locked by public keys (not scripts) as collateral inputs. Script-locked UTxOs cannot be used as collateral.".to_string()
        ),
        Phase1Error::TooManyCollateralInputs { .. } => Some(
            "Reduce the number of collateral inputs to stay within the protocol limit. Combine smaller UTxOs into a new one by making a new transaction or use fewer, larger collateral inputs.".to_string()
        ),
        Phase1Error::NoCollateralInputs => Some(
            "Add collateral inputs to the transaction since it includes Plutus script execution. Collateral is required when spending script-locked (by plutus script) UTxOs.".to_string()
        ),
        Phase1Error::IncorrectTotalCollateralField { .. } => Some(
            "Ensure the declared total collateral amount + collateral return output matches the actual sum of collateral input values. Recalculate and update the total collateral field.".to_string()
        ),
        Phase1Error::InvalidSignature { .. } => Some(
            "Verify the signature was created with the correct private key and signing algorithm. Ensure the signature corresponds to the expected public key hash. Check that you signed the correct data".to_string()
        ),
        Phase1Error::ExtraneousSignature { .. } => Some(
            "Remove unnecessary signatures from the transaction witness set. Only include signatures that are required for validation.".to_string()
        ),
        Phase1Error::NativeScriptIsUnsuccessful { .. } => Some(
            "Review the native script conditions and ensure they are satisfied. Check time locks, signature requirements, and script logic.".to_string()
        ),
        Phase1Error::PlutusScriptIsUnsuccessful { .. } => Some(
            "Debug the Plutus script execution. Check the redeemer data, datum, and script context. Ensure the script logic handles all edge cases correctly.".to_string()
        ),
        Phase1Error::MissingVKeyWitnesses { .. } => Some(
            "Add the required verification key signatures to the transaction witness set. Ensure all necessary parties have signed the transaction.".to_string()
        ),
        Phase1Error::MissingScriptWitnesses { .. } => Some(
            "Include the required script in the transaction witness set. Provide both the script code, any necessary redeemers and datums.".to_string()
        ),
        Phase1Error::MissingRedeemer { .. } => Some(
            "Add the required redeemer for the script execution. Ensure the redeemer corresponds to the correct script input or purpose.".to_string()
        ),
        Phase1Error::MissingTxBodyMetadataHash => Some(
            "Either remove the metadata from the transaction or add the metadata hash to the transaction body.".to_string()
        ),
        Phase1Error::MissingTxMetadata => Some(
            "Either add the required metadata to the transaction or remove the metadata hash from the transaction body.".to_string()
        ),
        Phase1Error::ConflictingMetadataHash { .. } => Some(
            "Ensure the metadata hash in the transaction body matches the actual hash of the provided metadata. Recalculate the hash if necessary.".to_string()
        ),
        Phase1Error::InvalidMetadata { .. } => Some(
            "Fix the metadata format to comply with the CBOR specification and Cardano metadata standards. Check for invalid characters or structure.".to_string()
        ),
        Phase1Error::ExtraneousScriptWitnesses { .. } => Some(
            "Remove unnecessary script witnesses from the transaction witness set. Only include scripts that are actually referenced by the transaction.".to_string()
        ),
        Phase1Error::StakeAlreadyRegistered { .. } => Some(
            "The stake key is already registered. Skip the registration or use a different stake key.".to_string()
        ),
        Phase1Error::StakeNotRegistered { .. } => Some(
            "Register the stake key before attempting to delegate or deregister it. Use a stake registration certificate first.".to_string()
        ),
        Phase1Error::StakeNonZeroAccountBalance { .. } => Some(
            "Withdraw all rewards from the stake account before deregistering the stake key. A withdrawal in the same transaction also works: withdrawals are applied before certificates.".to_string()
        ),
        Phase1Error::RewardAccountNotExisting { .. } => Some(
            "Ensure the reward account exists and is properly registered (via stake registration certificate) before attempting to withdraw from it.".to_string()
        ),
        Phase1Error::WrongRequestedWithdrawalAmount { .. } => Some(
            "Update the withdrawal amount to match the exact balance available in the reward account. Check that you are withdrawing from the correct account.".to_string()
        ),
        Phase1Error::StakePoolNotRegistered { .. } => Some(
            "Register the stake pool before attempting to update or retire it. Use a stake pool registration certificate first.".to_string()
        ),
        Phase1Error::WrongRetirementEpoch { .. } => Some(
            "Choose a retirement epoch within the valid range.".to_string()
        ),
        Phase1Error::StakePoolCostTooLow { .. } => Some(
            "Increase the stake pool's fixed cost to meet the minimum required amount set by protocol parameters.".to_string()
        ),
        Phase1Error::InsufficientFundsForMir { .. } => Some(
            "Reduce the MIR (Move Instantaneous Rewards) amount to stay within available treasury or reserve funds.".to_string()
        ),
        Phase1Error::InvalidCommitteeVote { .. } => Some(
            "Ensure the committee member is properly elected and authorized to vote on governance actions.".to_string()
        ),
        Phase1Error::DRepIncorrectDeposit { .. } => Some(
            "Use the correct deposit amount for DRep registration as specified in the current protocol parameters.".to_string()
        ),
        Phase1Error::DRepDeregistrationWrongRefund { .. } => Some(
            "Ensure the refund amount matches the original deposit paid during DRep registration.".to_string()
        ),
        Phase1Error::StakeRegistrationWrongDeposit { .. } => Some(
            "Use the correct deposit amount for stake registration as specified in the current protocol parameters.".to_string()
        ),
        Phase1Error::StakeDeregistrationWrongRefund { .. } => Some(
            "Ensure the refund amount matches the original deposit paid during stake registration.".to_string()
        ),
        Phase1Error::PoolRegistrationWrongDeposit { .. } => Some(
            "Use the correct deposit amount for pool registration as specified in the current protocol parameters.".to_string()
        ),
        Phase1Error::CommitteeHasPreviouslyResigned { .. } => Some(
            "The committee member has already resigned and cannot perform further actions. Use a different committee member.".to_string()
        ),
        Phase1Error::TreasuryValueMismatch { .. } => Some(
            "Ensure the declared treasury value matches the actual current treasury balance.".to_string()
        ),
        Phase1Error::RefScriptsSizeTooBig { .. } => Some(
            "Reduce the total size of reference scripts in the transaction by using smaller scripts or fewer reference scripts.".to_string()
        ),
        Phase1Error::WithdrawalNotAllowedBecauseNotDelegatedToDRep { .. } => Some(
            "Ensure the stake credential is properly delegated to a DRep before attempting withdrawals in Conway era.".to_string()
        ),
        Phase1Error::CommitteeIsUnknown { .. } => Some(
            "Verify the committee credential is properly registered and recognized in the current governance state.".to_string()
        ),
        Phase1Error::GovActionsDoNotExist { .. } => Some(
            "Ensure all referenced governance actions exist and are still active. Check governance action IDs for accuracy.".to_string()
        ),
        Phase1Error::MalformedProposal { .. } => Some(
            "Review the governance proposal format and ensure all required fields are properly filled and valid.".to_string()
        ),
        Phase1Error::ProposalProcedureNetworkIdMismatch { .. } => Some(
            "Ensure the reward account in the proposal procedure matches the expected network (mainnet vs testnet).".to_string()
        ),
        Phase1Error::TreasuryWithdrawalsNetworkIdMismatch { .. } => Some(
            "Verify that treasury withdrawal accounts belong to the correct network (mainnet vs testnet).".to_string()
        ),
        Phase1Error::VotingProposalIncorrectDeposit { .. } => Some(
            "Use the correct deposit amount for proposal submission as specified in the current protocol parameters.".to_string()
        ),
        Phase1Error::DisallowedVoters { .. } => Some(
            "Ensure voters are authorized to vote on the specified governance actions. Check voter eligibility and action types.".to_string()
        ),
        Phase1Error::ConflictingCommitteeUpdate { .. } => Some(
            "Remove the conflicting credentials from either the add or remove sets in the committee update proposal.".to_string()
        ),
        Phase1Error::ExpirationEpochTooSmall { .. } => Some(
            "Set committee member expiration epochs to be sufficiently far in the future according to governance rules.".to_string()
        ),
        Phase1Error::InvalidPrevGovActionId { .. } => Some(
            "Ensure the previous governance action ID is valid and correctly references the predecessor action.".to_string()
        ),
        Phase1Error::VotingOnExpiredGovAction { .. } => Some(
            "Remove votes on expired governance actions. Only vote on currently active proposals.".to_string()
        ),
        Phase1Error::ProposalCantFollow { .. } => Some(
            "Ensure the proposed protocol version follows the correct progression rules from the previous version.".to_string()
        ),
        Phase1Error::InvalidConstitutionPolicyHash { .. } => Some(
            "Verify the constitution policy hash matches the expected value for the proposed constitution.".to_string()
        ),
        Phase1Error::VoterDoNotExist { .. } => Some(
            "Ensure all referenced voters are properly registered in the ledger state before attempting to record their votes.".to_string()
        ),
        Phase1Error::ZeroTreasuryWithdrawals { .. } => Some(
            "Treasury withdrawal proposals must specify a non-zero withdrawal amount. Remove the proposal or add valid withdrawals.".to_string()
        ),
        Phase1Error::ProposalReturnAccountDoesNotExist { .. } => Some(
            "Ensure the proposal return account is properly registered before submitting the governance proposal.".to_string()
        ),
        Phase1Error::TreasuryWithdrawalReturnAccountsDoNotExist { .. } => Some(
            "Verify all treasury withdrawal return accounts exist and are properly registered in the ledger state.".to_string()
        ),
        Phase1Error::AuxiliaryDataHashMismatch { .. } => Some(
            "Ensure the auxiliary data hash in the transaction body matches the actual hash of the provided auxiliary data.".to_string()
        ),
        Phase1Error::AuxiliaryDataHashMissing => Some(
            "Add the auxiliary data hash to the transaction body or remove the auxiliary data from the transaction.".to_string()
        ),
        Phase1Error::AuxiliaryDataHashPresentButNotExpected => Some(
            "Remove the auxiliary data hash from the transaction body if no auxiliary data is provided.".to_string()
        ),
        Phase1Error::GenesisKeyDelegationCertificateIsNotSupported => Some(
            "Genesis key delegation certificates are not supported in this era. Use alternative delegation mechanisms.".to_string()
        ),
        Phase1Error::MoveInstantaneousRewardsCertificateIsNotSupported => Some(
            "Move Instantaneous Rewards (MIR) certificates are not supported in this era. Use governance proposals for treasury operations.".to_string()
        ),
        Phase1Error::UnknownError { .. } => Some(
            "An unexpected error occurred. Check the transaction format and ensure all fields are properly constructed.".to_string()
        ),
        Phase1Error::MissingDatum { .. } => Some(
            "Provide the required datum either: (1) in the witness set (plutus_data field) when using datum hash, or \
            (2) as inline datum in the spending input itself. Datums from reference inputs CANNOT be used for spending validation. \
            Also note that PlutusV1 scripts do not support inline datums, so you must use datum hash in utxo.".to_string()
        ),
        Phase1Error::ExtraneousDatumWitnesses { .. } => Some(
            "Remove unnecessary datum witnesses from the transaction. Only include datums that are actually referenced.".to_string()
        ),
        Phase1Error::ScriptDataHashMismatch { .. } => Some(
            "Ensure the script data hash matches the actual hash of the redeemers, datums and costmodels. Recalculate the hash if necessary.\
            \n\n=== script_data_hash format (Alonzo+ ledger spec) ===\
            \nblake2b256(redeemers || datums || used_cost_models)\
            \nAll components serialized according to ledger CDDL specification.\
            \n\n=== Serialization Details ===\
            \n\n[REDEEMERS]\
            \n- Pre-Conway: array format\
            \n- Conway+: map format\
            \n- Original format from deserialization is preserved\
            \n\n[DATUMS]\
            \n- For hash uses set encoding:\
            \n  * Adds CBOR tag 258 (set semantic)\
            \n  * Deduplicates elements\
            \n  * May use indefinite length encoding\
            \n\n[COST MODELS]\
            \n- For hash uses special encoding:\
            \n  * Keys sorted by length first, then lexicographically\
            \n  * PlutusV1 special case (cardano-node bug workaround):\
            \n    - Key 0 serialized as bytes(0x00) instead of integer\
            \n    - Value wrapped in bytestring containing indefinite-length array\
            \n    - Format: { bytes(0x00): bytes(9F cost1 cost2 ... FF) }\
            \n  * PlutusV2 (key=1) and PlutusV3 (key=2): standard integer key with array value\
            \n\n=== Special Case (datums-only) ===\
            \nIf no redeemers but datums present: 0xA0 || datums || 0xA0\
            \n(0xA0 is empty CBOR map)\
            \n\nCheck the expected_decomposition field for component details.".to_string()
        ),
        Phase1Error::ReferenceInputOverlapsWithInput { .. } => Some(
            "Remove the reference input that overlaps with the input. Reference inputs are not allowed to overlap with inputs.".to_string()
        ),
        Phase1Error::DelegateeDRepNotRegistered { .. } => Some(
            "The vote-delegation certificate targets a DRep that is not registered. Register the DRep first (or include its registration certificate earlier in the transaction), or delegate to AlwaysAbstain / AlwaysNoConfidence which do not require registration.".to_string()
        ),
    }
}

/// Provides helpful hints for resolving Phase 1 validation warnings
pub fn get_warning_hint(warning: &Phase1Warning) -> Option<String> {
    match warning {
        Phase1Warning::FeeIsBiggerThanMinFee { .. } => Some(
            "It might be due inperfection of the fee calculation. But if difference is small, it's ok".to_string()
        ),
        Phase1Warning::InputsAreNotSorted => Some(
            "Sort transaction inputs in canonical order (lexicographically by transaction ID and output index) for better interoperability and deterministic behavior.".to_string()
        ),
        Phase1Warning::WithdrawalsAreNotSorted => Some(
            "Sort transaction withdrawals in canonical order (lexicographically by reward address) for better interoperability and deterministic behavior.".to_string()
        ),
        Phase1Warning::CollateralIsUnnecessary => Some(
            "Remove collateral inputs if the transaction doesn't include Plutus script execution to reduce transaction size and complexity.".to_string()
        ),
        Phase1Warning::TotalCollateralIsNotDeclared => Some(
            "Declare the total collateral amount in the transaction body for better transaction clarity, even though it's optional.".to_string()
        ),
        Phase1Warning::InputUsesRewardAddress { .. } => Some(
            "Consider using a regular payment address (base address or enterprise address) instead of a reward address for transaction inputs, as this is not a common pattern.".to_string()
        ),
        Phase1Warning::CollateralInputUsesRewardAddress { .. } => Some(
            "Use a regular payment address (base address or enterprise address) instead of a reward address.".to_string()
        ),
        Phase1Warning::CannotCheckStakeDeregistrationRefund { .. } => Some(
            "The stake deregistration refund amount cannot be verified. Ensure you're provided required information into validation context for cquisitor.".to_string()
        ),
        Phase1Warning::CannotCheckDRepDeregistrationRefund { .. } => Some(
            "The DRep deregistration refund amount cannot be verified. Ensure you're provided required information into validation context for cquisitor.".to_string()
        ),
        Phase1Warning::PoolAlreadyRegistered { .. } => Some(
            "The stake pool is already registered. It's ok, it just means pool parameters will be updated and you don't need to pay a deposit.".to_string()
        ),
        Phase1Warning::DRepAlreadyRegistered { .. } => Some(
            "The DRep is already registered. Consider using a DRep update certificate instead of registration if you need to modify DRep information.".to_string()
        ),
        Phase1Warning::CommitteeAlreadyAuthorized { .. } => Some(
            "The committee member is already authorized. Verify that this authorization is intentional and not a duplicate action.".to_string()
        ),
        Phase1Warning::DRepNotRegistered { .. } => Some(
            "The DRep is not registered in the ledger state. Consider registering the DRep first before performing other DRep-related actions.".to_string()
        ),
        Phase1Warning::DuplicateRegistrationInTx { .. } => Some(
            "Remove duplicate registration certificates from the same transaction to avoid redundancy and reduce transaction size.".to_string()
        ),
        Phase1Warning::DuplicateCommitteeColdResignationInTx { .. } => Some(
            "Remove duplicate committee cold resignation certificates from the same transaction to avoid redundancy.".to_string()
        ),
        Phase1Warning::DuplicateCommitteeHotRegistrationInTx { .. } => Some(
            "Remove duplicate committee hot registration certificates from the same transaction to avoid redundancy.".to_string()
        ),
        Phase1Warning::DelegationToRetiringPool { .. } => Some(
            "The pool you are delegating to is being retired in the same transaction. The delegation is valid but will only earn rewards until the pool's retirement epoch. Consider delegating to an active pool instead.".to_string()
        ),
    }
}