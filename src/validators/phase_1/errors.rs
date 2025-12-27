use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::collections::HashMap;
use std::collections::HashSet;

use crate::common::TxInput;
use crate::validators::common::ProtocolVersion;

use crate::validators::common::{FeeDecomposition, LocalCredential as Credential, GovernanceActionId, Voter};
use crate::validators::phase_1::hints::get_error_hint;
use crate::validators::phase_1::hints::get_warning_hint;
use crate::validators::value::Value;

#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct ValidationPhase1Error {
    pub error: Phase1Error,
    pub error_message: String,
    pub locations: Vec<String>,
    pub hint: Option<String>,
}

impl ValidationPhase1Error {
    pub fn new(error: Phase1Error, location: String) -> Self {
        let error_message = error.to_string();
        let hint = get_error_hint(&error);
        Self {
            error,
            error_message,
            locations: vec![location],
            hint,
        }
    }

    pub fn new_with_locations(error: Phase1Error, locations: &[String]) -> Self {
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
pub struct ValidationPhase1Warning {
    pub warning: Phase1Warning,
    pub warning_message: String,
    pub locations: Vec<String>,
    pub hint: Option<String>,
}

impl ValidationPhase1Warning {
    pub fn new(warning: Phase1Warning, location: String) -> Self {
        let warning_message = warning.to_string();
        let hint = get_warning_hint(&warning);
        Self {
            warning,
            warning_message,
            locations: vec![location],
            hint,
        }
    }
}

/// Phase 1 validation errors
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub enum Phase1Error {
    /// The transaction references one or more input UTxOs that do not exist or have already been spent
    BadInputsUTxO {
        /// The invalid input UTxO
        invalid_input: TxInput,
    },
    /// The transaction's validity interval is not satisfied by the current slot
    OutsideValidityIntervalUTxO {
        current_slot: u64,
        interval_start: u64,
        interval_end: u64,
    },
    /// The transaction's size in bytes exceeds the protocol's maximum allowed size
    MaxTxSizeUTxO { actual_size: u64, max_size: u64 },
    /// The transaction has an empty input set
    InputSetEmptyUTxO,
    /// The transaction fee is below the minimum required
    FeeTooSmallUTxO { 
        actual_fee: u64,
        min_fee: u64,
        fee_decomposition: FeeDecomposition,
    },
    /// The transaction fails the value conservation check
    ValueNotConservedUTxO {
        input_sum: Value,
        output_sum: Value,
        difference: Value,
    },
    /// One or more output addresses have a network ID that does not match the chain's network
    WrongNetwork { wrong_addresses: HashSet<String> },
    /// One or more withdrawal reward accounts have a network ID that doesn't match the expected network
    WrongNetworkWithdrawal { wrong_addresses: HashSet<String> },
    /// The network ID specified in the transaction body is incorrect
    WrongNetworkInTxBody {
        actual_network: u8,
        expected_network: u8,
    },
    /// One or more transaction outputs contain less than the minimum required amount of Ada
    OutputTooSmallUTxO {
        output_amount: i128,
        min_amount: i128,
    },
    /// The collateral return is too small
    CollateralReturnTooSmall {
        output_amount: i128,
        min_amount: i128,
    },
    /// A transaction output to a Byron-era address has attributes that are too large
    OutputBootAddrAttrsTooBig {
        output: serde_json::Value,
        actual_size: u64,
        max_size: u64,
    },
    /// One or more transaction outputs are too large in size
    OutputsValueTooBig {
        actual_size: u32,
        max_size: u32,
    },
    /// The transaction's collateral inputs do not cover the required collateral amount
    InsufficientCollateral {
        total_collateral: i128,
        required_collateral: i128,
    },
    /// The total execution units requested by the transaction's Plutus scripts exceed the allowed maximum
    ExUnitsTooBigUTxO { 
        actual_memory_units: u64,
        actual_steps_units: u64,
        max_memory_units: u64,
        max_steps_units: u64,
    },
    /// The collateral inputs contain non-ADA assets
    CalculatedCollateralContainsNonAdaAssets,
    /// The collateral input contains non-ADA assets
    CollateralInputContainsNonAdaAssets { collateral_input: String },
    /// The collateral inputs are locked by a script
    CollateralIsLockedByScript { invalid_collateral: String },
    /// The number of collateral inputs exceeds the maximum allowed
    TooManyCollateralInputs { actual_count: u32, max_count: u32 },
    /// The transaction marked as requiring script execution has no collateral inputs
    NoCollateralInputs,
    /// The total collateral amount declared does not match the sum of the provided collateral inputs
    IncorrectTotalCollateralField {
        declared_total: i128,
        actual_sum: i128,
    },
    /// Invalid signature
    InvalidSignature {
        invalid_signature: String,
    },
    /// Extraneous signature
    ExtraneousSignature {
        extraneous_signature: String,
    },
    /// Native script is unsuccessful
    NativeScriptIsUnsuccessful {
        native_script_hash: String,
    },
    /// Plutus script is unsuccessful
    PlutusScriptIsUnsuccessful {
        plutus_script_hash: String,
    },
    /// The transaction is missing required verification key witnesses
    MissingVKeyWitnesses { missing_key_hash: String },
    /// A needed script is not provided
    MissingScriptWitnesses {
        missing_script_hash: String,
    },
    /// A required redeemer is not provided
    MissingRedeemer {
        tag: String,
        index: u32,
    },
    /// The transaction body indicated a metadata hash, but the actual metadata was not included
    MissingTxBodyMetadataHash,
    /// The transaction includes metadata, but the transaction body's metadata hash field is absent
    MissingTxMetadata,
    /// The metadata hash in the transaction body does not match the hash of the actual metadata
    ConflictingMetadataHash {
        expected_hash: String,
        actual_hash: String,
    },
    /// The metadata payload is invalid
    InvalidMetadata { message: String },
    /// The transaction supplied script witnesses that are not needed
    ExtraneousScriptWitnesses { extraneous_script: String },
    /// A stake registration certificate attempted to register an already registered stake key
    StakeAlreadyRegistered { reward_address: String },
    /// A stake key deregistration or delegation was attempted for an unregistered stake key
    StakeNotRegistered { reward_address: String },
    /// A stake key deregistration attempted while reward account still has unwithdrawn rewards
    StakeNonZeroAccountBalance {
        reward_address: String,
        remaining_balance: u64,
    },
    /// A withdrawal attempted from a non-existent reward account
    RewardAccountNotExisting { reward_address: String },
    /// Wrong requested withdrawal amount
    WrongRequestedWithdrawalAmount {
        expected_amount: i128,
        requested_amount: i128,
        reward_address: String,
    },
    /// A stake pool retirement or update attempted for a non-existent pool
    StakePoolNotRegistered { pool_id: String },
    /// The epoch specified for a stake pool's retirement is invalid
    WrongRetirementEpoch {
        specified_epoch: u64,
        current_epoch: u64,
        min_epoch: u64,
        max_epoch: u64,
    },
    /// A stake pool's cost parameter is below the minimum fixed fee
    StakePoolCostTooLow { specified_cost: u64, min_cost: u64 },
    /// An MIR certificate attempted to withdraw more than available
    InsufficientFundsForMir {
        requested_amount: u64,
        available_amount: u64,
    },
    /// Constitutional Committee vote by non-elected member
    InvalidCommitteeVote { voter: serde_json::Value, message: String },
    /// DRep registration deposit mismatch
    DRepIncorrectDeposit {
        supplied_deposit: i128,
        required_deposit: i128,
    },
    /// DRep deregistration refund mismatch
    DRepDeregistrationWrongRefund {
        supplied_refund: i128,
        required_refund: i128,
    },
    /// Stake registration deposit mismatch
    StakeRegistrationWrongDeposit {
        supplied_deposit: i128,
        required_deposit: i128,
    },
    /// Stake deregistration refund mismatch
    StakeDeregistrationWrongRefund {
        supplied_refund: i128,
        required_refund: i128,
    },
    /// Pool registration deposit mismatch
    PoolRegistrationWrongDeposit {
        supplied_deposit: i128,
        required_deposit: i128,
    },
    /// Committee member has previously resigned
    CommitteeHasPreviouslyResigned { committee_credential: Credential },
    /// Treasury value mismatch
    TreasuryValueMismatch {
        declared_value: u64,
        actual_value: u64,
    },
    /// Reference scripts size too big
    RefScriptsSizeTooBig { actual_size: u64, max_size: u64 },
    /// Withdrawal from stake credential not delegated to DRep
    WithdrawalNotAllowedBecauseNotDelegatedToDRep { reward_address: String },
    /// The transaction attempts to reference or update a committee cold credential that is not recognized
    CommitteeIsUnknown {
        /// The committee key hash
        committee_key_hash: Credential,
    },
    /// Governance actions referenced in the transaction do not exist
    GovActionsDoNotExist {
        /// The list of invalid governance action IDs
        invalid_action_ids: Vec<GovernanceActionId>,
    },
    /// The proposal is malformed (e.g. invalid parameter updates)
    MalformedProposal {
        /// The invalid governance action
        gov_action: GovernanceActionId,
    },
    /// Network ID mismatch in proposal procedure
    ProposalProcedureNetworkIdMismatch {
        /// The reward account
        reward_account: String,
        /// The expected network ID
        expected_network: u8,
    },
    /// Network ID mismatch in treasury withdrawals
    TreasuryWithdrawalsNetworkIdMismatch {
        /// The set of mismatched reward accounts
        mismatched_account: String,
        /// The expected network ID
        expected_network: u8,
    },
    /// The proposal deposit amount is incorrect
    VotingProposalIncorrectDeposit {
        /// The supplied deposit amount
        supplied_deposit: i128,
        /// The required deposit amount
        required_deposit: i128,
        proposal_index: u32,
    },
    /// Voters are not allowed to vote on certain governance actions
    DisallowedVoters {
        /// List of disallowed voter and action ID pairs
        disallowed_pairs: Vec<(Voter, GovernanceActionId)>,
    },
    /// Conflicting committee update (same credentials in remove and add sets)
    ConflictingCommitteeUpdate {
        /// The set of conflicting credentials
        conflicting_credentials: Credential,
    },
    /// Committee member expiration epochs are too small
    ExpirationEpochTooSmall {
        /// Map of credentials to their invalid expiration epochs
        invalid_expirations: HashMap<Credential, u64>,
    },
    /// Invalid previous governance action ID in proposal
    InvalidPrevGovActionId {
        /// The invalid proposal
        proposal: serde_json::Value,
    },
    /// Voting attempted on expired governance actions
    VotingOnExpiredGovAction {
        /// The expired governance action
        expired_gov_action: GovernanceActionId,
    },
    /// Protocol version cannot follow previous version
    ProposalCantFollow {
        /// Previous governance action ID
        prev_gov_action_id: Option<GovernanceActionId>,
        /// The supplied protocol version
        supplied_version: ProtocolVersion,
        /// The expected protocol version
        expected_versions: Vec<ProtocolVersion>,
    },
    /// Invalid constitution policy hash
    InvalidConstitutionPolicyHash {
        /// The supplied policy hash
        supplied_hash: Option<String>,
        /// The expected policy hash
        expected_hash: Option<String>,
    },
    /// Referenced voters do not exist in the ledger state
    VoterDoNotExist {
        /// List of non-existent voters
        missing_voter: serde_json::Value,
    },
    /// Treasury withdrawals sum to zero (not allowed)
    ZeroTreasuryWithdrawals {
        /// The governance action with zero withdrawals
        gov_action: GovernanceActionId,
    },
    /// Proposal return account does not exist
    ProposalReturnAccountDoesNotExist {
        /// The invalid return account
        return_account: String,
    },
    /// Treasury withdrawal return accounts do not exist
    TreasuryWithdrawalReturnAccountsDoNotExist {
        /// List of non-existent return accounts
        missing_account: String,
    },
    /// Auxiliary data hash mismatch
    AuxiliaryDataHashMismatch {
        /// The expected auxiliary data hash
        expected_hash: String,
        /// The actual auxiliary data hash
        actual_hash: Option<String>,
    },
    /// Auxiliary data hash is missing
    AuxiliaryDataHashMissing,
    /// Auxiliary data hash is present but not expected
    AuxiliaryDataHashPresentButNotExpected,
    GenesisKeyDelegationCertificateIsNotSupported,
    MoveInstantaneousRewardsCertificateIsNotSupported,
    /// Unknown error
    UnknownError {
        message: String,
    },
    MissingDatum {
        datum_hash: String,
    },
    ExtraneousDatumWitnesses {
        datum_hash: String,
    },
    /// Script data hash mismatch
    ScriptDataHashMismatch {
        /// The expected script data hash
        expected_hash: Option<String>,
        /// The actual script data hash
        provided_hash: Option<String>,
    },
    ReferenceInputOverlapsWithInput {
        input: TxInput,
    },
}

impl Phase1Error {
    pub fn to_string(&self) -> String {
        match self {
            Self::BadInputsUTxO { invalid_input } => {
                        format!(
                            "Transaction contains invalid or already spent input UTxO: {:?}",
                            invalid_input
                        )
                    }
            Self::OutsideValidityIntervalUTxO {
                        current_slot,
                        interval_start,
                        interval_end,
                    } => {
                        format!(
                            "Transaction validity interval [{}..{}] does not contain current slot {}",
                            interval_start, interval_end, current_slot
                        )
                    }
            Self::MaxTxSizeUTxO {
                        actual_size,
                        max_size,
                    } => {
                        format!(
                            "Transaction size ({} bytes) exceeds maximum allowed size ({} bytes)",
                            actual_size, max_size
                        )
                    }
            Self::InputSetEmptyUTxO => "Transaction has no inputs".to_string(),
            Self::FeeTooSmallUTxO {
                        actual_fee,
                        min_fee,
                        fee_decomposition,
                    } => {
                        format!(
                            "Transaction fee ({} lovelace) is below minimum required fee ({} lovelace). Fee decomposition: {:?}",
                            actual_fee, min_fee, fee_decomposition
                        )
                    }
            Self::ValueNotConservedUTxO {
                        input_sum,
                        output_sum,
                        difference,
                    } => {
                        format!(
                            "Value not conserved. Inputs: {}, Outputs: {}, Difference: {}",
                            input_sum.to_string(), output_sum.to_string(), difference.to_string()
                        )
                    }
            Self::WrongNetwork { wrong_addresses } => {
                        format!(
                            "Output addresses belong to wrong network: {:?}",
                            wrong_addresses
                        )
                    }
            Self::WrongNetworkWithdrawal { wrong_addresses } => {
                        format!(
                            "Withdrawal addresses belong to wrong network: {:?}",
                            wrong_addresses
                        )
                    }
            Self::WrongNetworkInTxBody {
                        actual_network,
                        expected_network,
                    } => {
                        format!(
                            "Transaction network ID mismatch. Expected: {}, Found: {}",
                            expected_network, actual_network
                        )
                    }
            Self::OutputTooSmallUTxO {
                        output_amount,
                        min_amount,
                    } => {
                        format!("Output contains {} lovelace, which is below minimum required amount of {} lovelace", output_amount, min_amount)
                    }
            Self::OutputBootAddrAttrsTooBig {
                        output: _,
                        actual_size,
                        max_size,
                    } => {
                        format!(
                            "Byron address attributes too large: {} bytes (maximum: {} bytes)",
                            actual_size, max_size
                        )
                    }
            Self::OutputsValueTooBig {
                        actual_size,
                        max_size,
                    } => {
                        format!(
                            "Transaction outputs value exceeds maximum size of {} bytes: {:?}",
                            max_size, actual_size
                        )
                    }
            Self::InsufficientCollateral {
                        total_collateral,
                        required_collateral,
                    } => {
                        format!(
                            "Insufficient collateral: {} lovelace provided, {} lovelace required",
                            total_collateral, required_collateral
                        )
                    }
            Self::TooManyCollateralInputs {
                        actual_count,
                        max_count,
                    } => {
                        format!(
                            "Too many collateral inputs: {} (maximum: {})",
                            actual_count, max_count
                        )
                    }
            Self::NoCollateralInputs => {
                        "Transaction requires script execution but has no collateral inputs".to_string()
                    }
            Self::IncorrectTotalCollateralField {
                        declared_total,
                        actual_sum,
                    } => {
                        format!(
                            "Declared total collateral ({}) does not match actual sum ({})",
                            declared_total, actual_sum
                        )
                    }
            Self::InvalidSignature { invalid_signature } => {
                        format!("Invalid signature: {:?}", invalid_signature)
                    }
            Self::ExtraneousSignature { extraneous_signature } => {
                        format!("Extraneous signature: {:?}", extraneous_signature)
                    }
            Self::NativeScriptIsUnsuccessful { native_script_hash } => {
                        format!("Native script is unsuccessful: {:?}", native_script_hash)
                    }
            Self::PlutusScriptIsUnsuccessful { plutus_script_hash } => {
                        format!("Plutus script is unsuccessful: {:?}", plutus_script_hash)
                    }
            Self::MissingVKeyWitnesses { missing_key_hash } => {
                        format!(
                            "Missing required verification key witnesses: {:?}",
                            missing_key_hash
                        )
                    }
            Self::MissingScriptWitnesses {
                        missing_script_hash,
                    } => {
                        format!(
                            "Missing required script witnesses: {:?}",
                            missing_script_hash
                        )
                    }
            Self::MissingRedeemer { tag, index } => {
                        format!(
                            "Missing required redeemer for tag {} at index {}",
                            tag, index
                        )
                    }
            Self::MissingTxBodyMetadataHash => {
                        "Transaction metadata present but metadata hash missing from transaction body"
                            .to_string()
                    }
            Self::MissingTxMetadata => {
                        "Transaction body indicates metadata but no metadata provided".to_string()
                    }
            Self::ConflictingMetadataHash {
                        expected_hash,
                        actual_hash,
                    } => {
                        format!(
                            "Metadata hash mismatch. Expected: {}, Found: {}",
                            expected_hash, actual_hash
                        )
                    }
            Self::InvalidMetadata { message } => {
                        format!("Invalid metadata: {}", message)
                    }
            Self::ExtraneousScriptWitnesses { extraneous_script } => {
                        format!(
                            "Unnecessary script witness provided: {}",
                            extraneous_script
                        )
                    }
            Self::StakeAlreadyRegistered { reward_address } => {
                        format!("Stake key already registered: {:?}", reward_address)
                    }
            Self::StakeNotRegistered { reward_address } => {
                        format!("Stake key not registered: {:?}", reward_address)
                    }
            Self::StakeNonZeroAccountBalance {
                        reward_address,
                        remaining_balance,
                    } => {
                        format!(
                            "Cannot deregister stake key with non-zero balance ({} lovelace): {:?}",
                            remaining_balance, reward_address
                        )
                    }
            Self::RewardAccountNotExisting { reward_address } => {
                        format!("Reward account does not exist: {:?}", reward_address)
                    }
            Self::StakePoolNotRegistered { pool_id } => {
                        format!("Stake pool not registered: {:?}", pool_id)
                    }
            Self::WrongRetirementEpoch {
                        specified_epoch,
                        current_epoch,
                        min_epoch,
                        max_epoch,
                    } => {
                        format!("Invalid pool retirement epoch {}. Must be between {} and {} (current epoch: {})", 
                            specified_epoch, min_epoch, max_epoch, current_epoch)
                    }
            Self::StakePoolCostTooLow {
                        specified_cost,
                        min_cost,
                    } => {
                        format!(
                            "Stake pool cost {} is below minimum required {}",
                            specified_cost, min_cost
                        )
                    }
            Self::InsufficientFundsForMir {
                        requested_amount,
                        available_amount,
                    } => {
                        format!(
                            "Insufficient funds for MIR. Requested: {}, Available: {}",
                            requested_amount, available_amount
                        )
                    }
            Self::InvalidCommitteeVote { voter, message } => {
                        format!("Invalid committee vote by {:?}: {}", voter, message)
                    }
            Self::DRepIncorrectDeposit {
                        supplied_deposit,
                        required_deposit,
                    } => {
                        format!(
                            "Incorrect DRep deposit. Supplied: {}, Required: {}",
                            supplied_deposit, required_deposit
                        )
                    }
            Self::CommitteeHasPreviouslyResigned { committee_credential } => {
                        format!(
                            "Committee member has previously resigned: {:?}",
                            committee_credential
                        )
                    }
            Self::TreasuryValueMismatch {
                        declared_value,
                        actual_value,
                    } => {
                        format!(
                            "Treasury value mismatch. Declared: {}, Actual: {}",
                            declared_value, actual_value
                        )
                    }
            Self::RefScriptsSizeTooBig {
                        actual_size,
                        max_size,
                    } => {
                        format!("Total reference scripts size ({} bytes) exceeds maximum allowed ({} bytes) in the transaction", actual_size, max_size)
                    }
            Self::WithdrawalNotAllowedBecauseNotDelegatedToDRep { reward_address } => {
                        format!(
                            "Withdrawal attempted from stake credential not delegated to DRep: {:?}",
                            reward_address
                        )
                    }
            Self::CommitteeIsUnknown { committee_key_hash } => {
                        format!(
                            "Unknown committee cold credential: {:?}",
                            committee_key_hash
                        )
                    }
            Self::GovActionsDoNotExist { invalid_action_ids } => {
                        format!(
                            "Referenced governance actions do not exist: {:?}",
                            invalid_action_ids
                        )
                    }
            Self::MalformedProposal { gov_action } => {
                        format!("Malformed governance proposal: {:?}", gov_action)
                    }
            Self::ProposalProcedureNetworkIdMismatch {
                        reward_account,
                        expected_network,
                    } => {
                        format!("Network ID mismatch in proposal procedure. Account: {:?}, Expected network: {}", reward_account, expected_network)
                    }
            Self::TreasuryWithdrawalsNetworkIdMismatch {
                        mismatched_account,
                        expected_network,
                    } => {
                        format!("Network ID mismatch in treasury withdrawal. Account: {:?}, Expected network: {}", mismatched_account, expected_network)
                    }
            Self::VotingProposalIncorrectDeposit {
                        supplied_deposit,
                        required_deposit,
                        proposal_index,
                    } => {
                        format!(
                            "Incorrect proposal deposit. Supplied: {}, Required: {}, Proposal index: {}",
                            supplied_deposit, required_deposit, proposal_index
                        )
                    }
            Self::DisallowedVoters { disallowed_pairs } => {
                        format!(
                            "Voters not allowed for specified governance actions: {:?}",
                            disallowed_pairs
                        )
                    }
            Self::ConflictingCommitteeUpdate {
                        conflicting_credentials,
                    } => {
                        format!(
                            "Conflicting committee update - same credentials in remove and add sets: {:?}",
                            conflicting_credentials
                        )
                    }
            Self::ExpirationEpochTooSmall {
                        invalid_expirations,
                    } => {
                        format!(
                            "Committee member expiration epochs are too small: {:?}",
                            invalid_expirations
                        )
                    }
            Self::InvalidPrevGovActionId { proposal } => {
                        format!(
                            "Invalid previous governance action ID in proposal: {:?}",
                            proposal
                        )
                    }
            Self::VotingOnExpiredGovAction { expired_gov_action } => {
                        format!(
                            "Attempted voting on expired governance actions: {:?}",
                            expired_gov_action
                        )
                    }
            Self::ProposalCantFollow {
                        prev_gov_action_id,
                        supplied_version,
                        expected_versions,
                    } => {
                        format!("Invalid protocol version progression. Previous action: {:?}, Supplied: {:?}, Expected: {:?}", 
                            prev_gov_action_id, supplied_version, expected_versions)
                    }
            Self::InvalidConstitutionPolicyHash {
                        supplied_hash,
                        expected_hash,
                    } => {
                        format!(
                            "Invalid constitution policy hash. Supplied: {:?}, Expected: {:?}",
                            supplied_hash, expected_hash
                        )
                    }
            Self::VoterDoNotExist { missing_voter } => {
                        format!(
                            "Referenced voters do not exist in ledger state: {:?}",
                            serde_json::to_string(&missing_voter).unwrap()
                        )
                    }
            Self::ZeroTreasuryWithdrawals { gov_action } => {
                        format!(
                            "Treasury withdrawals sum to zero for governance action: {:?}",
                            gov_action
                        )
                    }
            Self::ProposalReturnAccountDoesNotExist { return_account } => {
                        format!(
                            "Proposal return account does not exist: {:?}",
                            return_account
                        )
                    }
            Self::TreasuryWithdrawalReturnAccountsDoNotExist { missing_account } => {
                        format!(
                            "Treasury withdrawal return account does not exist: {:?}",
                            missing_account
                        )
                    }
            Self::ExUnitsTooBigUTxO { actual_memory_units, actual_steps_units, max_memory_units, max_steps_units } => {
                        format!("Transaction exec   ution units exceed maximum allowed. Memory units: {}, Steps units: {}, Max memory units: {}, Max steps units: {}", actual_memory_units, actual_steps_units, max_memory_units, max_steps_units)
                    }
            Self::AuxiliaryDataHashMismatch {
                        expected_hash,
                        actual_hash,
                    } => {
                        format!(
                            "Auxiliary data hash mismatch. Expected: {}, Found: {}",
                            expected_hash, actual_hash.as_ref().unwrap_or(&"None".to_string())
                        )
                    }
            Self::AuxiliaryDataHashMissing => "Auxiliary data hash is missing".to_string(),
            Self::AuxiliaryDataHashPresentButNotExpected => {
                        "Auxiliary data hash is present but not expected".to_string()
                    }
            Self::CollateralIsLockedByScript { invalid_collateral } => {
                        format!(
                            "Collateral input is locked by a script: {:?}",
                            invalid_collateral
                        )
                    }
            Self::CollateralReturnTooSmall { output_amount, min_amount } => {
                format!("Collateral return is too small. Output amount: {}, Min amount: {}", output_amount, min_amount)
            }
            Self::CalculatedCollateralContainsNonAdaAssets => {
                "Calculated collateral contains non-ADA assets".to_string()
            }
            Self::CollateralInputContainsNonAdaAssets { collateral_input } => {
                format!("Collateral input contains non-ADA assets: {:?}", collateral_input)
            }
            Self::WrongRequestedWithdrawalAmount { expected_amount, requested_amount, reward_address } => {
                format!("Wrong requested withdrawal amount. Expected: {}, Requested: {}, Reward address: {}", expected_amount, requested_amount, reward_address)
            }
            Self::DRepDeregistrationWrongRefund { supplied_refund, required_refund } => {
                format!("DRep deregistration refund mismatch. Supplied: {}, Required: {}", supplied_refund, required_refund)
            }
            Self::StakeRegistrationWrongDeposit { supplied_deposit, required_deposit } => {
                format!("Stake registration deposit mismatch. Supplied: {}, Required: {}", supplied_deposit, required_deposit)
            }
            Self::StakeDeregistrationWrongRefund { supplied_refund, required_refund } => {
                format!("Stake deregistration refund mismatch. Supplied: {}, Required: {}", supplied_refund, required_refund)
            }
            Self::PoolRegistrationWrongDeposit { supplied_deposit, required_deposit } => {
                format!("Pool registration deposit mismatch. Supplied: {}, Required: {}", supplied_deposit, required_deposit)
            }
            Self::GenesisKeyDelegationCertificateIsNotSupported => {
                "Genesis key delegation certificate is not supported".to_string()
            }
            Self::MoveInstantaneousRewardsCertificateIsNotSupported => {
                "Move instantaneous rewards certificate is not supported".to_string()
            }
            Self::UnknownError { message } => {
                format!("Unknown error. Seems something went wrong. Message: {}", message)
            },
            Self::MissingDatum { datum_hash } => {
                format!("Datum {} not found in witness set or as inline datum in the spending input", datum_hash)
            },
            Self::ExtraneousDatumWitnesses { datum_hash } => {
                format!("Extraneous datum witnesses provided: {}", datum_hash)
            }
            Self::ScriptDataHashMismatch { expected_hash, provided_hash } => {
                format!("Script data hash mismatch. Expected: {}, Found: {}", expected_hash.as_ref().unwrap_or(&"None".to_string()), provided_hash.as_ref().unwrap_or(&"None".to_string()))
            },
            Self::ReferenceInputOverlapsWithInput { input } => {
                format!("Reference input overlaps with input: {:?}", input)
            },
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub enum Phase1Warning {
    FeeIsBiggerThanMinFee {
        actual_fee: u64,
        min_fee: u64,
        fee_decomposition: FeeDecomposition,
    },
    InputsAreNotSorted,
    WithdrawalsAreNotSorted,
    CollateralIsUnnecessary,
    TotalCollateralIsNotDeclared,
    /// The transaction's collateral input uses a reward address
    InputUsesRewardAddress {
        invalid_input: String,
    },
    /// The transaction's collateral input uses a reward address
    CollateralInputUsesRewardAddress {
        invalid_collateral: String,
    },
    /// Cannot check stake key deregistration refund
    CannotCheckStakeDeregistrationRefund,
    /// Cannot check DRep deregistration refund
    CannotCheckDRepDeregistrationRefund,
    /// Pool already registered
    PoolAlreadyRegistered {
        pool_id: String,
    },
    /// DRep already registered
    DRepAlreadyRegistered {
        drep_id: String,
    },
    /// Committee already authorized
    CommitteeAlreadyAuthorized {
        committee_key: String,
    },
    /// DRep not registered
    DRepNotRegistered {
        cert_index: u32,
    },
    /// Duplicate registration attempt in the same transaction
    DuplicateRegistrationInTx {
        entity_type: String,
        entity_id: String,
        cert_index: u32,
    },
    DuplicateCommitteeColdResignationInTx {  
        committee_credential: Credential,
        cert_index: u32,
    },
    DuplicateCommitteeHotRegistrationInTx {  
        committee_credential: Credential,
        cert_index: u32,
    },
}

impl Phase1Warning {
    pub fn to_string(&self) -> String {
        match self {
            Self::FeeIsBiggerThanMinFee { actual_fee, min_fee, fee_decomposition } => {
                        format!("Transaction fee ({} lovelace) is larger than minimum required fee ({} lovelace). Fee decomposition: {:?}", actual_fee, min_fee, fee_decomposition  )
                    }
            Self::InputsAreNotSorted => "Transaction inputs are not in canonical order".to_string(),
            Self::WithdrawalsAreNotSorted => "Transaction withdrawals are not in canonical order".to_string(),
            Self::CollateralIsUnnecessary => "Collateral input is unnecessary".to_string(),
            Self::TotalCollateralIsNotDeclared => "Total collateral is not declared".to_string(),
            Self::InputUsesRewardAddress { invalid_input } => {
                        format!(
                            "Transaction input uses a reward address: {:?}",
                            invalid_input
                        )
                    }
            Self::CollateralInputUsesRewardAddress { invalid_collateral } => {
                        format!(
                            "Transaction collateral input uses a reward address: {:?}",
                            invalid_collateral
                        )
                    }
            Self::PoolAlreadyRegistered { pool_id } => {
                        format!("Pool already registered: {}", pool_id)
                    }
            Self::DRepAlreadyRegistered { drep_id } => {
                        format!("DRep already registered: {}", drep_id)
                    }
            Self::CommitteeAlreadyAuthorized { committee_key } => {
                        format!("Committee already authorized: {}", committee_key)
                    }
            Self::DRepNotRegistered { cert_index } => {
                        format!("DRep not registered for certificate at index: {}", cert_index)
                    }
            Self::DuplicateRegistrationInTx { entity_type, entity_id, cert_index } => {
                        format!("Duplicate registration attempt in the same transaction. Entity type: {}, Entity ID: {}, Certificate index: {}", entity_type, entity_id, cert_index)
                    }
            Self::CannotCheckStakeDeregistrationRefund => {
                "Cannot check stake deregistration refund".to_string()
            },
            Self::CannotCheckDRepDeregistrationRefund => {
                "Cannot check DRep deregistration refund".to_string()
            },
            Self::DuplicateCommitteeColdResignationInTx { committee_credential, cert_index } => {
                format!("Duplicate committee cold resignation in the same transaction. Committee credential: {}, Certificate index: {}", committee_credential, cert_index)
            },
            Self::DuplicateCommitteeHotRegistrationInTx { committee_credential, cert_index } => {
                format!("Duplicate committee hot registration in the same transaction. Committee credential: {}, Certificate index: {}", committee_credential, cert_index)
            },
        }
    }
}
