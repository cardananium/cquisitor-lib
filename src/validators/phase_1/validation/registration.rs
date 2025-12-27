use cardano_serialization_lib as csl;
use std::collections::{HashMap, HashSet};

use crate::validators::{
    common::LocalCredential,
    helpers::{credential_to_bech32_reward_address, csl_credential_to_local_credential},
    input_contexts::ValidationInputContext,
    phase_1::errors::{
        Phase1Error, Phase1Warning, ValidationPhase1Error, ValidationPhase1Warning,
    },
    validation_result::ValidationResult,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RegistrableEntity {
    Account(String),
    Pool(String),
    DRep(String),
    ConstitutionCommitteeHotCredential(LocalCredential),
}

#[derive(Debug, Clone)]
struct CertificateInfo {
    cert_index: u32,
    cert_type: CertificateType,
}

#[derive(Debug, Clone)]
enum CertificateType {
    StakeRegistration {
        reward_address: String,
    },
    StakeDeregistration {
        reward_address: String,
    },
    StakeDelegation {
        reward_address: String,
        pool_id: String,
    },
    PoolRegistration {
        pool_id: String,
        pool_cost: u64,
    },
    PoolRetirement {
        pool_id: String,
        retirement_epoch: u64,
    },
    DRepRegistration {
        drep_id: String,
    },
    DRepDeregistration {
        drep_id: String,
    },
    DRepUpdate {
        drep_id: String,
    },
    CommitteeHotAuth {
        committee_cold_credential: LocalCredential,
        committee_hot_credential: LocalCredential,
    },
    CommitteeColdResign {
        committee_cold_credential: LocalCredential,
    },
    StakeRegistrationAndDelegation {
        reward_address: String,
        pool_id: String,
    },
    StakeAndVoteDelegation {
        reward_address: String,
        pool_id: String,
        drep: String,
    },
    StakeVoteRegistrationAndDelegation {
        reward_address: String,
        pool_id: String,
        drep: String,
    },
    VoteDelegation {
        reward_address: String,
        drep: String,
    },
    VoteRegistrationAndDelegation {
        reward_address: String,
        drep: String,
    },
    GenesisKeyDelegation,
    MoveInstantaneousRewardsCert,
}

#[derive(Debug)]
struct RegistrationState {
    /// Tracks which entities are registered at the start of tx processing
    initial_registrations: HashSet<RegistrableEntity>,
    /// Tracks registration changes made by certificates in this tx
    /// Maps entity to the cert_index of the FIRST certificate that registered it
    registrations_in_tx: HashMap<RegistrableEntity, u32>,
    deregistrations_in_tx: HashSet<RegistrableEntity>,
    /// Pool retirements scheduled in this tx
    pool_retirements_in_tx: HashMap<String, u64>, // pool_id -> retirement_epoch
    /// Committee resignations in this tx
    committee_resignations_in_tx: HashSet<LocalCredential>,
}

pub struct RegistrationValidator<'a> {
    certificates: Vec<CertificateInfo>,
    registration_state: RegistrationState,
    validation_input_context: &'a ValidationInputContext,
}

impl<'a> RegistrationValidator<'a> {
    pub fn new(
        tx_body: &'a csl::TransactionBody,
        validation_input_context: &'a ValidationInputContext,
    ) -> Self {
        let mut certificates = Vec::new();
        let mut registration_state = RegistrationState {
            initial_registrations: HashSet::new(),
            registrations_in_tx: HashMap::new(),
            deregistrations_in_tx: HashSet::new(),
            pool_retirements_in_tx: HashMap::new(),
            committee_resignations_in_tx: HashSet::new(),
        };

        // Load initial registration state from validation context
        Self::load_initial_state(&mut registration_state, validation_input_context);

        // Process certificates and collect information
        if let Some(certs) = tx_body.certs() {
            let certs_count = certs.len();
            for i in 0..certs_count {
                let cert = certs.get(i);
                if let Some(cert_info) =
                    Self::process_certificate(&cert, i as u32, validation_input_context)
                {
                    Self::update_state(&mut registration_state, &cert_info.cert_type, cert_info.cert_index);
                    certificates.push(cert_info);
                }
            }
        }

        Self {
            certificates,
            registration_state,
            validation_input_context,
        }
    }

    fn load_initial_state(state: &mut RegistrationState, context: &ValidationInputContext) {
        // Load registered accounts
        for account in &context.account_contexts {
            if account.is_registered {
                state
                    .initial_registrations
                    .insert(RegistrableEntity::Account(account.bech32_address.clone()));
            }
        }

        // Load registered pools
        for pool in &context.pool_contexts {
            if pool.is_registered {
                state
                    .initial_registrations
                    .insert(RegistrableEntity::Pool(pool.pool_id.clone()));
            }
        }

        // Load registered DReps
        for drep in &context.drep_contexts {
            if drep.is_registered {
                state
                    .initial_registrations
                    .insert(RegistrableEntity::DRep(drep.bech32_drep.clone()));
            }
        }
    }

    fn process_certificate(
        cert: &csl::Certificate,
        cert_index: u32,
        context: &ValidationInputContext,
    ) -> Option<CertificateInfo> {
        let cert_type = match cert.kind() {
            csl::CertificateKind::StakeRegistration => {
                if let Some(reg_cert) = cert.as_stake_registration() {
                    let stake_credential = reg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    Some(CertificateType::StakeRegistration { reward_address })
                } else {
                    None
                }
            }
            csl::CertificateKind::StakeDeregistration => {
                if let Some(dereg_cert) = cert.as_stake_deregistration() {
                    let stake_credential = dereg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    Some(CertificateType::StakeDeregistration { reward_address })
                } else {
                    None
                }
            }
            csl::CertificateKind::StakeDelegation => {
                if let Some(deleg_cert) = cert.as_stake_delegation() {
                    let stake_credential = deleg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    let pool_id = deleg_cert.pool_keyhash().to_hex();
                    Some(CertificateType::StakeDelegation {
                        reward_address,
                        pool_id,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::PoolRegistration => {
                if let Some(pool_reg_cert) = cert.as_pool_registration() {
                    let pool_params = pool_reg_cert.pool_params();
                    let pool_id = pool_params.operator().to_hex();
                    let pool_cost = pool_params.cost().into();
                    Some(CertificateType::PoolRegistration { pool_id, pool_cost })
                } else {
                    None
                }
            }
            csl::CertificateKind::PoolRetirement => {
                if let Some(pool_ret_cert) = cert.as_pool_retirement() {
                    let pool_id = pool_ret_cert.pool_keyhash().to_hex();
                    let retirement_epoch: u64 = pool_ret_cert.epoch().into();
                    Some(CertificateType::PoolRetirement {
                        pool_id,
                        retirement_epoch,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::DRepRegistration => {
                if let Some(drep_reg_cert) = cert.as_drep_registration() {
                    let drep_credential = drep_reg_cert.voting_credential();
                    let drep = csl::DRep::new_from_credential(&drep_credential);
                    let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                    Some(CertificateType::DRepRegistration { drep_id })
                } else {
                    None
                }
            }
            csl::CertificateKind::DRepDeregistration => {
                if let Some(drep_dereg_cert) = cert.as_drep_deregistration() {
                    let drep_credential = drep_dereg_cert.voting_credential();
                    let drep = csl::DRep::new_from_credential(&drep_credential);
                    let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                    Some(CertificateType::DRepDeregistration { drep_id })
                } else {
                    None
                }
            }
            csl::CertificateKind::CommitteeHotAuth => {
                if let Some(committee_auth_cert) = cert.as_committee_hot_auth() {
                    let committee_cold_credential =
                        csl_credential_to_local_credential(&committee_auth_cert.committee_cold_credential());
                    let committee_hot_credential =
                        csl_credential_to_local_credential(&committee_auth_cert.committee_hot_credential());
                    Some(CertificateType::CommitteeHotAuth {
                        committee_cold_credential,
                        committee_hot_credential,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::CommitteeColdResign => {
                if let Some(committee_resign_cert) = cert.as_committee_cold_resign() {
                    let committee_cold_credential =
                        csl_credential_to_local_credential(&committee_resign_cert.committee_cold_credential());
                    Some(CertificateType::CommitteeColdResign {
                        committee_cold_credential,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::StakeRegistrationAndDelegation => {
                if let Some(reg_deleg_cert) = cert.as_stake_registration_and_delegation() {
                    let stake_credential = reg_deleg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    let pool_id = reg_deleg_cert.pool_keyhash().to_hex();
                    Some(CertificateType::StakeRegistrationAndDelegation {
                        reward_address,
                        pool_id,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::DRepUpdate => {
                if let Some(drep_update_cert) = cert.as_drep_update() {
                    let drep_credential = drep_update_cert.voting_credential();
                    let drep = csl::DRep::new_from_credential(&drep_credential);
                    let drep_id = drep.to_bech32(true).unwrap_or_else(|_| "".to_string());
                    Some(CertificateType::DRepUpdate { drep_id })
                } else {
                    None
                }
            }
            csl::CertificateKind::StakeAndVoteDelegation => {
                if let Some(stake_vote_deleg_cert) = cert.as_stake_and_vote_delegation() {
                    let stake_credential = stake_vote_deleg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    let pool_id = stake_vote_deleg_cert.pool_keyhash().to_hex();
                    let drep = stake_vote_deleg_cert
                        .drep()
                        .to_bech32(true)
                        .unwrap_or_else(|_| "".to_string());
                    Some(CertificateType::StakeAndVoteDelegation {
                        reward_address,
                        pool_id,
                        drep,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::StakeVoteRegistrationAndDelegation => {
                if let Some(stake_vote_reg_deleg_cert) =
                    cert.as_stake_vote_registration_and_delegation()
                {
                    let stake_credential = stake_vote_reg_deleg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    let pool_id = stake_vote_reg_deleg_cert.pool_keyhash().to_hex();
                    let drep = stake_vote_reg_deleg_cert
                        .drep()
                        .to_bech32(true)
                        .unwrap_or_else(|_| "".to_string());
                    Some(CertificateType::StakeVoteRegistrationAndDelegation {
                        reward_address,
                        pool_id,
                        drep,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::VoteDelegation => {
                if let Some(vote_deleg_cert) = cert.as_vote_delegation() {
                    let stake_credential = vote_deleg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    let drep = vote_deleg_cert
                        .drep()
                        .to_bech32(true)
                        .unwrap_or_else(|_| "".to_string());
                    Some(CertificateType::VoteDelegation {
                        reward_address,
                        drep,
                    })
                } else {
                    None
                }
            }
            csl::CertificateKind::VoteRegistrationAndDelegation => {
                if let Some(vote_reg_deleg_cert) = cert.as_vote_registration_and_delegation() {
                    let stake_credential = vote_reg_deleg_cert.stake_credential();
                    let reward_address = credential_to_bech32_reward_address(
                        &stake_credential,
                        &context.network_type,
                    );
                    let drep = vote_reg_deleg_cert
                        .drep()
                        .to_bech32(true)
                        .unwrap_or_else(|_| "".to_string());
                    Some(CertificateType::VoteRegistrationAndDelegation {
                        reward_address,
                        drep,
                    })
                } else {
                    None
                }
            }
            // These certificate types are not supported
            csl::CertificateKind::GenesisKeyDelegation => {
                Some(CertificateType::GenesisKeyDelegation)
            }
            csl::CertificateKind::MoveInstantaneousRewardsCert => {
                Some(CertificateType::MoveInstantaneousRewardsCert)
            }
        };

        cert_type.map(|cert_type| CertificateInfo {
            cert_index,
            cert_type,
        })
    }

    fn update_state(state: &mut RegistrationState, cert_type: &CertificateType, cert_index: u32) {
        match cert_type {
            CertificateType::StakeRegistration { reward_address, .. }
            | CertificateType::StakeRegistrationAndDelegation { reward_address, .. }
            | CertificateType::StakeVoteRegistrationAndDelegation { reward_address, .. }
            | CertificateType::VoteRegistrationAndDelegation { reward_address, .. } => {
                // Only insert if not already present (keeps the first cert_index)
                state
                    .registrations_in_tx
                    .entry(RegistrableEntity::Account(reward_address.clone()))
                    .or_insert(cert_index);
                state
                    .deregistrations_in_tx
                    .remove(&RegistrableEntity::Account(reward_address.clone()));
            }
            CertificateType::StakeDeregistration { reward_address, .. } => {
                state
                    .deregistrations_in_tx
                    .insert(RegistrableEntity::Account(reward_address.clone()));
                state
                    .registrations_in_tx
                    .remove(&RegistrableEntity::Account(reward_address.clone()));
            }
            CertificateType::PoolRegistration { pool_id, .. } => {
                // Only insert if not already present (keeps the first cert_index)
                state
                    .registrations_in_tx
                    .entry(RegistrableEntity::Pool(pool_id.clone()))
                    .or_insert(cert_index);
                state.pool_retirements_in_tx.remove(pool_id);
            }
            CertificateType::PoolRetirement {
                pool_id,
                retirement_epoch,
            } => {
                state
                    .pool_retirements_in_tx
                    .insert(pool_id.clone(), *retirement_epoch);
            }
            CertificateType::DRepRegistration { drep_id } => {
                // Only insert if not already present (keeps the first cert_index)
                state
                    .registrations_in_tx
                    .entry(RegistrableEntity::DRep(drep_id.clone()))
                    .or_insert(cert_index);
                state
                    .deregistrations_in_tx
                    .remove(&RegistrableEntity::DRep(drep_id.clone()));
            }
            CertificateType::DRepDeregistration { drep_id } => {
                state
                    .deregistrations_in_tx
                    .insert(RegistrableEntity::DRep(drep_id.clone()));
                state
                    .registrations_in_tx
                    .remove(&RegistrableEntity::DRep(drep_id.clone()));
            }
            CertificateType::DRepUpdate { .. } => {
                // DRep updates don't affect registration state
            }
            CertificateType::CommitteeColdResign {
                committee_cold_credential,
            } => {
                state
                    .committee_resignations_in_tx
                    .insert(committee_cold_credential.clone());
            }
            CertificateType::StakeDelegation { .. }
            | CertificateType::StakeAndVoteDelegation { .. }
            | CertificateType::VoteDelegation { .. }
            | CertificateType::CommitteeHotAuth { .. } => {
                // These don't affect registration state
            }
            CertificateType::GenesisKeyDelegation
            | CertificateType::MoveInstantaneousRewardsCert => {
                // These certificate types don't affect registration state
            }
        }
    }

    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Calculate epoch parameters
        let slots_per_epoch = 432000u64; // Standard epoch length in slots (5 days)
        let current_epoch = self.validation_input_context.slot / slots_per_epoch;

        for cert_info in &self.certificates {
            self.validate_certificate(&cert_info, current_epoch, &mut errors, &mut warnings);
        }

        ValidationResult::new_phase_1(errors, warnings)
    }

    fn validate_certificate(
        &self,
        cert_info: &CertificateInfo,
        current_epoch: u64,
        errors: &mut Vec<ValidationPhase1Error>,
        warnings: &mut Vec<ValidationPhase1Warning>,
    ) {
        match &cert_info.cert_type {
            CertificateType::StakeRegistration { reward_address } => {
                let entity = RegistrableEntity::Account(reward_address.clone());

                // Check for duplicate registration in the same transaction
                // Only warn if a PREVIOUS certificate already registered this entity
                if let Some(&first_cert_index) = self.registration_state.registrations_in_tx.get(&entity) {
                    if first_cert_index < cert_info.cert_index {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DuplicateRegistrationInTx {
                                entity_type: "stake key".to_string(),
                                entity_id: reward_address.clone(),
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                // Check if already registered (either initially or in this tx)
                if self
                    .registration_state
                    .initial_registrations
                    .contains(&entity)
                    && !self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&entity)
                {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeAlreadyRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::StakeDeregistration { reward_address } => {
                let entity = RegistrableEntity::Account(reward_address.clone());
                let is_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&entity);
                let is_deregistered = self
                    .registration_state
                    .deregistrations_in_tx
                    .contains(&entity);

                if !is_registered || is_deregistered {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeNotRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                } else {
                    // Check balance
                    if let Some(account_context) = self
                        .validation_input_context
                        .find_account_context(reward_address)
                    {
                        if let Some(balance) = account_context.balance {
                            if balance > 0 {
                                errors.push(ValidationPhase1Error::new(
                                    Phase1Error::StakeNonZeroAccountBalance {
                                        reward_address: reward_address.clone(),
                                        remaining_balance: balance,
                                    },
                                    format!("transaction.body.certs.{}", cert_info.cert_index),
                                ));
                            }
                        }
                    }
                }
            }
            CertificateType::StakeDelegation {
                reward_address,
                pool_id,
            } => {
                // Check if stake key is registered
                let account_entity = RegistrableEntity::Account(reward_address.clone());
                let is_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&account_entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&account_entity);
                let is_deregistered = self
                    .registration_state
                    .deregistrations_in_tx
                    .contains(&account_entity);

                if !is_registered || is_deregistered {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeNotRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if pool is registered
                let pool_entity = RegistrableEntity::Pool(pool_id.clone());
                let is_pool_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&pool_entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&pool_entity);
                let is_pool_retiring = self
                    .registration_state
                    .pool_retirements_in_tx
                    .contains_key(pool_id);

                if !is_pool_registered || is_pool_retiring {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakePoolNotRegistered {
                            pool_id: pool_id.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::PoolRegistration { pool_id, pool_cost } => {
                let entity = RegistrableEntity::Pool(pool_id.clone());

                // Check for duplicate registration in the same transaction
                // Only warn if a PREVIOUS certificate already registered this entity
                if let Some(&first_cert_index) = self.registration_state.registrations_in_tx.get(&entity) {
                    if first_cert_index < cert_info.cert_index {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DuplicateRegistrationInTx {
                                entity_type: "pool".to_string(),
                                entity_id: pool_id.clone(),
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                // Check pool cost
                let min_pool_cost = self
                    .validation_input_context
                    .protocol_parameters
                    .min_pool_cost;
                if *pool_cost < min_pool_cost {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakePoolCostTooLow {
                            specified_cost: *pool_cost,
                            min_cost: min_pool_cost,
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if pool is already registered (warning only)
                if self
                    .registration_state
                    .initial_registrations
                    .contains(&entity)
                    && !self
                        .registration_state
                        .pool_retirements_in_tx
                        .contains_key(pool_id)
                {
                    warnings.push(ValidationPhase1Warning::new(
                        Phase1Warning::PoolAlreadyRegistered {
                            pool_id: pool_id.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::PoolRetirement {
                pool_id,
                retirement_epoch,
            } => {
                // Check if pool is registered
                let entity = RegistrableEntity::Pool(pool_id.clone());
                let is_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&entity);

                if !is_registered {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakePoolNotRegistered {
                            pool_id: pool_id.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check retirement epoch validity
                let min_retirement_epoch = current_epoch + 1;
                let max_retirement_epoch = current_epoch
                    + self
                        .validation_input_context
                        .protocol_parameters
                        .max_epoch_for_pool_retirement as u64;

                if *retirement_epoch < min_retirement_epoch
                    || *retirement_epoch > max_retirement_epoch
                {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::WrongRetirementEpoch {
                            specified_epoch: *retirement_epoch,
                            current_epoch,
                            min_epoch: min_retirement_epoch,
                            max_epoch: max_retirement_epoch,
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::DRepRegistration { drep_id } => {
                let entity = RegistrableEntity::DRep(drep_id.clone());

                // Check for duplicate registration in the same transaction
                // Only warn if a PREVIOUS certificate already registered this entity
                if let Some(&first_cert_index) = self.registration_state.registrations_in_tx.get(&entity) {
                    if first_cert_index < cert_info.cert_index {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DuplicateRegistrationInTx {
                                entity_type: "DRep".to_string(),
                                entity_id: drep_id.clone(),
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                // DRep re-registration is typically allowed for updates
                if self
                    .registration_state
                    .initial_registrations
                    .contains(&entity)
                    && !self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&entity)
                {
                    warnings.push(ValidationPhase1Warning::new(
                        Phase1Warning::DRepAlreadyRegistered {
                            drep_id: drep_id.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::DRepDeregistration { drep_id } => {
                // Check if DRep is registered
                let entity = RegistrableEntity::DRep(drep_id.clone());
                let is_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&entity);
                let is_deregistered = self
                    .registration_state
                    .deregistrations_in_tx
                    .contains(&entity);

                if !is_registered || is_deregistered {
                    warnings.push(ValidationPhase1Warning::new(
                        Phase1Warning::DRepNotRegistered {
                            cert_index: cert_info.cert_index,
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::StakeRegistrationAndDelegation {
                reward_address,
                pool_id,
            } => {
                let account_entity = RegistrableEntity::Account(reward_address.clone());

                // Check for duplicate registration in the same transaction
                // Only warn if a PREVIOUS certificate already registered this entity
                if let Some(&first_cert_index) = self.registration_state.registrations_in_tx.get(&account_entity) {
                    if first_cert_index < cert_info.cert_index {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DuplicateRegistrationInTx {
                                entity_type: "stake key".to_string(),
                                entity_id: reward_address.clone(),
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                // Check if stake key is already registered
                if self
                    .registration_state
                    .initial_registrations
                    .contains(&account_entity)
                    && !self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&account_entity)
                {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeAlreadyRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if pool is registered
                let pool_entity = RegistrableEntity::Pool(pool_id.clone());
                let is_pool_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&pool_entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&pool_entity);
                let is_pool_retiring = self
                    .registration_state
                    .pool_retirements_in_tx
                    .contains_key(pool_id);

                if !is_pool_registered || is_pool_retiring {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakePoolNotRegistered {
                            pool_id: pool_id.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::DRepUpdate { drep_id } => {
                // Check if DRep is registered
                let entity = RegistrableEntity::DRep(drep_id.clone());
                let is_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&entity);
                let is_deregistered = self
                    .registration_state
                    .deregistrations_in_tx
                    .contains(&entity);

                if !is_registered || is_deregistered {
                    warnings.push(ValidationPhase1Warning::new(
                        Phase1Warning::DRepNotRegistered {
                            cert_index: cert_info.cert_index,
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::StakeAndVoteDelegation {
                reward_address,
                pool_id,
                drep,
            } => {
                // Check if stake key is registered
                let account_entity = RegistrableEntity::Account(reward_address.clone());
                let is_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&account_entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&account_entity);
                let is_deregistered = self
                    .registration_state
                    .deregistrations_in_tx
                    .contains(&account_entity);

                if !is_registered || is_deregistered {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeNotRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if pool is registered
                let pool_entity = RegistrableEntity::Pool(pool_id.clone());
                let is_pool_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&pool_entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&pool_entity);
                let is_pool_retiring = self
                    .registration_state
                    .pool_retirements_in_tx
                    .contains_key(pool_id);

                if !is_pool_registered || is_pool_retiring {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakePoolNotRegistered {
                            pool_id: pool_id.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if DRep is registered (if not empty)
                if !drep.is_empty() {
                    let drep_entity = RegistrableEntity::DRep(drep.clone());
                    let is_drep_registered = self
                        .registration_state
                        .initial_registrations
                        .contains(&drep_entity)
                        || self
                            .registration_state
                            .registrations_in_tx
                            .contains_key(&drep_entity);
                    let is_drep_deregistered = self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&drep_entity);

                    if !is_drep_registered || is_drep_deregistered {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DRepNotRegistered {
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }
            }
            CertificateType::StakeVoteRegistrationAndDelegation {
                reward_address,
                pool_id,
                drep,
            } => {
                let account_entity = RegistrableEntity::Account(reward_address.clone());

                // Check for duplicate registration in the same transaction
                // Only warn if a PREVIOUS certificate already registered this entity
                if let Some(&first_cert_index) = self.registration_state.registrations_in_tx.get(&account_entity) {
                    if first_cert_index < cert_info.cert_index {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DuplicateRegistrationInTx {
                                entity_type: "stake key".to_string(),
                                entity_id: reward_address.clone(),
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                // Check if stake key is already registered
                if self
                    .registration_state
                    .initial_registrations
                    .contains(&account_entity)
                    && !self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&account_entity)
                {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeAlreadyRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if pool is registered
                let pool_entity = RegistrableEntity::Pool(pool_id.clone());
                let is_pool_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&pool_entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&pool_entity);
                let is_pool_retiring = self
                    .registration_state
                    .pool_retirements_in_tx
                    .contains_key(pool_id);

                if !is_pool_registered || is_pool_retiring {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakePoolNotRegistered {
                            pool_id: pool_id.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if DRep is registered (if not empty)
                if !drep.is_empty() {
                    let drep_entity = RegistrableEntity::DRep(drep.clone());
                    let is_drep_registered = self
                        .registration_state
                        .initial_registrations
                        .contains(&drep_entity)
                        || self
                            .registration_state
                            .registrations_in_tx
                            .contains_key(&drep_entity);
                    let is_drep_deregistered = self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&drep_entity);

                    if !is_drep_registered || is_drep_deregistered {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DRepNotRegistered {
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }
            }
            CertificateType::VoteDelegation {
                reward_address,
                drep,
            } => {
                // Check if stake key is registered
                let account_entity = RegistrableEntity::Account(reward_address.clone());
                let is_registered = self
                    .registration_state
                    .initial_registrations
                    .contains(&account_entity)
                    || self
                        .registration_state
                        .registrations_in_tx
                        .contains_key(&account_entity);
                let is_deregistered = self
                    .registration_state
                    .deregistrations_in_tx
                    .contains(&account_entity);

                if !is_registered || is_deregistered {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeNotRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if DRep is registered (if not empty)
                if !drep.is_empty() {
                    let drep_entity = RegistrableEntity::DRep(drep.clone());
                    let is_drep_registered = self
                        .registration_state
                        .initial_registrations
                        .contains(&drep_entity)
                        || self
                            .registration_state
                            .registrations_in_tx
                            .contains_key(&drep_entity);
                    let is_drep_deregistered = self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&drep_entity);

                    if !is_drep_registered || is_drep_deregistered {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DRepNotRegistered {
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }
            }
            CertificateType::VoteRegistrationAndDelegation {
                reward_address,
                drep,
            } => {
                let account_entity = RegistrableEntity::Account(reward_address.clone());

                // Check for duplicate registration in the same transaction
                // Only warn if a PREVIOUS certificate already registered this entity
                if let Some(&first_cert_index) = self.registration_state.registrations_in_tx.get(&account_entity) {
                    if first_cert_index < cert_info.cert_index {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DuplicateRegistrationInTx {
                                entity_type: "stake key".to_string(),
                                entity_id: reward_address.clone(),
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                // Check if stake key is already registered
                if self
                    .registration_state
                    .initial_registrations
                    .contains(&account_entity)
                    && !self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&account_entity)
                {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::StakeAlreadyRegistered {
                            reward_address: reward_address.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if DRep is registered (if not empty)
                if !drep.is_empty() {
                    let drep_entity = RegistrableEntity::DRep(drep.clone());
                    let is_drep_registered = self
                        .registration_state
                        .initial_registrations
                        .contains(&drep_entity)
                        || self
                            .registration_state
                            .registrations_in_tx
                            .contains_key(&drep_entity);
                    let is_drep_deregistered = self
                        .registration_state
                        .deregistrations_in_tx
                        .contains(&drep_entity);

                    if !is_drep_registered || is_drep_deregistered {
                        warnings.push(ValidationPhase1Warning::new(
                            Phase1Warning::DRepNotRegistered {
                                cert_index: cert_info.cert_index,
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }
            }
            CertificateType::GenesisKeyDelegation => {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::GenesisKeyDelegationCertificateIsNotSupported,
                    format!("transaction.body.certs.{}", cert_info.cert_index),
                ));
            }
            CertificateType::MoveInstantaneousRewardsCert => {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::MoveInstantaneousRewardsCertificateIsNotSupported,
                    format!("transaction.body.certs.{}", cert_info.cert_index),
                ));
            }
            CertificateType::CommitteeHotAuth {
                committee_cold_credential,
                committee_hot_credential,
            } => {

                // Check if committee member has already resigned in this transaction
                if self
                    .registration_state
                    .committee_resignations_in_tx
                    .contains(&committee_cold_credential)
                {
                    warnings.push(ValidationPhase1Warning::new(
                        Phase1Warning::DuplicateCommitteeHotRegistrationInTx {
                            committee_credential: committee_hot_credential.clone(),
                            cert_index: cert_info.cert_index,
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if committee member has already resigned
                if self
                    .registration_state
                    .committee_resignations_in_tx
                    .contains(&committee_cold_credential)
                {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::CommitteeHasPreviouslyResigned {
                            committee_credential: committee_hot_credential.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if committee member has already resigned previously
                if let Some(current_member) = self
                    .validation_input_context
                    .find_current_committee_member_by_cold_credential(&committee_cold_credential)
                {
                    if current_member.is_resigned {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::CommitteeHasPreviouslyResigned {
                                committee_credential: committee_hot_credential.clone(),
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                } else if let Some(potential_member) = self
                    .validation_input_context
                    .find_potential_committee_member_by_cold_credential(&committee_cold_credential)
                {
                    if potential_member.is_resigned {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::CommitteeHasPreviouslyResigned {
                                committee_credential: committee_hot_credential.clone(),
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                // Check if committee cold key is in the list of potential committee members
                let is_potential_member = self
                    .validation_input_context
                    .find_potential_committee_member_by_cold_credential(&committee_cold_credential)
                    .is_some();
                let is_current_member = self
                    .validation_input_context
                    .find_current_committee_member_by_cold_credential(&committee_cold_credential)
                    .is_some();
                
                if !is_potential_member && !is_current_member {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::CommitteeIsUnknown {
                            committee_key_hash: committee_cold_credential.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
            CertificateType::CommitteeColdResign {
                committee_cold_credential,
            } => {

                // Check if committee member has already resigned previously
                if let Some(current_member) = self
                    .validation_input_context
                    .find_current_committee_member_by_cold_credential(&committee_cold_credential)
                {
                    if current_member.is_resigned {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::CommitteeHasPreviouslyResigned {
                                committee_credential: committee_cold_credential.clone(),
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                } else if let Some(potential_member) = self
                    .validation_input_context
                    .find_potential_committee_member_by_cold_credential(&committee_cold_credential)
                {
                    if potential_member.is_resigned {
                        errors.push(ValidationPhase1Error::new(
                            Phase1Error::CommitteeHasPreviouslyResigned {
                                committee_credential: committee_cold_credential.clone(),
                            },
                            format!("transaction.body.certs.{}", cert_info.cert_index),
                        ));
                    }
                }

                if self
                    .registration_state
                    .committee_resignations_in_tx
                    .contains(&committee_cold_credential)
                {
                    warnings.push(ValidationPhase1Warning::new(
                        Phase1Warning::DuplicateCommitteeColdResignationInTx {
                            committee_credential: committee_cold_credential.clone(),
                            cert_index: cert_info.cert_index,
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }

                // Check if committee cold key is actually a valid committee member
                let is_potential_member = self
                    .validation_input_context
                    .find_potential_committee_member_by_cold_credential(&committee_cold_credential)
                    .is_some();
                let is_current_member = self
                    .validation_input_context
                    .find_current_committee_member_by_cold_credential(&committee_cold_credential)
                    .is_some();
                
                if !is_potential_member && !is_current_member {
                    errors.push(ValidationPhase1Error::new(
                        Phase1Error::CommitteeIsUnknown {
                            committee_key_hash: committee_cold_credential.clone(),
                        },
                        format!("transaction.body.certs.{}", cert_info.cert_index),
                    ));
                }
            }
        }
    }
}
