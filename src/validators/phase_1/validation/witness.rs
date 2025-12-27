use crate::{
    js_error::JsError,
    validators::{
        helpers::{normalize_script_ref, string_to_csl_address},
        input_contexts::ValidationInputContext,
        phase_1::{
            converter::pp_cost_model_to_csl,
            errors::{Phase1Error, ValidationPhase1Error},
            validation::NativeScriptExecutor,
        },
        validation_result::ValidationResult,
    },
};
use cardano_serialization_lib::{self as csl, Redeemers};
use std::collections::{BTreeSet, HashMap, HashSet};

pub enum ScriptType {
    NativeScript,
    PlutusScript,
    UnknownScript,
}

#[derive(Debug, Clone)]
pub enum WitnessSource {
    /// Witness provided in witness set
    WitnessSet(u32),
    /// Script available through reference input
    ReferenceInput(csl::TransactionInput, u32),
    Input(csl::TransactionInput, u32),
}

impl WitnessSource {
    pub fn get_location(&self, entity_name: &str) -> String {
        match self {
            WitnessSource::WitnessSet(i) => {
                format!("transaction.witness_set.{}.{}", entity_name, i)
            }
            WitnessSource::ReferenceInput(_, i) => format!("transaction.reference_inputs.{}", i),
            WitnessSource::Input(_, i) => format!("transaction.inputs.{}", i),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequiredVKeyWitness {
    pub key_hash: csl::Ed25519KeyHash,
    pub location: String,
    pub entity_index: u32,
}

#[derive(Debug, Clone)]
pub struct RequiredScriptWitness {
    pub script_hash: csl::ScriptHash,
    pub location: String,
    pub entity_index: u32,
}

#[derive(Debug, Clone)]
pub struct RequiredRedeemerWitness {
    pub tag: csl::RedeemerTag,
    pub index: u32,
    pub location: String,
    pub entity_index: u32,
}

#[derive(Debug, Clone)]
pub struct RequiredDatumWitness {
    pub datum_hash: csl::DataHash,
    pub location: String,
    pub entity_index: u32,
}

pub struct WitnessValidator<'a> {
    /// Required VKey witnesses
    pub required_vkey_witnesses: Vec<RequiredVKeyWitness>,
    /// Required native script witnesses
    pub required_native_script_witnesses: Vec<RequiredScriptWitness>,
    /// Required plutus script witnesses
    pub required_plutus_script_witnesses: Vec<RequiredScriptWitness>,
    /// Required redeemer witnesses
    pub required_redeemer_witnesses: Vec<RequiredRedeemerWitness>,
    /// Required datum witnesses
    pub required_datum_witnesses: Vec<RequiredDatumWitness>,
    /// Required unknown script witnesses
    pub required_unknown_script_witnesses: Vec<RequiredScriptWitness>,
    /// Set of provided VKey witnesses
    pub provided_vkey_witnesses: HashMap<csl::Ed25519KeyHash, u32>,
    /// Map of native script hashes to their sources
    pub native_script_sources: HashMap<csl::ScriptHash, WitnessSource>,
    pub provided_native_scripts: HashMap<csl::ScriptHash, csl::NativeScript>,
    pub native_scripts_signature_candidates: HashSet<csl::Ed25519KeyHash>,
    /// Map of plutus script hashes to their sources
    pub plutus_script_sources: HashMap<csl::ScriptHash, WitnessSource>,
    pub plutus_script_versions: HashMap<csl::ScriptHash, csl::Language>,
    /// Map of datum hashes to their sources
    pub datum_sources: HashMap<csl::DataHash, WitnessSource>,
    pub output_datums_hashes: HashSet<csl::DataHash>,
    /// Set of provided redeemers by (tag, index)
    pub provided_redeemers: HashSet<(csl::RedeemerTag, u32)>,
    /// Validation context
    pub validation_input_context: &'a ValidationInputContext,

    pub invalid_signatures: HashMap<csl::Ed25519KeyHash, u32>,
    pub valid_signatures: HashMap<csl::Ed25519KeyHash, u32>,
    pub invalid_native_scripts: HashMap<csl::ScriptHash, WitnessSource>,
    pub used_plutus_versions: HashSet<csl::LanguageKind>,
    pub expected_script_data_hash: Option<String>,
    pub provided_script_data_hash: Option<String>,
}

impl<'a> WitnessValidator<'a> {
    pub fn new(
        tx_body: &csl::TransactionBody,
        tx_witness_set: &csl::TransactionWitnessSet,
        tx_hash: &csl::TransactionHash,
        validation_input_context: &'a ValidationInputContext,
    ) -> Result<Self, JsError> {
        let mut context = Self {
            required_vkey_witnesses: Vec::new(),
            required_native_script_witnesses: Vec::new(),
            required_plutus_script_witnesses: Vec::new(),
            required_redeemer_witnesses: Vec::new(),
            required_datum_witnesses: Vec::new(),
            required_unknown_script_witnesses: Vec::new(),
            provided_vkey_witnesses: HashMap::new(),
            native_script_sources: HashMap::new(),
            provided_native_scripts: HashMap::new(),
            native_scripts_signature_candidates: HashSet::new(),
            plutus_script_sources: HashMap::new(),
            plutus_script_versions: HashMap::new(),
            datum_sources: HashMap::new(),
            output_datums_hashes: HashSet::new(),
            provided_redeemers: HashSet::new(),
            validation_input_context,
            invalid_signatures: HashMap::new(),
            valid_signatures: HashMap::new(),
            invalid_native_scripts: HashMap::new(),
            used_plutus_versions: HashSet::new(),
            provided_script_data_hash: None,
            expected_script_data_hash: None,
        };

        // Collect all provided witnesses
        context
            .collect_provided_witnesses(tx_body, tx_witness_set, tx_hash)
            .map_err(|e| JsError::new(&format!("Failed to collect provided witnesses: {}", e)))?;

        // Collect all required witnesses
        context.collect_required_witnesses(tx_body);

        // Fill native_scripts_signature_candidates
        context.collect_native_scripts_signature_candidates();

        context.collect_output_datums_hashes(tx_body);

        context.collect_invalid_native_scripts().map_err(|e| {
            JsError::new(&format!("Failed to collect invalid native scripts: {}", e))
        })?;

        context.collect_used_plutus_versions();

        context
            .collect_script_data_hash(tx_body, tx_witness_set)
            .map_err(|e| JsError::new(&format!("Failed to collect script data hash: {}", e)))?;

        Ok(context)
    }

    fn collect_script_data_hash(
        &mut self,
        tx_body: &csl::TransactionBody,
        tx_witness_set: &csl::TransactionWitnessSet,
    ) -> Result<(), String> {
        let script_data_hash = self.calulucate_actual_script_data_hash(tx_witness_set)?;
        self.expected_script_data_hash = script_data_hash;

        let provided_script_data_hash = tx_body.script_data_hash();
        self.provided_script_data_hash = provided_script_data_hash.map(|hash| hash.to_hex());

        Ok(())
    }

    fn collect_used_plutus_versions(&mut self) {
        for witness in &self.required_plutus_script_witnesses {
            if let Some(plutus_script_version) =
                self.plutus_script_versions.get(&witness.script_hash)
            {
                self.used_plutus_versions
                    .insert(plutus_script_version.kind());
            }
        }
    }

    fn collect_invalid_native_scripts(&mut self) -> Result<(), String> {
        let signatures = self.provided_vkey_witnesses.keys().cloned().collect();
        let slot = self.validation_input_context.slot;
        for (_i, required_native_script_witness) in
            self.required_native_script_witnesses.iter().enumerate()
        {
            let script_hash = &required_native_script_witness.script_hash;
            if let Some(native_script) = self.provided_native_scripts.get(&script_hash) {
                let executor = NativeScriptExecutor::new(native_script, &signatures, slot);
                match executor.execute() {
                    Ok(result) => {
                        if !result {
                            let source = self.native_script_sources.get(script_hash).unwrap();
                            self.invalid_native_scripts
                                .insert(script_hash.clone(), source.clone());
                        }
                    }
                    Err(e) => {
                        return Err(format!("Failed to execute native script: {}", e));
                    }
                }
            }
        }
        Ok(())
    }

    fn collect_output_datums_hashes(&mut self, tx_body: &csl::TransactionBody) {
        let outputs = tx_body.outputs();
        for i in 0..outputs.len() {
            let output = outputs.get(i);
            if let Some(datum_hash) = output.data_hash() {
                self.output_datums_hashes.insert(datum_hash);
            }
        }
    }

    fn collect_provided_witnesses(
        &mut self,
        tx_body: &csl::TransactionBody,
        tx_witness_set: &csl::TransactionWitnessSet,
        tx_hash: &csl::TransactionHash,
    ) -> Result<(), String> {
        let witness_set = tx_witness_set;

        // VKey witnesses
        if let Some(vkey_witnesses) = witness_set.vkeys() {
            for i in 0..vkey_witnesses.len() {
                let vkey_witness = vkey_witnesses.get(i);
                let public_key = vkey_witness.vkey().public_key();
                let key_hash = public_key.hash();
                self.provided_vkey_witnesses
                    .insert(key_hash.clone(), i as u32);

                if !public_key.verify(&tx_hash.to_bytes(), &vkey_witness.signature()) {
                    self.invalid_signatures.insert(key_hash.clone(), i as u32);
                } else {
                    self.valid_signatures.insert(key_hash.clone(), i as u32);
                }
            }
        }

        // Native scripts
        if let Some(native_scripts) = witness_set.native_scripts() {
            for i in 0..native_scripts.len() {
                let script = native_scripts.get(i);
                let script_hash = script.hash();
                self.provided_native_scripts
                    .insert(script_hash.clone(), script.clone());
                self.native_script_sources
                    .insert(script_hash, WitnessSource::WitnessSet(i as u32));
            }
        }

        // Plutus scripts
        if let Some(plutus_scripts) = witness_set.plutus_scripts() {
            for i in 0..plutus_scripts.len() {
                let script = plutus_scripts.get(i);
                let script_hash = script.hash();
                self.plutus_script_sources
                    .insert(script_hash.clone(), WitnessSource::WitnessSet(i as u32));
                self.plutus_script_versions
                    .insert(script_hash.clone(), script.language_version());
            }
        }

        // Plutus data (datums)
        if let Some(plutus_data) = witness_set.plutus_data() {
            for i in 0..plutus_data.len() {
                let datum = plutus_data.get(i);
                let datum_hash = csl::hash_plutus_data(&datum);
                self.datum_sources
                    .insert(datum_hash, WitnessSource::WitnessSet(i as u32));
            }
        }

        // Redeemers
        if let Some(redeemers) = witness_set.redeemers() {
            for i in 0..redeemers.len() {
                let redeemer = redeemers.get(i);
                if let Ok(index_u32) = redeemer.index().to_str().parse::<u32>() {
                    self.provided_redeemers.insert((redeemer.tag(), index_u32));
                }
            }
        }

        // Collect scripts and datums from reference inputs
        let ref_inputs = tx_body
            .reference_inputs()
            .unwrap_or(csl::TransactionInputs::new());
        let inputs = tx_body.inputs();

        self.collect_scripts_from_inputs(&inputs, false)?;
        self.collect_scripts_from_inputs(&ref_inputs, true)?;

        Ok(())
    }

    fn collect_scripts_from_inputs(
        &mut self,
        inputs: &csl::TransactionInputs,
        is_reference_inputs: bool,
    ) -> Result<(), String> {
        for (i, input) in inputs.into_iter().enumerate() {
            if let Some(utxo) = self
                .validation_input_context
                .find_utxo(input.transaction_id().to_hex(), input.index())
            {
                let witness_source = if is_reference_inputs {
                    WitnessSource::ReferenceInput(input.clone(), i as u32)
                } else {
                    WitnessSource::Input(input.clone(), i as u32)
                };

                // Check script_ref - scripts CAN be provided via both regular inputs and reference inputs
                if let Some(script_ref_hex) = &utxo.utxo.output.script_ref {
                    let script_ref = normalize_script_ref(script_ref_hex)?;
                    // ScriptRef contains either NativeScript or PlutusScript
                    // Try to get as NativeScript
                    if let Some(native_script) = script_ref.native_script() {
                        let script_hash = native_script.hash();
                        self.provided_native_scripts
                            .insert(script_hash.clone(), native_script.clone());
                        self.native_script_sources
                            .insert(script_hash, witness_source.clone());
                    }
                    // Try to get as PlutusScript
                    else if let Some(plutus_script) = script_ref.plutus_script() {
                        let script_hash = plutus_script.hash();
                        self.plutus_script_sources
                            .insert(script_hash.clone(), witness_source.clone());
                        self.plutus_script_versions
                            .insert(script_hash.clone(), plutus_script.language_version());
                    }
                }

                // NOTE: We do NOT collect inline datums here!
                // Datums for spending validation can only come from:
                // 1. Witness set (plutus_data) - collected in collect_provided_witnesses
                // 2. Inline datum in the SAME spending input - checked separately in collect_input_witnesses
                // Inline datums from OTHER inputs or reference inputs CANNOT be used!
            }
        }
        Ok(())
    }

    /// Determines script type by its hash
    fn determine_script_type(&self, script_hash: &csl::ScriptHash) -> ScriptType {
        if self.native_script_sources.contains_key(script_hash) {
            ScriptType::NativeScript
        } else if self.plutus_script_sources.contains_key(script_hash) {
            ScriptType::PlutusScript
        } else {
            ScriptType::UnknownScript
        }
    }

    /// Adds required witnesses for script based on its type
    /// If script is unknown, adds UnknownScript requirement
    /// 
    /// # Arguments
    /// * `script_hash` - The script hash
    /// * `location` - Location string for error messages (contains original index)
    /// * `entity_index` - Original index of the entity in the transaction body
    /// * `redeemer_index` - Sorted index for redeemer matching (Cardano node sorts inputs/withdrawals)
    /// * `redeemer_tag` - Redeemer tag if script requires a redeemer
    /// * `datum_hash` - Datum hash if script requires a datum
    fn add_script_witness_requirement(
        &mut self,
        script_hash: csl::ScriptHash,
        location: String,
        entity_index: u32,
        redeemer_index: u32,
        redeemer_tag: Option<csl::RedeemerTag>,
        datum_hash: Option<csl::DataHash>,
    ) {
        let script_type = self.determine_script_type(&script_hash);
        match script_type {
            ScriptType::PlutusScript => {
                // Plutus script
                self.required_plutus_script_witnesses
                    .push(RequiredScriptWitness {
                        script_hash,
                        location: location.clone(),
                        entity_index,
                    });

                // Redeemer (if tag provided)
                if let Some(tag) = redeemer_tag {
                    self.required_redeemer_witnesses
                        .push(RequiredRedeemerWitness {
                            tag,
                            index: redeemer_index,
                            location: location.clone(),
                            entity_index,
                        });
                }

                // Datum (if provided)
                if let Some(datum) = datum_hash {
                    self.required_datum_witnesses.push(RequiredDatumWitness {
                        datum_hash: datum,
                        location,
                        entity_index,
                    });
                }
            }
            ScriptType::NativeScript => {
                // Native script
                self.required_native_script_witnesses
                    .push(RequiredScriptWitness {
                        script_hash,
                        location,
                        entity_index,
                    });
            }
            ScriptType::UnknownScript => {
                self.required_unknown_script_witnesses
                    .push(RequiredScriptWitness {
                        script_hash,
                        location,
                        entity_index,
                    });
            }
        }
    }

    fn collect_required_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        // 1. Inputs
        self.collect_input_witnesses(tx_body);

        // 2. Collateral inputs
        self.collect_collateral_witnesses(tx_body);

        // 3. Withdrawals
        self.collect_withdrawal_witnesses(tx_body);

        // 4. Certificates
        self.collect_certificate_witnesses(tx_body);

        // 5. Voting proposals
        self.collect_voting_proposal_witnesses(tx_body);

        // 6. Votes
        self.collect_vote_witnesses(tx_body);

        // 7. Mint
        self.collect_mint_witnesses(tx_body);

        // 8. Required signers
        self.collect_required_signer_witnesses(tx_body);
    }

    fn collect_native_scripts_signature_candidates(&mut self) {
        // Iterate through all required native scripts
        for required in &self.required_native_script_witnesses.clone() {
            if let Some(native_script) = self.provided_native_scripts.get(&required.script_hash) {
                let key_hashes = get_native_script_key_hashes(&native_script);
                for key_hash in key_hashes {
                    self.native_scripts_signature_candidates.insert(key_hash);
                }
            }
        }
    }

    fn collect_input_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        let inputs = tx_body.inputs();
        
        // Build sorted index mapping: Cardano node sorts inputs before matching with redeemer indices
        let sorted_input_map = build_sorted_input_index_map(&inputs);
        
        for i in 0..inputs.len() {
            let input = inputs.get(i);
            // Get the sorted index for redeemer matching
            let sorted_index = sorted_input_map
                .get(&input)
                .copied()
                .unwrap_or(i as u32);
            
            if let Some(utxo) = self
                .validation_input_context
                .find_utxo(input.transaction_id().to_hex(), input.index())
            {
                if let Ok(address) = string_to_csl_address(&utxo.utxo.output.address) {
                    if let Some(payment_cred) = address.payment_cred() {
                        match payment_cred.kind() {
                            csl::CredKind::Key => {
                                if let Some(key_hash) = payment_cred.to_keyhash() {
                                    self.required_vkey_witnesses.push(RequiredVKeyWitness {
                                        key_hash,
                                        location: format!("transaction.body.inputs.{}", i),
                                        entity_index: i as u32,
                                    });
                                }
                            }
                            csl::CredKind::Script => {
                                if let Some(script_hash) = payment_cred.to_scripthash() {
                                    let has_inline_datum = utxo.utxo.output.plutus_data.is_some();
                                    
                                    let datum_hash = if has_inline_datum {
                                        // Inline datum present - no need to require datum in witness set
                                        None
                                    } else if let Some(data_hash_hex) = &utxo.utxo.output.data_hash {
                                        // Datum hash present - require datum in witness set
                                        if let Ok(data_hash_bytes) = hex::decode(data_hash_hex) {
                                            csl::DataHash::from_bytes(data_hash_bytes).ok()
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                    self.add_script_witness_requirement(
                                        script_hash,
                                        format!("transaction.body.inputs.{}", i),
                                        i as u32,
                                        sorted_index,
                                        Some(csl::RedeemerTag::new_spend()),
                                        datum_hash,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn collect_collateral_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        if let Some(collateral) = tx_body.collateral() {
            for i in 0..collateral.len() {
                let input = collateral.get(i);
                if let Some(utxo) = self
                    .validation_input_context
                    .find_utxo(input.transaction_id().to_hex(), input.index())
                {
                    if let Ok(address) = string_to_csl_address(&utxo.utxo.output.address) {
                        if let Some(payment_cred) = address.payment_cred() {
                            if payment_cred.kind() == csl::CredKind::Key {
                                if let Some(key_hash) = payment_cred.to_keyhash() {
                                    self.required_vkey_witnesses.push(RequiredVKeyWitness {
                                        key_hash,
                                        location: format!("transaction.body.collateral.{}", i),
                                        entity_index: i as u32,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn collect_withdrawal_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        if let Some(withdrawals) = tx_body.withdrawals() {
            let withdrawal_keys = withdrawals.keys();
            
            // Build sorted index mapping: Cardano node sorts withdrawals before matching with redeemer indices
            let sorted_withdrawal_map = build_sorted_withdrawal_index_map(&withdrawal_keys);
            
            for i in 0..withdrawal_keys.len() {
                let reward_address = withdrawal_keys.get(i);
                // Get the sorted index for redeemer matching
                let sorted_index = sorted_withdrawal_map
                    .get(&reward_address)
                    .copied()
                    .unwrap_or(i as u32);
                
                let stake_cred = reward_address.payment_cred();

                match stake_cred.kind() {
                    csl::CredKind::Key => {
                        if let Some(key_hash) = stake_cred.to_keyhash() {
                            self.required_vkey_witnesses.push(RequiredVKeyWitness {
                                key_hash,
                                location: format!("transaction.body.withdrawals.{}", i),
                                entity_index: i as u32,
                            });
                        }
                    }
                    csl::CredKind::Script => {
                        if let Some(script_hash) = stake_cred.to_scripthash() {
                            // Determine script type by collected witnesses
                            self.add_script_witness_requirement(
                                script_hash,
                                format!("transaction.body.withdrawals.{}", i),
                                i as u32,
                                sorted_index,
                                Some(csl::RedeemerTag::new_reward()),
                                None,
                            );
                        }
                    }
                }
            }
        }
    }

    fn collect_certificate_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        if let Some(certs) = tx_body.certs() {
            for i in 0..certs.len() {
                let cert = certs.get(i);
                self.collect_certificate_witness(&cert, i as u32);
            }
        }
    }

    fn collect_certificate_witness(&mut self, cert: &csl::Certificate, index: u32) {
        match cert.kind() {
            csl::CertificateKind::StakeRegistration => {
                if let Some(stake_reg) = cert.as_stake_registration() {
                    let stake_cred = stake_reg.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::StakeDeregistration => {
                if let Some(stake_dereg) = cert.as_stake_deregistration() {
                    let stake_cred = stake_dereg.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::StakeDelegation => {
                if let Some(stake_del) = cert.as_stake_delegation() {
                    let stake_cred = stake_del.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::PoolRegistration => {
                if let Some(pool_reg) = cert.as_pool_registration() {
                    let pool_params = pool_reg.pool_params();
                    let operator = pool_params.operator();
                    self.required_vkey_witnesses.push(RequiredVKeyWitness {
                        key_hash: operator,
                        location: format!("transaction.body.certs.{}", index),
                        entity_index: index,
                    });
                    let owners = pool_params.pool_owners();
                    for owner in owners.into_iter() {
                        self.required_vkey_witnesses.push(RequiredVKeyWitness {
                            key_hash: owner.clone(),
                            location: format!("transaction.body.certs.{}", index),
                            entity_index: index,
                        });
                    }
                }
            }
            csl::CertificateKind::PoolRetirement => {
                if let Some(pool_ret) = cert.as_pool_retirement() {
                    let pool_keyhash = pool_ret.pool_keyhash();
                    self.required_vkey_witnesses.push(RequiredVKeyWitness {
                        key_hash: pool_keyhash,
                        location: format!("transaction.body.certs.{}", index),
                        entity_index: index,
                    });
                }
            }
            csl::CertificateKind::DRepRegistration => {
                if let Some(drep_reg) = cert.as_drep_registration() {
                    let voting_cred = drep_reg.voting_credential();
                    self.add_certificate_credential_witness(
                        voting_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::DRepDeregistration => {
                if let Some(drep_dereg) = cert.as_drep_deregistration() {
                    let voting_cred = drep_dereg.voting_credential();
                    self.add_certificate_credential_witness(
                        voting_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::DRepUpdate => {
                if let Some(drep_update) = cert.as_drep_update() {
                    let voting_cred = drep_update.voting_credential();
                    self.add_certificate_credential_witness(
                        voting_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::CommitteeHotAuth => {
                if let Some(committee_auth) = cert.as_committee_hot_auth() {
                    let committee_cold_cred = committee_auth.committee_cold_credential();
                    self.add_certificate_credential_witness(
                        committee_cold_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::CommitteeColdResign => {
                if let Some(committee_resign) = cert.as_committee_cold_resign() {
                    let committee_cold_cred = committee_resign.committee_cold_credential();
                    self.add_certificate_credential_witness(
                        committee_cold_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::StakeAndVoteDelegation => {
                if let Some(stake_vote_del) = cert.as_stake_and_vote_delegation() {
                    let stake_cred = stake_vote_del.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::StakeRegistrationAndDelegation => {
                if let Some(stake_reg_del) = cert.as_stake_registration_and_delegation() {
                    let stake_cred = stake_reg_del.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::StakeVoteRegistrationAndDelegation => {
                if let Some(stake_vote_reg_del) = cert.as_stake_vote_registration_and_delegation() {
                    let stake_cred = stake_vote_reg_del.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::VoteDelegation => {
                if let Some(vote_del) = cert.as_vote_delegation() {
                    let stake_cred = vote_del.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::VoteRegistrationAndDelegation => {
                if let Some(vote_reg_del) = cert.as_vote_registration_and_delegation() {
                    let stake_cred = vote_reg_del.stake_credential();
                    self.add_certificate_credential_witness(
                        stake_cred,
                        format!("transaction.body.certs.{}", index),
                        index,
                    );
                }
            }
            csl::CertificateKind::GenesisKeyDelegation => {}
            csl::CertificateKind::MoveInstantaneousRewardsCert => {}
        }
    }

    fn add_certificate_credential_witness(
        &mut self,
        credential: csl::Credential,
        location: String,
        index: u32,
    ) {
        match credential.kind() {
            csl::CredKind::Key => {
                if let Some(key_hash) = credential.to_keyhash() {
                    self.required_vkey_witnesses.push(RequiredVKeyWitness {
                        key_hash,
                        location,
                        entity_index: index,
                    });
                }
            }
            csl::CredKind::Script => {
                if let Some(script_hash) = credential.to_scripthash() {
                    self.add_script_witness_requirement(
                        script_hash,
                        location,
                        index,
                        index, // certificates are not sorted, so redeemer_index = entity_index
                        Some(csl::RedeemerTag::new_cert()),
                        None,
                    );
                }
            }
        }
    }

    fn collect_voting_proposal_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        if let Some(voting_proposals) = tx_body.voting_proposals() {
            for i in 0..voting_proposals.len() {
                let proposal = voting_proposals.get(i);
                let gov_action = proposal.governance_action();
                let action_kind = gov_action.kind();
                if action_kind == csl::GovernanceActionKind::ParameterChangeAction {
                    let pp_change_action = gov_action.as_parameter_change_action().unwrap();
                    if let Some(script_hash) = pp_change_action.policy_hash() {
                        self.add_script_witness_requirement(
                            script_hash,
                            format!("transaction.body.voting_proposals.{}", i),
                            i as u32,
                            i as u32, // voting proposals are not sorted
                            Some(csl::RedeemerTag::new_voting_proposal()),
                            None,
                        );
                    }
                } else if action_kind == csl::GovernanceActionKind::TreasuryWithdrawalsAction {
                    let treasury_action = gov_action.as_treasury_withdrawals_action().unwrap();
                    if let Some(script_hash) = treasury_action.policy_hash() {
                        self.add_script_witness_requirement(
                            script_hash,
                            format!("transaction.body.voting_proposals.{}", i),
                            i as u32,
                            i as u32, // voting proposals are not sorted
                            Some(csl::RedeemerTag::new_voting_proposal()),
                            None,
                        );
                    }
                }
            }
        }
    }

    fn collect_vote_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        let votes = tx_body.voting_procedures();
        if let Some(votes) = votes {
            let voters = votes.get_voters();
            let voters_count = voters.len();
            for i in 0..voters_count {
                let voter = voters.get(i).unwrap();
                let voter_kind = voter.kind();
                match voter_kind {
                    csl::VoterKind::ConstitutionalCommitteeHotKeyHash => {
                        if let Some(voter_cred) = voter
                            .to_constitutional_committee_hot_credential()
                            .unwrap()
                            .to_keyhash()
                        {
                            self.required_vkey_witnesses.push(RequiredVKeyWitness {
                                key_hash: voter_cred,
                                location: format!("transaction.body.voting_procedures.{}", i),
                                entity_index: i as u32,
                            });
                        }
                    }
                    csl::VoterKind::ConstitutionalCommitteeHotScriptHash => {
                        if let Some(voter_cred) = voter
                            .to_constitutional_committee_hot_credential()
                            .unwrap()
                            .to_scripthash()
                        {
                            self.add_script_witness_requirement(
                                voter_cred,
                                format!("transaction.body.voting_procedures.{}", i),
                                i as u32,
                                i as u32, // votes are not sorted
                                Some(csl::RedeemerTag::new_vote()),
                                None,
                            );
                        }
                    }
                    csl::VoterKind::DRepKeyHash => {
                        if let Some(voter_cred) = voter.to_drep_credential().unwrap().to_keyhash() {
                            self.required_vkey_witnesses.push(RequiredVKeyWitness {
                                key_hash: voter_cred,
                                location: format!("transaction.body.voting_procedures.{}", i),
                                entity_index: i as u32,
                            });
                        }
                    }
                    csl::VoterKind::DRepScriptHash => {
                        if let Some(voter_cred) = voter
                            .to_drep_credential()
                            .map(|cred| cred.to_scripthash())
                            .flatten()
                        {
                            self.add_script_witness_requirement(
                                voter_cred,
                                format!("transaction.body.voting_procedures.{}", i),
                                i as u32,
                                i as u32, // votes are not sorted
                                Some(csl::RedeemerTag::new_vote()),
                                None,
                            );
                        }
                    }
                    csl::VoterKind::StakingPoolKeyHash => {
                        if let Some(voter_cred) = voter.to_stake_pool_key_hash() {
                            self.required_vkey_witnesses.push(RequiredVKeyWitness {
                                key_hash: voter_cred,
                                location: format!("transaction.body.voting_procedures.{}", i),
                                entity_index: i as u32,
                            });
                        }
                    }
                }
            }
        }
    }

    fn collect_mint_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        if let Some(mint) = tx_body.mint() {
            let policy_ids = mint.keys();
            
            for i in 0..policy_ids.len() {
                let policy_id = policy_ids.get(i);
                let script_hash = csl::ScriptHash::from_bytes(policy_id.to_bytes()).unwrap();

                self.add_script_witness_requirement(
                    script_hash,
                    format!("transaction.body.mint.{}", i),
                    i as u32,
                    i as u32, // mints are not sorted
                    Some(csl::RedeemerTag::new_mint()),
                    None,
                );
            }
        }
    }

    fn collect_required_signer_witnesses(&mut self, tx_body: &csl::TransactionBody) {
        if let Some(required_signers) = tx_body.required_signers() {
            for i in 0..required_signers.len() {
                let key_hash = required_signers.get(i);
                self.required_vkey_witnesses.push(RequiredVKeyWitness {
                    key_hash,
                    location: format!("transaction.body.required_signers.{}", i),
                    entity_index: i as u32,
                });
            }
        }
    }

    pub fn calulucate_actual_script_data_hash(
        &self,
        tx_witness_set: &csl::TransactionWitnessSet,
    ) -> Result<Option<String>, String> {
        let datums = tx_witness_set.plutus_data();
        let redeemers = tx_witness_set.redeemers().unwrap_or(Redeemers::new());
        let mut cost_models = csl::Costmdls::new();

        for used_plutus_version in &self.used_plutus_versions {
            if used_plutus_version == &csl::LanguageKind::PlutusV1 {
                let cost_model = pp_cost_model_to_csl(
                    self.validation_input_context
                        .protocol_parameters
                        .cost_models
                        .plutus_v1
                        .as_ref()
                        .ok_or("Plutus V1 cost model not found")?,
                );
                cost_models.insert(&csl::Language::new_plutus_v1(), &cost_model);
            } else if used_plutus_version == &csl::LanguageKind::PlutusV2 {
                let cost_model = pp_cost_model_to_csl(
                    self.validation_input_context
                        .protocol_parameters
                        .cost_models
                        .plutus_v2
                        .as_ref()
                        .ok_or("Plutus V2 cost model not found")?,
                );
                cost_models.insert(&csl::Language::new_plutus_v2(), &cost_model);
            } else if used_plutus_version == &csl::LanguageKind::PlutusV3 {
                let cost_model = pp_cost_model_to_csl(
                    self.validation_input_context
                        .protocol_parameters
                        .cost_models
                        .plutus_v3
                        .as_ref()
                        .ok_or("Plutus V3 cost model not found")?,
                );
                cost_models.insert(&csl::Language::new_plutus_v3(), &cost_model);
            }
        }

        if datums.is_some() || redeemers.len() > 0 || cost_models.len() > 0 {
            let script_data_hash = csl::hash_script_data(&redeemers, &cost_models, datums);
            Ok(Some(script_data_hash.to_hex()))
        } else {
            Ok(None)
        }
    }

    pub fn validate(&self) -> ValidationResult {
        let mut errors = Vec::new();

        for required in &self.required_vkey_witnesses {
            let found = self
                .provided_vkey_witnesses
                .contains_key(&required.key_hash);

            if !found {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::MissingVKeyWitnesses {
                        missing_key_hash: hex::encode(required.key_hash.to_bytes()),
                    },
                    required.location.clone(),
                ));
            }
        }

        let required_signatures = self
            .required_vkey_witnesses
            .iter()
            .map(|req| (&req.key_hash, req.location.clone()))
            .collect::<HashMap<_, _>>();
        for (key_hash, index) in self.invalid_signatures.iter() {
            let location = format!("transaction.witness_set.vkeys.{}", index);
            let required_location = required_signatures.get(key_hash).cloned();
            if let Some(required_location) = required_location {
                errors.push(ValidationPhase1Error::new_with_locations(
                    Phase1Error::InvalidSignature {
                        invalid_signature: key_hash.to_hex(),
                    },
                    &[location, required_location],
                ));
            } else {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::InvalidSignature {
                        invalid_signature: key_hash.to_hex(),
                    },
                    location,
                ));
            }
        }

        for required in &self.required_native_script_witnesses {
            let found = self
                .native_script_sources
                .contains_key(&required.script_hash);

            if !found {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::MissingScriptWitnesses {
                        missing_script_hash: hex::encode(required.script_hash.to_bytes()),
                    },
                    required.location.clone(),
                ));
            }

            if let Some(invalid_native_script) =
                self.invalid_native_scripts.get(&required.script_hash)
            {
                errors.push(ValidationPhase1Error::new_with_locations(
                    Phase1Error::NativeScriptIsUnsuccessful {
                        native_script_hash: required.script_hash.to_hex(),
                    },
                    &[
                        required.location.clone(),
                        invalid_native_script.get_location("native_scripts"),
                    ],
                ));
            }
        }

        for required in &self.required_plutus_script_witnesses {
            let script_found = self
                .plutus_script_sources
                .contains_key(&required.script_hash);

            if !script_found {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::MissingScriptWitnesses {
                        missing_script_hash: hex::encode(required.script_hash.to_bytes()),
                    },
                    required.location.clone(),
                ));
            }
        }

        for required in &self.required_redeemer_witnesses {
            let redeemer_found = self
                .provided_redeemers
                .contains(&(required.tag.clone(), required.index));

            if !redeemer_found {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::MissingRedeemer {
                        tag: format!("{:?}", required.tag),
                        index: required.index,
                    },
                    required.location.clone(),
                ));
            }
        }

        for required in &self.required_datum_witnesses {
            let datum_found = self.datum_sources.contains_key(&required.datum_hash);
            if !datum_found {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::MissingDatum {
                        datum_hash: hex::encode(required.datum_hash.to_bytes()),
                    },
                    required.location.clone(),
                ));
            }
        }

        for required in &self.required_unknown_script_witnesses {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::MissingScriptWitnesses {
                    missing_script_hash: hex::encode(required.script_hash.to_bytes()),
                },
                required.location.clone(),
            ));
        }

        let required_native_scripts = self
            .required_native_script_witnesses
            .iter()
            .map(|req| &req.script_hash)
            .collect::<HashSet<_>>();
        let required_plutus_scripts = self
            .required_plutus_script_witnesses
            .iter()
            .map(|req| &req.script_hash)
            .collect::<HashSet<_>>();

        for (script_hash, source) in &self.native_script_sources {
            let required = required_native_scripts.contains(script_hash);
            if !required && matches!(source, WitnessSource::WitnessSet(_)) {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::ExtraneousScriptWitnesses {
                        extraneous_script: script_hash.to_hex(),
                    },
                    source.get_location("native_scripts"),
                ));
            }
        }

        for (script_hash, source) in &self.plutus_script_sources {
            let required = required_plutus_scripts.contains(script_hash);
            if !required && matches!(source, WitnessSource::WitnessSet(_)) {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::ExtraneousScriptWitnesses {
                        extraneous_script: script_hash.to_hex(),
                    },
                    source.get_location("plutus_scripts"),
                ));
            }
        }

        let mut required_datums = self
            .required_datum_witnesses
            .iter()
            .map(|req| &req.datum_hash)
            .collect::<HashSet<_>>();
        required_datums.extend(self.output_datums_hashes.iter());

        for (datum_hash, source) in &self.datum_sources {
            if !required_datums.contains(datum_hash)
                && matches!(source, WitnessSource::WitnessSet(_))
            {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::ExtraneousDatumWitnesses {
                        datum_hash: hex::encode(datum_hash.to_bytes()),
                    },
                    source.get_location("plutus_data"),
                ));
            }
        }

        let mut required_signatures = self
            .required_vkey_witnesses
            .iter()
            .map(|req| &req.key_hash)
            .collect::<HashSet<_>>();
        required_signatures.extend(self.native_scripts_signature_candidates.iter());

        for (key_hash, index) in &self.provided_vkey_witnesses {
            if !required_signatures.contains(key_hash) {
                errors.push(ValidationPhase1Error::new(
                    Phase1Error::ExtraneousSignature {
                        extraneous_signature: key_hash.to_hex(),
                    },
                    format!("transaction.witness_set.vkeys.{}", index),
                ));
            }
        }

        if self.provided_script_data_hash != self.expected_script_data_hash {
            errors.push(ValidationPhase1Error::new(
                Phase1Error::ScriptDataHashMismatch {
                    expected_hash: self.expected_script_data_hash.clone(),
                    provided_hash: self.provided_script_data_hash.clone(),
                },
                "transaction.body.script_data_hash".to_string(),
            ));
        }

        ValidationResult::new_phase_1(errors, vec![])
    }
}

fn get_native_script_key_hashes(native_script: &csl::NativeScript) -> HashSet<csl::Ed25519KeyHash> {
    let mut key_hashes = HashSet::new();
    get_native_script_key_hashes_internal(native_script, &mut key_hashes);
    key_hashes
}

fn get_native_script_key_hashes_internal(
    native_script: &csl::NativeScript,
    key_hashes: &mut HashSet<csl::Ed25519KeyHash>,
) {
    let script_kind = native_script.kind();
    match script_kind {
        csl::NativeScriptKind::ScriptPubkey => {
            if let Some(script_pubkey) = native_script.as_script_pubkey() {
                key_hashes.insert(script_pubkey.addr_keyhash());
            }
        }
        csl::NativeScriptKind::ScriptAll => {
            if let Some(script_all) = native_script.as_script_all() {
                for script in script_all.native_scripts() {
                    get_native_script_key_hashes_internal(&script, key_hashes);
                }
            }
        }
        csl::NativeScriptKind::ScriptAny => {
            if let Some(script_any) = native_script.as_script_any() {
                for script in script_any.native_scripts() {
                    get_native_script_key_hashes_internal(&script, key_hashes);
                }
            }
        }
        csl::NativeScriptKind::ScriptNOfK => {
            if let Some(script_n_of_k) = native_script.as_script_n_of_k() {
                for script in script_n_of_k.native_scripts() {
                    get_native_script_key_hashes_internal(&script, key_hashes);
                }
            }
        }
        csl::NativeScriptKind::TimelockStart => {}
        csl::NativeScriptKind::TimelockExpiry => {}
    }
}

/// Builds a mapping from TransactionInput to sorted index
/// Cardano node sorts inputs by (transaction_id, index) before matching with redeemer indices
fn build_sorted_input_index_map(inputs: &csl::TransactionInputs) -> HashMap<csl::TransactionInput, u32> {
    // Collect inputs
    let original_order: Vec<csl::TransactionInput> = (0..inputs.len())
        .map(|i| inputs.get(i))
        .collect();

    // Sort using BTreeSet (TransactionInput implements Ord)
    let sorted_set: BTreeSet<&csl::TransactionInput> = original_order.iter().collect();
    let sorted_order: Vec<&csl::TransactionInput> = sorted_set.into_iter().collect();

    // Build mapping from TransactionInput to sorted index
    sorted_order
        .into_iter()
        .enumerate()
        .map(|(sorted_idx, input)| (input.clone(), sorted_idx as u32))
        .collect()
}

/// Builds a mapping from RewardAddress to sorted index
/// Cardano node sorts withdrawals by RewardAddress before matching with redeemer indices
fn build_sorted_withdrawal_index_map(keys: &csl::RewardAddresses) -> HashMap<csl::RewardAddress, u32> {
    // Collect reward addresses
    let original_order: Vec<csl::RewardAddress> = (0..keys.len())
        .map(|i| keys.get(i))
        .collect();

    // Sort using BTreeSet (RewardAddress implements Ord)
    let sorted_set: BTreeSet<&csl::RewardAddress> = original_order.iter().collect();
    let sorted_order: Vec<&csl::RewardAddress> = sorted_set.into_iter().collect();

    // Build mapping from RewardAddress to sorted index
    sorted_order
        .into_iter()
        .enumerate()
        .map(|(sorted_idx, addr)| (addr.clone(), sorted_idx as u32))
        .collect()
}

