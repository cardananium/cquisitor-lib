use crate::{
    common::{TxInput, UTxO},
    validators::common::{GovernanceActionId, GovernanceActionType, NetworkType},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use super::{common::LocalCredential, protocol_params::ProtocolParameters};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NecessaryInputData {
    pub utxos: Vec<TxInput>,
    pub accounts: Vec<String>,
    pub pools: Vec<String>,
    pub d_reps: Vec<String>,
    pub gov_actions: Vec<GovernanceActionId>,
    pub last_enacted_gov_action: Vec<GovernanceActionType>,
    pub committee_members_cold: Vec<LocalCredential>,
    pub committee_members_hot: Vec<LocalCredential>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GovActionInputContext {
    pub action_id: GovernanceActionId,
    pub action_type: GovernanceActionType,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DrepInputContext {
    pub bech32_drep: String,
    pub is_registered: bool,
    pub payed_deposit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AccountInputContext {
    pub bech32_address: String,
    pub is_registered: bool,
    pub payed_deposit: Option<u64>,
    pub delegated_to_drep: Option<String>,
    pub delegated_to_pool: Option<String>,
    pub balance: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PoolInputContext {
    pub pool_id: String,
    pub is_registered: bool,
    pub retirement_epoch: Option<u64>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UtxoInputContext {
    pub utxo: UTxO,
    pub is_spent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommitteeInputContext {
    pub committee_member_cold: LocalCredential,
    pub committee_member_hot: Option<LocalCredential>,
    pub is_resigned: bool,
}

/// Current on-chain constitution, as far as the caller can supply it. Only the
/// guardrails (constitution policy) script hash matters for validation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConstitutionContext {
    /// Guardrails script hash (hex). `None` means the constitution defines no
    /// guardrails script.
    pub guardrail_script_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ValidationInputContext {
    pub utxo_set: Vec<UtxoInputContext>,
    pub protocol_parameters: ProtocolParameters,
    pub slot: u64,
    pub account_contexts: Vec<AccountInputContext>,
    pub drep_contexts: Vec<DrepInputContext>,
    pub pool_contexts: Vec<PoolInputContext>,
    pub gov_action_contexts: Vec<GovActionInputContext>,
    pub last_enacted_gov_action: Vec<GovActionInputContext>,
    pub current_committee_members: Vec<CommitteeInputContext>,
    pub potential_committee_members: Vec<CommitteeInputContext>,
    pub treasury_value: u64,
    pub network_type: NetworkType,
    /// Current constitution. When present, enables the ParameterChange /
    /// TreasuryWithdrawals guardrails-policy-hash check; when absent (older
    /// callers, or a provider that can't supply it) that check is skipped.
    #[serde(default)]
    pub constitution: Option<ConstitutionContext>,
}

impl ValidationInputContext {
    pub fn new(
        utxo_set: Vec<UtxoInputContext>,
        protocol_parameters: ProtocolParameters,
        slot: u64,
        account_contexts: Vec<AccountInputContext>,
        drep_contexts: Vec<DrepInputContext>,
        pool_contexts: Vec<PoolInputContext>,
        gov_action_contexts: Vec<GovActionInputContext>,
        last_enacted_gov_action: Vec<GovActionInputContext>,
        treasury_value: u64,
        network_type: NetworkType,
        current_committee_members: Vec<CommitteeInputContext>,
        potential_committee_members: Vec<CommitteeInputContext>,
    ) -> Self {
        Self {
            utxo_set,
            protocol_parameters,
            slot,
            account_contexts,
            drep_contexts,
            pool_contexts,
            gov_action_contexts,
            last_enacted_gov_action,
            treasury_value,
            network_type,
            current_committee_members,
            potential_committee_members,
            constitution: None,
        }
    }

    pub fn find_utxo(&self, tx_hash: String, tx_index: u32) -> Option<&UtxoInputContext> {
        self.utxo_set.iter().find(|utxo| {
            utxo.utxo.input.tx_hash == tx_hash && utxo.utxo.input.output_index == tx_index
        })
    }

    pub fn find_account_context(&self, bech32_address: &String) -> Option<&AccountInputContext> {
        self.account_contexts
            .iter()
            .find(|account| &account.bech32_address == bech32_address)
    }

    pub fn find_drep_context(&self, bech32_drep: &String) -> Option<&DrepInputContext> {
        self.drep_contexts
            .iter()
            .find(|drep| &drep.bech32_drep == bech32_drep)
    }

    pub fn find_pool_context(&self, pool_id: &String) -> Option<&PoolInputContext> {
        self.pool_contexts
            .iter()
            .find(|pool| &pool.pool_id == pool_id)
    }

    pub fn find_gov_action_context(
        &self,
        action_id: GovernanceActionId,
    ) -> Option<&GovActionInputContext> {
        self.gov_action_contexts
            .iter()
            .find(|action| action.action_id == action_id)
    }

    pub fn find_last_enacted_gov_action(
        &self,
        action_type: GovernanceActionType,
    ) -> Option<&GovActionInputContext> {
        self.last_enacted_gov_action
            .iter()
            .find(|action| action.action_type == action_type)
    }

    pub fn find_current_committee_member_by_cold_credential(
        &self,
        credential: &LocalCredential,
    ) -> Option<&CommitteeInputContext> {
        self.current_committee_members
            .iter()
            .find(|member| member.committee_member_cold == *credential)
    }

    pub fn find_potential_committee_member_by_cold_credential(
        &self,
        credential: &LocalCredential,
    ) -> Option<&CommitteeInputContext> {
        self.potential_committee_members
            .iter()
            .find(|member| member.committee_member_cold == *credential)
    }

    pub fn find_current_committee_member_by_hot_credential(
        &self,
        credential: &LocalCredential,
    ) -> Option<&CommitteeInputContext> {
        self.current_committee_members
            .iter()
            .filter(|member| member.committee_member_hot.is_some())
            .find(|member| member.committee_member_hot.as_ref().unwrap() == credential)
    }

    pub fn find_potential_committee_member_by_hot_credential(
        &self,
        credential: &LocalCredential,
    ) -> Option<&CommitteeInputContext> {
        self.potential_committee_members
            .iter()
            .filter(|member| member.committee_member_hot.is_some())
            .find(|member| member.committee_member_hot.as_ref().unwrap() == credential)
    }
}
