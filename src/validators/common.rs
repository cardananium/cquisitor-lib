use std::fmt::Display;
use schemars::JsonSchema;
use std::convert::TryFrom;
use serde::{Serialize, Deserialize};
use std::fmt;

pub use crate::validators::value::{Value};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum GovernanceActionType {
    ParameterChangeAction,
    HardForkInitiationAction,
    TreasuryWithdrawalsAction,
    NoConfidenceAction,
    UpdateCommitteeAction,
    NewConstitutionAction,
    InfoAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum NetworkType {
    Mainnet,
    Preview,
    Preprod,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FeeDecomposition {
    pub tx_size_fee: u64,
    pub reference_scripts_fee: u64,
    pub execution_units_fee: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum LocalCredential {
    KeyHash(Vec<u8>),
    ScriptHash(Vec<u8>),
}

impl Display for LocalCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LocalCredential::KeyHash(key_hash) => write!(f, "KeyHash({})", hex::encode(key_hash)),
            LocalCredential::ScriptHash(script_hash) => write!(f, "ScriptHash({})", hex::encode(script_hash)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum Voter {
    ConstitutionalCommitteeHotScriptHash(Vec<u8>),
    ConstitutionalCommitteeHotKeyHash(Vec<u8>),
    DRepScriptHash(Vec<u8>),
    DRepKeyHash(Vec<u8>),
    StakingPoolKeyHash(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceActionId {
    pub tx_hash: Vec<u8>,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolVersion {
    pub major: u64,
    pub minor: u64,
}

/// Decomposition of script_data_hash computation for debugging.
/// 
/// The script_data_hash is computed as blake2b256 of concatenated bytes in a specific format.
/// This structure provides the raw CBOR data and explains the encoding used.
/// 
/// ## script_data_hash format (Alonzo+ ledger spec):
/// 
/// Standard: `blake2b256(redeemers || datums || used_cost_models)`
/// Datums-only: `blake2b256(0xA0 || datums || 0xA0)` (when no redeemers)
/// 
/// All components must be serialized according to the ledger CDDL specification.
/// 
/// ### Redeemers
/// - **Pre-Conway**: array format
/// - **Conway+**: map format  
/// - Original format from deserialization is preserved
/// 
/// ### Datums
/// - For hash: uses CBOR set encoding (tag 258) with deduplication
/// - May use indefinite length encoding
/// 
/// ### Cost Models
/// 
/// **Encoding rules:**
/// - Keys sorted by **length first**, then lexicographically  
/// - **PlutusV1 special case** (cardano-node bug workaround):
///   - Key `0` serialized as `bytes(0x00)` instead of integer
///   - Value wrapped in bytestring containing **indefinite length array**
///   - Format: `{ bytes(0x00): bytes(9F cost1 cost2 ... FF) }`
/// - **PlutusV2** (key=1) and **PlutusV3** (key=2): standard integer key with array value
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ScriptDataHashDecomposition {
    /// Which encoding format was used for script_data_hash
    /// - "standard": redeemers || datums || used_cost_models
    /// - "datums_only": 0xA0 || datums || 0xA0 (when no redeemers but has datums)
    pub encoding_format: String,
    
    /// Redeemers CBOR hex (serialized per CDDL, preserves original Map or Array format)
    pub redeemers_cbor: Option<String>,
    /// Number of redeemers
    pub redeemers_count: u32,
    
    /// Datums CBOR hex (standard array encoding)
    /// Note: for hash computation uses set encoding (tag 258 + deduplication)
    pub datums_cbor: Option<String>,
    /// Number of datums
    pub datums_count: Option<u32>,
    
    /// Cost models CBOR hex (standard map encoding)
    pub cost_models_cbor: Option<String>,
    
    /// Plutus versions used (e.g. ["PlutusV1", "PlutusV2", "PlutusV3"])
    pub plutus_versions_used: Vec<String>,
    
    /// Description of what is actually concatenated for hashing
    pub hash_input_description: String,
}