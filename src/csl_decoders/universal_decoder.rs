use crate::bingen::wasm_bindgen;
use crate::csl_decoders::params::DecodingParams;
use crate::csl_decoders::specific_decoders::{
    decode_native_script, decode_address, decode_plutus_data, decode_plutus_script, decode_transaction,
};
use crate::js_value::{empty_js_value, from_js_value, from_serde_json_value, JsValue};
use bech32;
use bs58;
use cardano_serialization_lib as csl;
use hex;

fn is_valid_hex(input: &str) -> bool {
    hex::decode(input).is_ok()
}

fn is_valid_base58(input: &str) -> bool {
    bs58::decode(input).into_vec().is_ok()
}

fn is_valid_bech32(input: &str) -> bool {
    bech32::decode(input).is_ok()
}

// Returns a list of all the types that we can attempt to decode

#[wasm_bindgen]
pub fn get_decodable_types() -> Vec<String> {
    vec![
        String::from("Address"),
        String::from("AnchorDataHash"),
        String::from("AuxiliaryDataHash"),
        String::from("Bip32PrivateKey"),
        String::from("Bip32PublicKey"),
        String::from("BlockHash"),
        String::from("DRep"),
        String::from("DataHash"),
        String::from("Ed25519KeyHash"),
        String::from("Ed25519Signature"),
        String::from("GenesisDelegateHash"),
        String::from("GenesisHash"),
        String::from("KESVKey"),
        String::from("PoolMetadataHash"),
        String::from("PrivateKey"),
        String::from("PublicKey"),
        String::from("ScriptDataHash"),
        String::from("ScriptHash"),
        String::from("TransactionHash"),
        String::from("VRFKeyHash"),
        String::from("VRFVKey"),
        String::from("Anchor"),
        String::from("AssetName"),
        String::from("AssetNames"),
        String::from("Assets"),
        String::from("AuxiliaryData"),
        String::from("BigInt"),
        String::from("BigNum"),
        String::from("Block"),
        String::from("BootstrapWitness"),
        String::from("BootstrapWitnesses"),
        String::from("Certificate"),
        String::from("Certificates"),
        String::from("Committee"),
        String::from("CommitteeColdResign"),
        String::from("CommitteeHotAuth"),
        String::from("Constitution"),
        String::from("ConstrPlutusData"),
        String::from("CostModel"),
        String::from("Costmdls"),
        String::from("Credential"),
        String::from("Credentials"),
        String::from("DNSRecordAorAAAA"),
        String::from("DNSRecordSRV"),
        String::from("DRepDeregistration"),
        String::from("DRepRegistration"),
        String::from("DRepUpdate"),
        String::from("DRepVotingThresholds"),
        String::from("Ed25519KeyHashes"),
        String::from("ExUnitPrices"),
        String::from("ExUnits"),
        String::from("GeneralTransactionMetadata"),
        String::from("GenesisHashes"),
        String::from("GenesisKeyDelegation"),
        String::from("GovernanceAction"),
        String::from("GovernanceActionId"),
        String::from("HardForkInitiationAction"),
        String::from("Header"),
        String::from("HeaderBody"),
        String::from("Int"),
        String::from("Ipv4"),
        String::from("Ipv6"),
        String::from("Language"),
        String::from("MIRToStakeCredentials"),
        String::from("MetadataList"),
        String::from("MetadataMap"),
        String::from("Mint"),
        String::from("MoveInstantaneousReward"),
        String::from("MoveInstantaneousRewardsCert"),
        String::from("MultiAsset"),
        String::from("MultiHostName"),
        String::from("NativeScript"),
        String::from("NativeScripts"),
        String::from("NetworkId"),
        String::from("NewConstitutionAction"),
        String::from("NoConfidenceAction"),
        String::from("Nonce"),
        String::from("OperationalCert"),
        String::from("ParameterChangeAction"),
        String::from("PlutusData"),
        String::from("PlutusList"),
        String::from("PlutusMap"),
        String::from("PlutusScript"),
        String::from("PlutusScripts"),
        String::from("PoolMetadata"),
        String::from("PoolParams"),
        String::from("PoolRegistration"),
        String::from("PoolRetirement"),
        String::from("PoolVotingThresholds"),
        String::from("ProposedProtocolParameterUpdates"),
        String::from("ProtocolParamUpdate"),
        String::from("ProtocolVersion"),
        String::from("Redeemer"),
        String::from("RedeemerTag"),
        String::from("Redeemers"),
        String::from("Relay"),
        String::from("Relays"),
        String::from("RewardAddresses"),
        String::from("ScriptAll"),
        String::from("ScriptAny"),
        String::from("ScriptHashes"),
        String::from("ScriptNOfK"),
        String::from("ScriptPubkey"),
        String::from("ScriptRef"),
        String::from("SingleHostAddr"),
        String::from("SingleHostName"),
        String::from("StakeAndVoteDelegation"),
        String::from("StakeDelegation"),
        String::from("StakeDeregistration"),
        String::from("StakeRegistration"),
        String::from("StakeRegistrationAndDelegation"),
        String::from("StakeVoteRegistrationAndDelegation"),
        String::from("TimelockExpiry"),
        String::from("TimelockStart"),
        String::from("Transaction"),
        String::from("TransactionBodies"),
        String::from("TransactionBody"),
        String::from("TransactionInput"),
        String::from("TransactionInputs"),
        String::from("TransactionMetadatum"),
        String::from("TransactionMetadatumLabels"),
        String::from("TransactionOutput"),
        String::from("TransactionOutputs"),
        String::from("TransactionUnspentOutput"),
        String::from("TransactionWitnessSet"),
        String::from("TransactionWitnessSets"),
        String::from("TreasuryWithdrawalsAction"),
        String::from("URL"),
        String::from("UnitInterval"),
        String::from("Update"),
        String::from("UpdateCommitteeAction"),
        String::from("VRFCert"),
        String::from("Value"),
        String::from("VersionedBlock"),
        String::from("Vkey"),
        String::from("Vkeywitness"),
        String::from("Vkeywitnesses"),
        String::from("VoteDelegation"),
        String::from("VoteRegistrationAndDelegation"),
        String::from("Voter"),
        String::from("VotingProcedure"),
        String::from("VotingProcedures"),
        String::from("VotingProposal"),
        String::from("VotingProposals"),
        String::from("Withdrawals"),
        String::from("ByronAddress"),
        String::from("KESSignature"),
        String::from("LegacyDaedalusPrivateKey"),
        String::from("RewardAddress"),
        String::from("PointerAddress"),
        String::from("BaseAddress"),
        String::from("EnterpriseAddress"),
    ]
}

// Decodes a given input as a particular type, returning a JsValue (serialized JSON or other representation)

#[wasm_bindgen]
pub fn decode_specific_type(
    input: &str,
    type_name: &str,
    params_json: JsValue,
) -> Result<JsValue, String> {
    let params: DecodingParams = from_js_value(&params_json)?;

    // Run our checks ONCE at the top of the function:
    let is_hex = is_valid_hex(input);
    let is_base58 = is_valid_base58(input);
    let is_bech32 = is_valid_bech32(input);

    match type_name {
        "Address" => decode_address(input, is_hex, is_bech32, is_base58),

        "AnchorDataHash" => {
            if is_hex {
                if let Ok(decoded) = csl::AnchorDataHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::AnchorDataHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "AuxiliaryDataHash" => {
            if is_hex {
                if let Ok(decoded) = csl::AuxiliaryDataHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::AuxiliaryDataHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Bip32PrivateKey" => {
            if is_hex {
                if let Ok(decoded) = csl::Bip32PrivateKey::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::Bip32PrivateKey::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Bip32PublicKey" => {
            if is_hex {
                if let Ok(decoded) = csl::Bip32PublicKey::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::Bip32PublicKey::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "BlockHash" => {
            if is_hex {
                if let Ok(decoded) = csl::BlockHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::BlockHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DRep" => {
            if is_hex {
                if let Ok(decoded) = csl::DRep::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::DRep::from_bech32(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DataHash" => {
            if is_hex {
                if let Ok(decoded) = csl::DataHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::DataHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Ed25519KeyHash" => {
            if is_hex {
                if let Ok(decoded) = csl::Ed25519KeyHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::Ed25519KeyHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Ed25519Signature" => {
            if is_hex {
                if let Ok(decoded) = csl::Ed25519Signature::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::Ed25519Signature::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "GenesisDelegateHash" => {
            if is_hex {
                if let Ok(decoded) = csl::GenesisDelegateHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::GenesisDelegateHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "GenesisHash" => {
            if is_hex {
                if let Ok(decoded) = csl::GenesisHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::GenesisHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "KESVKey" => {
            if is_hex {
                if let Ok(decoded) = csl::KESVKey::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::KESVKey::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PoolMetadataHash" => {
            if is_hex {
                if let Ok(decoded) = csl::PoolMetadataHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::PoolMetadataHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PrivateKey" => {
            if is_hex {
                if let Ok(decoded) = csl::PrivateKey::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::PrivateKey::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PublicKey" => {
            if is_hex {
                if let Ok(decoded) = csl::PublicKey::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::PublicKey::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptDataHash" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptDataHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::ScriptDataHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptHash" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::ScriptHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionHash" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::TransactionHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VRFKeyHash" => {
            if is_hex {
                if let Ok(decoded) = csl::VRFKeyHash::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::VRFKeyHash::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VRFVKey" => {
            if is_hex {
                if let Ok(decoded) = csl::VRFVKey::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            if is_bech32 {
                if let Ok(decoded) = csl::VRFVKey::from_bech32(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex(),
                      "bech32": decoded.to_bech32("").map_err(|e| format!("Failed to convert to bech32: {:?}", e))?
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Anchor" => {
            if is_hex {
                if let Ok(decoded) = csl::Anchor::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "AssetName" => {
            if is_hex {
                if let Ok(decoded) = csl::AssetName::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "AssetNames" => {
            if is_hex {
                if let Ok(decoded) = csl::AssetNames::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Assets" => {
            if is_hex {
                if let Ok(decoded) = csl::Assets::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "AuxiliaryData" => {
            if is_hex {
                if let Ok(decoded) = csl::AuxiliaryData::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "BigInt" => {
            if is_hex {
                if let Ok(decoded) = csl::BigInt::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "BigNum" => {
            if is_hex {
                if let Ok(decoded) = csl::BigNum::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Block" => {
            if is_hex {
                if let Ok(decoded) = csl::Block::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "BootstrapWitness" => {
            if is_hex {
                if let Ok(decoded) = csl::BootstrapWitness::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "BootstrapWitnesses" => {
            if is_hex {
                if let Ok(decoded) = csl::BootstrapWitnesses::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Certificate" => {
            if is_hex {
                if let Ok(decoded) = csl::Certificate::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Certificates" => {
            if is_hex {
                if let Ok(decoded) = csl::Certificates::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Committee" => {
            if is_hex {
                if let Ok(decoded) = csl::Committee::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "CommitteeColdResign" => {
            if is_hex {
                if let Ok(decoded) = csl::CommitteeColdResign::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "CommitteeHotAuth" => {
            if is_hex {
                if let Ok(decoded) = csl::CommitteeHotAuth::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Constitution" => {
            if is_hex {
                if let Ok(decoded) = csl::Constitution::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ConstrPlutusData" => {
            if is_hex {
                if let Ok(decoded) = csl::ConstrPlutusData::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "CostModel" => {
            if is_hex {
                if let Ok(decoded) = csl::CostModel::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Costmdls" => {
            if is_hex {
                if let Ok(decoded) = csl::Costmdls::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Credential" => {
            if is_hex {
                if let Ok(decoded) = csl::Credential::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Credentials" => {
            if is_hex {
                if let Ok(decoded) = csl::Credentials::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DNSRecordAorAAAA" => {
            if is_hex {
                if let Ok(decoded) = csl::DNSRecordAorAAAA::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DNSRecordSRV" => {
            if is_hex {
                if let Ok(decoded) = csl::DNSRecordSRV::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DRepDeregistration" => {
            if is_hex {
                if let Ok(decoded) = csl::DRepDeregistration::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DRepRegistration" => {
            if is_hex {
                if let Ok(decoded) = csl::DRepRegistration::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DRepUpdate" => {
            if is_hex {
                if let Ok(decoded) = csl::DRepUpdate::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "DRepVotingThresholds" => {
            if is_hex {
                if let Ok(decoded) = csl::DRepVotingThresholds::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Ed25519KeyHashes" => {
            if is_hex {
                if let Ok(decoded) = csl::Ed25519KeyHashes::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ExUnitPrices" => {
            if is_hex {
                if let Ok(decoded) = csl::ExUnitPrices::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ExUnits" => {
            if is_hex {
                if let Ok(decoded) = csl::ExUnits::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "GeneralTransactionMetadata" => {
            if is_hex {
                if let Ok(decoded) = csl::GeneralTransactionMetadata::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "GenesisHashes" => {
            if is_hex {
                if let Ok(decoded) = csl::GenesisHashes::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "GenesisKeyDelegation" => {
            if is_hex {
                if let Ok(decoded) = csl::GenesisKeyDelegation::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "GovernanceAction" => {
            if is_hex {
                if let Ok(decoded) = csl::GovernanceAction::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "GovernanceActionId" => {
            if is_hex {
                if let Ok(decoded) = csl::GovernanceActionId::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "HardForkInitiationAction" => {
            if is_hex {
                if let Ok(decoded) = csl::HardForkInitiationAction::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Header" => {
            if is_hex {
                if let Ok(decoded) = csl::Header::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "HeaderBody" => {
            if is_hex {
                if let Ok(decoded) = csl::HeaderBody::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Int" => {
            if is_hex {
                if let Ok(decoded) = csl::Int::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Ipv4" => {
            if is_hex {
                if let Ok(decoded) = csl::Ipv4::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Ipv6" => {
            if is_hex {
                if let Ok(decoded) = csl::Ipv6::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Language" => {
            if is_hex {
                if let Ok(decoded) = csl::Language::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "MIRToStakeCredentials" => {
            if is_hex {
                if let Ok(decoded) = csl::MIRToStakeCredentials::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "MetadataList" => {
            if is_hex {
                if let Ok(decoded) = csl::MetadataList::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "MetadataMap" => {
            if is_hex {
                if let Ok(decoded) = csl::MetadataMap::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Mint" => {
            if is_hex {
                if let Ok(decoded) = csl::Mint::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "MoveInstantaneousReward" => {
            if is_hex {
                if let Ok(decoded) = csl::MoveInstantaneousReward::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "MoveInstantaneousRewardsCert" => {
            if is_hex {
                if let Ok(decoded) = csl::MoveInstantaneousRewardsCert::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "MultiAsset" => {
            if is_hex {
                if let Ok(decoded) = csl::MultiAsset::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "MultiHostName" => {
            if is_hex {
                if let Ok(decoded) = csl::MultiHostName::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "NativeScript" => {
            decode_native_script(input, is_hex, is_bech32, is_base58)
        }

        "NativeScripts" => {
            if is_hex {
                if let Ok(decoded) = csl::NativeScripts::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "NetworkId" => {
            if is_hex {
                if let Ok(decoded) = csl::NetworkId::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "NewConstitutionAction" => {
            if is_hex {
                if let Ok(decoded) = csl::NewConstitutionAction::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "NoConfidenceAction" => {
            if is_hex {
                if let Ok(decoded) = csl::NoConfidenceAction::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Nonce" => {
            if is_hex {
                if let Ok(decoded) = csl::Nonce::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "OperationalCert" => {
            if is_hex {
                if let Ok(decoded) = csl::OperationalCert::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ParameterChangeAction" => {
            if is_hex {
                if let Ok(decoded) = csl::ParameterChangeAction::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PlutusData" => decode_plutus_data(
            input,
            params.plutus_data_schema,
            is_hex,
            is_bech32,
            is_base58,
        ),

        "PlutusList" => {
            if is_hex {
                if let Ok(decoded) = csl::PlutusList::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PlutusMap" => {
            if is_hex {
                if let Ok(decoded) = csl::PlutusMap::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PlutusScript" => decode_plutus_script(
            input,
            params.plutus_script_version,
            is_hex,
            is_bech32,
            is_base58,
        ),

        "PlutusScripts" => {
            if is_hex {
                if let Ok(decoded) = csl::PlutusScripts::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PoolMetadata" => {
            if is_hex {
                if let Ok(decoded) = csl::PoolMetadata::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PoolParams" => {
            if is_hex {
                if let Ok(decoded) = csl::PoolParams::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PoolRegistration" => {
            if is_hex {
                if let Ok(decoded) = csl::PoolRegistration::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PoolRetirement" => {
            if is_hex {
                if let Ok(decoded) = csl::PoolRetirement::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "PoolVotingThresholds" => {
            if is_hex {
                if let Ok(decoded) = csl::PoolVotingThresholds::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ProposedProtocolParameterUpdates" => {
            if is_hex {
                if let Ok(decoded) = csl::ProposedProtocolParameterUpdates::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ProtocolParamUpdate" => {
            if is_hex {
                if let Ok(decoded) = csl::ProtocolParamUpdate::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ProtocolVersion" => {
            if is_hex {
                if let Ok(decoded) = csl::ProtocolVersion::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Redeemer" => {
            if is_hex {
                if let Ok(decoded) = csl::Redeemer::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "RedeemerTag" => {
            if is_hex {
                if let Ok(decoded) = csl::RedeemerTag::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Redeemers" => {
            if is_hex {
                if let Ok(decoded) = csl::Redeemers::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Relay" => {
            if is_hex {
                if let Ok(decoded) = csl::Relay::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Relays" => {
            if is_hex {
                if let Ok(decoded) = csl::Relays::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "RewardAddresses" => {
            if is_hex {
                if let Ok(decoded) = csl::RewardAddresses::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptAll" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptAll::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptAny" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptAny::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptHashes" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptHashes::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptNOfK" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptNOfK::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptPubkey" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptPubkey::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ScriptRef" => {
            if is_hex {
                if let Ok(decoded) = csl::ScriptRef::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "SingleHostAddr" => {
            if is_hex {
                if let Ok(decoded) = csl::SingleHostAddr::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "SingleHostName" => {
            if is_hex {
                if let Ok(decoded) = csl::SingleHostName::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "StakeAndVoteDelegation" => {
            if is_hex {
                if let Ok(decoded) = csl::StakeAndVoteDelegation::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "StakeDelegation" => {
            if is_hex {
                if let Ok(decoded) = csl::StakeDelegation::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "StakeDeregistration" => {
            if is_hex {
                if let Ok(decoded) = csl::StakeDeregistration::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "StakeRegistration" => {
            if is_hex {
                if let Ok(decoded) = csl::StakeRegistration::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "StakeRegistrationAndDelegation" => {
            if is_hex {
                if let Ok(decoded) = csl::StakeRegistrationAndDelegation::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "StakeVoteRegistrationAndDelegation" => {
            if is_hex {
                if let Ok(decoded) = csl::StakeVoteRegistrationAndDelegation::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TimelockExpiry" => {
            if is_hex {
                if let Ok(decoded) = csl::TimelockExpiry::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TimelockStart" => {
            if is_hex {
                if let Ok(decoded) = csl::TimelockStart::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Transaction" => decode_transaction(input, is_hex, is_bech32, is_base58),

        "TransactionBodies" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionBodies::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionBody" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionBody::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionInput" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionInput::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionInputs" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionInputs::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionMetadatum" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionMetadatum::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionMetadatumLabels" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionMetadatumLabels::from_hex(input) {
                    let value = Ok::<serde_json::Value, String>(serde_json::json!({
                      "hex": decoded.to_hex()
                    }))?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionOutput" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionOutput::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionOutputs" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionOutputs::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionUnspentOutput" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionUnspentOutput::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionWitnessSet" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionWitnessSet::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TransactionWitnessSets" => {
            if is_hex {
                if let Ok(decoded) = csl::TransactionWitnessSets::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "TreasuryWithdrawalsAction" => {
            if is_hex {
                if let Ok(decoded) = csl::TreasuryWithdrawalsAction::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "URL" => {
            if is_hex {
                if let Ok(decoded) = csl::URL::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "UnitInterval" => {
            if is_hex {
                if let Ok(decoded) = csl::UnitInterval::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Update" => {
            if is_hex {
                if let Ok(decoded) = csl::Update::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "UpdateCommitteeAction" => {
            if is_hex {
                if let Ok(decoded) = csl::UpdateCommitteeAction::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VRFCert" => {
            if is_hex {
                if let Ok(decoded) = csl::VRFCert::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Value" => {
            if is_hex {
                if let Ok(decoded) = csl::Value::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VersionedBlock" => {
            if is_hex {
                if let Ok(decoded) = csl::VersionedBlock::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Vkey" => {
            if is_hex {
                if let Ok(decoded) = csl::Vkey::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Vkeywitness" => {
            if is_hex {
                if let Ok(decoded) = csl::Vkeywitness::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Vkeywitnesses" => {
            if is_hex {
                if let Ok(decoded) = csl::Vkeywitnesses::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VoteDelegation" => {
            if is_hex {
                if let Ok(decoded) = csl::VoteDelegation::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VoteRegistrationAndDelegation" => {
            if is_hex {
                if let Ok(decoded) = csl::VoteRegistrationAndDelegation::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Voter" => {
            if is_hex {
                if let Ok(decoded) = csl::Voter::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VotingProcedure" => {
            if is_hex {
                if let Ok(decoded) = csl::VotingProcedure::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VotingProcedures" => {
            if is_hex {
                if let Ok(decoded) = csl::VotingProcedures::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VotingProposal" => {
            if is_hex {
                if let Ok(decoded) = csl::VotingProposal::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "VotingProposals" => {
            if is_hex {
                if let Ok(decoded) = csl::VotingProposals::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "Withdrawals" => {
            if is_hex {
                if let Ok(decoded) = csl::Withdrawals::from_hex(input) {
                    let value = decoded
                        .to_json()
                        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
                        .and_then(|json| {
                            serde_json::from_str(&json)
                                .map_err(|e| format!("Failed to parse JSON: {}", e))
                        })?;
                    return from_serde_json_value(&value)
                        .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                }
            }

            Err("Failed to decode".to_string())
        }

        "ByronAddress" => decode_address(input, is_hex, is_bech32, is_base58),

        "KESSignature" => {
            if is_hex {
                if let Ok(bytes) = hex::decode(input) {
                    if let Ok(_decoded) = csl::KESSignature::from_bytes(bytes) {
                        let value = Ok::<serde_json::Value, String>(serde_json::Value::String(
                            "Decoded, but no additional representation".to_string(),
                        ))?;
                        return from_serde_json_value(&value)
                            .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                    }
                }
            }

            Err("Failed to decode".to_string())
        }

        "LegacyDaedalusPrivateKey" => {
            if is_hex {
                if let Ok(bytes) = hex::decode(input) {
                    if let Ok(_decoded) = csl::LegacyDaedalusPrivateKey::from_bytes(&bytes) {
                        let value = Ok::<serde_json::Value, String>(serde_json::Value::String(
                            "Decoded, but no additional representation".to_string(),
                        ))?;
                        return from_serde_json_value(&value)
                            .map_err(|e| format!("Failed to convert to JsValue: {}", e));
                    }
                }
            }

            Err("Failed to decode".to_string())
        }

        "RewardAddress" => decode_address(input, is_hex, is_bech32, is_base58),

        "PointerAddress" => decode_address(input, is_hex, is_bech32, is_base58),

        "BaseAddress" => decode_address(input, is_hex, is_bech32, is_base58),

        "EnterpriseAddress" => decode_address(input, is_hex, is_bech32, is_base58),
        _ => Err("Unsupported type".to_string()),
    }
}

// Tries to decode the input as every known type, returning the list of which decodes succeeded

#[wasm_bindgen]
pub fn get_possible_types_for_input(input: &str) -> Vec<String> {
    let mut type_names = Vec::new();

    if decode_specific_type(input, "Address", empty_js_value()).is_ok() {
        type_names.push("Address".to_string());
    }

    if decode_specific_type(input, "AnchorDataHash", empty_js_value()).is_ok() {
        type_names.push("AnchorDataHash".to_string());
    }

    if decode_specific_type(input, "AuxiliaryDataHash", empty_js_value()).is_ok() {
        type_names.push("AuxiliaryDataHash".to_string());
    }

    if decode_specific_type(input, "Bip32PrivateKey", empty_js_value()).is_ok() {
        type_names.push("Bip32PrivateKey".to_string());
    }

    if decode_specific_type(input, "Bip32PublicKey", empty_js_value()).is_ok() {
        type_names.push("Bip32PublicKey".to_string());
    }

    if decode_specific_type(input, "BlockHash", empty_js_value()).is_ok() {
        type_names.push("BlockHash".to_string());
    }

    if decode_specific_type(input, "DRep", empty_js_value()).is_ok() {
        type_names.push("DRep".to_string());
    }

    if decode_specific_type(input, "DataHash", empty_js_value()).is_ok() {
        type_names.push("DataHash".to_string());
    }

    if decode_specific_type(input, "Ed25519KeyHash", empty_js_value()).is_ok() {
        type_names.push("Ed25519KeyHash".to_string());
    }

    if decode_specific_type(input, "Ed25519Signature", empty_js_value()).is_ok() {
        type_names.push("Ed25519Signature".to_string());
    }

    if decode_specific_type(input, "GenesisDelegateHash", empty_js_value()).is_ok() {
        type_names.push("GenesisDelegateHash".to_string());
    }

    if decode_specific_type(input, "GenesisHash", empty_js_value()).is_ok() {
        type_names.push("GenesisHash".to_string());
    }

    if decode_specific_type(input, "KESVKey", empty_js_value()).is_ok() {
        type_names.push("KESVKey".to_string());
    }

    if decode_specific_type(input, "PoolMetadataHash", empty_js_value()).is_ok() {
        type_names.push("PoolMetadataHash".to_string());
    }

    if decode_specific_type(input, "PrivateKey", empty_js_value()).is_ok() {
        type_names.push("PrivateKey".to_string());
    }

    if decode_specific_type(input, "PublicKey", empty_js_value()).is_ok() {
        type_names.push("PublicKey".to_string());
    }

    if decode_specific_type(input, "ScriptDataHash", empty_js_value()).is_ok() {
        type_names.push("ScriptDataHash".to_string());
    }

    if decode_specific_type(input, "ScriptHash", empty_js_value()).is_ok() {
        type_names.push("ScriptHash".to_string());
    }

    if decode_specific_type(input, "TransactionHash", empty_js_value()).is_ok() {
        type_names.push("TransactionHash".to_string());
    }

    if decode_specific_type(input, "VRFKeyHash", empty_js_value()).is_ok() {
        type_names.push("VRFKeyHash".to_string());
    }

    if decode_specific_type(input, "VRFVKey", empty_js_value()).is_ok() {
        type_names.push("VRFVKey".to_string());
    }

    if decode_specific_type(input, "Anchor", empty_js_value()).is_ok() {
        type_names.push("Anchor".to_string());
    }

    if decode_specific_type(input, "AssetName", empty_js_value()).is_ok() {
        type_names.push("AssetName".to_string());
    }

    if decode_specific_type(input, "AssetNames", empty_js_value()).is_ok() {
        type_names.push("AssetNames".to_string());
    }

    if decode_specific_type(input, "Assets", empty_js_value()).is_ok() {
        type_names.push("Assets".to_string());
    }

    if decode_specific_type(input, "AuxiliaryData", empty_js_value()).is_ok() {
        type_names.push("AuxiliaryData".to_string());
    }

    if decode_specific_type(input, "BigInt", empty_js_value()).is_ok() {
        type_names.push("BigInt".to_string());
    }

    if decode_specific_type(input, "BigNum", empty_js_value()).is_ok() {
        type_names.push("BigNum".to_string());
    }

    if decode_specific_type(input, "Block", empty_js_value()).is_ok() {
        type_names.push("Block".to_string());
    }

    if decode_specific_type(input, "BootstrapWitness", empty_js_value()).is_ok() {
        type_names.push("BootstrapWitness".to_string());
    }

    if decode_specific_type(input, "BootstrapWitnesses", empty_js_value()).is_ok() {
        type_names.push("BootstrapWitnesses".to_string());
    }

    if decode_specific_type(input, "Certificate", empty_js_value()).is_ok() {
        type_names.push("Certificate".to_string());
    }

    if decode_specific_type(input, "Certificates", empty_js_value()).is_ok() {
        type_names.push("Certificates".to_string());
    }

    if decode_specific_type(input, "Committee", empty_js_value()).is_ok() {
        type_names.push("Committee".to_string());
    }

    if decode_specific_type(input, "CommitteeColdResign", empty_js_value()).is_ok() {
        type_names.push("CommitteeColdResign".to_string());
    }

    if decode_specific_type(input, "CommitteeHotAuth", empty_js_value()).is_ok() {
        type_names.push("CommitteeHotAuth".to_string());
    }

    if decode_specific_type(input, "Constitution", empty_js_value()).is_ok() {
        type_names.push("Constitution".to_string());
    }

    if decode_specific_type(input, "ConstrPlutusData", empty_js_value()).is_ok() {
        type_names.push("ConstrPlutusData".to_string());
    }

    if decode_specific_type(input, "CostModel", empty_js_value()).is_ok() {
        type_names.push("CostModel".to_string());
    }

    if decode_specific_type(input, "Costmdls", empty_js_value()).is_ok() {
        type_names.push("Costmdls".to_string());
    }

    if decode_specific_type(input, "Credential", empty_js_value()).is_ok() {
        type_names.push("Credential".to_string());
    }

    if decode_specific_type(input, "Credentials", empty_js_value()).is_ok() {
        type_names.push("Credentials".to_string());
    }

    if decode_specific_type(input, "DNSRecordAorAAAA", empty_js_value()).is_ok() {
        type_names.push("DNSRecordAorAAAA".to_string());
    }

    if decode_specific_type(input, "DNSRecordSRV", empty_js_value()).is_ok() {
        type_names.push("DNSRecordSRV".to_string());
    }

    if decode_specific_type(input, "DRepDeregistration", empty_js_value()).is_ok() {
        type_names.push("DRepDeregistration".to_string());
    }

    if decode_specific_type(input, "DRepRegistration", empty_js_value()).is_ok() {
        type_names.push("DRepRegistration".to_string());
    }

    if decode_specific_type(input, "DRepUpdate", empty_js_value()).is_ok() {
        type_names.push("DRepUpdate".to_string());
    }

    if decode_specific_type(input, "DRepVotingThresholds", empty_js_value()).is_ok() {
        type_names.push("DRepVotingThresholds".to_string());
    }

    if decode_specific_type(input, "Ed25519KeyHashes", empty_js_value()).is_ok() {
        type_names.push("Ed25519KeyHashes".to_string());
    }

    if decode_specific_type(input, "ExUnitPrices", empty_js_value()).is_ok() {
        type_names.push("ExUnitPrices".to_string());
    }

    if decode_specific_type(input, "ExUnits", empty_js_value()).is_ok() {
        type_names.push("ExUnits".to_string());
    }

    if decode_specific_type(input, "GeneralTransactionMetadata", empty_js_value()).is_ok() {
        type_names.push("GeneralTransactionMetadata".to_string());
    }

    if decode_specific_type(input, "GenesisHashes", empty_js_value()).is_ok() {
        type_names.push("GenesisHashes".to_string());
    }

    if decode_specific_type(input, "GenesisKeyDelegation", empty_js_value()).is_ok() {
        type_names.push("GenesisKeyDelegation".to_string());
    }

    if decode_specific_type(input, "GovernanceAction", empty_js_value()).is_ok() {
        type_names.push("GovernanceAction".to_string());
    }

    if decode_specific_type(input, "GovernanceActionId", empty_js_value()).is_ok() {
        type_names.push("GovernanceActionId".to_string());
    }

    if decode_specific_type(input, "HardForkInitiationAction", empty_js_value()).is_ok() {
        type_names.push("HardForkInitiationAction".to_string());
    }

    if decode_specific_type(input, "Header", empty_js_value()).is_ok() {
        type_names.push("Header".to_string());
    }

    if decode_specific_type(input, "HeaderBody", empty_js_value()).is_ok() {
        type_names.push("HeaderBody".to_string());
    }

    if decode_specific_type(input, "Int", empty_js_value()).is_ok() {
        type_names.push("Int".to_string());
    }

    if decode_specific_type(input, "Ipv4", empty_js_value()).is_ok() {
        type_names.push("Ipv4".to_string());
    }

    if decode_specific_type(input, "Ipv6", empty_js_value()).is_ok() {
        type_names.push("Ipv6".to_string());
    }

    if decode_specific_type(input, "Language", empty_js_value()).is_ok() {
        type_names.push("Language".to_string());
    }

    if decode_specific_type(input, "MIRToStakeCredentials", empty_js_value()).is_ok() {
        type_names.push("MIRToStakeCredentials".to_string());
    }

    if decode_specific_type(input, "MetadataList", empty_js_value()).is_ok() {
        type_names.push("MetadataList".to_string());
    }

    if decode_specific_type(input, "MetadataMap", empty_js_value()).is_ok() {
        type_names.push("MetadataMap".to_string());
    }

    if decode_specific_type(input, "Mint", empty_js_value()).is_ok() {
        type_names.push("Mint".to_string());
    }

    if decode_specific_type(input, "MoveInstantaneousReward", empty_js_value()).is_ok() {
        type_names.push("MoveInstantaneousReward".to_string());
    }

    if decode_specific_type(input, "MoveInstantaneousRewardsCert", empty_js_value()).is_ok() {
        type_names.push("MoveInstantaneousRewardsCert".to_string());
    }

    if decode_specific_type(input, "MultiAsset", empty_js_value()).is_ok() {
        type_names.push("MultiAsset".to_string());
    }

    if decode_specific_type(input, "MultiHostName", empty_js_value()).is_ok() {
        type_names.push("MultiHostName".to_string());
    }

    if decode_specific_type(input, "NativeScript", empty_js_value()).is_ok() {
        type_names.push("NativeScript".to_string());
    }

    if decode_specific_type(input, "NativeScripts", empty_js_value()).is_ok() {
        type_names.push("NativeScripts".to_string());
    }

    if decode_specific_type(input, "NetworkId", empty_js_value()).is_ok() {
        type_names.push("NetworkId".to_string());
    }

    if decode_specific_type(input, "NewConstitutionAction", empty_js_value()).is_ok() {
        type_names.push("NewConstitutionAction".to_string());
    }

    if decode_specific_type(input, "NoConfidenceAction", empty_js_value()).is_ok() {
        type_names.push("NoConfidenceAction".to_string());
    }

    if decode_specific_type(input, "Nonce", empty_js_value()).is_ok() {
        type_names.push("Nonce".to_string());
    }

    if decode_specific_type(input, "OperationalCert", empty_js_value()).is_ok() {
        type_names.push("OperationalCert".to_string());
    }

    if decode_specific_type(input, "ParameterChangeAction", empty_js_value()).is_ok() {
        type_names.push("ParameterChangeAction".to_string());
    }

    if decode_specific_type(input, "PlutusData", empty_js_value()).is_ok() {
        type_names.push("PlutusData".to_string());
    }

    if decode_specific_type(input, "PlutusList", empty_js_value()).is_ok() {
        type_names.push("PlutusList".to_string());
    }

    if decode_specific_type(input, "PlutusMap", empty_js_value()).is_ok() {
        type_names.push("PlutusMap".to_string());
    }

    if decode_specific_type(input, "PlutusScript", empty_js_value()).is_ok() {
        type_names.push("PlutusScript".to_string());
    }

    if decode_specific_type(input, "PlutusScripts", empty_js_value()).is_ok() {
        type_names.push("PlutusScripts".to_string());
    }

    if decode_specific_type(input, "PoolMetadata", empty_js_value()).is_ok() {
        type_names.push("PoolMetadata".to_string());
    }

    if decode_specific_type(input, "PoolParams", empty_js_value()).is_ok() {
        type_names.push("PoolParams".to_string());
    }

    if decode_specific_type(input, "PoolRegistration", empty_js_value()).is_ok() {
        type_names.push("PoolRegistration".to_string());
    }

    if decode_specific_type(input, "PoolRetirement", empty_js_value()).is_ok() {
        type_names.push("PoolRetirement".to_string());
    }

    if decode_specific_type(input, "PoolVotingThresholds", empty_js_value()).is_ok() {
        type_names.push("PoolVotingThresholds".to_string());
    }

    if decode_specific_type(input, "ProposedProtocolParameterUpdates", empty_js_value()).is_ok() {
        type_names.push("ProposedProtocolParameterUpdates".to_string());
    }

    if decode_specific_type(input, "ProtocolParamUpdate", empty_js_value()).is_ok() {
        type_names.push("ProtocolParamUpdate".to_string());
    }

    if decode_specific_type(input, "ProtocolVersion", empty_js_value()).is_ok() {
        type_names.push("ProtocolVersion".to_string());
    }

    if decode_specific_type(input, "Redeemer", empty_js_value()).is_ok() {
        type_names.push("Redeemer".to_string());
    }

    if decode_specific_type(input, "RedeemerTag", empty_js_value()).is_ok() {
        type_names.push("RedeemerTag".to_string());
    }

    if decode_specific_type(input, "Redeemers", empty_js_value()).is_ok() {
        type_names.push("Redeemers".to_string());
    }

    if decode_specific_type(input, "Relay", empty_js_value()).is_ok() {
        type_names.push("Relay".to_string());
    }

    if decode_specific_type(input, "Relays", empty_js_value()).is_ok() {
        type_names.push("Relays".to_string());
    }

    if decode_specific_type(input, "RewardAddresses", empty_js_value()).is_ok() {
        type_names.push("RewardAddresses".to_string());
    }

    if decode_specific_type(input, "ScriptAll", empty_js_value()).is_ok() {
        type_names.push("ScriptAll".to_string());
    }

    if decode_specific_type(input, "ScriptAny", empty_js_value()).is_ok() {
        type_names.push("ScriptAny".to_string());
    }

    if decode_specific_type(input, "ScriptHashes", empty_js_value()).is_ok() {
        type_names.push("ScriptHashes".to_string());
    }

    if decode_specific_type(input, "ScriptNOfK", empty_js_value()).is_ok() {
        type_names.push("ScriptNOfK".to_string());
    }

    if decode_specific_type(input, "ScriptPubkey", empty_js_value()).is_ok() {
        type_names.push("ScriptPubkey".to_string());
    }

    if decode_specific_type(input, "ScriptRef", empty_js_value()).is_ok() {
        type_names.push("ScriptRef".to_string());
    }

    if decode_specific_type(input, "SingleHostAddr", empty_js_value()).is_ok() {
        type_names.push("SingleHostAddr".to_string());
    }

    if decode_specific_type(input, "SingleHostName", empty_js_value()).is_ok() {
        type_names.push("SingleHostName".to_string());
    }

    if decode_specific_type(input, "StakeAndVoteDelegation", empty_js_value()).is_ok() {
        type_names.push("StakeAndVoteDelegation".to_string());
    }

    if decode_specific_type(input, "StakeDelegation", empty_js_value()).is_ok() {
        type_names.push("StakeDelegation".to_string());
    }

    if decode_specific_type(input, "StakeDeregistration", empty_js_value()).is_ok() {
        type_names.push("StakeDeregistration".to_string());
    }

    if decode_specific_type(input, "StakeRegistration", empty_js_value()).is_ok() {
        type_names.push("StakeRegistration".to_string());
    }

    if decode_specific_type(input, "StakeRegistrationAndDelegation", empty_js_value()).is_ok() {
        type_names.push("StakeRegistrationAndDelegation".to_string());
    }

    if decode_specific_type(
        input,
        "StakeVoteRegistrationAndDelegation",
        empty_js_value(),
    )
    .is_ok()
    {
        type_names.push("StakeVoteRegistrationAndDelegation".to_string());
    }

    if decode_specific_type(input, "TimelockExpiry", empty_js_value()).is_ok() {
        type_names.push("TimelockExpiry".to_string());
    }

    if decode_specific_type(input, "TimelockStart", empty_js_value()).is_ok() {
        type_names.push("TimelockStart".to_string());
    }

    if decode_specific_type(input, "Transaction", empty_js_value()).is_ok() {
        type_names.push("Transaction".to_string());
    }

    if decode_specific_type(input, "TransactionBodies", empty_js_value()).is_ok() {
        type_names.push("TransactionBodies".to_string());
    }

    if decode_specific_type(input, "TransactionBody", empty_js_value()).is_ok() {
        type_names.push("TransactionBody".to_string());
    }

    if decode_specific_type(input, "TransactionInput", empty_js_value()).is_ok() {
        type_names.push("TransactionInput".to_string());
    }

    if decode_specific_type(input, "TransactionInputs", empty_js_value()).is_ok() {
        type_names.push("TransactionInputs".to_string());
    }

    if decode_specific_type(input, "TransactionMetadatum", empty_js_value()).is_ok() {
        type_names.push("TransactionMetadatum".to_string());
    }

    if decode_specific_type(input, "TransactionMetadatumLabels", empty_js_value()).is_ok() {
        type_names.push("TransactionMetadatumLabels".to_string());
    }

    if decode_specific_type(input, "TransactionOutput", empty_js_value()).is_ok() {
        type_names.push("TransactionOutput".to_string());
    }

    if decode_specific_type(input, "TransactionOutputs", empty_js_value()).is_ok() {
        type_names.push("TransactionOutputs".to_string());
    }

    if decode_specific_type(input, "TransactionUnspentOutput", empty_js_value()).is_ok() {
        type_names.push("TransactionUnspentOutput".to_string());
    }

    if decode_specific_type(input, "TransactionWitnessSet", empty_js_value()).is_ok() {
        type_names.push("TransactionWitnessSet".to_string());
    }

    if decode_specific_type(input, "TransactionWitnessSets", empty_js_value()).is_ok() {
        type_names.push("TransactionWitnessSets".to_string());
    }

    if decode_specific_type(input, "TreasuryWithdrawalsAction", empty_js_value()).is_ok() {
        type_names.push("TreasuryWithdrawalsAction".to_string());
    }

    if decode_specific_type(input, "URL", empty_js_value()).is_ok() {
        type_names.push("URL".to_string());
    }

    if decode_specific_type(input, "UnitInterval", empty_js_value()).is_ok() {
        type_names.push("UnitInterval".to_string());
    }

    if decode_specific_type(input, "Update", empty_js_value()).is_ok() {
        type_names.push("Update".to_string());
    }

    if decode_specific_type(input, "UpdateCommitteeAction", empty_js_value()).is_ok() {
        type_names.push("UpdateCommitteeAction".to_string());
    }

    if decode_specific_type(input, "VRFCert", empty_js_value()).is_ok() {
        type_names.push("VRFCert".to_string());
    }

    if decode_specific_type(input, "Value", empty_js_value()).is_ok() {
        type_names.push("Value".to_string());
    }

    if decode_specific_type(input, "VersionedBlock", empty_js_value()).is_ok() {
        type_names.push("VersionedBlock".to_string());
    }

    if decode_specific_type(input, "Vkey", empty_js_value()).is_ok() {
        type_names.push("Vkey".to_string());
    }

    if decode_specific_type(input, "Vkeywitness", empty_js_value()).is_ok() {
        type_names.push("Vkeywitness".to_string());
    }

    if decode_specific_type(input, "Vkeywitnesses", empty_js_value()).is_ok() {
        type_names.push("Vkeywitnesses".to_string());
    }

    if decode_specific_type(input, "VoteDelegation", empty_js_value()).is_ok() {
        type_names.push("VoteDelegation".to_string());
    }

    if decode_specific_type(input, "VoteRegistrationAndDelegation", empty_js_value()).is_ok() {
        type_names.push("VoteRegistrationAndDelegation".to_string());
    }

    if decode_specific_type(input, "Voter", empty_js_value()).is_ok() {
        type_names.push("Voter".to_string());
    }

    if decode_specific_type(input, "VotingProcedure", empty_js_value()).is_ok() {
        type_names.push("VotingProcedure".to_string());
    }

    if decode_specific_type(input, "VotingProcedures", empty_js_value()).is_ok() {
        type_names.push("VotingProcedures".to_string());
    }

    if decode_specific_type(input, "VotingProposal", empty_js_value()).is_ok() {
        type_names.push("VotingProposal".to_string());
    }

    if decode_specific_type(input, "VotingProposals", empty_js_value()).is_ok() {
        type_names.push("VotingProposals".to_string());
    }

    if decode_specific_type(input, "Withdrawals", empty_js_value()).is_ok() {
        type_names.push("Withdrawals".to_string());
    }

    if decode_specific_type(input, "ByronAddress", empty_js_value()).is_ok() {
        type_names.push("ByronAddress".to_string());
    }

    if decode_specific_type(input, "KESSignature", empty_js_value()).is_ok() {
        type_names.push("KESSignature".to_string());
    }

    if decode_specific_type(input, "LegacyDaedalusPrivateKey", empty_js_value()).is_ok() {
        type_names.push("LegacyDaedalusPrivateKey".to_string());
    }

    if decode_specific_type(input, "RewardAddress", empty_js_value()).is_ok() {
        type_names.push("RewardAddress".to_string());
    }

    if decode_specific_type(input, "PointerAddress", empty_js_value()).is_ok() {
        type_names.push("PointerAddress".to_string());
    }

    if decode_specific_type(input, "BaseAddress", empty_js_value()).is_ok() {
        type_names.push("BaseAddress".to_string());
    }

    if decode_specific_type(input, "EnterpriseAddress", empty_js_value()).is_ok() {
        type_names.push("EnterpriseAddress".to_string());
    }
    type_names
}