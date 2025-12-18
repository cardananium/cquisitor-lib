use crate::csl_decoders::params::PlutusDataSchema;
use cardano_serialization_lib as csl;
use cardano_serialization_lib::chain_core::property::FromStr;
use cardano_serialization_lib::legacy_address::ExtendedAddr;
use cardano_serialization_lib::{AddressKind, ByronAddress, RewardAddress};
use serde_json::Value;
use crate::js_value::JsValue;
use crate::js_value::from_serde_json_value;
use crate::plutus::plutus_script_normalizer::{normalize_plutus_script_with_core_version, OutputEncoding};

pub fn decode_address(input: &str, is_hex: bool, is_bech32: bool, is_base58: bool) -> Result<JsValue, String> {
    let decoded = decode_address_internal(input, is_hex, is_bech32, is_base58)?;
    format_address(decoded)
}

pub fn decode_transaction(input: &str, is_hex: bool, _is_bech32: bool, _is_base58: bool) -> Result<JsValue, String> {
    if !is_hex {
        Err("Only hex encoding is supported".to_string())?;
    }
    let fixed_tx = csl::FixedTransaction::from_hex(input)
        .map_err(|e| format!("Failed to decode Transaction: {:?}", e))?;
    let parsed_tx: Value = csl::Transaction::from_hex(input)
        .map_err(|e| format!("Failed to decode Transaction: {:?}", e))
        .and_then(|tx| tx.to_json().map_err(|e| format!("Failed to convert to JSON: {:?}", e)))
        .and_then(|json| serde_json::from_str(&json).map_err(|e| format!("Failed to convert to JSON: {:?}", e)))?;
    let value = Ok::<Value, String>(serde_json::json!({
        "transaction_hash": fixed_tx.transaction_hash().to_hex(),
        "transaction": parsed_tx,
    }))?;
    from_serde_json_value(&value).map_err(|e| format!("Failed to convert to JsValue: {}", e))
}

pub fn decode_address_internal(input: &str, is_hex: bool, is_bech32: bool, is_base58: bool) -> Result<csl::Address, String> {
    if is_bech32 {
        if let Ok(decoded) = csl::Address::from_bech32(input) {
            return Ok(decoded);
        }
    }
    if is_base58 {
        return Ok(decode_byron_addr_internal(input, is_hex, is_bech32, is_base58)?.to_address());
    }
    if is_hex {
        if let Ok(decoded) = csl::Address::from_hex(input) {
            return Ok(decoded);
        } else if let Ok(byron_addr) = decode_byron_addr_internal(input, is_hex, is_bech32, is_base58) {
            return Ok(byron_addr.to_address());
        } else {
            return Err("Failed to decode".to_string());
        }
    }

    Err("Failed to decode".to_string())
}

pub fn format_address(address: csl::Address) -> Result<JsValue, String> {
    let address_type = address.kind();
    let json_representation = match address_type {
        AddressKind::Byron => {
            let byron_address = ByronAddress::from_address(&address).unwrap();
            format_byron_address(byron_address)
        }
        AddressKind::Pointer => {
            let pointer_address = csl::PointerAddress::from_address(&address).unwrap();
            format_pointer_address(pointer_address)
        }
        AddressKind::Enterprise => {
            let enterprise_address = csl::EnterpriseAddress::from_address(&address).unwrap();
            format_enterprise_address(enterprise_address)
        }
        AddressKind::Base => {
            let base_address = csl::BaseAddress::from_address(&address).unwrap();
            format_base_address(base_address)
        }
        AddressKind::Reward => {
            let reward_address = RewardAddress::from_address(&address).unwrap();
            format_reward_address(reward_address)
        }
        AddressKind::Malformed => Ok(Value::String("Malformed address".to_string())),
    }?;

    let address_info =  Ok::<Value, String>(serde_json::json!({
        "address_type": address_kind_to_string(address_type),
        "details": json_representation,
    }))?;
    from_serde_json_value(&address_info)
        .map_err(|e| format!("Failed to convert to JsValue: {}", e))
}

pub fn format_pointer_address(address: csl::PointerAddress) -> Result<Value, String> {
    let pointer = address.stake_pointer();
    let pointer_json =  Ok::<Value, String>(serde_json::json!({
        "slot": pointer.slot_bignum().to_string(),
        "transaction_index": pointer.tx_index_bignum().to_string(),
        "cert_index": pointer.cert_index_bignum().to_string(),
    }))?;
    Ok::<Value, String>(serde_json::json!({
        "address_bech32": address.to_address().to_bech32(None).unwrap(),
         "network_id": address.network_id(),
        "payment_cred": format_credential(address.payment_cred())?,
        "stake_pointer": pointer_json,
    }))
}

pub fn format_reward_address(address: RewardAddress) -> Result<Value, String> {
    Ok::<Value, String>(serde_json::json!({
        "address_bech32": address.to_address().to_bech32(None).unwrap(),
        "network_id": address.network_id(),
        "payment_cred": format_credential(address.payment_cred())?,
    }))
}

pub fn format_base_address(address: csl::BaseAddress) -> Result<Value, String> {
    Ok::<Value, String>(serde_json::json!({
        "address_bech32": address.to_address().to_bech32(None).unwrap(),
        "network_id": address.network_id(),
        "payment_cred": format_credential(address.payment_cred())?,
        "staking_cred": format_credential(address.stake_cred())?,
    }))
}

pub fn format_enterprise_address(address: csl::EnterpriseAddress) -> Result<Value, String> {
    Ok::<Value, String>(serde_json::json!({
        "address_bech32": address.to_address().to_bech32(None).unwrap(),
        "network_id": address.network_id(),
        "payment_cred": format_credential(address.payment_cred())?,
    }))
}

pub fn format_credential(cred: csl::Credential) -> Result<Value, String> {
    let kind = cred.kind();
    let credential_str = match kind {
        csl::CredKind::Key => {
            let key = cred.to_keyhash().unwrap();
            key.to_hex()
        }
        csl::CredKind::Script => {
            let script = cred.to_scripthash().unwrap();
            script.to_hex()
        }
    };
    Ok(serde_json::json!({
        "type": credential_kind_to_string(kind),
        "credential": credential_str,
    }))
}

pub fn credential_kind_to_string(kind: csl::CredKind) -> String {
    match kind {
        csl::CredKind::Key => "KeyHash".to_string(),
        csl::CredKind::Script => "ScriptHash".to_string(),
    }
}

pub fn address_kind_to_string(kind: AddressKind) -> String {
    match kind {
        AddressKind::Byron => "Byron".to_string(),
        AddressKind::Pointer => "Pointer".to_string(),
        AddressKind::Enterprise => "Enterprise".to_string(),
        AddressKind::Base => "Base".to_string(),
        AddressKind::Reward => "Reward".to_string(),
        AddressKind::Malformed => "Malformed".to_string(),
    }
}

pub fn format_byron_address(byron_address: ByronAddress) -> Result<Value, String> {
    let extended_address = ExtendedAddr::from_str(&byron_address.to_base58())
        .map_err(|e| format!("Failed to decode ExtendedAddr: {}", e))?;
     Ok::<Value, String>(serde_json::json!({
        "address_base58": byron_address.to_base58(),
        "address_bech32": byron_address.to_address().to_bech32(None).unwrap(),
        "type": map_byron_address_type(&extended_address),
        "derivation_path": map_byron_derivation_path(&extended_address),
    }))
}

pub fn map_byron_address_type(addr: &ExtendedAddr) -> String {
    format!("{}", addr.addr_type).to_string()
}

pub fn map_byron_derivation_path(addr: &ExtendedAddr) -> String {
    match &addr.attributes.derivation_path {
        Some(path) => vec_to_string(path),
        None => "None".to_string(),
    }
}

fn vec_to_string(vec: &Vec<u8>) -> String {
    let mut result = "[".to_string();
    for i in 0..vec.len() {
        result.push_str(&vec[i].to_string());
        if i != vec.len() - 1 {
            result.push_str(", ");
        }
    }
    result.push_str("]");
    result
}

fn decode_byron_addr_internal(input: &str, is_hex: bool, _is_bech32: bool, is_base58: bool) -> Result<ByronAddress, String> {
    if is_hex {
        if let Ok(bytes) = hex::decode(input) {
            if let Ok(decoded) = csl::ByronAddress::from_bytes(bytes) {
                return Ok(decoded);
            }
        }
    }
    if is_base58 {
        if let Ok(decoded) = csl::ByronAddress::from_base58(input) {
            return Ok(decoded);
        }
    }
    Err("Failed to decode".to_string())
}

pub fn decode_native_script(input: &str, is_hex: bool, _is_bech32: bool, _is_base58: bool) -> Result<JsValue, String> {
    if !is_hex {
        Err("Only hex encoding is supported".to_string())?;
    }

    let script = csl::NativeScript::from_hex(input)
        .map_err(|e| format!("Failed to decode NativeScript: {:?}", e))?;
    let script_json = script.to_json()
        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))?;
    let script_value: Value = serde_json::from_str(&script_json)
        .map_err(|e| format!("Failed to convert to JSON: {:?}", e))?;
    let value =  Ok::<Value, String>(serde_json::json!({
      "script_hash": script.hash().to_hex(),
      "script": script_value,
    }))?;
    from_serde_json_value(&value).map_err(|e| format!("Failed to convert to JsValue: {}", e))
}

pub fn decode_plutus_script(input: &str, version: Option<i32>, is_hex: bool, _is_bech32: bool, _is_base58: bool) -> Result<JsValue, String> {
    if !is_hex {
        Err("Only hex encoding is supported".to_string())?;
    }
    let bytes = hex::decode(input).map_err(|e| format!("Failed to decode hex: {}", e))?;
    let (normalized_script, core_version) = normalize_plutus_script_with_core_version(&bytes, OutputEncoding::DoubleCBOR)
        .map_err(|e| format!("Failed to normalize Plutus script: {}", e))?;
    let version = version.unwrap_or(1);
    let core_version_str = format!("{}.{}.{}", core_version[0], core_version[1], core_version[2]);
    match version {
        1 => {
            let script = csl::PlutusScript::from_bytes(normalized_script)
                .map_err(|e| format!("Failed to decode Plutus script: {:?}", e))?;
            let value =  Ok::<Value, String>(serde_json::json!({
                "script_hash": script.hash().to_hex(),
                "core_version": core_version_str,
            }))?;
            from_serde_json_value(&value)
                .map_err(|e| format!("Failed to convert to JsValue: {}", e))
        }
        2 => {
            let script = csl::PlutusScript::from_bytes_v2(normalized_script)
                .map_err(|e| format!("Failed to decode Plutus script: {:?}", e))?;
            let value =  Ok::<Value, String>(serde_json::json!({
                "script_hash": script.hash().to_hex(),
                "core_version": core_version_str,
            }))?;
            from_serde_json_value(&value)
                .map_err(|e| format!("Failed to convert to JsValue: {}", e))
        }
        3 => {
            let script = csl::PlutusScript::from_bytes_v3(normalized_script)
                .map_err(|e| format!("Failed to decode Plutus script: {:?}", e))?;
            let value =  Ok::<Value, String>(serde_json::json!({
                "script_hash": script.hash().to_hex(),
                "core_version": core_version_str,
            }))?;
            from_serde_json_value(&value)
                .map_err(|e| format!("Failed to convert to JsValue: {}", e))
        }
        _ => Err("Invalid Plutus script version".to_string()),
    }
}

pub fn decode_plutus_data(
    input: &str,
    schema: Option<PlutusDataSchema>,
    is_hex: bool,
    _is_bech32: bool,
    _is_base58: bool
) -> Result<JsValue, String> {
    if !is_hex {
        Err("Only hex encoding is supported".to_string())?;
    }
    if let Ok(decoded) = csl::PlutusData::from_hex(input) {
        let value: Value = decoded
            .to_json(map_schema(schema))
            .map_err(|e| format!("Failed to convert to JSON: {:?}", e))
            .and_then(|json| {
                serde_json::from_str(&json).map_err(|e| format!("Failed to parse JSON: {}", e))
            })?;
        return from_serde_json_value(&value)
            .map_err(|e| format!("Failed to convert to JsValue: {}", e));
    }
    Err("Failed to decode".to_string())
}

pub fn map_schema(schema: Option<PlutusDataSchema>) -> csl::PlutusDatumSchema {
    match schema {
        Some(PlutusDataSchema::BasicConversions) => csl::PlutusDatumSchema::BasicConversions,
        Some(PlutusDataSchema::DetailedSchema) => csl::PlutusDatumSchema::DetailedSchema,
        None => csl::PlutusDatumSchema::BasicConversions,
    }
}
