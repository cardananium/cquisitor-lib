use std::fmt;
use schemars::JsonSchema;
use std::convert::TryFrom;
use serde::{Serialize, Deserialize, ser::{SerializeStruct, Serializer}, de::{self, Deserializer, Visitor}};
use cardano_serialization_lib as csl;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Value {
    pub assets: MultiAsset,
    pub coins: i128,
}

#[derive(Debug, Clone,Hash, Serialize, Deserialize, JsonSchema)]
pub struct MultiAsset {
    assets: Vec<ValidatorAsset>,
}

impl Eq for MultiAsset {}
impl PartialEq for MultiAsset {
    fn eq(&self, other: &Self) -> bool {
        if self.assets.len() != other.assets.len() {
            return false;
        }
        for asset in &self.assets {
            if !other.assets.contains(asset) {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatorAsset {
    pub unit: String,
    pub quantity: i128,
}

impl MultiAsset {
    pub fn new() -> Self {
        MultiAsset {
            assets: Vec::new(),
        }
    }

    pub fn new_from_csl_multiasset(multiasset: &csl::MultiAsset, abs: bool) -> Self {
        let mut new_multiasset = MultiAsset::new();
        let keys = multiasset.keys();
        for i in 0..keys.len() {
            let key = keys.get(i);
            let assets = multiasset.get(&key);
            if let Some(assets) = assets {
                let asset_keys = assets.keys();
                for j in 0..asset_keys.len() {
                    let asset_name = asset_keys.get(j);
                    let quantity = assets.get(&asset_name)
                        .map(|q| q.to_string().parse::<i128>().unwrap())
                        .unwrap_or(0);
                    let unit = format!("{}{}", key.to_hex(), hex::encode(asset_name.name()));
                    if abs {
                        new_multiasset.add_asset(unit, quantity.abs());
                    } else {
                        new_multiasset.add_asset(unit, quantity);
                    }

                }
            }
        }
        new_multiasset
    }

    pub fn add_asset(&mut self, unit: String, quantity: i128) {
        let mut found = false;
        for asset in &mut self.assets {
            if asset.unit == unit {
                asset.quantity += quantity;
                found = true;
                break;
            }
        }

        if !found && quantity != 0 {
            self.assets.push(ValidatorAsset {
                unit,
                quantity,
            });
        }

        // Clean up any zero-quantity assets
        self.assets.retain(|asset| asset.quantity != 0);
    }

    pub fn set_asset(&mut self, unit: String, quantity: i128) {
        self.assets.retain(|asset| asset.unit != unit);
        self.add_asset(unit, quantity);
    }

    pub fn add(&mut self, other: &MultiAsset) {
        for other_asset in &other.assets {
            self.add_asset(other_asset.unit.clone(), other_asset.quantity);
        }
    }

    pub fn subtract(&mut self, other: &MultiAsset) {
        for other_asset in &other.assets {
            self.add_asset(other_asset.unit.clone(), -other_asset.quantity);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.assets.is_empty()
    }

    pub fn is_positive(&self) -> bool {
        for asset in &self.assets {
            if asset.quantity < 0 {
                return false;
            }
        }
        true
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ValidatorAsset> {
        self.assets.iter()
    }
}

impl Value {
    // Create an empty value (zero)
    pub fn zero() -> Self {
        Value {
            assets: MultiAsset::new(),
            coins: 0,
        }
    }

    // Create a new value with only ADA/Lovelace
    pub fn new_from_coins(coins: i128) -> Self {
        Value {
            assets: MultiAsset::new(),
            coins,
        }
    }

    /// The value of a UTxO's asset list. A quantity that is not an integer
    /// is an input error, named with its unit.
    pub fn new_from_common_assets(assets: &Vec<crate::common::Asset>) -> Result<Self, String> {
        let mut value = Value::zero();
        for asset in assets {
            let quantity = asset.quantity.parse::<i128>().map_err(|e| {
                format!(
                    "Invalid quantity '{}' for asset '{}': {}",
                    asset.quantity, asset.unit, e
                )
            })?;
            if asset.unit == "lovelace" || asset.unit.is_empty() {
                value.add_coins(quantity);
            } else {
                value.add_asset(asset.unit.clone(), quantity);
            }
        }
        Ok(value)
    }

    pub fn new_from_csl_value(value: &csl::Value) -> Self {
        let mut new_value = Value::zero();
        if let Some(multiasset) = value.multiasset() {
            new_value.assets = MultiAsset::new_from_csl_multiasset(&multiasset, false);
        }
        let coins = value.coin().to_string().parse::<i128>().unwrap_or(0);
        new_value.coins = coins;
        new_value
    }

    // Add ADA/Lovelace to this value
    pub fn add_coins(&mut self, coins: i128) {
        self.coins += coins;
    }

    // Add another Value to this Value (internal implementation)
    pub fn add_ref(&mut self, other: &Value) {
        // Add coins
        self.coins += other.coins;
        // Add assets
        self.assets.add(&other.assets);
    }

    // Add another Value to this Value (public API)
    pub fn add(&mut self, other: &Value) {
        self.add_ref(other);
    }

    // Add a specific asset to this Value
    pub fn add_asset(&mut self, unit: String, quantity: i128) {
        self.assets.add_asset(unit, quantity);
    }

    pub fn add_multiasset(&mut self, other: &MultiAsset) {
        self.assets.add(other);
    }

    pub fn set_asset(&mut self, unit: String, quantity: i128) {
        self.assets.set_asset(unit, quantity);
    }

    // Subtract another Value from this Value (internal implementation)
    pub fn subtract_ref(&mut self, other: &Value) {
        // Subtract coins
        self.coins -= other.coins;
        // Subtract assets
        self.assets.subtract(&other.assets);
    }

    // Subtract another Value from this Value (public API)
    pub fn subtract(&mut self, other: &Value) {
        self.subtract_ref(other);
    }

    pub fn subtract_multiasset(&mut self, other: &MultiAsset) {
        self.assets.subtract(other);
    }

    // Get the difference between this Value and another Value
    pub fn difference(&self, other: &Value) -> Value {
        let mut result = self.clone();
        result.subtract_ref(other);
        result
    }

    pub fn has_assets(&self) -> bool {
        !self.assets.is_empty()
    }

    // Check if this Value is positive (all coins and assets >= 0)
    pub fn is_positive(&self) -> bool {
        if self.coins < 0 {
            return false;
        }
        self.assets.is_positive()
    }

    // Sum multiple Values
    pub fn sum(values: &[Value]) -> Value {
        let mut result = Value::zero();
        for value in values {
            result.add_ref(value);
        }
        result
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let json = serde_json::to_string(self).unwrap();
        write!(f, "{}", json)?;
        Ok(())
    }
}

// Make Value implement the std::ops::Add trait
impl std::ops::Add for Value {
    type Output = Value;

    fn add(mut self, other: Value) -> Value {
        self.add_ref(&other);
        self
    }
}

// Make Value implement the std::ops::AddAssign trait
impl std::ops::AddAssign for Value {
    fn add_assign(&mut self, other: Self) {
        self.add_ref(&other);
    }
}

// Make Value implement the std::ops::Sub trait
impl std::ops::Sub for Value {
    type Output = Value;

    fn sub(mut self, other: Value) -> Value {
        self.subtract_ref(&other);
        self
    }
}

impl std::ops::Sub for &Value {
    type Output = Value;

    fn sub(self, other: &Value) -> Value {
        let mut result = self.clone();
        result.subtract_ref(other);
        result
    }
}
// Make Value implement the std::ops::SubAssign trait
impl std::ops::SubAssign for Value {
    fn sub_assign(&mut self, other: Value) {
        self.subtract_ref(&other);
    }
}

impl Serialize for ValidatorAsset {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // A unit is a policy id (56 hex characters) followed by the asset
        // name; one too short or split inside a character is reported whole
        // as the policy id rather than sliced.
        let (policy_id, asset_name) = if self.unit.is_char_boundary(56) {
            self.unit.split_at(56)
        } else {
            (self.unit.as_str(), "")
        };
        let mut state = serializer.serialize_struct("Asset", 3)?;
        state.serialize_field("policy_id", policy_id)?;
        state.serialize_field("asset_name", asset_name)?;
        state.serialize_field("quantity", &self.quantity)?;
        state.end()
    }
}

impl JsonSchema for ValidatorAsset {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ValidatorAsset".into()
    }
    
    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        serde_json::from_value(serde_json::json!({
            "type": "object",
            "properties": {
                "policy_id": {
                    "type": "string"
                },
                "asset_name": {
                    "type": "string"
                },
                "quantity": {
                    "type": "integer"
                }
            },
            "required": ["policy_id", "asset_name", "quantity"]
        })).unwrap()
    }
}

impl<'de> Deserialize<'de> for ValidatorAsset {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            PolicyId,
            AssetName,
            Quantity,
        }

        struct AssetVisitor;
        impl<'de> Visitor<'de> for AssetVisitor {
            type Value = ValidatorAsset;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Asset with policy_id, asset_name, and quantity")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ValidatorAsset, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mut policy_id: Option<String> = None;
                let mut asset_name: Option<String> = None;
                let mut quantity: Option<i128> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PolicyId => {
                            if policy_id.is_some() {
                                return Err(de::Error::duplicate_field("policy_id"));
                            }
                            policy_id = Some(map.next_value()?);
                        }
                        Field::AssetName => {
                            if asset_name.is_some() {
                                return Err(de::Error::duplicate_field("asset_name"));
                            }
                            asset_name = Some(map.next_value()?);
                        }
                        Field::Quantity => {
                            if quantity.is_some() {
                                return Err(de::Error::duplicate_field("quantity"));
                            }
                            quantity = Some(map.next_value()?);
                        }
                    }
                }

                let policy_id: String = policy_id.ok_or_else(|| de::Error::missing_field("policy_id"))?;
                let asset_name: String = asset_name.ok_or_else(|| de::Error::missing_field("asset_name"))?;
                let quantity = quantity.ok_or_else(|| de::Error::missing_field("quantity"))?;

                Ok(ValidatorAsset    {
                    unit: format!("{}{}", policy_id, asset_name),
                    quantity,   
                })
            }
        }

        deserializer.deserialize_struct("Asset", &["policy_id", "asset_name", "quantity"], AssetVisitor)
    }
} 