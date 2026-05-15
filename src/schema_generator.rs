use schemars::{schema_for};
use serde_json;
use std::collections::HashMap;

use crate::script_context::SerializableScriptContext;
use crate::validators::input_contexts::{NecessaryInputData, ValidationInputContext};
use crate::validators::validation_result::ValidationResult;

/// Generate JSON schemas for the three main types
pub fn generate_schemas() -> Result<HashMap<String, serde_json::Value>, String> {
    let mut schemas = HashMap::new();
    
    // Generate schema for NecessaryInputData
    let necessary_input_data_schema = schema_for!(NecessaryInputData);
    schemas.insert(
        "NecessaryInputData".to_string(),
        serde_json::to_value(necessary_input_data_schema)
            .map_err(|e| format!("Failed to serialize NecessaryInputData schema: {}", e))?
    );
    
    // Generate schema for ValidationResult
    let validation_result_schema = schema_for!(ValidationResult);
    schemas.insert(
        "ValidationResult".to_string(),
        serde_json::to_value(validation_result_schema)
            .map_err(|e| format!("Failed to serialize ValidationResult schema: {}", e))?
    );
    
    // Generate schema for ValidationInputContext
    let validation_input_context_schema = schema_for!(ValidationInputContext);
    schemas.insert(
        "ValidationInputContext".to_string(),
        serde_json::to_value(validation_input_context_schema)
            .map_err(|e| format!("Failed to serialize ValidationInputContext schema: {}", e))?
    );

    // Generate schema for SerializableScriptContext. It is not reachable from
    // the three root types (EvalRedeemerResult exposes it as a JSON string),
    // so it is registered standalone to keep its TypeScript types generated.
    let script_context_schema = schema_for!(SerializableScriptContext);
    schemas.insert(
        "SerializableScriptContext".to_string(),
        serde_json::to_value(script_context_schema)
            .map_err(|e| format!("Failed to serialize SerializableScriptContext schema: {}", e))?
    );

    Ok(schemas)
}

/// Generate JSON schemas as JSON strings
pub fn generate_schemas_as_json() -> Result<HashMap<String, String>, String> {
    let schemas = generate_schemas()?;
    let mut json_schemas = HashMap::new();
    
    for (name, schema) in schemas {
        let json_string = serde_json::to_string_pretty(&schema)
            .map_err(|e| format!("Failed to convert {} schema to JSON string: {}", name, e))?;
        json_schemas.insert(name, json_string);
    }
    
    Ok(json_schemas)
}

/// Generate all schemas and save them to files
pub fn save_schemas_to_files(output_dir: &str) -> Result<(), String> {
    let schemas = generate_schemas_as_json()?;
    
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("Failed to create output directory: {}", e))?;
    
    for (name, schema_json) in schemas {
        let filename = format!("{}/{}.schema.json", output_dir, name);
        std::fs::write(&filename, schema_json)
            .map_err(|e| format!("Failed to write schema file {}: {}", filename, e))?;
        println!("Generated schema: {}", filename);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_generation() {
        let schemas = generate_schemas().unwrap();
        assert!(schemas.contains_key("NecessaryInputData"));
        assert!(schemas.contains_key("ValidationResult"));
        assert!(schemas.contains_key("ValidationInputContext"));
    }

    #[test]
    fn test_json_schema_generation() {
        let schemas = generate_schemas_as_json().unwrap();
        assert!(schemas.contains_key("NecessaryInputData"));
        assert!(schemas.contains_key("ValidationResult"));
        assert!(schemas.contains_key("ValidationInputContext"));
        
        // Check that each schema is valid JSON
        for (name, schema_json) in schemas {
            serde_json::from_str::<serde_json::Value>(&schema_json)
                .unwrap_or_else(|_| panic!("Invalid JSON for schema: {}", name));
        }
    }
} 