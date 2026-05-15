use std::env;
use cquisitor_lib::schema_generator;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let output_dir = if args.len() > 1 {
        &args[1]
    } else {
        "schemas"
    };
    
    println!("Generating JSON schemas...");
    println!("Output directory: {}", output_dir);
    
    match schema_generator::save_schemas_to_files(output_dir) {
        Ok(()) => {
            println!("✅ Successfully generated all JSON schemas!");
            println!("Generated files:");
            println!("  - {}/NecessaryInputData.schema.json", output_dir);
            println!("  - {}/ValidationResult.schema.json", output_dir);
            println!("  - {}/ValidationInputContext.schema.json", output_dir);
            println!("  - {}/SerializableScriptContext.schema.json", output_dir);
        },
        Err(e) => {
            eprintln!("❌ Error generating schemas: {}", e);
            std::process::exit(1);
        }
    }
} 