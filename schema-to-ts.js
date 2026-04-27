#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { compile } from 'json-schema-to-typescript';

/**
 * Extract all field paths that should be bigint from a schema based on format
 */
function extractBigIntFields(schema, prefix = '', bigIntFields = new Map(), typeName = '') {
    if (!schema || typeof schema !== 'object') return bigIntFields;
    
    // Check if this is a bigint field based on format
    if (schema.type === 'integer' && (schema.format === 'uint64' || schema.format === 'int64')) {
        const fieldPath = prefix || typeName;
        if (!bigIntFields.has(fieldPath)) {
            bigIntFields.set(fieldPath, []);
        }
        bigIntFields.get(fieldPath).push({
            path: prefix,
            format: schema.format
        });
    }
    
    // Recursively check properties
    if (schema.properties) {
        Object.entries(schema.properties).forEach(([key, propSchema]) => {
            const newPrefix = prefix ? `${prefix}.${key}` : key;
            extractBigIntFields(propSchema, newPrefix, bigIntFields, typeName);
        });
    }
    
    // Check array items
    if (schema.items) {
        extractBigIntFields(schema.items, prefix, bigIntFields, typeName);
    }
    
    // Check oneOf, anyOf, allOf
    ['oneOf', 'anyOf', 'allOf'].forEach(unionKey => {
        if (schema[unionKey] && Array.isArray(schema[unionKey])) {
            schema[unionKey].forEach(subSchema => {
                extractBigIntFields(subSchema, prefix, bigIntFields, typeName);
            });
        }
    });
    
    // Check definitions/defs
    if (schema.$defs) {
        Object.entries(schema.$defs).forEach(([defName, defSchema]) => {
            extractBigIntFields(defSchema, '', bigIntFields, defName);
        });
    }
    
    if (schema.definitions) {
        Object.entries(schema.definitions).forEach(([defName, defSchema]) => {
            extractBigIntFields(defSchema, '', bigIntFields, defName);
        });
    }
    
    return bigIntFields;
}

/**
 * Convert number types to bigint based on schema format information
 */
function convertToBigInt(content, allSchemas) {
    console.log('🔄 Converting uint64/int64 fields to bigint based on schema format...');
    
    // Collect all fields that should be bigint from all schemas
    const bigIntFields = new Map();
    Object.entries(allSchemas).forEach(([typeName, schema]) => {
        extractBigIntFields(schema, '', bigIntFields, typeName);
    });
    
    console.log(`📋 Found ${bigIntFields.size} types with bigint fields:`, 
        Array.from(bigIntFields.keys()));
    
    // Debug: show what fields were found
    bigIntFields.forEach((fields, typeName) => {
        if (fields.length > 0) {
            console.log(`  ${typeName}: ${fields.map(f => f.path || 'root').join(', ')}`);
        }
    });
    
    let convertedContent = content;
    
    // Convert fields based on their actual schema format
    bigIntFields.forEach((fields, typeName) => {
        fields.forEach(fieldInfo => {
            if (fieldInfo.path) {
                // Extract just the field name from the path
                const fieldName = fieldInfo.path.split('.').pop();
                
                // Pattern: fieldName: number; (in context of the type)
                const pattern = new RegExp(`(\\s+${fieldName}\\s*:\\s*)number(\\s*;)`, 'g');
                const oldContent = convertedContent;
                convertedContent = convertedContent.replace(pattern, '$1bigint$2');
                
                // Pattern: fieldName?: number | null;
                const optionalPattern = new RegExp(`(\\s+${fieldName}\\?\\s*:\\s*)number(\\s*\\|\\s*null\\s*;)`, 'g');
                convertedContent = convertedContent.replace(optionalPattern, '$1bigint$2');
                
                if (convertedContent !== oldContent) {
                    console.log(`  ✅ Converted ${fieldName} to bigint`);
                }
            }
        });
    });
    
    console.log('✅ Completed bigint conversion based on schema format');
    return convertedContent;
}

/**
 * Normalize a type definition by removing comments and whitespace for comparison.
 * Also sorts top-level `|` union members so `"A" | "B"` and `"B" | "A"` compare
 * equal — these are semantically identical TypeScript types.
 */
function normalizeTypeDefinition(typeDef) {
    const flat = typeDef
        .replace(/\/\*\*[\s\S]*?\*\//g, '') // Remove comments
        .replace(/\/\*[\s\S]*?\*\//g, '')   // Remove single-line comments
        .replace(/\s+/g, ' ')               // Normalize whitespace
        .replace(/\s*([=|;{}()[\]<>,])\s*/g, '$1') // Remove spaces around operators
        .replace(/\s*:\s*/g, ':')           // Remove spaces around colons
        .replace(/\s*\?\s*/g, '?')          // Remove spaces around question marks
        .trim();

    return sortTopLevelUnions(flat);
}

/**
 * Walk `input` and sort members of every top-level `|`-union so that member
 * order doesn't affect equality. Tracks nesting depth and string state so
 * unions inside objects/tuples are independently sorted too.
 */
function sortTopLevelUnions(input) {
    const parts = splitTopLevelUnion(input);
    if (parts.length <= 1) {
        return transformNestedUnions(input);
    }
    const sortedParts = parts
        .map(transformNestedUnions)
        .slice()
        .sort();
    return sortedParts.join('|');
}

/**
 * Split on top-level `|` only (not inside (), [], {}, <>, or strings).
 */
function splitTopLevelUnion(input) {
    const parts = [];
    let depth = 0;
    let inString = false;
    let stringChar = '';
    let current = '';
    for (let i = 0; i < input.length; i++) {
        const ch = input[i];
        const prev = i > 0 ? input[i - 1] : '';
        if ((ch === '"' || ch === "'") && prev !== '\\') {
            if (!inString) { inString = true; stringChar = ch; }
            else if (ch === stringChar) { inString = false; }
        }
        if (!inString) {
            if (ch === '(' || ch === '[' || ch === '{' || ch === '<') depth++;
            else if (ch === ')' || ch === ']' || ch === '}' || ch === '>') depth--;
            else if (ch === '|' && depth === 0) {
                parts.push(current);
                current = '';
                continue;
            }
        }
        current += ch;
    }
    parts.push(current);
    return parts;
}

/**
 * Recurse into object/array bracket groups and sort unions found inside.
 */
function transformNestedUnions(input) {
    // Replace each {...}, [...], (...) body with a version whose inner unions
    // are themselves sorted. Simple depth-tracking recursive scan.
    let result = '';
    let i = 0;
    while (i < input.length) {
        const ch = input[i];
        if (ch === '{' || ch === '[' || ch === '(') {
            const open = ch;
            const close = open === '{' ? '}' : open === '[' ? ']' : ')';
            let depth = 1;
            let j = i + 1;
            let inString = false;
            let stringChar = '';
            while (j < input.length && depth > 0) {
                const c = input[j];
                const p = input[j - 1];
                if ((c === '"' || c === "'") && p !== '\\') {
                    if (!inString) { inString = true; stringChar = c; }
                    else if (c === stringChar) { inString = false; }
                }
                if (!inString) {
                    if (c === open) depth++;
                    else if (c === close) depth--;
                }
                if (depth === 0) break;
                j++;
            }
            const inner = input.slice(i + 1, j);
            result += open + sortTopLevelUnions(inner) + close;
            i = j + 1;
        } else {
            result += ch;
            i++;
        }
    }
    return result;
}

/**
 * Extract type definitions from content
 */
function extractTypeDefinitions(content) {
    const typeOccurrences = new Map(); // typeName -> array of occurrences
    
    // Split content into lines for better parsing
    const lines = content.split('\n');
    let i = 0;
    
    while (i < lines.length) {
        const line = lines[i].trim();
        
        // Look for export interface or export type
        const typeMatch = line.match(/^export\s+(interface|type)\s+(\w+)/);
        
        if (typeMatch) {
            const [, kind, typeName] = typeMatch;
            let typeDefinition = '';
            let fullMatch = '';
            let startLine = i;
            
            if (kind === 'interface') {
                // For interfaces, capture until the closing brace
                let braceCount = 0;
                let foundOpenBrace = false;
                
                while (i < lines.length) {
                    const currentLine = lines[i];
                    fullMatch += currentLine + '\n';
                    
                    // Count braces
                    for (const char of currentLine) {
                        if (char === '{') {
                            braceCount++;
                            foundOpenBrace = true;
                        } else if (char === '}') {
                            braceCount--;
                        }
                    }
                    
                    // If we found the opening brace and are back to 0, we're done
                    if (foundOpenBrace && braceCount === 0) {
                        i++;
                        break;
                    }
                    
                    i++;
                }
                
                typeDefinition = fullMatch.substring(fullMatch.indexOf(typeName) + typeName.length);
            } else {
                // For type aliases, we need to be more careful with complex union types
                let depth = 0;
                let foundEquals = false;
                let parenDepth = 0;
                let bracketDepth = 0;
                let braceDepth = 0;
                let inString = false;
                let stringChar = '';
                
                while (i < lines.length) {
                    const currentLine = lines[i];
                    fullMatch += currentLine + '\n';
                    
                    // Parse character by character for complex union types
                    for (let j = 0; j < currentLine.length; j++) {
                        const char = currentLine[j];
                        const prevChar = j > 0 ? currentLine[j-1] : '';
                        
                        // Handle string literals
                        if ((char === '"' || char === "'") && prevChar !== '\\') {
                            if (!inString) {
                                inString = true;
                                stringChar = char;
                            } else if (char === stringChar) {
                                inString = false;
                                stringChar = '';
                            }
                        }
                        
                        if (!inString) {
                            if (char === '=' && !foundEquals) {
                                foundEquals = true;
                            } else if (foundEquals) {
                                // Track nesting depth
                                if (char === '(' || char === '<') {
                                    parenDepth++;
                                } else if (char === ')' || char === '>') {
                                    parenDepth--;
                                } else if (char === '[') {
                                    bracketDepth++;
                                } else if (char === ']') {
                                    bracketDepth--;
                                } else if (char === '{') {
                                    braceDepth++;
                                } else if (char === '}') {
                                    braceDepth--;
                                }
                            }
                        }
                    }
                    
                    // Check if we're done (at depth 0 and line ends with semicolon)
                    if (foundEquals && 
                        parenDepth === 0 && bracketDepth === 0 && braceDepth === 0 && 
                        !inString &&
                        currentLine.trim().endsWith(';')) {
                        i++;
                        break;
                    }
                    
                    i++;
                }
                
                typeDefinition = fullMatch.substring(fullMatch.indexOf('='));
            }
            
            const normalizedDef = normalizeTypeDefinition(typeDefinition);
            
            const typeInfo = {
                kind,
                definition: typeDefinition,
                normalizedDefinition: normalizedDef,
                fullMatch: fullMatch.trim()
            };
            
            // Store all occurrences of the type
            if (!typeOccurrences.has(typeName)) {
                typeOccurrences.set(typeName, []);
            }
            typeOccurrences.get(typeName).push(typeInfo);
        } else {
            i++;
        }
    }
    
    // Convert to the format expected by findDuplicateTypes (keep only first occurrence for comparison)
    const typeMap = new Map();
    typeOccurrences.forEach((occurrences, typeName) => {
        typeMap.set(typeName, occurrences[0]); // Use first occurrence for comparison
        
        // Store all occurrences for removal
        typeMap.get(typeName).allOccurrences = occurrences;
    });
    
    return typeMap;
}

/**
 * Find duplicate type definitions and create a mapping of duplicates to canonical names
 */
function findDuplicateTypes(typeMap) {
    const duplicateGroups = new Map(); // normalized definition -> [typeNames]
    const canonicalMapping = new Map(); // duplicate name -> canonical name
    const duplicateOccurrences = new Map(); // type name -> array of duplicate occurrences to remove
    
    // Group types by their normalized definitions
    typeMap.forEach((typeInfo, typeName) => {
        const normalizedDef = typeInfo.normalizedDefinition;
        
        if (!duplicateGroups.has(normalizedDef)) {
            duplicateGroups.set(normalizedDef, []);
        }
        duplicateGroups.get(normalizedDef).push(typeName);
    });
    
    // For each group of duplicates, choose a canonical name and map others to it
    duplicateGroups.forEach((typeNames, normalizedDef) => {
        if (typeNames.length > 1) {
            // Sort to get a consistent canonical name (prefer simpler names without numbers)
            const sortedNames = typeNames.sort((a, b) => {
                // Prefer names without numbers
                const aHasNumber = /\d/.test(a);
                const bHasNumber = /\d/.test(b);
                
                if (aHasNumber && !bHasNumber) return 1;
                if (!aHasNumber && bHasNumber) return -1;
                
                // If both have or don't have numbers, prefer shorter name
                return a.length - b.length || a.localeCompare(b);
            });
            
            const canonicalName = sortedNames[0];
            
            // Map all other names to the canonical one
            sortedNames.slice(1).forEach(duplicateName => {
                canonicalMapping.set(duplicateName, canonicalName);
            });
            
            console.log(`🔄 Found duplicates: ${typeNames.join(', ')} -> using ${canonicalName}`);
        }
    });
    
    // Handle multiple occurrences of the same type name
    typeMap.forEach((typeInfo, typeName) => {
        if (typeInfo.allOccurrences && typeInfo.allOccurrences.length > 1) {
            // Remove all but the first occurrence
            const duplicates = typeInfo.allOccurrences.slice(1);
            duplicateOccurrences.set(typeName, duplicates);
            console.log(`🔄 Found ${typeInfo.allOccurrences.length} occurrences of ${typeName}, will remove ${duplicates.length}`);
        }
    });
    
    return { canonicalMapping, duplicateOccurrences };
}

/**
 * Scan a TypeScript source for types declared under the same name with
 * *different* bodies. Identical repeats are tolerated silently (the caller's
 * dedup pass handles those), but a real collision is a correctness bug —
 * usually caused by the Rust side producing a type that shadows a hand-written
 * one. We throw with a readable diff so the drift is caught immediately.
 */
function assertNoNameConflicts(content, label) {
    const typeMap = extractTypeDefinitions(content);
    const conflicts = [];
    typeMap.forEach((info, name) => {
        const bodies = new Map(); // normalizedDefinition -> count
        for (const occurrence of info.allOccurrences || [info]) {
            const key = occurrence.kind + '|' + occurrence.normalizedDefinition;
            bodies.set(key, (bodies.get(key) || 0) + 1);
        }
        if (bodies.size > 1) {
            conflicts.push({ name, variants: [...bodies.keys()] });
        }
    });

    if (conflicts.length === 0) {
        return;
    }

    console.error(`❌ ${label}: same-name / different-body type conflicts detected:`);
    for (const { name, variants } of conflicts) {
        console.error(`  - ${name} has ${variants.length} distinct bodies:`);
        variants.forEach((v, i) => {
            const [kind, body] = v.split('|');
            const snippet = body.length > 160 ? body.slice(0, 160) + '…' : body;
            console.error(`      [${i + 1}] ${kind}: ${snippet}`);
        });
    }
    throw new Error(
        `Type-name conflicts in ${label}. Align the Rust types (src/common.rs, ` +
        `input_contexts, etc.) or remove the hand-written copy so one name maps ` +
        `to one definition.`
    );
}

/**
 * Remove duplicate type definitions and replace references
 */
function deduplicateTypes(content) {
    console.log('🔄 Removing duplicate type definitions...');
    
    const typeMap = extractTypeDefinitions(content);
    const { canonicalMapping, duplicateOccurrences } = findDuplicateTypes(typeMap);
    
    if (canonicalMapping.size === 0 && duplicateOccurrences.size === 0) {
        console.log('✅ No duplicate types found');
        return content;
    }
    
    let deduplicatedContent = content;
    
    // Remove duplicate type definitions (from canonicalMapping - different type names)
    canonicalMapping.forEach((canonicalName, duplicateName) => {
        const typeInfo = typeMap.get(duplicateName);
        if (typeInfo) {
            // Remove the entire type definition
            deduplicatedContent = deduplicatedContent.replace(typeInfo.fullMatch, '');
            console.log(`  🗑️  Removed duplicate type: ${duplicateName}`);
        }
    });
    
    // Remove duplicate occurrences of the same type name
    duplicateOccurrences.forEach((duplicates, typeName) => {
        duplicates.forEach((duplicate, index) => {
            deduplicatedContent = deduplicatedContent.replace(duplicate.fullMatch, '');
            console.log(`  🗑️  Removed duplicate occurrence ${index + 2} of ${typeName}`);
        });
    });
    
    // Replace references to duplicate types with canonical types
    canonicalMapping.forEach((canonicalName, duplicateName) => {
        // Replace type references in field types, union types, etc.
        const patterns = [
            // Field type references: field: DuplicateType;
            new RegExp(`(:\\s*)${duplicateName}(\\s*[;|}])`, 'g'),
            // Array type references: DuplicateType[]
            new RegExp(`\\b${duplicateName}(\\[\\])`, 'g'),
            // Union type references: | DuplicateType |
            new RegExp(`(\\|\\s*)${duplicateName}(\\s*[|}])`, 'g'),
            // Generic type references: SomeType<DuplicateType>
            new RegExp(`(<\\s*)${duplicateName}(\\s*[,>])`, 'g'),
            // Function parameter/return types
            new RegExp(`(\\(.*?:\\s*)${duplicateName}(\\s*\\))`, 'g'),
        ];
        
        patterns.forEach(pattern => {
            deduplicatedContent = deduplicatedContent.replace(pattern, `$1${canonicalName}$2`);
        });
        
        console.log(`  🔄 Replaced ${duplicateName} references with ${canonicalName}`);
    });
    
    // Clean up multiple empty lines that might have been created
    deduplicatedContent = deduplicatedContent.replace(/\n\s*\n\s*\n/g, '\n\n');
    
    const totalRemoved = canonicalMapping.size + Array.from(duplicateOccurrences.values()).reduce((sum, arr) => sum + arr.length, 0);
    console.log(`✅ Removed ${totalRemoved} duplicate types`);
    return deduplicatedContent;
}

/**
 * Compile the schemas into a TypeScript type body. The returned string
 * contains only `export ...` declarations — no banner comment — so the caller
 * can prepend whatever header each target file needs.
 */
async function generateTypesBody(allSchemas) {
    const mainTypes = Object.keys(allSchemas);

    console.log(`📝 Generating type body with ${mainTypes.length} main types`);

    let content = '';

    // Process each schema with json-schema-to-typescript
    for (const [typeName, schema] of Object.entries(allSchemas)) {
        try {
            console.log(`🔄 Compiling schema for ${typeName}...`);
            
            // Configure options for json-schema-to-typescript
            const options = {
                bannerComment: '', // No banner comment for individual types
                style: {
                    bracketSpacing: true,
                    printWidth: 100,
                    semi: true,
                    singleQuote: false,
                    tabWidth: 2,
                    trailingComma: 'none',
                    useTabs: false
                },
                unreachableDefinitions: false,
                $refOptions: {
                    resolve: {
                        // Handle internal references
                        internal: true
                    }
                },
                // Disable additional properties to remove [k: string]: unknown;
                additionalProperties: false
            };
            
            // Compile the schema to TypeScript
            const compiledType = await compile(schema, typeName, options);
            
            // Keep export statements as-is, don't convert to declare
            const exportedType = compiledType
                .replace(/^interface/gm, 'export interface')
                .replace(/^type/gm, 'export type');
            
            content += exportedType + '\n';
            
            console.log(`✅ Compiled ${typeName}`);
        } catch (error) {
            console.error(`❌ Failed to compile schema for ${typeName}:`, error.message);
            // Fallback: add a basic type declaration
            content += `export type ${typeName} = any; // Failed to compile schema\n\n`;
        }
    }
    
    // Post-process to convert large integers to bigint
    content = convertToBigInt(content, allSchemas);
    
    // Remove duplicate type definitions and replace references
    content = deduplicateTypes(content);

    return content;
}

/**
 * Main function
 */
async function main() {
    const args = process.argv.slice(2);
    const schemasDir = args[0] || 'schemas';
    const outputDir = args[1] || 'types';
    
    console.log(`Converting JSON schemas from '${schemasDir}' to TypeScript .d.ts in '${outputDir}'`);
    
    // Create output directory
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }
    
    // Discover every *.schema.json in the input directory. The Rust side
    // (src/schema_generator.rs) is the single source of truth for which
    // schemas exist — adding a new `schema_for!(...)` there is enough.
    if (!fs.existsSync(schemasDir)) {
        console.error(`❌ Schemas directory not found: ${schemasDir}`);
        process.exit(1);
    }

    const schemaFiles = fs
        .readdirSync(schemasDir)
        .filter(name => name.endsWith('.schema.json'))
        .sort();

    if (schemaFiles.length === 0) {
        console.error(`❌ No *.schema.json files in ${schemasDir}. Run generate-schemas first.`);
        process.exit(1);
    }

    const allSchemas = {};
    schemaFiles.forEach(filename => {
        const schemaPath = path.join(schemasDir, filename);
        try {
            const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
            const typeName = filename.replace('.schema.json', '');
            allSchemas[typeName] = schema;
            console.log(`📋 Loaded schema for ${typeName}`);
        } catch (error) {
            console.warn(`⚠️  Failed to load schema ${filename}: ${error.message}`);
        }
    });
    
    if (Object.keys(allSchemas).length === 0) {
        console.error('❌ No schemas loaded. Exiting.');
        return;
    }
    
    try {
        const typesBody = await generateTypesBody(allSchemas);

        // 1. Standalone importable module: types/index.ts
        const indexBanner = `// Auto-generated TypeScript types from JSON schemas
// Generated at: ${new Date().toISOString()}
//
// This file contains exported TypeScript types that can be imported in other modules.
// Large integers (uint64, int64) are represented as bigint for safe handling.

`;
        const indexPath = path.join(outputDir, 'index.ts');
        fs.writeFileSync(indexPath, indexBanner + typesBody);
        console.log(`✅ Generated: ${indexPath}`);

        // 2. Splice the same body into the hand-maintained d.ts, replacing
        //    everything after the `///AUTOGENERATED` marker. If either the
        //    file or the marker is missing we leave a clear warning rather
        //    than silently overwriting the hand-written half.
        const dtsPath = path.join(outputDir, 'cquisitor_lib.d.ts');
        if (fs.existsSync(dtsPath)) {
            const marker = '///AUTOGENERATED';
            const existing = fs.readFileSync(dtsPath, 'utf8');
            const markerIndex = existing.indexOf(marker);
            if (markerIndex === -1) {
                console.warn(
                    `⚠️  Skipped ${dtsPath}: marker '${marker}' not found. ` +
                    `Add it on its own line below the hand-written section so ` +
                    `future runs can refresh the generated types.`
                );
            } else {
                const head = existing.slice(0, markerIndex + marker.length);
                const updated = `${head}\n${typesBody}`;
                assertNoNameConflicts(updated, dtsPath);
                fs.writeFileSync(dtsPath, updated);
                console.log(`✅ Refreshed autogenerated section of: ${dtsPath}`);
            }
        } else {
            console.warn(`⚠️  ${dtsPath} not found; skipping d.ts refresh.`);
        }

        console.log('\n🎉 TypeScript type generation completed!');
        console.log('\nUsage example:');
        console.log("  import { ValidationResult, NecessaryInputData } from './types/index.js';");
    } catch (error) {
        console.error('❌ Failed to generate .ts file:', error.message);
        process.exit(1);
    }
}

// Run the script
main().catch(error => {
    console.error('❌ Unexpected error:', error);
    process.exit(1);
}); 