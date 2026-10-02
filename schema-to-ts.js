#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { compile } from 'json-schema-to-typescript';

/**
 * Integer formats whose values may not fit a JS number exactly. The wrappers hand
 * these back as `number` when the value fits 2^53 and `bigint` above, so the
 * declared type is `number | bigint`. u32 and narrower stay `number`.
 */
const WIDE_INTEGER_FORMATS = new Set(['uint64', 'int64', 'uint128', 'int128']);
const WIDE_INTEGER_TYPE = 'number | bigint';

function isIntegerSchema(schema) {
    if (schema.type === 'integer') return true;
    return Array.isArray(schema.type) && schema.type.includes('integer');
}

/**
 * Extract all field paths that should be `number | bigint` from a schema based on
 * format. Keyed by the definition name that owns the field, so the rewrite can be
 * scoped to that type's block instead of every same-named field in the file.
 */
function extractBigIntFields(schema, prefix = '', bigIntFields = new Map(), typeName = '') {
    if (!schema || typeof schema !== 'object') return bigIntFields;

    if (isIntegerSchema(schema) && WIDE_INTEGER_FORMATS.has(schema.format)) {
        if (!bigIntFields.has(typeName)) {
            bigIntFields.set(typeName, []);
        }
        bigIntFields.get(typeName).push({
            path: prefix,
            format: schema.format,
            nullable: Array.isArray(schema.type) && schema.type.includes('null')
        });
    }

    // Recursively check properties
    if (schema.properties) {
        Object.entries(schema.properties).forEach(([key, propSchema]) => {
            const newPrefix = prefix ? `${prefix}.${key}` : key;
            extractBigIntFields(propSchema, newPrefix, bigIntFields, typeName);
        });
    }

    // Array items (one schema, or a positional list) and tuple prefixes
    if (schema.items) {
        (Array.isArray(schema.items) ? schema.items : [schema.items]).forEach(item =>
            extractBigIntFields(item, prefix, bigIntFields, typeName));
    }
    if (Array.isArray(schema.prefixItems)) {
        schema.prefixItems.forEach(item => extractBigIntFields(item, prefix, bigIntFields, typeName));
    }
    if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        extractBigIntFields(schema.additionalProperties, prefix, bigIntFields, typeName);
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
 * json-schema-to-typescript predates `prefixItems` (JSON Schema 2020-12) and
 * emits `[unknown, unknown]` for a tuple described that way. Rewrite tuples into
 * the positional `items` array it understands, so `protocolVersion` comes out as
 * `[number, number]`. Returns a deep copy; the schema files are not touched.
 */
function normalizeTuples(schema) {
    if (Array.isArray(schema)) return schema.map(normalizeTuples);
    if (!schema || typeof schema !== 'object') return schema;
    const out = {};
    for (const [key, value] of Object.entries(schema)) {
        out[key] = normalizeTuples(value);
    }
    if (Array.isArray(out.prefixItems) && (out.items === undefined || out.items === false)) {
        out.items = out.prefixItems;
        if (out.minItems === undefined) out.minItems = out.prefixItems.length;
        if (out.maxItems === undefined) out.maxItems = out.prefixItems.length;
        delete out.prefixItems;
    }
    return out;
}

/**
 * Locate every top-level `export interface Name {...}` / `export type Name = ...;`
 * declaration of `typeName` in `content` — including the `Name1`, `Name2` copies
 * json-schema-to-typescript emits when one definition is reached through several
 * paths (the dedup pass folds them back once their bodies agree), and the repeats
 * that come from compiling several schemas sharing a definition. Returns
 * [start, end) pairs in document order.
 */
function findTypeBlocks(content, typeName) {
    const re = new RegExp(`^export (interface|type) ${typeName}\\d*\\b`, 'gm');
    const blocks = [];
    let match;
    while ((match = re.exec(content)) !== null) {
        blocks.push(blockExtent(content, match));
    }
    return blocks;
}

function blockExtent(content, match) {
    const start = match.index;
    let i = start + match[0].length;
    if (match[1] === 'interface') {
        // Up to the matching closing brace of the first `{`.
        let depth = 0;
        let seenOpen = false;
        for (; i < content.length; i++) {
            const ch = content[i];
            if (ch === '{') { depth++; seenOpen = true; }
            else if (ch === '}') { depth--; if (seenOpen && depth === 0) { i++; break; } }
        }
        return [start, i];
    }
    // Type alias: up to the first `;` at bracket depth 0 outside strings.
    let depth = 0;
    let inString = false;
    let stringChar = '';
    for (; i < content.length; i++) {
        const ch = content[i];
        const prev = content[i - 1];
        if ((ch === '"' || ch === "'") && prev !== '\\') {
            if (!inString) { inString = true; stringChar = ch; }
            else if (ch === stringChar) inString = false;
        }
        if (inString) continue;
        if (ch === '{' || ch === '[' || ch === '(' || ch === '<') depth++;
        else if (ch === '}' || ch === ']' || ch === ')' || ch === '>') depth--;
        else if (ch === ';' && depth === 0) { i++; break; }
    }
    return [start, i];
}

function widenFieldsIn(text, fieldName) {
    // fieldName: number;  ->  fieldName: number | bigint;
    const required = new RegExp(`(\\s+${fieldName}\\s*:\\s*)number(\\s*;)`, 'g');
    // fieldName?: number | null;  ->  fieldName?: number | bigint | null;
    const optional = new RegExp(`(\\s+${fieldName}\\??\\s*:\\s*)number(\\s*\\|\\s*null\\s*;)`, 'g');
    return text
        .replace(required, `$1${WIDE_INTEGER_TYPE}$2`)
        .replace(optional, `$1${WIDE_INTEGER_TYPE}$2`);
}

/**
 * Widen 64/128-bit integer fields to `number | bigint`, scoped to the type that
 * declares them. A type whose block cannot be found falls back to a file-wide
 * rewrite of that field name (with a warning), which is what earlier versions did.
 */
function convertToBigInt(content, allSchemas) {
    console.log('🔄 Widening uint64/int64/int128 fields to number | bigint based on schema format...');

    const bigIntFields = new Map();
    Object.entries(allSchemas).forEach(([typeName, schema]) => {
        extractBigIntFields(schema, '', bigIntFields, typeName);
    });

    console.log(`📋 Found ${bigIntFields.size} types with wide integer fields:`,
        Array.from(bigIntFields.keys()));

    let convertedContent = content;
    let widened = 0;

    bigIntFields.forEach((fields, typeName) => {
        const names = [...new Set(fields.map(f => f.path.split('.').pop()).filter(Boolean))];
        if (names.length === 0) return;
        const blocks = findTypeBlocks(convertedContent, typeName);
        if (blocks.length === 0) {
            console.warn(`  ⚠️  No declaration block for ${typeName}; widening ${names.join(', ')} file-wide`);
            names.forEach(name => {
                const before = convertedContent;
                convertedContent = widenFieldsIn(convertedContent, name);
                if (convertedContent !== before) widened++;
            });
            return;
        }
        // Last block first, so earlier offsets stay valid while the text changes.
        for (const [start, end] of blocks.reverse()) {
            let blockText = convertedContent.slice(start, end);
            names.forEach(name => {
                const before = blockText;
                blockText = widenFieldsIn(blockText, name);
                if (blockText !== before) {
                    widened++;
                    console.log(`  ✅ ${typeName}.${name}: number | bigint`);
                }
            });
            convertedContent = convertedContent.slice(0, start) + blockText + convertedContent.slice(end);
        }
    });

    console.log(`✅ Widened ${widened} field declarations`);
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
        // Every pattern must capture the text on each side of the name in
        // exactly two groups, because the single replacement below places the
        // canonical name between `$1` and `$2`. A pattern with one group emits
        // a literal `$2` and moves the surrounding text to the front.
        const patterns = [
            // Field type references: field: DuplicateType;
            new RegExp(`(:\\s*)${duplicateName}(\\s*[;|}])`, 'g'),
            // Array type references: DuplicateType[]
            new RegExp(`\\b()${duplicateName}(\\[\\])`, 'g'),
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
            
            // Compile the schema to TypeScript (tuples rewritten into the positional
            // `items` form the compiler understands)
            const compiledType = await compile(normalizeTuples(schema), typeName, options);
            
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
    
    // Post-process: 64/128-bit integers are `number | bigint` at runtime
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
// 64/128-bit integers (uint64, int64, int128) are typed "number | bigint": the library
// hands them back as a number when they fit 2^53 and as a bigint above.

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