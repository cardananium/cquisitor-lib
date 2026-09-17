// Two properties of a built wasm module that the source states and the
// artifact has to carry: the shadow stack it links with, and the export table
// holding no entry point of the CDDL crate it links.
//
// The shadow stack: the bounds in `src/cbor/limits` were calibrated against
// wasm-ld's default of 1 MiB (`RUNTIME_STACK` in `src/cbor/stack_calibration`),
// and nothing in the build is meant to change it. A trapped instance is not
// recoverable from the page that holds it, so the size is read back out of the
// artifact rather than assumed, and a mismatch — a link argument that crept in,
// or a toolchain whose default moved — fails the build.
//
// wasm-ld places the shadow stack at the top of a region at the bottom of
// linear memory and emits its pointer as the first global, mutable and i32,
// initialised to the size of that region. That initialiser is what is read.
//
// The export table: every `#[wasm_bindgen]` function of a dependency lands in
// the export table of the module that links it. The CDDL crate compiles its
// own JavaScript entry points under its `wasm-exports` feature, which this
// crate's dependency leaves off; were one of them to reach the artifact it
// would run on that crate's default limits rather than on the bounds in
// `src/cbor/limits`, outside this crate's API and its d.ts. So the table is
// read back too, and a foreign entry point in it fails the build.

import { readFileSync } from "node:fs";

const EXPECTED_STACK_BYTES = 1024 * 1024;

// The CDDL crate's entry points, every one of which its `wasm-exports`
// feature would compile into this module.
const FOREIGN_EXPORTS = [
  "cddl_from_str",
  "validate_cddl_from_str",
  "format_cddl_from_str",
  "validate_json_from_str",
  "validate_cbor_from_slice",
  "validate_csv_from_str",
];

const WASM_MAGIC = 0x6d736100;
const SECTION_GLOBAL = 6;
const SECTION_EXPORT = 7;
const TYPE_I32 = 0x7f;
const OP_I32_CONST = 0x41;
const OP_END = 0x0b;
const EXPORT_KIND_FUNCTION = 0;

class Reader {
  constructor(bytes, offset = 0) {
    this.bytes = bytes;
    this.offset = offset;
  }

  byte() {
    if (this.offset >= this.bytes.length) {
      throw new Error("the module ends inside a section");
    }
    return this.bytes[this.offset++];
  }

  // LEB128, unsigned.
  varuint() {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = this.byte();
      result += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7;
      if (shift > 63) throw new Error("an unsigned LEB128 value does not end");
    }
  }

  // LEB128, signed.
  varint() {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      const byte = this.byte();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if ((byte & 0x80) === 0) {
        if (byte & 0x40) result -= 1n << shift;
        return Number(result);
      }
      if (shift > 70n) throw new Error("a signed LEB128 value does not end");
    }
  }

  // A length-prefixed UTF-8 name.
  name() {
    const length = this.varuint();
    const start = this.offset;
    this.offset += length;
    if (this.offset > this.bytes.length) {
      throw new Error("the module ends inside a name");
    }
    return this.bytes.subarray(start, this.offset).toString("utf8");
  }
}

/// The initialiser of the module's first global, when that global is the
/// mutable i32 constant wasm-ld emits as the stack pointer.
function stackPointerInitialiser(reader) {
  const count = reader.varuint();
  if (count === 0) throw new Error("the module declares no globals");

  const type = reader.byte();
  const mutable = reader.byte();
  const op = reader.byte();
  if (type !== TYPE_I32 || mutable !== 1 || op !== OP_I32_CONST) {
    throw new Error(
      "the first global is not the mutable i32 constant wasm-ld emits as the stack pointer",
    );
  }

  const value = reader.varint();
  if (reader.byte() !== OP_END) {
    throw new Error("the first global's initialiser is not a lone constant");
  }
  return value;
}

/// The names the module exports as functions.
function exportedFunctions(reader) {
  const count = reader.varuint();
  const names = [];
  for (let i = 0; i < count; i++) {
    const name = reader.name();
    const kind = reader.byte();
    reader.varuint(); // the index, which says nothing here
    if (kind === EXPORT_KIND_FUNCTION) names.push(name);
  }
  return names;
}

/// The two properties, read from the module's global and export sections.
function inspect(bytes) {
  if (bytes.length < 8 || bytes.readUInt32LE(0) !== WASM_MAGIC) {
    throw new Error("not a wasm module");
  }

  let stackBytes = null;
  let functions = null;
  const reader = new Reader(bytes, 8);
  while (reader.offset < bytes.length) {
    const id = reader.byte();
    const size = reader.varuint();
    const end = reader.offset + size;

    if (id === SECTION_GLOBAL) stackBytes = stackPointerInitialiser(reader);
    if (id === SECTION_EXPORT) functions = exportedFunctions(reader);

    reader.offset = end;
  }

  if (stackBytes === null) throw new Error("the module has no global section");
  if (functions === null) throw new Error("the module has no export section");
  return { stackBytes, functions };
}

const paths = process.argv.slice(2);
if (paths.length === 0) {
  console.error("usage: node check-wasm-stack.mjs <module.wasm>...");
  process.exit(2);
}

let failed = false;
for (const path of paths) {
  let module;
  try {
    module = inspect(readFileSync(path));
  } catch (error) {
    console.error(`${path}: ${error.message}`);
    failed = true;
    continue;
  }

  if (module.stackBytes !== EXPECTED_STACK_BYTES) {
    console.error(
      `${path}: linked with a ${module.stackBytes}-byte shadow stack, but the bounds in ` +
        `src/cbor/limits are stated against ${EXPECTED_STACK_BYTES}, wasm-ld's default: ` +
        `a -zstack-size argument reached the linker, or the toolchain's default moved.`,
    );
    failed = true;
    continue;
  }

  const foreign = FOREIGN_EXPORTS.filter((name) => module.functions.includes(name));
  if (foreign.length > 0) {
    console.error(
      `${path}: exports ${foreign.join(", ")} — entry points of the CDDL crate, which ` +
        `its wasm-exports feature compiles. The dependency in Cargo.toml has to be ` +
        `built with default-features = false and without that feature.`,
    );
    failed = true;
    continue;
  }

  console.log(
    `${path}: shadow stack ${module.stackBytes} bytes; ${module.functions.length} exported ` +
      `functions, none of the CDDL crate's`,
  );
}

process.exit(failed ? 1 : 0);
