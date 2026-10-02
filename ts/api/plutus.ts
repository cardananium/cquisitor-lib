// Plutus scripts: UPLC of a flat-encoded (CBOR-wrapped) program.

import type { LibCallOptions } from "../backend.js";
import type { ProgramJson } from "@cardananium/cquisitor-lib/wasm";
import { callLib } from "./call.js";

/** The program as a JSON term tree. */
export function decodePlutusProgramJson(hex: string, options?: LibCallOptions): Promise<ProgramJson> {
  return callLib("decode_plutus_program_uplc_json", [hex], options);
}

/** The program pretty-printed as UPLC text. */
export function decodePlutusProgramPretty(hex: string, options?: LibCallOptions): Promise<string> {
  return callLib("decode_plutus_program_pretty_uplc", [hex], options);
}
