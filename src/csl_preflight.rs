//! Checks run on caller bytes before they reach cardano-serialization-lib.
//!
//! CSL's deserializers return errors for most bad input, but a few inputs
//! make them abort the process instead. On wasm an abort is an
//! uncatchable trap that kills the instance, so those inputs are refused
//! here, with an ordinary error, before CSL sees them:
//!
//! * Input that is not one well-formed CBOR item (truncated, reserved
//!   header bits, a stray break, trailing bytes, …). CSL reads such input
//!   with `unwrap()`s in a few places. The check is the positional
//!   decoder behind `cbor_to_json`, so what it rejects here is exactly
//!   what that export reports as an error.
//! * A witness list (`Vkeywitnesses`, `BootstrapWitnesses`) holding a
//!   major-type-7 item (`true`, `false`, `null`, `undefined`, an
//!   unassigned simple value or a float): CSL asserts that any such item
//!   inside those arrays is the break of an indefinite array. The scan
//!   follows CSL's own route to those arrays (witness set keys 0 and 2,
//!   the witness set at index 1 of a transaction, the witness sets at
//!   index 2 of a block) and refuses the document when one is found.
//! * Address bytes of length zero: CSL indexes the header byte without a
//!   length check. Hex and bech32 address parsing goes through
//!   [`address_from_hex`] / [`address_from_bech32`]; an address embedded
//!   in a CBOR document (an output's address, a withdrawal key, a pool's
//!   or a proposal's reward account, a treasury withdrawal key) is found
//!   by following CSL's own route to it, and the document is refused when
//!   the byte string there is empty. An indefinite-length byte string
//!   counts as its spliced chunks, as CSL reads it.
//! * Nesting deeper than [`limits::MAX_CSL_NESTING_DEPTH`]: CSL recurses
//!   on the host stack, one frame per level (Plutus data, metadata, native
//!   scripts), and on wasm an exhausted stack is a trap. Every entry point
//!   that hands bytes to CSL applies it here; the typed decoders, which
//!   also render what CSL read as JSON (recursively), apply the lower
//!   [`limits::MAX_TYPED_DECODER_NESTING_DEPTH`] first. CBOR carried in a byte string
//!   under tag 24 (an output's inline datum, a script reference) counts
//!   on top of the level it is embedded at, because CSL and pallas parse
//!   it in place while reading the enclosing document. Bytes only pallas
//!   and the Plutus evaluator read pass the same checks with
//!   [`limits::MAX_PALLAS_NESTING_DEPTH`] instead ([`check_pallas_cbor`]).
//!
//! The typed decoders classify every registry type as raw bytes (hashes,
//! keys, signatures, addresses, Plutus script bytes) or as a CBOR item of
//! some [`CslShape`]; only the latter are gated. See [`decoder_input`].

use crate::cbor::errors::{CborDecodeError, ErrorKind};
use crate::cbor::limits;
use cardano_serialization_lib as csl;
use std::convert::TryFrom;

/// What CSL will read the bytes as, so the scan can follow its route to
/// the witness lists whose deserializer aborts on a simple value and to
/// the byte strings it reads as addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum CslShape {
    /// `[body, witness_set, …]`: the witness set sits at index 1, the body
    /// at index 0.
    Transaction,
    /// `[header, bodies, witness_sets, …]`: the bodies sit at index 1, the
    /// witness sets at index 2.
    Block,
    /// `[era, block]`.
    VersionedBlock,
    /// A witness set map: keys 0 and 2 hold witness lists.
    WitnessSet,
    /// An array of witness set maps.
    WitnessSets,
    /// A `Vkeywitnesses` / `BootstrapWitnesses` array (optionally tagged 258).
    WitnessList,
    /// A transaction body map: keys 1 and 16 hold outputs, key 5
    /// withdrawals, key 4 certificates, key 20 proposals.
    TransactionBody,
    /// An array of transaction body maps.
    TransactionBodies,
    /// `[address, amount, …]` or `{0: address, …}`.
    TransactionOutput,
    /// An array of outputs.
    TransactionOutputs,
    /// `[input, output]`.
    TransactionUnspentOutput,
    /// A `{reward_address => coin}` map.
    Withdrawals,
    /// An array of reward addresses.
    RewardAddresses,
    /// `[operator, vrf, pledge, cost, margin, reward_account, …]`: the
    /// reward account sits at index 5.
    PoolParams,
    /// A certificate `[kind, …]`; kind 3 (pool registration) holds the
    /// reward account at index 6. `PoolRegistration` reads the same array.
    Certificate,
    /// An array of certificates (optionally tagged 258).
    Certificates,
    /// `[deposit, reward_account, governance_action, anchor]`.
    VotingProposal,
    /// An array of proposals (optionally tagged 258).
    VotingProposals,
    /// A governance action `[kind, …]`; kind 2 (treasury withdrawals)
    /// holds a `{reward_address => coin}` map at index 1.
    GovernanceAction,
    /// A native script (`NativeScript`, and the `ScriptAll`, `ScriptAny`,
    /// `ScriptNOfK`, `ScriptPubkey`, `TimelockStart`, `TimelockExpiry`
    /// types, which read the same array).
    NativeScript,
    /// An array of native scripts (optionally tagged 258).
    NativeScripts,
    /// A script reference: `#6.24(bytes .cbor [kind, script])`, or the bare
    /// `[kind, script]` a validation context may give.
    ScriptRef,
    /// Auxiliary data: a metadata map, `[metadata, [* native_script]]`, or
    /// `#6.259({…, 1: [* native_script], …})`.
    AuxiliaryData,
    /// Any other CBOR item: only well-formedness and nesting are checked.
    Item,
}

impl CslShape {
    /// Every shape, for tables indexed by [`CslShape::index`].
    const ALL: [CslShape; 24] = [
        CslShape::Transaction,
        CslShape::Block,
        CslShape::VersionedBlock,
        CslShape::WitnessSet,
        CslShape::WitnessSets,
        CslShape::WitnessList,
        CslShape::TransactionBody,
        CslShape::TransactionBodies,
        CslShape::TransactionOutput,
        CslShape::TransactionOutputs,
        CslShape::TransactionUnspentOutput,
        CslShape::Withdrawals,
        CslShape::RewardAddresses,
        CslShape::PoolParams,
        CslShape::Certificate,
        CslShape::Certificates,
        CslShape::VotingProposal,
        CslShape::VotingProposals,
        CslShape::GovernanceAction,
        CslShape::NativeScript,
        CslShape::NativeScripts,
        CslShape::ScriptRef,
        CslShape::AuxiliaryData,
        CslShape::Item,
    ];

    fn index(self) -> usize {
        CslShape::ALL
            .iter()
            .position(|shape| *shape == self)
            .expect("every shape is listed in CslShape::ALL")
    }
}

/// How a registry type reads its hex input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecoderInput {
    /// Raw bytes with their own framing (fixed-length hashes and keys,
    /// address bytes, Plutus script bytes): CBOR checks do not apply.
    RawBytes,
    /// A single CBOR item of the given shape.
    Cbor(CslShape),
}

/// Registry types whose hex is raw bytes rather than a CBOR item: fixed
/// length hashes and verification keys, key material, address bytes (a
/// header byte and credentials; Byron addresses are CBOR, but the address
/// decoder tries them itself) and flat Plutus script bytes, which the
/// script decoder wraps before CSL reads them. Every other CSL type is
/// read through its `Deserialize` implementation, i.e. as CBOR.
pub(crate) const RAW_BYTE_TYPES: &[&str] = &[
    "Address",
    "AnchorDataHash",
    "AuxiliaryDataHash",
    "BaseAddress",
    "Bip32PrivateKey",
    "Bip32PublicKey",
    "BlockHash",
    "ByronAddress",
    "DataHash",
    "Ed25519KeyHash",
    "Ed25519Signature",
    "EnterpriseAddress",
    "GenesisDelegateHash",
    "GenesisHash",
    "KESSignature",
    "KESVKey",
    "LegacyDaedalusPrivateKey",
    "PlutusScript",
    "PointerAddress",
    "PoolMetadataHash",
    "PrivateKey",
    "PublicKey",
    "RewardAddress",
    "ScriptDataHash",
    "ScriptHash",
    "TransactionHash",
    "VRFKeyHash",
    "VRFVKey",
];

/// The input classification of every type the typed decoders offer.
pub(crate) fn decoder_input(type_name: &str) -> DecoderInput {
    if RAW_BYTE_TYPES.contains(&type_name) {
        return DecoderInput::RawBytes;
    }
    DecoderInput::Cbor(match type_name {
        "Transaction" => CslShape::Transaction,
        "Block" => CslShape::Block,
        "VersionedBlock" => CslShape::VersionedBlock,
        "TransactionWitnessSet" => CslShape::WitnessSet,
        "TransactionWitnessSets" => CslShape::WitnessSets,
        "Vkeywitnesses" | "BootstrapWitnesses" => CslShape::WitnessList,
        "TransactionBody" => CslShape::TransactionBody,
        "TransactionBodies" => CslShape::TransactionBodies,
        "TransactionOutput" => CslShape::TransactionOutput,
        "TransactionOutputs" => CslShape::TransactionOutputs,
        "TransactionUnspentOutput" => CslShape::TransactionUnspentOutput,
        "Withdrawals" => CslShape::Withdrawals,
        "RewardAddresses" => CslShape::RewardAddresses,
        "PoolParams" => CslShape::PoolParams,
        "Certificate" | "PoolRegistration" => CslShape::Certificate,
        "Certificates" => CslShape::Certificates,
        "VotingProposal" => CslShape::VotingProposal,
        "VotingProposals" => CslShape::VotingProposals,
        "GovernanceAction" | "TreasuryWithdrawalsAction" => CslShape::GovernanceAction,
        "NativeScript" | "ScriptAll" | "ScriptAny" | "ScriptNOfK" | "ScriptPubkey"
        | "TimelockStart" | "TimelockExpiry" => CslShape::NativeScript,
        "NativeScripts" => CslShape::NativeScripts,
        "ScriptRef" => CslShape::ScriptRef,
        "AuxiliaryData" => CslShape::AuxiliaryData,
        _ => CslShape::Item,
    })
}

/// Why bytes were refused before reaching CSL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PreflightError {
    /// No bytes at all.
    Empty,
    /// Not one well-formed CBOR item; the decoder's own diagnosis.
    Malformed {
        kind: &'static str,
        path: String,
        message: String,
    },
    /// Well-formed CBOR the decoders cannot represent (non-finite float,
    /// nesting past the decoder's bound): no CSL type contains it.
    Unsupported { kind: &'static str, message: String },
    /// A witness list holds a major-type-7 item at this byte offset.
    SimpleValueInWitnessList { offset: usize },
    /// A byte string of length zero sits at this byte offset where CSL
    /// reads an address.
    EmptyAddress { offset: usize },
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::Empty => write!(f, "Input is empty"),
            PreflightError::Malformed {
                kind,
                path,
                message,
            } => write!(
                f,
                "Malformed CBOR: {} (kind: {}, path: {})",
                message, kind, path
            ),
            PreflightError::Unsupported { kind, message } => {
                write!(f, "Unsupported CBOR content: {} (kind: {})", message, kind)
            }
            PreflightError::SimpleValueInWitnessList { offset } => write!(
                f,
                "Malformed witness list: a simple value or float at byte offset {} where a witness (an array) is expected",
                offset
            ),
            PreflightError::EmptyAddress { offset } => write!(
                f,
                "Malformed address: an empty byte string at byte offset {} where an address is expected",
                offset
            ),
        }
    }
}

impl From<PreflightError> for String {
    fn from(e: PreflightError) -> String {
        e.to_string()
    }
}

impl From<CborDecodeError> for PreflightError {
    fn from(e: CborDecodeError) -> PreflightError {
        let kind = e.kind.as_str();
        match e.kind {
            ErrorKind::NonFiniteFloat
            | ErrorKind::IntNotRepresentable
            | ErrorKind::NestingTooDeep => PreflightError::Unsupported {
                kind,
                message: e.message,
            },
            _ => PreflightError::Malformed {
                kind,
                path: e.path,
                message: e.message,
            },
        }
    }
}

/// Refuse `bytes` unless they are one well-formed CBOR item, nested no
/// deeper than CSL's recursion is calibrated for, that CSL can read as
/// `shape` without aborting. Levels inside the native scripts `shape`
/// holds do not count toward that bound (see [`nesting_outside_native_scripts`]).
pub(crate) fn check_cbor(bytes: &[u8], shape: CslShape) -> Result<(), PreflightError> {
    check_cbor_within(bytes, shape, Reader::Csl)
}

/// [`check_cbor`] for bytes only pallas and the Plutus evaluator read,
/// never CSL (a validation context's inline datum, the transaction of
/// `get_utxo_list_from_tx`, `get_ref_script_bytes` and
/// `execute_tx_scripts`): the same checks, with nesting bounded by
/// [`limits::MAX_PALLAS_NESTING_DEPTH`], which their recursion is
/// calibrated for.
pub(crate) fn check_pallas_cbor(bytes: &[u8], shape: CslShape) -> Result<(), PreflightError> {
    check_cbor_within(bytes, shape, Reader::Pallas)
}

/// [`check_pallas_cbor`] on hex text; invalid hex is reported as such.
pub(crate) fn check_pallas_cbor_hex(hex_text: &str, shape: CslShape) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(hex_text).map_err(|e| format!("Invalid hex: {}", e))?;
    check_pallas_cbor(&bytes, shape)?;
    Ok(bytes)
}

/// Which library's recursion the nesting of the checked bytes is bounded
/// for.
#[derive(Clone, Copy)]
enum Reader {
    /// CSL, deserializing without rendering: [`limits::MAX_CSL_NESTING_DEPTH`].
    Csl,
    /// pallas and the Plutus evaluator only: [`limits::MAX_PALLAS_NESTING_DEPTH`].
    Pallas,
    /// The typed decoders (CSL, then its JSON rendering):
    /// [`limits::MAX_TYPED_DECODER_NESTING_DEPTH`].
    Typed,
}

impl Reader {
    fn bound(self) -> usize {
        match self {
            Reader::Csl => limits::MAX_CSL_NESTING_DEPTH,
            Reader::Pallas => limits::MAX_PALLAS_NESTING_DEPTH,
            Reader::Typed => limits::MAX_TYPED_DECODER_NESTING_DEPTH,
        }
    }

    /// The refusal for a document that nests past the bound, naming the
    /// bound and the reader it is for.
    fn nesting_refusal(self) -> PreflightError {
        let message = match self {
            Reader::Csl => limits::csl_nesting_message(self.bound()),
            Reader::Pallas => limits::pallas_nesting_message(self.bound()),
            Reader::Typed => limits::typed_decoder_nesting_message(self.bound()),
        };
        PreflightError::Unsupported {
            kind: "nesting_too_deep",
            message,
        }
    }
}

/// The refusal for a document whose nesting, native scripts included and
/// through tag-24 payloads, passes [`limits::MAX_CBOR_NESTING_DEPTH`]:
/// the bound on every walk, native scripts included.
fn total_nesting_refusal() -> PreflightError {
    PreflightError::Unsupported {
        kind: "nesting_too_deep",
        message: limits::nesting_depth_message(limits::MAX_CBOR_NESTING_DEPTH),
    }
}

fn check_cbor_within(bytes: &[u8], shape: CslShape, reader: Reader) -> Result<(), PreflightError> {
    if bytes.is_empty() {
        return Err(PreflightError::Empty);
    }
    if let Some(error) = crate::cbor::well_formedness_error(bytes) {
        return Err(error.into());
    }
    if let Some(refusal) = nesting_verdict(bytes, shape, reader) {
        return Err(refusal);
    }
    match shape_hazard(bytes, shape) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// The nesting refusal for well-formed `bytes` read as `shape` by
/// `reader`, or `None` when they are within its bounds: nesting outside
/// the native scripts `shape` holds within `reader`'s bound, and all
/// nesting, native scripts included, within [`limits::MAX_CBOR_NESTING_DEPTH`].
fn nesting_verdict(bytes: &[u8], shape: CslShape, reader: Reader) -> Option<PreflightError> {
    // Most documents are shallow: when even their whole nesting fits the
    // reader's bound there is nothing to tell apart.
    let whole = limits::cbor_nesting_depth_through_embedded_capped(bytes, limits::MAX_CBOR_NESTING_DEPTH);
    if whole <= reader.bound() {
        return None;
    }
    if whole > limits::MAX_CBOR_NESTING_DEPTH {
        return Some(total_nesting_refusal());
    }
    (nesting_outside_native_scripts(bytes, shape, reader.bound()) > reader.bound())
        .then(|| reader.nesting_refusal())
}

/// Whether `bytes` nest past [`limits::MAX_CSL_NESTING_DEPTH`] outside
/// native scripts when read as `shape` (or past
/// [`limits::MAX_CBOR_NESTING_DEPTH`] with them). Scanned iteratively. A
/// byte string under tag 24 (an inline datum `[1, #6.24(bytes)]`, a script
/// reference `#6.24(bytes)`) is measured as the item it carries, on top of
/// the level it sits at: CSL and pallas parse those payloads while reading
/// the enclosing document, on the same stack.
#[cfg(test)]
pub(crate) fn nests_past_csl(bytes: &[u8], shape: CslShape) -> bool {
    nesting_verdict(bytes, shape, Reader::Csl).is_some()
}

/// Whether `bytes`, read as `shape`, nest past what the typed decoders
/// (deserialize, then render as JSON) are calibrated to hold on a host
/// stack: [`limits::MAX_TYPED_DECODER_NESTING_DEPTH`] outside native
/// scripts, [`limits::MAX_CBOR_NESTING_DEPTH`] with them. The refusal, when
/// they do.
pub(crate) fn typed_decoder_nesting_refusal(bytes: &[u8], shape: CslShape) -> Option<String> {
    nesting_verdict(bytes, shape, Reader::Typed).map(|e| match e {
        PreflightError::Unsupported { message, .. } => message,
        other => other.to_string(),
    })
}

/// The refusal [`check_cbor`] gives well-formed `bytes` read as `shape`
/// for their nesting; `None` when they are malformed (a data fault,
/// reported as such by the caller's own check) or within the bounds.
pub(crate) fn csl_nesting_refusal(bytes: &[u8], shape: CslShape) -> Option<String> {
    nesting_refusal(bytes, shape, Reader::Csl)
}

/// [`csl_nesting_refusal`] for bytes only pallas and the Plutus evaluator
/// read, against [`limits::MAX_PALLAS_NESTING_DEPTH`].
pub(crate) fn pallas_nesting_refusal(bytes: &[u8], shape: CslShape) -> Option<String> {
    nesting_refusal(bytes, shape, Reader::Pallas)
}

fn nesting_refusal(bytes: &[u8], shape: CslShape, reader: Reader) -> Option<String> {
    if bytes.is_empty() || crate::cbor::well_formedness_error(bytes).is_some() {
        return None;
    }
    nesting_verdict(bytes, shape, reader).map(|e| e.to_string())
}

// ============================================================
// Native scripts: where the ledger puts them
// ============================================================

/// Where native scripts sit in a document read as some [`CslShape`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeScriptSites {
    /// Whole native scripts in the document: `(start, end)` byte ranges,
    /// sorted and disjoint.
    pub(crate) scripts: Vec<(usize, usize)>,
    /// First bytes of the definite-length tag-24 payloads that are script
    /// references (`[kind, script]`), sorted.
    pub(crate) script_refs: Vec<usize>,
}

/// The native scripts (and script-reference payloads) of `bytes` read as
/// `shape`, found by following the serialization library's own routes to
/// them:
///
/// * a native script itself, or an array of them (optionally tagged 258);
/// * a witness set's key 1 (every witness set of a block, the witness set
///   at index 1 of a transaction);
/// * auxiliary data: `[metadata, [* native_script]]` or tag 259's key 1
///   (index 3 of a four-item transaction, index 2 of a three-item one, the
///   values of a block's auxiliary data map at index 3);
/// * a script reference `#6.24(bytes .cbor [0, native_script])`: an
///   output map's key 3 (a body's outputs, key 1, and collateral return,
///   key 16; an unspent output's index 1; every body of a block).
///
/// Only an item that is a whole native script (as
/// [`crate::native_script::FlatNativeScript`] reads one) counts; anything
/// else at those routes is left to the ordinary nesting count. Every
/// decoder here reads such an item without recursion.
pub(crate) fn native_script_sites(bytes: &[u8], shape: CslShape) -> NativeScriptSites {
    let mut sites = NativeScriptSites::default();
    let _ = native_sites_at(bytes, 0, shape, &mut sites);
    sites.scripts.sort_unstable();
    sites.scripts.dedup();
    sites.script_refs.sort_unstable();
    sites.script_refs.dedup();
    sites
}

/// Follow `shape`'s routes from `at`; `None` where framing cannot be
/// followed (what was found so far stays recorded).
fn native_sites_at(bytes: &[u8], at: usize, shape: CslShape, sites: &mut NativeScriptSites) -> Option<()> {
    match shape {
        CslShape::NativeScript => native_script_at(bytes, at, sites),
        CslShape::NativeScripts => native_script_list_at(bytes, at, sites),
        CslShape::WitnessSet => witness_set_scripts_at(bytes, at, sites),
        CslShape::WitnessSets => {
            for set in array_element_offsets(bytes, at)? {
                let _ = witness_set_scripts_at(bytes, set, sites);
            }
            Some(())
        }
        CslShape::AuxiliaryData => auxiliary_data_scripts_at(bytes, at, sites),
        CslShape::ScriptRef => {
            let header = read_header(bytes, at)?;
            if header.major == 6 {
                script_ref_payload_at(bytes, at, sites)
            } else {
                script_ref_content_at(bytes, at, sites)
            }
        }
        CslShape::TransactionOutput => output_scripts_at(bytes, at, sites),
        CslShape::TransactionOutputs => {
            for output in array_element_offsets(bytes, at)? {
                let _ = output_scripts_at(bytes, output, sites);
            }
            Some(())
        }
        CslShape::TransactionUnspentOutput => {
            let output = array_element_offsets(bytes, at)?.into_iter().nth(1)?;
            output_scripts_at(bytes, output, sites)
        }
        CslShape::TransactionBody => body_scripts_at(bytes, at, sites),
        CslShape::TransactionBodies => {
            for body in array_element_offsets(bytes, at)? {
                let _ = body_scripts_at(bytes, body, sites);
            }
            Some(())
        }
        CslShape::Transaction => {
            let elements = array_element_offsets(bytes, at)?;
            if let Some(&body) = elements.first() {
                let _ = body_scripts_at(bytes, body, sites);
            }
            if let Some(&witness_set) = elements.get(1) {
                let _ = witness_set_scripts_at(bytes, witness_set, sites);
            }
            let auxiliary = match elements.len() {
                4 => elements.get(3),
                3 => elements.get(2),
                _ => None,
            };
            if let Some(&auxiliary) = auxiliary {
                let _ = auxiliary_data_scripts_at(bytes, auxiliary, sites);
            }
            Some(())
        }
        CslShape::Block => block_scripts_at(bytes, at, sites),
        CslShape::VersionedBlock => {
            let block = array_element_offsets(bytes, at)?.into_iter().nth(1)?;
            block_scripts_at(bytes, block, sites)
        }
        CslShape::WitnessList
        | CslShape::Withdrawals
        | CslShape::RewardAddresses
        | CslShape::PoolParams
        | CslShape::Certificate
        | CslShape::Certificates
        | CslShape::VotingProposal
        | CslShape::VotingProposals
        | CslShape::GovernanceAction
        | CslShape::Item => Some(()),
    }
}

/// A whole native script at `at`.
fn native_script_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    let end = crate::native_script::native_script_end(bytes, at)?;
    sites.scripts.push((at, end));
    Some(())
}

/// An array of native scripts, after up to two set tags (258).
fn native_script_list_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    for script in array_element_offsets(bytes, skip_set_tags(bytes, at)?)? {
        let _ = native_script_at(bytes, script, sites);
    }
    Some(())
}

/// Key 1 of a witness set map.
fn witness_set_scripts_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    for (key, value) in map_entry_offsets(bytes, at)? {
        if is_uint(bytes, key, 1) {
            let _ = native_script_list_at(bytes, value, sites);
        }
    }
    Some(())
}

/// `[metadata, [* native_script], …]` or `#6.259({…, 1: [* native_script]})`;
/// a bare metadata map holds none.
fn auxiliary_data_scripts_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    let header = read_header(bytes, at)?;
    match header.major {
        4 => {
            let scripts = array_element_offsets(bytes, at)?.into_iter().nth(1)?;
            native_script_list_at(bytes, scripts, sites)
        }
        6 if header.argument == Some(259) => {
            for (key, value) in map_entry_offsets(bytes, at + header.len)? {
                if is_uint(bytes, key, 1) {
                    let _ = native_script_list_at(bytes, value, sites);
                }
            }
            Some(())
        }
        _ => Some(()),
    }
}

/// A post-Alonzo output map's script reference (key 3).
fn output_scripts_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    if read_header(bytes, at)?.major != 5 {
        return Some(());
    }
    for (key, value) in map_entry_offsets(bytes, at)? {
        if is_uint(bytes, key, 3) {
            let _ = script_ref_payload_at(bytes, value, sites);
        }
    }
    Some(())
}

/// `#6.24(bytes)` at `at`: the payload's first byte, when the byte string
/// has a definite length.
fn script_ref_payload_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    let tag = read_header(bytes, at)?;
    if tag.major != 6 || tag.argument != Some(24) {
        return None;
    }
    let string = read_header(bytes, at + tag.len)?;
    if string.major != 2 || string.argument.is_none() {
        return None;
    }
    sites.script_refs.push(at + tag.len + string.len);
    Some(())
}

/// `[0, native_script]`: the script at index 1.
fn script_ref_content_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    let elements = array_element_offsets(bytes, at)?;
    if elements.len() != 2 || !is_uint(bytes, elements[0], 0) {
        return None;
    }
    native_script_at(bytes, elements[1], sites)
}

/// A body map's outputs (key 1) and collateral return (key 16).
fn body_scripts_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    for (key, value) in map_entry_offsets(bytes, at)? {
        if is_uint(bytes, key, 1) {
            for output in array_element_offsets(bytes, value).unwrap_or_default() {
                let _ = output_scripts_at(bytes, output, sites);
            }
        } else if is_uint(bytes, key, 16) {
            let _ = output_scripts_at(bytes, value, sites);
        }
    }
    Some(())
}

/// `[header, bodies, witness_sets, auxiliary_data_set, …]`.
fn block_scripts_at(bytes: &[u8], at: usize, sites: &mut NativeScriptSites) -> Option<()> {
    let elements = array_element_offsets(bytes, at)?;
    if let Some(&bodies) = elements.get(1) {
        for body in array_element_offsets(bytes, bodies).unwrap_or_default() {
            let _ = body_scripts_at(bytes, body, sites);
        }
    }
    if let Some(&sets) = elements.get(2) {
        for set in array_element_offsets(bytes, sets).unwrap_or_default() {
            let _ = witness_set_scripts_at(bytes, set, sites);
        }
    }
    if let Some(&auxiliary) = elements.get(3) {
        for (_, data) in map_entry_offsets(bytes, auxiliary).unwrap_or_default() {
            let _ = auxiliary_data_scripts_at(bytes, data, sites);
        }
    }
    Some(())
}

/// How deep `bytes` nest when read as `shape`, through tag-24 payloads,
/// with every native script `shape` holds counted as one item at the level
/// it sits at (see [`native_script_sites`]); a script reference's payload
/// is read the same way (`[0, native_script]`). Stops once past `ceiling`.
pub(crate) fn nesting_outside_native_scripts(bytes: &[u8], shape: CslShape, ceiling: usize) -> usize {
    let sites = native_script_sites(bytes, shape);
    let refs = sites.script_refs;
    limits::cbor_nesting_depth_through_embedded_skipping(
        bytes,
        ceiling,
        &sites.scripts,
        &|start, payload| {
            if refs.binary_search(&start).is_err() {
                return Vec::new();
            }
            let mut inner = NativeScriptSites::default();
            let _ = script_ref_content_at(payload, 0, &mut inner);
            inner.scripts
        },
    )
}

/// The first abort CSL would hit reading well-formed `bytes` as `shape`:
/// a simple value in a witness list, or an empty address byte string.
fn shape_hazard(bytes: &[u8], shape: CslShape) -> Option<PreflightError> {
    if let Some(offset) = witness_list_hazard(bytes, shape) {
        return Some(PreflightError::SimpleValueInWitnessList { offset });
    }
    address_hazard(bytes, shape).map(|offset| PreflightError::EmptyAddress { offset })
}

/// [`check_cbor`] on hex text; invalid hex is reported as such.
pub(crate) fn check_cbor_hex(hex_text: &str, shape: CslShape) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(hex_text).map_err(|e| format!("Invalid hex: {}", e))?;
    check_cbor(&bytes, shape)?;
    Ok(bytes)
}

/// The well-formedness gate alone, for callers that read the shape from
/// the registry classification.
pub(crate) fn check_decoder_input(bytes: &[u8], input: DecoderInput) -> Result<(), PreflightError> {
    match input {
        DecoderInput::RawBytes => Ok(()),
        DecoderInput::Cbor(shape) => check_cbor(bytes, shape),
    }
}

/// Every shape's hazard verdict over one document, for callers that try
/// many types against the same bytes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShapeHazards {
    hazardous: [bool; CslShape::ALL.len()],
}

impl ShapeHazards {
    pub(crate) fn scan(bytes: &[u8]) -> ShapeHazards {
        let mut hazardous = [false; CslShape::ALL.len()];
        for shape in CslShape::ALL {
            hazardous[shape.index()] = shape_hazard(bytes, shape).is_some();
        }
        ShapeHazards { hazardous }
    }

    pub(crate) fn hazardous(&self, shape: CslShape) -> bool {
        self.hazardous[shape.index()]
    }
}

// ============================================================
// Address parsing
// ============================================================

/// `csl::Address::from_hex`, refusing the empty payload CSL indexes.
pub(crate) fn address_from_hex(hex_text: &str) -> Result<csl::Address, String> {
    let bytes = hex::decode(hex_text).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.is_empty() {
        return Err("Address bytes are empty".to_string());
    }
    csl::Address::from_hex(hex_text).map_err(|e| format!("Invalid address: {:?}", e))
}

/// `csl::Address::from_bech32`, refusing the empty payload CSL indexes.
pub(crate) fn address_from_bech32(text: &str) -> Result<csl::Address, String> {
    let (_, payload) = bech32::decode(text).map_err(|e| format!("Invalid bech32: {}", e))?;
    if payload.is_empty() {
        return Err("Address bytes are empty".to_string());
    }
    csl::Address::from_bech32(text).map_err(|e| format!("Invalid address: {:?}", e))
}

// ============================================================
// Witness list hazard scan
// ============================================================

/// Byte offset of the first major-type-7 item CSL would meet inside a
/// witness list while reading `bytes` as `shape`, or `None`. Assumes
/// nothing about well-formedness: any framing the scan cannot follow
/// ends it with `None` (CSL then fails on that framing with an error).
fn witness_list_hazard(bytes: &[u8], shape: CslShape) -> Option<usize> {
    match shape {
        CslShape::WitnessList => witness_list_hazard_at(bytes, 0),
        CslShape::WitnessSet => witness_set_hazard_at(bytes, 0),
        CslShape::WitnessSets => witness_sets_hazard_at(bytes, 0),
        CslShape::Transaction => transaction_hazard_at(bytes, 0),
        CslShape::Block => block_hazard_at(bytes, 0),
        CslShape::VersionedBlock => {
            let block = array_element_offsets(bytes, 0)?.into_iter().nth(1)?;
            block_hazard_at(bytes, block)
        }
        CslShape::Item
        | CslShape::TransactionBody
        | CslShape::TransactionBodies
        | CslShape::TransactionOutput
        | CslShape::TransactionOutputs
        | CslShape::TransactionUnspentOutput
        | CslShape::Withdrawals
        | CslShape::RewardAddresses
        | CslShape::PoolParams
        | CslShape::Certificate
        | CslShape::Certificates
        | CslShape::VotingProposal
        | CslShape::VotingProposals
        | CslShape::GovernanceAction
        | CslShape::NativeScript
        | CslShape::NativeScripts
        | CslShape::ScriptRef
        | CslShape::AuxiliaryData => None,
    }
}

fn transaction_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    let witness_set = array_element_offsets(bytes, at)?.into_iter().nth(1)?;
    witness_set_hazard_at(bytes, witness_set)
}

fn block_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    let witness_sets = array_element_offsets(bytes, at)?.into_iter().nth(2)?;
    witness_sets_hazard_at(bytes, witness_sets)
}

fn witness_sets_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    array_element_offsets(bytes, at)?
        .into_iter()
        .find_map(|set| witness_set_hazard_at(bytes, set))
}

/// Keys 0 (`Vkeywitnesses`) and 2 (`BootstrapWitnesses`) of a witness set map.
fn witness_set_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    for (key, value) in map_entry_offsets(bytes, at)? {
        let header = read_header(bytes, key)?;
        if header.major == 0 && matches!(header.argument, Some(0) | Some(2)) {
            if let Some(offset) = witness_list_hazard_at(bytes, value) {
                return Some(offset);
            }
        }
    }
    None
}

/// The array of a witness list, after up to two set tags (258), holds
/// only arrays; a major-type-7 item there is the hazard.
fn witness_list_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    array_element_offsets(bytes, skip_set_tags(bytes, at)?)?
        .into_iter()
        .find(|&item| matches!(read_header(bytes, item), Some(h) if h.major == 7))
}

// ============================================================
// Empty address hazard scan
// ============================================================

/// Byte offset of the first byte string of length zero CSL would read as
/// an address while reading `bytes` as `shape`, or `None`. Like
/// [`witness_list_hazard`], framing the scan cannot follow ends it with
/// `None`, and a route is followed only where CSL follows it (a pool
/// registration's reward account only behind certificate kind 3, a
/// treasury withdrawal map only behind action kind 2), so a document is
/// refused here only if CSL would abort on it.
fn address_hazard(bytes: &[u8], shape: CslShape) -> Option<usize> {
    match shape {
        CslShape::Item
        | CslShape::WitnessSet
        | CslShape::WitnessSets
        | CslShape::WitnessList
        | CslShape::NativeScript
        | CslShape::NativeScripts
        | CslShape::ScriptRef
        | CslShape::AuxiliaryData => None,
        CslShape::Transaction => {
            let body = array_element_offsets(bytes, 0)?.into_iter().next()?;
            body_address_hazard_at(bytes, body)
        }
        CslShape::Block => block_address_hazard_at(bytes, 0),
        CslShape::VersionedBlock => {
            let block = array_element_offsets(bytes, 0)?.into_iter().nth(1)?;
            block_address_hazard_at(bytes, block)
        }
        CslShape::TransactionBody => body_address_hazard_at(bytes, 0),
        CslShape::TransactionBodies => array_element_offsets(bytes, 0)?
            .into_iter()
            .find_map(|body| body_address_hazard_at(bytes, body)),
        CslShape::TransactionOutput => output_address_hazard_at(bytes, 0),
        CslShape::TransactionOutputs => outputs_address_hazard_at(bytes, 0),
        CslShape::TransactionUnspentOutput => {
            let output = array_element_offsets(bytes, 0)?.into_iter().nth(1)?;
            output_address_hazard_at(bytes, output)
        }
        CslShape::Withdrawals => map_keys_address_hazard_at(bytes, 0),
        CslShape::RewardAddresses => array_element_offsets(bytes, 0)?
            .into_iter()
            .find_map(|address| empty_byte_string_at(bytes, address)),
        CslShape::PoolParams => {
            let account = array_element_offsets(bytes, 0)?.into_iter().nth(5)?;
            empty_byte_string_at(bytes, account)
        }
        CslShape::Certificate => certificate_address_hazard_at(bytes, 0),
        CslShape::Certificates => certificates_address_hazard_at(bytes, 0),
        CslShape::VotingProposal => proposal_address_hazard_at(bytes, 0),
        CslShape::VotingProposals => proposals_address_hazard_at(bytes, 0),
        CslShape::GovernanceAction => governance_action_address_hazard_at(bytes, 0),
    }
}

/// `[header, bodies, …]`: every body at index 1.
fn block_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    let bodies = array_element_offsets(bytes, at)?.into_iter().nth(1)?;
    array_element_offsets(bytes, bodies)?
        .into_iter()
        .find_map(|body| body_address_hazard_at(bytes, body))
}

/// The body map's routes to addresses: outputs (key 1), the collateral
/// return (key 16), withdrawals (key 5), certificates (key 4) and
/// proposals (key 20).
fn body_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    for (key, value) in map_entry_offsets(bytes, at)? {
        let header = read_header(bytes, key)?;
        if header.major != 0 {
            continue;
        }
        let hit = match header.argument {
            Some(1) => outputs_address_hazard_at(bytes, value),
            Some(16) => output_address_hazard_at(bytes, value),
            Some(5) => map_keys_address_hazard_at(bytes, value),
            Some(4) => certificates_address_hazard_at(bytes, value),
            Some(20) => proposals_address_hazard_at(bytes, value),
            _ => None,
        };
        if hit.is_some() {
            return hit;
        }
    }
    None
}

fn outputs_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    array_element_offsets(bytes, at)?
        .into_iter()
        .find_map(|output| output_address_hazard_at(bytes, output))
}

/// A legacy output `[address, amount, …]` or a post-Alonzo output map
/// `{0: address, …}`.
fn output_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    match read_header(bytes, at)?.major {
        4 => {
            let address = array_element_offsets(bytes, at)?.into_iter().next()?;
            empty_byte_string_at(bytes, address)
        }
        5 => map_entry_offsets(bytes, at)?
            .into_iter()
            .filter(|(key, _)| is_uint(bytes, *key, 0))
            .find_map(|(_, value)| empty_byte_string_at(bytes, value)),
        _ => None,
    }
}

/// Every key of a `{reward_address => coin}` map.
fn map_keys_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    map_entry_offsets(bytes, at)?
        .into_iter()
        .find_map(|(key, _)| empty_byte_string_at(bytes, key))
}

fn certificates_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    array_element_offsets(bytes, skip_set_tags(bytes, at)?)?
        .into_iter()
        .find_map(|certificate| certificate_address_hazard_at(bytes, certificate))
}

/// A pool registration certificate `[3, operator, vrf, pledge, cost,
/// margin, reward_account, …]`.
fn certificate_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    let elements = array_element_offsets(bytes, at)?;
    if !is_uint(bytes, *elements.first()?, 3) {
        return None;
    }
    empty_byte_string_at(bytes, *elements.get(6)?)
}

fn proposals_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    array_element_offsets(bytes, skip_set_tags(bytes, at)?)?
        .into_iter()
        .find_map(|proposal| proposal_address_hazard_at(bytes, proposal))
}

/// `[deposit, reward_account, governance_action, anchor]`.
fn proposal_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    let elements = array_element_offsets(bytes, at)?;
    if let Some(offset) = elements.get(1).and_then(|&account| empty_byte_string_at(bytes, account)) {
        return Some(offset);
    }
    governance_action_address_hazard_at(bytes, *elements.get(2)?)
}

/// A treasury withdrawals action `[2, {reward_address => coin}, …]`.
fn governance_action_address_hazard_at(bytes: &[u8], at: usize) -> Option<usize> {
    let elements = array_element_offsets(bytes, at)?;
    if !is_uint(bytes, *elements.first()?, 2) {
        return None;
    }
    map_keys_address_hazard_at(bytes, *elements.get(1)?)
}

/// `at`, when the byte string there has no payload; `None` when it has
/// one or is not a byte string the scan can follow.
fn empty_byte_string_at(bytes: &[u8], at: usize) -> Option<usize> {
    (byte_string_len(bytes, at)? == 0).then_some(at)
}

/// Payload length of the byte string at `at`: the argument of a
/// definite-length string, the chunk lengths of an indefinite-length one
/// summed (CSL splices them). `None` for anything else.
fn byte_string_len(bytes: &[u8], at: usize) -> Option<u64> {
    let header = read_header(bytes, at)?;
    if header.major != 2 {
        return None;
    }
    match header.argument {
        Some(len) => Some(len),
        None => {
            let mut i = at + header.len;
            let mut total = 0u64;
            while !is_break(bytes, i) {
                let chunk = read_header(bytes, i)?;
                if chunk.major != 2 {
                    return None;
                }
                let len = chunk.argument?;
                total = total.checked_add(len)?;
                i = i
                    .checked_add(chunk.len)?
                    .checked_add(usize::try_from(len).ok()?)?;
                if i > bytes.len() {
                    return None;
                }
            }
            Some(total)
        }
    }
}

/// Whether the item at `at` is the unsigned integer `value`.
fn is_uint(bytes: &[u8], at: usize, value: u64) -> bool {
    matches!(read_header(bytes, at), Some(h) if h.major == 0 && h.argument == Some(value))
}

/// Offset past up to two set tags (258) at `at`, as CSL skips them before
/// a set's array.
fn skip_set_tags(bytes: &[u8], at: usize) -> Option<usize> {
    let mut at = at;
    for _ in 0..2 {
        let header = read_header(bytes, at)?;
        if header.major == 6 && header.argument == Some(258) {
            at += header.len;
        } else {
            break;
        }
    }
    Some(at)
}

// ============================================================
// Transaction layout
// ============================================================

/// The size of the transaction `bytes` as the ledger measures it for the
/// minimum fee and for `maxTxSize`: the three-element array
/// `[body, witness set, auxiliary data or null]`, each component as its
/// original bytes (cardano-ledger `sizeAlonzoTxF` over
/// `toCBORForSizeComputation`, which Conway keeps). That is one byte of
/// array header and the components, without the `is_valid` flag of a
/// four-element transaction and whatever header and break the document
/// itself writes. `None` when `bytes` is not an array of three or four
/// items.
pub(crate) fn ledger_tx_size(bytes: &[u8]) -> Option<usize> {
    let starts = array_element_offsets(bytes, 0)?;
    let mut lengths = Vec::with_capacity(starts.len());
    for &start in &starts {
        lengths.push(skip_item(bytes, start)? - start);
    }
    let components: usize = match lengths.as_slice() {
        [body, witnesses, _is_valid, auxiliary] => body + witnesses + auxiliary,
        [body, witnesses, auxiliary] => body + witnesses + auxiliary,
        _ => return None,
    };
    Some(1 + components)
}

/// Cost-model language keys CSL reads: PlutusV1, PlutusV2, PlutusV3.
const CSL_COST_MODEL_LANGUAGES: u64 = 3;

/// Why CSL cannot read the transaction `bytes` when a protocol parameter
/// update in it carries a cost model of a language CSL does not know, or
/// `None`. The ledger accepts such a model (its cost models keep unknown
/// languages); CSL refuses the whole transaction as `No variant matched`
/// on `Language`. Followed routes: every parameter change proposal (body
/// key 20) and the pre-Conway update (body key 6).
pub(crate) fn unknown_cost_model_language(bytes: &[u8]) -> Option<String> {
    let body = *array_element_offsets(bytes, 0)?.first()?;
    for (key, value) in map_entry_offsets(bytes, body)? {
        let found = if is_uint(bytes, key, 20) {
            array_element_offsets(bytes, skip_set_tags(bytes, value)?)?
                .into_iter()
                .enumerate()
                .find_map(|(i, proposal)| {
                    let action = *array_element_offsets(bytes, proposal)?.get(2)?;
                    let elements = array_element_offsets(bytes, action)?;
                    if !is_uint(bytes, *elements.first()?, 0) {
                        return None;
                    }
                    let language = unknown_language_in_update(bytes, *elements.get(2)?)?;
                    Some(format!(
                        "the parameter change of proposal {}{}",
                        i, language
                    ))
                })
        } else if is_uint(bytes, key, 6) {
            let updates = *array_element_offsets(bytes, value)?.first()?;
            map_entry_offsets(bytes, updates)?
                .into_iter()
                .find_map(|(_, update)| unknown_language_in_update(bytes, update))
                .map(|language| format!("the protocol parameter update (body key 6){}", language))
        } else {
            None
        };
        if found.is_some() {
            return found;
        }
    }
    None
}

/// `" names cost model language N"` when the protocol parameter update map
/// at `at` has cost models (key 18) keyed by a language CSL does not read.
fn unknown_language_in_update(bytes: &[u8], at: usize) -> Option<String> {
    let (_, cost_models) = map_entry_offsets(bytes, at)?
        .into_iter()
        .find(|(key, _)| is_uint(bytes, *key, 18))?;
    map_entry_offsets(bytes, cost_models)?
        .into_iter()
        .find_map(|(language, _)| {
            let header = read_header(bytes, language)?;
            let n = header.argument?;
            (header.major == 0 && n >= CSL_COST_MODEL_LANGUAGES).then(|| n)
        })
        .map(|n| format!(" carries a cost model for language {}", n))
}

/// The reason to report when CSL refuses the transaction `bytes` with
/// `csl_error`: a cost model of a language CSL does not know named as
/// such, CSL's own error otherwise.
pub(crate) fn transaction_parse_failure(bytes: &[u8], csl_error: &dyn std::fmt::Debug) -> String {
    parse_failure(bytes, csl_error, "")
}

/// [`transaction_parse_failure`] for the validator, which also says that
/// such a transaction is not validated and what still runs it.
pub(crate) fn validation_parse_failure(bytes: &[u8], csl_error: &dyn std::fmt::Debug) -> String {
    parse_failure(
        bytes,
        csl_error,
        ", so it cannot be validated here (executeTxScripts still runs its scripts)",
    )
}

fn parse_failure(bytes: &[u8], csl_error: &dyn std::fmt::Debug, consequence: &str) -> String {
    match unknown_cost_model_language(bytes) {
        Some(found) => format!(
            "{}; the ledger accepts cost models of unknown languages, but the transaction \
             reader (cardano-serialization-lib) knows only languages 0-2 (PlutusV1-V3) and \
             refuses the transaction{}",
            found, consequence
        ),
        None => format!("{:?}", csl_error),
    }
}

// ============================================================
// Header-level CBOR navigation
// ============================================================

/// One decoded CBOR header.
struct Header {
    major: u8,
    /// `None` for indefinite length (additional info 31).
    argument: Option<u64>,
    /// Bytes the header occupies.
    len: usize,
}

/// The header at `at`, or `None` when truncated or reserved.
fn read_header(bytes: &[u8], at: usize) -> Option<Header> {
    let initial = *bytes.get(at)?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let (argument, len) = match additional {
        0..=23 => (Some(additional as u64), 1),
        24 => (Some(read_be(bytes, at + 1, 1)?), 2),
        25 => (Some(read_be(bytes, at + 1, 2)?), 3),
        26 => (Some(read_be(bytes, at + 1, 4)?), 5),
        27 => (Some(read_be(bytes, at + 1, 8)?), 9),
        31 => (None, 1),
        _ => return None,
    };
    Some(Header {
        major,
        argument,
        len,
    })
}

fn read_be(bytes: &[u8], at: usize, width: usize) -> Option<u64> {
    let slice = bytes.get(at..at.checked_add(width)?)?;
    Some(slice.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64))
}

/// Whether the header at `at` is a break (`0xff`).
fn is_break(bytes: &[u8], at: usize) -> bool {
    bytes.get(at) == Some(&0xff)
}

/// Offset just past the item starting at `at`. Iterative: open containers
/// are counted on the heap, never on the stack.
fn skip_item(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    // Items still expected by each open container (`None`: until a break).
    let mut open: Vec<Option<u64>> = Vec::new();
    loop {
        let header = read_header(bytes, i)?;
        i += header.len;
        if header.major == 7 && header.argument.is_none() {
            // A break closes the innermost indefinite container.
            match open.pop() {
                Some(None) => {}
                _ => return None,
            }
        } else {
            if let Some(Some(remaining)) = open.last_mut() {
                *remaining -= 1;
            }
            match header.major {
                2 | 3 => match header.argument {
                    Some(payload) => {
                        i = i.checked_add(usize::try_from(payload).ok()?)?;
                        if i > bytes.len() {
                            return None;
                        }
                    }
                    None => open.push(None),
                },
                4 => match header.argument {
                    Some(0) => {}
                    Some(n) => open.push(Some(n)),
                    None => open.push(None),
                },
                5 => match header.argument {
                    Some(0) => {}
                    Some(n) => open.push(Some(n.checked_mul(2)?)),
                    None => open.push(None),
                },
                6 => open.push(Some(1)),
                _ => {}
            }
        }
        while matches!(open.last(), Some(Some(0))) {
            open.pop();
        }
        if open.is_empty() {
            return Some(i);
        }
    }
}

/// Offsets of the items of the array at `at`, or `None` if `at` is not an
/// array the scan can follow.
fn array_element_offsets(bytes: &[u8], at: usize) -> Option<Vec<usize>> {
    let header = read_header(bytes, at)?;
    if header.major != 4 {
        return None;
    }
    let mut offsets = Vec::new();
    let mut i = at + header.len;
    match header.argument {
        Some(count) => {
            for _ in 0..count {
                offsets.push(i);
                i = skip_item(bytes, i)?;
            }
        }
        None => {
            while !is_break(bytes, i) {
                offsets.push(i);
                i = skip_item(bytes, i)?;
            }
        }
    }
    Some(offsets)
}

/// `(key, value)` offsets of the entries of the map at `at`, or `None` if
/// `at` is not a map the scan can follow.
fn map_entry_offsets(bytes: &[u8], at: usize) -> Option<Vec<(usize, usize)>> {
    let header = read_header(bytes, at)?;
    if header.major != 5 {
        return None;
    }
    let mut entries = Vec::new();
    let mut i = at + header.len;
    let mut pair = |i: &mut usize| -> Option<()> {
        let key = *i;
        let value = skip_item(bytes, key)?;
        *i = skip_item(bytes, value)?;
        entries.push((key, value));
        Some(())
    };
    match header.argument {
        Some(count) => {
            for _ in 0..count {
                pair(&mut i)?;
            }
        }
        None => {
            while !is_break(bytes, i) {
                pair(&mut i)?;
            }
        }
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    #[test]
    fn skip_item_covers_every_major_type() {
        // uint, bstr, tstr, array, map, tag, simple, indefinite forms.
        for (hex, len) in [
            ("00", 1),
            ("1903e8", 3),
            ("42abcd", 3),
            ("63616263", 4),
            ("820102", 3),
            ("a10102", 3),
            ("d9010280", 4),
            ("f5", 1),
            ("fb3ff0000000000000", 9),
            ("9f0102ff", 4),
            ("bf0102ff", 4),
            ("5f41ab41cdff", 6),
            ("80", 1),
            ("a0", 1),
        ] {
            assert_eq!(skip_item(&h(hex), 0), Some(len), "{hex}");
        }
        // Truncated items cannot be skipped.
        assert_eq!(skip_item(&h("82"), 0), None);
        assert_eq!(skip_item(&h("4201"), 0), None);
        assert_eq!(skip_item(&h("9f01"), 0), None);
    }

    #[test]
    fn witness_list_hazard_is_found_where_csl_reads_witness_lists() {
        // A bare list, a tagged list, a witness set, a transaction, a block.
        assert_eq!(
            witness_list_hazard(&h("81f5"), CslShape::WitnessList),
            Some(1)
        );
        assert_eq!(
            witness_list_hazard(&h("81e9"), CslShape::WitnessList),
            Some(1)
        );
        assert_eq!(
            witness_list_hazard(&h("81fb3ff0000000000000"), CslShape::WitnessList),
            Some(1)
        );
        assert_eq!(
            witness_list_hazard(&h("d9010281f6"), CslShape::WitnessList),
            Some(4)
        );
        assert_eq!(
            witness_list_hazard(&h("a10081f5"), CslShape::WitnessSet),
            Some(3)
        );
        assert_eq!(
            witness_list_hazard(&h("a10281f5"), CslShape::WitnessSet),
            Some(3)
        );
        assert_eq!(
            witness_list_hazard(&h("81a10081f5"), CslShape::WitnessSets),
            Some(4)
        );
        assert_eq!(
            witness_list_hazard(&h("84a0a10081f5f5f6"), CslShape::Transaction),
            Some(5)
        );
        assert_eq!(
            witness_list_hazard(&h("85a08081a10081f5a080"), CslShape::Block),
            Some(7)
        );
        assert_eq!(
            witness_list_hazard(&h("820685a08081a10081f5a080"), CslShape::VersionedBlock),
            Some(9)
        );
    }

    #[test]
    fn simple_values_outside_witness_lists_are_not_hazards() {
        // Other witness set keys, the transaction's own bool / null, and an
        // arbitrary item are all fine.
        assert_eq!(
            witness_list_hazard(&h("a10181f5"), CslShape::WitnessSet),
            None
        );
        assert_eq!(
            witness_list_hazard(&h("84a0a0f5f6"), CslShape::Transaction),
            None
        );
        assert_eq!(witness_list_hazard(&h("81f5"), CslShape::Item), None);
        assert_eq!(
            witness_list_hazard(&h("a10080"), CslShape::WitnessSet),
            None
        );
        // Indefinite arrays end at their break rather than tripping on it.
        assert_eq!(witness_list_hazard(&h("9fff"), CslShape::WitnessList), None);
        assert_eq!(
            witness_list_hazard(&h("9f8200ffff"), CslShape::WitnessList),
            None
        );
        // Framing the scan cannot follow is left to CSL's error path.
        assert_eq!(witness_list_hazard(&h("00"), CslShape::WitnessList), None);
        assert_eq!(witness_list_hazard(&h("81"), CslShape::WitnessList), None);
    }

    #[test]
    fn check_cbor_classifies_refusals() {
        assert_eq!(check_cbor(&[], CslShape::Item), Err(PreflightError::Empty));
        assert!(matches!(
            check_cbor(&h("85e9"), CslShape::Item),
            Err(PreflightError::Malformed {
                kind: "unexpected_eof",
                ..
            })
        ));
        assert!(matches!(
            check_cbor(&h("00ff"), CslShape::Item),
            Err(PreflightError::Malformed {
                kind: "trailing_data",
                ..
            })
        ));
        assert!(matches!(
            check_cbor(&h("f97e00"), CslShape::Item),
            Err(PreflightError::Unsupported {
                kind: "non_finite_float",
                ..
            })
        ));
        assert_eq!(check_cbor(&h("81f5"), CslShape::Item), Ok(()));
        assert_eq!(
            check_cbor(&h("81f5"), CslShape::WitnessList),
            Err(PreflightError::SimpleValueInWitnessList { offset: 1 })
        );
    }

    #[test]
    fn empty_address_hazard_is_found_where_csl_reads_addresses() {
        // An output alone: legacy array form and post-Alonzo map form.
        assert_eq!(
            address_hazard(&h("824000"), CslShape::TransactionOutput),
            Some(1)
        );
        assert_eq!(
            address_hazard(&h("a200400100"), CslShape::TransactionOutput),
            Some(2)
        );
        // An indefinite-length string with no payload counts as empty, with
        // and without an empty chunk.
        assert_eq!(
            address_hazard(&h("825fff00"), CslShape::TransactionOutput),
            Some(1)
        );
        assert_eq!(
            address_hazard(&h("825f40ff00"), CslShape::TransactionOutput),
            Some(1)
        );
        assert_eq!(
            address_hazard(&h("81824000"), CslShape::TransactionOutputs),
            Some(2)
        );
        assert_eq!(
            address_hazard(&h("8200824000"), CslShape::TransactionUnspentOutput),
            Some(3)
        );
        // Withdrawal keys and reward address lists.
        assert_eq!(address_hazard(&h("a14000"), CslShape::Withdrawals), Some(1));
        assert_eq!(
            address_hazard(&h("a2410100 4000"), CslShape::Withdrawals),
            Some(4)
        );
        assert_eq!(address_hazard(&h("8140"), CslShape::RewardAddresses), Some(1));
        // Pool parameters (index 5) and a pool registration certificate
        // (kind 3, index 6), alone and in a tagged set.
        assert_eq!(
            address_hazard(&h("89000000000040 8080f6"), CslShape::PoolParams),
            Some(6)
        );
        assert_eq!(
            address_hazard(&h("8a030000000000 408080f6"), CslShape::Certificate),
            Some(7)
        );
        assert_eq!(
            address_hazard(&h("d90102818a030000000000408080f6"), CslShape::Certificates),
            Some(11)
        );
        // A proposal's reward account (index 1) and the keys of a treasury
        // withdrawals action (kind 2) inside a proposal or alone.
        assert_eq!(
            address_hazard(&h("8400408200a0f6"), CslShape::VotingProposal),
            Some(2)
        );
        assert_eq!(
            address_hazard(&h("8400410183 02a14000f6 80"), CslShape::VotingProposal),
            Some(7)
        );
        assert_eq!(
            address_hazard(&h("d901028184004000 00"), CslShape::VotingProposals),
            Some(6)
        );
        assert_eq!(
            address_hazard(&h("8302a14000f6"), CslShape::GovernanceAction),
            Some(3)
        );
        // Every body key that leads to an address.
        assert_eq!(
            address_hazard(&h("a10181824000"), CslShape::TransactionBody),
            Some(4)
        );
        assert_eq!(
            address_hazard(&h("a110824000"), CslShape::TransactionBody),
            Some(3)
        );
        assert_eq!(
            address_hazard(&h("a105a14000"), CslShape::TransactionBody),
            Some(3)
        );
        assert_eq!(
            address_hazard(&h("a104818a030000000000408080f6"), CslShape::TransactionBody),
            Some(10)
        );
        assert_eq!(
            address_hazard(&h("a1148184004000 00"), CslShape::TransactionBody),
            Some(5)
        );
        assert_eq!(
            address_hazard(&h("81a10181824000"), CslShape::TransactionBodies),
            Some(5)
        );
        // A transaction, a block and a versioned block carrying that body.
        assert_eq!(
            address_hazard(&h("84a3008001818240000200a0f5f6"), CslShape::Transaction),
            Some(7)
        );
        assert_eq!(
            address_hazard(&h("84a300800181a2004001000200a0f5f6"), CslShape::Transaction),
            Some(8)
        );
        assert_eq!(
            address_hazard(&h("85a081a1018182400080a080"), CslShape::Block),
            Some(7)
        );
        assert_eq!(
            address_hazard(&h("820685a081a1018182400080a080"), CslShape::VersionedBlock),
            Some(9)
        );
    }

    #[test]
    fn empty_byte_strings_outside_address_positions_are_not_hazards() {
        // An empty input set, an empty datum hash: not addresses.
        assert_eq!(
            address_hazard(&h("a10040"), CslShape::TransactionBody),
            None
        );
        assert_eq!(
            address_hazard(&h("a3004001800240"), CslShape::TransactionBody),
            None
        );
        // Certificate kinds other than 3 and actions other than 2 hold no
        // address at those indexes.
        assert_eq!(
            address_hazard(&h("8a040000000000408080f6"), CslShape::Certificate),
            None
        );
        assert_eq!(
            address_hazard(&h("8301a14000f6"), CslShape::GovernanceAction),
            None
        );
        // A real address is not empty.
        let addr = format!("82581d{}00", "ab".repeat(29));
        assert_eq!(
            address_hazard(&h(&addr), CslShape::TransactionOutput),
            None
        );
        // Shapes that hold no addresses, and framing the scan cannot follow.
        assert_eq!(address_hazard(&h("40"), CslShape::Item), None);
        assert_eq!(address_hazard(&h("a10081f5"), CslShape::WitnessSet), None);
        assert_eq!(address_hazard(&h("00"), CslShape::TransactionOutput), None);
        assert_eq!(address_hazard(&h("82"), CslShape::TransactionOutput), None);
        // Indefinite strings with a payload are not empty.
        assert_eq!(
            address_hazard(&h("825f41ab41cdff00"), CslShape::TransactionOutput),
            None
        );
    }

    #[test]
    fn check_cbor_refuses_empty_addresses_and_deep_nesting() {
        assert_eq!(
            check_cbor(&h("824000"), CslShape::TransactionOutput),
            Err(PreflightError::EmptyAddress { offset: 1 })
        );
        assert_eq!(check_cbor(&h("824000"), CslShape::Item), Ok(()));
        assert_eq!(
            check_cbor(&h("a14000"), CslShape::Withdrawals),
            Err(PreflightError::EmptyAddress { offset: 1 })
        );
        let message = PreflightError::EmptyAddress { offset: 7 }.to_string();
        assert!(message.contains("empty byte string at byte offset 7"), "{}", message);

        let bound = limits::MAX_CSL_NESTING_DEPTH;
        let inside = h(&format!("{}00", "81".repeat(bound)));
        assert_eq!(check_cbor(&inside, CslShape::Item), Ok(()));
        let past = h(&format!("{}00", "81".repeat(bound + 1)));
        assert!(matches!(
            check_cbor(&past, CslShape::Item),
            Err(PreflightError::Unsupported {
                kind: "nesting_too_deep",
                ..
            })
        ));
        assert!(matches!(
            check_cbor(&past, CslShape::Transaction),
            Err(PreflightError::Unsupported {
                kind: "nesting_too_deep",
                ..
            })
        ));
    }

    #[test]
    fn shape_hazards_agree_with_check_cbor() {
        for hex in ["824000", "a14000", "84a3008001818240000200a0f5f6", "81f5", "00"] {
            let bytes = h(hex);
            let hazards = ShapeHazards::scan(&bytes);
            for shape in CslShape::ALL {
                assert_eq!(
                    hazards.hazardous(shape),
                    shape_hazard(&bytes, shape).is_some(),
                    "{hex} as {shape:?}"
                );
            }
        }
    }

    #[test]
    fn address_helpers_refuse_empty_payloads() {
        assert!(address_from_hex("").is_err());
        let empty =
            bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("addr").unwrap(), &[]).unwrap();
        assert!(address_from_bech32(&empty).is_err());
        let addr = "addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3n0d3vllmyqwsx5wktcd8cc3sq835lu7drv2xwl2wywfgse35a3x";
        assert!(address_from_bech32(addr).is_ok());
        let hex_addr = hex::encode(address_from_bech32(addr).unwrap().to_bytes());
        assert!(address_from_hex(&hex_addr).is_ok());
    }

    /// Each nesting refusal names the bound it is for: CSL's 128 levels
    /// and pallas' and the evaluator's 128, worded apart, and the typed
    /// decoders' 64 (their own gate, in front of CSL's); all keep the
    /// `supported limit of N levels` phrase consumers read N from, and say
    /// that native scripts do not count.
    #[test]
    fn nesting_refusals_name_their_own_bound() {
        let deep = |levels: usize| h(&format!("{}00", "81".repeat(levels)));
        let csl = check_cbor(&deep(129), CslShape::Item)
            .unwrap_err()
            .to_string();
        assert!(
            csl.contains("supported limit of 128 levels for decoding by the serialization library"),
            "{}",
            csl
        );
        assert!(csl.contains("native scripts do not count toward it"), "{}", csl);
        assert!(check_cbor(&deep(128), CslShape::Item).is_ok());
        assert!(check_pallas_cbor(&deep(128), CslShape::Item).is_ok());
        let pallas = check_pallas_cbor(&deep(129), CslShape::Item)
            .unwrap_err()
            .to_string();
        assert!(
            pallas.contains(
                "supported limit of 128 levels for decoding by pallas and the Plutus evaluator"
            ),
            "{}",
            pallas
        );
        assert!(!pallas.contains("serialization library"), "{}", pallas);
        assert!(pallas.contains("(kind: nesting_too_deep)"), "{}", pallas);
        assert!(typed_decoder_nesting_refusal(&deep(64), CslShape::Item).is_none());
        assert!(typed_decoder_nesting_refusal(&deep(65), CslShape::Item).is_some());
        assert_eq!(
            limits::typed_decoder_nesting_message(limits::MAX_TYPED_DECODER_NESTING_DEPTH),
            "CBOR nesting is deeper than the supported limit of 64 levels for typed decoding; \
             native scripts do not count toward it and may nest up to 32768 levels"
        );
        // A refusal for nesting only when nesting is the fault.
        assert!(csl_nesting_refusal(&deep(129), CslShape::Item).is_some());
        assert!(csl_nesting_refusal(&deep(128), CslShape::Item).is_none());
        assert!(csl_nesting_refusal(&h("81"), CslShape::Item).is_none());
        assert!(pallas_nesting_refusal(&deep(129), CslShape::Item).is_some());
    }

    /// `levels` of `ScriptAll` around a pubkey script: two CBOR levels each.
    fn script_chain(levels: usize) -> String {
        format!("{}8200581c{}", "820181".repeat(levels), "11".repeat(28))
    }

    /// A definite byte string carrying `payload` (hex).
    fn bstr(payload: &str) -> String {
        let len = payload.len() / 2;
        format!("5a{:08x}{}", len, payload)
    }

    /// A Conway transaction `[body, witness set, true, aux]` with the given
    /// hex parts.
    fn tx(body: &str, witness_set: &str, aux: &str) -> Vec<u8> {
        h(&format!("84{}{}f5{}", body, witness_set, aux))
    }

    /// Native scripts are left out of the bounded readers' count wherever
    /// the ledger puts them, and only there; the walkers' bound still holds
    /// them.
    #[test]
    fn native_scripts_do_not_count_toward_the_bounded_readers() {
        let levels = 3000; // 6001 CBOR levels
        let script = script_chain(levels);
        let body = "a300800180 0200";
        // Witness set key 1, plain and tagged.
        for witness_set in [format!("a10181{}", script), format!("a101d9010281{}", script)] {
            let bytes = tx(body, &witness_set, "f6");
            for shape in [CslShape::Transaction] {
                assert_eq!(check_cbor(&bytes, shape), Ok(()));
                assert_eq!(check_pallas_cbor(&bytes, shape), Ok(()));
                assert!(typed_decoder_nesting_refusal(&bytes, shape).is_none());
            }
            // Not where a transaction reads native scripts from.
            assert!(check_cbor(&bytes, CslShape::Item).is_err());
            assert!(typed_decoder_nesting_refusal(&bytes, CslShape::Item).is_some());
        }
        // Auxiliary data: tag 259 key 1, and the Shelley-MA array form.
        for aux in [format!("d90103a10181{}", script), format!("82a081{}", script)] {
            let bytes = tx(body, "a0", &aux);
            assert_eq!(check_cbor(&bytes, CslShape::Transaction), Ok(()));
            assert_eq!(check_cbor(&h(&aux), CslShape::AuxiliaryData), Ok(()));
        }
        // An output's script reference, in the transaction and alone.
        let script_ref = format!("d818{}", bstr(&format!("8200{}", script)));
        let output = format!("a3004100010003{}", script_ref);
        let bytes = tx(&format!("a3008001 81{} 0200", output), "a0", "f6");
        assert_eq!(check_cbor(&bytes, CslShape::Transaction), Ok(()));
        assert_eq!(check_pallas_cbor(&bytes, CslShape::Transaction), Ok(()));
        assert_eq!(check_cbor(&h(&output), CslShape::TransactionOutput), Ok(()));
        assert_eq!(check_cbor(&h(&script_ref), CslShape::ScriptRef), Ok(()));
        assert_eq!(check_cbor(&h(&format!("8200{}", script)), CslShape::ScriptRef), Ok(()));
        assert!(check_cbor(&h(&script_ref), CslShape::Item).is_err());
        // A native script and a list of them.
        assert_eq!(check_cbor(&h(&script), CslShape::NativeScript), Ok(()));
        assert_eq!(check_cbor(&h(&format!("81{}", script)), CslShape::NativeScripts), Ok(()));
    }

    /// What is not a whole native script at a native-script route counts
    /// in full, and so does everything around the scripts.
    #[test]
    fn only_whole_native_scripts_are_left_out() {
        let bound = limits::MAX_CSL_NESTING_DEPTH;
        // Nested arrays at key 1 are no native script.
        let arrays = format!("{}00", "81".repeat(bound + 1));
        let bytes = tx("a0", &format!("a10181{}", arrays), "f6");
        assert!(check_cbor(&bytes, CslShape::Transaction).is_err());
        // A script chain with a bad leaf is no native script either.
        let bad = format!("{}8200581b{}", "820181".repeat(100), "11".repeat(27));
        let bytes = tx("a0", &format!("a10181{}", bad), "f6");
        assert!(check_cbor(&bytes, CslShape::Transaction).is_err());
        // A deep datum next to a deep script still counts.
        let script = script_chain(1000);
        let datum = format!("{}00", "81".repeat(bound));
        let bytes = tx("a0", &format!("a20181{}0481{}", script, datum), "f6");
        assert!(check_cbor(&bytes, CslShape::Transaction).is_err());
        let datum = format!("{}00", "81".repeat(bound - 3));
        let bytes = tx("a0", &format!("a20181{}0481{}", script, datum), "f6");
        assert_eq!(check_cbor(&bytes, CslShape::Transaction), Ok(()));
    }

    /// The walkers' bound holds native scripts too, through script
    /// references.
    #[test]
    fn native_scripts_nest_up_to_the_walkers_bound() {
        let max = limits::MAX_CBOR_NESTING_DEPTH;
        // `[0, script]` inside the payload: 1 + 2 * levels + 1 CBOR levels
        // below the byte string, which sits at level 1 of `#6.24(...)`.
        let fits = (max - 3) / 2;
        let payload = |levels: usize| format!("8200{}", script_chain(levels));
        let script_ref = |levels: usize| h(&format!("d818{}", bstr(&payload(levels))));
        assert_eq!(check_cbor(&script_ref(fits), CslShape::ScriptRef), Ok(()));
        let err = check_cbor(&script_ref(fits + 1), CslShape::ScriptRef).unwrap_err();
        assert!(err.to_string().contains("supported limit of 32768 levels"), "{}", err);
        assert_eq!(
            csl_nesting_refusal(&script_ref(fits + 1), CslShape::ScriptRef),
            Some(err.to_string())
        );
        assert!(csl_nesting_refusal(&script_ref(fits), CslShape::ScriptRef).is_none());
    }

    #[test]
    fn native_script_sites_follow_the_ledgers_routes() {
        let script = script_chain(2);
        let len = script.len() / 2;
        // A witness set: key 1 after a key 0.
        let set = h(&format!("a200800181{}", script));
        let sites = native_script_sites(&set, CslShape::WitnessSet);
        assert_eq!(sites.scripts, vec![(5, 5 + len)]);
        // Another key holds no scripts.
        let set = h(&format!("a10381{}", script));
        assert!(native_script_sites(&set, CslShape::WitnessSet).scripts.is_empty());
        // A script reference's payload start.
        let script_ref = format!("d818{}", bstr(&format!("8200{}", script)));
        let output = h(&format!("a1 03{}", script_ref));
        let sites = native_script_sites(&output, CslShape::TransactionOutput);
        assert_eq!(sites.script_refs, vec![2 + 2 + 5]);
        assert!(sites.scripts.is_empty());
    }
}
