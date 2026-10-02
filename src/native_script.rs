//! Native scripts in a flat form, walked without recursion.
//!
//! A native script nests one level per `ScriptAll` / `ScriptAny` /
//! `ScriptNOfK`; a transaction of maximum size can carry thousands of
//! levels. The serialization library's accessors (`as_script_all`,
//! `native_scripts`, `get`) each clone the subtree they return, so a walk
//! through them costs time quadratic in depth, and a recursive walk costs
//! a host-stack frame per level. Here a script is read once from its CBOR
//! into a pre-order array ([`FlatNativeScript`]) and every question the
//! validator asks of it (evaluation, the key hashes it names, its JSON) is
//! answered by a loop over that array: linear time, constant stack.

use cardano_serialization_lib as csl;
use pallas_codec::minicbor::{self, data::Type};
use std::collections::HashSet;
use std::convert::TryInto;

/// One script of a [`FlatNativeScript`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    /// `[0, addr_keyhash]`.
    Pubkey([u8; 28]),
    /// `[1, [* native_script]]`.
    All,
    /// `[2, [* native_script]]`.
    Any,
    /// `[3, n, [* native_script]]`; `n` is any int64, as the ledger reads it.
    NOfK(i64),
    /// `[4, slot]` (`invalid_before`).
    TimelockStart(u64),
    /// `[5, slot]` (`invalid_hereafter`).
    TimelockExpiry(u64),
}

/// A transaction's validity interval `[invalid_before, invalid_hereafter)`
/// in slots: body key 8 (`validity_interval_start`) and key 3 (`ttl`);
/// `None` is an unbounded side.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ValidityInterval {
    pub invalid_before: Option<u64>,
    pub invalid_hereafter: Option<u64>,
}

impl ValidityInterval {
    pub fn new(invalid_before: Option<u64>, invalid_hereafter: Option<u64>) -> Self {
        ValidityInterval {
            invalid_before,
            invalid_hereafter,
        }
    }

    /// The interval a transaction body declares.
    pub fn of_body(body: &csl::TransactionBody) -> Self {
        ValidityInterval {
            invalid_before: body.validity_start_interval_bignum().map(u64::from),
            invalid_hereafter: body.ttl_bignum().map(u64::from),
        }
    }
}

/// A native script as a pre-order array: a script's sub-scripts follow it,
/// and `end[i]` is the index just past the subtree rooted at `i`, so the
/// direct children of `i` are `i + 1`, `end[i + 1]`, … up to `end[i]`.
#[derive(Debug, Clone)]
pub(crate) struct FlatNativeScript {
    nodes: Vec<Node>,
    end: Vec<u32>,
}

impl FlatNativeScript {
    /// Read the script the serialization library holds (its encoding is
    /// produced without recursion).
    pub(crate) fn from_csl(script: &csl::NativeScript) -> Result<FlatNativeScript, String> {
        FlatNativeScript::from_cbor(&script.to_bytes())
    }

    /// Read one native script from `bytes`, which must hold exactly it.
    /// Accepts what the serialization library reads: definite or
    /// indefinite arrays, and sub-script lists optionally tagged 258.
    pub(crate) fn from_cbor(bytes: &[u8]) -> Result<FlatNativeScript, String> {
        let mut d = minicbor::Decoder::new(bytes);
        let flat = read_script(&mut d).map_err(|e| format!("Invalid native script: {}", e))?;
        if d.position() != bytes.len() {
            return Err(format!(
                "Invalid native script: {} trailing bytes",
                bytes.len() - d.position()
            ));
        }
        Ok(flat)
    }

    #[cfg(test)]
    pub(crate) fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Direct children of `i`, in order.
    fn children(&self, i: usize) -> impl Iterator<Item = usize> + '_ {
        let end = self.end[i] as usize;
        let mut next = i + 1;
        std::iter::from_fn(move || {
            if next >= end {
                return None;
            }
            let child = next;
            next = self.end[child] as usize;
            Some(child)
        })
    }

    /// Whether the script holds, given the key hashes that signed and the
    /// transaction's validity interval. Children are judged before parents
    /// (reverse pre-order), each once.
    ///
    /// * `ScriptPubkey`: the key hash signed.
    /// * `ScriptAll` / `ScriptAny`: every / some sub-script holds (an empty
    ///   `ScriptAll` holds, an empty `ScriptAny` does not).
    /// * `ScriptNOfK`: at least `n` sub-scripts hold; a count of zero or
    ///   below always holds, one above the number of sub-scripts never.
    /// * `TimelockStart(s)`: the interval has a start and `s <= start`
    ///   (an absent start is minus infinity).
    /// * `TimelockExpiry(s)`: the interval has an end and `end <= s` (an
    ///   absent end is plus infinity).
    ///
    /// No slot enters: whether the current slot lies in the interval is a
    /// separate check of the transaction.
    pub(crate) fn evaluate(&self, signed: &HashSet<[u8; 28]>, interval: &ValidityInterval) -> bool {
        let mut holds = vec![false; self.nodes.len()];
        for i in (0..self.nodes.len()).rev() {
            holds[i] = match &self.nodes[i] {
                Node::Pubkey(key) => signed.contains(key),
                Node::All => self.children(i).all(|c| holds[c]),
                Node::Any => self.children(i).any(|c| holds[c]),
                Node::NOfK(n) => {
                    let count = self.children(i).filter(|&c| holds[c]).count() as i128;
                    count >= *n as i128
                }
                Node::TimelockStart(s) => interval.invalid_before.map_or(false, |start| *s <= start),
                Node::TimelockExpiry(s) => interval.invalid_hereafter.map_or(false, |end| end <= *s),
            };
        }
        holds.first().copied().unwrap_or(false)
    }

    /// Every key hash a `ScriptPubkey` anywhere in the script names.
    pub(crate) fn key_hashes(&self) -> impl Iterator<Item = &[u8; 28]> + '_ {
        self.nodes.iter().filter_map(|node| match node {
            Node::Pubkey(key) => Some(key),
            _ => None,
        })
    }

    /// The script as compact JSON text in the serialization library's
    /// schema for `NativeScript` (`{"ScriptAll":{"native_scripts":[…]}}`,
    /// `{"ScriptNOfK":{"n":2,"native_scripts":[…]}}`,
    /// `{"ScriptPubkey":{"addr_keyhash":"<hex>"}}`,
    /// `{"TimelockStart":{"slot":"<decimal>"}}`, …), written in one pass.
    pub(crate) fn to_csl_json(&self) -> String {
        let mut out = String::with_capacity(self.nodes.len() * 48);
        // Open sub-script lists: (index past the list, whether it has an item).
        let mut open: Vec<(usize, bool)> = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
            while matches!(open.last(), Some((end, _)) if *end == i) {
                open.pop();
                out.push_str("]}}");
            }
            if let Some((_, has_item)) = open.last_mut() {
                if *has_item {
                    out.push(',');
                }
                *has_item = true;
            }
            match node {
                Node::Pubkey(key) => {
                    out.push_str("{\"ScriptPubkey\":{\"addr_keyhash\":\"");
                    out.push_str(&hex::encode(key));
                    out.push_str("\"}}");
                }
                Node::TimelockStart(slot) => {
                    out.push_str(&format!("{{\"TimelockStart\":{{\"slot\":\"{}\"}}}}", slot));
                }
                Node::TimelockExpiry(slot) => {
                    out.push_str(&format!("{{\"TimelockExpiry\":{{\"slot\":\"{}\"}}}}", slot));
                }
                Node::All | Node::Any | Node::NOfK(_) => {
                    match node {
                        Node::All => out.push_str("{\"ScriptAll\":{"),
                        Node::Any => out.push_str("{\"ScriptAny\":{"),
                        Node::NOfK(n) => out.push_str(&format!("{{\"ScriptNOfK\":{{\"n\":{},", n)),
                        _ => unreachable!(),
                    }
                    out.push_str("\"native_scripts\":[");
                    open.push((self.end[i] as usize, false));
                }
            }
        }
        while open.pop().is_some() {
            out.push_str("]}}");
        }
        out
    }
}

/// The offset just past the native script starting at `at` in `bytes`,
/// when a whole native script (as [`FlatNativeScript::from_cbor`] reads
/// one) starts there; `None` otherwise. Read without recursion.
pub(crate) fn native_script_end(bytes: &[u8], at: usize) -> Option<usize> {
    if at >= bytes.len() {
        return None;
    }
    let mut d = minicbor::Decoder::new(bytes);
    d.set_position(at);
    read_script(&mut d).ok()?;
    Some(d.position())
}

/// A script whose sub-script list is being read.
struct OpenList {
    /// Its index in the pre-order array.
    index: usize,
    /// Sub-scripts still expected (`None`: until a break).
    remaining: Option<u64>,
    /// The script's own array was indefinite: a break closes it.
    indefinite: bool,
}

fn read_script(d: &mut minicbor::Decoder<'_>) -> Result<FlatNativeScript, minicbor::decode::Error> {
    let mut nodes: Vec<Node> = Vec::new();
    let mut end: Vec<u32> = Vec::new();
    let mut open: Vec<OpenList> = Vec::new();
    loop {
        let index = nodes.len();
        if index >= u32::MAX as usize {
            return Err(minicbor::decode::Error::message("native script too large"));
        }
        let size = d.array()?;
        let kind = d.u64()?;
        let expected = if kind == 3 { 3 } else { 2 };
        if let Some(size) = size {
            if size != expected {
                return Err(minicbor::decode::Error::message(
                    "unexpected array size in native script",
                ));
            }
        }
        let list = match kind {
            0 => {
                let bytes = d.bytes()?;
                let key: [u8; 28] = bytes
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("key hash is not 28 bytes"))?;
                nodes.push(Node::Pubkey(key));
                false
            }
            1 => {
                nodes.push(Node::All);
                true
            }
            2 => {
                nodes.push(Node::Any);
                true
            }
            3 => {
                nodes.push(Node::NOfK(d.i64()?));
                true
            }
            4 => {
                nodes.push(Node::TimelockStart(d.u64()?));
                false
            }
            5 => {
                nodes.push(Node::TimelockExpiry(d.u64()?));
                false
            }
            _ => {
                return Err(minicbor::decode::Error::message(
                    "unknown native script kind",
                ))
            }
        };
        end.push(index as u32 + 1);
        if list {
            if d.datatype()? == Type::Tag {
                let tag = d.tag()?;
                if tag.as_u64() != 258 {
                    return Err(minicbor::decode::Error::message(
                        "unexpected tag on a native script list",
                    ));
                }
            }
            let remaining = d.array()?;
            open.push(OpenList {
                index,
                remaining,
                indefinite: size.is_none(),
            });
        } else {
            close_script(d, size.is_none())?;
        }

        // Close every list that has taken all its sub-scripts; stop at the
        // first that expects another.
        loop {
            let top = match open.last_mut() {
                Some(top) => top,
                None => return Ok(FlatNativeScript { nodes, end }),
            };
            let more = match &mut top.remaining {
                None => {
                    if d.datatype()? == Type::Break {
                        d.set_position(d.position() + 1);
                        false
                    } else {
                        true
                    }
                }
                Some(0) => false,
                Some(n) => {
                    *n -= 1;
                    true
                }
            };
            if more {
                break;
            }
            let finished = open.pop().expect("the list just examined");
            end[finished.index] = nodes.len() as u32;
            close_script(d, finished.indefinite)?;
        }
    }
}

/// Read the break that closes an indefinite script array.
fn close_script(d: &mut minicbor::Decoder<'_>, indefinite: bool) -> Result<(), minicbor::decode::Error> {
    if indefinite {
        if d.datatype()? != Type::Break {
            return Err(minicbor::decode::Error::message(
                "expected the break closing a native script",
            ));
        }
        d.set_position(d.position() + 1);
    }
    Ok(())
}

/// The key hashes in `signed` as raw bytes, for [`FlatNativeScript::evaluate`].
pub(crate) fn signer_bytes<'a>(
    signed: impl IntoIterator<Item = &'a csl::Ed25519KeyHash>,
) -> HashSet<[u8; 28]> {
    signed
        .into_iter()
        .filter_map(|key| key.to_bytes().try_into().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `levels` of `ScriptAll` around a pubkey script of `key`.
    pub(crate) fn chain(levels: usize, key: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(levels * 3 + 32);
        for _ in 0..levels {
            bytes.extend_from_slice(&[0x82, 0x01, 0x81]);
        }
        bytes.extend_from_slice(&[0x82, 0x00, 0x58, 0x1c]);
        bytes.extend_from_slice(&[key; 28]);
        bytes
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        hex::decode(text.replace(' ', "")).unwrap()
    }

    fn csl_json(bytes: &[u8]) -> String {
        let script = csl::NativeScript::from_bytes(bytes.to_vec()).unwrap();
        crate::csl_decoders::compact_json(&script.to_json().unwrap())
    }

    /// The JSON is the serialization library's, byte for byte once its
    /// indentation is removed, for every kind of script.
    #[test]
    fn the_json_is_the_serialization_librarys() {
        let key = "ab".repeat(28);
        for text in [
            format!("8200581c{}", key),
            "820419ffff".to_string(),
            "82051b0000000100000000".to_string(),
            "820180".to_string(),
            "820280".to_string(),
            "83030280".to_string(),
            "830320 80".to_string(),
            format!("8202 83 8200581c{k} 8303 01 82 820401 820180 8201 81 8200581c{k}", k = key),
            format!("8303 01 d90102 82 8200581c{k} 820405", k = key),
            hex::encode(chain(50, 7)),
        ] {
            let bytes = hex_bytes(&text);
            let flat = FlatNativeScript::from_cbor(&bytes).unwrap();
            assert_eq!(flat.to_csl_json(), csl_json(&bytes), "{}", text);
        }
    }

    #[test]
    fn evaluation_follows_the_ledger_rules() {
        let a = [1u8; 28];
        let b = [2u8; 28];
        let none = ValidityInterval::default();
        let pk = |k: &[u8; 28]| format!("8200581c{}", hex::encode(k));
        let eval = |text: &str, signed: &[[u8; 28]], interval: ValidityInterval| {
            FlatNativeScript::from_cbor(&hex_bytes(text))
                .unwrap()
                .evaluate(&signed.iter().copied().collect(), &interval)
        };
        assert!(eval(&pk(&a), &[a], none));
        assert!(!eval(&pk(&a), &[b], none));
        assert!(eval("820180", &[], none));
        assert!(!eval("820280", &[], none));
        let all = format!("820182{}{}", pk(&a), pk(&b));
        assert!(eval(&all, &[a, b], none));
        assert!(!eval(&all, &[a], none));
        let any = format!("820282{}{}", pk(&a), pk(&b));
        assert!(eval(&any, &[b], none));
        assert!(!eval(&any, &[], none));
        // n of k: 2 of 2, 3 of 2 (never), 0 and -1 (always).
        let n_of = |n: &str| format!("8303{}82{}{}", n, pk(&a), pk(&b));
        assert!(eval(&n_of("02"), &[a, b], none));
        assert!(!eval(&n_of("02"), &[a], none));
        assert!(!eval(&n_of("03"), &[a, b], none));
        assert!(eval(&n_of("00"), &[], none));
        assert!(eval(&n_of("20"), &[], none));
        // Timelocks against the validity interval [before, hereafter):
        // start 100 holds iff before >= 100, expiry 100 iff hereafter <= 100;
        // an absent bound never satisfies either.
        let iv = ValidityInterval::new;
        assert!(!eval("82041864", &[], iv(None, None)));
        assert!(!eval("82041864", &[], iv(None, Some(100))));
        assert!(!eval("82041864", &[], iv(Some(99), None)));
        assert!(eval("82041864", &[], iv(Some(100), None)));
        assert!(eval("82041864", &[], iv(Some(101), None)));
        assert!(!eval("82051864", &[], iv(None, None)));
        assert!(!eval("82051864", &[], iv(Some(100), None)));
        assert!(eval("82051864", &[], iv(None, Some(100))));
        assert!(eval("82051864", &[], iv(None, Some(99))));
        assert!(!eval("82051864", &[], iv(None, Some(101))));
        // Inside All / Any / NofK.
        let lock = |kind: &str| format!("{}82 82041864 82051864", kind);
        assert!(eval(&lock("8201"), &[], iv(Some(100), Some(100))));
        assert!(!eval(&lock("8201"), &[], iv(Some(100), None)));
        assert!(eval(&lock("8202"), &[], iv(Some(100), None)));
        assert!(!eval(&lock("8202"), &[], iv(Some(99), Some(101))));
        assert!(eval(&lock("830302"), &[], iv(Some(100), Some(100))));
        assert!(!eval(&lock("830302"), &[], iv(None, Some(100))));
    }

    #[test]
    fn indefinite_arrays_tags_and_faults() {
        // Indefinite script array and sub-script list, tagged list.
        let flat = FlatNativeScript::from_cbor(&hex_bytes("9f 01 9f 820405 ff ff")).unwrap();
        assert_eq!(flat.nodes(), &[Node::All, Node::TimelockStart(5)]);
        let flat = FlatNativeScript::from_cbor(&hex_bytes("8201 d90102 81 820405")).unwrap();
        assert_eq!(flat.nodes().len(), 2);
        for bad in ["830100", "820600", "8201828204 00", "8200 41 00", "820180 00", "8201 d8 18 80"] {
            assert!(FlatNativeScript::from_cbor(&hex_bytes(bad)).is_err(), "{}", bad);
        }
    }

    /// Deep chains: linear time, constant stack, the same answers.
    #[test]
    fn a_deep_chain_is_walked_on_a_small_stack_in_linear_time() {
        let handle = std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| {
                let bytes = chain(100_000, 9);
                let started = std::time::Instant::now();
                let flat = FlatNativeScript::from_cbor(&bytes).unwrap();
                assert!(flat.evaluate(&std::iter::once([9u8; 28]).collect(), &ValidityInterval::default()));
                assert!(!flat.evaluate(&HashSet::new(), &ValidityInterval::default()));
                assert_eq!(flat.key_hashes().count(), 1);
                let json = flat.to_csl_json();
                assert!(json.starts_with("{\"ScriptAll\":{\"native_scripts\":[{\"ScriptAll\""));
                assert!(json.ends_with("]}}"));
                started.elapsed()
            })
            .unwrap();
        let elapsed = handle.join().expect("the walk holds on a small stack");
        assert!(elapsed.as_secs() < 5, "{:?}", elapsed);
    }

    /// The pallas codec: deep chains decode, clone, compare,
    /// re-encode byte for byte, format and drop on a small stack.
    #[test]
    fn pallas_native_scripts_hold_deep_chains_on_a_small_stack() {
        use pallas_primitives::alonzo::NativeScript as PallasScript;
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let bytes = chain(100_000, 7);
                let script: PallasScript = minicbor::decode(&bytes).expect("decodes");
                let copy = script.clone();
                assert_eq!(copy, script);
                assert_eq!(minicbor::to_vec(&copy).unwrap(), bytes);
                let text = format!("{:?}", copy);
                assert!(text.starts_with("ScriptAll([ScriptAll(["));
                drop(copy);
                drop(script);
            })
            .unwrap();
        handle.join().expect("the deep chain holds on a small stack");
    }

    #[test]
    fn pallas_native_scripts_encode_and_decode_as_before() {
        use pallas_primitives::alonzo::NativeScript as PallasScript;
        let hash = pallas_primitives::AddrKeyhash::new([1u8; 28]);
        let script = PallasScript::ScriptAny(vec![
            PallasScript::ScriptPubkey(hash),
            PallasScript::ScriptNOfK(
                2,
                vec![
                    PallasScript::InvalidBefore(1_000_000),
                    PallasScript::InvalidHereafter(24),
                    PallasScript::ScriptAll(vec![]),
                ],
            ),
        ]);
        let bytes = minicbor::to_vec(&script).unwrap();
        let mut expected = hex_bytes("8202 82 8200581c");
        expected.extend_from_slice(&[1u8; 28]);
        expected.extend(hex_bytes("8303 02 83 82041a000f4240 82051818 820180"));
        assert_eq!(bytes, expected);
        let back: PallasScript = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, script);
        assert_ne!(back, PallasScript::ScriptAny(vec![]));
        assert_eq!(
            format!("{:?}", PallasScript::ScriptNOfK(2, vec![PallasScript::InvalidBefore(5)])),
            "ScriptNOfK(2, [InvalidBefore(5)])"
        );
        assert_eq!(
            format!("{:?}", PallasScript::ScriptPubkey(hash)),
            format!("ScriptPubkey({:?})", hash)
        );
        // An indefinite sub-script list.
        let script: PallasScript = minicbor::decode(&hex_bytes("82019f8204190100ff")).unwrap();
        assert_eq!(script, PallasScript::ScriptAll(vec![PallasScript::InvalidBefore(256)]));
        // Wrong array size, unknown variant, truncated list.
        for bad in ["830100", "820600", "820182820400"] {
            assert!(minicbor::decode::<PallasScript>(&hex_bytes(bad)).is_err(), "{}", bad);
        }
        // An indefinite script array: its break is checked, not read.
        let bytes = hex_bytes("9f0400ff");
        let mut d = minicbor::Decoder::new(&bytes);
        let script: PallasScript = d.decode().unwrap();
        assert_eq!(script, PallasScript::InvalidBefore(0));
        assert_eq!(d.position(), 3);
        assert!(minicbor::decode::<PallasScript>(&hex_bytes("9f040000")).is_err());
    }

    /// `ScriptNOfK` carries the ledger's `Int`: every `i64` count decodes,
    /// re-encodes byte for byte in shortest form, and hashes the same
    /// whether from the original bytes, the re-encoding or CSL.
    #[test]
    fn pallas_n_of_k_counts_span_i64() {
        use pallas_primitives::alonzo::NativeScript as PallasScript;
        use pallas_traverse::ComputeHash;
        let cases: [(i64, &str); 13] = [
            (-1, "20"),
            (-24, "37"),
            (-25, "3818"),
            (0, "00"),
            (2, "02"),
            (23, "17"),
            (24, "1818"),
            (65_536, "1a00010000"),
            (u32::MAX as i64, "1affffffff"),
            (1 << 32, "1b0000000100000000"),
            (1 << 40, "1b0000010000000000"),
            (i64::MAX, "1b7fffffffffffffff"),
            (i64::MIN, "3b7fffffffffffffff"),
        ];
        for (n, int_hex) in cases {
            let bytes = hex_bytes(&format!("8303{}81 820405", int_hex));
            let script: PallasScript = minicbor::decode(&bytes).expect("decodes");
            assert_eq!(script, PallasScript::ScriptNOfK(n, vec![PallasScript::InvalidBefore(5)]));
            assert_eq!(minicbor::to_vec(&script).unwrap(), bytes, "n = {}", n);
            assert_eq!(script.clone(), script);
            assert_eq!(format!("{:?}", script), format!("ScriptNOfK({}, [InvalidBefore(5)])", n));
            let csl_script = csl::NativeScript::from_bytes(bytes.clone()).expect("CSL decodes");
            assert_eq!(csl_script.to_bytes(), bytes);
            assert_eq!(script.compute_hash().to_vec(), csl_script.hash().to_bytes(), "n = {}", n);
            let flat = FlatNativeScript::from_cbor(&bytes).unwrap();
            assert_eq!(flat.nodes()[0], Node::NOfK(n));
        }
        // Beyond the ledger's Int: rejected.
        for bad in ["8303 1b8000000000000000 80", "8303 3b8000000000000000 80"] {
            assert!(minicbor::decode::<PallasScript>(&hex_bytes(bad)).is_err(), "{}", bad);
        }
    }
}
