use crate::native_script::{signer_bytes, FlatNativeScript};
pub use crate::native_script::ValidityInterval;
use cardano_serialization_lib as csl;
use std::collections::HashSet;

/// Judges a native script against the key hashes that signed and the
/// transaction's validity interval, as the ledger does.
///
/// The script is read once into a flat pre-order array and judged by a
/// loop over it (see [`crate::native_script`]): time linear in its size and
/// host stack independent of its nesting.
#[derive(Debug)]
pub struct NativeScriptExecutor<'a> {
    script: &'a csl::NativeScript,
    signatures: &'a HashSet<csl::Ed25519KeyHash>,
    interval: ValidityInterval,
}

impl<'a> NativeScriptExecutor<'a> {
    pub fn new(
        script: &'a csl::NativeScript,
        signatures: &'a HashSet<csl::Ed25519KeyHash>,
        interval: ValidityInterval,
    ) -> Self {
        Self {
            script,
            signatures,
            interval,
        }
    }

    /// Whether the script holds: `ScriptPubkey` when its key hash signed;
    /// `ScriptAll` / `ScriptAny` when all / any sub-scripts hold;
    /// `ScriptNOfK` when at least `n` do (always for `n <= 0`);
    /// `TimelockStart(s)` when the interval has a start and `s <= start`;
    /// `TimelockExpiry(s)` when the interval has an end (ttl) and
    /// `ttl <= s`. The current slot plays no part.
    pub fn execute(&self) -> Result<bool, String> {
        let flat = FlatNativeScript::from_csl(self.script)?;
        Ok(flat.evaluate(&signer_bytes(self.signatures), &self.interval))
    }
}
