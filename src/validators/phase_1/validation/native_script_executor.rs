use cardano_serialization_lib as csl;
use std::collections::HashSet;

#[derive(Debug)]
pub struct NativeScriptExecutor<'a> {
    script: &'a csl::NativeScript,
    signatures: &'a HashSet<csl::Ed25519KeyHash>,
    slot: u64,
}

impl<'a> NativeScriptExecutor<'a> {
    pub fn new(
        script: &'a csl::NativeScript,
        signatures: &'a HashSet<csl::Ed25519KeyHash>,
        slot: u64,
    ) -> Self {
        Self {
            script,
            signatures,
            slot,
        }
    }

    pub fn execute(&self) -> Result<bool, String> {
        self.execute_internal(self.script)
    }

    fn execute_internal(&self, script: &csl::NativeScript) -> Result<bool, String> {
        match script.kind() {
            csl::NativeScriptKind::ScriptPubkey => {
                self.execute_pubkey_script(script.as_script_pubkey().ok_or("ScriptPubkey is None")?)
            }
            csl::NativeScriptKind::ScriptAll => {
                self.execute_all_script(script.as_script_all().ok_or("ScriptAll is None")?)
            }
            csl::NativeScriptKind::ScriptAny => {
                self.execute_any_script(script.as_script_any().ok_or("ScriptAny is None")?)
            }
            csl::NativeScriptKind::ScriptNOfK => self
                .execute_nofk_script(script.as_script_n_of_k().ok_or("ScriptNOfK is None")?),
            csl::NativeScriptKind::TimelockStart => self.execute_invalid_before_script(
                script
                    .as_timelock_start()
                    .ok_or("TimelockStart is None")?,
            ),
            csl::NativeScriptKind::TimelockExpiry => self.execute_invalid_hereafter_script(
                script
                    .as_timelock_expiry()
                    .ok_or("TimelockExpiry is None")?,
            ),
        }
    }

    fn execute_pubkey_script(&self, script_pubkey: csl::ScriptPubkey) -> Result<bool, String> {
        Ok(self.signatures.contains(&script_pubkey.addr_keyhash()))
    }

    fn execute_all_script(&self, script_all: csl::ScriptAll) -> Result<bool, String> {
        let native_scripts = script_all.native_scripts();
        for i in 0..native_scripts.len() {
            let script = native_scripts.get(i);
            if !self.execute_internal(&script)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn execute_any_script(&self, script_any: csl::ScriptAny) -> Result<bool, String> {
        let native_scripts = script_any.native_scripts();
        for i in 0..native_scripts.len() {
            let script = native_scripts.get(i);
            if self.execute_internal(&script)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn execute_nofk_script(&self, script_nofk: csl::ScriptNOfK) -> Result<bool, String> {
        let native_scripts = script_nofk.native_scripts();
        let mut valid_count = 0;
        for i in 0..native_scripts.len() {
            let script = native_scripts.get(i);
            if self.execute_internal(&script)? {
                valid_count += 1;
            }
        }
        Ok(valid_count >= script_nofk.n())
    }

    fn execute_invalid_before_script(
        &self,
        timelock_start: csl::TimelockStart,
    ) -> Result<bool, String> {
        let slot = timelock_start
            .slot_bignum()
            .to_str()
            .parse::<u64>()
            .map_err(|_| "Failed to parse slot as u64".to_string())?;
        Ok(self.slot > slot)
    }

    fn execute_invalid_hereafter_script(
        &self,
        timelock_expiry: csl::TimelockExpiry,
    ) -> Result<bool, String> {
        let slot = timelock_expiry
            .slot_bignum()
            .to_str()
            .parse::<u64>()
            .map_err(|_| "Failed to parse slot as u64".to_string())?;
        Ok(self.slot <= slot)
    }
}
