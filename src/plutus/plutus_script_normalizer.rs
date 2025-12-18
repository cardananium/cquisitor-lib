use anyhow::{anyhow, Result};
use pallas_codec::minicbor as minicbor;

#[derive(Debug, Clone, Copy)]
pub enum OutputEncoding {
    SingleCBOR,
    DoubleCBOR,
    PurePlutusScriptBytes,
}

static SUPPORTED_PLUTUS_VERSIONS: &[[u8; 3]] = &[
    [1, 0, 0], // Plutus V1
    [1, 1, 0], // Plutus V3
];

pub fn normalize_plutus_script(
    plutus_script: &[u8],
    encoding: OutputEncoding,
) -> Result<Vec<u8>> {
    let pure_plutus_bytes = get_pure_plutus_bytes(plutus_script)?;
    apply_encoding(&pure_plutus_bytes, encoding)
}

pub fn normalize_plutus_script_with_core_version(
    plutus_script: &[u8],
    encoding: OutputEncoding,
) -> Result<(Vec<u8>, [u8; 3])> {
    let pure_plutus_bytes = get_pure_plutus_bytes(plutus_script)?;
    let encoded_bytes = apply_encoding(&pure_plutus_bytes, encoding)?;
    let core_version = [pure_plutus_bytes[0], pure_plutus_bytes[1], pure_plutus_bytes[2]];
    Ok((encoded_bytes, core_version))
}

fn get_pure_plutus_bytes(plutus_script: &[u8]) -> Result<Vec<u8>> {
    let mut unwrapped_script = plutus_script.to_vec();

    for _ in 0..10 {
        if has_supported_plutus_version(&unwrapped_script) {
            return Ok(unwrapped_script);
        }
        // Try to parse as CBOR "bytes" (major type 2)
        match try_decode_cbor_bytes(&unwrapped_script) {
            Ok(inner) => unwrapped_script = inner,
            Err(_) => break,
        }
    }

    if has_supported_plutus_version(&unwrapped_script) {
        Ok(unwrapped_script)
    } else {
        Err(anyhow!(
            "Unsupported Plutus version or invalid Plutus script bytes"
        ))
    }
}

fn has_supported_plutus_version(plutus_script: &[u8]) -> bool {
    if plutus_script.len() < 3 {
        return false;
    }
    let version = [plutus_script[0], plutus_script[1], plutus_script[2]];
    SUPPORTED_PLUTUS_VERSIONS
        .iter()
        .any(|&v| v == version)
}

fn try_decode_cbor_bytes(input: &[u8]) -> Result<Vec<u8>> {
    let bytes_wrapper = minicbor::decode::<ByteWrapper>(input)
        .map_err(|e| anyhow!("CBOR decode error: {:?}", e))?;
    Ok(bytes_wrapper.0)
}

#[derive(Debug)]
struct ByteWrapper(Vec<u8>);


impl<'b, C> minicbor::Decode<'b, C> for ByteWrapper
{
    fn decode(d: &mut minicbor::Decoder<'b>, _ctx: &mut C) -> std::result::Result<Self, minicbor::decode::Error> {
        let cbor = d.bytes()?;
        Ok(ByteWrapper(cbor.to_vec()))
    }
}

impl<C> minicbor::Encode<C> for ByteWrapper
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> std::result::Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?;
        Ok(())
    }
}

fn apply_encoding(pure_plutus_script: &[u8], output_encoding: OutputEncoding) -> Result<Vec<u8>> {
    match output_encoding {
        OutputEncoding::SingleCBOR => apply_cbor_encoding(pure_plutus_script),
        OutputEncoding::DoubleCBOR => {
            let single = apply_cbor_encoding(pure_plutus_script)?;
            apply_cbor_encoding(&single)
        }
        OutputEncoding::PurePlutusScriptBytes => Ok(pure_plutus_script.to_vec()),
    }
}

fn apply_cbor_encoding(bytes: &[u8]) -> Result<Vec<u8>> {
    let encoded = minicbor::to_vec(ByteWrapper(bytes.to_vec()))
        .map_err(|e| anyhow!("Failed to encode CBOR bytes: {:?}", e))?;
    Ok(encoded)
}