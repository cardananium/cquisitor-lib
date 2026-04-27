//! Shared fixtures for phase_1 validator tests.
//!
//! The transactions used here are real signed preview/mainnet transactions
//! captured for regression purposes — they let us exercise validators with
//! authentic CBOR bodies instead of hand-rolling every field through CSL.
//! Individual tests mutate the surrounding [`ValidationInputContext`] (slot,
//! protocol parameters, account state, etc.) to drive failure branches.

use crate::common::{CostModels, ExUnitPrices, ExUnits, SubCoin};
use crate::validators::common::NetworkType;
use crate::validators::input_contexts::{
    UtxoInputContext, ValidationInputContext,
};
use crate::validators::protocol_params::ProtocolParameters;

/// A minimal preview-era value-transfer tx. Single input → two outputs, no
/// scripts, no certs, no metadata. Its signing slot is around 1_000_000.
pub const PREVIEW_SIMPLE_TX_HEX: &str = "84a400d901028182582016b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a00018282583900aef399a405edd6797117a3db6653e1a230e1f6f91dd5badb77f2be3720fc45da826093ae8ed2e4f0f81c4f5ea9b6f0dda561c974cfc6355d1a000f424082583900f275cb75d82f737c49280039947e484919ee044c82c2e4ceaf2f2d87984c3eb5c8a01b4b53c7cec4cfc139345a28d24a6ec918873c459add1a48b7d00d021a00030d40075820bdaa99eb158414dea0a91d6c727e2268574b23efe6e08ab3b841abe8059a030ca100d9010281825820f8f5750132a13473240e318dd36eccd70083e8f08ac589c74ebe776f43e9401d58401e149e081ff497d7f97c3ef7427a916d1b0632c6eb98bb54b040aca413a2ad94273291c9b63b2802083c72b0cfe03eef2b55f767ecf32dba894dd59701076409f5d90103a0";

/// The sole input consumed by [`PREVIEW_SIMPLE_TX_HEX`].
pub const PREVIEW_SIMPLE_INPUT_UTXO: &str = r#"{"input":{"outputIndex":0,"txHash":"16b6ee8c812f8b1c9c643ee3828f50fdcf0f174625bbd6e947ba77b12374094a"},"output":{"address":"addr_test1qre8tjm4mqhhxlzf9qqrn9r7fpy3nmsyfjpv9exw4uhjmpucfslttj9qrd94837wcn8uzwf5tg5dyjnweyvgw0z9ntwsl3q7la","amount":[{"unit":"lovelace","quantity":"1221175714"}],"scriptHash":null}}"#;

pub fn preview_simple_utxo() -> UtxoInputContext {
    UtxoInputContext {
        utxo: serde_json::from_str(PREVIEW_SIMPLE_INPUT_UTXO).unwrap(),
        is_spent: false,
    }
}

/// Reasonable preview-network protocol parameters (Conway/Plomin era).
pub fn default_protocol_parameters() -> ProtocolParameters {
    ProtocolParameters {
        min_fee_coefficient_a: 44,
        min_fee_constant_b: 155381,
        max_block_body_size: 90112,
        max_transaction_size: 16384,
        max_block_header_size: 1100,
        stake_key_deposit: 2_000_000,
        stake_pool_deposit: 500_000_000,
        max_epoch_for_pool_retirement: 18,
        protocol_version: (10, 0),
        min_pool_cost: 170_000_000,
        ada_per_utxo_byte: 4310,
        cost_models: default_cost_models(),
        execution_prices: ExUnitPrices {
            mem_price: SubCoin {
                numerator: 577,
                denominator: 10_000,
            },
            step_price: SubCoin {
                numerator: 721,
                denominator: 10_000_000,
            },
        },
        max_tx_execution_units: ExUnits {
            mem: 14_000_000,
            steps: 10_000_000_000,
        },
        max_block_execution_units: ExUnits {
            mem: 62_000_000,
            steps: 20_000_000_000,
        },
        max_value_size: 5000,
        collateral_percentage: 150,
        max_collateral_inputs: 3,
        governance_action_deposit: 100_000_000_000,
        drep_deposit: 500_000_000,
        reference_script_cost_per_byte: SubCoin {
            numerator: 15,
            denominator: 1,
        },
    }
}

/// Standard preview-network cost models that let Plutus-aware tests compute
/// script_data_hash correctly. Values mirror the ones returned by the preview
/// node's `query protocol-parameters` at Conway activation.
pub fn default_cost_models() -> CostModels {
    CostModels {
        plutus_v1: Some(vec![
            100788, 420, 1, 1, 1000, 173, 0, 1, 1000, 59957, 4, 1, 11183, 32, 201305, 8356, 4,
            16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 100, 100,
            16000, 100, 94375, 32, 132994, 32, 61462, 4, 72010, 178, 0, 1, 22151, 32, 91189, 769,
            4, 2, 85848, 228465, 122, 0, 1, 1, 1000, 42921, 4, 2, 24548, 29498, 38, 1, 898148,
            27279, 1, 51775, 558, 1, 39184, 1000, 60594, 1, 141895, 32, 83150, 32, 15299, 32,
            76049, 1, 13169, 4, 22100, 10, 28999, 74, 1, 28999, 74, 1, 43285, 552, 1, 44749, 541,
            1, 33852, 32, 68246, 32, 72362, 32, 7243, 32, 7391, 32, 11546, 32, 85848, 228465, 122,
            0, 1, 1, 90434, 519, 0, 1, 74433, 32, 85848, 228465, 122, 0, 1, 1, 85848, 228465, 122,
            0, 1, 1, 270652, 22588, 4, 1457325, 64566, 4, 20467, 1, 4, 0, 141992, 32, 100788, 420,
            1, 1, 81663, 32, 59498, 32, 20142, 32, 24588, 32, 20744, 32, 25933, 32, 24623, 32,
            53384111, 14333, 10,
        ]),
        plutus_v2: Some(vec![
            100788, 420, 1, 1, 1000, 173, 0, 1, 1000, 59957, 4, 1, 11183, 32, 201305, 8356, 4,
            16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 100, 100,
            16000, 100, 94375, 32, 132994, 32, 61462, 4, 72010, 178, 0, 1, 22151, 32, 91189, 769,
            4, 2, 85848, 228465, 122, 0, 1, 1, 1000, 42921, 4, 2, 24548, 29498, 38, 1, 898148,
            27279, 1, 51775, 558, 1, 39184, 1000, 60594, 1, 141895, 32, 83150, 32, 15299, 32,
            76049, 1, 13169, 4, 22100, 10, 28999, 74, 1, 28999, 74, 1, 43285, 552, 1, 44749, 541,
            1, 33852, 32, 68246, 32, 72362, 32, 7243, 32, 7391, 32, 11546, 32, 85848, 228465, 122,
            0, 1, 1, 90434, 519, 0, 1, 74433, 32, 85848, 228465, 122, 0, 1, 1, 85848, 228465, 122,
            0, 1, 1, 955506, 213312, 0, 2, 270652, 22588, 4, 1457325, 64566, 4, 20467, 1, 4, 0,
            141992, 32, 100788, 420, 1, 1, 81663, 32, 59498, 32, 20142, 32, 24588, 32, 20744, 32,
            25933, 32, 24623, 32, 43053543, 10, 53384111, 14333, 10, 43574283, 26308, 10,
        ]),
        plutus_v3: Some(vec![
            100788, 420, 1, 1, 1000, 173, 0, 1, 1000, 59957, 4, 1, 11183, 32, 201305, 8356, 4,
            16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 16000, 100, 100, 100,
            16000, 100, 94375, 32, 132994, 32, 61462, 4, 72010, 178, 0, 1, 22151, 32, 91189, 769,
            4, 2, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 1, 1000, 42921, 4, 2,
            24548, 29498, 38, 1, 898148, 27279, 1, 51775, 558, 1, 39184, 1000, 60594, 1, 141895,
            32, 83150, 32, 15299, 32, 76049, 1, 13169, 4, 22100, 10, 28999, 74, 1, 28999, 74, 1,
            43285, 552, 1, 44749, 541, 1, 33852, 32, 68246, 32, 72362, 32, 7243, 32, 7391, 32,
            11546, 32, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 90434, 519, 0, 1,
            74433, 32, 85848, 123203, 7305, -900, 1716, 549, 57, 85848, 0, 1, 1, 85848, 123203,
            7305, -900, 1716, 549, 57, 85848, 0, 1, 955506, 213312, 0, 2, 270652, 22588, 4,
            1457325, 64566, 4, 20467, 1, 4, 0, 141992, 32, 100788, 420, 1, 1, 81663, 32, 59498, 32,
            20142, 32, 24588, 32, 20744, 32, 25933, 32, 24623, 32, 43053543, 10, 53384111, 14333,
            10, 43574283, 26308, 10, 16000, 100, 16000, 100, 962335, 18, 2780678, 6, 442008, 1,
            52538055, 3756, 18, 267929, 18, 76433006, 8868, 18, 52948122, 18, 1995836, 36, 3227919,
            12, 901022, 1, 166917843, 4307, 36, 284546, 36, 158221314, 26549, 36, 74698472, 36,
            333849714, 1, 254006273, 72, 2174038, 72, 2261318, 64571, 4, 207616, 8310, 4, 1293828,
            28716, 63, 0, 1, 1006041, 43623, 251, 0, 1, 100181, 726, 719, 0, 1, 100181, 726, 719,
            0, 1, 100181, 726, 719, 0, 1, 107878, 680, 0, 1, 95336, 1, 281145, 18848, 0, 1, 180194,
            159, 1, 1, 158519, 8942, 0, 1, 159378, 8813, 0, 1, 107490, 3298, 1, 106057, 655, 1,
            1964219, 24520, 3,
        ]),
    }
}

/// A reusable validation context for tests: single-UTxO preview tx, slot
/// inside the validity interval, empty ledger-state collections.
pub fn preview_simple_context() -> ValidationInputContext {
    ValidationInputContext::new(
        vec![preview_simple_utxo()],
        default_protocol_parameters(),
        1_000_000,
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        0,
        NetworkType::Preview,
        vec![],
        vec![],
    )
}
