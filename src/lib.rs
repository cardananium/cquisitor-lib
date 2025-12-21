pub mod js_error;
pub mod csl_decoders;
pub mod plutus;
pub mod cbor;
mod bingen;
pub mod check_signatures;
mod js_value;
pub mod validators;
pub mod common;
pub mod schema_generator;
pub mod tx_utils;
// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

