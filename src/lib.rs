#![feature(let_chains)]
#![feature(slice_pattern)]

#[cfg(all(feature = "wasm", feature = "nowasm"))]
compile_error!(
    "proof-of-exploit: both wasm & nowasm are enabled, just one of them must be enabled"
);
#[cfg(all(not(feature = "wasm"), not(feature = "nowasm")))]
compile_error!("proof-of-exploit: none of wasm & nowasm are enabled, one of them must be enabled");

#[cfg(not(feature = "wasm"))]
pub mod cli;
#[cfg(not(feature = "wasm"))]
pub mod constants;
#[cfg(not(feature = "wasm"))]
pub mod env;
#[cfg(not(feature = "wasm"))]
pub mod error;
#[cfg(not(feature = "wasm"))]
pub mod utils;
#[cfg(not(feature = "wasm"))]
pub mod verification;
#[cfg(not(feature = "wasm"))]
pub mod witness;

#[cfg(feature = "wasm")]
pub mod wasm;
#[cfg(feature = "wasm")]
pub use wasm::*;
