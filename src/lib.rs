#![feature(let_chains)]
#![feature(slice_pattern)]

#[cfg(not(feature = "dep_wasm"))]
pub mod cli;
#[cfg(not(feature = "dep_wasm"))]
pub mod constants;
#[cfg(not(feature = "dep_wasm"))]
pub mod env;
#[cfg(not(feature = "dep_wasm"))]
pub mod error;
#[cfg(not(feature = "dep_wasm"))]
pub mod utils;
#[cfg(not(feature = "dep_wasm"))]
pub mod verification;
#[cfg(not(feature = "dep_wasm"))]
pub mod witness;

#[cfg(feature = "dep_wasm")]
pub mod wasm;
#[cfg(feature = "dep_wasm")]
pub use wasm::*;
