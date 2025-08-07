#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::many_single_char_names)]

mod api;
mod error;
mod ekekem;
mod hic;
mod symmetric;
mod reference;
mod params;
mod rng;

pub use api::*;
pub use error::*;
