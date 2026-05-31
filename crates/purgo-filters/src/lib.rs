#![no_std]

extern crate alloc;

pub mod png;
pub mod wire;

pub use png::{disarm_png, PngOptions, RemovedChunk};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    Malformed(&'static str),
}
