//! Independent socket-reality verification.

mod availability;
mod creation;
mod implementation;
mod lifecycle;
mod model;
mod raw;
mod reuse_port;

pub use availability::verify_requirement;
pub use implementation::verify;
pub use model::{
    DerivedFacts, RawIdObservation, VerificationError, VerificationErrorKind, VerifiedReality,
};

#[cfg(test)]
mod tests;
