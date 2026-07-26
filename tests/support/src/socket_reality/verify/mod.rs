//! Independent socket-reality verification.

mod availability;
mod contract;
mod creation;
mod disconnect;
mod icmp_dgram;
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
mod disconnect_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod tests;
