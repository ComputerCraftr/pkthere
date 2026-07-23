//! Small runtime-wide constants shared by the process bootstrap path.

pub(crate) const SIGINT_EXIT: u32 = (1 << 31) | 130;
pub(crate) const FATAL_EXIT: u32 = (1 << 31) | 1;
