//! Small runtime-wide constants shared by the process bootstrap path.

pub(crate) const SIGINT_EXIT: u32 = (1 << 31) | 130;
