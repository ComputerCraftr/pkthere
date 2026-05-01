#[inline(always)]
pub(crate) const fn be16_16(b0: u8, b1: u8) -> u16 {
    (b1 as u16) | ((b0 as u16) << 8)
}
