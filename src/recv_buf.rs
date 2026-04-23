use std::mem::MaybeUninit;

#[repr(align(64))]
pub(crate) struct RecvBuf<const N: usize> {
    data: [MaybeUninit<u8>; N],
}

impl<const N: usize> RecvBuf<N> {
    #[inline]
    pub(crate) const fn new() -> Self {
        Self {
            data: [MaybeUninit::uninit(); N],
        }
    }

    #[inline]
    pub(crate) fn recv_buf_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        &mut self.data
    }

    #[inline]
    pub(crate) fn initialized(&self, len: usize) -> &[u8] {
        let prefix = &self.data[..len];
        // Safety: callers must pass the exact number of bytes reported initialized
        // by the preceding recv call, so only that initialized prefix is exposed.
        unsafe { &*(prefix as *const [MaybeUninit<u8>] as *const [u8]) }
    }
}
