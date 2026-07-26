const MIN_CATCHUP_WINDOW: usize = 8;
const MAX_CATCHUP_WINDOW: usize = 1024;

#[inline]
pub(crate) fn sync_catchup_window(icmp_sync_pps: u32) -> usize {
    (icmp_sync_pps as usize)
        .saturating_div(4)
        .clamp(MIN_CATCHUP_WINDOW, MAX_CATCHUP_WINDOW)
}

#[cfg(test)]
mod tests;
