use super::TopologyReservation;
impl Drop for TopologyReservation {
    fn drop(&mut self) {
        if let Err(error) = self.rollback_inner()
            && error.is_fatal_topology_invariant()
        {
            crate::runtime_support::publish_process_fatal(format_args!(
                "managed socket topology reservation drop failed closed: {error}"
            ));
        }
    }
}
