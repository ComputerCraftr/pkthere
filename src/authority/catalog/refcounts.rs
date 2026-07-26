use super::super::{
    AuthorityId, DropClass, FieldIdentity, ReferenceCountOwnershipRecord, ResourceIdentity,
    TypeIdentity,
};

const DESCRIPTOR_TRANSITION_AUTHORITIES: &[AuthorityId] = &[
    AuthorityId::FlowReservation,
    AuthorityId::FlowWrite,
    AuthorityId::ManagerTransaction,
    AuthorityId::SocketTopology,
    AuthorityId::SocketIo,
];

pub(crate) const REFERENCE_COUNT_OWNERSHIP_RECORDS: &[ReferenceCountOwnershipRecord] =
    &[ReferenceCountOwnershipRecord {
        resource: ResourceIdentity::OwnedField {
            owner: TypeIdentity::ManagedSocketInner,
            field: FieldIdentity::DescriptorOwner,
            source_field: "descriptor_owner",
            resource_type: TypeIdentity::DescriptorOwner,
        },
        wrapper: TypeIdentity::WorkerDescriptorCache,
        clone_methods: &[super::super::FunctionIdentity::DescriptorCacheClone],
        upgrade_methods: &[super::super::FunctionIdentity::DescriptorCacheUpgrade],
        permitted_authorities: DESCRIPTOR_TRANSITION_AUTHORITIES,
        retirement_owner: TypeIdentity::ManagedSocket,
        final_drop_owner: TypeIdentity::ManagedSocket,
        final_drop_method: super::super::FunctionIdentity::RetireDescriptorAfterRevocation,
        // `retire_descriptor_after_revocation` first extracts the uniquely
        // owned Socket with `Arc::try_unwrap`. The Arc allocation then has a
        // bounded, infallible final disposition; kernel descriptor closure is
        // governed separately by `SocketDescriptorClose`.
        final_drop_class: DropClass::BoundedInfallible,
    }];
