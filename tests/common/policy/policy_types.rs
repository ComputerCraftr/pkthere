#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum PolicyKind {
    SyntacticDirectRecursion,
    WildcardImport,
    ForbiddenAllow,
    LoopbackAlias,
    UnconditionalDebug,
    RetiredEndpointAuthority,
    SocketLifecycleAuthority,
    InlineSocketPlatformDecision,
    ManagerVersionAuthority,
    CoherentStatsAuthority,
    RequiredEvidenceDefault,
    ProductionDebugAssertion,
    ProductionPanicSurface,
    FailureContainmentAuthority,
    InteriorMutabilityAuthority,
    SequentiallyConsistentProtocol,
    TestStateAuthority,
    HardcodedTemporaryRoot,
}

impl PolicyKind {
    fn description(self) -> &'static str {
        match self {
            Self::SyntacticDirectRecursion => "syntactic direct recursion",
            Self::WildcardImport => "wildcard import",
            Self::ForbiddenAllow => "forbidden allow attribute",
            Self::LoopbackAlias => "forbidden loopback alias",
            Self::UnconditionalDebug => "unconditional debug emission",
            Self::RetiredEndpointAuthority => "retired endpoint authority",
            Self::SocketLifecycleAuthority => "socket lifecycle authority violation",
            Self::InlineSocketPlatformDecision => {
                "inline socket platform decision outside the platform backend"
            }
            Self::ManagerVersionAuthority => "socket-manager version authority violation",
            Self::CoherentStatsAuthority => "coherent stats authority violation",
            Self::RequiredEvidenceDefault => "required evidence default",
            Self::ProductionDebugAssertion => "production debug-only assertion",
            Self::ProductionPanicSurface => "production panic surface",
            Self::FailureContainmentAuthority => "failure-containment authority violation",
            Self::InteriorMutabilityAuthority => "unregistered interior-mutability authority",
            Self::SequentiallyConsistentProtocol => {
                "production protocol relies on sequentially-consistent ordering"
            }
            Self::TestStateAuthority => "mutable test-only authority in a production type",
            Self::HardcodedTemporaryRoot => "hard-coded platform temporary root",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyFinding {
    pub kind: PolicyKind,
    pub path: String,
    pub line: usize,
    pub item: String,
    pub cfg_domain: String,
    pub detail: String,
}

impl PolicyFinding {
    pub(super) fn render(&self) -> String {
        let domain = if self.cfg_domain.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.cfg_domain)
        };
        format!(
            "{}:{}: {} in {}{}: {}",
            self.path,
            self.line,
            self.kind.description(),
            self.item,
            domain,
            self.detail
        )
    }
}
