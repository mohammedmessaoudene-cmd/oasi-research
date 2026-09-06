use std::fmt;

pub const MAX_LEASE_NS: u64 = 1_000_000_000;
pub const MIN_LEASE_NS: u64 = 1;
pub const MAX_WORK_UNITS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    Allow = 0,
    BlockQuarantine = 1,
    BlockBodyUid = 2,
    BlockEpoch = 3,
    BlockGeneration = 4,
    BlockCertificate = 5,
    BlockExpired = 6,
    BlockPrincipal = 7,
    BlockResource = 8,
    BlockAction = 9,
    BlockNoLease = 10,
}

impl Decision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::BlockQuarantine => "BLOCK_QUARANTINE",
            Self::BlockBodyUid => "BLOCK_BODY_UID",
            Self::BlockEpoch => "BLOCK_EPOCH",
            Self::BlockGeneration => "BLOCK_GENERATION",
            Self::BlockCertificate => "BLOCK_CERTIFICATE",
            Self::BlockExpired => "BLOCK_EXPIRED",
            Self::BlockPrincipal => "BLOCK_PRINCIPAL",
            Self::BlockResource => "BLOCK_RESOURCE",
            Self::BlockAction => "BLOCK_ACTION",
            Self::BlockNoLease => "BLOCK_NO_LEASE",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyState {
    pub body_uid: u64,
    pub epoch: u64,
    pub generation: u64,
    pub certificate: u64,
    pub quarantined: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafetyLease {
    pub body_uid: u64,
    pub epoch: u64,
    pub generation: u64,
    pub certificate: u64,
    pub valid_until_ns: u64,
    pub principal_id: u64,
    pub resource_id: u64,
    pub action_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitRequest {
    pub now_ns: u64,
    pub principal_id: u64,
    pub resource_id: u64,
    pub action_id: u64,
}

pub fn validate_commit(
    body: &BodyState,
    lease: Option<&SafetyLease>,
    request: &CommitRequest,
) -> Decision {
    let Some(lease) = lease else {
        return Decision::BlockNoLease;
    };
    if body.quarantined {
        return Decision::BlockQuarantine;
    }
    if body.body_uid != lease.body_uid {
        return Decision::BlockBodyUid;
    }
    if body.epoch != lease.epoch {
        return Decision::BlockEpoch;
    }
    if body.generation != lease.generation {
        return Decision::BlockGeneration;
    }
    if body.certificate != lease.certificate {
        return Decision::BlockCertificate;
    }
    if request.now_ns >= lease.valid_until_ns {
        return Decision::BlockExpired;
    }
    if request.principal_id != lease.principal_id {
        return Decision::BlockPrincipal;
    }
    if request.resource_id != lease.resource_id {
        return Decision::BlockResource;
    }
    if request.action_id != lease.action_id {
        return Decision::BlockAction;
    }
    Decision::Allow
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginError {
    AlreadyPending,
}

/// Single-use authority transaction spanning BEGIN capture and COMMIT.
///
/// A transaction captures the exact active lease at BEGIN. COMMIT consumes
/// that capture, revalidates it against the current body and request through
/// the canonical eleven-decision oracle, and also requires the active lease to
/// remain byte-for-byte authority-equivalent. This keeps revocation, lease
/// replacement, duplicate BEGIN and duplicate COMMIT fail-closed without
/// adding or reordering any semantic decision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorityTransaction {
    pending: bool,
    captured_lease: Option<SafetyLease>,
}

impl AuthorityTransaction {
    pub const fn new() -> Self {
        Self {
            pending: false,
            captured_lease: None,
        }
    }

    pub const fn is_pending(&self) -> bool {
        self.pending
    }

    pub fn begin(&mut self, active_lease: Option<SafetyLease>) -> Result<(), BeginError> {
        if self.pending {
            return Err(BeginError::AlreadyPending);
        }
        self.pending = true;
        self.captured_lease = active_lease;
        Ok(())
    }

    /// Cancels a pending authorization before any effect may be committed.
    pub fn abort(&mut self) -> bool {
        let was_pending = self.pending;
        self.pending = false;
        self.captured_lease = None;
        was_pending
    }

    pub fn commit(
        &mut self,
        body: &BodyState,
        current_lease: Option<&SafetyLease>,
        request: &CommitRequest,
    ) -> Decision {
        if !self.pending {
            return Decision::BlockNoLease;
        }

        self.pending = false;
        let captured_lease = self.captured_lease.take();
        let Some(current_lease) = current_lease else {
            return Decision::BlockNoLease;
        };

        let captured_decision = validate_commit(body, captured_lease.as_ref(), request);
        if captured_decision != Decision::Allow {
            return captured_decision;
        }
        let Some(captured_lease) = captured_lease.as_ref() else {
            return Decision::BlockNoLease;
        };
        lease_replacement_decision(captured_lease, current_lease)
    }
}

fn lease_replacement_decision(
    captured_lease: &SafetyLease,
    current_lease: &SafetyLease,
) -> Decision {
    if captured_lease.body_uid != current_lease.body_uid {
        return Decision::BlockBodyUid;
    }
    if captured_lease.epoch != current_lease.epoch {
        return Decision::BlockEpoch;
    }
    if captured_lease.generation != current_lease.generation {
        return Decision::BlockGeneration;
    }
    if captured_lease.certificate != current_lease.certificate {
        return Decision::BlockCertificate;
    }
    if captured_lease.valid_until_ns != current_lease.valid_until_ns {
        return Decision::BlockExpired;
    }
    if captured_lease.principal_id != current_lease.principal_id {
        return Decision::BlockPrincipal;
    }
    if captured_lease.resource_id != current_lease.resource_id {
        return Decision::BlockResource;
    }
    if captured_lease.action_id != current_lease.action_id {
        return Decision::BlockAction;
    }
    Decision::Allow
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub intent_id: u64,
    pub principal_id: u64,
    pub goal: Goal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Goal {
    ExecuteChildWork { units: u64 },
    PauseChild,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyIr {
    pub policy_id: u64,
    pub principal_id: u64,
    pub resource_id: u64,
    pub action_id: u64,
    pub goal: Goal,
    pub max_units: u64,
    pub lease_ns: u64,
    pub rollback_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReflexInstruction {
    Work { units: u64 },
    Pause,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReflexProgram {
    pub reflex_id: u64,
    pub instructions: Vec<ReflexInstruction>,
    pub principal_id: u64,
    pub resource_id: u64,
    pub action_id: u64,
    pub lease_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    EmptyProgram,
    TooManyInstructions,
    WorkBudgetOutOfRange,
    LeaseDurationOutOfRange,
    MissingRollback,
    IdentityMismatch,
}

pub fn compile_policy(policy: &PolicyIr) -> Result<ReflexProgram, CompileError> {
    if !policy.rollback_required {
        return Err(CompileError::MissingRollback);
    }
    if !(MIN_LEASE_NS..=MAX_LEASE_NS).contains(&policy.lease_ns) {
        return Err(CompileError::LeaseDurationOutOfRange);
    }
    let instruction = match &policy.goal {
        Goal::ExecuteChildWork { units } => {
            if *units == 0 || *units > policy.max_units || policy.max_units > MAX_WORK_UNITS {
                return Err(CompileError::WorkBudgetOutOfRange);
            }
            ReflexInstruction::Work { units: *units }
        }
        Goal::PauseChild => ReflexInstruction::Pause,
    };
    let program = ReflexProgram {
        reflex_id: policy.policy_id,
        instructions: vec![instruction],
        principal_id: policy.principal_id,
        resource_id: policy.resource_id,
        action_id: policy.action_id,
        lease_ns: policy.lease_ns,
    };
    verify_reflex(&program)?;
    Ok(program)
}

pub fn verify_reflex(program: &ReflexProgram) -> Result<(), CompileError> {
    if program.instructions.is_empty() {
        return Err(CompileError::EmptyProgram);
    }
    if program.instructions.len() > 8 {
        return Err(CompileError::TooManyInstructions);
    }
    if !(MIN_LEASE_NS..=MAX_LEASE_NS).contains(&program.lease_ns) {
        return Err(CompileError::LeaseDurationOutOfRange);
    }
    for instruction in &program.instructions {
        if let ReflexInstruction::Work { units } = instruction
            && (*units == 0 || *units > MAX_WORK_UNITS)
        {
            return Err(CompileError::WorkBudgetOutOfRange);
        }
    }
    Ok(())
}
