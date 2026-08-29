use osia_core_r1::model::{
    BodyState, CommitRequest, CompileError, Decision, Goal, MAX_LEASE_NS, MIN_LEASE_NS, PolicyIr,
    SafetyLease, compile_policy, validate_commit,
};
use osia_core_r1::runtime::{LeaseDeadlineError, checked_lease_deadline};

fn fixture() -> (BodyState, SafetyLease, CommitRequest) {
    let body = BodyState {
        body_uid: 1,
        epoch: 2,
        generation: 3,
        certificate: 4,
        quarantined: false,
    };
    let lease = SafetyLease {
        body_uid: 1,
        epoch: 2,
        generation: 3,
        certificate: 4,
        valid_until_ns: 100,
        principal_id: 5,
        resource_id: 6,
        action_id: 7,
    };
    let request = CommitRequest {
        now_ns: 99,
        principal_id: 5,
        resource_id: 6,
        action_id: 7,
    };
    (body, lease, request)
}

#[test]
fn valid_commit_is_allowed() {
    let (body, lease, request) = fixture();
    assert_eq!(
        validate_commit(&body, Some(&lease), &request),
        Decision::Allow
    );
}

#[test]
fn quarantine_dominates() {
    let (mut body, lease, request) = fixture();
    body.quarantined = true;
    assert_eq!(
        validate_commit(&body, Some(&lease), &request),
        Decision::BlockQuarantine
    );
}

#[test]
fn epoch_race_is_blocked() {
    let (mut body, lease, request) = fixture();
    body.epoch += 1;
    assert_eq!(
        validate_commit(&body, Some(&lease), &request),
        Decision::BlockEpoch
    );
}

#[test]
fn expiry_is_fail_closed() {
    let (body, lease, mut request) = fixture();
    request.now_ns = lease.valid_until_ns;
    assert_eq!(
        validate_commit(&body, Some(&lease), &request),
        Decision::BlockExpired
    );
}

#[test]
fn compiler_requires_rollback_and_bounds() {
    let policy = PolicyIr {
        policy_id: 1,
        principal_id: 1,
        resource_id: 1,
        action_id: 1,
        goal: Goal::ExecuteChildWork { units: 100 },
        max_units: 1_000,
        lease_ns: 50_000_000,
        rollback_required: true,
    };
    let program = compile_policy(&policy).expect("valid policy must compile");
    assert_eq!(program.lease_ns, policy.lease_ns);
}

fn policy_with_lease(lease_ns: u64) -> PolicyIr {
    PolicyIr {
        policy_id: 1,
        principal_id: 1,
        resource_id: 1,
        action_id: 1,
        goal: Goal::ExecuteChildWork { units: 100 },
        max_units: 1_000,
        lease_ns,
        rollback_required: true,
    }
}

#[test]
fn policy_lease_bounds_are_fail_closed() {
    assert_eq!(
        compile_policy(&policy_with_lease(0)),
        Err(CompileError::LeaseDurationOutOfRange)
    );
    assert_eq!(
        compile_policy(&policy_with_lease(MAX_LEASE_NS + 1)),
        Err(CompileError::LeaseDurationOutOfRange)
    );
    assert_eq!(
        compile_policy(&policy_with_lease(MIN_LEASE_NS))
            .expect("minimum lease must compile")
            .lease_ns,
        MIN_LEASE_NS
    );
    assert_eq!(
        compile_policy(&policy_with_lease(50_000_000))
            .expect("normal lease must compile")
            .lease_ns,
        50_000_000
    );
    assert_eq!(
        compile_policy(&policy_with_lease(MAX_LEASE_NS))
            .expect("maximum lease must compile")
            .lease_ns,
        MAX_LEASE_NS
    );
}

#[test]
fn lease_deadline_uses_checked_monotonic_addition() {
    assert_eq!(checked_lease_deadline(10, MIN_LEASE_NS), Ok(11));
    assert_eq!(checked_lease_deadline(10, 50_000_000), Ok(50_000_010));
    assert_eq!(
        checked_lease_deadline(10, MAX_LEASE_NS),
        Ok(MAX_LEASE_NS + 10)
    );
    assert_eq!(
        checked_lease_deadline(10, 0),
        Err(LeaseDeadlineError::DurationOutOfRange)
    );
    assert_eq!(
        checked_lease_deadline(u64::MAX, MIN_LEASE_NS),
        Err(LeaseDeadlineError::Overflow)
    );
}
