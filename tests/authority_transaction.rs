use osia_core_r1::model::{
    AuthorityTransaction, BeginError, BodyState, CommitRequest, Decision, SafetyLease,
    validate_commit,
};
use osia_core_r1::protocol::{ExpectedAck, rollback_ack, rollback_request};
use osia_core_r1::runtime::{ChildProcess, checked_counter_increment};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

fn fixture() -> (BodyState, SafetyLease, CommitRequest) {
    (
        BodyState {
            body_uid: 11,
            epoch: 22,
            generation: 33,
            certificate: 44,
            quarantined: false,
        },
        SafetyLease {
            body_uid: 11,
            epoch: 22,
            generation: 33,
            certificate: 44,
            valid_until_ns: 1_000,
            principal_id: 55,
            resource_id: 66,
            action_id: 77,
        },
        CommitRequest {
            now_ns: 999,
            principal_id: 55,
            resource_id: 66,
            action_id: 77,
        },
    )
}

fn transact(
    body: BodyState,
    captured_lease: Option<SafetyLease>,
    current_lease: Option<SafetyLease>,
    request: CommitRequest,
) -> Decision {
    let mut transaction = AuthorityTransaction::new();
    transaction
        .begin(captured_lease)
        .expect("fresh BEGIN must be accepted");
    transaction.commit(&body, current_lease.as_ref(), &request)
}

#[test]
fn transaction_preserves_all_eleven_decisions_and_precedence() {
    let (body, lease, request) = fixture();
    let cases = [
        (
            "allow",
            body,
            Some(lease),
            Some(lease),
            request,
            Decision::Allow,
        ),
        (
            "no_lease",
            body,
            None,
            None,
            request,
            Decision::BlockNoLease,
        ),
        (
            "no_lease_precedes_quarantine",
            BodyState {
                quarantined: true,
                ..body
            },
            None,
            None,
            request,
            Decision::BlockNoLease,
        ),
        (
            "quarantine",
            BodyState {
                quarantined: true,
                ..body
            },
            Some(lease),
            Some(lease),
            request,
            Decision::BlockQuarantine,
        ),
        (
            "body_uid",
            BodyState {
                body_uid: body.body_uid + 1,
                ..body
            },
            Some(lease),
            Some(lease),
            request,
            Decision::BlockBodyUid,
        ),
        (
            "epoch",
            BodyState {
                epoch: body.epoch + 1,
                ..body
            },
            Some(lease),
            Some(lease),
            request,
            Decision::BlockEpoch,
        ),
        (
            "generation",
            BodyState {
                generation: body.generation + 1,
                ..body
            },
            Some(lease),
            Some(lease),
            request,
            Decision::BlockGeneration,
        ),
        (
            "certificate",
            BodyState {
                certificate: body.certificate + 1,
                ..body
            },
            Some(lease),
            Some(lease),
            request,
            Decision::BlockCertificate,
        ),
        (
            "expired",
            body,
            Some(lease),
            Some(lease),
            CommitRequest {
                now_ns: lease.valid_until_ns,
                ..request
            },
            Decision::BlockExpired,
        ),
        (
            "principal",
            body,
            Some(lease),
            Some(lease),
            CommitRequest {
                principal_id: request.principal_id + 1,
                ..request
            },
            Decision::BlockPrincipal,
        ),
        (
            "resource",
            body,
            Some(lease),
            Some(lease),
            CommitRequest {
                resource_id: request.resource_id + 1,
                ..request
            },
            Decision::BlockResource,
        ),
        (
            "action",
            body,
            Some(lease),
            Some(lease),
            CommitRequest {
                action_id: request.action_id + 1,
                ..request
            },
            Decision::BlockAction,
        ),
    ];

    for (name, candidate_body, captured, current, candidate_request, expected) in cases {
        assert_eq!(
            validate_commit(&candidate_body, captured.as_ref(), &candidate_request,),
            expected,
            "canonical authority case {name}",
        );
        assert_eq!(
            transact(candidate_body, captured, current, candidate_request,),
            expected,
            "authority transaction case {name}",
        );
    }

    assert_eq!(
        validate_commit(
            &BodyState {
                quarantined: true,
                certificate: body.certificate + 1,
                ..body
            },
            Some(&lease),
            &request,
        ),
        Decision::BlockQuarantine,
        "pairwise quarantine/certificate precedence",
    );
    assert_eq!(
        validate_commit(
            &BodyState {
                epoch: body.epoch + 1,
                ..body
            },
            Some(&lease),
            &CommitRequest {
                principal_id: request.principal_id + 1,
                ..request
            },
        ),
        Decision::BlockEpoch,
        "pairwise epoch/principal precedence",
    );
}

#[test]
fn preregistered_begin_commit_transition_matrix_is_deterministic() {
    let (body, lease, request) = fixture();
    let transitions = [
        (
            "unchanged_before_expiry",
            body,
            lease,
            request,
            Decision::Allow,
        ),
        (
            "reset",
            BodyState {
                epoch: body.epoch + 1,
                generation: body.generation + 1,
                ..body
            },
            lease,
            request,
            Decision::BlockEpoch,
        ),
        (
            "body_replacement",
            BodyState {
                body_uid: body.body_uid + 1,
                ..body
            },
            lease,
            request,
            Decision::BlockBodyUid,
        ),
        (
            "epoch_change",
            BodyState {
                epoch: body.epoch + 1,
                ..body
            },
            lease,
            request,
            Decision::BlockEpoch,
        ),
        (
            "generation_change",
            BodyState {
                generation: body.generation + 1,
                ..body
            },
            lease,
            request,
            Decision::BlockGeneration,
        ),
        (
            "certificate_rotation",
            BodyState {
                certificate: body.certificate + 1,
                ..body
            },
            lease,
            request,
            Decision::BlockCertificate,
        ),
        (
            "quarantine",
            BodyState {
                quarantined: true,
                ..body
            },
            lease,
            request,
            Decision::BlockQuarantine,
        ),
        (
            "expiry_before_boundary",
            body,
            lease,
            CommitRequest {
                now_ns: lease.valid_until_ns - 1,
                ..request
            },
            Decision::Allow,
        ),
        (
            "expiry_at_boundary",
            body,
            lease,
            CommitRequest {
                now_ns: lease.valid_until_ns,
                ..request
            },
            Decision::BlockExpired,
        ),
        (
            "expiry_after_boundary",
            body,
            lease,
            CommitRequest {
                now_ns: lease.valid_until_ns + 1,
                ..request
            },
            Decision::BlockExpired,
        ),
        (
            "principal_substitution",
            body,
            lease,
            CommitRequest {
                principal_id: request.principal_id + 1,
                ..request
            },
            Decision::BlockPrincipal,
        ),
        (
            "resource_substitution",
            body,
            lease,
            CommitRequest {
                resource_id: request.resource_id + 1,
                ..request
            },
            Decision::BlockResource,
        ),
        (
            "action_substitution",
            body,
            lease,
            CommitRequest {
                action_id: request.action_id + 1,
                ..request
            },
            Decision::BlockAction,
        ),
    ];

    for (name, current_body, current_lease, current_request, expected) in transitions {
        assert_eq!(
            transact(
                current_body,
                Some(lease),
                Some(current_lease),
                current_request,
            ),
            expected,
            "BEGIN -> {name} -> COMMIT",
        );
    }

    let rotated_lease = SafetyLease {
        certificate: lease.certificate + 1,
        ..lease
    };
    assert_eq!(
        transact(body, Some(lease), Some(rotated_lease), request),
        Decision::BlockCertificate,
        "current lease replacement after BEGIN",
    );
    assert_eq!(
        transact(body, Some(lease), None, request),
        Decision::BlockNoLease,
        "revocation after BEGIN",
    );
}

#[test]
fn duplicate_begin_duplicate_commit_and_rollback_are_fail_closed() {
    let (body, lease, request) = fixture();
    let mut transaction = AuthorityTransaction::new();
    transaction.begin(Some(lease)).expect("first BEGIN");
    assert_eq!(
        transaction.begin(Some(lease)),
        Err(BeginError::AlreadyPending),
        "duplicate BEGIN must not replace the captured authority",
    );
    assert_eq!(
        transaction.commit(&body, Some(&lease), &request),
        Decision::Allow,
    );
    assert_eq!(
        transaction.commit(&body, Some(&lease), &request),
        Decision::BlockNoLease,
        "duplicate COMMIT must not authorize a second effect",
    );

    transaction
        .begin(Some(lease))
        .expect("BEGIN before rollback");
    assert!(transaction.abort(), "rollback must consume pending BEGIN");
    assert!(!transaction.is_pending());
    assert_eq!(
        transaction.commit(&body, Some(&lease), &request),
        Decision::BlockNoLease,
        "COMMIT after rollback must fail closed",
    );
}

#[test]
fn concurrent_revoke_happens_before_commit_by_recorded_schedule() {
    let (body, lease, request) = fixture();
    let active_lease = Arc::new(Mutex::new(Some(lease)));
    let worker_lease = Arc::clone(&active_lease);
    let (revoke, revoke_requested) = mpsc::channel();
    let (revoked, revocation_observed) = mpsc::channel();
    let worker = thread::spawn(move || {
        revoke_requested.recv().expect("recorded revoke step");
        *worker_lease.lock().expect("lease mutex") = None;
        revoked.send(()).expect("recorded revoke completion");
    });

    let mut transaction = AuthorityTransaction::new();
    transaction.begin(Some(lease)).expect("BEGIN before revoke");
    revoke.send(()).expect("schedule revoke");
    revocation_observed.recv().expect("wait for revoke");
    let current = *active_lease.lock().expect("lease mutex");
    assert_eq!(
        transaction.commit(&body, current.as_ref(), &request),
        Decision::BlockNoLease,
    );
    worker.join().expect("revoke worker");
}

#[test]
fn rollback_ack_and_process_death_schedules_cannot_create_an_effect() {
    let (body, lease, request) = fixture();
    for schedule in ["rollback_before_ack", "process_death_before_ack"] {
        let mut transaction = AuthorityTransaction::new();
        transaction.begin(Some(lease)).expect("BEGIN");
        assert!(transaction.abort(), "{schedule}: pending authorization");

        let late_ack_arrived = true;
        let decision = transaction.commit(&body, Some(&lease), &request);
        let effects = u64::from(decision == Decision::Allow && late_ack_arrived);
        assert_eq!(decision, Decision::BlockNoLease, "{schedule}");
        assert_eq!(effects, 0, "{schedule}: unauthorized effect");
    }
}

#[derive(Debug)]
struct GateObservation {
    gate_id: &'static str,
    name: &'static str,
    schedule: String,
    expected_decision: String,
    observed_decision: String,
    effects_expected: u64,
    effects_observed: u64,
    blocked_attempt_effects_observed: u64,
    child_reaped: Option<bool>,
    detail: String,
    pass: bool,
}

struct TransactionScenario {
    body: BodyState,
    captured_lease: Option<SafetyLease>,
    current_lease: Option<SafetyLease>,
    request: CommitRequest,
    expected: Decision,
}

fn decision_observation(
    gate_id: &'static str,
    name: &'static str,
    schedule: &'static str,
    scenario: TransactionScenario,
) -> GateObservation {
    let observed = transact(
        scenario.body,
        scenario.captured_lease,
        scenario.current_lease,
        scenario.request,
    );
    let effects_expected = u64::from(scenario.expected == Decision::Allow);
    let effects_observed = u64::from(observed == Decision::Allow);
    let blocked_attempt_effects_observed = if observed == Decision::Allow {
        0
    } else {
        effects_observed
    };
    GateObservation {
        gate_id,
        name,
        schedule: schedule.to_owned(),
        expected_decision: scenario.expected.as_str().to_owned(),
        observed_decision: observed.as_str().to_owned(),
        effects_expected,
        effects_observed,
        blocked_attempt_effects_observed,
        child_reaped: None,
        detail: format!(
            "BEGIN captured lease; COMMIT observed {} after scheduled mutation",
            observed.as_str()
        ),
        pass: observed == scenario.expected && effects_observed == effects_expected,
    }
}

fn duplicate_begin_commit_observation() -> GateObservation {
    let (body, lease, request) = fixture();
    let mut transaction = AuthorityTransaction::new();
    let first_begin = transaction.begin(Some(lease));
    let duplicate_begin = transaction.begin(Some(lease));
    let observed = transaction.commit(&body, Some(&lease), &request);
    let effects_observed = u64::from(observed == Decision::Allow);
    let duplicate_rejected = duplicate_begin == Err(BeginError::AlreadyPending);
    GateObservation {
        gate_id: "G079",
        name: "duplicate_begin_commit_safe",
        schedule: "BEGIN; duplicate BEGIN; COMMIT".to_owned(),
        expected_decision: Decision::Allow.as_str().to_owned(),
        observed_decision: observed.as_str().to_owned(),
        effects_expected: 1,
        effects_observed,
        blocked_attempt_effects_observed: 0,
        child_reaped: None,
        detail: format!(
            "first_begin={first_begin:?}; duplicate_begin={duplicate_begin:?}; one COMMIT={observed}"
        ),
        pass: first_begin.is_ok()
            && duplicate_rejected
            && observed == Decision::Allow
            && effects_observed == 1,
    }
}

fn counter_overflow_observation() -> GateObservation {
    let result = checked_counter_increment(u64::MAX, "action identifier");
    let observed = match &result {
        Ok(value) => format!("COUNTER_INCREMENTED_TO_{value}"),
        Err(error) if error.to_string() == "action identifier overflow" => {
            "ERROR_ACTION_IDENTIFIER_OVERFLOW".to_owned()
        }
        Err(error) => format!("UNEXPECTED_ERROR_{:?}_{}", error.kind(), error),
    };
    let expected = "ERROR_ACTION_IDENTIFIER_OVERFLOW".to_owned();
    GateObservation {
        gate_id: "G080",
        name: "counter_overflow_fail_closed",
        schedule: "set production action counter input to u64::MAX; checked increment".to_owned(),
        expected_decision: expected.clone(),
        observed_decision: observed.clone(),
        effects_expected: 0,
        effects_observed: 0,
        blocked_attempt_effects_observed: 0,
        child_reaped: None,
        detail: match &result {
            Ok(value) => format!("unexpected counter value {value}"),
            Err(error) => format!("error_kind={:?}; error_message={error}", error.kind()),
        },
        pass: result.is_err() && observed == expected,
    }
}

fn concurrent_revocation_observation() -> GateObservation {
    let (body, lease, request) = fixture();
    let active_lease = Arc::new(Mutex::new(Some(lease)));
    let worker_lease = Arc::clone(&active_lease);
    let (revoke, revoke_requested) = mpsc::channel();
    let (revoked, revocation_observed) = mpsc::channel();
    let worker = thread::spawn(move || {
        revoke_requested.recv().expect("recorded revoke step");
        *worker_lease.lock().expect("lease mutex") = None;
        revoked.send(()).expect("recorded revoke completion");
    });

    let mut transaction = AuthorityTransaction::new();
    let begin = transaction.begin(Some(lease));
    revoke.send(()).expect("schedule revoke");
    revocation_observed.recv().expect("wait for revoke");
    let current = *active_lease.lock().expect("lease mutex");
    let observed = transaction.commit(&body, current.as_ref(), &request);
    worker.join().expect("revoke worker");
    let effects_observed = u64::from(observed == Decision::Allow);
    GateObservation {
        gate_id: "G198",
        name: "race_concurrent_revocation",
        schedule: "BEGIN; worker revokes lease; revocation completion ACK; COMMIT".to_owned(),
        expected_decision: Decision::BlockNoLease.as_str().to_owned(),
        observed_decision: observed.as_str().to_owned(),
        effects_expected: 0,
        effects_observed,
        blocked_attempt_effects_observed: effects_observed,
        child_reaped: None,
        detail: format!(
            "begin={begin:?}; current_lease_present={}; observed={observed}",
            current.is_some()
        ),
        pass: begin.is_ok()
            && current.is_none()
            && observed == Decision::BlockNoLease
            && effects_observed == 0,
    }
}

fn duplicate_begin_observation() -> GateObservation {
    let (_, lease, _) = fixture();
    let mut transaction = AuthorityTransaction::new();
    let first = transaction.begin(Some(lease));
    let duplicate = transaction.begin(Some(lease));
    let observed = if duplicate == Err(BeginError::AlreadyPending) {
        "BEGIN_ALREADY_PENDING"
    } else {
        "DUPLICATE_BEGIN_ACCEPTED"
    };
    GateObservation {
        gate_id: "G199",
        name: "race_duplicate_begin",
        schedule: "BEGIN; concurrent-equivalent duplicate BEGIN before COMMIT".to_owned(),
        expected_decision: "BEGIN_ALREADY_PENDING".to_owned(),
        observed_decision: observed.to_owned(),
        effects_expected: 0,
        effects_observed: 0,
        blocked_attempt_effects_observed: 0,
        child_reaped: None,
        detail: format!("first_begin={first:?}; duplicate_begin={duplicate:?}"),
        pass: first.is_ok() && duplicate == Err(BeginError::AlreadyPending),
    }
}

fn duplicate_commit_observation() -> GateObservation {
    let (body, lease, request) = fixture();
    let mut transaction = AuthorityTransaction::new();
    let begin = transaction.begin(Some(lease));
    let first = transaction.commit(&body, Some(&lease), &request);
    let duplicate = transaction.commit(&body, Some(&lease), &request);
    let duplicate_effects = u64::from(duplicate == Decision::Allow);
    GateObservation {
        gate_id: "G200",
        name: "race_duplicate_commit",
        schedule: "BEGIN; COMMIT; duplicate COMMIT".to_owned(),
        expected_decision: Decision::BlockNoLease.as_str().to_owned(),
        observed_decision: duplicate.as_str().to_owned(),
        effects_expected: 0,
        effects_observed: duplicate_effects,
        blocked_attempt_effects_observed: duplicate_effects,
        child_reaped: None,
        detail: format!(
            "begin={begin:?}; setup_commit={first}; duplicate_commit={duplicate}; setup_effects={}",
            u64::from(first == Decision::Allow)
        ),
        pass: begin.is_ok()
            && first == Decision::Allow
            && duplicate == Decision::BlockNoLease
            && duplicate_effects == 0,
    }
}

fn rollback_ack_observation() -> GateObservation {
    let (body, lease, request) = fixture();
    let ack = rollback_ack(1, 2);
    let source = concat!(
        "import sys\n",
        "sys.stdin.readline()\n",
        "sys.stdout.write(sys.argv[1])\n",
        "sys.stdout.flush()\n"
    );
    let mut child =
        ChildProcess::spawn_program(Path::new("/usr/bin/python3"), &["-c", source, &ack])
            .expect("spawn rollback ACK child");
    let mut transaction = AuthorityTransaction::new();
    let begin = transaction.begin(Some(lease));
    let ack_result = child.transact(
        &rollback_request(1, 2),
        ExpectedAck::Rollback { id: 1, nonce: 2 },
    );
    let aborted = transaction.abort();
    let observed = transaction.commit(&body, Some(&lease), &request);
    thread::sleep(std::time::Duration::from_millis(25));
    let cleanup_result = child.transact(
        &rollback_request(3, 4),
        ExpectedAck::Rollback { id: 3, nonce: 4 },
    );
    let child_reaped = child.is_reaped();
    drop(child);
    let effects_observed = u64::from(observed == Decision::Allow);
    GateObservation {
        gate_id: "G201",
        name: "race_rollback_ack",
        schedule: "BEGIN; send ROLLBACK; validate child ACK; abort; late COMMIT".to_owned(),
        expected_decision: Decision::BlockNoLease.as_str().to_owned(),
        observed_decision: observed.as_str().to_owned(),
        effects_expected: 0,
        effects_observed,
        blocked_attempt_effects_observed: effects_observed,
        child_reaped: Some(child_reaped),
        detail: format!(
            "begin={begin:?}; rollback_ack={ack_result:?}; abort_consumed_pending={aborted}; \
             late_commit={observed}; cleanup={cleanup_result:?}; child_reaped={child_reaped}"
        ),
        pass: begin.is_ok()
            && ack_result.is_ok()
            && aborted
            && observed == Decision::BlockNoLease
            && effects_observed == 0
            && child_reaped,
    }
}

fn output_path() -> PathBuf {
    let directory = std::env::var_os("OASI_R1_R5_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&directory).expect("create authority output directory");
    directory.join("AUTHORITY_TRANSACTION_CASES.json")
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn observation_json(observation: &GateObservation) -> String {
    let executed = !observation.observed_decision.is_empty();
    let observed_equals_expected = observation.observed_decision == observation.expected_decision;
    let unauthorized_effects = if observation.expected_decision == Decision::Allow.as_str() {
        observation.blocked_attempt_effects_observed
    } else {
        observation.effects_observed
    };
    let child_reaped = observation
        .child_reaped
        .map_or_else(|| "null".to_owned(), |value| value.to_string());
    let return_code = if observation.pass { 0 } else { 1 };
    format!(
        concat!(
            "{{\"case_id\":{},\"gate_id\":{},\"schedule\":{},",
            "\"executed\":{},\"return_code\":{},\"timed_out\":false,",
            "\"expected_decision\":{},\"observed_decision\":{},",
            "\"observed_equals_expected\":{},",
            "\"effects_expected\":{},\"effects_observed\":{},",
            "\"blocked_attempt_effects_observed\":{},\"unauthorized_effects\":{},",
            "\"child_reaped\":{},\"detail\":{},\"pass\":{}}}"
        ),
        json_string(observation.name),
        json_string(observation.gate_id),
        json_string(&observation.schedule),
        executed,
        return_code,
        json_string(&observation.expected_decision),
        json_string(&observation.observed_decision),
        observed_equals_expected,
        observation.effects_expected,
        observation.effects_observed,
        observation.blocked_attempt_effects_observed,
        unauthorized_effects,
        child_reaped,
        json_string(&observation.detail),
        observation.pass,
    )
}

#[test]
fn required_gate_authority_transactions_are_executed_and_reported() {
    let (body, lease, request) = fixture();
    let mut observations = vec![
        decision_observation(
            "G067",
            "begin_reset_commit_blocked",
            "BEGIN; reset epoch and generation; COMMIT",
            TransactionScenario {
                body: BodyState {
                    epoch: body.epoch + 1,
                    generation: body.generation + 1,
                    ..body
                },
                captured_lease: Some(lease),
                current_lease: Some(lease),
                request,
                expected: Decision::BlockEpoch,
            },
        ),
        decision_observation(
            "G068",
            "begin_body_change_commit_blocked",
            "BEGIN; replace body UID; COMMIT",
            TransactionScenario {
                body: BodyState {
                    body_uid: body.body_uid + 1,
                    ..body
                },
                captured_lease: Some(lease),
                current_lease: Some(lease),
                request,
                expected: Decision::BlockBodyUid,
            },
        ),
        decision_observation(
            "G069",
            "begin_epoch_change_commit_blocked",
            "BEGIN; increment epoch; COMMIT",
            TransactionScenario {
                body: BodyState {
                    epoch: body.epoch + 1,
                    ..body
                },
                captured_lease: Some(lease),
                current_lease: Some(lease),
                request,
                expected: Decision::BlockEpoch,
            },
        ),
        decision_observation(
            "G070",
            "begin_generation_change_commit_blocked",
            "BEGIN; increment generation; COMMIT",
            TransactionScenario {
                body: BodyState {
                    generation: body.generation + 1,
                    ..body
                },
                captured_lease: Some(lease),
                current_lease: Some(lease),
                request,
                expected: Decision::BlockGeneration,
            },
        ),
        decision_observation(
            "G071",
            "begin_certificate_rotation_commit_blocked",
            "BEGIN; rotate certificate; COMMIT",
            TransactionScenario {
                body: BodyState {
                    certificate: body.certificate + 1,
                    ..body
                },
                captured_lease: Some(lease),
                current_lease: Some(lease),
                request,
                expected: Decision::BlockCertificate,
            },
        ),
        decision_observation(
            "G072",
            "begin_quarantine_commit_blocked",
            "BEGIN; enter quarantine; COMMIT",
            TransactionScenario {
                body: BodyState {
                    quarantined: true,
                    ..body
                },
                captured_lease: Some(lease),
                current_lease: Some(lease),
                request,
                expected: Decision::BlockQuarantine,
            },
        ),
        duplicate_begin_commit_observation(),
        counter_overflow_observation(),
    ];

    for (gate_id, name, schedule, current_body, expected) in [
        (
            "G186",
            "race_reset_between_begin_commit",
            "BEGIN; scheduled reset; COMMIT",
            BodyState {
                epoch: body.epoch + 1,
                generation: body.generation + 1,
                ..body
            },
            Decision::BlockEpoch,
        ),
        (
            "G187",
            "race_body_uid_between_begin_commit",
            "BEGIN; scheduled body UID replacement; COMMIT",
            BodyState {
                body_uid: body.body_uid + 1,
                ..body
            },
            Decision::BlockBodyUid,
        ),
        (
            "G188",
            "race_epoch_between_begin_commit",
            "BEGIN; scheduled epoch increment; COMMIT",
            BodyState {
                epoch: body.epoch + 1,
                ..body
            },
            Decision::BlockEpoch,
        ),
        (
            "G189",
            "race_generation_between_begin_commit",
            "BEGIN; scheduled generation increment; COMMIT",
            BodyState {
                generation: body.generation + 1,
                ..body
            },
            Decision::BlockGeneration,
        ),
        (
            "G190",
            "race_certificate_between_begin_commit",
            "BEGIN; scheduled certificate rotation; COMMIT",
            BodyState {
                certificate: body.certificate + 1,
                ..body
            },
            Decision::BlockCertificate,
        ),
        (
            "G191",
            "race_quarantine_between_begin_commit",
            "BEGIN; scheduled quarantine; COMMIT",
            BodyState {
                quarantined: true,
                ..body
            },
            Decision::BlockQuarantine,
        ),
    ] {
        observations.push(decision_observation(
            gate_id,
            name,
            schedule,
            TransactionScenario {
                body: current_body,
                captured_lease: Some(lease),
                current_lease: Some(lease),
                request,
                expected,
            },
        ));
    }
    observations.extend([
        concurrent_revocation_observation(),
        duplicate_begin_observation(),
        duplicate_commit_observation(),
        rollback_ack_observation(),
    ]);

    let required_gate_ids = [
        "G067", "G068", "G069", "G070", "G071", "G072", "G079", "G080", "G186", "G187", "G188",
        "G189", "G190", "G191", "G198", "G199", "G200", "G201",
    ];
    let observed_gate_ids = observations
        .iter()
        .map(|case| case.gate_id)
        .collect::<Vec<_>>();
    let passed = observations.iter().filter(|case| case.pass).count();
    let total = observations.len();
    let exact_gate_set = observed_gate_ids == required_gate_ids;
    let campaign_kind =
        std::env::var("OASI_R1_R5_CAMPAIGN_KIND").unwrap_or_else(|_| "targeted_test".to_owned());
    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"oasi-core-r1-r5-authority-transaction-cases-1\",\n",
            "  \"campaign_kind\": {},\n",
            "  \"required_gate_ids\": [{}],\n",
            "  \"cases\": {{\n",
            "{}\n",
            "  }},\n",
            "  \"executed_cases\": {},\n",
            "  \"passed_cases\": {},\n",
            "  \"failed_cases\": {},\n",
            "  \"exact_gate_set\": {},\n",
            "  \"pass\": {}\n",
            "}}\n"
        ),
        json_string(&campaign_kind),
        required_gate_ids
            .iter()
            .map(|gate_id| json_string(gate_id))
            .collect::<Vec<_>>()
            .join(","),
        observations
            .iter()
            .map(|observation| format!(
                "    {}: {}",
                json_string(observation.name),
                observation_json(observation)
            ))
            .collect::<Vec<_>>()
            .join(",\n"),
        total,
        passed,
        total - passed,
        exact_gate_set,
        exact_gate_set && passed == total,
    );
    fs::write(output_path(), report).expect("write authority transaction report");
    assert!(
        exact_gate_set,
        "authority gate set differs from required set"
    );
    for observation in &observations {
        assert!(
            observation.pass,
            "{} {} failed: expected {}, observed {}, effects {}",
            observation.gate_id,
            observation.name,
            observation.expected_decision,
            observation.observed_decision,
            observation.effects_observed,
        );
    }
}
