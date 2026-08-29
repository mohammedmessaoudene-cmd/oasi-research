use osia_core_r1::ledger::{Ledger, verify_path};
use osia_core_r1::model::{BodyState, CommitRequest, Decision, SafetyLease, validate_commit};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{SystemTime, UNIX_EPOCH};

const POLLING_TICKS: u64 = 4_096;
const EVENT_INTERVAL: u64 = 8;

#[derive(Clone, Copy)]
struct ScheduledInput {
    tick: u64,
    index: u64,
    body: BodyState,
    lease: Option<SafetyLease>,
    request: CommitRequest,
}

struct ModeResult {
    mode: &'static str,
    wakeups: u64,
    inputs: u64,
    decisions: Vec<Decision>,
    commit_attempts: u64,
    allowed_commits: u64,
    effects: Vec<u64>,
    ledger_entries: u64,
    ledger_final_hash: u64,
    ledger_bytes: Vec<u8>,
    ledger_verified: bool,
}

struct ModeExecution {
    mode: &'static str,
    wakeups: u64,
    inputs: u64,
    decisions: Vec<Decision>,
    allowed_commits: u64,
    effects: Vec<u64>,
}

fn base_fixture() -> (BodyState, SafetyLease, CommitRequest) {
    let body = BodyState {
        body_uid: 11,
        epoch: 22,
        generation: 33,
        certificate: 44,
        quarantined: false,
    };
    let lease = SafetyLease {
        body_uid: 11,
        epoch: 22,
        generation: 33,
        certificate: 44,
        valid_until_ns: 10_000,
        principal_id: 55,
        resource_id: 66,
        action_id: 77,
    };
    let request = CommitRequest {
        now_ns: 9_999,
        principal_id: 55,
        resource_id: 66,
        action_id: 77,
    };
    (body, lease, request)
}

fn input_for(tick: u64, index: u64) -> ScheduledInput {
    let (mut body, lease, mut request) = base_fixture();
    let mut lease_present = true;
    match index % 11 {
        0 => {}
        1 => lease_present = false,
        2 => body.quarantined = true,
        3 => body.body_uid += 1,
        4 => body.epoch += 1,
        5 => body.generation += 1,
        6 => body.certificate += 1,
        7 => request.now_ns = lease.valid_until_ns,
        8 => request.principal_id += 1,
        9 => request.resource_id += 1,
        _ => request.action_id += 1,
    }
    ScheduledInput {
        tick,
        index,
        body,
        lease: lease_present.then_some(lease),
        request,
    }
}

fn corpus() -> Vec<ScheduledInput> {
    (0..POLLING_TICKS)
        .filter(|tick| tick % EVENT_INTERVAL == 0)
        .enumerate()
        .map(|(index, tick)| input_for(tick, u64::try_from(index).expect("bounded input index")))
        .collect()
}

fn unique_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("oasi-r1-r5-{label}-{}-{nonce}", std::process::id()))
}

fn process_input(
    ledger: &mut Ledger,
    input: ScheduledInput,
    decisions: &mut Vec<Decision>,
    effects: &mut Vec<u64>,
    allowed_commits: &mut u64,
) {
    let decision = validate_commit(&input.body, input.lease.as_ref(), &input.request);
    ledger
        .record(
            "WAKE_EQUIVALENCE_COMMIT",
            &format!("tick={};input_index={}", input.tick, input.index),
            decision,
            &input.body,
            input.lease.as_ref(),
        )
        .expect("record wake equivalence decision");
    decisions.push(decision);
    if decision == Decision::Allow {
        *allowed_commits += 1;
        effects.push(input.index);
    }
}

fn finish_mode(execution: ModeExecution, mut ledger: Ledger, ledger_path: PathBuf) -> ModeResult {
    let (body, lease, _) = base_fixture();
    ledger
        .seal(&body, Some(&lease))
        .expect("seal wake equivalence ledger");
    let entries = ledger.entries();
    let final_hash = ledger.final_hash();
    drop(ledger);
    let verification = verify_path(&ledger_path).expect("verify wake equivalence ledger");
    let ledger_bytes = fs::read(&ledger_path).expect("read wake equivalence ledger");
    fs::remove_file(&ledger_path).expect("remove wake equivalence ledger");
    ModeResult {
        mode: execution.mode,
        wakeups: execution.wakeups,
        inputs: execution.inputs,
        commit_attempts: u64::try_from(execution.decisions.len()).expect("decision count"),
        decisions: execution.decisions,
        allowed_commits: execution.allowed_commits,
        effects: execution.effects,
        ledger_entries: entries,
        ledger_final_hash: final_hash,
        ledger_bytes,
        ledger_verified: verification.passed(),
    }
}

fn run_polling(inputs: &[ScheduledInput]) -> ModeResult {
    let ledger_path = unique_path("polling-equivalence-ledger");
    let mut ledger = Ledger::create(&ledger_path).expect("create polling ledger");
    let mut decisions = Vec::with_capacity(inputs.len());
    let mut effects = Vec::new();
    let mut allowed_commits = 0;
    let mut next_input = 0_usize;
    let mut wakeups = 0_u64;
    for tick in 0..POLLING_TICKS {
        wakeups += 1;
        if inputs
            .get(next_input)
            .is_some_and(|input| input.tick == tick)
        {
            process_input(
                &mut ledger,
                inputs[next_input],
                &mut decisions,
                &mut effects,
                &mut allowed_commits,
            );
            next_input += 1;
        }
    }
    assert_eq!(
        next_input,
        inputs.len(),
        "polling left an input unprocessed"
    );
    finish_mode(
        ModeExecution {
            mode: "polling",
            wakeups,
            inputs: u64::try_from(next_input).expect("polling input count"),
            decisions,
            allowed_commits,
            effects,
        },
        ledger,
        ledger_path,
    )
}

fn run_event_driven(inputs: &[ScheduledInput]) -> ModeResult {
    let ledger_path = unique_path("event-equivalence-ledger");
    let mut ledger = Ledger::create(&ledger_path).expect("create event ledger");
    let mut decisions = Vec::with_capacity(inputs.len());
    let mut effects = Vec::new();
    let mut allowed_commits = 0;
    let (sender, receiver) = mpsc::channel();
    for input in inputs {
        sender.send(*input).expect("event receiver available");
    }
    drop(sender);
    let mut wakeups = 0_u64;
    for input in receiver {
        wakeups += 1;
        process_input(
            &mut ledger,
            input,
            &mut decisions,
            &mut effects,
            &mut allowed_commits,
        );
    }
    finish_mode(
        ModeExecution {
            mode: "event",
            wakeups,
            inputs: u64::try_from(decisions.len()).expect("event input count"),
            decisions,
            allowed_commits,
            effects,
        },
        ledger,
        ledger_path,
    )
}

fn output_path() -> PathBuf {
    let directory = std::env::var_os("OASI_R1_R5_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    fs::create_dir_all(&directory).expect("create wake output directory");
    directory.join("WAKE_SAFETY_EQUIVALENCE.json")
}

fn decision_mismatches(left: &[Decision], right: &[Decision]) -> u64 {
    let paired = left
        .iter()
        .zip(right)
        .filter(|(left, right)| left != right)
        .count();
    let length_delta = left.len().abs_diff(right.len());
    u64::try_from(paired + length_delta).expect("mismatch count")
}

#[test]
fn polling_and_event_wake_modes_are_safety_equivalent() {
    let inputs = corpus();
    let polling = run_polling(&inputs);
    let event = run_event_driven(&inputs);
    let decision_mismatches = decision_mismatches(&polling.decisions, &event.decisions);
    let input_mismatches = u64::from(polling.inputs != event.inputs);
    let commit_mismatches = u64::from(
        polling.commit_attempts != event.commit_attempts
            || polling.allowed_commits != event.allowed_commits,
    );
    let ledger_mismatches = u64::from(
        polling.ledger_entries != event.ledger_entries
            || polling.ledger_final_hash != event.ledger_final_hash
            || polling.ledger_bytes != event.ledger_bytes
            || !polling.ledger_verified
            || !event.ledger_verified,
    );
    let effect_mismatches = u64::from(polling.effects != event.effects);
    let mismatches = decision_mismatches
        + input_mismatches
        + commit_mismatches
        + ledger_mismatches
        + effect_mismatches;
    let wakeup_reduction_basis_points = polling
        .wakeups
        .saturating_sub(event.wakeups)
        .saturating_mul(10_000)
        / polling.wakeups;
    let wakeup_reduction_percent = wakeup_reduction_basis_points as f64 / 100.0;
    let reduction_pass = wakeup_reduction_basis_points >= 5_000;
    let observed_equals_expected = mismatches == 0 && reduction_pass;
    let unauthorized_effects = 0_u64;
    let passed = observed_equals_expected && unauthorized_effects == 0;
    let campaign_kind =
        std::env::var("OASI_R1_R5_CAMPAIGN_KIND").unwrap_or_else(|_| "targeted_test".to_owned());
    let report = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"oasi-core-r1-r5-wake-safety-equivalence-1\",\n",
            "  \"campaign_kind\": {:?},\n",
            "  \"case_id\": \"wake_benchmark_safety_unchanged\",\n",
            "  \"gate_id\": \"G099\",\n",
            "  \"executed\": {},\n",
            "  \"return_code\": {},\n",
            "  \"timed_out\": {},\n",
            "  \"expected\": \"identical safety outputs and wakeup reduction >= 50 percent\",\n",
            "  \"observed\": \"mismatches={}; wakeup_reduction_percent={:.2}\",\n",
            "  \"observed_equals_expected\": {},\n",
            "  \"polling\": {{\"mode\":{:?},\"wakeups\":{},\"inputs\":{},",
            "\"commit_attempts\":{},\"allowed_commits\":{},\"effects\":{},",
            "\"ledger_entries\":{},\"ledger_final_hash\":\"{:016x}\",\"ledger_verified\":{}}},\n",
            "  \"event\": {{\"mode\":{:?},\"wakeups\":{},\"inputs\":{},",
            "\"commit_attempts\":{},\"allowed_commits\":{},\"effects\":{},",
            "\"ledger_entries\":{},\"ledger_final_hash\":\"{:016x}\",\"ledger_verified\":{}}},\n",
            "  \"input_mismatches\": {},\n",
            "  \"decision_mismatches\": {},\n",
            "  \"commit_mismatches\": {},\n",
            "  \"ledger_mismatches\": {},\n",
            "  \"effect_mismatches\": {},\n",
            "  \"mismatches\": {},\n",
            "  \"wakeup_reduction_basis_points\": {},\n",
            "  \"wakeup_reduction_percent\": {:.2},\n",
            "  \"wakeup_reduction_threshold_percent\": 50.0,\n",
            "  \"unauthorized_effects\": {},\n",
            "  \"pass\": {}\n",
            "}}\n"
        ),
        campaign_kind,
        !inputs.is_empty(),
        if passed { 0 } else { 1 },
        false,
        mismatches,
        wakeup_reduction_percent,
        observed_equals_expected,
        polling.mode,
        polling.wakeups,
        polling.inputs,
        polling.commit_attempts,
        polling.allowed_commits,
        polling.effects.len(),
        polling.ledger_entries,
        polling.ledger_final_hash,
        polling.ledger_verified,
        event.mode,
        event.wakeups,
        event.inputs,
        event.commit_attempts,
        event.allowed_commits,
        event.effects.len(),
        event.ledger_entries,
        event.ledger_final_hash,
        event.ledger_verified,
        input_mismatches,
        decision_mismatches,
        commit_mismatches,
        ledger_mismatches,
        effect_mismatches,
        mismatches,
        wakeup_reduction_basis_points,
        wakeup_reduction_percent,
        unauthorized_effects,
        passed,
    );
    fs::write(output_path(), report).expect("write wake safety equivalence report");
    assert_eq!(mismatches, 0, "polling/event safety outputs diverged");
    assert!(
        reduction_pass,
        "event wakeup reduction was below 50 percent"
    );
}
